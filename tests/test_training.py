"""CIC training checks independent of packet capture and later experiment stages."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from dataset import numeric_features, read_sample
from features import FEATURES
from train import main, split_data


def sample(offset=0):
    rows = []
    for label, base in (("BENIGN", 0), ("PortScan", 1000)):
        for n in range(45):
            rows.append({**dict(zip(FEATURES, [offset + base + n, 100 + n, 1, 0, n, 0, 0, 1, 0, 0, 0, 0])),
                         "Label": label})
    frame = pd.DataFrame(rows)
    frame[FEATURES] = numeric_features(frame)
    return frame


def tiny_estimators(*_):
    # Small sklearn fixtures exercise OOF/refit/export without claiming booster results.
    models = {name: (DecisionTreeClassifier(random_state=42), {"max_depth": [1, 2]})
              for name in ("dt", "rf", "xgb", "lgbm")}
    models["lr"] = (LogisticRegression(max_iter=1000), {"C": [0.1, 1.0]})
    return models


class TrainingTests(unittest.TestCase):
    def test_cic_schema_sampling_deduplication_and_reproducibility(self):
        frame = sample()
        frame = pd.concat([frame, frame.iloc[[0]].assign(Label="PortScan"),
                           frame.iloc[[1]], frame.iloc[[2]].assign(Label=None)], ignore_index=True)
        frame = frame.rename(columns=lambda name: " " + name + " ")
        with tempfile.TemporaryDirectory(dir=ROOT / "tests") as tmp:
            frame.to_csv(Path(tmp) / "cic.csv", index=False, encoding="utf-8-sig")
            data, meta = read_sample(tmp, 100, 42)
            repeated, _ = read_sample(tmp, 100, 42)
        pd.testing.assert_frame_equal(data, repeated)
        self.assertEqual(meta["invalid_labels"], 1)
        self.assertEqual(meta["sample_conflicting_rows_removed"], 2)
        self.assertEqual(meta["sample_duplicate_rows_removed"], 1)
        self.assertFalse(data[FEATURES].duplicated().any())
        self.assertEqual(set(data.Label), {"BENIGN", "PortScan"})

    def test_binary_mapping_precedes_sampling_and_rare_class_filter(self):
        frame = sample()
        frame.loc[45, "Label"] = "Heartbleed"
        with tempfile.TemporaryDirectory(dir=ROOT / "tests") as tmp:
            frame.to_csv(Path(tmp) / "cic.csv", index=False)
            data, meta = read_sample(tmp, 100, binary=True)
        self.assertEqual(data.Label.value_counts().to_dict(), {"BENIGN": 45, "ATTACK": 45})
        self.assertEqual(meta["raw_class_counts"]["Heartbleed"], 1)
        self.assertEqual(meta["task"], "binary")
        self.assertIn("per binary class", meta["sampling"])

    def test_class_cap_and_nonfinite_normalization(self):
        frame = sample()
        frame.loc[0, "Flow Duration"] = np.inf
        with tempfile.TemporaryDirectory(dir=ROOT / "tests") as tmp:
            frame.to_csv(Path(tmp) / "cic.csv", index=False)
            data, meta = read_sample(tmp, 15, binary=True)
        self.assertTrue((data.Label.value_counts() <= 15).all())
        self.assertEqual(meta["raw_missing_or_nonfinite"]["Flow Duration"], 1)
        self.assertFalse(np.isinf(numeric_features(data).to_numpy()).any())

    def test_missing_schema_is_rejected(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "tests") as tmp:
            sample().drop(columns=[FEATURES[0]]).to_csv(Path(tmp) / "bad.csv", index=False)
            with self.assertRaisesRegex(ValueError, "missing/ambiguous columns"):
                read_sample(tmp)

    def test_splits_are_disjoint_and_holdout_overlap_is_purged(self):
        data = sample()
        train, val, dev, test, removed = split_data(data, 42)
        self.assertEqual(removed, 0)
        self.assertEqual(len(train) + len(val) + len(test), len(data))
        hashes = [set(pd.util.hash_pandas_object(f[FEATURES], index=False)) for f in (train, val, test)]
        self.assertFalse(hashes[0] & hashes[1] or hashes[0] & hashes[2] or hashes[1] & hashes[2])
        holdout = data.groupby("Label").head(2).copy()
        _, _, purged, _, removed = split_data(data, 42, holdout)
        self.assertEqual(removed, 4)
        self.assertEqual(len(purged), len(data) - 4)
        with self.assertRaisesRegex(ValueError, "classes missing"):
            split_data(data, 42, holdout.assign(Label="UnknownAttack"))

    def test_cli_binary_training_exports_reproducible_predictions(self):
        for tune in (False, True):
            with self.subTest(tune=tune), tempfile.TemporaryDirectory(dir=ROOT / "tests") as tmp:
                folder = Path(tmp)
                source, out = folder / "cic.csv", folder / "run"
                sample().to_csv(source, index=False)
                argv = ["train.py", "--data", str(source), "--dataset", "CIC-IDS2017", "--out", str(out),
                        "--binary", "--max-per-class", "100", "--trees", "2", "--folds", "2"]
                if tune:
                    argv.append("--tune")
                with patch.object(sys, "argv", argv), patch("train.estimators", side_effect=tiny_estimators), \
                     patch("train.version", return_value="fixture-only"), contextlib.redirect_stdout(io.StringIO()):
                    main()
                protocol = json.loads((out / "protocol.json").read_text(encoding="utf-8"))
                self.assertEqual(protocol["task"], "binary")
                self.assertTrue(protocol["arguments"]["binary"])
                self.assertEqual(len(json.loads((out / "comparison.json").read_text())), 6)
                selection = json.loads((out / "selection.json").read_text())
                self.assertEqual("train_cv_macro_f1" in selection["rf"], tune)
                self.assertTrue((out / "confusion_stacking.csv").exists())
                report = json.loads((out / "report_stacking.json").read_text())
                self.assertIn("attack_recall", report["summary"])
                artifact = joblib.load(out / "models" / "stacking_ids.joblib")
                self.assertEqual(set(artifact["classes"]), {"BENIGN", "ATTACK"})
                smoke = pd.read_csv(out / "smoke_test.csv")
                labels = np.asarray(artifact["classes"])[artifact["model"].predict(numeric_features(smoke))]
                self.assertEqual(labels.tolist(), smoke.ExpectedPrediction.tolist())
                self.assertNotIn("scapy", (out / "models" / "requirements-deploy.txt").read_text())
                with patch.object(sys, "argv", argv), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as error:
                        main()
                self.assertNotEqual(error.exception.code, 0)

    def test_binary_flag_applies_to_external_holdout(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "tests") as tmp:
            folder = Path(tmp)
            source, holdout = folder / "train.csv", folder / "holdout.csv"
            sample().to_csv(source, index=False)
            sample(10000).to_csv(holdout, index=False)
            argv = ["train.py", "--data", str(source), "--dataset", "CIC-IDS2017", "--out", str(folder / "run"),
                    "--test-data", str(holdout), "--binary"]
            with patch.object(sys, "argv", argv), patch("train.run_experiment") as run, \
                 contextlib.redirect_stdout(io.StringIO()):
                main()
            self.assertEqual(set(run.call_args.args[4].Label), {"BENIGN", "ATTACK"})
            self.assertEqual(run.call_args.args[5]["task"], "binary")
            self.assertEqual(run.call_args.args[6]["task"], "binary")

    def test_help_exposes_binary_without_training_dependencies(self):
        result = subprocess.run([sys.executable, str(ROOT / "src" / "train.py"), "--help"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--binary", result.stdout)


if __name__ == "__main__":
    unittest.main()
