"""Protocol and orchestration checks; tiny classifiers are fixtures, not benchmark results."""
from argparse import Namespace
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import joblib
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import StackingClassifier
from sklearn.tree import DecisionTreeClassifier

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from dataset import read_sample
from check_model import check_model
from features import FEATURES
from three_models import SOURCES, feature_hashes, prepare_splits, run_three_models
from train import run_experiment, split_data
from summarize import main as summarize_main, summarize_three_models


def sample(offset):
    rows = []
    for label, base in (("BENIGN", 0), ("ATTACK", 1000)):
        for n in range(45):
            rows.append({**dict(zip(FEATURES, [offset + base + n, 100 + n, 1, 0, n, 0, 0, 1, 0, 0, 0, 0])),
                         "Label": label})
    return pd.DataFrame(rows)


def tiny_estimators(*_):
    # Exercise the real sklearn selection/OOF/refit/export code without booster dependencies.
    models = {name: (DecisionTreeClassifier(max_depth=2, random_state=42), {"max_depth": [1, 2]})
              for name in ("dt", "rf", "xgb", "lgbm")}
    models["lr"] = (LogisticRegression(max_iter=1000), {"C": [0.1, 1.0]})
    return models


class ThreeModelsTests(unittest.TestCase):
    def test_binary_mapping_precedes_sampling_and_rare_class_filter(self):
        frame = sample(0)
        frame.loc[frame.Label == "BENIGN", "Label"] = "Normal"
        # A subtype with a single row should remain part of the binary ATTACK class.
        frame.loc[45, "Label"] = "RareSubtype"
        frame.loc[46:, "Label"] = "Probe"
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            frame.to_csv(Path(tmp) / "data.csv", index=False)
            data, meta = read_sample(tmp, 100, binary=True)
        self.assertEqual(data.Label.value_counts().to_dict(), {"BENIGN": 45, "ATTACK": 45})
        self.assertEqual(meta["raw_class_counts"]["RareSubtype"], 1)
        self.assertEqual(meta["task"], "binary")

    def test_global_conflicts_duplicates_and_disjoint_reproducible_splits(self):
        cic, insdn = sample(0), sample(10000)
        insdn = pd.concat([insdn, cic.iloc[[0]], cic.iloc[[1]].assign(Label="ATTACK")], ignore_index=True)
        splits, meta = prepare_splits(cic, insdn)
        repeated, repeated_meta = prepare_splits(cic, insdn)
        self.assertEqual(meta["conflicting_rows_removed"], 2)
        self.assertEqual(meta["duplicate_rows_removed"], 1)
        self.assertEqual(meta, repeated_meta)
        seen = set()
        for source in SOURCES:
            for part, frame in splits[source].items():
                current = set(feature_hashes(frame))
                self.assertFalse(seen & current)
                seen |= current
                pd.testing.assert_frame_equal(frame, repeated[source][part])

    def test_missing_binary_class_and_insufficient_rows_fail(self):
        with self.assertRaisesRegex(ValueError, "both binary labels"):
            prepare_splits(sample(0).iloc[:45], sample(10000))
        with self.assertRaisesRegex(ValueError, "too few unique"):
            prepare_splits(sample(0).groupby("Label").head(5), sample(10000))

    def test_combined_reuses_exact_tests_and_exports_three_models(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            root = Path(tmp)
            cic, insdn = root / "cic.csv", root / "insdn.csv"
            sample(0).to_csv(cic, index=False)
            sample(10000).to_csv(insdn, index=False)
            args = Namespace(cic_data=str(cic), insdn_data=str(insdn), out=str(root / "run"),
                             max_per_class=100, trees=2, seed=42, folds=2, tune=False, combined=True)
            with patch.object(StackingClassifier, "fit", autospec=True, side_effect=StackingClassifier.fit) as stack_fit, \
                 patch("train.estimators", side_effect=tiny_estimators), \
                 patch("train.version", return_value="fixture-only"), contextlib.redirect_stdout(io.StringIO()):
                result = run_three_models(args)
            # Two validation candidates plus one final fit per configuration; never refit per test.
            self.assertEqual(stack_fit.call_count, 9)
            self.assertEqual(len(result), 30)  # M3 also evaluates the concatenation of both tests.
            manifests = {name: json.loads((root / "run" / name / "protocol.json").read_text())
                         for name in ("M1", "M2", "M3")}
            self.assertEqual(manifests["M1"]["split_feature_sha256"]["cicids2017"],
                             manifests["M3"]["split_feature_sha256"]["cicids2017"])
            self.assertEqual(manifests["M2"]["split_feature_sha256"]["insdn"],
                             manifests["M3"]["split_feature_sha256"]["insdn"])
            self.assertEqual(manifests["M3"]["task"], "binary")
            combined = pd.read_csv(root / "run" / "M3" / "combined" / "predictions.csv")
            separate = pd.concat([pd.read_csv(root / "run" / "M3" / s / "predictions.csv")
                                  for s in SOURCES], ignore_index=True)
            pd.testing.assert_frame_equal(combined, separate)
            for name in manifests:
                artifact = joblib.load(root / "run" / name / "models" / "stacking_ids.joblib")
                source = "insdn" if name == "M2" else "cicids2017"
                smoke = pd.read_csv(root / "run" / name / source / "smoke_test.csv")
                predicted = artifact["model"].predict(smoke[FEATURES])
                labels = [artifact["classes"][int(n)] for n in predicted]
                self.assertEqual(labels, smoke.ExpectedPrediction.tolist())
            m3 = joblib.load(root / "run" / "M3" / "models" / "stacking_ids.joblib")
            insdn_smoke = pd.read_csv(root / "run" / "M3" / "insdn" / "smoke_test.csv")
            predicted = [m3["classes"][int(n)] for n in m3["model"].predict(insdn_smoke[FEATURES])]
            self.assertEqual(predicted, insdn_smoke.ExpectedPrediction.tolist())
            with contextlib.redirect_stdout(io.StringIO()):
                model_path = root / "run" / "M3" / "models" / "stacking_ids.joblib"
                for source in SOURCES:
                    self.assertEqual(check_model(model_path, root / "run" / "M3" / source / "smoke_test.csv"), 1)
                insdn_smoke["ExpectedPrediction"] = "WRONG"
                bad_smoke = root / "bad-smoke.csv"
                insdn_smoke.to_csv(bad_smoke, index=False)
                with self.assertRaisesRegex(ValueError, "Smoke-test mismatch"):
                    check_model(model_path, bad_smoke)
            self.assertTrue((root / "run" / "completed.json").exists())
            with self.assertRaisesRegex(ValueError, "not empty"):
                run_three_models(args)

    def test_development_test_overlap_is_rejected_before_training(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            train, val, dev, test, _ = split_data(sample(0), 42)
            args = Namespace(out=tmp, trees=2, seed=42, folds=2, tune=False, dataset="fixture")
            with self.assertRaisesRegex(ValueError, "Development/test feature overlap"):
                run_experiment(args, train, val, dev, {"test": dev.iloc[:2]}, {})

    def test_single_dataset_tuning_still_writes_legacy_outputs(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            train, val, dev, test, _ = split_data(sample(0), 42)
            args = Namespace(out=tmp, trees=2, seed=42, folds=2, tune=True, dataset="fixture")
            with patch("train.estimators", side_effect=tiny_estimators), \
                 patch("train.version", return_value="fixture-only"), contextlib.redirect_stdout(io.StringIO()):
                scores = run_experiment(args, train, val, dev, {"test": test}, {})
            self.assertEqual(len(scores["test"]), 6)
            for name in ("comparison.csv", "comparison.json", "smoke_test.csv", "predictions.csv", "protocol.json"):
                self.assertTrue((Path(tmp) / name).exists(), name)
            with self.assertRaisesRegex(ValueError, "Completed run"):
                run_experiment(args, train, val, dev, {"test": test}, {})

    def test_summary_keeps_tests_separate_and_rejects_duplicate_seeds(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            roots = [Path(tmp) / name for name in ("seed7", "seed42")]
            for root, seed in zip(roots, (7, 42)):
                root.mkdir()
                protocol = {"arguments": {"max_per_class": 100, "trees": 2, "folds": 2,
                                           "tune": False, "combined": True, "seed": seed},
                            "task": "binary", "features": FEATURES, "sources": {}}
                (root / "protocol.json").write_text(json.dumps(protocol))
                (root / "completed.json").write_text(json.dumps({"configurations": ["M1", "M2", "M3"], "result_rows": 24}))
                pairs = [("M1", "cicids2017"), ("M2", "insdn"), ("M3", "cicids2017"), ("M3", "insdn")]
                pd.DataFrame([{"configuration": config, "test_dataset": source, "algorithm": algorithm,
                               "seed": seed, "accuracy": 0.7 if source == "cicids2017" else 0.9,
                               "macro_f1": 0.7 if source == "cicids2017" else 0.9}
                              for config, source in pairs for algorithm in ("dt", "rf", "xgb", "lgbm", "lr", "stacking")]
                             ).to_csv(root / "comparison_all.csv", index=False)
            with contextlib.redirect_stdout(io.StringIO()):
                summary = summarize_three_models(roots, Path(tmp) / "summary")
            self.assertEqual(len(summary), 24)
            self.assertEqual(summary.loc[("M3", "cicids2017", "stacking"), ("macro_f1", "mean")], 0.7)
            self.assertEqual(summary.loc[("M3", "insdn", "stacking"), ("macro_f1", "mean")], 0.9)
            with self.assertRaisesRegex(ValueError, "Repeated"):
                summarize_three_models([roots[0], roots[0]], Path(tmp) / "bad")
            protocol["arguments"]["trees"] = 99
            (roots[1] / "protocol.json").write_text(json.dumps(protocol))
            with self.assertRaisesRegex(ValueError, "different three-model protocols"):
                summarize_three_models(roots, Path(tmp) / "bad")
            (roots[0] / "completed.json").unlink()
            with self.assertRaisesRegex(ValueError, "Incomplete three-model run"):
                summarize_three_models(roots, Path(tmp) / "bad")

    def test_legacy_summary_rejects_binary_multiclass_mix(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            roots = [Path(tmp) / name for name in ("binary", "multiclass")]
            for root, task in zip(roots, ("binary", "multiclass")):
                root.mkdir()
                protocol = {"dataset": "CIC-IDS2017", "task": task,
                            "arguments": {"max_per_class": 100, "trees": 2, "folds": 2, "tune": False,
                                          "test_data": None, "seed": 42},
                            "data": {"sample_class_counts": {"BENIGN": 45, "ATTACK": 45}, "files": []}}
                (root / "protocol.json").write_text(json.dumps(protocol))
                (root / "comparison.json").write_text(json.dumps({"stacking": {"macro_f1": 0.7}}))
            argv = ["summarize.py", "--runs", *map(str, roots), "--out", str(Path(tmp) / "out")]
            with patch.object(sys, "argv", argv), self.assertRaisesRegex(ValueError, "binary and multiclass"):
                summarize_main()


if __name__ == "__main__":
    unittest.main()
