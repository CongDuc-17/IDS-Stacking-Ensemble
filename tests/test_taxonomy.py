"""Mapping precedes sampling; combined multiclass uses isolated shared tests."""
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
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from dataset import read_sample
from features import FEATURES
from taxonomy import LABELS, manifest, map_labels
from three_models import SOURCES, feature_hashes, prepare_splits, run_three_models
from test_three_models import sample, tiny_estimators
from check_model import check_model
from evaluate_model import evaluate_model
from summarize import summarize_three_models
from train import evaluate


def family_fixture(offset, source):
    frame = sample(offset)
    frame["Label"] = frame.Label.map({"BENIGN": "BENIGN" if source == "cicids2017" else "Normal",
                                     "ATTACK": "PortScan" if source == "cicids2017" else "Probe"})
    specific = sample(offset + 3000).iloc[:45].assign(Label="Infiltration" if source == "cicids2017" else "U2R")
    return pd.concat([frame, specific], ignore_index=True)


class TaxonomyTests(unittest.TestCase):
    def test_source_macro_f1_uses_fixed_truth_classes_despite_extra_predictions(self):
        class Fixture:
            def predict(self, x):
                return np.array([0, 2, 1, 1])
        with tempfile.TemporaryDirectory(dir=ROOT / "tests") as tmp, contextlib.redirect_stdout(io.StringIO()):
            scores, _ = evaluate("fixture", Fixture(), None, np.array([0, 0, 1, 1]),
                                 np.array(["BENIGN", "DOS", "BOT"]), Path(tmp), None,
                                 metric_labels=np.array([0, 1]))
        self.assertAlmostEqual(scores["macro_f1"], (2 / 3 + 1) / 2)
        self.assertEqual(scores["macro_f1_classes_in_truth"], ["BENIGN", "DOS"])

    def test_all_declared_labels_and_known_dash_variants(self):
        for source, mapping in LABELS.items():
            self.assertEqual(map_labels(pd.Series(list(mapping)), source).tolist(), list(mapping.values()))
        labels = pd.Series(["Web Attack \ufffd Brute Force", "Web Attack – XSS", " Web  Attack — Sql Injection "])
        self.assertEqual(map_labels(labels, "cicids2017").tolist(), ["BRUTE_FORCE", "WEB_ATTACK", "WEB_ATTACK"])
        self.assertNotEqual(LABELS["cicids2017"]["Infiltration"], LABELS["insdn"]["U2R"])
        self.assertNotEqual(LABELS["cicids2017"]["Heartbleed"], LABELS["insdn"]["DoS"])
        for source, label in (("insdn", "FTP-Patator"), ("cicids2017", "UnknownAttack")):
            with self.assertRaisesRegex(ValueError, "unmapped labels"):
                map_labels(pd.Series([label]), source)
        with self.assertRaisesRegex(ValueError, "Unknown taxonomy source"):
            map_labels(pd.Series(["BENIGN"]), "other")

    def test_rare_subtypes_merge_before_sampling_and_keep_raw_labels(self):
        frame = sample(0)
        frame.loc[frame.Label == "ATTACK", "Label"] = "DoS Hulk"
        frame.loc[45, "Label"] = "DoS GoldenEye"
        with tempfile.TemporaryDirectory(dir=ROOT / "tests") as tmp:
            csv = Path(tmp) / "data.csv"
            frame.to_csv(csv, index=False)
            result, meta = read_sample(csv, 30, label_source="cicids2017")
            with self.assertRaisesRegex(ValueError, "not both"):
                read_sample(csv, 30, binary=True, label_source="cicids2017")
            frame.loc[45, "Label"] = "DoS unknown"
            frame.to_csv(csv, index=False)
            with self.assertRaisesRegex(ValueError, "unmapped labels"):
                read_sample(csv, 30, label_source="cicids2017")
        self.assertEqual(meta["mapped_class_counts"], {"BENIGN": 45, "DOS": 45})
        self.assertEqual(meta["raw_class_counts"]["DoS GoldenEye"], 1)
        self.assertEqual(meta["label_taxonomy"], manifest())
        self.assertEqual(result.Label.value_counts().to_dict(), {"BENIGN": 30, "DOS": 30})
        self.assertIn("RawLabel", result)

    def test_global_family_conflicts_and_source_specific_classes(self):
        cic = family_fixture(0, "cicids2017")
        insdn = family_fixture(10000, "insdn")
        for source, frame in zip(SOURCES, (cic, insdn)):
            frame["Label"] = map_labels(frame.Label, source)
        insdn = pd.concat([insdn, cic.iloc[[0]], cic.iloc[[1]].assign(Label="U2R")], ignore_index=True)
        splits, meta = prepare_splits(cic, insdn, binary=False)
        self.assertEqual(meta["conflicting_rows_removed"], 2)
        self.assertEqual(meta["duplicate_rows_removed"], 1)
        seen = set()
        for source, parts in splits.items():
            expected = {"BENIGN", "RECON", "INFILTRATION" if source == "cicids2017" else "U2R"}
            for frame in parts.values():
                self.assertEqual(set(frame.Label), expected)
                hashes = set(feature_hashes(frame))
                self.assertFalse(seen & hashes)
                seen |= hashes
        with self.assertRaisesRegex(ValueError, "both binary labels"):
            prepare_splits(cic, insdn)

    def test_multiclass_orchestration_exports_mapping_model_and_scores(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "tests") as tmp:
            root = Path(tmp)
            for source, offset in zip(SOURCES, (0, 10000)):
                family_fixture(offset, source).to_csv(root / f"{source}.csv", index=False)
            args = Namespace(cic_data=str(root / "cicids2017.csv"), insdn_data=str(root / "insdn.csv"),
                             out=str(root / "run"), max_per_class=100, trees=2, folds=2, seed=42,
                             combined=True, multiclass=True, tune=False, stack_search=True)
            with patch("train.estimators", side_effect=tiny_estimators), contextlib.redirect_stdout(io.StringIO()):
                result = run_three_models(args)
                for source in SOURCES:
                    check_model(root / "run/M3/models/stacking_ids.joblib", root / f"run/M3/{source}/smoke_test.csv")
                scores = evaluate_model(root / "run/M3/models/stacking_ids.joblib",
                                        root / "run/splits/insdn/test.csv", root / "reload")
            self.assertEqual(len(result), 30)
            self.assertEqual(scores["macro_f1"], result.query("configuration == 'M3' and test_dataset == 'insdn' and algorithm == 'stacking'").iloc[0].macro_f1)
            protocol = json.loads((root / "run/protocol.json").read_text(encoding="utf-8"))
            self.assertEqual(protocol["label_taxonomy"], manifest())
            mapping = pd.read_csv(root / "run/label_mapping.csv")
            self.assertEqual(mapping.raw_rows.sum(), 270)
            support = pd.read_csv(root / "run/family_support.csv", index_col="family")
            self.assertEqual(support.loc["U2R", "cicids2017"], 0)
            artifact = joblib.load(root / "run/M3/models/stacking_ids.joblib")
            self.assertEqual(artifact["task"], "multiclass")
            self.assertEqual(artifact["label_taxonomy"], manifest())
            self.assertEqual(set(artifact["classes"]), {"BENIGN", "RECON", "INFILTRATION", "U2R"})
            self.assertEqual(artifact["features"], FEATURES)
            self.assertEqual(protocol["m3_stack_variant"], "trees")
            self.assertEqual([name for name, _ in artifact["model"].estimators], ["rf", "xgb", "lgbm"])
            self.assertEqual(type(artifact["model"].final_estimator_).__name__, "LogisticRegression")
            selection = json.loads((root / "run/M3/selection.json").read_text(encoding="utf-8"))
            candidates = [name for name in selection if name.startswith("stack_")]
            self.assertEqual(len(candidates), 6)
            self.assertTrue(all(name.startswith("stack_trees_") for name in candidates))
            for source, config in zip(SOURCES, ("M1", "M2")):
                single = json.loads((root / f"run/{config}/protocol.json").read_text(encoding="utf-8"))
                combined = json.loads((root / "run/M3/protocol.json").read_text(encoding="utf-8"))
                self.assertEqual(single["split_feature_sha256"][source], combined["split_feature_sha256"][source])
            with self.assertRaisesRegex(ValueError, "not empty"):
                run_three_models(args)
            other = root / "other"
            other.mkdir()
            for file in ("protocol.json", "completed.json", "comparison_all.csv"):
                (other / file).write_bytes((root / "run" / file).read_bytes())
            protocol["label_taxonomy"]["version"] = "different-taxonomy"
            (other / "protocol.json").write_text(json.dumps(protocol), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "different three-model protocols"):
                summarize_three_models([root / "run", other], root / "summary")


if __name__ == "__main__":
    unittest.main()
