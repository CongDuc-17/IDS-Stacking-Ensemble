"""Meta search uses train OOF and validation, never test labels or in-sample probabilities."""
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
from sklearn.model_selection import cross_val_predict

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from train import run_experiment, split_data
from dataset import numeric_features
from features import FEATURES
from test_training import sample, tiny_estimators
from summarize import main as summarize_main


class StackSearchTests(unittest.TestCase):
    def test_binary_and_multiclass_search_use_training_only_oof(self):
        for multiclass in (False, True):
            with self.subTest(multiclass=multiclass), tempfile.TemporaryDirectory(dir=ROOT / "tests") as tmp:
                frame = sample()
                if multiclass:
                    third = sample(20000).iloc[:45].assign(Label="Other")
                    frame = pd.concat([frame, third], ignore_index=True)
                train, val, dev, test, _ = split_data(frame, 42)
                args = Namespace(out=tmp, trees=2, seed=42, folds=2, tune=False, stack_search=True, dataset="fixture")
                with patch("train.estimators", side_effect=tiny_estimators), \
                     patch("train.cross_val_predict", wraps=cross_val_predict) as oof, contextlib.redirect_stdout(io.StringIO()):
                    run_experiment(args, train, val, dev, test, {"task": "multiclass"})
                self.assertEqual(oof.call_count, 4)
                for call in oof.call_args_list:
                    pd.testing.assert_frame_equal(call.args[1], numeric_features(train))
                    self.assertEqual(call.kwargs["method"], "predict_proba")
                selected = json.loads((Path(tmp) / "selection.json").read_text())
                candidates = {name: item for name, item in selected.items() if name.startswith("stack_")}
                self.assertEqual(len(candidates), 12)
                protocol = json.loads((Path(tmp) / "protocol.json").read_text())
                for part, expected in (("train", train), ("validation", val), ("test", test)):
                    actual = pd.read_csv(Path(tmp) / "splits" / f"{part}.csv")
                    pd.testing.assert_frame_equal(numeric_features(actual).reset_index(drop=True), numeric_features(expected).reset_index(drop=True))
                winner = candidates["stack_"+protocol["selected_stack"]]
                self.assertEqual(winner["validation_macro_f1"], max(item["validation_macro_f1"] for item in candidates.values()))
                artifact = joblib.load(Path(tmp) / "models/stacking_ids.joblib")
                self.assertFalse(artifact["model"].passthrough)
                expected_meta_columns = 9 if multiclass else 3
                self.assertEqual(artifact["model"].transform(numeric_features(test)).shape[1], expected_meta_columns)
                self.assertEqual(artifact["model"].final_estimator_.n_features_in_, expected_meta_columns)
                self.assertEqual(artifact["model"].final_estimator_.C, winner["meta_C"])
                self.assertEqual(artifact["model"].final_estimator_.class_weight, winner["meta_class_weight"])
                with np.load(Path(tmp) / "stack_oof.npz") as saved:
                    self.assertEqual(saved["rf"].shape, (len(train), 3 if multiclass else 2))
                smoke = pd.read_csv(Path(tmp) / "smoke_test.csv")
                prediction = np.asarray(artifact["classes"])[artifact["model"].predict(numeric_features(smoke))]
                self.assertEqual(prediction.tolist(), smoke.ExpectedPrediction.tolist())

    def test_summary_rejects_mixed_search_settings(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "tests") as tmp:
            roots = [Path(tmp) / name for name in ["fixed", "search"]]
            for root, enabled in zip(roots, [False, True]):
                root.mkdir()
                protocol = {"dataset": "fixture", "arguments": {"stack_search": enabled, "seed": 42}}
                (root / "protocol.json").write_text(json.dumps(protocol))
                (root / "comparison.json").write_text(json.dumps({"stacking": {"macro_f1": .5}}))
            argv = ["summarize.py", "--runs", *map(str, roots), "--out", str(Path(tmp) / "out")]
            with patch.object(sys, "argv", argv), self.assertRaisesRegex(ValueError, "stack-search"):
                summarize_main()


if __name__ == "__main__":
    unittest.main()
