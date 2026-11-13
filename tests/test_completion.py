"""Saved-model truth scoring and periodic-flow candidates."""
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
from sklearn.dummy import DummyClassifier

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from beaconing import analyze_beaconing, main as beaconing_main
from evaluate_model import evaluate_model
from features import FEATURES


class SavedModelTests(unittest.TestCase):
    def fixture(self, root):
        frame = pd.DataFrame([[0]*len(FEATURES), [1]*len(FEATURES)], columns=FEATURES)
        model = DummyClassifier(strategy="constant", constant=0).fit(frame, [0, 1])
        artifact = {"model": model, "classes": ["ATTACK", "BENIGN"], "features": FEATURES, "task": "binary"}
        model_path, csv = root / "model.joblib", root / "test.csv"
        joblib.dump(artifact, model_path)
        frame["Label"], frame["ExpectedPrediction"] = [" normal ", " Probe "], "ATTACK"
        frame.to_csv(csv, index=False)
        return model_path, csv

    def test_truth_accuracy_differs_from_prediction_match_without_refitting(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "tests") as tmp:
            root = Path(tmp)
            model, csv = self.fixture(root)
            with patch.object(DummyClassifier, "fit", side_effect=AssertionError("Do not refit")), contextlib.redirect_stdout(io.StringIO()):
                summary = evaluate_model(model, csv, root / "out")
            self.assertEqual(summary["accuracy"], .5)
            self.assertEqual(summary["benign_false_positive_rate"], 1)
            self.assertEqual(summary["attack_false_negative_rate"], 0)
            self.assertIsNone(summary["fit_seconds_final_refit"])
            self.assertEqual(len(pd.read_csv(root / "out/errors.csv")), 1)
            self.assertEqual(json.loads((root / "out/metrics.json").read_text())["rows"], 2)
            self.assertEqual(len(json.loads((root / "out/protocol.json").read_text())["model_sha256"]), 64)
            with self.assertRaisesRegex(ValueError, "new --out"):
                evaluate_model(model, csv, root / "out")

    def test_truth_is_required_and_unknown_labels_are_not_scored(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "tests") as tmp:
            root = Path(tmp)
            model, csv = self.fixture(root)
            with self.assertRaisesRegex(ValueError, "not ground truth"):
                evaluate_model(model, csv, root / "out", "ExpectedPrediction")
            frame = pd.read_csv(csv)
            frame["Label"] = "UNKNOWN"
            frame.to_csv(csv, index=False)
            with self.assertRaisesRegex(ValueError, "UNKNOWN"):
                evaluate_model(model, csv, root / "out")
            self.assertFalse((root / "out").exists())
            frame.drop(columns="Label").to_csv(csv, index=False)
            with self.assertRaisesRegex(ValueError, "label column"):
                evaluate_model(model, csv, root / "out")

    def test_ground_truth_cli(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "tests") as tmp:
            root = Path(tmp)
            model, csv = self.fixture(root)
            frame = pd.read_csv(csv).rename(columns={"Label": "GroundTruth"})
            frame.to_csv(csv, index=False)
            result = subprocess.run([sys.executable, str(ROOT / "src/evaluate_model.py"), "--model", str(model),
                                     "--csv", str(csv), "--label-column", "GroundTruth", "--out", str(root / "out")],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Ground-truth Accuracy: 50.00%", result.stdout)


class BeaconingTests(unittest.TestCase):
    def rows(self, times, port=443, protocol="TCP"):
        return pd.DataFrame([{"src_ip": "192.0.2.1", "dst_ip": "192.0.2.2", "dst_port": port,
                              "protocol": protocol, "flow_first_epoch": float(t)} for t in times])

    def test_periodicity_requires_sufficient_distinct_observations(self):
        regular = self.rows(np.arange(7)*10)
        frame = pd.concat([regular, regular.iloc[[0]], self.rows([0, 1, 2, 5, 20, 60, 100], 80),
                           self.rows([0]*10, 53, "UDP"), self.rows([0, 10, 20], 443, "UDP")], ignore_index=True)
        stats = analyze_beaconing(frame)
        selected = stats.loc[stats.candidate]
        self.assertEqual(selected[["dst_port", "protocol"]].values.tolist(), [[443, "TCP"]])
        self.assertEqual(selected.duplicate_starts.iloc[0], 1)
        self.assertEqual(selected.interval_cv.iloc[0], 0)
        pd.testing.assert_frame_equal(stats, analyze_beaconing(frame.sample(frac=1, random_state=7)))

    def test_invalid_timing_and_thresholds_fail(self):
        frame = self.rows([0, 10, 20])
        for kwargs in ({"min_connections": 2}, {"min_interval": 0}, {"max_cv": float("nan")}):
            with self.assertRaises(ValueError):
                analyze_beaconing(frame, **kwargs)
        frame.loc[0, "flow_first_epoch"] = float("inf")
        with self.assertRaisesRegex(ValueError, "finite"):
            analyze_beaconing(frame)

    def test_cli_discloses_unsupported_protocols_and_preserves_outputs(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "tests") as tmp:
            root = Path(tmp)
            frame = self.rows(np.arange(7)*10)
            frame["flow_last_epoch"] = frame.flow_first_epoch + .1
            frame["Label"] = "BENIGN"
            for feature in ["Total Fwd Packets", "Total Backward Packets", "Total Length of Fwd Packets", "Total Length of Bwd Packets", "SYN Flag Count", "RST Flag Count"]:
                frame[feature] = 1
            frame = pd.concat([frame, frame.iloc[[0]].assign(protocol="0")], ignore_index=True)
            frame.to_csv(root / "flows.csv", index=False)
            argv = ["beaconing.py", "--csv", str(root / "flows.csv"), "--out", str(root / "out")]
            with patch.object(sys, "argv", argv), contextlib.redirect_stdout(io.StringIO()):
                beaconing_main()
            summary = json.loads((root / "out/summary.json").read_text())
            self.assertEqual(summary["candidate_pairs"], 1)
            self.assertEqual(summary["unsupported_protocol_rows"], {"0": 1})
            self.assertEqual(summary["input_flows"], 7)
            with patch.object(sys, "argv", argv), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                beaconing_main()
