"""Lab labels and independent-reference parity; synthetic fixtures are not lab evidence."""
import contextlib
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from evaluate_lab import evaluate, main as evaluate_main
from feature_parity import compare_features, normalize_reference, main as parity_main
from features import FEATURES
from taxonomy import manifest


def flow():
    return {**dict(zip(FEATURES, [80, 100000, 2, 1, 3, 4, 0, 2, 0, 0, 1, 0])),
            "src_ip": "192.0.2.1", "src_port": 12345, "dst_ip": "192.0.2.2", "dst_port": 80,
            "protocol": "TCP", "flow_first_epoch": 1.123456}


class DeploymentTests(unittest.TestCase):
    def test_lab_matches_live_timestamp_jitter_without_reusing_or_guessing_flows(self):
        epoch = 1794539522.267002
        truth = pd.DataFrame([
            {**flow(), "flow_first_epoch": epoch, "Label": "BENIGN"},
            {**flow(), "flow_first_epoch": epoch + 10, "Label": "RECON"},
            {**flow(), "flow_first_epoch": epoch + 20, "Label": "RECON"},
            {**flow(), "flow_first_epoch": epoch + 30, "Label": "RECON"},
            {**flow(), "flow_first_epoch": epoch + 30.000003, "Label": "RECON"},
        ])
        predictions = pd.DataFrame([
            {**flow(), "flow_first_epoch": epoch + 30.0000015, "predicted_label": "RECON"},
            {**flow(), "flow_first_epoch": epoch + 20.00001, "predicted_label": "RECON"},
            {**flow(), "flow_first_epoch": epoch + 10.000001, "predicted_label": "RECON"},
            {**flow(), "flow_first_epoch": epoch + .0000012, "predicted_label": "BENIGN"},
        ])
        report = evaluate(predictions, truth)
        self.assertEqual(report["confusion_matrix"], [[1, 0], [0, 1]])
        self.assertEqual(report["truth_flows_without_prediction"], 3)
        self.assertEqual(report["predicted_flows_without_truth"], 2)
        swapped = evaluate(truth.rename(columns={"Label": "predicted_label"}),
                           predictions.rename(columns={"predicted_label": "Label"}))
        self.assertEqual(swapped["matched_flows"], 2)

    def test_lab_raw_labels_require_explicit_source_and_map_to_model_families(self):
        predictions = pd.DataFrame([{**flow(), "predicted_label": "RECON"}])
        truth = pd.DataFrame([{**flow(), "Label": "PortScan"}])
        artifact = {"task": "multiclass", "classes": ["BENIGN", "RECON"], "label_taxonomy": manifest()}
        with self.assertRaisesRegex(ValueError, "Truth labels are absent"):
            evaluate(predictions, truth, artifact=artifact)
        report = evaluate(predictions, truth, artifact=artifact, truth_source="cicids2017")
        self.assertEqual(report["classification_report_matched_only"]["accuracy"], 1)
        self.assertEqual(report["label_protocol"]["taxonomy_sha256"], manifest()["sha256"])
        with self.assertRaisesRegex(ValueError, "requires --model"):
            evaluate(predictions, truth, truth_source="cicids2017")
        with self.assertRaisesRegex(ValueError, "unmapped labels"):
            evaluate(predictions, truth, artifact=artifact, truth_source="insdn")

    def test_lab_unknown_scenario_needs_binary_mode_and_wrong_model_is_rejected(self):
        artifact = {"task": "multiclass", "classes": ["BENIGN", "RECON"], "label_taxonomy": manifest()}
        predictions = pd.DataFrame([{**flow(), "predicted_label": "RECON"}])
        truth = pd.DataFrame([{**flow(), "Label": "SYN-LAB"}])
        with self.assertRaisesRegex(ValueError, "Truth labels are absent"):
            evaluate(predictions, truth, artifact=artifact)
        report = evaluate(predictions, truth, artifact=artifact, binary_only=True)
        self.assertTrue(report["label_protocol"]["binary_only"])
        self.assertEqual(report["binary_detection_matched_only"]["ATTACK"]["recall"], 1)
        with self.assertRaisesRegex(ValueError, "Prediction labels are absent"):
            evaluate(predictions.assign(predicted_label="WRONG_MODEL"), truth, artifact=artifact, binary_only=True)
        binary = {"task": "binary", "classes": ["BENIGN", "ATTACK"]}
        report = evaluate(predictions.assign(predicted_label="ATTACK"), truth.assign(Label="PortScan"), artifact=binary)
        self.assertEqual(report["classification_report_matched_only"]["accuracy"], 1)

    def test_lab_metrics_do_not_overwrite_previous_results(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "tests") as tmp:
            folder = Path(tmp)
            pd.DataFrame([{**flow(), "predicted_label": "BENIGN"}]).to_json(folder / "pred.jsonl", orient="records", lines=True)
            pd.DataFrame([{**flow(), "Label": "BENIGN"}]).to_csv(folder / "truth.csv", index=False)
            (folder / "metrics.json").write_text("previous run", encoding="utf-8")
            argv = ["evaluate_lab.py", "--predictions", str(folder / "pred.jsonl"), "--truth", str(folder / "truth.csv"), "--out", str(folder / "metrics.json")]
            with patch.object(sys, "argv", argv), self.assertRaises(FileExistsError):
                evaluate_main()
            self.assertEqual((folder / "metrics.json").read_text(encoding="utf-8"), "previous run")

    def test_reference_normalization_has_explicit_timezone_and_preserves_precision(self):
        expected = datetime(2026, 11, 10, 0, 0, 1, 123456, tzinfo=timezone.utc).timestamp()
        normalized = pd.DataFrame([{**flow(), "flow_first_epoch": expected}])
        raw = normalized.drop(columns=["dst_port", "flow_first_epoch"]).rename(columns={
            "src_ip": "Src IP", "src_port": "Src Port", "dst_ip": "Dst IP", "protocol": "Protocol", "Destination Port": "Dst Port"})
        raw["Protocol"] = 6
        raw["Timestamp"] = "10/11/2026 07:00:01.123456"
        reference = normalize_reference(raw, "%d/%m/%Y %H:%M:%S.%f", "Asia/Ho_Chi_Minh")
        self.assertAlmostEqual(reference.flow_first_epoch.iloc[0], expected, places=6)
        self.assertTrue(compare_features(reference, normalized)["passed_this_capture"])
        with self.assertRaisesRegex(ValueError, "explicit --timestamp-format and --timezone"):
            normalize_reference(raw, "%d/%m/%Y %H:%M:%S.%f", None)
        with self.assertRaisesRegex(ValueError, "unsupported protocols"):
            normalize_reference(raw.assign(Protocol=1), "%d/%m/%Y %H:%M:%S.%f", "UTC")

    def test_parity_rejects_same_input_and_records_failure_and_hashes(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "tests") as tmp:
            root = Path(tmp)
            pd.DataFrame([flow()]).to_csv(root / "reference.csv", index=False)
            pd.DataFrame([{**flow(), "SYN Flag Count": 99}]).to_csv(root / "candidate.csv", index=False)
            args = ["feature_parity.py", "--reference", str(root / "reference.csv"), "--candidate", str(root / "reference.csv"), "--out", str(root / "same.json")]
            with patch.object(sys, "argv", args), contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as error:
                parity_main()
            self.assertEqual(error.exception.code, 1)
            self.assertFalse((root / "same.json").exists())
            args[4] = str(root / "candidate.csv")
            args[6] = str(root / "failed.json")
            with patch.object(sys, "argv", args), contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
                parity_main()
            report = json.loads((root / "failed.json").read_text(encoding="utf-8"))
            self.assertFalse(report["passed_this_capture"])
            self.assertEqual(report["feature_errors"]["SYN Flag Count"]["mismatch_rows"], 1)
            self.assertEqual(set(report["provenance"]["inputs"]), {"reference", "candidate"})


if __name__ == "__main__":
    unittest.main()
