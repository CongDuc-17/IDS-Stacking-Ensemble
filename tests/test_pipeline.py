import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import subprocess
from unittest.mock import patch
import numpy as np
import pandas as pd
from scapy.all import IP, TCP, UDP, ICMP, Raw

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from dataset import numeric_features
from detect import FlowDetector, csv_smoke, live_capture, validate_artifact
from evaluate_lab import evaluate
from features import FEATURES
from flows import FlowTable


class FixedModel:
    classes_ = np.array([0, 1])
    def predict_proba(self, frame):
        return np.tile([0.8, 0.2], (len(frame), 1))


def packet(t, reverse=False, sport=1234, flags="S"):
    addresses = ("192.0.2.1", "192.0.2.2")
    if reverse:
        addresses = addresses[::-1]
    pkt = IP(src=addresses[0], dst=addresses[1]) / TCP(
        sport=80 if reverse else sport, dport=sport if reverse else 80, flags=flags) / Raw(b"abc")
    pkt.time = t
    return pkt


class PipelineTests(unittest.TestCase):
    def test_nonfinite_numeric(self):
        frame = pd.DataFrame([[1] * len(FEATURES)], columns=FEATURES)
        frame["Flow Duration"] = np.inf
        self.assertTrue(np.isnan(numeric_features(frame).iloc[0]["Flow Duration"]))

    def test_bidirectional_flow_and_flags(self):
        emitted = []
        table = FlowTable(lambda row, meta: emitted.append((row, meta)))
        table.process(packet(100))
        table.process(packet(101, reverse=True, flags="SA"))
        table.flush(101, force=True)
        row, meta = emitted[0]
        self.assertEqual(list(row), FEATURES)
        self.assertEqual(row["Total Fwd Packets"], 1)
        self.assertEqual(row["Total Backward Packets"], 1)
        self.assertEqual(row["Total Length of Bwd Packets"], 3)
        self.assertEqual(row["Flow Duration"], 1_000_000)
        self.assertEqual(row["SYN Flag Count"], 2)
        self.assertEqual(row["ACK Flag Count"], 1)
        self.assertEqual(meta["src_ip"], "192.0.2.1")

    def test_timeout_before_same_key_packet_and_capacity(self):
        emitted = []
        table = FlowTable(lambda row, meta: emitted.append((row, meta)), idle=2, maximum=5, max_flows=1)
        table.process(packet(100))
        table.process(packet(102))
        self.assertEqual(len(emitted), 1)
        self.assertEqual(emitted[0][0]["Total Fwd Packets"], 1)
        table.process(packet(103, sport=1235))
        self.assertEqual(table.capacity_evictions, 1)
        self.assertEqual(len(table.flows), 1)
        self.assertEqual(emitted[-1][1]["flow_close_reason"], "capacity")
        table.flush(110)
        self.assertEqual(len(table.flows), 0)

    def test_maximum_age_and_unsupported_packets(self):
        emitted = []
        table = FlowTable(lambda row, meta: emitted.append((row, meta)), idle=10, maximum=2)
        table.process(packet(0))
        table.process(packet(1))
        table.process(packet(2))
        self.assertEqual(emitted[0][0]["Total Fwd Packets"], 2)
        bad = IP() / ICMP()
        bad.time = 3
        table.process(bad)
        self.assertEqual(table.unsupported_packets, 1)
        with self.assertRaises(ValueError):
            FlowTable(lambda *_: None, idle=float("nan"))

    def test_smoke_mismatch_fails_and_benign_is_logged(self):
        art = {"model": FixedModel(), "classes": ["BENIGN", "Probe"], "features": FEATURES}
        validate_artifact(art)
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            frame = pd.DataFrame([[0] * len(FEATURES)], columns=FEATURES)
            frame["ExpectedPrediction"] = "Probe"
            path = Path(tmp) / "smoke.csv"
            frame.to_csv(path, index=False)
            with self.assertRaises(ValueError):
                with contextlib.redirect_stdout(io.StringIO()):
                    csv_smoke(art, path)
            detector = FlowDetector(art, tmp)
            detector.flow_table.process(packet(100))
            detector.flow_table.flush(101, force=True)
            record = json.loads(detector.logfile.read_text())
            self.assertFalse(record["is_attack"])
            self.assertEqual(detector.total_flows, 1)
            self.assertEqual(detector.alerts, 0)

    def test_capture_queue_bounded_and_drained_on_stop(self):
        filters = []
        class FakeSniffer:
            def __init__(self, **kwargs):
                self.kwargs, self.running = kwargs, False
                filters.append(kwargs["filter"])
            def start(self):
                self.kwargs["started_callback"]()
                for i in range(3):
                    self.kwargs["prn"](packet(100, sport=1234+i))
            def join(self):
                pass
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp, patch("scapy.all.AsyncSniffer", FakeSniffer):
            detector = FlowDetector({"model": FixedModel(), "classes": ["BENIGN", "Probe"]}, tmp)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                live_capture(detector, "test0", 1, "tcp port 8080")
            self.assertEqual(detector.total_flows, 1)
            self.assertIn("application_queue_dropped_packets=2", output.getvalue())
            self.assertEqual(filters, ["ip and (tcp or udp) and (tcp port 8080)"])

    def test_detector_reserves_log_and_rejects_existing_runs(self):
        artifact = {"model": FixedModel(), "classes": ["BENIGN", "Probe"]}
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            detector = FlowDetector(artifact, tmp)
            self.assertTrue(detector.logfile.exists())
            with self.assertRaisesRegex(FileExistsError, "new --out"):
                FlowDetector(artifact, tmp)
            detector.flow_table.process(packet(100))
            detector.flow_table.flush(101, force=True)
            original = detector.logfile.read_bytes()
            with self.assertRaisesRegex(FileExistsError, "new --out"):
                FlowDetector(artifact, tmp)
            self.assertEqual(detector.logfile.read_bytes(), original)
            detector.flow_table.process(packet(120))
            detector.flow_table.flush(121, force=True)
            self.assertEqual(len(detector.logfile.read_text().splitlines()), 2)

    def test_lab_report_matches_ground_truth_and_reports_missing(self):
        keys = dict(zip(["src_ip", "src_port", "dst_ip", "dst_port", "protocol", "flow_first_epoch"],
                        ["192.0.2.1", 1234, "192.0.2.2", 80, "TCP", 100.0]))
        truth = pd.DataFrame([{**keys, "Label": "Probe"}, {**keys, "src_port": 1235, "Label": "BENIGN"}])
        predictions = pd.DataFrame([{**keys, "predicted_label": "BENIGN", "inference_ms": 3.0}])
        report = evaluate(predictions, truth)
        self.assertEqual(report["attack_false_negative_rate"], 1)
        self.assertEqual(report["truth_flows_without_prediction"], 1)
        self.assertIsNone(report["benign_false_positive_rate"])

    def test_lab_report_normalizes_labels_without_mutating_inputs(self):
        keys = dict(zip(["src_ip", "src_port", "dst_ip", "dst_port", "protocol", "flow_first_epoch"],
                        ["192.0.2.1", 1234, "192.0.2.2", 80, "TCP", 100.0]))
        truth = pd.DataFrame([{**keys, "src_port": 1234+i, "Label": label}
                              for i, label in enumerate([" BENIGN ", " NORMAL ", " Probe ", " attack "])])
        predictions = truth.drop(columns="Label").assign(predicted_label=[" attack ", " benign ", "Probe", "ATTACK"])
        original_truth, original_predictions = truth.copy(), predictions.copy()
        report = evaluate(predictions, truth)
        self.assertEqual(report["benign_false_positive_rate"], .5)
        self.assertEqual(report["attack_false_negative_rate"], 0)
        self.assertEqual(report["confusion_labels"], ["ATTACK", "BENIGN", "Probe"])
        self.assertEqual(report["binary_detection_matched_only"]["ATTACK"]["support"], 2)
        pd.testing.assert_frame_equal(truth, original_truth)
        pd.testing.assert_frame_equal(predictions, original_predictions)

    def test_lab_report_rejects_unknown_or_missing_labels(self):
        keys = dict(zip(["src_ip", "src_port", "dst_ip", "dst_port", "protocol", "flow_first_epoch"],
                        ["192.0.2.1", 1234, "192.0.2.2", 80, "TCP", 100.0]))
        for column in ("Label", "predicted_label"):
            for label in (None, np.nan, pd.NA, "", " \t ", "UNKNOWN", " unknown ", " NaN ", " null ", "None"):
                with self.subTest(column=column, label=label):
                    truth = pd.DataFrame([{**keys, "Label": "Probe"}])
                    predictions = pd.DataFrame([{**keys, "predicted_label": "ATTACK"}])
                    target = truth if column == "Label" else predictions
                    target[column] = label
                    with self.assertRaisesRegex(ValueError, column):
                        evaluate(predictions, truth)

    def test_pcap_cli_uses_the_same_rows_as_live_extractor(self):
        from scapy.all import wrpcap
        root = Path(__file__).resolve().parents[1]
        emitted = []
        table = FlowTable(lambda row, meta: emitted.append(row))
        packets = [packet(100), packet(101, reverse=True, flags="SA"), packet(120)]
        for pkt in packets:
            table.process(pkt)
        table.flush(120, force=True)
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            capture, target = Path(tmp) / "sample.pcap", Path(tmp) / "flows.csv"
            wrpcap(str(capture), packets)
            result = subprocess.run([sys.executable, str(root / "src/extract.py"), "--pcap", str(capture),
                                     "--out", str(target), "--label", "BENIGN"], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            frame = pd.read_csv(target)
            pd.testing.assert_frame_equal(numeric_features(frame), numeric_features(pd.DataFrame(emitted)), check_dtype=False)
            self.assertTrue((frame.Label == "BENIGN").all())


if __name__ == "__main__":
    unittest.main()
