"""Host aggregation, Gaussian calibration and graph evidence checks."""
from pathlib import Path
import contextlib
import io
import json
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from host_features import COUNTS, HOST_FEATURES, aggregate_hosts, normalize_flows
from gaussian import evaluate_gaussian, fit_gaussian, split_windows, main as gaussian_main
from features import FEATURES
from feature_parity import compare_features
from botnet_graph import analyze_edges, export_graph


def flow(first=1, last=2, src="192.0.2.1", dst="192.0.2.2", label="BENIGN", port=80):
    return {"src_ip": src, "dst_ip": dst, "dst_port": port, "flow_first_epoch": first,
            "flow_last_epoch": last, "Label": label, **dict(zip(COUNTS, [3, 2, 30, 20, 1, 0]))}


def host_rows():
    return pd.DataFrame([{"window_epoch": w * 60, "window_seconds": 60, "host_ip": f"192.0.2.{h+1}",
                          "Label": "BENIGN", **{f: float(1+h%3) for f in HOST_FEATURES}}
                         for w in range(10) for h in range(6)])


class HostAnalysisTests(unittest.TestCase):
    def test_parity_rejects_feature_changes_and_unmatched_boundaries(self):
        frame = pd.DataFrame([{**flow(), "src_port": 12345, "protocol": "TCP", **{f: 1 for f in FEATURES}}])
        self.assertTrue(compare_features(frame, frame)["passed_this_capture"])
        changed = frame.copy()
        changed["Flow Duration"] = 100
        report = compare_features(frame, changed)
        self.assertFalse(report["passed_this_capture"])
        self.assertEqual(report["feature_errors"]["Flow Duration"]["max_abs_error"],99)
        changed["flow_first_epoch"] = 100
        report = compare_features(frame, changed)
        self.assertEqual(report["matched_flows"],0)
        self.assertFalse(report["passed_this_capture"])
    def test_completed_flow_windows_and_directional_counters(self):
        hosts, edges = aggregate_hosts(normalize_flows(pd.DataFrame([flow(), flow(3, 125, dst="192.0.2.3", port=443)])))
        row = hosts.loc[(hosts.host_ip == "192.0.2.1") & (hosts.window_epoch == 0)].iloc[0]
        self.assertEqual((row.flows_out, row.packets_sent, row.packets_received, row.bytes_sent, row.unique_dst_ports_out), (1,3,2,30,1))
        receiver = hosts.loc[hosts.host_ip == "192.0.2.2"].iloc[0]
        self.assertEqual((receiver.bytes_sent, receiver.bytes_received), (20,30))
        self.assertEqual(set(edges.window_epoch), {0,120})
        self.assertEqual(edges.flows.sum(), 2)

    def test_unknown_and_attack_labels_cover_incident_endpoints(self):
        hosts, _ = aggregate_hosts(normalize_flows(pd.DataFrame([flow(label="Probe"), flow(label=None)])))
        self.assertEqual(set(hosts.Label), {"UNKNOWN"})
        hosts, _ = aggregate_hosts(normalize_flows(pd.DataFrame([flow(label="Probe")])))
        self.assertEqual(set(hosts.Label), {"ATTACK"})

    def test_explicit_timestamp_formats_and_invalid_input(self):
        frame = pd.DataFrame([flow()]).drop(columns=["flow_first_epoch", "flow_last_epoch"])
        frame = frame.rename(columns={"src_ip":"Src IP", "dst_ip":"Dst IP", "dst_port":"Dst Port", "Total Fwd Packets":"Tot Fwd Pkts"})
        frame["Timestamp"], frame["Flow Duration"] = "05/02/2020 13:58", 2_000_000
        with self.assertRaisesRegex(ValueError, "explicit"):
            normalize_flows(frame)
        result = normalize_flows(frame, "%d/%m/%Y %H:%M|%d/%m/%Y %I:%M:%S %p")
        self.assertEqual(result.flow_last_epoch.iloc[0] - result.flow_first_epoch.iloc[0], 2)
        self.assertEqual(result.flow_first_epoch.iloc[0], pd.Timestamp("2020-02-05 13:58", tz="UTC").timestamp())
        with self.assertRaisesRegex(ValueError, "disagree"):
            normalize_flows(frame, "%d/%m/%Y %H:%M|%m/%d/%Y %H:%M")
        with self.assertRaises(ValueError):
            normalize_flows(pd.DataFrame([flow(src="bad-ip")]))
        with self.assertRaisesRegex(ValueError, "nonnegative"):
            normalize_flows(pd.DataFrame([{**flow(), COUNTS[0]:-1}]))
        mixed = pd.DataFrame([flow(), flow(first=2, last=1)])
        with self.assertRaisesRegex(ValueError, "end before"):
            normalize_flows(mixed)
        clean = normalize_flows(mixed, drop_invalid_time=True)
        self.assertEqual(len(clean),1)
        self.assertEqual(clean.attrs["invalid_time_rows_removed"],1)

    def test_gaussian_benign_only_calibration_and_temporal_isolation(self):
        train, val, test = split_windows(host_rows())
        self.assertLess(train.window_epoch.max(), val.window_epoch.min())
        self.assertLess(val.window_epoch.max(), test.window_epoch.min())
        attack = train.iloc[[0]].copy()
        attack["Label"], attack[HOST_FEATURES] = "ATTACK", 1000000
        model = fit_gaussian(train, val)
        other = fit_gaussian(pd.concat([train, attack]), val)
        np.testing.assert_allclose(model["model"].means_, other["model"].means_)
        self.assertEqual(model["threshold"], other["threshold"])
        test.loc[test.index[:3], HOST_FEATURES] = 1000000
        test.loc[test.index[:3], "Label"] = "ATTACK"
        predictions, report = evaluate_gaussian(model, test)
        self.assertEqual(set(predictions.iloc[:3].predicted_label), {"ATTACK"})
        self.assertEqual(report["false_negative_rate"], 0)
        with self.assertRaisesRegex(ValueError, "later"):
            evaluate_gaussian(model, val)
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            split_windows(pd.concat([host_rows(), host_rows().iloc[[0]]]))
        with self.assertRaisesRegex(ValueError, "BENIGN"):
            fit_gaussian(train.assign(Label="ATTACK"), val)

    def test_gaussian_flow_cli_uses_predefined_splits_and_records_signed_transform(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "tests") as tmp:
            root = Path(tmp)
            paths = []
            for i, name in enumerate(("train", "validation", "test")):
                frame = pd.DataFrame(np.arange(20*12).reshape(20,12)+i*1000,columns=FEATURES)
                frame.loc[0,"Flow Duration"] = -1-i
                frame["Label"] = ["ATTACK" if n%3==0 else "BENIGN" for n in range(20)]
                path=root/f"{name}.csv"
                frame.to_csv(path,index=False)
                paths.extend([f"--{name}",str(path)])
            argv=["gaussian.py",*paths,"--out",str(root/"out")]
            with patch.object(sys,"argv",argv), contextlib.redirect_stdout(io.StringIO()):
                gaussian_main()
            protocol=json.loads((root/"out"/"protocol.json").read_text())
            self.assertEqual(protocol["negative_measurements"],{"train":1,"validation":1,"test":1})
            self.assertTrue((root/"out"/"gaussian.joblib").exists())
            report=json.loads((root/"out"/"metrics.json").read_text())
            self.assertEqual(report["evaluated_rows"],20)

    def test_graph_windows_and_complete_export(self):
        edges = pd.DataFrame([{"window_epoch":0, "src_ip":"192.0.2.1", "dst_ip":f"192.0.2.{i}",
                               "flows":1, "packets":3, "bytes":30} for i in range(2,7)])
        _, candidates = analyze_edges(edges, 5)
        self.assertEqual(candidates.host_ip.tolist(), ["192.0.2.1"])
        self.assertTrue(candidates.candidate_fan_out.iloc[0])
        split = edges.copy()
        split.loc[3:, "window_epoch"] = 60
        self.assertTrue(analyze_edges(split,5)[1].empty)
        with tempfile.TemporaryDirectory(dir=ROOT / "tests") as tmp:
            self.assertEqual(export_graph(edges, Path(tmp),3), (6,5,3))
            graph = ET.parse(Path(tmp)/"communication.graphml")
            self.assertEqual(len(graph.findall(".//{http://graphml.graphdrawing.org/xmlns}node")),6)
            svg = ET.parse(Path(tmp)/"overview.svg")
            self.assertEqual(len(svg.findall(".//{http://www.w3.org/2000/svg}circle")),3)


if __name__ == "__main__":
    unittest.main()
