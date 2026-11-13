from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from detect import FlowDetector
from match_capture_labels import Reference, endpoints
from pcap_experiments import CONTRACT, reference_agrees
from train import session_folds


class PcapExperimentTests(unittest.TestCase):
    def test_oof_keeps_all_rows_of_a_session_together(self):
        sessions = pd.DataFrame({"session_id": ["a", "a", "b", "c", "c", "d"]})
        y = np.array([0, 0, 0, 1, 1, 1])
        folds = session_folds(sessions, y, 2, 42)
        self.assertEqual(sorted(np.concatenate([test for _, test in folds])), list(range(len(y))))
        for train, test in folds:
            self.assertFalse(set(sessions.iloc[train].session_id) & set(sessions.iloc[test].session_id))
            self.assertEqual(set(y[train]), {0, 1})
        with self.assertRaisesRegex(ValueError, "every model class"):
            session_folds(sessions.loc[[0, 1, 2, 3, 4]], y[:5], 2, 42)

    def test_reference_interval_requires_coverage_direction_and_label_agreement(self):
        row = SimpleNamespace(src_ip="192.0.2.1", src_port=1234, dst_ip="192.0.2.2", dst_port=80,
                              protocol="TCP", flow_first_epoch=62, flow_last_epoch=64)
        direction, key = endpoints(row.src_ip, row.src_port, row.dst_ip, row.dst_port, row.protocol)
        verified = Reference(direction, 60, 1, "DoS", (4e6,), "")
        conflict = Reference(direction, 62, 1, "Normal", (4e6,), "")
        reverse = Reference(direction[::-1], 60, 1, "DoS", (4e6,), "")
        self.assertTrue(reference_agrees(row, {key: [verified]}, "dos"))
        self.assertFalse(reference_agrees(row, {key: [verified, conflict]}, "dos"))
        self.assertFalse(reference_agrees(row, {key: [reverse]}, "dos"))
        row.flow_last_epoch = 66
        self.assertFalse(reference_agrees(row, {key: [verified]}, "dos"))

    def test_detector_checks_pcap_contract_before_creating_output(self):
        with self.assertRaisesRegex(ValueError, "flow contract"):
            FlowDetector({"flow_contract": CONTRACT}, None, idle=11)
