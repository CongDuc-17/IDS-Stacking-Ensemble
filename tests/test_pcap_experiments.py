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
from train import CLASSES, build_stack, session_folds


class PcapExperimentTests(unittest.TestCase):
    def test_oof_keeps_all_rows_of_a_session_together(self):
        sessions = pd.Series(["a", "a", "b", "b", "c", "c", "d", "d"])
        y = np.array([0, 1, 0, 1, 2, 3, 2, 3])
        folds = session_folds(sessions, y)
        self.assertEqual(sorted(np.concatenate([test for _, test in folds])), list(range(len(y))))
        for train, test in folds:
            self.assertFalse(set(sessions.iloc[train]) & set(sessions.iloc[test]))
            self.assertEqual(set(y[train]), set(range(len(CLASSES))))
        with self.assertRaisesRegex(ValueError, "all four classes"):
            session_folds(sessions.iloc[:6], y[:6])

    def test_refit_meta_gets_four_probabilities_per_base_plus_twelve_flow_features(self):
        from features import FEATURES

        x = pd.DataFrame(np.arange(16 * len(FEATURES)).reshape(16, -1), columns=FEATURES, dtype=float)
        labels = np.tile(np.arange(len(CLASSES)), 4)
        folds = session_folds(np.repeat(["a", "b", "c", "d"], 4), labels)
        stack = build_stack(folds)
        for _, model in stack.estimators:
            model.steps[-1][1].set_params(n_estimators=1)
        stack.fit(x, labels)
        self.assertEqual(stack.transform(x).shape, (16, 24))
        self.assertEqual(stack.predict_proba(x).shape, (16, 4))

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
