"""Verify source label normalization and the evaluation label policy."""
import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from taxonomy import LABELS, map_labels
from train import evaluate


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
