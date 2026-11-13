import csv
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scapy.all import Ether, IP, TCP, wrpcapng

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from match_capture_labels import MEASUREMENTS, Reference, match, reference_time


class CaptureLabelTests(unittest.TestCase):
    def test_probe_count_shift_requires_unique_evidence(self):
        direction = (("192.0.2.1", 1234), ("192.0.2.2", 80))
        row = dict(zip(MEASUREMENTS, (100, 1, 1, 0, 0)), protocol="TCP", flow_close_reason="timeout")
        exact = Reference(direction, 60, 60, "Probe", (100, 1, 1, 0, 0), "")
        shifted = Reference(direction, 60, 60, "Probe", (100, 0, 2, 0, 0), "")
        conflicting = Reference(direction, 0, 60, "Normal", (20_000_000, 1, 1, 0, 0), "")

        def status(refs, starts=(70,), allow=False):
            return match(row, direction, 70, 70.0001, refs, starts, {"probe": "RECON"}, allow)[0]

        self.assertEqual(status([exact]), "matched")
        self.assertEqual(status([shifted]), "measurement_mismatch")
        self.assertEqual(status([shifted], allow=True), "matched_probe_count_shift")
        self.assertEqual(status([shifted], starts=(70, 71), allow=True), "ambiguous_capture")
        self.assertEqual(status([shifted, exact], allow=True), "ambiguous_reference")
        self.assertEqual(status([shifted, conflicting], allow=True), "conflicting_interval")
        row[MEASUREMENTS[3]] = 1
        self.assertEqual(status([shifted], allow=True), "measurement_mismatch")

    def test_reference_time_preserves_source_precision(self):
        expected, _ = reference_time("07/07/2017 17:52:00", 0, False)
        self.assertEqual(reference_time("7/7/2017 2:52", 180, True), (expected, 60))
        self.assertEqual(reference_time("07/07/2017 05:52:00 PM", 0, False), (expected, 1))

    def test_pcapng_window_keeps_context_and_drops_boundary_flows(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            capture, output = Path(directory) / "sample.pcapng", Path(directory) / "flows.csv"
            packets = []
            for stamp, port in [(99, 1000), (100.25, 1000), (101, 1001), (102, 1002), (104, 1002), (108, 1003)]:
                packet = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") /
                          IP(src="192.0.2.1", dst="192.0.2.2") / TCP(sport=port, dport=80))
                packet.time = stamp
                packets.append(packet)
            wrpcapng(str(capture), packets)
            result = subprocess.run([sys.executable, str(ROOT / "src/extract.py"), "--pcap", str(capture),
                                     "--out", str(output), "--window", "100", "104", "--idle", "3",
                                     "--max-age", "6"], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            with output.open(encoding="utf-8", newline="") as stream:
                self.assertEqual([r["src_port"] for r in csv.DictReader(stream)], ["1001"])
