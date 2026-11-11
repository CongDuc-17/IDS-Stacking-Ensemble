"""Ethernet minimum-frame padding is outside IP/TCP/UDP application payload."""
from pathlib import Path
import sys
import unittest

from scapy.all import Ether, IP, TCP, UDP, Raw

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from flows import FlowTable


class PaddingTests(unittest.TestCase):
    def extract(self, packets):
        emitted = []
        table = FlowTable(lambda row, meta: emitted.append((row, meta)))
        for n, packet in enumerate(packets):
            packet.time = 100 + n / 10
            table.process(packet)
        table.flush(table.watermark, force=True)
        return emitted

    def padded(self, transport):
        wire = bytes(Ether() / IP(src="192.0.2.1", dst="192.0.2.2") / transport)
        return Ether(wire + b"\0" * max(0, 60 - len(wire)))

    def test_empty_tcp_ack_has_no_payload_despite_six_ethernet_padding_bytes(self):
        packet = self.padded(TCP(sport=12345, dport=8080, flags="A"))
        self.assertEqual(len(bytes(packet[TCP].payload)), 6)
        rows = self.extract([packet])
        self.assertEqual(rows[0][0]["Total Length of Fwd Packets"], 0)
        self.assertEqual(rows[0][0]["ACK Flag Count"], 1)

    def test_udp_padding_excluded_but_legitimate_zero_payload_bytes_preserved(self):
        for data in [b"", b"\0\0", b"hello"]:
            with self.subTest(data=data):
                packet = self.padded(UDP(sport=12345, dport=5353) / Raw(data))
                rows = self.extract([packet])
                self.assertEqual(rows[0][0]["Total Length of Fwd Packets"], len(data))

    def test_legitimate_tcp_zero_bytes_are_counted_and_invalid_udp_length_rejected(self):
        packet = self.padded(TCP(sport=12345, dport=8080, flags="PA") / Raw(b"\0\0"))
        self.assertEqual(self.extract([packet])[0][0]["Total Length of Fwd Packets"], 2)
        table = FlowTable(lambda *_: self.fail("Invalid packet must not emit a flow"))
        packet = self.padded(UDP(sport=12345, dport=5353, len=4))
        packet.time = 100
        table.process(packet)
        self.assertEqual(table.unsupported_packets, 1)

    def test_tcp_options_and_bidirectional_counts_preserved(self):
        forward = self.padded(TCP(sport=12345, dport=8080, flags="S", options=[("MSS", 1460)]))
        backward = self.padded(TCP(sport=12345, dport=8080, flags="PA") / Raw(b"abc"))
        backward[IP].src, backward[IP].dst = "192.0.2.2", "192.0.2.1"
        backward[TCP].sport, backward[TCP].dport = 8080, 12345
        row, _ = self.extract([forward, backward])[0]
        self.assertEqual(row["Total Fwd Packets"], 1)
        self.assertEqual(row["Total Backward Packets"], 1)
        self.assertEqual(row["Total Length of Fwd Packets"], 0)
        self.assertEqual(row["Total Length of Bwd Packets"], 3)


if __name__ == "__main__":
    unittest.main()
