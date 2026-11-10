"""One bounded IPv4 TCP/UDP flow extractor shared by PCAP and live inference.

This is NOT a reimplementation of CICFlowMeter. Flow byte counts are L4 payload
bytes; a bidirectional flow is oriented by its first observed packet.
"""
from collections import OrderedDict
import math

FLAGS = (("FIN", 1), ("SYN", 2), ("RST", 4), ("PSH", 8), ("ACK", 16), ("URG", 32))


class FlowTable:
    def __init__(self, emit, idle=10.0, maximum=60.0, max_flows=10000):
        if not math.isfinite(idle) or not math.isfinite(maximum) or idle <= 0 or maximum <= 0 or max_flows < 1:
            raise ValueError("Timeouts and max_flows must be finite and positive.")
        self.emit, self.idle, self.maximum = emit, idle, maximum
        self.max_flows = max_flows
        self.flows = OrderedDict()
        self.watermark = self.last_sweep = float("-inf")
        self.capacity_evictions = self.unsupported_packets = self.invalid_timestamps = 0

    def expired(self, flow, now):
        return now - flow["last"] >= self.idle or now - flow["first"] >= self.maximum

    def process(self, pkt):
        from scapy.layers.inet import IP, TCP, UDP
        now = float(pkt.time)
        if not math.isfinite(now):
            self.invalid_timestamps += 1
            return
        self.watermark = max(self.watermark, now)
        if self.watermark - self.last_sweep >= 1:
            self.flush(self.watermark)
            self.last_sweep = self.watermark
        if IP not in pkt or (TCP not in pkt and UDP not in pkt):
            self.unsupported_packets += 1
            return
        ip = pkt[IP]
        if ip.frag or ip.flags.MF:
            self.unsupported_packets += 1
            return
        transport = pkt[TCP] if TCP in pkt else pkt[UDP]
        protocol = "TCP" if TCP in pkt else "UDP"
        src, dst = (ip.src, int(transport.sport)), (ip.dst, int(transport.dport))
        key = (protocol, *sorted((src, dst)))
        # Expire BEFORE adding the next packet of an old connection.
        if key in self.flows and self.expired(self.flows[key], self.watermark):
            self.finish(key, self.watermark, "timeout")
        if key not in self.flows:
            if len(self.flows) >= self.max_flows:
                self.capacity_evictions += 1
                self.finish(next(iter(self.flows)), self.watermark, "capacity")
            self.flows[key] = {
                "first": now, "last": now, "src": src, "dst": dst,
                "fwd": 0, "bwd": 0, "fwd_bytes": 0, "bwd_bytes": 0,
                "flags": {name: 0 for name, _ in FLAGS},
            }
        flow = self.flows[key]
        forward = src == flow["src"] and dst == flow["dst"]
        flow["fwd" if forward else "bwd"] += 1
        flow["fwd_bytes" if forward else "bwd_bytes"] += len(bytes(transport.payload))
        if TCP in pkt:
            for name, mask in FLAGS:
                flow["flags"][name] += int(bool(int(pkt[TCP].flags) & mask))
        flow["first"] = min(flow["first"], now)
        flow["last"] = max(flow["last"], now)

    def finish(self, key, now, reason):
        flow = self.flows.pop(key)
        row = {
            "Destination Port": flow["dst"][1],
            "Flow Duration": (flow["last"] - flow["first"]) * 1_000_000,
            "Total Fwd Packets": flow["fwd"], "Total Backward Packets": flow["bwd"],
            "Total Length of Fwd Packets": flow["fwd_bytes"], "Total Length of Bwd Packets": flow["bwd_bytes"],
            **{f"{name} Flag Count": flow["flags"][name] for name, _ in FLAGS},
        }
        meta = {
            "flow_first_epoch": flow["first"], "flow_last_epoch": flow["last"],
            "flow_emitted_epoch": now, "flow_close_reason": reason,
            "src_ip": flow["src"][0], "src_port": flow["src"][1],
            "dst_ip": flow["dst"][0], "dst_port": flow["dst"][1], "protocol": key[0],
        }
        self.emit(row, meta)

    def flush(self, now, force=False):
        self.watermark = max(self.watermark, now)
        for key in [k for k, f in self.flows.items() if force or self.expired(f, self.watermark)]:
            self.finish(key, self.watermark, "end" if force else "timeout")
