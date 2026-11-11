"""PCAP -> flow CSV using exactly the same extractor as live detection."""
import argparse
import csv
from pathlib import Path
from scapy.all import PcapReader
from features import FEATURES
from flows import EXTRACTOR_VERSION, FlowTable

METADATA = ["flow_first_epoch", "flow_last_epoch", "flow_emitted_epoch", "flow_close_reason",
            "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "flow_extractor_version"]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--label", help="Known ground-truth label ONLY for a single-scenario lab capture")
    ap.add_argument("--idle", type=float, default=10)
    ap.add_argument("--max-age", type=float, default=60)
    ap.add_argument("--max-flows", type=int, default=10000)
    args = ap.parse_args()
    target = Path(args.out)
    target.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    # Refuse overwriting a capture's extracted ground truth.
    with target.open("x", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=FEATURES + METADATA + (["Label"] if args.label else []))
        writer.writeheader()
        def emit(row, meta):
            nonlocal count
            writer.writerow({**row, **meta, "flow_extractor_version": EXTRACTOR_VERSION, **({"Label": args.label} if args.label else {})})
            count += 1
        flows = FlowTable(emit, args.idle, args.max_age, args.max_flows)
        with PcapReader(args.pcap) as capture:
            for packet in capture:
                flows.process(packet)
        if flows.flows:
            flows.flush(flows.watermark, force=True)
    print(f"flows={count}; capacity_evictions={flows.capacity_evictions}; unsupported_packets={flows.unsupported_packets}")


if __name__ == "__main__":
    main()
