"""PCAP -> flow CSV using exactly the same extractor as live detection."""
import argparse
import csv
import math
from pathlib import Path
from scapy.all import PcapReader, RawPcapNgReader, conf
from features import FEATURES
from flows import EXTRACTOR_VERSION, FlowTable

METADATA = ["flow_first_epoch", "flow_last_epoch", "flow_emitted_epoch", "flow_close_reason",
            "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "flow_extractor_version"]


def windowed_packets(capture, start, end, padding):
    for data, meta in capture:
        if meta.tshigh is None:
            continue
        epoch = ((meta.tshigh << 32) | meta.tslow) / meta.tsresol
        if start - padding <= epoch <= end + padding:
            packet = conf.l2types.num2layer[meta.linktype](data)
            packet.time = epoch
            packet.wirelen = meta.wirelen
            yield packet


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--label", help="Known ground-truth label ONLY for a single-scenario lab capture")
    ap.add_argument("--idle", type=float, default=10)
    ap.add_argument("--max-age", type=float, default=60)
    ap.add_argument("--max-flows", type=int, default=10000)
    ap.add_argument("--window", type=float, nargs=2, metavar=("START_EPOCH", "END_EPOCH"),
                    help="Export complete flows inside a UTC window from PCAPNG, with packet context on both sides")
    args = ap.parse_args()
    if args.window and (not all(map(math.isfinite, args.window)) or args.window[0] >= args.window[1]):
        ap.error("--window requires two increasing finite epoch timestamps")
    target = Path(args.out)
    target.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    # Refuse overwriting a capture's extracted ground truth.
    with target.open("x", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=FEATURES + METADATA + (["Label"] if args.label else []))
        writer.writeheader()
        def emit(row, meta):
            nonlocal count
            if args.window and (meta["flow_close_reason"] == "end" or
                                meta["flow_first_epoch"] < args.window[0] or meta["flow_last_epoch"] >= args.window[1]):
                return
            writer.writerow({**row, **meta, "flow_extractor_version": EXTRACTOR_VERSION, **({"Label": args.label} if args.label else {})})
            count += 1
        flows = FlowTable(emit, args.idle, args.max_age, args.max_flows)
        reader = RawPcapNgReader if args.window else PcapReader
        with reader(args.pcap) as capture:
            packets = windowed_packets(capture, *args.window, max(args.idle, args.max_age)) if args.window else capture
            for packet in packets:
                flows.process(packet)
        if flows.flows:
            flows.flush(flows.watermark, force=True)
    print(f"flows={count}; capacity_evictions={flows.capacity_evictions}; unsupported_packets={flows.unsupported_packets}")


if __name__ == "__main__":
    main()
