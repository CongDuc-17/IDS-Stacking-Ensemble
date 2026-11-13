"""Check saved predictions, replay a PCAP, or capture IPv4 TCP/UDP live."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import queue
import sys
import threading
import time
import joblib
import numpy as np
import pandas as pd
from dataset import column_name, numeric_features
from features import FEATURES
from flows import EXTRACTOR_VERSION, FlowTable


class FlowDetector:
    def __init__(self, artifact, out_dir, idle=10.0, maximum=60.0, max_flows=10000, live=False):
        contract = artifact.get("flow_contract")
        if contract is not None and contract != {"version": EXTRACTOR_VERSION, "idle": idle,
                                                  "max_age": maximum, "max_flows": max_flows}:
            raise ValueError(f"Detector settings must match the model flow contract: {contract}")
        self.artifact, self.live = artifact, live
        self.total_flows = self.alerts = 0
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        self.logfile = out_dir / "predictions.jsonl"
        self.flow_table = FlowTable(self.predict, idle, maximum, max_flows)
        try:
            # Exclusive creation reserves this log before capture, including empty runs.
            self.logfile.touch(exist_ok=False)
        except FileExistsError as error:
            raise FileExistsError(f"Prediction log already exists: {self.logfile}. Choose a new --out.") from error

    def predict(self, row, meta):
        x = pd.DataFrame([row], columns=FEATURES)
        start = time.perf_counter()
        proba = self.artifact["model"].predict_proba(x)[0]
        inference_ms = (time.perf_counter() - start) * 1000
        index = int(np.argmax(proba))
        label = str(self.artifact["classes"][index])
        is_attack = label not in self.artifact.get("benign_labels", ["BENIGN", "Normal", "normal"])
        record = {
            **meta, "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "predicted_label": label, "is_attack": is_attack,
            "model_score_uncalibrated": float(proba[index]), "inference_ms": inference_ms,
            "experimental_feature_parity_unvalidated": "flow_contract" not in self.artifact,
            "flow_extractor_version": EXTRACTOR_VERSION, "feature_values": row,
            "observed_first_packet_to_result_seconds": max(0, time.time() - meta["flow_first_epoch"]) if self.live else None,
        }
        if "model_id" in self.artifact:
            record["model_id"] = self.artifact["model_id"]
        self.total_flows += 1
        self.alerts += int(is_attack)
        # Benign records are needed to measure false alarms and misses in the lab.
        with self.logfile.open("a", encoding="utf-8") as output:
            output.write(json.dumps(record, ensure_ascii=False, allow_nan=False) + "\n")
        if is_attack:
            print(json.dumps(record, ensure_ascii=False), flush=True)


def validate_artifact(artifact):
    if list(artifact["features"]) != FEATURES:
        raise ValueError("Artifact feature contract differs from src/features.py.")
    if not np.array_equal(artifact["model"].classes_, np.arange(len(artifact["classes"]))):
        raise ValueError("Artifact probability columns do not match the stored label encoding.")


def csv_smoke(artifact, path):
    frame = pd.read_csv(path)
    frame.columns = [column_name(c) for c in frame.columns]
    missing = set(FEATURES) - set(frame.columns)
    if missing or frame.empty:
        raise ValueError(f"Missing features or empty CSV: {sorted(missing)}")
    predicted = np.asarray(artifact["classes"])[artifact["model"].predict_proba(numeric_features(frame)).argmax(axis=1)]
    print(pd.Series(predicted).value_counts().to_string())
    if "ExpectedPrediction" in frame:
        match = float(np.mean(predicted == frame["ExpectedPrediction"].to_numpy()))
        print(f"Prediction match: {match:.2%}")
        if match < 1:
            raise ValueError("Smoke-test mismatch. Check Python/package versions and model provenance.")


def live_capture(detector, iface, queue_size, capture_filter=None):
    from scapy.all import AsyncSniffer
    pending = queue.Queue(maxsize=queue_size)
    dropped = 0
    ready = threading.Event()
    def enqueue(packet):
        nonlocal dropped
        try:
            pending.put_nowait(packet)
        except queue.Full:
            dropped += 1
    packet_filter = "ip and (tcp or udp)"
    if capture_filter:
        packet_filter += f" and ({capture_filter})"
    sniffer = AsyncSniffer(iface=iface, filter=packet_filter, prn=enqueue,
                           store=False, started_callback=ready.set)
    sniffer.start()
    try:
        if not ready.wait(10):
            raise RuntimeError("Capture failed to start. Check the interface and capture permissions (Npcap on Windows, libpcap on Linux).")
        print(f"Capturing {iface}; Ctrl+C to stop.", flush=True)
        last_flush = time.monotonic()
        while sniffer.running:
            try:
                detector.flow_table.process(pending.get(timeout=0.2))
            except queue.Empty:
                pass
            if time.monotonic() - last_flush >= 1:
                # Do not expire against wall time while older packets remain queued.
                detector.flow_table.flush(detector.flow_table.watermark if not pending.empty() else time.time())
                last_flush = time.monotonic()
    except KeyboardInterrupt:
        pass
    finally:
        if sniffer.running:
            sniffer.stop()
        else:
            sniffer.join()  # Surface capture-thread exceptions rather than silently succeeding.
        while not pending.empty():
            detector.flow_table.process(pending.get_nowait())
        detector.flow_table.flush(time.time(), force=True)
        print(f"application_queue_dropped_packets={dropped}; OS/NIC drops not measured", flush=True)


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", default="experiments/pcap-combined-refit-seed42/PCAP-Combined-Refit.joblib")
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--csv")
    group.add_argument("--pcap")
    group.add_argument("--iface")
    group.add_argument("--list-ifaces", action="store_true", help="Show the interfaces Scapy can use")
    ap.add_argument("--out", default="logs", help="Output directory; predictions.jsonl must not already exist")
    ap.add_argument("--idle", type=float, default=10)
    ap.add_argument("--max-age", type=float, default=60)
    ap.add_argument("--max-flows", type=int, default=10000)
    ap.add_argument("--queue-size", type=int, default=10000)
    ap.add_argument("--capture-filter", help="Additional BPF scope for live capture, e.g. 'host 192.168.56.1'")
    args = ap.parse_args()
    if args.list_ifaces:
        from scapy.all import show_interfaces
        show_interfaces()
        return
    if args.queue_size < 1:
        ap.error("--queue-size must be positive.")
    artifact = joblib.load(args.model)  # Load ONLY your own trusted model files.
    validate_artifact(artifact)
    if args.csv:
        csv_smoke(artifact, args.csv)
        return
    if "flow_contract" in artifact:
        print(f"{artifact['model_id']}: capture uses the model's PCAP flow settings.", file=sys.stderr)
    else:
        print("EXPERIMENTAL: CICFlowMeter/Scapy parity is unvalidated; live accuracy must be measured separately.", file=sys.stderr)
    try:
        detector = FlowDetector(artifact, args.out, args.idle, args.max_age, args.max_flows, live=bool(args.iface))
    except (FileExistsError, ValueError) as error:
        ap.exit(1, f"Error: {error}\n")
    if args.pcap:
        from scapy.all import PcapReader
        with PcapReader(args.pcap) as capture:
            for packet in capture:
                detector.flow_table.process(packet)
        if detector.flow_table.flows:
            detector.flow_table.flush(detector.flow_table.watermark, force=True)
    else:
        try:
            live_capture(detector, args.iface, args.queue_size, args.capture_filter)
        except (OSError, ValueError, RuntimeError) as error:
            ap.exit(1, f"Capture error on {args.iface}: {error}\n")
    print(f"flows={detector.total_flows}; alerts={detector.alerts}; capacity_evictions={detector.flow_table.capacity_evictions}; unsupported_packets={detector.flow_table.unsupported_packets}")


if __name__ == "__main__":
    main()
