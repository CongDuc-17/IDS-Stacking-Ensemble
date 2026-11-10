"""Aggregate completed bidirectional flows into host/time-window features and directed edges."""
import argparse
import ipaddress
import json
from pathlib import Path

import numpy as np
import pandas as pd

from dataset import column_name

HOST_FEATURES = ["flows_out", "flows_in", "unique_peers", "unique_dst_ports_out",
                 "packets_sent", "packets_received", "bytes_sent", "bytes_received", "syn_flags", "rst_flags"]
META = {"Src IP": "src_ip", "Dst IP": "dst_ip", "Timestamp": "Timestamp"}
COUNTS = ["Total Fwd Packets", "Total Backward Packets", "Total Length of Fwd Packets",
          "Total Length of Bwd Packets", "SYN Flag Count", "RST Flag Count"]


def normalize_flows(frame, timestamp_format=None, drop_invalid_time=False):
    frame = frame.copy()
    frame.columns = [META.get(str(c).strip(), column_name(str(c))) for c in frame.columns]
    if frame.columns.duplicated().any():
        raise ValueError("Ambiguous flow columns after normalization.")
    required = {"src_ip", "dst_ip", *COUNTS}
    if frame.empty or required - set(frame):
        raise ValueError(f"Empty flows or missing metadata/features: {sorted(required - set(frame))}")
    for name in ("src_ip", "dst_ip"):
        frame[name] = frame[name].map(lambda value: str(ipaddress.ip_address(str(value).strip())))
    if "flow_first_epoch" not in frame:
        if "Timestamp" not in frame or not timestamp_format:
            raise ValueError("Need flow_first_epoch or Timestamp with an explicit --timestamp-format.")
        dates = pd.Series(pd.NaT, index=frame.index, dtype="datetime64[ns, UTC]")
        for date_format in timestamp_format.split("|"):
            parsed = pd.to_datetime(frame.Timestamp, format=date_format, errors="coerce", utc=True)
            conflict = dates.notna() & parsed.notna() & dates.ne(parsed)
            if conflict.any():
                raise ValueError("Timestamp formats disagree; specify unambiguous source formats.")
            dates = dates.fillna(parsed)
        if dates.isna().any():
            raise ValueError("Missing timestamps or values not matching the explicit timestamp formats.")
        # astype('int64') depends on datetime resolution; timestamp() always returns seconds.
        frame["flow_first_epoch"] = dates.map(lambda value: value.timestamp())
    if "flow_last_epoch" not in frame:
        if "Flow Duration" not in frame:
            raise ValueError("Need flow_last_epoch or Flow Duration in microseconds.")
        frame["flow_last_epoch"] = pd.to_numeric(frame.flow_first_epoch) + pd.to_numeric(frame["Flow Duration"]) / 1e6
    if "dst_port" not in frame:
        if "Destination Port" not in frame:
            raise ValueError("Need dst_port or Destination Port.")
        frame["dst_port"] = frame["Destination Port"]
    numeric = COUNTS + ["flow_first_epoch", "flow_last_epoch", "dst_port"]
    frame[numeric] = frame[numeric].apply(pd.to_numeric, errors="raise")
    if not np.isfinite(frame[numeric].to_numpy(dtype=float)).all() or (frame[numeric] < 0).any().any():
        raise ValueError("Flow counters/timestamps must be finite and nonnegative.")
    invalid_time = frame.flow_last_epoch < frame.flow_first_epoch
    if invalid_time.any() and not drop_invalid_time:
        raise ValueError(f"{int(invalid_time.sum())} flows end before they start; inspect input or explicitly use --drop-invalid-time.")
    if ((frame.dst_port > 65535) | (frame.dst_port % 1 != 0)).any():
        raise ValueError("Invalid destination ports.")
    removed = int(invalid_time.sum())
    if removed:
        frame = frame.loc[~invalid_time].copy()
    if frame.empty:
        raise ValueError("No valid flows remain.")
    labels = frame.get("Label", pd.Series("UNKNOWN", index=frame.index)).astype("string").str.strip()
    unknown = labels.isna() | labels.str.casefold().isin(["", "unknown", "nan", "null", "none"])
    frame["Label"] = np.where(unknown, "UNKNOWN", np.where(labels.str.casefold().isin(["benign", "normal"]), "BENIGN", "ATTACK"))
    frame.attrs["invalid_time_rows_removed"] = removed
    return frame


def aggregate_hosts(frame, window_seconds=60):
    if not isinstance(window_seconds, int) or window_seconds < 1:
        raise ValueError("Window seconds must be a positive integer.")
    frame = frame.copy()
    # A completed flow contributes only when its final packet has been observed.
    frame["window_epoch"] = np.floor(frame.flow_last_epoch / window_seconds).astype("int64") * window_seconds
    views = []
    for reverse in (False, True):
        view = pd.DataFrame({"window_epoch": frame.window_epoch,
                             "host_ip": frame.dst_ip if reverse else frame.src_ip,
                             "peer": frame.src_ip if reverse else frame.dst_ip,
                             "dst_port_out": np.nan if reverse else frame.dst_port,
                             "flows_out": int(not reverse), "flows_in": int(reverse),
                             "packets_sent": frame[COUNTS[1 if reverse else 0]],
                             "packets_received": frame[COUNTS[0 if reverse else 1]],
                             "bytes_sent": frame[COUNTS[3 if reverse else 2]],
                             "bytes_received": frame[COUNTS[2 if reverse else 3]],
                             "syn_flags": frame[COUNTS[4]], "rst_flags": frame[COUNTS[5]],
                             "attack": frame.Label.eq("ATTACK"), "unknown": frame.Label.eq("UNKNOWN")})
        views.append(view)
    incident = pd.concat(views, ignore_index=True)
    sums = [c for c in HOST_FEATURES if c not in ("unique_peers", "unique_dst_ports_out")]
    grouped = incident.groupby(["window_epoch", "host_ip"], sort=True)
    hosts = grouped[sums].sum()
    hosts["unique_peers"] = grouped.peer.nunique()
    hosts["unique_dst_ports_out"] = grouped.dst_port_out.nunique()
    hosts["Label"] = np.where(grouped.unknown.max(), "UNKNOWN", np.where(grouped.attack.max(), "ATTACK", "BENIGN"))
    hosts = hosts.reset_index()
    hosts["window_seconds"] = window_seconds
    frame["packets"] = frame[COUNTS[0]] + frame[COUNTS[1]]
    frame["bytes"] = frame[COUNTS[2]] + frame[COUNTS[3]]
    edges = frame.groupby(["window_epoch", "src_ip", "dst_ip"], sort=True).agg(
        flows=("Label", "size"), packets=("packets", "sum"), bytes=("bytes", "sum")).reset_index()
    edges["window_seconds"] = window_seconds
    return hosts, edges


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--csv", required=True, help="Extracted lab flows or original InSDN with IP/timestamp columns")
    ap.add_argument("--out", required=True, help="New output directory")
    ap.add_argument("--window", type=int, default=60)
    ap.add_argument("--timestamp-format", help="Explicit format(s) separated by |; normalized lab epochs need none")
    ap.add_argument("--drop-invalid-time", action="store_true", help="Explicitly exclude/report flows ending before they start")
    args = ap.parse_args()
    try:
        target = Path(args.out)
        if target.exists():
            raise ValueError("Choose a new --out to preserve existing output.")
        flows = normalize_flows(pd.read_csv(args.csv, encoding="utf-8-sig"), args.timestamp_format, args.drop_invalid_time)
        hosts, edges = aggregate_hosts(flows, args.window)
        target.mkdir(parents=True)
        hosts.to_csv(target / "hosts.csv", index=False)
        edges.to_csv(target / "edges.csv", index=False)
        (target / "protocol.json").write_text(json.dumps({
            "source": str(Path(args.csv).resolve()), "flows": len(flows), "host_windows": len(hosts),
            "window_seconds": args.window, "timestamp_format": args.timestamp_format,
            "invalid_time_rows_removed": flows.attrs["invalid_time_rows_removed"],
            "features": HOST_FEATURES, "label_counts": hosts.Label.value_counts().to_dict(),
            "limitations": ["Assign complete flows to completion-time windows; no packet-rate estimate.",
                            "Host ATTACK means incident attack traffic, including victims; not proof of infection.",
                            "SYN/RST counts cover both directions of incident flows.",
                            "Unlabeled incident flows make the host/window UNKNOWN; never use predictions as truth."]
        }, indent=2), encoding="utf-8")
        print(f"host_windows={len(hosts)}; edges={len(edges)}; out={target.resolve()}")
    except (ValueError, KeyError) as error:
        ap.exit(1, f"Error: {error}\n")


if __name__ == "__main__":
    main()
