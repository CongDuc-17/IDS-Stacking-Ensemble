"""Offline periodic-flow candidates; low timing variation alone is not proof of C2."""
import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

from host_features import normalize_flows

PAIR = ["src_ip", "dst_ip", "dst_port", "protocol"]


def analyze_beaconing(flows, min_connections=6, min_span=60., min_interval=1., max_cv=.1):
    if (min_connections < 3 or not np.isfinite([min_span, min_interval, max_cv]).all()
            or min_span < 0 or min_interval <= 0 or max_cv < 0):
        raise ValueError("Need at least three connections and finite, valid timing thresholds.")
    required = set(PAIR + ["flow_first_epoch"])
    if flows.empty or required - set(flows) or flows[list(required)].isna().any().any():
        raise ValueError("Need nonempty flows with endpoint, protocol and start-time metadata.")
    flows = flows.copy()
    flows["flow_first_epoch"] = pd.to_numeric(flows.flow_first_epoch, errors="raise")
    if not np.isfinite(flows.flow_first_epoch).all() or (flows.flow_first_epoch < 0).any():
        raise ValueError("Flow start times must be finite, nonnegative epoch seconds.")
    rows = []
    for key, group in flows.groupby(PAIR, sort=True):
        starts = np.unique(group.flow_first_epoch.to_numpy(dtype=float))
        intervals = np.diff(starts)
        mean = float(intervals.mean()) if len(intervals) else None
        sd = float(intervals.std(ddof=1)) if len(intervals) >= 2 else None
        cv = sd / mean if sd is not None else None
        span = float(starts[-1] - starts[0])
        rows.append({**dict(zip(PAIR, key)), "flow_count": len(group), "unique_starts": len(starts),
                     "duplicate_starts": len(group)-len(starts), "span_seconds": span,
                     "mean_interval_seconds": mean, "interval_std_seconds": sd, "interval_cv": cv,
                     "candidate": bool(len(starts) >= min_connections and span >= min_span
                                       and mean >= min_interval and cv is not None and cv <= max_cv)})
    return pd.DataFrame(rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--csv", required=True, help="Unsampled extracted flows or original InSDN CSV")
    ap.add_argument("--out", required=True)
    ap.add_argument("--timestamp-format")
    ap.add_argument("--drop-invalid-time", action="store_true")
    ap.add_argument("--min-connections", type=int, default=6)
    ap.add_argument("--min-span", type=float, default=60.)
    ap.add_argument("--min-interval", type=float, default=1.)
    ap.add_argument("--max-cv", type=float, default=.1)
    args = ap.parse_args()
    try:
        root = Path(args.out)
        if root.exists():
            raise ValueError("Choose a new --out.")
        raw = pd.read_csv(args.csv)
        if "protocol" in raw and "Protocol" in raw:
            raise ValueError("Ambiguous protocol columns.")
        raw = raw.rename(columns={"Protocol": "protocol"})
        if "protocol" not in raw:
            raise ValueError("Missing protocol column.")
        raw["protocol"] = raw.protocol.astype("string").str.strip().str.upper().replace({"6": "TCP", "17": "UDP"})
        if raw.protocol.isna().any() or raw.protocol.eq("").any():
            raise ValueError("Missing protocol values.")
        supported = raw.protocol.isin(["TCP", "UDP"])
        unsupported = raw.loc[~supported, "protocol"].value_counts().to_dict()
        flows = normalize_flows(raw.loc[supported], args.timestamp_format, args.drop_invalid_time)
        stats = analyze_beaconing(flows, args.min_connections, args.min_span, args.min_interval, args.max_cv)
        candidates = stats.loc[stats.candidate]
        root.mkdir(parents=True)
        stats.to_csv(root / "pairs.csv", index=False)
        candidates.to_csv(root / "candidates.csv", index=False)
        summary = {"arguments": vars(args), "source_rows": len(raw), "input_flows": len(flows), "pairs": len(stats),
                   "unsupported_protocol_rows": unsupported,
                   "candidate_pairs": len(candidates), "duplicate_starts": int(stats.duplicate_starts.sum()),
                   "invalid_time_rows_removed": flows.attrs["invalid_time_rows_removed"],
                   "interpretation": "Periodic flow-start candidates only; no C2 ground truth or maliciousness metrics.",
                   "limitations": ["Use unsampled flows; sampled training splits destroy interval statistics.",
                                   "Duplicate timestamps are counted and deduplicated; coarse timestamps can create regularity.",
                                   "Flow timeouts, legitimate polling and keep-alives can look periodic.",
                                   "Whole-capture pair analysis, not sliding-window live detection; jittered beacons can be missed."]}
        (root / "summary.json").write_text(json.dumps(summary, indent=2, allow_nan=False), encoding="utf-8")
        print(f"pairs={len(stats)}; periodic_candidates={len(candidates)}; not confirmed C2", flush=True)
    except (ValueError, KeyError) as error:
        ap.exit(1, f"Error: {error}\n")


if __name__ == "__main__":
    main()
