"""Compare two normalized, independently extracted flow CSVs; never infer parity from names alone."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path

import numpy as np
import pandas as pd

from features import FEATURES
from evaluate_lab import KEYS
from dataset import column_name


def normalize_reference(frame, timestamp_format, timezone):
    """Normalize a full CICFlowMeter export; never guess timestamp units or timezone."""
    aliases = {"Source IP": "src_ip", "Src IP": "src_ip", "Destination IP": "dst_ip",
               "Dst IP": "dst_ip", "Source Port": "src_port", "Src Port": "src_port", "Protocol": "protocol"}
    frame = frame.copy()
    frame.columns = [aliases.get(column_name(c), column_name(c)) for c in frame.columns]
    if frame.columns.duplicated().any():
        raise ValueError("Ambiguous reference columns after normalization.")
    if "dst_port" not in frame and "Destination Port" in frame:
        frame["dst_port"] = frame["Destination Port"]
    if "flow_first_epoch" not in frame:
        if "Timestamp" not in frame or not timestamp_format or not timezone:
            raise ValueError("Reference needs Timestamp plus explicit --timestamp-format and --timezone, or flow_first_epoch.")
        dates = pd.to_datetime(frame.Timestamp, format=timestamp_format, errors="raise")
        if dates.dt.tz is not None:
            raise ValueError("Use timezone-naive reference timestamps with explicit --timezone.")
        frame["flow_first_epoch"] = dates.dt.tz_localize(timezone, ambiguous="raise", nonexistent="raise").map(lambda date: date.timestamp())
    if set(KEYS + FEATURES) - set(frame):
        raise ValueError("Need a full CICFlowMeter CSV with IPs, ports, protocol and all features; MachineLearningCSV alone lacks metadata.")
    for name in ("src_ip", "dst_ip"):
        frame[name] = frame[name].map(lambda value: str(ipaddress.IPv4Address(str(value).strip())))
    frame["protocol"] = frame.protocol.astype("string").str.strip().str.upper().replace({"6": "TCP", "17": "UDP", "6.0": "TCP", "17.0": "UDP"})
    if not frame.protocol.isin(["TCP", "UDP"]).all():
        raise ValueError("Reference must cover the same IPv4 TCP/UDP capture scope; unsupported protocols are not silently dropped.")
    return frame[KEYS + FEATURES]


def compare_features(reference, candidate, rtol=1e-6, atol=1e-6):
    required = set(KEYS + FEATURES)
    frames = []
    for source in (reference, candidate):
        if source.empty or required - set(source):
            raise ValueError("Need nonempty normalized flow CSVs with canonical features and flow metadata keys.")
        frame = source[KEYS + FEATURES].copy()
        for name in ["src_port", "dst_port", "flow_first_epoch", *FEATURES]:
            frame[name] = pd.to_numeric(frame[name], errors="raise")
        frame["flow_first_epoch"] = frame.flow_first_epoch.round(6)
        if frame.isna().any().any() or not np.isfinite(frame.select_dtypes(include="number")).all().all():
            raise ValueError("Missing or nonfinite parity input.")
        frames.append(frame)
    joined = frames[0].merge(frames[1], on=KEYS, how="outer", indicator=True,
                            suffixes=("_reference", "_candidate"), validate="one_to_one")
    matched = joined.loc[joined._merge == "both"]
    errors = {}
    for feature in FEATURES:
        left, right = matched[feature + "_reference"].to_numpy(), matched[feature + "_candidate"].to_numpy()
        errors[feature] = {"max_abs_error": float(np.max(np.abs(left-right))) if len(left) else None,
                           "mismatch_rows": int((~np.isclose(left, right, rtol=rtol, atol=atol)).sum())}
    missing_reference = int((joined._merge == "right_only").sum())
    missing_candidate = int((joined._merge == "left_only").sum())
    return {"matched_flows": len(matched), "reference_flows_without_candidate": missing_candidate,
            "candidate_flows_without_reference": missing_reference, "feature_errors": errors,
            "rtol": rtol, "atol": atol,
            "passed_this_capture": bool(len(matched) and not missing_reference and not missing_candidate
                                        and not any(v["mismatch_rows"] for v in errors.values())),
            "limitation": "Exact endpoint/direction/first-packet matching only. Unmatched boundaries fail this check; one passing capture does not establish general equivalence."}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--reference", required=True)
    ap.add_argument("--candidate", required=True)
    ap.add_argument("--out", required=True, help="New JSON file")
    ap.add_argument("--reference-format", choices=["normalized", "cicflowmeter"], default="normalized")
    ap.add_argument("--timestamp-format", help="Exact datetime format for full CICFlowMeter export")
    ap.add_argument("--timezone", help="Actual timezone of reference timestamps, e.g. UTC; never inferred")
    ap.add_argument("--reference-extractor", help="Reference extractor version/commit and command used")
    ap.add_argument("--pcap", help="Same capture used by both extractors, saved as a provenance hash")
    args = ap.parse_args()
    try:
        if Path(args.reference).resolve() == Path(args.candidate).resolve():
            raise ValueError("Use two independently extracted CSVs, not the same file twice.")
        reference = pd.read_csv(args.reference)
        if args.reference_format == "cicflowmeter":
            if not args.reference_extractor:
                raise ValueError("Record --reference-extractor version/commit and command.")
            reference = normalize_reference(reference, args.timestamp_format, args.timezone)
        report = compare_features(reference, pd.read_csv(args.candidate))
        inputs = {"reference": args.reference, "candidate": args.candidate, **({"pcap": args.pcap} if args.pcap else {})}
        manifests = {}
        for name, path in inputs.items():
            with Path(path).open("rb") as stream:
                manifests[name] = {"path": str(Path(path).resolve()), "sha256": hashlib.file_digest(stream, "sha256").hexdigest()}
        report["provenance"] = {"inputs": manifests,
                                "reference_format": args.reference_format, "reference_extractor": args.reference_extractor,
                                "timestamp_format": args.timestamp_format, "timezone": args.timezone}
        target = Path(args.out)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("x", encoding="utf-8") as output:
            json.dump(report, output, indent=2, allow_nan=False)
        print(json.dumps(report, indent=2))
        if not report["passed_this_capture"]:
            ap.exit(1, "Feature parity failed for this capture; inspect the saved report.\n")
    except (ValueError, KeyError) as error:
        ap.exit(1, f"Error: {error}\n")


if __name__ == "__main__":
    main()
