"""Compare two normalized, independently extracted flow CSVs; never infer parity from names alone."""
import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

from features import FEATURES
from evaluate_lab import KEYS


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
    args = ap.parse_args()
    try:
        report = compare_features(pd.read_csv(args.reference), pd.read_csv(args.candidate))
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
