"""Join lab flow predictions to explicit ground truth; never treat predictions as labels."""
import argparse
import json
from pathlib import Path
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

KEYS = ["src_ip", "src_port", "dst_ip", "dst_port", "protocol", "flow_first_epoch"]


def normalize_labels(labels):
    name = labels.name or "Label"
    labels = labels.astype("string").str.strip()
    normalized = labels.str.casefold()
    if labels.isna().any() or normalized.isin(["", "unknown", "nan", "null", "none"]).any():
        raise ValueError(f"{name} contains missing or UNKNOWN labels. Supply known labels before evaluation.")
    return labels.mask(normalized.isin(["benign", "normal"]), "BENIGN").mask(normalized.eq("attack"), "ATTACK")


def evaluate(predictions, truth):
    required = set(KEYS)
    if not required.union({"predicted_label"}) <= set(predictions) or not required.union({"Label"}) <= set(truth):
        raise ValueError("Need flow metadata keys and predicted_label/Label.")
    predictions, truth = predictions.copy(), truth.copy()
    for frame in [predictions, truth]:
        frame["flow_first_epoch"] = pd.to_numeric(frame["flow_first_epoch"], errors="raise").round(6)
        if frame[KEYS].isna().any().any():
            raise ValueError("Ground truth/prediction keys must not be missing.")
    for frame, column in ((truth, "Label"), (predictions, "predicted_label")):
        frame[column] = normalize_labels(frame[column])
    joined = truth.merge(predictions, on=KEYS, how="outer", indicator=True, validate="one_to_one", suffixes=("_truth", ""))
    matched = joined.loc[joined["_merge"] == "both"].copy()
    if matched.empty:
        raise ValueError("No matching flows. Check capture, clock, direction, idle and max-age settings.")
    y = matched["Label"]
    p = matched["predicted_label"]
    classes = sorted(set(y) | set(p))
    report = {
        "matched_flows": len(matched),
        "truth_flows_without_prediction": int((joined["_merge"] == "left_only").sum()),
        "predicted_flows_without_truth": int((joined["_merge"] == "right_only").sum()),
        "classification_report_matched_only": classification_report(y, p, zero_division=0, output_dict=True),
        "binary_detection_matched_only": classification_report(y != "BENIGN", p != "BENIGN", labels=[False, True],
            target_names=["BENIGN", "ATTACK"], zero_division=0, output_dict=True),
        "confusion_labels": classes, "confusion_matrix": confusion_matrix(y, p, labels=classes).tolist(),
        "limitations": "Metrics cover matched observed flows only; capture loss and unknown labels are NOT counted as correct.",
    }
    benign, attack = y == "BENIGN", y != "BENIGN"
    report["benign_false_positive_rate"] = float((p[benign] != "BENIGN").mean()) if benign.any() else None
    report["attack_false_negative_rate"] = float((p[attack] == "BENIGN").mean()) if attack.any() else None
    for col in ["inference_ms", "observed_first_packet_to_result_seconds"]:
        if col in matched:
            values = pd.to_numeric(matched[col], errors="coerce").dropna()
            report[col] = {"p50": float(values.quantile(0.5)), "p95": float(values.quantile(0.95))} if len(values) else None
    return report


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--predictions", required=True)
    ap.add_argument("--truth", required=True, help="CSV from extractor plus manually verified Label")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    predictions = pd.read_json(args.predictions, lines=True)
    truth = pd.read_csv(args.truth)
    try:
        report = evaluate(predictions, truth)
    except ValueError as error:
        ap.exit(1, f"Error: {error}\n")
    target = Path(args.out)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
