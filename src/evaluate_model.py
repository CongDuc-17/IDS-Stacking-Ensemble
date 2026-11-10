"""Score a trusted saved model against verified CSV labels, without retraining."""
import argparse
import hashlib
from pathlib import Path

import numpy as np
import pandas as pd

from check_model import load_model
from dataset import column_name, numeric_features
from evaluate_lab import normalize_labels
from features import FEATURES
from train import evaluate, write_json


def evaluate_model(model_path, csv_path, out, label_column="Label"):
    if label_column == "ExpectedPrediction":
        raise ValueError("ExpectedPrediction is not ground truth. Use verified Label or GroundTruth.")
    root = Path(out)
    if root.exists():
        raise ValueError("Choose a new --out to preserve existing evaluation results.")
    artifact = load_model(model_path)
    frame = pd.read_csv(csv_path)
    frame.columns = [column_name(name) for name in frame.columns]
    if frame.empty or frame.columns.duplicated().any() or set(FEATURES + [label_column]) - set(frame):
        raise ValueError("Need nonempty CSV with unambiguous features and a verified label column.")
    labels = normalize_labels(frame[label_column])
    if artifact.get("task") == "binary":
        labels = labels.where(labels.eq("BENIGN"), "ATTACK")
    classes = np.asarray(artifact["classes"])
    if set(labels) - set(classes):
        raise ValueError(f"Truth labels absent from the model: {sorted(set(labels) - set(classes))}")
    x = numeric_features(frame)
    if x.isna().all(axis=1).any():
        raise ValueError("CSV contains rows with no usable feature values.")
    y = labels.map({label: i for i, label in enumerate(classes)}).to_numpy(dtype=int)
    root.mkdir(parents=True)
    summary, predicted = evaluate("stacking", artifact["model"], x, y, classes, root, fit_seconds=None)
    results = x.copy()
    results["GroundTruth"] = labels.to_numpy()
    results["Prediction"] = classes[predicted]
    results.to_csv(root / "predictions.csv", index=False)
    results.loc[results.GroundTruth != results.Prediction].to_csv(root / "errors.csv", index=False)
    write_json(root / "metrics.json", {"rows": len(frame), **summary})
    hashes = {}
    for name, path in (("model_sha256", model_path), ("csv_sha256", csv_path)):
        with Path(path).open("rb") as source:
            hashes[name] = hashlib.file_digest(source, "sha256").hexdigest()
    write_json(root / "protocol.json", {
        "model": str(Path(model_path).resolve()), "csv": str(Path(csv_path).resolve()),
        **hashes,
        "label_column": label_column, "task": artifact.get("task"), "features": FEATURES,
        "note": "Scores the supplied verified labels; no training. Does not establish holdout independence or live feature parity.",
    })
    print(f"Ground-truth Accuracy: {summary['accuracy']:.2%}; Macro-F1: {summary['macro_f1']:.2%}", flush=True)
    return summary


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", required=True, help="Only load a model you created or trust")
    ap.add_argument("--csv", required=True)
    ap.add_argument("--out", required=True, help="New evaluation directory")
    ap.add_argument("--label-column", default="Label", choices=["Label", "GroundTruth"])
    args = ap.parse_args()
    try:
        evaluate_model(args.model, args.csv, args.out, args.label_column)
    except (ValueError, FileNotFoundError) as error:
        ap.exit(1, f"Error: {error}\n")


if __name__ == "__main__":
    main()
