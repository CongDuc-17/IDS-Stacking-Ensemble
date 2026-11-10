"""Check saved CSV predictions using a trusted model, without packet-capture dependencies."""
import argparse

import joblib
import numpy as np
import pandas as pd

from dataset import column_name, numeric_features
from features import FEATURES


def load_model(model_path):
    """Load only trusted artifacts and verify the feature/label contract."""
    artifact = joblib.load(model_path)
    if list(artifact["features"]) != FEATURES:
        raise ValueError("Artifact feature contract differs from src/features.py.")
    classes = np.asarray(artifact["classes"])
    if not np.array_equal(artifact["model"].classes_, np.arange(len(classes))):
        raise ValueError("Artifact probability columns do not match the stored label encoding.")
    return artifact


def check_model(model_path, csv_path):
    artifact = load_model(model_path)
    classes = np.asarray(artifact["classes"])
    frame = pd.read_csv(csv_path)
    frame.columns = [column_name(name) for name in frame.columns]
    required = set(FEATURES + ["ExpectedPrediction"])
    if frame.empty or required - set(frame.columns) or frame.columns.duplicated().any():
        raise ValueError("Smoke CSV is empty or has missing/ambiguous feature or ExpectedPrediction columns.")
    predicted = classes[artifact["model"].predict_proba(numeric_features(frame)).argmax(axis=1)]
    match = float(np.mean(predicted == frame.ExpectedPrediction.to_numpy()))
    print(f"Prediction match: {match:.2%}")
    if match < 1:
        raise ValueError("Smoke-test mismatch. Check Python/package versions and model provenance.")
    return match


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", required=True, help="Only load a model you created or trust")
    ap.add_argument("--csv", required=True, help="CSV exported with ExpectedPrediction")
    args = ap.parse_args()
    try:
        check_model(args.model, args.csv)
    except (ValueError, FileNotFoundError) as error:
        ap.exit(1, f"Error: {error}\n")


if __name__ == "__main__":
    main()
