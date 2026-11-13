"""Reproduce the PCAP-Combined-Refit model on prepared session splits."""
import argparse
from hashlib import file_digest
from importlib.metadata import version
import json
from pathlib import Path
import platform
import time

import joblib
from lightgbm import LGBMClassifier
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier, StackingClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import LeaveOneGroupOut
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, LabelEncoder, StandardScaler
from xgboost import XGBClassifier

from dataset import SOURCES, feature_hashes, numeric_features
from features import FEATURES
from pcap_experiments import CONTRACT, PARTS, SEED
from taxonomy import manifest


MODEL_ID = "PCAP-Combined-Refit"
CLASSES = ("BENIGN", "BRUTE_FORCE", "DOS", "RECON")
SESSION_CAP = 2000


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False), encoding="utf-8")


def evaluate(name, fitted, x, y, classes, folder, fit_seconds, *, metric_labels=None):
    start = time.perf_counter()
    pred = fitted.predict(x)
    elapsed = time.perf_counter() - start
    summary = {
        "accuracy": float(accuracy_score(y, pred)),
        "macro_f1": float(f1_score(y, pred, labels=metric_labels, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y, pred, average="weighted", zero_division=0)),
        "fit_seconds_final_refit": fit_seconds, "batch_predict_ms_per_flow": elapsed * 1000 / len(y),
    }
    if metric_labels is not None:
        summary["macro_f1_classes_in_truth"] = list(classes[metric_labels])
    if "BENIGN" in classes:
        benign = int(np.flatnonzero(classes == "BENIGN")[0])
        normal, attack = y == benign, y != benign
        summary["benign_false_positive_rate"] = float(np.mean(pred[normal] != benign)) if normal.any() else None
        summary["attack_false_negative_rate"] = float(np.mean(pred[attack] == benign)) if attack.any() else None
    labels = np.arange(len(classes))
    report = classification_report(y, pred, labels=labels, target_names=list(classes), zero_division=0, output_dict=True)
    binary_report = None
    if "BENIGN" in classes:
        binary_report = classification_report(y != benign, pred != benign, labels=[False, True],
                            target_names=["BENIGN", "ATTACK"], zero_division=0, output_dict=True)
        summary.update({f"attack_{name}": float(binary_report["ATTACK"][metric])
                        for name, metric in (("precision", "precision"), ("recall", "recall"), ("f1", "f1-score"))})
    write_json(folder / f"report_{name}.json", {
        "summary": summary, "classification_report": report, "binary_detection_from_multiclass": binary_report,
    })
    pd.DataFrame(confusion_matrix(y, pred, labels=labels), index=classes, columns=classes).to_csv(folder / f"confusion_{name}.csv")
    print(f"{name}: macro-F1={summary['macro_f1']:.4f}; accuracy={summary['accuracy']:.4f}", flush=True)
    return summary, pred




def prepare_refit(prepared):
    """Pool development rows in the original order, then cap each session."""
    splits = {}
    required = set(FEATURES + ["session_id", "source_dataset", "split", "flow_extractor_version", "Label"])
    for part in PARTS:
        for source in SOURCES:
            path = Path(prepared) / "splits" / source / f"{part}.csv"
            frame = pd.read_csv(path)
            if missing := required - set(frame.columns):
                raise ValueError(f"{path}: missing columns {sorted(missing)}")
            x = numeric_features(frame)
            if (frame.empty or frame.session_id.isna().any() or
                    not frame.source_dataset.eq(source).all() or not frame.split.eq(part).all() or
                    not frame.flow_extractor_version.eq(CONTRACT["version"]).all() or
                    not frame.Label.isin(CLASSES).all() or not x.ge(0).to_numpy().all()):
                raise ValueError(f"Invalid {source} {part} split: {path}")
            splits[source, part] = frame

    dev = pd.concat([splits[source, part] for part in ("train", "validation") for source in SOURCES],
                    ignore_index=True)
    tests = {source: splits[source, "test"] for source in SOURCES}
    tests["combined"] = pd.concat(tests.values(), ignore_index=True)
    holdout = tests["combined"]
    if (set(dev.session_id) & set(holdout.session_id) or
            feature_hashes(dev).isin(feature_hashes(holdout)).any()):
        raise ValueError("Development and test share sessions or feature vectors.")
    # Preserve the input order within each sampled session for deterministic tree fitting.
    fit = pd.concat([session.sample(n=min(len(session), SESSION_CAP), random_state=SEED).sort_index()
                     for _, session in dev.groupby("session_id", sort=False)], ignore_index=True)
    return fit, tests


def session_folds(groups, labels):
    folds = list(LeaveOneGroupOut().split(labels, labels, groups))
    if any(len(np.unique(labels[train])) != len(CLASSES) for train, _ in folds):
        raise ValueError("Every OOF training fold must contain all four classes.")
    return folds


def build_stack(folds):
    base_models = [
        ("rf", RandomForestClassifier(n_estimators=60, max_depth=18,
                                      class_weight="balanced_subsample", n_jobs=2, random_state=SEED)),
        ("xgb", XGBClassifier(n_estimators=60, max_depth=3, learning_rate=0.1,
                              tree_method="hist", n_jobs=2, random_state=SEED)),
        ("lgbm", LGBMClassifier(n_estimators=60, max_depth=10, num_leaves=15, learning_rate=0.08,
                                n_jobs=2, verbosity=-1, random_state=SEED)),
    ]
    base = [(name, make_pipeline(SimpleImputer(strategy="median", keep_empty_features=True), model))
            for name, model in base_models]
    score_count = len(base) * len(CLASSES)
    meta_features = ColumnTransformer([
        ("scores", "passthrough", list(range(score_count))),
        ("flow", make_pipeline(FunctionTransformer(np.log1p), StandardScaler()),
         list(range(score_count, score_count + len(FEATURES)))),
    ])
    return StackingClassifier(
        estimators=base, cv=folds, passthrough=True, stack_method="predict_proba", n_jobs=1,
        final_estimator=make_pipeline(meta_features, LogisticRegression(C=0.1, max_iter=3000)),
    )


def train(prepared, out):
    out = Path(out)
    if out.exists():
        raise FileExistsError(f"Choose a new output directory: {out}")
    fit, tests = prepare_refit(prepared)
    encoder = LabelEncoder().fit(CLASSES)
    y = encoder.transform(fit.Label)
    folds = session_folds(fit.session_id, y)
    stack = build_stack(folds)
    out.mkdir(parents=True)
    print(f"Fitting {len(fit):,} flows with {len(folds)} leave-one-session-out folds", flush=True)
    started = time.perf_counter()
    stack.fit(numeric_features(fit), y)
    seconds = time.perf_counter() - started

    artifact = {
        "model": stack, "features": FEATURES, "classes": encoder.classes_.tolist(),
        "dataset": "+".join(SOURCES), "benign_labels": ["BENIGN"], "task": "multiclass",
        "feature_extractor": CONTRACT["version"], "flow_contract": CONTRACT,
        "label_taxonomy": manifest(), "model_id": MODEL_ID, "python_version": platform.python_version(),
    }
    metrics = {}
    for source, frame in tests.items():
        folder = out / source
        folder.mkdir()
        x = numeric_features(frame)
        truth = encoder.transform(frame.Label)
        metrics[source], pred = evaluate("stacking", stack, x, truth, encoder.classes_, folder, seconds)
        predictions = pd.DataFrame({"GroundTruth": frame.Label, "Prediction": encoder.inverse_transform(pred)})
        predictions.to_csv(folder / "predictions.csv", index=False)
        x.assign(ExpectedPrediction=predictions.Prediction).head(100).to_csv(folder / "smoke.csv", index=False)

    path = out / f"{MODEL_ID}.joblib"
    joblib.dump(artifact, path, compress=3)
    with path.open("rb") as stream:
        model_sha256 = file_digest(stream, "sha256").hexdigest()
    write_json(out / "REFIT_CARD.json", {
        "model_id": MODEL_ID, "seed": SEED, "session_cap": SESSION_CAP,
        "fit_rows": len(fit), "fit_sessions": len(folds), "fit_class_counts": fit.Label.value_counts().to_dict(),
        "sources": list(SOURCES), "flow_contract": CONTRACT, "python_version": artifact["python_version"],
        "base_models": list(stack.named_estimators_), "meta": "LogisticRegression with raw flow passthrough",
        "meta_iterations": int(stack.final_estimator_.steps[-1][1].n_iter_[0]),
        "model_sha256": model_sha256, "reference_metrics": metrics,
        "prepared_data": str(Path(prepared).resolve()),
        "versions": {name: version(name) for name in ("numpy", "pandas", "scipy", "scikit-learn",
                                                       "xgboost", "lightgbm", "joblib", "scapy")},
    })
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared", default="experiments/pcap-scapy-20261112-seed42",
                        help="Directory containing splits/<source>/{train,validation,test}.csv")
    parser.add_argument("--out", required=True, help="New directory for model and test reports")
    args = parser.parse_args()
    try:
        train(args.prepared, args.out)
    except (FileNotFoundError, FileExistsError, ValueError) as error:
        parser.exit(1, f"Error: {error}\n")


if __name__ == "__main__":
    main()
