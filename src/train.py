"""CIC-IDS2017/InSDN baselines and two-level out-of-fold stacking, one dataset per run."""
from __future__ import annotations
import argparse
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import platform
import time
import joblib
import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.ensemble import RandomForestClassifier, StackingClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import GridSearchCV, StratifiedKFold, cross_val_predict, train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.tree import DecisionTreeClassifier
from dataset import numeric_features, read_sample
from features import FEATURES


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False), encoding="utf-8")


def estimators(trees, seed):
    from lightgbm import LGBMClassifier
    from xgboost import XGBClassifier
    return {
        "dt": (DecisionTreeClassifier(class_weight="balanced", random_state=seed), {"max_depth": [8, 18]}),
        "rf": (RandomForestClassifier(n_estimators=trees, max_depth=18,
               class_weight="balanced_subsample", n_jobs=2, random_state=seed), {"max_depth": [10, 18]}),
        "xgb": (XGBClassifier(n_estimators=trees, max_depth=6, learning_rate=0.1,
                tree_method="hist", n_jobs=2, random_state=seed), {"max_depth": [3, 6]}),
        "lgbm": (LGBMClassifier(n_estimators=trees, max_depth=10, num_leaves=31,
                 learning_rate=0.08, n_jobs=2, verbosity=-1, random_state=seed), {"num_leaves": [15, 31]}),
        "lr": (LogisticRegression(max_iter=3000, class_weight="balanced", random_state=seed), {"C": [0.1, 1.0]}),
    }


def pipeline(name, model):
    steps = [SimpleImputer(strategy="median", keep_empty_features=True)]
    if name == "lr":
        steps.append(StandardScaler())
    return make_pipeline(*steps, model)


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


def split_data(data, seed, external=None):
    if external is None:
        dev, test = train_test_split(data, test_size=0.2, random_state=seed, stratify=data["Label"])
        removed = 0
    else:
        test = external
        hashes = pd.util.hash_pandas_object(test[FEATURES], index=False)
        overlap = pd.util.hash_pandas_object(data[FEATURES], index=False).isin(set(hashes))
        removed = int(overlap.sum())
        dev = data.loc[~overlap]
        if set(test["Label"]) - set(dev["Label"]):
            raise ValueError("External test contains classes missing from training after overlap purge.")
        if dev["Label"].value_counts().min() < 10:
            raise ValueError("Too few development rows after external-test overlap purge.")
    train, val = train_test_split(dev, test_size=0.25, random_state=seed, stratify=dev["Label"])
    hashes = [set(pd.util.hash_pandas_object(f[FEATURES], index=False)) for f in (train, val, test)]
    if any(hashes[i] & hashes[j] for i in range(3) for j in range(i)):
        raise ValueError("Duplicate feature rows cross splits.")
    return train, val, dev, test, removed


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", required=True, help="ONE dataset directory or CSV")
    ap.add_argument("--dataset", required=True, help="Dataset name for provenance")
    ap.add_argument("--out", required=True, help="New experiment directory")
    ap.add_argument("--test-data", help="Independent holdout CSV/directory with same schema")
    ap.add_argument("--max-per-class", type=int, default=5000)
    ap.add_argument("--trees", type=int, default=120)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--folds", type=int, default=3)
    ap.add_argument("--binary", action="store_true", help="Map BENIGN/Normal versus all attacks before sampling")
    ap.add_argument("--tune", action="store_true", help="Two candidates per baseline, training-only CV")
    ap.add_argument("--stack-search", action="store_true", help="Select meta C/weight on validation using cached training OOF probabilities")
    args = ap.parse_args()
    if args.trees < 1 or args.folds < 2 or args.max_per_class < 15:
        ap.error("Require trees >= 1, folds >= 2 and max-per-class >= 15.")
    root = Path(args.out)
    if (root / "protocol.json").exists() or (root / "comparison.json").exists():
        ap.error("Completed run exists. Choose a new --out to preserve results.")
    root.mkdir(parents=True, exist_ok=True)
    data, metadata = read_sample(args.data, args.max_per_class, args.seed, binary=args.binary)
    external, external_metadata = None, None
    if args.test_data:
        external, external_metadata = read_sample(args.test_data, args.max_per_class, args.seed, binary=args.binary)
    train, val, dev, test, removed = split_data(data, args.seed, external)
    run_experiment(args, train, val, dev, test, metadata, external_metadata, removed)


def run_experiment(args, train, val, dev, test, metadata, external_metadata=None, removed=0, *, stack_variant=None):
    """Refit once and evaluate a DataFrame or named tests; retain the single-test API."""
    root = Path(args.out)
    if (root / "protocol.json").exists() or (root / "comparison.json").exists():
        raise ValueError(f"Completed run exists: {root}. Choose a new --out.")
    root.mkdir(parents=True, exist_ok=True)
    multiple_tests = isinstance(test, dict)
    tests = test if multiple_tests else {"test": test}
    if train.empty or val.empty or dev.empty or not tests:
        raise ValueError("Require nonempty training, validation, development and test data.")
    if train["Label"].value_counts().min() < args.folds:
        raise ValueError("Rarest training class has fewer rows than --folds.")
    encoder = LabelEncoder().fit(dev["Label"])
    x_train, x_val, x_dev = [numeric_features(f) for f in (train, val, dev)]
    y_train, y_val, y_dev = [encoder.transform(f["Label"]) for f in (train, val, dev)]
    dev_hashes = set(pd.util.hash_pandas_object(x_dev, index=False))
    test_inputs = {}
    for test_name, frame in tests.items():
        if frame.empty or set(frame["Label"]) - set(encoder.classes_):
            raise ValueError(f"Empty test or labels absent from development data: {test_name}")
        x_test = numeric_features(frame)
        if dev_hashes & set(pd.util.hash_pandas_object(x_test, index=False)):
            raise ValueError(f"Development/test feature overlap: {test_name}")
        test_root = root if test_name == "test" else root / test_name
        test_root.mkdir(parents=True, exist_ok=True)
        test_inputs[test_name] = (x_test, encoder.transform(frame["Label"]), test_root)
    if not multiple_tests:
        split_root = root / "splits"
        split_root.mkdir(exist_ok=True)
        for name, frame in (("train", train), ("validation", val), ("test", test)):
            frame.to_csv(split_root / f"{name}.csv", index=False)
    cv = StratifiedKFold(args.folds, shuffle=True, random_state=args.seed)
    chosen, selection, validation_proba = {}, {}, {}
    stack_search = getattr(args, "stack_search", False)
    variants = {"trees": ["rf", "xgb", "lgbm"], "diverse": ["rf", "xgb", "lr"]}
    if stack_variant is not None:
        variants = {stack_variant: variants[stack_variant]}
    stack_bases = dict.fromkeys(name for names in variants.values() for name in names)
    experiment_start = time.perf_counter()
    for name, (model, grid) in estimators(args.trees, args.seed).items():
        print(f"Selecting baseline {name}...", flush=True)
        candidate = pipeline(name, model)
        if args.tune:
            last = candidate.steps[-1][0]
            search = GridSearchCV(candidate, {f"{last}__{k}": v for k, v in grid.items()},
                                  cv=cv, scoring="f1_macro", n_jobs=1, error_score="raise")
            search.fit(x_train, y_train)
            candidate = search.best_estimator_
            selection[name] = {
                "best_parameters": search.best_params_, "train_cv_macro_f1": float(search.best_score_),
                "cv_candidates": [dict(params=p, mean_macro_f1=float(s), std_macro_f1=float(sd))
                    for p, s, sd in zip(search.cv_results_["params"], search.cv_results_["mean_test_score"], search.cv_results_["std_test_score"])],
            }
        else:
            candidate.fit(x_train, y_train)
            selection[name] = {"best_parameters": "fixed; tuning disabled"}
        selection[name]["validation_macro_f1"] = float(f1_score(y_val, candidate.predict(x_val), average="macro"))
        chosen[name] = clone(candidate)
        if stack_search and name in stack_bases:
            validation_proba[name] = candidate.predict_proba(x_val)
    oof = {}
    if stack_search:
        for name in stack_bases:
            print(f"Training-only OOF probabilities: {name}...", flush=True)
            oof[name] = cross_val_predict(chosen[name], x_train, y_train, cv=cv, method="predict_proba", n_jobs=1)
        np.savez_compressed(root / "stack_oof.npz", **oof, y_train=y_train)
    stack_candidates = {}
    for variant, names in variants.items():
        print(f"Selecting OOF stack: {variant}...", flush=True)
        meta_grid = [(c, weight) for c in (.1, 1., 10.) for weight in (None, "balanced")] if stack_search else [(1., "balanced")]
        for c, weight in meta_grid:
            meta = LogisticRegression(C=c, class_weight=weight, max_iter=3000)
            candidate = StackingClassifier(
                estimators=[(n, clone(chosen[n])) for n in names], final_estimator=clone(meta),
                cv=cv, stack_method="predict_proba", passthrough=False, n_jobs=1,
            )
            if stack_search:
                # Match StackingClassifier: drop the first probability column for binary tasks.
                columns = slice(1, None) if len(encoder.classes_) == 2 else slice(None)
                meta_train = np.hstack([oof[n][:, columns] for n in names])
                meta_val = np.hstack([validation_proba[n][:, columns] for n in names])
                meta.fit(meta_train, y_train)
                prediction = meta.predict(meta_val)
                key = f"{variant}_C{c:g}_{weight or 'unweighted'}"
            else:
                candidate.fit(x_train, y_train)
                prediction = candidate.predict(x_val)
                key = variant
            score = float(f1_score(y_val, prediction, average="macro", zero_division=0))
            selection[f"stack_{key}"] = {"base_models": names, "meta_C": c, "meta_class_weight": weight,
                                          "validation_macro_f1": score}
            stack_candidates[key] = (score, clone(candidate))
    winner = max(stack_candidates, key=lambda k: stack_candidates[k][0])
    chosen["stacking"] = stack_candidates[winner][1]
    write_json(root / "selection.json", selection)
    all_scores = {name: {} for name in tests}
    all_predictions = {name: {} for name in tests}
    for name, candidate in chosen.items():
        print(f"Final fit on development data: {name}...", flush=True)
        start = time.perf_counter()
        candidate.fit(x_dev, y_dev)
        fitted_seconds = time.perf_counter() - start
        for test_name, (x_test, y_test, test_root) in test_inputs.items():
            all_scores[test_name][name], all_predictions[test_name][name] = evaluate(
                name, candidate, x_test, y_test, encoder.classes_, test_root, fitted_seconds,
                metric_labels=np.unique(y_test) if "label_taxonomy" in metadata else None)
        if name == "stacking":
            model_dir = root / "models"
            model_dir.mkdir(exist_ok=True)
            artifact = {"model": candidate, "features": FEATURES, "classes": list(encoder.classes_),
                        "dataset": args.dataset, "benign_labels": ["BENIGN"],
                        "task": metadata.get("task", "multiclass"),
                        "feature_extractor": "dataset-cicflowmeter",
                        "python_version": platform.python_version(),
                        "training_note": "Offline sampled reference; live traffic accuracy has not been validated."}
            if "label_taxonomy" in metadata:
                artifact["label_taxonomy"] = metadata["label_taxonomy"]
            joblib.dump(artifact, model_dir / "stacking_ids.joblib", compress=3)
            write_json(model_dir / "features.json", FEATURES)
            packages = ["numpy", "pandas", "scipy", "scikit-learn", "xgboost", "lightgbm", "joblib"]
            (model_dir / "requirements-deploy.txt").write_text(
                "\n".join(f"{p}=={version(p)}" for p in packages) + "\n", encoding="utf-8")
    test_summaries = {}
    for test_name, (x_test, y_test, test_root) in test_inputs.items():
        scores, predictions = all_scores[test_name], all_predictions[test_name]
        comparison = pd.DataFrame(scores).T
        comparison.index.name = "model"
        comparison.to_csv(test_root / "comparison.csv")
        write_json(test_root / "comparison.json", scores)
        best = max((n for n in scores if n != "stacking"), key=lambda n: scores[n]["macro_f1"])
        delta = scores["stacking"]["macro_f1"] - scores[best]["macro_f1"]
        test_summaries[test_name] = {"best_test_baseline_descriptive_only": best,
            "stacking_minus_best_baseline_macro_f1": delta, "stacking_improved_this_test": bool(delta > 0)}
        smoke = x_test.iloc[:100].copy()
        smoke["ExpectedPrediction"] = encoder.inverse_transform(predictions["stacking"][:100])
        smoke["GroundTruth"] = encoder.inverse_transform(y_test[:100])
        smoke.to_csv(test_root / "smoke_test.csv", index=False)
        pd.DataFrame({"GroundTruth": encoder.inverse_transform(y_test),
                      **{n: encoder.inverse_transform(p) for n, p in predictions.items()}}).to_csv(test_root / "predictions.csv", index=False)
        print(f"{test_name}: selected stack={winner}; delta macro-F1 vs {best}={delta:+.6f}", flush=True)
    split_frames = {"train": train, "validation": val, **tests}
    protocol = {
        "dataset": args.dataset, "arguments": vars(args), "data": metadata,
        "external_test_data": external_metadata, "overlap_training_rows_removed": removed,
        "task": metadata.get("task", "multiclass"),
        "split": metadata.get("split_protocol", "independent external holdout" if external_metadata is not None else "60/20/20 stratified random; NOT temporal/session isolation"),
        "split_class_counts": {n: {str(k): int(v) for k, v in f["Label"].value_counts().items()}
                               for n, f in split_frames.items()},
        "split_feature_sha256": {n: hashlib.sha256(pd.util.hash_pandas_object(f[FEATURES], index=False).to_numpy().tobytes()).hexdigest()
                                 for n, f in split_frames.items()},
        "selected_stack": winner, "selection_metric": "validation macro F1; test only after selection",
        "stack_search": stack_search,
        **(test_summaries["test"] if "test" in test_summaries else {}),
        "test_summaries": test_summaries,
        "total_training_seconds": time.perf_counter() - experiment_start,
        "python_version": platform.python_version(), "features": FEATURES,
        "limitations": ["Class sampling and feature deduplication change test prevalence.",
                        "Rare classes may be excluded; inspect raw counts and exclusions.",
                        "Exact-feature duplicates purged; related sessions may cross random splits.",
                        "Tuning before OOF is not nested tuning: held-out test is the evaluation.",
                        "Single-seed delta is descriptive, not statistical significance.",
                        "Batch inference timing is not end-to-end live latency."],
    }
    write_json(root / "protocol.json", protocol)
    print(f"Results: {root.resolve()}", flush=True)
    return all_scores if multiple_tests else all_scores["test"]


if __name__ == "__main__":
    main()
