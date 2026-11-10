"""Aggregate preplanned seeds of a compatible single-dataset or M1/M2/M3 protocol."""
import argparse
import json
from pathlib import Path
import pandas as pd


def summarize_three_models(runs, out):
    """Aggregate only completed, compatible M1/M2/M3 runs; keep each test separate."""
    frames, reference = [], None
    for run in map(Path, runs):
        if not (run / "completed.json").exists():
            raise ValueError(f"Incomplete three-model run: {run}")
        protocol = json.loads((run / "protocol.json").read_text(encoding="utf-8"))
        completed = json.loads((run / "completed.json").read_text(encoding="utf-8"))
        settings = {key: protocol["arguments"][key]
                    for key in ("max_per_class", "trees", "folds", "tune", "combined")}
        settings.update(task=protocol["task"], features=protocol["features"],
                        stack_search=protocol["arguments"].get("stack_search", False),
                        evaluation_protocol_version=protocol.get("evaluation_protocol_version", 1),
                        sources={source: meta["files"] for source, meta in protocol["sources"].items()},
                        split_protocol=protocol.get("protocol"),
                        duplicate_policy=protocol.get("cleanup_and_splits", {}).get("duplicate_policy"))
        if reference is not None and settings != reference:
            raise ValueError("Do not aggregate different three-model protocols or input file manifests.")
        reference = settings
        frame = pd.read_csv(run / "comparison_all.csv")
        if frame.empty or set(frame.seed) != {protocol["arguments"]["seed"]}:
            raise ValueError(f"Missing rows or seed mismatch: {run}")
        configurations = {"M1", "M2", "M3"} if settings["combined"] else {"M1", "M2"}
        pairs = {("M1", "cicids2017"), ("M2", "insdn")}
        if settings["combined"]:
            pairs |= {("M3", "cicids2017"), ("M3", "insdn")}
            if settings["evaluation_protocol_version"] >= 2:
                pairs.add(("M3", "combined"))
        algorithms = {"dt", "rf", "xgb", "lgbm", "lr", "stacking"}
        expected_rows = {(config, source, model) for config, source in pairs for model in algorithms}
        actual_rows = set(map(tuple, frame[["configuration", "test_dataset", "algorithm"]].to_numpy()))
        if (set(completed.get("configurations", [])) != configurations
                or completed.get("result_rows") != len(frame) or actual_rows != expected_rows):
            raise ValueError(f"Incomplete or inconsistent configuration/test/algorithm results: {run}")
        frames.append(frame)
    frame = pd.concat(frames, ignore_index=True)
    keys = ["configuration", "test_dataset", "algorithm"]
    if frame.duplicated(keys + ["seed"]).any():
        raise ValueError("Repeated configuration/test/algorithm/seed.")
    root = Path(out)
    root.mkdir(parents=True, exist_ok=True)
    frame.to_csv(root / "all_seeds.csv", index=False)
    summary = frame.drop(columns="seed").groupby(keys).agg(["mean", "std"])
    summary.to_csv(root / "mean_std.csv")
    summary.xs("stacking", level="algorithm").to_csv(root / "stacking_mean_std.csv")
    print(summary[["accuracy", "macro_f1"]].round(6).to_string())
    return summary


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--runs", nargs="+", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    if any((Path(run) / "comparison_all.csv").exists() for run in args.runs):
        summarize_three_models(args.runs, args.out)
        return
    records, protocols = [], []
    for run in map(Path, args.runs):
        protocol = json.loads((run / "protocol.json").read_text(encoding="utf-8"))
        scores = json.loads((run / "comparison.json").read_text(encoding="utf-8"))
        protocols.append(protocol)
        for model, metrics in scores.items():
            records.append({"model": model, "seed": protocol["arguments"]["seed"], **metrics})
    reference = protocols[0]
    for protocol in protocols[1:]:
        if protocol["arguments"].get("stack_search", False) != reference["arguments"].get("stack_search", False):
            raise ValueError("Do not aggregate different stack-search settings.")
        keys = ["max_per_class", "trees", "folds", "tune", "test_data"]
        if protocol["dataset"] != reference["dataset"] or any(protocol["arguments"][k] != reference["arguments"][k] for k in keys):
            raise ValueError("Do not aggregate different datasets or experiment configurations.")
        if protocol.get("task", "multiclass") != reference.get("task", "multiclass"):
            raise ValueError("Do not aggregate binary and multiclass experiments.")
        if set(protocol["data"]["sample_class_counts"]) != set(reference["data"]["sample_class_counts"]):
            raise ValueError("Retained class sets differ. Report those runs separately.")
        if protocol["data"]["files"] != reference["data"]["files"]:
            raise ValueError("Input file manifests differ. Report those runs separately.")
    frame = pd.DataFrame(records)
    if frame.duplicated(["model", "seed"]).any():
        raise ValueError("Repeated model/seed: each preplanned seed must be counted only once.")
    root = Path(args.out)
    root.mkdir(parents=True, exist_ok=True)
    frame.to_csv(root / "all_seeds.csv", index=False)
    summary = frame.drop(columns="seed").groupby("model").agg(["mean", "std"])
    summary.to_csv(root / "mean_std.csv")
    print(summary[["accuracy", "macro_f1"]].round(6).to_string())


if __name__ == "__main__":
    main()
