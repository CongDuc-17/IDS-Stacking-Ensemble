"""Compare single-source and mixed-source training with equal class/partition budgets."""
import argparse
from argparse import Namespace
import hashlib
import json
from pathlib import Path

import pandas as pd

from features import FEATURES
from three_models import SOURCES, feature_hashes
from train import run_experiment, write_json

CONFIGURATIONS = ("CIC_matched", "InSDN_matched", "Mixed_matched")


def load_splits(run):
    run = Path(run)
    protocol = json.loads((run / "protocol.json").read_text(encoding="utf-8"))
    done = json.loads((run / "completed.json").read_text(encoding="utf-8"))
    if (protocol.get("evaluation_protocol_version") != 2 or protocol["features"] != FEATURES
            or set(done.get("configurations", [])) != {"M1", "M2", "M3"} or done.get("result_rows") != 30):
        raise ValueError("Require a completed v2 M1/M2/M3 run with the same feature contract.")
    splits, seen = {}, set()
    for source in SOURCES:
        splits[source] = {}
        for part in ("train", "validation", "test"):
            frame = pd.read_csv(run / "splits" / source / f"{part}.csv")
            hashes = feature_hashes(frame)
            digest = hashlib.sha256(hashes.to_numpy().tobytes()).hexdigest()
            expected = protocol["cleanup_and_splits"]["split_feature_sha256"][source][part]
            if (digest != expected or seen & set(hashes) or hashes.duplicated().any()
                    or frame.Label.value_counts().to_dict() != protocol["cleanup_and_splits"]["split_counts"][source][part]
                    or not frame.source_dataset.eq(source).all()):
                raise ValueError(f"Changed, overlapping or invalid source split: {source}/{part}")
            seen.update(hashes)
            splits[source][part] = frame
    return splits, protocol


def matched_development(splits, seed, folds=3):
    """Match each class in train/validation; Mixed uses half of each source."""
    result = {name: {} for name in CONFIGURATIONS}
    budgets = {}
    for part in ("train", "validation"):
        budgets[part] = {}
        for label in ("ATTACK", "BENIGN"):
            available = [splits[source][part].loc[splits[source][part].Label.eq(label)] for source in SOURCES]
            budget = 2 * (min(map(len, available)) // 2)
            if budget < max(2, folds if part == "train" else 2):
                raise ValueError(f"Too few rows for matched {part}/{label}.")
            budgets[part][label] = budget
        for name in CONFIGURATIONS:
            chunks = []
            for label, budget in budgets[part].items():
                sources = SOURCES if name == "Mixed_matched" else (SOURCES[CONFIGURATIONS.index(name)],)
                for source in sources:
                    frame = splits[source][part]
                    chunks.append(frame.loc[frame.Label.eq(label)].sample(n=budget // len(sources), random_state=seed))
            result[name][part] = pd.concat(chunks, ignore_index=True)
    return result, budgets


def run_size_ablation(runs, out):
    root = Path(out)
    if root.exists():
        raise ValueError("Choose a new --out for the ablation.")
    loaded, reference, seeds = [], None, set()
    for run in map(Path, runs):
        if run.resolve() in root.resolve().parents or run.resolve() == root.resolve():
            raise ValueError("Ablation output must be outside the source runs.")
        splits, protocol = load_splits(run)
        settings = {key: protocol["arguments"][key] for key in ("trees", "folds", "tune", "max_per_class")}
        settings["stack_search"] = protocol["arguments"].get("stack_search", False)
        settings["sources"] = {key: value["files"] for key, value in protocol["sources"].items()}
        if reference is not None and settings != reference:
            raise ValueError("Require compatible source protocols and input manifests.")
        reference = settings
        seed = protocol["arguments"]["seed"]
        if seed in seeds:
            raise ValueError("Repeated seed in ablation inputs.")
        seeds.add(seed)
        development, budgets = matched_development(splits, seed, settings["folds"])
        loaded.append((run, splits, protocol, development, budgets))
    if not loaded:
        raise ValueError("Need at least one source run.")
    root.mkdir(parents=True)
    rows = []
    for source_run, splits, protocol, development, budgets in loaded:
        seed = protocol["arguments"]["seed"]
        seed_root = root / f"seed{seed}"
        seed_root.mkdir()
        write_json(seed_root / "ablation_protocol.json", {
            "source_run": str(source_run.resolve()), "seed": seed, "budgets": budgets,
            "settings": reference, "original_split_hashes": protocol["cleanup_and_splits"]["split_feature_sha256"],
            "selection": "Same tuning budget and validation rule as the source run; no tuning on test.",
            "limitations": ["Retrospective analysis on previously inspected sampled tests, not new confirmation.",
                            "Matched counts control class/partition size, not session independence or domain artifacts."],
        })
        tests = {source: splits[source]["test"] for source in SOURCES}
        tests["combined"] = pd.concat(list(tests.values()), ignore_index=True)
        for name, parts in development.items():
            config = Namespace(**{**protocol["arguments"], "dataset": name, "out": str(seed_root / name),
                                  "data": str(source_run.resolve()), "test_data": None})
            scores = run_experiment(config, parts["train"], parts["validation"],
                                    pd.concat(list(parts.values()), ignore_index=True), tests,
                                    {"task": "binary", "split_protocol": "Matched class budgets; unchanged original tests.",
                                     "source_run": str(source_run.resolve()), "budgets": budgets})
            for part, frame in parts.items():
                frame.to_csv(seed_root / name / f"{part}.csv", index=False)
            for source, models in scores.items():
                for algorithm, metrics in models.items():
                    rows.append({"configuration": name, "test_dataset": source, "algorithm": algorithm,
                                 "seed": seed, **metrics})
        write_json(seed_root / "completed.json", {"configurations": list(CONFIGURATIONS), "result_rows": 54})
    frame = pd.DataFrame(rows)
    frame.to_csv(root / "all_seeds.csv", index=False)
    summary = frame.drop(columns="seed").groupby(["configuration", "test_dataset", "algorithm"]).agg(["mean", "std"])
    summary.to_csv(root / "mean_std.csv")
    summary.xs("stacking", level="algorithm").to_csv(root / "stacking_mean_std.csv")
    write_json(root / "completed.json", {"seeds": sorted(seeds), "result_rows": len(frame), "source_runs": [str(Path(run).resolve()) for run in runs]})
    print(f"Ablation complete: {len(frame)} rows, seeds={sorted(seeds)}", flush=True)
    return frame


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--runs", nargs="+", required=True, help="Completed v2 source runs; no raw-data resampling")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    try:
        run_size_ablation(args.runs, args.out)
    except (ValueError, KeyError, FileNotFoundError) as error:
        ap.exit(1, f"Error: {error}\n")


if __name__ == "__main__":
    main()
