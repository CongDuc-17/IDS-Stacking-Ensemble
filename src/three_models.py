"""Binary M1/M2/M3 experiments with shared, globally deduplicated test sets."""
from argparse import Namespace
import hashlib
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

from dataset import numeric_features, read_sample
from features import FEATURES


SOURCES = ("cicids2017", "insdn")


def feature_hashes(frame):
    return pd.util.hash_pandas_object(numeric_features(frame), index=False)


def prepare_splits(cic, insdn, seed=42, folds=3):
    """Deduplicate across sources before any split; preserve source-specific tests."""
    if folds < 2:
        raise ValueError("Require folds >= 2.")
    frames = []
    for source, frame in zip(SOURCES, (cic, insdn)):
        if set(frame["Label"]) != {"BENIGN", "ATTACK"}:
            raise ValueError(f"{source}: require both binary labels BENIGN and ATTACK.")
        frame = frame.copy()
        frame[FEATURES] = numeric_features(frame)
        frame["source_dataset"] = source
        frames.append(frame)
    combined = pd.concat(frames, ignore_index=True)
    hashes = feature_hashes(combined)
    conflicts = combined.groupby(hashes)["Label"].transform("nunique") > 1
    consistent = combined.loc[~conflicts]
    duplicates = consistent.duplicated(FEATURES, keep="first")
    clean = consistent.loc[~duplicates].copy()
    metadata = {
        "conflicting_rows_removed": int(conflicts.sum()),
        "duplicate_rows_removed": int(duplicates.sum()),
        "duplicate_policy": "Remove contradictory binary labels; keep first identical vector (CIC before InSDN) before splitting.",
        "rows_before": combined.groupby("source_dataset").size().to_dict(),
        "rows_after": clean.groupby("source_dataset").size().to_dict(),
    }
    splits = {}
    for source in SOURCES:
        data = clean.loc[clean.source_dataset == source].reset_index(drop=True)
        counts = data["Label"].value_counts()
        if set(counts.index) != {"BENIGN", "ATTACK"} or counts.min() < max(15, 2 * folds):
            raise ValueError(f"{source}: too few unique rows per binary class after global cleanup: {counts.to_dict()}")
        dev, test = train_test_split(data, test_size=0.2, random_state=seed, stratify=data.Label)
        train, val = train_test_split(dev, test_size=0.25, random_state=seed, stratify=dev.Label)
        if train.Label.value_counts().min() < folds:
            raise ValueError(f"{source}: training class count is below folds={folds}.")
        splits[source] = {name: frame.reset_index(drop=True)
                          for name, frame in (("train", train), ("validation", val), ("test", test))}
    # Guard the whole protocol, including M3's union of both development sets.
    groups = [set(feature_hashes(frame)) for parts in splits.values() for frame in parts.values()]
    if any(groups[i] & groups[j] for i in range(len(groups)) for j in range(i)):
        raise ValueError("Feature overlap across source/split boundaries.")
    metadata["split_counts"] = {
        source: {name: frame.Label.value_counts().to_dict() for name, frame in parts.items()}
        for source, parts in splits.items()
    }
    metadata["split_feature_sha256"] = {
        source: {name: hashlib.sha256(feature_hashes(frame).to_numpy().tobytes()).hexdigest()
                 for name, frame in parts.items()} for source, parts in splits.items()
    }
    return splits, metadata


def run_three_models(args):
    # Validate paths before importing optional training dependencies or creating output.
    cic_path, insdn_path = Path(args.cic_data).resolve(), Path(args.insdn_data).resolve()
    if cic_path == insdn_path or cic_path in insdn_path.parents or insdn_path in cic_path.parents:
        raise ValueError("CIC and InSDN inputs must be separate, non-overlapping paths.")
    for path in (cic_path, insdn_path):
        if not path.exists() or (path.is_dir() and not any(path.rglob("*.csv"))):
            raise ValueError(f"No input CSV: {path}")
    root = Path(args.out)
    if root.exists() and (not root.is_dir() or any(root.iterdir())):
        raise ValueError(f"Output directory is not empty: {root}. Choose a new --out.")
    if args.trees < 1 or args.folds < 2 or args.max_per_class < 15:
        raise ValueError("Require trees >= 1, folds >= 2 and max-per-class >= 15.")
    if root.resolve() in (cic_path, insdn_path) or any(p in root.resolve().parents for p in (cic_path, insdn_path)):
        raise ValueError("Experiment output must be outside the input dataset directories.")
    from train import run_experiment, write_json

    cic, cic_meta = read_sample(cic_path, args.max_per_class, args.seed, binary=True)
    insdn, insdn_meta = read_sample(insdn_path, args.max_per_class, args.seed, binary=True)
    splits, cleanup = prepare_splits(cic, insdn, args.seed, args.folds)
    root.mkdir(parents=True, exist_ok=True)
    manifest = {
        "arguments": vars(args), "task": "binary detection; BENIGN versus ATTACK",
        "evaluation_protocol_version": 2,
        "features": FEATURES, "sources": {"cicids2017": cic_meta, "insdn": insdn_meta},
        "cleanup_and_splits": cleanup,
        "protocol": "Split each source 60/20/20 after global exact-feature cleanup; M3 unions train/validation, reuses both tests.",
        "limitations": [
            "Random split does not isolate related sessions or collection times.",
            "Binary class caps and global deduplication change class/source prevalence.",
            "Matching column names do not establish feature-extractor parity between datasets or live traffic.",
            "This compares pooled-data training; it is not unseen-domain validation.",
        ],
    }
    write_json(root / "protocol.json", manifest)
    for source, parts in splits.items():
        folder = root / "splits" / source
        folder.mkdir(parents=True)
        for name, frame in parts.items():
            frame.to_csv(folder / f"{name}.csv", index=False)
    specs = [("M1", ("cicids2017",), ("cicids2017",)),
             ("M2", ("insdn",), ("insdn",))]
    if args.combined:
        specs.append(("M3", SOURCES, SOURCES))
    rows = []
    for configuration, train_sources, test_sources in specs:
        print(f"\n=== {configuration}: train {', '.join(train_sources)} ===", flush=True)
        train = pd.concat([splits[s]["train"] for s in train_sources], ignore_index=True)
        val = pd.concat([splits[s]["validation"] for s in train_sources], ignore_index=True)
        dev = pd.concat([train, val], ignore_index=True)
        tests = {source: splits[source]["test"] for source in test_sources}
        if configuration == "M3":
            tests["combined"] = pd.concat([splits[s]["test"] for s in SOURCES], ignore_index=True)
        config = Namespace(**{**vars(args), "data": [str(cic_path), str(insdn_path)],
                              "dataset": "+".join(train_sources), "out": str(root / configuration), "test_data": None})
        scores = run_experiment(config, train, val, dev, tests, {
            "configuration": configuration, "training_sources": list(train_sources),
            "task": "binary",
            "shared_protocol": str((root / "protocol.json").resolve()),
            "split_protocol": manifest["protocol"],
        })
        for test_source, models in scores.items():
            for model, metrics in models.items():
                rows.append({"configuration": configuration, "test_dataset": test_source,
                             "algorithm": model, "seed": args.seed, **metrics})
        # Keep completed configurations reviewable if a later configuration fails.
        pd.DataFrame(rows).to_csv(root / "comparison_all.csv", index=False)
    frame = pd.DataFrame(rows)
    frame.loc[frame.algorithm == "stacking"].to_csv(root / "comparison_stacking.csv", index=False)
    write_json(root / "completed.json", {"configurations": [spec[0] for spec in specs], "result_rows": len(rows)})
    print(f"\nCompleted: {root.resolve() / 'comparison_stacking.csv'}", flush=True)
    return frame
