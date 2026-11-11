"""Bounded CIC-IDS2017/InSDN CSV sampling with explicit schema validation."""
from collections import Counter
from pathlib import Path
import numpy as np
import pandas as pd
from features import FEATURES


ALIASES = {
    "Dst Port": "Destination Port",
    "Tot Fwd Pkts": "Total Fwd Packets",
    "Tot Bwd Pkts": "Total Backward Packets",
    "TotLen Fwd Pkts": "Total Length of Fwd Packets",
    "TotLen Bwd Pkts": "Total Length of Bwd Packets",
    "FIN Flag Cnt": "FIN Flag Count",
    "SYN Flag Cnt": "SYN Flag Count",
    "RST Flag Cnt": "RST Flag Count",
    "PSH Flag Cnt": "PSH Flag Count",
    "ACK Flag Cnt": "ACK Flag Count",
    "URG Flag Cnt": "URG Flag Count",
}


def column_name(name):
    name = name.strip().lstrip("\ufeff").strip()
    return ALIASES.get(name, name)


def numeric_features(frame):
    return frame[FEATURES].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan).astype("float64")


def read_sample(folder, max_per_class=5000, seed=42, min_class=15, *, binary=False, label_source=None):
    """Uniform priority reservoir per class: O(classes * cap + chunk) memory.

    Class caps change prevalence, including test prevalence. Raw counts are saved.
    """
    if max_per_class < min_class or min_class < 5:
        raise ValueError("Require max_per_class >= min_class >= 5.")
    if label_source is not None and binary:
        raise ValueError("Choose binary mapping or source attack families, not both.")
    folder = Path(folder)
    paths = [folder] if folder.is_file() else sorted(folder.rglob("*.csv"))
    if not paths:
        raise ValueError(f"No CSV found: {folder.resolve()}")
    required = set(FEATURES + ["Label"])
    rng = np.random.default_rng(seed)
    reservoirs, counts, missing, mapped_counts = {}, Counter(), Counter(), Counter()
    invalid_labels = empty_rows = 0
    for path in paths:
        print(f"Reading: {path.name}", flush=True)
        header = pd.read_csv(path, nrows=0, encoding="utf-8-sig").columns
        names = [column_name(c) for c in header if column_name(c) in required]
        if required - set(names) or len(names) != len(set(names)):
            raise ValueError(f"{path}: missing/ambiguous columns; missing={sorted(required - set(names))}")
        with pd.read_csv(path, chunksize=50_000, usecols=lambda c: column_name(c) in required,
                                 encoding="utf-8-sig", encoding_errors="replace", low_memory=False) as chunks:
            for chunk in chunks:
                chunk.columns = [column_name(c) for c in chunk.columns]
                labels = chunk["Label"].astype("string").str.strip()
                valid = labels.notna() & ~labels.str.lower().isin(["", "nan", "none", "null"])
                invalid_labels += int((~valid).sum())
                chunk = chunk.loc[valid].copy()
                chunk["Label"] = labels.loc[valid]
                counts.update(chunk["Label"].value_counts().to_dict())
                normal = chunk["Label"].str.casefold().isin(["benign", "normal"])
                if label_source is not None:
                    from taxonomy import map_labels
                    chunk["RawLabel"] = chunk["Label"]
                    chunk["Label"] = map_labels(chunk["Label"], label_source)
                elif binary:
                    # Map before sampling/deduplication so rare attack subtypes remain eligible.
                    chunk["Label"] = np.where(normal, "BENIGN", "ATTACK")
                else:
                    chunk.loc[normal, "Label"] = "BENIGN"
                mapped_counts.update(chunk["Label"].value_counts().to_dict())
                chunk[FEATURES] = numeric_features(chunk)
                missing.update(chunk[FEATURES].isna().sum().to_dict())
                empty = chunk[FEATURES].isna().all(axis=1)
                empty_rows += int(empty.sum())
                chunk = chunk.loc[~empty].copy()
                chunk["_priority"] = rng.random(len(chunk))
                for label, part in chunk.groupby("Label", sort=False):
                    merged = pd.concat([reservoirs[label], part], ignore_index=True) if label in reservoirs else part
                    reservoirs[label] = merged.nsmallest(max_per_class, "_priority")
    if not reservoirs:
        raise ValueError("No valid rows.")
    sample = pd.concat(reservoirs.values(), ignore_index=True).drop(columns="_priority")
    hashes = pd.util.hash_pandas_object(sample[FEATURES], index=False)
    conflicting = sample.groupby(hashes)["Label"].transform("nunique") > 1
    conflict_rows = int(conflicting.sum())
    sample = sample.loc[~conflicting].copy()
    before = len(sample)
    sample = sample.drop_duplicates(subset=FEATURES)
    duplicates = before - len(sample)
    class_sizes = sample["Label"].value_counts()
    excluded = class_sizes[class_sizes < min_class].to_dict()
    sample = sample.loc[~sample["Label"].isin(excluded)].reset_index(drop=True)
    if sample["Label"].nunique() < 2:
        raise ValueError("Need at least two retained classes. Increase --max-per-class or check data.")
    metadata = {
        "files": [{"path": str(p.resolve()), "bytes": p.stat().st_size} for p in paths],
        "seed": seed, "max_per_class": max_per_class,
        "task": "binary" if binary else "multiclass",
        "label_mapping": "BENIGN/Normal (case-insensitive) -> BENIGN; all other valid labels -> ATTACK" if binary else "BENIGN/Normal (case-insensitive) -> BENIGN; retain attack subtypes",
        "sampling": "uniform priority reservoir per binary class, then feature deduplication" if binary else "uniform priority reservoir per raw class, then feature deduplication",
        "prevalence": "class-capped sample, NOT original traffic prevalence",
        "raw_class_counts": dict(counts), "invalid_labels": invalid_labels,
        "raw_missing_or_nonfinite": dict(missing), "all_features_missing_rows": empty_rows,
        "sample_conflicting_rows_removed": conflict_rows, "sample_duplicate_rows_removed": duplicates,
        "excluded_classes_below_minimum": {str(k): int(v) for k, v in excluded.items()},
        "sample_class_counts": {str(k): int(v) for k, v in sample["Label"].value_counts().items()},
    }
    if label_source is not None:
        from taxonomy import manifest, map_labels
        metadata.update(label_source=label_source, label_taxonomy=manifest(),
                        label_mapping="source-specific attack families before sampling; retain RawLabel for audit",
                        sampling="uniform priority reservoir per mapped family per source, then feature deduplication",
                        mapped_class_counts=dict(mapped_counts),
                        raw_to_family={raw: map_labels(pd.Series([raw]), label_source).iloc[0] for raw in counts})
    return sample, metadata
