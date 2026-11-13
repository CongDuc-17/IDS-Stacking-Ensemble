"""Build named PCAP experiments from a plan of labeled capture sessions."""

import argparse
from collections import Counter
from datetime import datetime
import json
from pathlib import Path
import subprocess
import sys

import numpy as np
import pandas as pd

from dataset import numeric_features
from features import FEATURES
from flows import EXTRACTOR_VERSION
from match_capture_labels import endpoints, reference_index
from taxonomy import label_key, manifest, map_labels
from three_models import SOURCES, feature_hashes, fit_model_runs
from train import write_json


PARTS = ("train", "validation", "test")
NAMES = ("PCAP-CIC", "PCAP-InSDN", "PCAP-Combined")
CONTRACT = {"version": EXTRACTOR_VERSION, "idle": 10.0, "max_age": 60.0, "max_flows": 10000}


def epoch(value):
    time = datetime.fromisoformat(value)
    if time.utcoffset() is None:
        raise ValueError(f"Window timestamp requires timezone: {value}")
    return time.timestamp()


def validate_plan(plan):
    seen = set()
    ranges = {}
    for case in plan:
        session, capture = case["id"], Path(case["pcap"]).resolve()
        if (not session or Path(session).name != session or session in {".", ".."} or session in seen or
                case["source"] not in SOURCES or case["split"] not in PARTS or not capture.is_file()):
            raise ValueError(f"Invalid or duplicate session: {session}")
        seen.add(session)
        start, stop = map(epoch, case["window"]) if "window" in case else (-np.inf, np.inf)
        if start >= stop or any(start < last + CONTRACT["max_age"] and stop + CONTRACT["max_age"] > first
                                for first, last in ranges.get(capture, ())):
            raise ValueError(f"Overlapping or adjacent windows for {capture}")
        ranges.setdefault(capture, []).append((start, stop))
        map_labels(pd.Series([case["label"]]), case["source"])


def reference_agrees(row, index, expected):
    direction, key = endpoints(row.src_ip, row.src_port, row.dst_ip, row.dst_port, row.protocol)
    first, last = row.flow_first_epoch, row.flow_last_epoch
    overlapping = []
    for ref in index.get(key, ()):
        duration = ref.measurement[0]
        if np.isfinite(duration) and duration >= 0:
            end = ref.start + ref.precision + duration / 1e6
            if ref.start <= last and end > first:
                overlapping.append((ref, end))
    return (bool(overlapping) and all(label_key(ref.label) == expected for ref, _ in overlapping) and
            any(ref.direction == direction and ref.start <= first and end >= last for ref, end in overlapping))


def label_session(frame, case):
    if not frame["flow_extractor_version"].eq(CONTRACT["version"]).all() or "Label" in frame:
        raise ValueError(f"Expected unlabeled {CONTRACT['version']} flows: {case['id']}")
    first, last = frame.flow_first_epoch, frame.flow_last_epoch
    usable = (np.isfinite(first) & np.isfinite(last) & first.le(last) &
              frame.protocol.isin(["TCP", "UDP"]) & frame.flow_close_reason.ne("capacity"))
    if "window" in case:
        start, stop = map(epoch, case["window"])
        if not (first.ge(start) & last.lt(stop) & frame.flow_close_reason.ne("end")).all():
            raise ValueError(f"Flow crosses capture window: {case['id']}")
    features = numeric_features(frame)
    usable &= (np.isfinite(features) & features.ge(0)).all(axis=1)
    for field, allowed in case.get("equals", {}).items():
        usable &= frame[field].isin(allowed)
    for field, minimum in case.get("minimum", {}).items():
        usable &= frame[field].ge(minimum)
    if "exclude_src_ports" in case:
        usable &= ~frame.src_port.isin(case["exclude_src_ports"])
    selected = frame.loc[usable].copy()
    if "reference" in case and not selected.empty:
        rows = list(selected.itertuples(index=False))
        keys = {endpoints(r.src_ip, r.src_port, r.dst_ip, r.dst_port, r.protocol)[1] for r in rows}
        refs = reference_index(Path(case["reference"]), keys, case.get("shift_minutes", 0), case.get("afternoon", False))
        selected = selected.loc[[reference_agrees(r, refs, label_key(case["label"])) for r in rows]].copy()
    selected["source_dataset"] = case["source"]
    selected["session_id"] = case["id"]
    selected["source_capture"] = case["pcap"]
    selected["RawLabel"] = case["label"]
    selected["label_source"] = case["evidence"]
    selected["Label"] = case["label"]
    return selected, int(usable.sum())


def collect_sessions(plan, out, cache):
    script = Path(__file__).with_name("extract.py")
    audits, frames = [], []
    for case in plan:
        session = case["id"]
        path = Path(case["cached_flows"]) if cache and "cached_flows" in case else out / "raw" / f"{session}.csv"
        if not cache or "cached_flows" not in case:
            command = [sys.executable, str(script), "--pcap", case["pcap"], "--out", str(path)]
            if "window" in case:
                command += ["--window", *[str(epoch(t)) for t in case["window"]]]
            subprocess.run(command, check=True)
        frame = pd.read_csv(path)
        labeled, eligible = label_session(frame, case)
        print(f"{session}: {len(labeled)}/{len(frame)} labeled", flush=True)
        audits.append({"session": session, "source": case["source"], "split": case["split"], "raw_label": case["label"],
                       "extracted": len(frame), "eligible": eligible, "labeled": len(labeled), "flows": str(path)})
        labeled["split"] = case["split"]
        frames.append(labeled)
    pd.DataFrame(audits).to_csv(out / "label_audit.csv", index=False)
    result = pd.concat(frames, ignore_index=True)
    if result.empty:
        raise ValueError("The plan yielded no labeled flows.")
    return result


def partition(data, cap, seed):
    data = data.copy()
    for source in SOURCES:
        mask = data.source_dataset.eq(source)
        data.loc[mask, "Label"] = map_labels(data.loc[mask, "RawLabel"], source)
    data[FEATURES] = numeric_features(data)
    test = data.loc[data.split.eq("test")].copy()
    val = data.loc[data.split.eq("validation")].copy()
    train = data.loc[data.split.eq("train")].copy()
    # Keep held-out rows. Purge exact vector overlap from earlier partitions.
    heldout = set(feature_hashes(test))
    val = val.loc[~feature_hashes(val).isin(heldout)].copy()
    blocked = heldout | set(feature_hashes(val))
    hashes = feature_hashes(train)
    conflicts = train.groupby(hashes).Label.transform("nunique").gt(1)
    train = train.loc[~conflicts & ~hashes.isin(blocked)].drop_duplicates(FEATURES)
    sampled = []
    for _, family in train.groupby(["source_dataset", "Label"]):
        sessions = list(family.groupby("session_id"))
        budget, extra = divmod(cap, len(sessions))
        if not budget:
            raise ValueError("Training cap is smaller than the number of sessions in a class.")
        sampled.extend(part.sample(n=min(len(part), budget + int(i < extra)), random_state=seed)
                       for i, (_, part) in enumerate(sessions))
    if not sampled:
        raise ValueError("No train rows remain after deduplication.")
    parts = dict(zip(PARTS, (pd.concat(sampled), val, test)))
    splits = {source: {name: frame.loc[frame.source_dataset.eq(source)].reset_index(drop=True)
                       for name, frame in parts.items()} for source in SOURCES}
    for source, tables in splits.items():
        trained = set(tables["train"].Label)
        if len(trained) < 2 or any(frame.empty or set(frame.Label) - trained for frame in tables.values()):
            raise ValueError(f"Missing training classes or empty partition: {source}: " +
                             str({part: Counter(frame.Label) for part, frame in tables.items()}))
    return splits


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--out", required=True, help="New experiment directory")
    parser.add_argument("--reuse-extracted", action="store_true", help="Use the extracted CSV paths recorded in the plan")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--folds", type=int, default=2)
    parser.add_argument("--trees", type=int, default=60)
    parser.add_argument("--max-per-class", type=int, default=2000)
    args = parser.parse_args()
    if args.folds < 2 or args.trees < 1 or args.max_per_class < 15:
        parser.error("Require at least two folds, one tree and 15 rows per class cap.")
    args.combined = args.multiclass = args.tune = args.stack_search = True
    out = Path(args.out)
    plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
    validate_plan(plan)
    out.mkdir(parents=True)
    write_json(out / "session_plan.json", plan)
    data = collect_sessions(plan, out, args.reuse_extracted)
    splits = partition(data, args.max_per_class, args.seed)
    inputs, mappings = [], []
    support = {}
    for source, parts in splits.items():
        subset = data.loc[data.source_dataset.eq(source)]
        path = out / f"{source}-labeled.csv"
        subset.to_csv(path, index=False)
        inputs.append(path)
        raw = subset.RawLabel.value_counts()
        for label, count in raw.items():
            mappings.append({"source_dataset": source, "raw_label": label,
                             "family": map_labels(pd.Series([label]), source).iloc[0], "raw_rows": count})
        support[source] = pd.concat(list(parts.values())).Label.value_counts()
        subprocess.run([sys.executable, str(Path(__file__).with_name("eda.py")), "--data", str(path),
                        "--out", str(out / "eda" / source), "--seed", str(args.seed),
                        "--max-per-class", str(args.max_per_class)], check=True)
    pd.DataFrame(mappings).to_csv(out / "label_mapping.csv", index=False)
    pd.DataFrame(support).fillna(0).astype(int).to_csv(out / "family_support.csv", index_label="family")
    protocol = {"arguments": vars(args), "configuration_names": list(NAMES),
                "pooled_configuration": NAMES[-1], "task": "multiclass attack families",
                "label_taxonomy": manifest(), "m3_stack_variant": "trees", "flow_contract": CONTRACT,
                "protocol": "Declared sessions and time blocks, grouped OOF, identical held-out rows for all algorithms.",
                "session_support": {source: {part: frame.groupby("session_id").Label.value_counts().unstack(fill_value=0).to_dict(orient="index")
                                             for part, frame in parts.items()} for source, parts in splits.items()}}
    fit_model_runs(args, splits, protocol, inputs)


if __name__ == "__main__":
    main()
