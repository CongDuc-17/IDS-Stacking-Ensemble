"""Audit one capture against a labeled flow CSV and export high-confidence matches."""

import argparse
from bisect import bisect_left
from collections import Counter, defaultdict
import csv
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
import json
import math
from pathlib import Path

from dataset import column_name
from features import FEATURES
from taxonomy import LABELS, label_key


TIMESTAMP_FORMATS = (
    ("%d/%m/%Y %H:%M:%S", 1), ("%d/%m/%Y %H:%M", 60),
    ("%d/%m/%Y %I:%M:%S %p", 1), ("%d/%m/%Y %I:%M %p", 60),
)
MEASUREMENTS = FEATURES[1:6]


@dataclass(frozen=True)
class Reference:
    direction: tuple
    start: float
    precision: int
    label: str
    measurement: tuple
    timestamp: str


@lru_cache(maxsize=4096)
def reference_time(value, shift_minutes, afternoon):
    for fmt, precision in TIMESTAMP_FORMATS:
        try:
            parsed = datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if afternoon and "%p" not in fmt and parsed.hour < 12:
            parsed = parsed.replace(hour=parsed.hour + 12)
        return parsed.timestamp() + shift_minutes * 60, precision
    raise ValueError(f"Unsupported reference timestamp: {value!r}")


def endpoints(src, sport, dst, dport, protocol):
    direction = ((src, int(sport)), (dst, int(dport)))
    return direction, (*sorted(direction), protocol)


def reference_index(path, keys, shift_minutes, afternoon):
    index = defaultdict(list)
    aliases = {"Src IP": "Source IP", "Dst IP": "Destination IP", "Src Port": "Source Port"}
    with path.open(encoding="utf-8-sig", errors="replace", newline="") as stream:
        reader = csv.DictReader(stream)
        reader.fieldnames = [aliases.get(name, name) for name in map(column_name, reader.fieldnames)]
        for row in reader:
            protocol = {"6": "TCP", "17": "UDP"}.get(row["Protocol"].strip())
            if protocol is None:
                continue
            direction, key = endpoints(row["Source IP"], row["Source Port"], row["Destination IP"],
                                       row["Destination Port"], protocol)
            if key not in keys:
                continue
            stamp = row["Timestamp"].strip()
            start, precision = reference_time(stamp, shift_minutes, afternoon)
            index[key].append(Reference(direction, start, precision, row["Label"].strip(),
                                        tuple(float(row[name]) for name in MEASUREMENTS), stamp))
    return index


def match(row, direction, first, last, refs, starts, labels, allow_probe_count_shift=False):
    if row["flow_close_reason"] == "capacity":
        return "capacity", None
    candidates = [r for r in refs if r.start <= first < r.start + r.precision]
    if not candidates:
        return "unmatched", None
    if len(candidates) != 1:
        return "ambiguous_reference", None
    ref, = candidates
    if bisect_left(starts, ref.start + ref.precision) - bisect_left(starts, ref.start) != 1:
        return "ambiguous_capture", ref
    if ref.direction != direction:
        return "direction_mismatch", ref
    measured = tuple(float(row[name]) for name in MEASUREMENTS)
    if not all(math.isfinite(value) and value >= 0 for value in measured + ref.measurement):
        return "measurement_mismatch", ref
    duration, fwd, bwd, fwd_bytes, bwd_bytes = measured
    same_duration = abs(duration - ref.measurement[0]) <= 1
    status = "matched"
    if not same_duration or measured[1:] != ref.measurement[1:]:
        # In these InSDN Probe captures the reference assigns one forward packet to backward.
        if (allow_probe_count_shift and same_duration and row["protocol"] == "TCP" and
                label_key(ref.label) == "probe" and fwd >= 1 and bwd >= 1 and
                (fwd_bytes, bwd_bytes) == (0, 0) and ref.measurement[1:] == (fwd - 1, bwd + 1, 0, 0)):
            status = "matched_probe_count_shift"
        else:
            return "measurement_mismatch", ref
    if label_key(ref.label) not in labels:
        return "unknown_label", ref
    if any(label_key(other.label) != label_key(ref.label) and other.start <= last and
           other.start + other.precision + max(0, other.measurement[0]) / 1e6 > first for other in refs):
        return "conflicting_interval", ref
    return status, ref


def audit(args):
    labels = {label_key(raw): family for raw, family in LABELS[args.source].items()}
    starts = defaultdict(list)
    with args.flows.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        fields = reader.fieldnames
        if "Label" in fields:
            raise ValueError("Expected unlabeled flow input")
        rows = []  # shortcut: one pilot capture in memory, partition by capture for larger batches.
        for row in reader:
            direction, key = endpoints(row["src_ip"], row["src_port"], row["dst_ip"], row["dst_port"], row["protocol"])
            first, last = float(row["flow_first_epoch"]), float(row["flow_last_epoch"])
            if not (math.isfinite(first) and math.isfinite(last) and first <= last):
                raise ValueError(f"Invalid capture flow timestamps on line {reader.line_num}")
            starts[key].append(first)
            rows.append((row, direction, key, first, last))
    for times in starts.values():
        times.sort()
    refs = reference_index(args.reference, starts, args.shift_minutes, args.afternoon)
    args.out.mkdir(parents=True)
    counts, families, eligible = Counter(), Counter(), Counter()
    fields += ["source_dataset", "capture_id", "session_id", "Label", "family", "match_status",
               "reference_label", "reference_timestamp", "label_source"]
    with (args.out / "audit.csv").open("x", encoding="utf-8", newline="") as log, \
         (args.out / "matched.csv").open("x", encoding="utf-8", newline="") as accepted:
        writer, matched = [csv.DictWriter(stream, fieldnames=fields) for stream in (log, accepted)]
        writer.writeheader()
        matched.writeheader()
        for row, direction, key, first, last in rows:
            status, ref = match(row, direction, first, last, refs.get(key, ()), starts[key], labels,
                                args.allow_probe_count_shift)
            counts[status] += 1
            label = ref.label if status in {"matched", "matched_probe_count_shift"} else ""
            family = labels[label_key(label)] if label else ""
            record = dict(row, source_dataset=args.source, capture_id=args.flows.stem, session_id=args.session,
                          Label=label, family=family, match_status=status, reference_label=ref.label if ref else "",
                          reference_timestamp=ref.timestamp if ref else "", label_source=args.reference.name)
            writer.writerow(record)
            if label:
                matched.writerow(record)
                families[family] += 1
                eligible[label] += 1
    report = {"flows": len(rows), "status": counts, "matched_families": families, "matched_labels": eligible,
              "source": args.source, "capture": args.flows.stem, "session": args.session,
              "reference": args.reference.name, "shift_minutes": args.shift_minutes, "afternoon": args.afternoon,
              "allow_probe_count_shift": args.allow_probe_count_shift}
    result = json.dumps(report, indent=2)
    (args.out / "report.json").write_text(result + "\n", encoding="utf-8")
    print(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--flows", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--source", choices=LABELS, required=True)
    parser.add_argument("--session", required=True)
    parser.add_argument("--shift-minutes", type=int, required=True, help="Add this verified offset to reference timestamps")
    parser.add_argument("--afternoon", action="store_true", help="Legacy 12-hour afternoon CSV without an AM/PM marker")
    parser.add_argument("--allow-probe-count-shift", action="store_true",
                        help="Allow the verified one-packet direction discrepancy in InSDN TCP Probe captures")
    parser.add_argument("--out", type=Path, required=True, help="New audit directory")
    args = parser.parse_args()
    if args.allow_probe_count_shift and args.source != "insdn":
        parser.error("--allow-probe-count-shift requires --source insdn")
    audit(args)


if __name__ == "__main__":
    main()
