"""Full raw counts plus plots and summaries of a bounded sample."""
import argparse
import json
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from dataset import read_sample
from features import FEATURES


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-per-class", type=int, default=5000)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    data, meta = read_sample(args.data, args.max_per_class, args.seed)
    meta["plots_note"] = "Distributions/correlation: capped sample. Raw counts: all input rows."
    (out / "eda.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    data[FEATURES].describe().to_csv(out / "feature_summary.csv")
    counts = meta["raw_class_counts"]
    fig, ax = plt.subplots(figsize=(11, 6), layout="constrained")
    labels = sorted(counts, key=counts.get)
    ax.barh([label.replace("\ufffd", "-") for label in labels], [counts[k] for k in labels])
    ax.set(xscale="log", xlabel="Raw rows (log scale)", title="Raw class counts before sampling")
    fig.savefig(out / "class_distribution.png", dpi=140)
    plt.close(fig)
    fig, axes = plt.subplots(2, 2, figsize=(11, 7), layout="constrained")
    for ax, feature in zip(axes.flat, ["Flow Duration", "Total Fwd Packets", "Total Length of Fwd Packets", "SYN Flag Count"]):
        for normal, name in [(True, "BENIGN"), (False, "ATTACK (all classes)")]:
            values = data.loc[(data.Label == "BENIGN") == normal, feature].dropna()
            ax.hist(np.log1p(values.clip(lower=0)), bins=40, alpha=0.5, density=True, label=name)
        ax.set(title=feature, xlabel="log(1 + value), negatives clipped for display", ylabel="Sample density")
        ax.legend(fontsize=7)
    fig.savefig(out / "feature_distributions.png", dpi=140)
    plt.close(fig)
    corr = data[FEATURES].corr().fillna(0)
    fig, ax = plt.subplots(figsize=(10, 9), layout="constrained")
    im = ax.imshow(corr, vmin=-1, vmax=1, cmap="coolwarm")
    ax.set_xticks(range(len(FEATURES)), FEATURES, rotation=90, fontsize=8)
    ax.set_yticks(range(len(FEATURES)), FEATURES, fontsize=8)
    ax.set_title("Sample Pearson correlation; undefined values displayed as zero")
    fig.colorbar(im, ax=ax, shrink=0.6)
    fig.savefig(out / "correlation.png", dpi=140)
    plt.close(fig)
    print(f"EDA written: {out.resolve()}")


if __name__ == "__main__":
    main()
