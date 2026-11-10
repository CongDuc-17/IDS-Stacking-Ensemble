"""Run M1 (CIC), M2 (InSDN), and optionally M3 (combined) on shared binary tests."""
import argparse
from pathlib import Path

from three_models import run_three_models


def main():
    project = Path(__file__).resolve().parents[1]
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cic-data", default=str(project / "data" / "MachineLearningCVE"))
    ap.add_argument("--insdn-data", default=str(project / "data" / "InSDN(2020)"))
    ap.add_argument("--out", required=True, help="New/empty experiment directory")
    ap.add_argument("--combined", action="store_true", help="Include M3 trained on both development sets")
    ap.add_argument("--max-per-class", type=int, default=5000, help="Rows per BINARY class per source, before deduplication")
    ap.add_argument("--trees", type=int, default=120)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--folds", type=int, default=3)
    ap.add_argument("--tune", action="store_true", help="Training-only CV to choose baseline parameters")
    ap.add_argument("--stack-search", action="store_true", help="Select meta learner C/weight using training OOF and validation")
    args = ap.parse_args()
    try:
        run_three_models(args)
    except (ValueError, FileNotFoundError, ModuleNotFoundError) as error:
        ap.exit(1, f"Error: {error}\n")


if __name__ == "__main__":
    main()
