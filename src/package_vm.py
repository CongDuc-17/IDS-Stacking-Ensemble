"""Package a completed pooled multiclass run and its matching runtime for Linux lab validation."""
import argparse
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import zipfile

import numpy as np
import pandas as pd

from check_model import check_model, load_model
from dataset import numeric_features
from flows import EXTRACTOR_VERSION
from taxonomy import manifest


RUNTIME = ("features", "dataset", "taxonomy", "flows", "detect", "check_model", "extract",
           "evaluate_lab", "evaluate_model", "feature_parity", "train")
DEFAULT_BUNDLE = "ids-vm-multiclass-combined-seed42-trees"


def package_vm(run, output):
    project = Path(__file__).resolve().parents[1]
    run, output = Path(run).resolve(), Path(output).resolve()
    if output.exists():
        raise ValueError("Choose a new ZIP path; existing bundles are preserved.")
    completed = json.loads((run / "completed.json").read_text(encoding="utf-8"))
    protocol = json.loads((run / "protocol.json").read_text(encoding="utf-8"))
    pooled = protocol.get("pooled_configuration", "M3")
    if pooled not in {"M3", "PCAP-Combined"} or pooled not in completed["configurations"] or protocol.get("label_taxonomy") != manifest():
        raise ValueError("Need a completed pooled family run matching this runtime taxonomy.")
    model_run = run / pooled
    model = model_run / "models/stacking_ids.joblib"
    artifact = load_model(model)
    if artifact.get("task") != "multiclass" or artifact.get("label_taxonomy") != manifest():
        raise ValueError("Require the pooled multiclass family model, not a binary or single-source model.")
    contract = artifact.get("flow_contract")
    if pooled == "PCAP-Combined" and (not contract or contract != protocol.get("flow_contract") or
                                      contract.get("version") != EXTRACTOR_VERSION):
        raise ValueError("PCAP run and runtime must agree on the extractor contract.")
    model_protocol = json.loads((model_run / "protocol.json").read_text(encoding="utf-8"))
    if set(model_protocol["data"]["training_sources"]) != {"cicids2017", "insdn"}:
        raise ValueError("Model must have both training sources.")
    for source in ("cicids2017", "insdn"):
        check_model(model, model_run / f"{source}/smoke_test.csv")
        truth = pd.read_csv(run / f"splits/{source}/test.csv")
        expected = pd.read_csv(model_run / f"{source}/predictions.csv")
        prediction = np.asarray(artifact["classes"])[artifact["model"].predict(numeric_features(truth))]
        if prediction.tolist() != expected.stacking.tolist() or truth.Label.tolist() != expected.GroundTruth.tolist():
            raise ValueError(f"Model/test/reference predictions disagree: {source}")
    files = {f"src/{name}.py": (project / f"src/{name}.py").read_bytes() for name in RUNTIME}
    files.update({
        "models/stacking_ids.joblib": model.read_bytes(),
        "models/requirements-deploy.txt": (model.parent / "requirements-deploy.txt").read_bytes(),
        "models/features.json": (model.parent / "features.json").read_bytes(),
        "models/protocol.json": (model_run / "protocol.json").read_bytes(),
        "models/selection.json": (model_run / "selection.json").read_bytes(),
        "protocol/pooled.json": (run / "protocol.json").read_bytes(),
        "protocol/taxonomy.json": json.dumps(manifest(), indent=2).encode("utf-8"),
        "protocol/label_mapping.csv": (run / "label_mapping.csv").read_bytes(),
        "protocol/family_support.csv": (run / "family_support.csv").read_bytes(),
        "README.md": (project / "docs/VM_DEPLOYMENT.md").read_text(encoding="utf-8").replace("](FEATURE_PARITY.md)", "](docs/FEATURE_PARITY.md)").encode("utf-8"),
        "docs/LABEL_TAXONOMY.md": (project / "docs/LABEL_TAXONOMY.md").read_bytes(),
        "docs/FEATURE_PARITY.md": (project / "docs/FEATURE_PARITY.md").read_bytes(),
        "requirements-vm.in": f"-r models/requirements-deploy.txt\nscapy=={version('scapy')}\n".encode("utf-8"),
    })
    seed = protocol["arguments"]["seed"]
    folder = f"ids-vm-multiclass-combined-seed{seed}"
    if protocol.get("m3_stack_variant") == "trees":
        folder += "-trees"
    if contract:
        folder = f"ids-vm-pcap-models-seed{seed}"
        files["README.md"] = (project / "docs/PCAP_DEPLOYMENT.md").read_text(encoding="utf-8").replace(
            "ids-vm-pcap-models-seed42.zip", output.name).replace("~/ids-vm-pcap-models-seed42", f"~/{folder}").encode("utf-8")
        for name, source in (("PCAP-CIC", "cicids2017"), ("PCAP-InSDN", "insdn")):
            alternative = run / name
            alternative_model = alternative / "models/stacking_ids.joblib"
            smoke = alternative / source / "smoke_test.csv"
            metadata = load_model(alternative_model)
            if metadata.get("model_id") != name or metadata.get("flow_contract") != contract:
                raise ValueError(f"{name} does not match the PCAP runtime contract.")
            check_model(alternative_model, smoke)
            files[f"models/{name}.joblib"] = alternative_model.read_bytes()
            files[f"smoke/{name}.csv"] = smoke.read_bytes()
    else:
        files["README.md"] = (files["README.md"].decode("utf-8").replace(DEFAULT_BUNDLE, folder)
                              .replace(f"{folder}.zip", output.name).encode("utf-8"))
    for source in ("cicids2017", "insdn"):
        files[f"smoke/{source}.csv"] = (model_run / f"{source}/smoke_test.csv").read_bytes()
        files[f"evaluation/{source}.csv"] = (run / f"splits/{source}/test.csv").read_bytes()
        files[f"evaluation/reference-{source}.json"] = (model_run / f"{source}/comparison.json").read_bytes()
    files["MODEL_CARD.json"] = json.dumps({
        "seed": seed, "task": artifact["task"], "classes": artifact["classes"],
        "base_learners": [name for name, _ in artifact["model"].estimators],
        "meta_learner": type(artifact["model"].final_estimator_).__name__,
        "python_version": artifact["python_version"], "taxonomy_sha256": manifest()["sha256"],
        "model_sha256": hashlib.sha256(files["models/stacking_ids.joblib"]).hexdigest(),
        "source_run": str(run), "linux_validation": "not performed by packaging",
        "flow_extractor_version": EXTRACTOR_VERSION,
        "feature_parity": "shared training and runtime extractor" if contract else "unvalidated; follow docs/FEATURE_PARITY.md",
        **({"model_id": pooled, "flow_contract": contract} if contract else {}),
        "runtime_origin": "current workspace; includes uncommitted changes if present",
    }, indent=2).encode("utf-8")
    files["SHA256SUMS"] = ("\n".join(f"{hashlib.sha256(data).hexdigest()}  {name}" for name, data in sorted(files.items())) + "\n").encode("utf-8")
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            archive.writestr(f"{folder}/{name}", data)
    with zipfile.ZipFile(output) as archive:
        if archive.testzip() is not None:
            raise ValueError("ZIP integrity verification failed.")
        for name, data in files.items():
            if archive.read(f"{folder}/{name}") != data:
                raise ValueError(f"ZIP content mismatch: {name}")
    print(f"Packaged {len(files)} files, {len(artifact['classes'])} classes: {output}")
    return output


def main():
    project = Path(__file__).resolve().parents[1]
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--run", default=str(project / "experiments/m3-trees/seed42"))
    ap.add_argument("--out", default=str(project / "deliverables" / f"{DEFAULT_BUNDLE}.zip"))
    args = ap.parse_args()
    try:
        package_vm(args.run, args.out)
    except (ValueError, FileNotFoundError) as error:
        ap.exit(1, f"Error: {error}\n")


if __name__ == "__main__":
    main()
