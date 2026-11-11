"""Project-defined attack families; source evidence and decisions: docs/LABEL_TAXONOMY.md."""
import hashlib
import json


VERSION = "cic-insdn-families-v1"
LABELS = {
    "cicids2017": {
        "BENIGN": "BENIGN", "DDoS": "DDOS", "PortScan": "RECON",
        "DoS slowloris": "DOS", "DoS Slowhttptest": "DOS",
        "DoS Hulk": "DOS", "DoS GoldenEye": "DOS",
        "FTP-Patator": "BRUTE_FORCE", "SSH-Patator": "BRUTE_FORCE",
        "Web Attack - Brute Force": "BRUTE_FORCE",
        "Web Attack - XSS": "WEB_ATTACK", "Web Attack - Sql Injection": "WEB_ATTACK",
        "Bot": "BOT", "Infiltration": "INFILTRATION", "Heartbleed": "HEARTBLEED",
    },
    "insdn": {
        "Normal": "BENIGN", "DoS": "DOS", "DDoS": "DDOS", "Probe": "RECON",
        "BFA": "BRUTE_FORCE", "Web-Attack": "WEB_ATTACK", "BOTNET": "BOT", "U2R": "U2R",
    },
}


def label_key(label):
    # Known CIC exports use U+FFFD in place of the web-label dash.
    return " ".join(str(label).replace("\ufffd", "-").replace("–", "-").replace("—", "-").split()).casefold()


def map_labels(labels, source):
    if source not in LABELS:
        raise ValueError(f"Unknown taxonomy source: {source}")
    mapping = {label_key(raw): family for raw, family in LABELS[source].items()}
    result = labels.map(lambda label: mapping.get(label_key(label)))
    if result.isna().any():
        unknown = sorted(set(labels.loc[result.isna()].astype(str)))
        raise ValueError(f"{source}: unmapped labels {unknown}; review taxonomy before training.")
    return result


def manifest():
    payload = {"version": VERSION, "labels": LABELS,
               "normalization": "trim/collapse whitespace, casefold, en/em/replacement dash -> ASCII dash",
               "policy": "Union of families; retain source-specific classes; never infer unknown labels."}
    payload["sha256"] = hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
    return payload
