"""Column normalization and feature identity for labeled and extracted flows."""
import numpy as np
import pandas as pd
from features import FEATURES


SOURCES = ("cicids2017", "insdn")


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


def feature_hashes(frame):
    return pd.util.hash_pandas_object(numeric_features(frame), index=False)
