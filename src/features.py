"""CIC-IDS2017 CSV features; validate definition parity before reusing an extractor."""
FEATURES = [
    "Destination Port",
    "Flow Duration",                   # microseconds
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",     # bytes per CICFlowMeter definition
    "Total Length of Bwd Packets",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
]
