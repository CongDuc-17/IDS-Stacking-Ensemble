"""Windowed communication graph and fan-in/fan-out candidates; not a validated botnet classifier."""
import argparse
import json
import math
from pathlib import Path
import xml.etree.ElementTree as ET

import numpy as np
import pandas as pd


def analyze_edges(edges, min_peers=5):
    required = {"window_epoch", "src_ip", "dst_ip", "flows", "packets", "bytes"}
    if edges.empty or required - set(edges) or min_peers < 2:
        raise ValueError("Need nonempty windowed edges and min-peers >= 2.")
    edges = edges.copy()
    numeric = ["window_epoch", "flows", "packets", "bytes"]
    edges[numeric] = edges[numeric].apply(pd.to_numeric, errors="raise")
    if (not np.isfinite(edges[numeric].to_numpy(dtype=float)).all()
            or (edges[numeric] < 0).any().any() or (edges.flows < 1).any()
            or edges[["src_ip", "dst_ip"]].isna().any().any()):
        raise ValueError("Invalid edge endpoints or nonnegative counters.")
    endpoints = pd.concat([edges[["window_epoch", c]].rename(columns={c: "host_ip"})
                           for c in ("src_ip", "dst_ip")]).drop_duplicates()
    pairs = edges.loc[edges.src_ip.ne(edges.dst_ip), ["window_epoch", "src_ip", "dst_ip"]].drop_duplicates()
    stats = endpoints.set_index(["window_epoch", "host_ip"])
    for endpoint, name in (("src_ip", "out_peers"), ("dst_ip", "in_peers")):
        counts = pairs.groupby(["window_epoch", endpoint]).size()
        counts.index.names = ["window_epoch", "host_ip"]
        stats[name] = counts
    reversed_pairs = pairs.rename(columns={"src_ip": "dst_ip", "dst_ip": "src_ip"})
    mutual = pairs.merge(reversed_pairs, on=["window_epoch", "src_ip", "dst_ip"])
    reciprocal = mutual.groupby(["window_epoch", "src_ip"]).size()
    reciprocal.index.names = ["window_epoch", "host_ip"]
    stats["reciprocal_peers"] = reciprocal
    stats = stats.fillna(0).astype(int).sort_index().reset_index()
    stats["candidate_fan_out"] = stats.out_peers >= min_peers
    stats["candidate_fan_in"] = stats.in_peers >= min_peers
    candidates = stats.loc[stats.candidate_fan_in | stats.candidate_fan_out].copy()
    return stats, candidates


def export_graph(edges, target, max_nodes=40):
    """Export complete GraphML plus a bounded SVG overview; never discard full graph data."""
    if max_nodes < 2:
        raise ValueError("max-nodes must be at least two.")
    totals = edges.groupby(["src_ip", "dst_ip"], sort=True)[["flows", "packets", "bytes"]].sum().reset_index()
    hosts = sorted(set(totals.src_ip) | set(totals.dst_ip))
    ids = {host: f"n{i}" for i, host in enumerate(hosts)}
    namespace = "http://graphml.graphdrawing.org/xmlns"
    ET.register_namespace("", namespace)
    graphml = ET.Element(f"{{{namespace}}}graphml")
    for name, domain, kind in [("ip", "node", "string"), ("flows", "edge", "double"),
                               ("packets", "edge", "double"), ("bytes", "edge", "double")]:
        ET.SubElement(graphml, f"{{{namespace}}}key", {"id": name, "for": domain, "attr.name": name, "attr.type": kind})
    graph = ET.SubElement(graphml, f"{{{namespace}}}graph", edgedefault="directed")
    for host in hosts:
        node = ET.SubElement(graph, f"{{{namespace}}}node", id=ids[host])
        ET.SubElement(node, f"{{{namespace}}}data", key="ip").text = host
    for i, row in enumerate(totals.to_dict("records")):
        edge = ET.SubElement(graph, f"{{{namespace}}}edge", id=f"e{i}", source=ids[row["src_ip"]], target=ids[row["dst_ip"]])
        for name in ("flows", "packets", "bytes"):
            ET.SubElement(edge, f"{{{namespace}}}data", key=name).text = str(row[name])
    ET.ElementTree(graphml).write(target / "communication.graphml", encoding="utf-8", xml_declaration=True)
    weights = pd.concat([totals[["src_ip", "flows"]].rename(columns={"src_ip": "host"}),
                         totals[["dst_ip", "flows"]].rename(columns={"dst_ip": "host"})]).groupby("host").flows.sum()
    shown = weights.sort_values(ascending=False, kind="stable").head(max_nodes).index.tolist()
    positions = {host: (500 + 370 * math.cos(i * 2 * math.pi / len(shown)),
                        450 + 330 * math.sin(i * 2 * math.pi / len(shown))) for i, host in enumerate(shown)}
    svg = ET.Element("svg", xmlns="http://www.w3.org/2000/svg", width="1000", height="900", viewBox="0 0 1000 900")
    ET.SubElement(svg, "rect", width="1000", height="900", fill="white")
    ET.SubElement(svg, "text", x="20", y="30", **{"font-size": "18"}).text = f"Communication overview: {len(shown)}/{len(hosts)} hosts; full graph in GraphML"
    for row in totals.to_dict("records"):
        if row["src_ip"] in positions and row["dst_ip"] in positions:
            a, b = positions[row["src_ip"]], positions[row["dst_ip"]]
            ET.SubElement(svg, "line", x1=str(a[0]), y1=str(a[1]), x2=str(b[0]), y2=str(b[1]), stroke="#a8b9cb", **{"stroke-width": "1"})
    for host, (x, y) in positions.items():
        ET.SubElement(svg, "circle", cx=str(x), cy=str(y), r="7", fill="#187c91")
        ET.SubElement(svg, "text", x=str(x + 9), y=str(y), **{"font-size": "10"}).text = host
    ET.ElementTree(svg).write(target / "overview.svg", encoding="utf-8", xml_declaration=True)
    return len(hosts), len(totals), len(shown)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--edges", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--min-peers", type=int, default=5)
    ap.add_argument("--max-nodes", type=int, default=40, help="SVG only; GraphML/CSV retain every host")
    args = ap.parse_args()
    try:
        target = Path(args.out)
        if target.exists():
            raise ValueError("Choose a new --out.")
        edges = pd.read_csv(args.edges)
        stats, candidates = analyze_edges(edges, args.min_peers)
        if args.max_nodes < 2:
            raise ValueError("max-nodes must be at least two.")
        target.mkdir(parents=True)
        stats.to_csv(target / "host_roles.csv", index=False)
        candidates.to_csv(target / "candidates.csv", index=False)
        nodes, links, shown = export_graph(edges, target, args.max_nodes)
        (target / "summary.json").write_text(json.dumps({
            "source": str(Path(args.edges).resolve()), "nodes": nodes, "directed_edges": links,
            "svg_nodes_shown": shown, "candidate_host_windows": len(candidates), "min_peers": args.min_peers,
            "interpretation": "Structural fan-in/fan-out candidates only, not proof of botnet, C2, infection or maliciousness.",
            "limitations": ["Legitimate DNS/web servers and scans can have the same topology.",
                            "Graph direction follows the first observed sender of a bidirectional flow.",
                            "SVG collapses direction and time; GraphML is directed and host_roles.csv preserves windows.",
                            "No botnet ground truth supplied; no botnet Accuracy/Recall is reported."]
        }, indent=2), encoding="utf-8")
        print(f"nodes={nodes}; edges={links}; candidate_host_windows={len(candidates)}")
    except (ValueError, KeyError) as error:
        ap.exit(1, f"Error: {error}\n")


if __name__ == "__main__":
    main()
