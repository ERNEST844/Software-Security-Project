"""Match SBOM components to advisories (as-of snapshot date) and compute dependency-graph features."""
import json, glob, os, re, sys, collections, urllib.parse, yaml, pandas as pd, numpy as np, networkx as nx
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from versions import in_range
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
cfg = yaml.safe_load(open(f"{ROOT}/config/study.yaml")); T = cfg["snapshots"]["project_snapshot_date"]
ASOF = os.environ.get("ASOF", T)                      # allow "current" scans via ASOF=2026-10-13
TAG = os.environ.get("TAG", "t0")
SBOM_GLOB = os.environ.get("SBOM_GLOB", f"{ROOT}/data/sbom/*.cdx.json")
ECO = {"npm": "npm", "pypi": "PyPI"}
norm = lambda eco, n: re.sub(r"[-_.]+", "-", n).lower() if eco == "PyPI" else n

adv = pd.read_csv(f"{ROOT}/data/processed/advisories.csv", dtype=str).set_index("ghsa_id")
aff = pd.read_csv(f"{ROOT}/data/processed/advisory_affected.csv.gz", dtype=str)
aff = aff[aff.ecosystem.isin(["npm", "PyPI"])]
aff = aff[aff.ghsa_id.map(adv.published) <= ASOF]       # only advisories public as-of the snapshot date
index = collections.defaultdict(list)
for r in aff.itertuples():
    index[(r.ecosystem, r.package_norm)].append((r.ghsa_id, json.loads(r.ranges), json.loads(r.versions)))

comp_rows, find_rows, unparsed = [], [], collections.Counter()
for f in sorted(glob.glob(SBOM_GLOB)):
    project = os.path.basename(f).replace(".cdx.json", "")
    j = json.load(open(f)); comps = {}
    for c in j.get("components", []):
        p = c.get("purl", "")
        m = re.match(r"pkg:(npm|pypi)/", p)
        if not m: continue
        eco = ECO[m.group(1)]; name = urllib.parse.unquote(p.split("/", 1)[1].rsplit("@", 1)[0]) if eco == "PyPI" else c["name"]
        comps[c["bom-ref"]] = dict(key=p.split("?")[0], name=c["name"], version=c["version"], eco=eco)
    G = nx.DiGraph(); G.add_nodes_from({v["key"] for v in comps.values()})
    for d in j.get("dependencies", []):
        a = comps.get(d["ref"])
        for t in d.get("dependsOn", []):
            b = comps.get(t)
            if a and b and a["key"] != b["key"]: G.add_edge(a["key"], b["key"])
    roots = [n for n in G if G.in_degree(n) == 0]
    depth = {}
    frontier, d = list(roots), 1
    for r in roots: depth[r] = 1
    while frontier:
        nxt = []
        for u in frontier:
            for v in G.successors(u):
                if v not in depth: depth[v] = depth[u] + 1; nxt.append(v)
        frontier = nxt
    pr = nx.pagerank(G, alpha=0.85) if len(G) else {}
    meta = {v["key"]: v for v in comps.values()}
    vuln_nodes = set()
    for key, v in meta.items():
        hits = []
        for ghsa, ranges, versions in index.get((v["eco"], norm(v["eco"], v["name"])), []):
            res = in_range(v["eco"], v["version"], ranges, versions)
            if res is None: unparsed[v["eco"]] += 1
            elif res: hits.append(ghsa)
        if hits:
            vuln_nodes.add(key)
            for g in sorted(set(hits)):
                find_rows.append(dict(project=project, component=key, name=v["name"], version=v["version"], ecosystem=v["eco"], ghsa_id=g))
    for key, v in meta.items():
        comp_rows.append(dict(project=project, component=key, name=v["name"], version=v["version"], ecosystem=v["eco"],
            is_direct=int(G.in_degree(key) == 0), depth=depth.get(key, np.nan), fan_in=G.in_degree(key), fan_out=G.out_degree(key),
            pagerank=pr.get(key, 0.0),
            ancestors=len(nx.ancestors(G, key)) if key in vuln_nodes else np.nan,
            descendants=len(nx.descendants(G, key)) if key in vuln_nodes else np.nan, is_vulnerable=int(key in vuln_nodes)))
    print(f"{project:34} comps={len(meta):5} roots={len(roots):4} max_depth={max(depth.values()) if depth else 0:2} vulnerable_components={len(vuln_nodes):4}")
comp = pd.DataFrame(comp_rows, columns=[
    "project", "component", "name", "version", "ecosystem", "is_direct", "depth",
    "fan_in", "fan_out", "pagerank", "ancestors", "descendants", "is_vulnerable",
])
fnd = pd.DataFrame(find_rows, columns=[
    "project", "component", "name", "version", "ecosystem", "ghsa_id",
])
comp.to_csv(f"{ROOT}/data/processed/project_components_{TAG}.csv", index=False)
fnd.to_csv(f"{ROOT}/data/processed/project_findings_raw_{TAG}.csv", index=False)
print("as-of:", ASOF, "| components:", len(comp), "| raw findings (component x advisory):", len(fnd), "| unparsable-version comparisons:", dict(unparsed))
