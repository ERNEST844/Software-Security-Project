"""Parse the pinned GitHub Advisory Database snapshot (OSV format) into analysis tables."""
import json, glob, os, re, gzip, subprocess, pandas as pd, numpy as np
from cvss import CVSS3, CVSS4
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GH = f"{ROOT}/data/raw/ghsa"
def norm(eco, name):
    return re.sub(r"[-_.]+", "-", name).lower() if eco == "PyPI" else name
def score(vec):
    try:
        if vec.startswith("CVSS:4"): return float(CVSS4(vec).base_score), "v4"
        if vec.startswith("CVSS:3"): return float(CVSS3(vec).scores()[0]), "v3"
    except Exception: pass
    return np.nan, None
rows, aff = [], []
for f in glob.glob(f"{GH}/advisories/github-reviewed/*/*/*/*.json"):
    d = json.load(open(f))
    if d.get("withdrawn"): continue
    cves = sorted(a for a in d.get("aliases", []) if a.startswith("CVE-"))
    v3 = next((s["score"] for s in d.get("severity", []) if s["type"] == "CVSS_V3"), None)
    v4 = next((s["score"] for s in d.get("severity", []) if s["type"] == "CVSS_V4"), None)
    s3, _ = score(v3) if v3 else (np.nan, None); s4, _ = score(v4) if v4 else (np.nan, None)
    base, src = (s3, "v3") if not np.isnan(s3) else ((s4, "v4") if not np.isnan(s4) else (np.nan, None))
    ds = d.get("database_specific", {}); refs = d.get("references", [])
    ecos = sorted({a["package"]["ecosystem"] for a in d.get("affected", [])})
    has_fix = any(e.get("fixed") for a in d.get("affected", []) for r in a.get("ranges", []) for e in r.get("events", []))
    rows.append(dict(ghsa_id=d["id"], cves=";".join(cves), published=d["published"][:10], modified=d.get("modified", "")[:10],
        severity_label=(ds.get("severity") or "").upper(), cvss_v3_vector=v3, cvss_v4_vector=v4, cvss_base=base, cvss_source=src,
        cwe_ids=";".join(ds.get("cwe_ids", [])), n_affected_packages=len({(a["package"]["ecosystem"], a["package"]["name"]) for a in d.get("affected", [])}),
        ecosystems=";".join(ecos), has_fix=has_fix, n_refs=len(refs),
        n_ref_fix=sum(r["type"] == "FIX" for r in refs), n_ref_report=sum(r["type"] == "REPORT" for r in refs),
        n_ref_evidence=sum(r["type"] == "EVIDENCE" for r in refs)))
    for a in d.get("affected", []):
        p = a["package"]
        aff.append(dict(ghsa_id=d["id"], ecosystem=p["ecosystem"], package=p["name"], package_norm=norm(p["ecosystem"], p["name"]),
                        ranges=json.dumps([{"type": r["type"], "events": r.get("events", [])} for r in a.get("ranges", [])]),
                        versions=json.dumps(a.get("versions", []))))
adv = pd.DataFrame(rows).sort_values("ghsa_id"); af = pd.DataFrame(aff)
os.makedirs(f"{ROOT}/data/processed", exist_ok=True)
adv.to_csv(f"{ROOT}/data/processed/advisories.csv", index=False)
af.to_csv(f"{ROOT}/data/processed/advisory_affected.csv.gz", index=False)
pin = subprocess.run(["git", "log", "-1", "--format=%H %cI"], cwd=GH, capture_output=True, text=True).stdout.strip()
print("advisories (non-withdrawn):", len(adv), "| affected rows:", len(af), "| pinned GHSA commit:", pin)
print("with CVE:", (adv.cves != "").sum(), "| with CVSS base:", adv.cvss_base.notna().sum(), "| source mix:", adv.cvss_source.value_counts(dropna=False).to_dict())
