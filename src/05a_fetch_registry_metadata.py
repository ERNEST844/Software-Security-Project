"""Fetch release histories (version -> first-publication date) from npm and PyPI for packages that have findings.
Release dates are immutable, so package-health features can be computed AS-OF any snapshot date without leakage."""
import pandas as pd, requests, json, os, urllib.parse, time, concurrent.futures as cf, re, glob
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
frames = [pd.read_csv(f) for f in glob.glob(f"{ROOT}/data/processed/project_findings_raw_*.csv")]
pk = pd.concat(frames)[["ecosystem", "name"]].drop_duplicates()
pk["name"] = pk.apply(lambda r: re.sub(r"[-_.]+", "-", r["name"]).lower() if r["ecosystem"] == "PyPI" else r["name"], axis=1)
pk = pk.drop_duplicates(); print("packages to fetch:", len(pk))
def path(eco, name): return f"{ROOT}/data/raw/registry/{eco}/{urllib.parse.quote(name, safe='')}.json"
def fetch(row):
    eco, name = row; p = path(eco, name)
    if os.path.exists(p): return "cached"
    url = f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}" if eco == "npm" else f"https://pypi.org/pypi/{name}/json"
    for a in range(4):
        try:
            r = requests.get(url, timeout=40)
            if r.status_code == 404: out = {"missing": True}
            elif r.status_code == 200:
                j = r.json()
                if eco == "npm":
                    t = j.get("time", {}); out = {"versions": {v: d for v, d in t.items() if v not in ("created", "modified")}, "created": t.get("created")}
                else:
                    out = {"versions": {v: min(f["upload_time_iso_8601"] for f in fs) for v, fs in j.get("releases", {}).items() if fs}}
            else: time.sleep(2 * (a + 1)); continue
            os.makedirs(os.path.dirname(p), exist_ok=True); json.dump(out, open(p, "w")); return "ok"
        except Exception: time.sleep(2 * (a + 1))
    return "failed"
with cf.ThreadPoolExecutor(10) as ex: res = list(ex.map(fetch, [(r.ecosystem, r.name) for r in pk.itertuples()]))
print(pd.Series(res).value_counts().to_dict())
