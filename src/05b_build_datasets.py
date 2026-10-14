"""Build (A) the population cohort dataset and (B) the project-findings dataset. All features are AS-OF the snapshot date T."""
import pandas as pd, numpy as np, json, glob, os, re, gzip, yaml, urllib.parse
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
cfg = yaml.safe_load(open(f"{ROOT}/config/study.yaml")); S = cfg["snapshots"]
COHORTS = [pd.Timestamp(d) for d in S["cohort_dates"]]; CUTOFF = pd.Timestamp(S["data_cutoff"]); H = S["horizon_months"]
POP_ECO = set(cfg["ecosystems_population"])

# ---------- external signals ----------
kev = {v["cveID"]: pd.Timestamp(v["dateAdded"]) for v in json.load(open(f"{ROOT}/data/raw/kev.json"))["vulnerabilities"]}
poc = {}
for f in glob.glob(f"{ROOT}/data/raw/poc/20*/CVE-*.json"):
    try: L = json.load(open(f))
    except Exception: continue
    ds = sorted(pd.Timestamp(x["created_at"][:10]) for x in L if x.get("created_at"))
    if ds: poc[os.path.basename(f)[:-5]] = ds
def load_epss(T):
    p = f"{ROOT}/data/raw/epss/epss_scores-{T.date()}.csv.gz"
    if not os.path.exists(p): return None
    return pd.read_csv(p, comment="#").set_index("cve")
# ---------- advisories -> CVE table ----------
adv = pd.read_csv(f"{ROOT}/data/processed/advisories.csv", dtype={"cves": str, "cwe_ids": str}, keep_default_na=False, na_values=[""])
adv["published"] = pd.to_datetime(adv.published)
adv = adv[adv.ecosystems.fillna("").apply(lambda s: bool(set(s.split(";")) & POP_ECO))]
adv = adv[adv.cves.notna()].assign(cve=lambda d: d.cves.str.split(";")).explode("cve")
SEV = {"": 0, "LOW": 1, "MODERATE": 2, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
def vec_parts(v):
    d = dict(x.split(":", 1) for x in str(v).split("/")[1:] if ":" in x) if isinstance(v, str) else {}
    return dict(AV=d.get("AV"), AC=d.get("AC"), PR=d.get("PR"), UI=d.get("UI"), SC=d.get("S"), C=d.get("C", d.get("VC")), I=d.get("I", d.get("VI")), A=d.get("A", d.get("VA")))
adv["sev_rank"] = adv.severity_label.fillna("").map(SEV)
best = adv.sort_values(["cvss_base", "published"], ascending=[False, True], na_position="last")
cvev = best.drop_duplicates("cve").set_index("cve")
agg = adv.groupby("cve").agg(published=("published", "min"), n_advisories=("ghsa_id", "nunique"), n_affected_packages=("n_affected_packages", "sum"),
                             has_fix=("has_fix", "max"), sev_rank=("sev_rank", "max"), ecosystems=("ecosystems", lambda s: ";".join(sorted(set(";".join(s).split(";"))))))
cve = agg.join(cvev[["cvss_base", "cvss_source", "cvss_v3_vector", "cvss_v4_vector", "cwe_ids"]])
vp = cve.apply(lambda r: vec_parts(r.cvss_v3_vector if isinstance(r.cvss_v3_vector, str) else r.cvss_v4_vector), axis=1, result_type="expand")
cve = pd.concat([cve, vp], axis=1)
cve["cwe_primary"] = cve.cwe_ids.fillna("").str.split(";").str[0].replace("", np.nan)
cve["n_ecosystems"] = cve.ecosystems.str.count(";") + 1
for e in ["npm", "PyPI", "Maven", "Packagist", "Go", "NuGet", "RubyGems", "crates.io"]: cve[f"eco_{e}"] = cve.ecosystems.str.contains(re.escape(e)).astype(int)

def label_block(T, ids):
    end = min(T + pd.DateOffset(months=H), CUTOFF); out = pd.DataFrame(index=ids)
    k = pd.Series({c: kev.get(c, pd.NaT) for c in ids}); p0 = pd.Series({c: poc[c][0] if c in poc else pd.NaT for c in ids})
    out["kev_date"], out["poc_first_date"] = k, p0
    out["cand_kev"] = (~(k <= T)).astype(int); out["kev_12m"] = ((k > T) & (k <= end)).astype(int)
    out["cand_poc"] = (~(p0 <= T)).astype(int); out["poc_12m"] = ((p0 > T) & (p0 <= end)).astype(int)
    out["poc_count_at_T"] = [sum(d <= T for d in poc.get(c, [])) for c in ids]
    return out, end

# ---------- (A) population cohorts ----------
blocks = []
for T in COHORTS:
    sub = cve[cve.published <= T].copy(); lab, end = label_block(T, sub.index)
    sub = sub.join(lab); sub["snapshot"] = T.date(); sub["window_end"] = end.date()
    sub["advisory_age_days"] = (T - sub.published).dt.days
    ep = load_epss(T)
    sub["epss_at_T"] = sub.index.map(ep["epss"]) if ep is not None else np.nan
    sub["epss_pct_at_T"] = sub.index.map(ep["percentile"]) if ep is not None else np.nan
    blocks.append(sub.reset_index().rename(columns={"index": "cve"}))
pop = pd.concat(blocks, ignore_index=True)
keep = ["snapshot", "window_end", "cve", "published", "advisory_age_days", "cvss_base", "cvss_source", "sev_rank", "AV", "AC", "PR", "UI", "SC", "C", "I", "A", "cwe_primary",
        "n_advisories", "n_affected_packages", "n_ecosystems", "has_fix", "ecosystems"] + [c for c in pop.columns if c.startswith("eco_")] + \
       ["poc_count_at_T", "epss_at_T", "epss_pct_at_T", "cand_kev", "kev_12m", "kev_date", "cand_poc", "poc_12m", "poc_first_date"]
pop[keep].to_csv(f"{ROOT}/data/processed/population_cohorts.csv", index=False)

# ---------- (B) project findings at snapshot T0 ----------
T0 = pd.Timestamp(S["project_snapshot_date"]); TAG = "t0"
raw = pd.read_csv(f"{ROOT}/data/processed/project_findings_raw_{TAG}.csv"); comp = pd.read_csv(f"{ROOT}/data/processed/project_components_{TAG}.csv")
advall = pd.read_csv(f"{ROOT}/data/processed/advisories.csv", dtype={"cves": str}, keep_default_na=False, na_values=[""]).set_index("ghsa_id")
raw["cve"] = raw.ghsa_id.map(advall.cves).fillna("").str.split(";").str[0].replace("", np.nan)
raw["finding_key"] = raw.cve.fillna(raw.ghsa_id)
f = raw.merge(comp.drop(columns=["name", "version", "ecosystem"]), on=["project", "component"], how="left").drop_duplicates(["project", "component", "finding_key"])
ghcols = ["severity_label", "cvss_base", "cvss_source", "cvss_v3_vector", "cwe_ids", "published", "has_fix"]
f = f.join(advall[ghcols], on="ghsa_id"); f["published"] = pd.to_datetime(f.published); f["advisory_age_days"] = (T0 - f.published).dt.days
def health(eco, name, ver):
    nm = re.sub(r"[-_.]+", "-", name).lower() if eco == "PyPI" else name
    p = f"{ROOT}/data/raw/registry/{eco}/{urllib.parse.quote(nm, safe='')}.json"
    if not os.path.exists(p): return {}
    j = json.load(open(p)); 
    if j.get("missing") or not j.get("versions"): return {}
    d = {v: pd.Timestamp(t).tz_localize(None) for v, t in j["versions"].items()}
    asof = {v: t for v, t in d.items() if t <= T0}
    if not asof: return {}
    latest = max(asof.values()); first = min(asof.values()); vd = d.get(ver)
    return dict(pkg_age_days=(T0 - first).days, days_since_last_release=(T0 - latest).days, releases_prior_12m=sum(t > T0 - pd.Timedelta(days=365) for t in asof.values()),
                n_releases_at_T=len(asof), installed_version_age_days=(T0 - vd).days if vd is not None and vd <= T0 else np.nan,
                version_lag_days=(latest - vd).days if vd is not None and vd <= T0 else np.nan)
H_ = f.apply(lambda r: health(r.ecosystem, r["name"], r.version), axis=1, result_type="expand"); f = pd.concat([f, H_], axis=1)
lab, _ = label_block(T0, f.cve.fillna("NA").unique()); lab = lab.drop(index="NA", errors="ignore")
f = f.join(lab, on="cve")
for c in ["cand_kev", "kev_12m", "cand_poc", "poc_12m"]: f[c] = f[c].fillna(0).astype(int)
ep = load_epss(T0); f["epss_at_T"] = f.cve.map(ep["epss"]) if ep is not None else np.nan
f["kev_at_T"] = f.cve.map(lambda c: int(c in kev and kev[c] <= T0)); f["has_cve"] = f.cve.notna().astype(int)
f.to_csv(f"{ROOT}/data/processed/project_findings_{TAG}.csv", index=False)
print("population rows:", len(pop), "| cohorts:", pop.groupby("snapshot").size().to_dict())
print("project findings (deduplicated):", len(f), "| with CVE:", int(f.has_cve.sum()), "| EPSS available:", bool(ep is not None))
print("project label counts: kev_12m=%d (cand %d) | poc_12m=%d (cand %d) | already KEV at T0=%d" % (f.kev_12m.sum(), f.cand_kev.sum(), f.poc_12m.sum(), f.cand_poc.sum(), f.kev_at_T.sum()))
