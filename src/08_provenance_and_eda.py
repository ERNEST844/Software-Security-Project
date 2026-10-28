import json, os, hashlib, subprocess, sys, platform, shutil, pandas as pd, numpy as np
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sha = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()
kev = json.load(open(f"{ROOT}/data/raw/kev.json"))
prior_prov = json.load(open(f"{ROOT}/data/processed/provenance_manifest.json"))
prior_sources = prior_prov.get("sources", {})


def git_revision(source, key):
    path = f"{ROOT}/data/raw/{source}"
    if os.path.isdir(path):
        result = subprocess.run(["git", "log", "-1", "--format=%H %cI"], cwd=path, capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    previous = prior_sources.get(key, {}).get("commit_and_date")
    if previous:
        print(f"{source} checkout unavailable; preserving its previously recorded pinned revision.")
        return previous + " (checkout unavailable in this run)"
    print(f"{source} checkout and previously recorded revision are unavailable.")
    return "unavailable"


epss_manifest_path = f"{ROOT}/data/raw/epss/epss_manifest.json"
epss_files = json.load(open(epss_manifest_path)) if os.path.exists(epss_manifest_path) else {}
epss = {"url": "https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz (daily files; see data_stats on first.org/epss)",
        "status": "RETRIEVED" if epss_files else "NOT RETRIEVED", "files": epss_files}
syft_bin = os.environ.get("SYFT") or shutil.which("syft")
if not syft_bin:
    syft_bin = next((p for p in (f"{ROOT}/tools/bin/syft", f"{ROOT}/tools/bin/syft.exe") if os.path.exists(p)), None)
if syft_bin:
    syft = subprocess.run([syft_bin, "version"], capture_output=True, text=True, check=True).stdout.strip()
else:
    previous = prior_prov.get("environment", {}).get("syft", "unknown")
    syft = f"unavailable in this run; previously recorded: {previous}"
    print(f"Syft unavailable in this run; preserving its previously recorded version: {previous}")
import pandas, sklearn, networkx, cvss, semantic_version
prov = {"retrieved_utc": pd.Timestamp.now(tz="UTC").isoformat(),
 "sources": {
  "CISA_KEV": {"url": "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json (GitHub mirror of the CISA catalogue)", "catalogVersion": kev["catalogVersion"], "dateReleased": kev["dateReleased"], "count": kev["count"], "sha256": sha(f"{ROOT}/data/raw/kev.json")},
  "GitHub_Advisory_Database": {"url": "https://github.com/github/advisory-database (advisories/github-reviewed)", "commit_and_date": git_revision("ghsa", "GitHub_Advisory_Database"), "note": "OSV-format; pinned by commit hash"},
  "PoC_in_GitHub": {"url": "https://github.com/nomi-sec/PoC-in-GitHub", "commit_and_date": git_revision("poc", "PoC_in_GitHub"), "note": "CVE -> GitHub PoC repositories with creation dates; noisy proxy"},
  "npm_registry": {"url": "https://registry.npmjs.org/<pkg>", "use": "release dates (immutable) for package-health features; fetched 2026-10-13"},
  "PyPI": {"url": "https://pypi.org/pypi/<pkg>/json", "use": "release dates (immutable) for package-health features; fetched 2026-10-13"},
  "EPSS": epss,
  "NVD": {"status": "not used; CVSS taken from GitHub advisory vectors and recomputed with the 'cvss' library"}},
 "repositories": json.load(open(f"{ROOT}/data/processed/snapshot_file_manifest.json")),
 "environment": {"python": sys.version.split()[0], "platform": platform.platform(), "syft": syft, "pandas": pandas.__version__, "scikit-learn": sklearn.__version__, "networkx": networkx.__version__, "cvss": cvss.__version__ if hasattr(cvss, "__version__") else "n/a", "semantic_version": semantic_version.__version__}}
json.dump(prov, open(f"{ROOT}/data/processed/provenance_manifest.json", "w"), indent=1)
comp = pd.read_csv(f"{ROOT}/data/processed/project_components_t0.csv"); f = pd.read_csv(f"{ROOT}/data/processed/project_findings_t0.csv")
sel = {r["repo"].replace("/", "__"): r for r in json.load(open(f"{ROOT}/data/processed/repo_selection_report.json")) if r["decision"] == "SELECTED"}
rows = []
for p, c in comp.groupby("project"):
    ff = f[f.project == p]
    rows.append(dict(project=p, ecosystems="+".join(sorted(c.ecosystem.unique())), commit=sel[p]["commit"][:10], commit_date=sel[p]["commit_date"][:10], components=len(c), direct_components=int(c.is_direct.sum()),
        max_depth=int(c.depth.max()), vulnerable_components=int(c.is_vulnerable.sum()), findings=len(ff), critical=int((ff.severity_label == "CRITICAL").sum()), high=int((ff.severity_label == "HIGH").sum()),
        poc_12m_positives=int(ff.poc_12m.sum()), kev_12m_positives=int(ff.kev_12m.sum())))
tab = pd.DataFrame(rows).sort_values("components", ascending=False); tab.to_csv(f"{ROOT}/results/project_summary_t0.csv", index=False); print(tab.to_string(index=False))
pop = pd.read_csv(f"{ROOT}/data/processed/population_cohorts.csv")
q = {"population_rows": len(pop), "cvss_missing_pct": round(100 * pop.cvss_base.isna().mean(), 2), "cvss_v4_only_pct": round(100 * (pop.cvss_source == "v4").mean(), 2),
     "components_total": len(comp), "components_vulnerable": int(comp.is_vulnerable.sum()), "findings": len(f), "findings_without_cve": int((f.has_cve == 0).sum()),
     "findings_depth_gt1_pct": round(100 * (f.depth > 1).mean(), 1), "findings_transitive_pct": round(100 * (f.is_direct == 0).mean(), 1),
     "health_missing_pct": round(100 * f.days_since_last_release.isna().mean(), 1), "median_installed_version_age_days": float(f.installed_version_age_days.median()), "median_version_lag_days": float(f.version_lag_days.median()),
     "median_advisory_age_days_at_T0": float(f.advisory_age_days.median()), "findings_by_ecosystem": f.ecosystem.value_counts().to_dict()}
json.dump(q, open(f"{ROOT}/results/eda_summary.json", "w"), indent=1); print(json.dumps(q, indent=1))
