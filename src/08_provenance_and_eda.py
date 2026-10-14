import json, os, hashlib, subprocess, sys, platform, pandas as pd, numpy as np
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sha = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()
kev = json.load(open(f"{ROOT}/data/raw/kev.json")); g = lambda d: subprocess.run(["git", "log", "-1", "--format=%H %cI"], cwd=f"{ROOT}/data/raw/{d}", capture_output=True, text=True).stdout.strip()
syft = subprocess.run([os.environ.get("SYFT", f"{ROOT}/tools/bin/syft"), "version"], capture_output=True, text=True).stdout.split("\n")[1]
import pandas, sklearn, networkx, cvss, semantic_version
prov = {"retrieved_utc": pd.Timestamp.utcnow().isoformat(),
 "sources": {
  "CISA_KEV": {"url": "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json (GitHub mirror of the CISA catalogue)", "catalogVersion": kev["catalogVersion"], "dateReleased": kev["dateReleased"], "count": kev["count"], "sha256": sha(f"{ROOT}/data/raw/kev.json")},
  "GitHub_Advisory_Database": {"url": "https://github.com/github/advisory-database (advisories/github-reviewed)", "commit_and_date": g("ghsa"), "note": "OSV-format; pinned by commit hash"},
  "PoC_in_GitHub": {"url": "https://github.com/nomi-sec/PoC-in-GitHub", "commit_and_date": g("poc"), "note": "CVE -> GitHub PoC repositories with creation dates; noisy proxy"},
  "npm_registry": {"url": "https://registry.npmjs.org/<pkg>", "use": "release dates (immutable) for package-health features; fetched 2026-10-13"},
  "PyPI": {"url": "https://pypi.org/pypi/<pkg>/json", "use": "release dates (immutable) for package-health features; fetched 2026-10-13"},
  "EPSS": {"status": "NOT RETRIEVED in the build environment (host unreachable). Run src/fetch_epss.py locally, then re-run 05b/06/07."},
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
