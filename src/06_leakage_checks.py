"""Automated leakage / integrity checks. Every check must pass before any model is trained."""
import pandas as pd, numpy as np, json, os, yaml
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
cfg = yaml.safe_load(open(f"{ROOT}/config/study.yaml")); S = cfg["snapshots"]
pop = pd.read_csv(f"{ROOT}/data/processed/population_cohorts.csv", parse_dates=["snapshot", "window_end", "published", "kev_date", "poc_first_date"])
prj = pd.read_csv(f"{ROOT}/data/processed/project_findings_t0.csv", parse_dates=["published", "kev_date", "poc_first_date"])
T_test = pd.Timestamp(S["test_cohort"]); cutoff = pd.Timestamp(S["data_cutoff"]); checks = []
def chk(name, ok, detail=""): checks.append({"check": name, "passed": bool(ok), "detail": detail})
chk("C1 every population row was public (published <= T) at its snapshot", (pop.published <= pop.snapshot).all())
chk("C2 no label window extends past the data cut-off", (pop.window_end <= cutoff).all())
chk("C3 one row per CVE per cohort (no duplicates)", not pop.duplicated(["snapshot", "cve"]).any())
k = pop[pop.cand_kev == 1]; chk("C4 KEV candidates were NOT already in KEV at T", ((k.kev_date.isna()) | (k.kev_date > k.snapshot)).all())
p = pop[pop.cand_poc == 1]; chk("C5 PoC candidates had no public PoC at T", ((p.poc_first_date.isna()) | (p.poc_first_date > p.snapshot)).all())
pk = pop[pop.kev_12m == 1]; chk("C6 KEV positives were added strictly after T and inside the window", ((pk.kev_date > pk.snapshot) & (pk.kev_date <= pk.window_end)).all())
pp = pop[pop.poc_12m == 1]; chk("C7 PoC positives first appeared strictly after T and inside the window", ((pp.poc_first_date > pp.snapshot) & (pp.poc_first_date <= pp.window_end)).all())
dev = pop[pop.snapshot < T_test]; chk("C8 temporal split: all dev-cohort label windows end on/before the test snapshot", (dev.window_end <= T_test).all(), f"max dev window_end = {dev.window_end.max().date()} ; test T = {T_test.date()}")
FEATURES = ["advisory_age_days", "cvss_base", "sev_rank", "AV", "AC", "PR", "UI", "SC", "C", "I", "A", "cwe_primary", "n_advisories", "n_affected_packages", "n_ecosystems", "has_fix"] + [c for c in pop.columns if c.startswith("eco_")] + ["poc_count_at_T", "epss_at_T", "epss_pct_at_T"]
FORBIDDEN = {"kev_date", "poc_first_date", "kev_12m", "poc_12m", "cand_kev", "cand_poc", "window_end", "published", "cve"}
chk("C9 the declared feature list contains no label-derived or future-dated column", not (set(FEATURES) & FORBIDDEN), "FEATURES saved to config/features.json")
json.dump({"population_features": FEATURES, "forbidden": sorted(FORBIDDEN)}, open(f"{ROOT}/config/features.json", "w"), indent=1)
import random, glob
random.seed(1); smp = pop[pop.poc_count_at_T > 0].sample(200, random_state=1); bad = 0
for r in smp.itertuples():
    f = glob.glob(f"{ROOT}/data/raw/poc/20*/{r.cve}.json")[0]
    n = sum(pd.Timestamp(x["created_at"][:10]) <= r.snapshot for x in json.load(open(f)) if x.get("created_at")); bad += int(n != r.poc_count_at_T)
chk("C10 poc_count_at_T independently recomputed from raw PoC files (200 random rows)", bad == 0, f"{bad} mismatches")
# project-level
trip = prj.dropna(subset=["cve"]).groupby(["name", "version", "cve"]).project.nunique()
shared = int((trip > 1).sum()); chk("C11 (informational) package-version-CVE triples shared by >1 project -> split by PROJECT not by row", True, f"{shared} of {len(trip)} triples appear in more than one project")
chk("C12 project findings use only advisories published <= T0", (prj.published <= pd.Timestamp(S["project_snapshot_date"])).all())
chk("C13 package-health features use only releases <= T0 (days_since_last_release >= 0)", (prj.days_since_last_release.dropna() >= 0).all())
res = {"all_passed": all(c["passed"] for c in checks), "checks": checks,
       "residual_risks_not_testable": [
        "Advisory metadata (CVSS vector, CWE, severity) is the 2026-10-13 version, not the version visible at T; later revisions could leak weakly.",
        "Reference-list features (FIX/REPORT/EVIDENCE counts) are excluded because references accrue over time and may include exploit links added after T.",
        "PoC repository creation dates are reliable, but PoC star counts are current values and are therefore NOT used as features.",
        "KEV and PoC labels are proxies for exploitation: KEV under-reports library flaws (only 135 of 1,739 KEV entries map to package advisories); PoC repos include fake/scanner repos.",
        "Right-censoring: later cohorts have had less time for exploitation to be observed; the 2025-10-08 window is the only one that is a full 12 months by the cut-off."]}
json.dump(res, open(f"{ROOT}/results/leakage_checks.json", "w"), indent=1)
for c in checks: print(("PASS" if c["passed"] else "FAIL"), c["check"], "|", c["detail"])
print("ALL PASSED:", res["all_passed"])
