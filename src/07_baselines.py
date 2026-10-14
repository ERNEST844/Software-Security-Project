"""Activity 4 - baselines. B1: CVSS-only ranking. B2b: rule 'public PoC exists, then CVSS' (KEV task only). B2: EPSS-based rule (runs when EPSS files are present).
Ties are handled by expectation (uniform random tie-breaking), never by input order."""
import pandas as pd, numpy as np, os, json, math
from scipy.stats import rankdata
from sklearn.metrics import roc_auc_score, average_precision_score
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); rng = np.random.default_rng(42)
pop = pd.read_csv(f"{ROOT}/data/processed/population_cohorts.csv", parse_dates=["snapshot"])
prj = pd.read_csv(f"{ROOT}/data/processed/project_findings_t0.csv")

def recall_at(y, s, frac):
    """Expected recall in the top frac of the list with uniform random tie-breaking."""
    n = len(y); k = math.ceil(frac * n); P = y.sum()
    if P == 0: return np.nan
    df = pd.DataFrame({"y": y, "s": s}).groupby("s").y.agg(["sum", "count"]).sort_index(ascending=False)
    got, left = 0.0, k
    for _, r in df.iterrows():
        if left <= 0: break
        take = min(left, r["count"]); got += r["sum"] * take / r["count"]; left -= take
    return got / P
def auc(y, s):
    r = rankdata(s); P = y.sum(); N = len(y) - P
    return (r[y == 1].sum() - P * (P + 1) / 2) / (P * N) if P and N else np.nan
def boot(y, s, fn, B=500):
    idx = np.arange(len(y)); v = []
    for _ in range(B):
        b = rng.choice(idx, len(idx)); 
        if y[b].sum() == 0: continue
        v.append(fn(y[b], s[b]))
    return (np.nanpercentile(v, 2.5), np.nanpercentile(v, 97.5)) if v else (np.nan, np.nan)
def scores(df, task):
    out = {"B1_cvss_only": df.cvss_base.fillna(-1).values}
    if task == "kev": out["B2b_poc_then_cvss"] = ((df.poc_count_at_T > 0) * 100 + df.cvss_base.fillna(0)).values
    if df.epss_at_T.notna().any(): out["B2_epss_then_cvss"] = (df.epss_at_T.fillna(0) * 100 + df.cvss_base.fillna(0) / 100).values
    return out
rows = []
for T, g in pop.groupby("snapshot"):
    for task, cand, lab in [("kev", "cand_kev", "kev_12m"), ("poc", "cand_poc", "poc_12m")]:
        d = g[g[cand] == 1]; y = d[lab].values
        for name, s in scores(d, task).items():
            lo, hi = boot(y, s, auc); rlo, rhi = boot(y, s, lambda a, b: recall_at(a, b, 0.05))
            rows.append(dict(snapshot=T.date(), label=lab, baseline=name, n_candidates=len(d), positives=int(y.sum()), prevalence_pct=round(100 * y.mean(), 3),
                roc_auc=round(auc(y, s), 3), auc_ci95=f"{lo:.2f}-{hi:.2f}", avg_precision=round(average_precision_score(y, s), 4),
                recall_top1pct=round(recall_at(y, s, .01), 3), recall_top5pct=round(recall_at(y, s, .05), 3), recall_top5_ci95=f"{rlo:.2f}-{rhi:.2f}", recall_top10pct=round(recall_at(y, s, .10), 3),
                random_avg_precision=round(y.mean(), 4)))
res = pd.DataFrame(rows); res.to_csv(f"{ROOT}/results/baseline_population_results.csv", index=False)
pd.set_option("display.width", 250, "display.max_columns", 30); print(res.drop(columns=["random_avg_precision", "n_candidates"]).to_string(index=False))
# project-level (descriptive: very few positives)
pr = []
for task, cand, lab in [("kev", "cand_kev", "kev_12m"), ("poc", "cand_poc", "poc_12m")]:
    d = prj[(prj[cand] == 1) & (prj.has_cve == 1)].copy(); y = d[lab].values; s = d.cvss_base.fillna(-1).values
    d["pct_rank"] = 1 - (rankdata(s, method="average") - 1) / (len(d) - 1)
    pr.append(dict(label=lab, findings=len(d), positives=int(y.sum()), cvss_only_auc=round(auc(y, s), 3), recall_top10pct=round(recall_at(y, s, .10), 3), recall_top20pct=round(recall_at(y, s, .20), 3),
                   positive_cvss_scores=sorted(d[y == 1].cvss_base.round(1).tolist()), median_cvss_all=float(d.cvss_base.median())))
pd.DataFrame(pr).to_csv(f"{ROOT}/results/baseline_project_results.csv", index=False); print(pd.DataFrame(pr).to_string(index=False))
sev = prj.severity_label.value_counts(dropna=False).to_dict(); print("project findings by severity:", sev)
