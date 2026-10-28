"""Activity 7 - independent evaluation on the held-out 2025 cohort (never used for any choice) plus project-level checks.
Writes (results/): eval_paired_differences.csv, eval_operating_points.csv, eval_robustness.csv, eval_by_ecosystem.csv, eval_overhead.csv, eval_calibration.csv,
eval_error_analysis.csv, eval_project_ablation.csv, evaluation_summary.json and figures/*.png"""
import os, sys, json, time
import numpy as np, pandas as pd, joblib
import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import *
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); R = f"{ROOT}/results"; FIG = f"{R}/figures"; os.makedirs(FIG, exist_ok=True)
mp = json.load(open(f"{R}/model_params.json")); ep = json.load(open(f"{R}/engine_params.json")); TEST = mp["test_cohort"]
pop = pd.read_csv(f"{ROOT}/data/processed/population_cohorts.csv"); pop["snapshot"] = pop.snapshot.astype(str).str[:10]
hy = pd.read_csv(f"{R}/test_predictions_2025.csv"); hyb = pd.read_csv(f"{R}/hybrid_test_scores_2025.csv"); tp = hy
rng = np.random.default_rng(SEED)
pairs, ops, rob, eco_rows, over, calib, errs, summary, curves = [], [], [], [], [], [], [], {"test_cohort": TEST}, {}


def hybrid_score(kind, pt, rt, df):
    return gate_fuse(pt, df.poc_count_at_T.fillna(0).values) if kind == "gate" else fuse(pt, rt, float(kind))


for task, (cand, lab) in LABELS.items():
    te = pop[(pop[cand] == 1) & (pop.snapshot == TEST)].reset_index(drop=True); h = hyb[hyb.label == lab].reset_index(drop=True)
    assert (h.cve.values == te.cve.values).all(), "row order mismatch between population and hybrid scores"
    y = h.y.values; best = ep["population_fusion"][lab]["best_model"]; kind = ep["population_fusion"][lab]["combination"]
    S = {"B1 CVSS only": te.cvss_base.fillna(-1).values, "Rule score": h.rule.values, f"Model ({best})": h.model_p.values, "Hybrid (selected)": h.hybrid.values}
    # 1. paired comparisons on the same rows
    for a, b in [("Hybrid (selected)", "B1 CVSS only"), ("Hybrid (selected)", "Rule score"), (f"Model ({best})", "Rule score"), ("Rule score", "B1 CVSS only")]:
        for mname, fn in [("ROC AUC", auc), ("Recall in top 5%", lambda yy, ss: recall_at(yy, ss, .05)), ("Average precision", lambda yy, ss: average_precision_score(yy, ss))]:
            lo, hi = paired_boot_diff(y, S[a], S[b], fn); pt_ = fn(y, S[a]) - fn(y, S[b])
            pairs.append(dict(label=lab, comparison=f"{a} minus {b}", metric=mname, difference=round(pt_, 4), ci95_low=round(lo, 4), ci95_high=round(hi, 4), interval_excludes_zero=bool(lo > 1e-9 or hi < -1e-9)))
    # 2. operating points: false positives / false negatives if the top 1/5/10% is flagged
    for n, s in S.items():
        for f in (.01, .05, .10): ops.append(dict(label=lab, scorer=n, top_fraction=f, **confusion_at(y, s, f)))
        curves[(lab, n)] = [recall_at(y, s, f) for f in np.linspace(0.005, 0.20, 40)]
    # 3. robustness and a bypass test (severity downgrade of the CVEs that really were exploited)
    model = joblib.load(f"{ROOT}/models/{lab}_{best}.joblib")

    def run(df):
        pt = model.predict_proba(prepare(df))[:, 1]; rt = rule_score(df)
        return {"B1 CVSS only": df.cvss_base.fillna(-1).values, "Rule score": rt, "Model": pt, "Hybrid (selected)": hybrid_score(kind, pt, rt, df)}
    pert = {"none (clean test)": lambda d: d,
            "CVSS noise (normal, sd 1.0)": lambda d: d.assign(cvss_base=(d.cvss_base + np.random.default_rng(SEED).normal(0, 1, len(d))).clip(0, 10)),
            "20% of CVSS scores missing": lambda d: d.assign(cvss_base=d.cvss_base.where(np.random.default_rng(SEED).random(len(d)) > .2)),
            "BYPASS: exploited CVEs get CVSS lowered by 3": lambda d: d.assign(cvss_base=np.where(y == 1, (d.cvss_base - 3).clip(0), d.cvss_base))}
    if task == "kev": pert["BYPASS: exploit code hidden for exploited CVEs"] = lambda d: d.assign(poc_count_at_T=np.where(y == 1, 0, d.poc_count_at_T))
    clean = None
    for pn, fn in pert.items():
        for sn, s in run(fn(te.copy())).items():
            a_, r_ = auc(y, s), recall_at(y, s, .05)
            if pn.startswith("none"): clean = clean or {}; clean[sn] = (a_, r_)
            rob.append(dict(label=lab, perturbation=pn, scorer=sn, roc_auc=round(a_, 3), recall_top5pct=round(r_, 3), auc_change=round(a_ - clean[sn][0], 3), recall_change=round(r_ - clean[sn][1], 3)))
    # 4. by ecosystem
    for e in ECO:
        m = (te[e] == 1).values
        if m.sum() > 200 and y[m].sum() >= 3:
            eco_rows.append(dict(label=lab, ecosystem=e.replace("eco_", ""), cves=int(m.sum()), positives=int(y[m].sum()), auc_B1=round(auc(y[m], S["B1 CVSS only"][m]), 3),
                                 auc_rule=round(auc(y[m], S["Rule score"][m]), 3), auc_hybrid=round(auc(y[m], S["Hybrid (selected)"][m]), 3)))
    # 5. calibration of the chosen model (raw and Platt-recalibrated)
    t = tp[(tp.label == lab) & (tp.model == best)]
    for col in ("p", "p_platt"):
        e_, tb = ece(t.y.values, t[col].values); tb.insert(0, "probabilities", col); tb.insert(0, "label", lab); calib.append(tb); summary[f"ece_{lab}_{col}"] = round(e_, 5)
    # 6. error analysis
    rk = pd.Series(S["Hybrid (selected)"]).rank(ascending=False, method="average").values; info = pd.DataFrame(dict(cve=te.cve, cvss=te.cvss_base, poc_count_at_T=te.poc_count_at_T, model_p=h.model_p, rank=rk, of=len(y), y=y))
    errs.append(info[info.y == 1].sort_values("rank").assign(label=lab, type="exploited CVE and where it was ranked").head(25))
    errs.append(info[info.y == 0].sort_values("rank").assign(label=lab, type="false positive: ranked high, not exploited").head(15))
    summary[f"{lab}_headline"] = {n: metrics(y, s) for n, s in S.items()}

# 7. overhead
for task, (cand, lab) in LABELS.items():
    te = pop[(pop[cand] == 1) & (pop.snapshot == TEST)]
    for name in ("logreg", "gboost", "forest"):
        f = f"{ROOT}/models/{lab}_{name}.joblib"; m = joblib.load(f); X = prepare(te); t0 = time.time(); m.predict_proba(X); s = time.time() - t0
        over.append(dict(label=lab, model=name, rows_scored=len(te), seconds=round(s, 3), ms_per_1000_rows=round(1000 * s / len(te) * 1000, 2), model_file_mb=round(os.path.getsize(f) / 1e6, 2), fit_seconds=mp["models"][f"{lab}/{name}"]["fit_seconds"]))
plan = pd.read_csv(f"{R}/remediation_plan.csv"); t0 = time.time(); build_plan(plan.drop(columns=["exploit_pct", "exposure", "health_penalty", "abandoned", "risk_score", "tier", "action", "reasons"]), plan.exploit_pct.values); eng_s = time.time() - t0
over.append(dict(label="project engine", model="build_plan", rows_scored=len(plan), seconds=round(eng_s, 3), ms_per_1000_rows=round(eng_s / len(plan) * 1e6, 2), model_file_mb=np.nan, fit_seconds=np.nan))

# 8. project-level ablation (descriptive: few positives)
sub = plan[(plan.cand_poc == 1) & (plan.has_cve == 1)].copy(); yp = sub.poc_12m.values; cp = sub.cvss_base.fillna(-1).values
PS = {"CVSS only": cp, "Exploitation percentile only": sub.exploit_pct.values, "Graph exposure only": sub.exposure.values, "Package health only": sub.health_penalty.values,
      "Exploitation + exposure": W["exploit"] * sub.exploit_pct.values + W["exposure"] * sub.exposure.values, "Exploitation + health": W["exploit"] * sub.exploit_pct.values + W["health"] * sub.health_penalty.values,
      "Full risk score": sub.risk_score.values}
prow = []
for n, s in PS.items():
    lo, hi = boot(yp, s, auc); prow.append(dict(scorer=n, findings=len(sub), positives=int(yp.sum()), roc_auc=round(auc(yp, s), 3), auc_ci95=f"{lo:.2f}-{hi:.2f}", recall_top10pct=round(recall_at(yp, s, .10), 3), recall_top20pct=round(recall_at(yp, s, .20), 3)))
kv = plan[(plan.cand_kev == 1) & (plan.has_cve == 1)]; tiers = sub.groupby("tier").agg(findings=("poc_12m", "size"), positives=("poc_12m", "sum")).reset_index()
summary["project"] = dict(poc_findings=len(sub), poc_positives=int(yp.sum()), kev_findings=len(kv), kev_positives=int(kv.kev_12m.sum()), kev_positive_rank_in_plan=[int(r) for r in kv[kv.kev_12m == 1]["rank"]],
                          positives_in_P1_P2=int(sub[sub.tier.isin(["P1", "P2"])].poc_12m.sum()), findings_in_P1_P2=int(sub.tier.isin(["P1", "P2"]).sum()), actions=plan.action.value_counts().to_dict(), tiers=plan.tier.value_counts().to_dict(),
                          explanation_coverage=float((plan.reasons.str.len() > 0).mean()))
pd.DataFrame(pairs).to_csv(f"{R}/eval_paired_differences.csv", index=False); pd.DataFrame(ops).to_csv(f"{R}/eval_operating_points.csv", index=False); pd.DataFrame(rob).to_csv(f"{R}/eval_robustness.csv", index=False)
pd.DataFrame(eco_rows).to_csv(f"{R}/eval_by_ecosystem.csv", index=False); pd.DataFrame(over).to_csv(f"{R}/eval_overhead.csv", index=False); pd.concat(calib).to_csv(f"{R}/eval_calibration.csv", index=False)
pd.concat(errs).to_csv(f"{R}/eval_error_analysis.csv", index=False); pd.DataFrame(prow).to_csv(f"{R}/eval_project_ablation.csv", index=False); pd.DataFrame(tiers).to_csv(f"{R}/eval_project_tiers.csv", index=False)
json.dump(summary, open(f"{R}/evaluation_summary.json", "w"), indent=1, default=float)

# 9. figures
fr = np.linspace(0.005, 0.20, 40)
for task, (cand, lab) in LABELS.items():
    plt.figure(figsize=(6, 4))
    for (l, n), v in curves.items():
        if l == lab: plt.plot(100 * fr, v, label=n)
    plt.plot(100 * fr, fr, "k:", label="Random"); plt.xlabel("Top % of CVEs flagged"); plt.ylabel("Share of future exploited CVEs found"); plt.title(f"Test cohort {TEST}: {lab}"); plt.legend(fontsize=7); plt.grid(alpha=.3); plt.tight_layout()
    plt.savefig(f"{FIG}/topk_recall_{lab}.png", dpi=130); plt.close()
cal = pd.concat(calib); plt.figure(figsize=(5, 4))
for task, (cand, lab) in LABELS.items():
    c = cal[(cal.label == lab) & (cal.probabilities == "p")]; plt.loglog(c.mean_predicted.clip(1e-5), c.observed_rate.clip(1e-5), "o-", label=lab)
plt.plot([1e-5, 1], [1e-5, 1], "k:", label="Perfect"); plt.xlabel("Predicted probability (decile mean)"); plt.ylabel("Observed rate"); plt.title("Calibration, 2025 test cohort"); plt.legend(fontsize=7); plt.grid(alpha=.3); plt.tight_layout()
plt.savefig(f"{FIG}/calibration.png", dpi=130); plt.close()

pd.set_option("display.width", 250, "display.max_columns", 30)
print("PAIRED DIFFERENCES (interval excludes 0 = clear difference)"); print(pd.DataFrame(pairs).query("metric != 'Average precision'")[["label", "comparison", "metric", "difference", "ci95_low", "ci95_high", "interval_excludes_zero"]].to_string(index=False))
print("\nROBUSTNESS"); print(pd.DataFrame(rob)[["label", "perturbation", "scorer", "roc_auc", "recall_top5pct", "auc_change"]].to_string(index=False))
print("\nBY ECOSYSTEM"); print(pd.DataFrame(eco_rows).to_string(index=False)); print("\nOVERHEAD"); print(pd.DataFrame(over).to_string(index=False))
print("\nPROJECT ABLATION"); print(pd.DataFrame(prow).to_string(index=False)); print(tiers.to_string(index=False)); print(json.dumps(summary["project"], default=float))
print("\nCALIBRATION ECE:", {k: v for k, v in summary.items() if k.startswith("ece")})
