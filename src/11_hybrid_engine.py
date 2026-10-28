"""Activity 6 - hybrid risk engine.
Part A (population, CVE level): combine the best learned ranker (chosen on 2024 validation) with the transparent rule score, either by linear rank fusion or by a rule gate
(public exploit code at T first, model order within). The combination is chosen on the 2024 validation cohort only (AUC + top-5% recall); the 2025 test cohort is scored once.
Ablation = B1, rule only, model only, rule-gated model.
Part B (project, finding level): combine exploitation percentile (Part A), graph exposure and package health into a risk score, a priority tier (P1-P4) and a
remediation decision (upgrade / replace / isolate / monitor / accept) with plain-language reasons.
Outputs: results/hybrid_ablation.csv, hybrid_alpha_validation.csv, hybrid_test_scores_2025.csv, remediation_plan.csv, engine_params.json"""
import os, sys, json
import numpy as np, pandas as pd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import *
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); R = f"{ROOT}/results"
mp = json.load(open(f"{R}/model_params.json")); TEST, VAL = mp["test_cohort"], mp["validation_cohort"]
pop = pd.read_csv(f"{ROOT}/data/processed/population_cohorts.csv"); pop["snapshot"] = pop.snapshot.astype(str).str[:10]
tp = pd.read_csv(f"{R}/test_predictions_2025.csv"); vp = pd.read_csv(f"{R}/validation_predictions_2024.csv")
KINDS = ["gate", 0.5, 0.25, 0.75, 0.0, 1.0]   # 'gate' = rule-gated model; numbers = linear rank fusion weight on the model


def combine(kind, pt, rt, df):
    return gate_fuse(pt, df.poc_count_at_T.fillna(0).values) if kind == "gate" else fuse(pt, rt, kind)


abl, sweep, hyb, chosen, pct_by_label = [], [], [], {}, {}
for task, (cand, lab) in LABELS.items():
    d = pop[pop[cand] == 1]; va = d[d.snapshot == VAL].reset_index(drop=True); te = d[d.snapshot == TEST].reset_index(drop=True); yv, yt = va[lab].values, te[lab].values
    vs = vp[vp.label == lab]; best = max(vs.model.unique(), key=lambda m: auc(vs[vs.model == m].y.values, vs[vs.model == m].p.values))   # best model on VALIDATION
    pv = vs[vs.model == best].set_index("cve").p.reindex(va.cve).values; rv = rule_score(va)
    vcrit = {k: (auc(yv, combine(k, pv, rv, va)), recall_at(yv, combine(k, pv, rv, va), .05)) for k in KINDS}   # selection = validation AUC + validation top-5% recall
    a_star = max(KINDS, key=lambda k: round(vcrit[k][0] + vcrit[k][1], 4))
    for k in KINDS: sweep.append(dict(label=lab, model=best, combination=str(k), validation_auc=round(vcrit[k][0], 4), validation_recall_top5=round(vcrit[k][1], 3), chosen=(k == a_star)))
    pt = tp[(tp.label == lab) & (tp.model == best)].set_index("cve").p.reindex(te.cve).values; rt = rule_score(te)
    variants = {"B1 CVSS only": te.cvss_base.fillna(-1).values, "Rule only": combine(0.0, pt, rt, te), "Model only": combine(1.0, pt, rt, te), "Rule-gated model": combine("gate", pt, rt, te)}
    sel = {"gate": "Rule-gated model", 0.0: "Rule only", 1.0: "Model only"}.get(a_star, f"Linear fusion (weight {a_star} on model)")
    if sel not in variants: variants[sel] = combine(a_star, pt, rt, te)
    for n, s in variants.items(): abl.append(dict(label=lab, variant=n, selected_on_validation=(n == sel), model_used=best if n not in ("B1 CVSS only", "Rule only") else "-", **metrics(yt, s)))
    h = variants[sel]; chosen[lab] = dict(best_model=best, combination=str(a_star), validation_auc_and_top5_recall={str(k): [round(v[0], 4), round(v[1], 3)] for k, v in vcrit.items()})
    hyb.append(pd.DataFrame(dict(label=lab, cve=te.cve, y=yt, hybrid=h, model_p=pt, rule=rt, cvss=te.cvss_base, poc_count_at_T=te.poc_count_at_T, **{c: te[c] for c in ECO})))
    pct_by_label[lab] = pd.Series(pct_rank(h), index=te.cve)
    print(f"[{lab}] best validation model: {best}; combination chosen on validation: {a_star}  { {str(k): [round(v[0], 3), round(v[1], 3)] for k, v in vcrit.items()} }")
pd.DataFrame(abl).to_csv(f"{R}/hybrid_ablation.csv", index=False); pd.DataFrame(sweep).to_csv(f"{R}/hybrid_alpha_validation.csv", index=False); pd.concat(hyb).to_csv(f"{R}/hybrid_test_scores_2025.csv", index=False)
pd.set_option("display.width", 250, "display.max_columns", 30)
print(pd.DataFrame(abl)[["label", "variant", "selected_on_validation", "positives", "roc_auc", "auc_ci95", "avg_precision", "recall_top5pct", "recall_top5_ci95", "recall_top10pct"]].to_string(index=False))

# ---- Part B: project-level engine ----
prj = pd.read_csv(f"{ROOT}/data/processed/project_findings_t0.csv"); cv = np.sort(pop[pop.snapshot == TEST].cvss_base.dropna().values); ex, src = [], []
for _, r in prj.iterrows():
    v = [pct_by_label[l].get(r.cve) for l in pct_by_label if isinstance(r.cve, str) and r.cve in pct_by_label[l].index]
    if v: ex.append(float(np.mean(v))); src.append("model")
    elif pd.notna(r.cvss_base): ex.append(float(np.searchsorted(cv, r.cvss_base, side="right") / len(cv))); src.append("severity only")
    else: ex.append(0.5); src.append("no score")
plan = build_plan(prj, ex); plan["exploit_source"] = src
plan.loc[plan.exploit_source != "model", "reasons"] += "; no CVE id or not a candidate, ranked by severity only"
plan = plan.sort_values("risk_score", ascending=False).reset_index(drop=True); plan.insert(0, "rank", np.arange(1, len(plan) + 1))
keep = ["rank", "project", "name", "version", "ecosystem", "component", "ghsa_id", "cve", "cvss_base", "severity_label", "is_direct", "depth", "fan_in", "descendants", "pagerank", "has_fix",
        "poc_count_at_T", "epss_at_T", "kev_at_T", "kev_override", "days_since_last_release", "releases_prior_12m", "version_lag_days", "exploit_pct", "exploit_source", "exposure", "health_penalty", "abandoned",
        "risk_score", "tier", "action", "reasons", "has_cve", "cand_kev", "kev_12m", "cand_poc", "poc_12m"]
plan = plan.sort_values(["kev_override", "risk_score"], ascending=[False, False]).reset_index(drop=True)
plan["rank"] = np.arange(1, len(plan) + 1)
plan[keep].round(4).to_csv(f"{R}/remediation_plan.csv", index=False)
json.dump(dict(weights=W, tier_cuts=TIER_CUTS, actions=ACTIONS, population_fusion=chosen, snapshot=TEST, rules=dict(
    tier="P1 if risk>=0.70, P2 if >=0.50, P3 if >=0.30 else P4",
    decision="P4: monitor if direct or abandoned else accept | P1-P3: upgrade if a fix exists; replace if abandoned; isolate if P1/P2; else monitor")), open(f"{R}/engine_params.json", "w"), indent=1)
print("\nremediation plan:", len(plan), "findings;", plan.project.nunique(), "projects"); print(pd.crosstab(plan.tier, plan.action).to_string()); print(plan.exploit_source.value_counts().to_dict())
