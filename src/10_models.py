"""Activity 5 - main models. Three learned rankers (logistic regression, gradient-boosted trees, random forest) for each label.
Protocol (frozen in config/study.yaml): tune on cohort 2024 using models trained on 2022-2023 only; refit on 2022-2024; score the held-out 2025 cohort ONCE.
Selection metric: validation ROC AUC (stable even with few positives). Probabilities are also Platt-recalibrated on the validation cohort, so calibration can be reported.
Outputs: results/model_population_results.csv, model_validation_2024.csv, model_params.json, feature_importance.csv, test_predictions_2025.csv, validation_predictions_2024.csv, models/*.joblib"""
import os, sys, json, time, warnings
import numpy as np, pandas as pd, yaml, joblib
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import brier_score_loss
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import *
warnings.filterwarnings("ignore")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
cfg = yaml.safe_load(open(f"{ROOT}/config/study.yaml"))["snapshots"]
dates = sorted(str(d) for d in cfg["cohort_dates"]); TEST = str(cfg["test_cohort"]); DEV = [d for d in dates if d < TEST]; VAL = DEV[-1]; DEVTRAIN = DEV[:-1]
pop = pd.read_csv(f"{ROOT}/data/processed/population_cohorts.csv"); pop["snapshot"] = pop.snapshot.astype(str).str[:10]
os.makedirs(f"{ROOT}/results", exist_ok=True); os.makedirs(f"{ROOT}/models", exist_ok=True)

# ---- leakage guards (also covered by tests/test_pipeline.py) ----
assert not (set(NUM + OPT + CAT) & FORBIDDEN), "a label/future column is among the model inputs"
assert (pop[pop.snapshot.isin(DEV)].window_end.astype(str).str[:10] <= TEST).all(), "a training label window reaches past the test snapshot"
assert TEST not in DEV and VAL < TEST

GRID = {"logreg": [{"C": c} for c in (0.01, 0.1, 1.0)],
        "gboost": [{"max_depth": d, "lr": l} for d in (2, 4) for l in (0.05, 0.1)],
        "forest": [{"leaf": l} for l in (20, 50)]}
NAMES = {"logreg": "Logistic regression", "gboost": "Gradient-boosted trees", "forest": "Random forest"}


def build(name, hp, use_epss):
    num = NUM + (OPT if use_epss else [])
    pre = ColumnTransformer([("num", Pipeline([("imp", SimpleImputer(strategy="median", add_indicator=True)), ("sc", StandardScaler())]), num),
                             ("cat", OneHotEncoder(handle_unknown="infrequent_if_exist", min_frequency=100, sparse_output=False), CAT)])
    if name == "logreg": clf = LogisticRegression(C=hp["C"], max_iter=3000, random_state=SEED)
    elif name == "gboost": clf = HistGradientBoostingClassifier(max_depth=hp["max_depth"], learning_rate=hp["lr"], max_iter=200, l2_regularization=1.0, min_samples_leaf=40, early_stopping=False, random_state=SEED)
    else: clf = RandomForestClassifier(n_estimators=150, min_samples_leaf=hp["leaf"], max_features="sqrt", n_jobs=-1, random_state=SEED)
    return Pipeline([("pre", pre), ("clf", clf)])


rows, vrows, preds, vpreds, params, imps = [], [], [], [], {}, []
for task, (cand, lab) in LABELS.items():
    d = pop[pop[cand] == 1]; tr = d[d.snapshot.isin(DEVTRAIN)]; va = d[d.snapshot == VAL]; fin = d[d.snapshot.isin(DEV)]; te = d[d.snapshot == TEST]
    use_epss = bool(fin.epss_at_T.notna().any()); yv, yt = va[lab].values, te[lab].values
    print(f"\n[{lab}] train {len(tr)} ({int(tr[lab].sum())} pos) | validate {len(va)} ({int(yv.sum())}) | final fit {len(fin)} ({int(fin[lab].sum())}) | test {len(te)} ({int(yt.sum())}) | EPSS used: {use_epss}")
    # baselines on the SAME test rows
    base = {"B1_cvss_only": te.cvss_base.fillna(-1).values, "R_rule_score": rule_score(te)}
    if task == "kev": base["B2b_poc_then_cvss"] = ((te.poc_count_at_T > 0) * 100 + te.cvss_base.fillna(0)).values
    for n, s in base.items(): rows.append(dict(label=lab, model=n, kind="baseline", **metrics(yt, s)))
    for name, grid in GRID.items():
        best = None
        for hp in grid:
            p = build(name, hp, use_epss).fit(prepare(tr), tr[lab]).predict_proba(prepare(va))[:, 1]; a = auc(yv, p)
            vrows.append(dict(label=lab, model=name, hyperparameters=json.dumps(hp), val_auc=round(a, 4)))
            if best is None or a > best[0]: best = (a, hp, p)
        a, hp, pval = best
        platt = LogisticRegression(C=1e6).fit(logit(pval).reshape(-1, 1), yv)       # Platt scaling on the validation cohort
        t0 = time.time(); m = build(name, hp, use_epss).fit(prepare(fin), fin[lab]); fit_s = time.time() - t0
        t1 = time.time(); pt = m.predict_proba(prepare(te))[:, 1]; score_s = time.time() - t1
        pp = platt.predict_proba(logit(pt).reshape(-1, 1))[:, 1]; ref = yt.mean() * (1 - yt.mean())
        e_raw, _ = ece(yt, pt); e_pl, _ = ece(yt, pp)
        rows.append(dict(label=lab, model=name, kind="model", **metrics(yt, pt), brier_skill_raw=round(1 - brier_score_loss(yt, pt) / ref, 3),
                         brier_skill_platt=round(1 - brier_score_loss(yt, pp) / ref, 3), ece_raw=round(e_raw, 5), ece_platt=round(e_pl, 5)))
        params[f"{lab}/{name}"] = dict(hyperparameters=hp, validation_auc=round(a, 4), fit_seconds=round(fit_s, 2), score_seconds_test=round(score_s, 3), n_scored=len(te), seed=SEED)
        preds.append(pd.DataFrame(dict(label=lab, model=name, cve=te.cve.values, y=yt, p=pt, p_platt=pp)))
        vpreds.append(pd.DataFrame(dict(label=lab, model=name, cve=va.cve.values, y=yv, p=pval)))
        joblib.dump(m, f"{ROOT}/models/{lab}_{name}.joblib", compress=3)
        names = m.named_steps["pre"].get_feature_names_out(); clf = m.named_steps["clf"]
        v = clf.coef_[0] if name == "logreg" else clf.feature_importances_ if name == "forest" else None
        if v is not None:
            for i in np.argsort(-np.abs(v))[:15]: imps.append(dict(label=lab, model=name, feature=names[i], value=round(float(v[i]), 5), meaning="standardised coefficient (+ raises risk)" if name == "logreg" else "importance"))
        print(f"  {NAMES[name]:24s} val AUC {a:.3f} hp={hp} | test AUC {auc(yt, pt):.3f}  top5% recall {recall_at(yt, pt, .05):.3f}  fit {fit_s:.1f}s")

res = pd.DataFrame(rows); res.insert(0, "test_snapshot", TEST)
res.to_csv(f"{ROOT}/results/model_population_results.csv", index=False)
pd.DataFrame(vrows).to_csv(f"{ROOT}/results/model_validation_2024.csv", index=False)
pd.concat(preds).to_csv(f"{ROOT}/results/test_predictions_2025.csv", index=False)
pd.concat(vpreds).to_csv(f"{ROOT}/results/validation_predictions_2024.csv", index=False)
pd.DataFrame(imps).to_csv(f"{ROOT}/results/feature_importance.csv", index=False)
json.dump(dict(test_cohort=TEST, validation_cohort=VAL, dev_train_cohorts=DEVTRAIN, final_train_cohorts=DEV, epss_used=use_epss, models=params), open(f"{ROOT}/results/model_params.json", "w"), indent=1)
pd.set_option("display.width", 250, "display.max_columns", 30)
print("\n", res[["label", "model", "positives", "roc_auc", "auc_ci95", "avg_precision", "recall_top1pct", "recall_top5pct", "recall_top5_ci95", "recall_top10pct", "ece_raw", "ece_platt"]].to_string(index=False))
