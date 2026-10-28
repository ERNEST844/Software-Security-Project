# Activities 5–8 — Models, Hybrid Engine, Evaluation, and Prototype

**Run date:** 2026-10-27  
**Test cohort:** 2025-10-08 (held out)  
**Data gate:** all 13 leakage/integrity checks passed after rebuilding the datasets from the restored PoC index and the four local EPSS snapshots.

## Activity 5 — Learned rankers

The rankers use the 2022 and 2023 cohorts for training, 2024 for model and hyperparameter selection, then refit on 2022–2024 before scoring 2025 once. EPSS was available in all four cohorts. The 2025 candidate sets contain 21,253 KEV candidates (11 positives) and 20,299 PoC candidates (138 positives).

| Label | Model | Test ROC AUC | Average precision | Recall in top 5% |
|---|---|---:|---:|---:|
| KEV within 12 months | Logistic regression | 0.916 | 0.1022 | 0.636 |
| KEV within 12 months | Gradient-boosted trees | 0.946 | 0.0458 | 0.636 |
| KEV within 12 months | Random forest | 0.956 | 0.1181 | 0.727 |
| PoC within 12 months | Logistic regression | 0.604 | 0.0110 | 0.094 |
| PoC within 12 months | Gradient-boosted trees | 0.647 | 0.0147 | 0.138 |
| PoC within 12 months | Random forest | 0.657 | 0.0159 | 0.196 |

The KEV results are based on only 11 held-out positives, so apparently high discrimination has substantial uncertainty. On the denser PoC label, the random forest had the best test AUC among the learned models, but the rule score had slightly higher AUC and average precision.

## Activity 6 — Hybrid engine and project remediation plan

Population fusion choices were made using 2024 validation results only: 25% model percentile / 75% rule percentile for KEV, and a public-PoC gate followed by model ordering for PoC. No 2025 result was used to choose the fusion.

| Label | Selected hybrid | Test ROC AUC (95% CI) | Average precision | Recall in top 5% (95% CI) | CVSS-only top-5% recall |
|---|---|---:|---:|---:|---:|
| KEV within 12 months | Linear fusion | 0.905 (0.79–0.98) | 0.0117 | 0.636 (0.30–0.92) | 0.299 |
| PoC within 12 months | PoC-gated random forest | 0.657 (0.61–0.71) | 0.0159 | 0.196 (0.13–0.27) | 0.112 |

The project plan contains 374 findings across 14 projects, including 357 findings with a CVE. It assigns a tier and a reasoned `upgrade`, `replace`, `isolate`, `monitor`, or `accept` action using the fixed 0.60 exploitation / 0.25 graph exposure / 0.15 package health policy. The project set has 12 PoC-label positives and one KEV-label positive; project-level comparisons are therefore descriptive.

A CVE already present in KEV at the scan snapshot is overridden to P1 and sorted ahead of the blended score. There are no such project findings in this 2025-10-08 snapshot.

## Activity 7 — Held-out evaluation

Paired bootstrap comparisons on the same held-out CVEs found:

- KEV hybrid versus CVSS-only: ROC AUC difference +0.1173 (95% CI 0.0146–0.2113) and top-5% recall difference +0.3377 (0.0113–0.6452); average-precision difference +0.0088 (-0.0021–0.0434), which does not exclude zero.
- PoC hybrid versus CVSS-only: top-5% recall difference +0.0832 (0.0197–0.1485), but the AUC difference is -0.0048 (-0.0589–0.0464) and the average-precision difference is +0.0037 (-0.0000–0.0100).
- Neither hybrid has a paired interval excluding zero for all metrics versus the rule score. Accordingly, the results do not establish that the hybrid is universally better than the transparent rule.

The project-level full-risk ablation AUC is 0.680 (95% CI 0.45–0.85), versus 0.648 (0.45–0.81) for CVSS only. These wide, overlapping intervals and the small positive count do not establish a project-level improvement.

## Activity 8 — Prototype

`results/dashboard.html` is a standalone dashboard with project, tier, action, and text filters; sortable findings; plain-language reasons; an export of filtered rows; action summaries; and held-out evaluation summaries. It makes no network requests and can be opened locally in a browser.

## Reproduction and output files

With the required raw inputs and dependencies available, run:

```text
python run_all.py --from 05b
```

This rebuilds datasets, reruns the leakage gate, and produces the model, hybrid, evaluation, and dashboard outputs. Key artifacts include `results/model_population_results.csv`, `results/hybrid_ablation.csv`, `results/remediation_plan.csv`, `results/evaluation_summary.json`, the `results/eval_*.csv` files, figures under `results/figures/`, and `results/dashboard.html`. Trained estimators are written under `models/`.

## Scope and limitations to retain in the final paper

- The 2025 held-out KEV set has only 11 positives; confidence intervals are wide. PoC existence is a noisy proxy for exploitation.
- The project ablation uses the 14-project set descriptively; it is not a project-held-out evaluation.
- The implemented population rankers do not include a learned graph-feature variant. Graph exposure and package health are analyzed in the project-level risk ablation instead.
- NDCG and SHAP stability were not calculated. Explanations use model feature importance where available and rule-generated reasons.
- The remediation ranking is metadata-level exposure and policy support; it does not demonstrate vulnerable-code reachability or exploitability.
- This run covers the activities' pipeline and prototype outputs, not a clean-room rerun from an empty checkout.
