# Research Protocol — Project 6: Intelligent Software Supply-Chain Security

**Course:** UTAMU S26.CSC 7203 Security of Software (2026/2027)
**Title:** Prioritising vulnerable third-party dependencies: from SBOMs to a risk-ranked remediation list
**Status:** v1.1. The original protocol was frozen 2026-10-13 before any model was trained; post-run deviations are recorded in the Amendments Log (Section 10).
**Companion files:** `01_literature_matrix.csv`, `../config/study.yaml`, `../config/features.json`

---

## 1. Problem and research gap

Dependency scanners report every known vulnerability in every package, direct or transitive. Teams then face a prioritisation problem: most findings are never exploited, many sit deep in the dependency tree, and CVSS (Common Vulnerability Scoring System) measures severity, not the likelihood of attack. The literature shows that:

- naive counting overstates real risk (L05, L06);
- vulnerabilities propagate through dependency structure, mostly indirectly (L07, L08, L09);
- exploitation likelihood can be modelled separately from severity (L03, L04);
- machine-learning results in security are frequently inflated by leakage and time-unaware evaluation (L17, L18).

**Gap.** We found no study in the reviewed set that, for application projects, combines (i) SBOM-derived dependency-graph position, (ii) package-health signals and (iii) exploitation evidence in a **time-aware** evaluation, and compares learned rankers against transparent baselines on the **same held-out evidence**. This protocol is designed to fill that gap at MSc scale. (This is a gap in the 20 references reviewed, not a claim about all literature.)

## 2. Research questions and hypotheses

| ID | Question | Hypothesis (falsifiable) |
|---|---|---|
| RQ1 | Does exploitation evidence (EPSS, public proof-of-concept) improve ranking over CVSS alone? | H1: Recall in the top 5% of the ranked list is higher than for CVSS-only on the held-out cohort. |
| RQ2 | Do learned rankers beat transparent rule-based scores on future (held-out) time periods? | H2: At least one learned model beats the best rule baseline on average precision on the 2025-10-08 cohort, with a bootstrap interval that excludes equality. |
| RQ3 | Do graph position and package-health features add value for **project-level** prioritisation? | H3: Adding graph/health features improves ranking of project findings versus the vulnerability-only model (ablation). |
| RQ4 | Are the scores calibrated and explainable enough to drive an upgrade / replace / isolate / monitor / accept decision? | H4: Calibration error is reported; SHAP explanations are stable across cohorts. |

H1–H4 are tested in Activities 5–7. Negative results will be reported as such.

## 3. Scope

**In scope:** known-vulnerable and poorly-maintained third-party dependencies in npm and PyPI lockfiles of application repositories (15 public repositories); vulnerability-level analysis across eight package ecosystems.

**Out of scope:** detection of malicious packages (the handbook title mentions them). Studying them requires downloading suspect packages, which the handbook permits only in an isolated approved environment; none is available. The taxonomy of L13 is used to state this boundary explicitly. Also out of scope: code-level reachability (L14–L16) and first-party code vulnerabilities.

## 4. Threat model

- **Asset:** an application assembled from open-source dependencies, including transitive ones pinned by a lockfile.
- **Adversary:** an external attacker who exploits a publicly known vulnerability in a dependency (known-vulnerability risk), or an attacker benefiting from an abandoned package that no longer receives fixes.
- **Defender decision:** which of the many findings to remediate first, and how (upgrade, replace, isolate, monitor, accept).
- **Security claims are limited to** metadata-level exposure: a component version is inside an advisory's affected range. We do **not** claim the vulnerable code is reachable or exploitable in the application.

## 5. Ethics, permissions and safety

- Only **public** repositories are analysed.
- Only dependency lockfiles/manifests are read (no source code is analysed or redistributed).
- No package is installed or executed in the study.
- No exploit code is downloaded. The PoC index is used only for repository creation **dates** per CVE.
- No live systems are scanned. All data sources are public.

## 6. Data and labels

| Source | Use | Pin / version | Licence |
|---|---|---|---|
| GitHub Advisory Database (OSV format) | vulnerabilities, affected ranges, CVSS vectors, CWE | commit `36d4c87c…`, 2026-10-13 | CC BY 4.0 (file header) |
| CISA KEV (via GitHub mirror) | label L1 | catalogVersion 2026.10.08, 1,739 entries | US-government publication; confirm terms at cisa.gov |
| nomi-sec/PoC-in-GitHub | label L2, PoC feature | commit `7bf2d879…`, 2026-10-13 | Creative Commons (file header) |
| npm registry, PyPI JSON API | release dates for package-health features | fetched 2026-10-13 | public API |
| FIRST EPSS | feature + Baseline 2 | four cohort snapshots retrieved 2026-10-27; `src/fetch_epss.py` | free per FIRST |
| 15 public repositories | lockfiles at the 2025-10-08 snapshot commit | commit hashes in `data/processed/snapshot_file_manifest.json` | see `02_data_provenance_and_dictionary.md` |

### 6.1 Time-aware design

For a snapshot date **T**, every feature uses only information that existed at T. The label looks **12 months forward**. Cohorts: T ∈ {2022-10-08, 2023-10-08, 2024-10-08, 2025-10-08}. The **2025-10-08 cohort is the held-out test set** (its window ends 2026-10-08, the KEV cut-off — a full 12 months). Earlier cohorts are for development; their label windows all end on or before 2025-10-08, so no development label sees the test window.

### 6.2 Labels — and why there are two

| Label | Definition | Positives per cohort (2022 → 2025) | Prevalence |
|---|---|---|---|
| **L1 `kev_12m`** (strong) | CVE first added to CISA KEV in (T, T+12m]; candidates exclude CVEs already in KEV at T | 8, 4, 5, 11 | 0.03–0.07 % |
| **L2 `poc_12m`** (dense) | First public GitHub PoC repository created in (T, T+12m]; candidates exclude CVEs that already had one at T | 42, 70, 187, 138 | 0.35–1.07 % |

**Finding that shaped the design.** Only 135 of the 1,739 KEV entries map to a library advisory (npm 14, PyPI 20, Maven 54). A forward-looking KEV label therefore yields only 4–11 positives per cohort among 12,000–21,000 candidates — far too few to support statistical claims alone. L1 is retained because it is the strongest evidence of real exploitation, but **L2 carries the statistical weight**; L1 is reported with wide confidence intervals and never as the sole basis for a conclusion. PoC existence is a noisy proxy (some repositories are fake, scanners or duplicates); this is a stated limitation.

### 6.3 KEV is a label, not a feature

KEV membership cannot be both the target and an input. Therefore Baseline 2 is **CVSS + EPSS** (and a PoC-existence variant for the KEV task), not CVSS + EPSS + KEV. In the operational remediation engine (Activity 6), a CVE that is *already* in KEV at scan time is an override to the top priority, and that override is evaluated separately as triage coverage.

## 7. Evaluation plan

- **Unit of analysis:** CVE (population dataset); project × component × CVE (project dataset). The population split is by time. A project-held-out evaluation was planned for project findings, because 45 of 307 package-version-CVE triples appear in more than one project; the current project ablation is descriptive across the full project set and must not be interpreted as a held-out project result.
- **Metrics:** ROC AUC; average precision; recall in the top 1% / 5% / 10% with ties broken by expectation (never by input order); calibration (reliability curve, Brier score) for probabilistic models; bootstrap 95% intervals (500 resamples over CVEs). NDCG was planned but not calculated.
- **Baselines (Activity 4):** B1 CVSS-only; B2 CVSS+EPSS rule (when EPSS available); B2b "public PoC at T, then CVSS" (KEV task). Random expectation (AUC 0.5; AP = prevalence) is the floor.
- **Main models (Activity 5):** Logistic Regression, Random Forest, and gradient boosting; **hybrid layer (Activity 6):** rules + learned score with an action engine. A learned graph-feature variant was planned but not implemented; graph exposure and package health are evaluated in the project-level risk ablation.
- **Ablations:** with/without EPSS; with/without graph and health features; with/without PoC feature.
- **Leakage checks:** 13 automated checks (`src/06_leakage_checks.py`), all passing, and a list of residual untestable risks in `results/leakage_checks.json`.
- **Matcher validation:** the advisory matcher was validated against npm's own audit service on 1,279 package-version pairs: recall 100%, precision 99.5%. Remaining differences are explained by advisories newer than npm's service and by prerelease-version semantics (`results/matcher_validation_npm.json`).

## 8. Known limitations (declared in advance)

1. Metadata-level exposure, not exploitability or reachability.
2. KEV and PoC are proxies for real-world exploitation.
3. Advisory metadata (CVSS vector, CWE) is the 2026-10-13 version, not the version visible at T.
4. "Direct" dependencies are approximated as components with no incoming edge in the lockfile graph; monorepo workspaces blur this.
5. Repository sample is a convenience sample of well-known application repositories with committed lockfiles; results may not generalise to repositories without lockfiles. Python quota is 7, not 8, because the candidate list was exhausted.
6. Project-level labelled positives are very few (1 KEV, 12 PoC among 357 KEV / 326 PoC candidate findings), so project-level results are descriptive.
7. EPSS model versions differ across cohort dates.

## 9. Deliverables and mapping to the marking scheme

| Activity | Deliverable | Where |
|---|---|---|
| 1 Protocol + literature | this file + literature matrix | `docs/01_*` |
| 2 Data, provenance, lab | provenance manifest, data dictionary, environment record | `docs/02_*`, `data/processed/provenance_manifest.json` |
| 3 Preprocessing / features | pipeline, EDA and quality report, leakage checks | `src/`, `docs/03_*`, `results/` |
| 4 Baseline | scripts + results table + report | `src/07_baselines.py`, `docs/04_*` |

| Activity | Deliverable | Where |
|---|---|---|
| 5 Models | time-aware rankers and held-out metrics | `src/10_models.py`, `results/model_population_results.csv`, `docs/05_activity_5_to_8_results.md` |
| 6 Hybrid engine | validation-selected fusion and project remediation plan | `src/11_hybrid_engine.py`, `results/remediation_plan.csv` |
| 7 Evaluation | paired comparisons, robustness, calibration, figures | `src/12_evaluation.py`, `results/eval_*.csv`, `results/figures/` |
| 8 Prototype | standalone remediation dashboard | `src/13_dashboard.py`, `results/dashboard.html` |

## 10. Amendments log

| Date | Change | Reason | Outcome data seen? |
|---|---|---|---|
| 2026-10-13 | Repository criterion changed from "package-lock.json only" to "root-level lockfile of a supported type (package-lock.json, yarn.lock, pnpm-lock.yaml, uv.lock, poetry.lock)". "OSI-approved licence" replaced by "public repository, lockfile-only analysis". | Discovery showed most candidates use yarn/pnpm and several have non-OSI licences. | **No** — only lockfile availability had been inspected. |
| 2026-10-13 | Single KEV label replaced by two labels (L1 KEV, L2 PoC). | KEV positives per cohort are 4–11, too few. | Label counts were inspected (not model results). |
| 2026-10-13 | Baseline 2 changed from CVSS+EPSS+KEV to CVSS+EPSS (+PoC variant). | KEV cannot be both target and feature. | No. |
| 2026-10-27 | Activities 5–8 executed after restoring the pinned PoC index and rebuilding all cohorts with the available EPSS snapshots. The protocol is clarified to distinguish completed analyses from planned work: the graph-feature ranker, project-held-out evaluation, NDCG, and SHAP stability analysis were not completed. | Record implementation scope and evaluation limitations accurately after the held-out results were generated. | **Yes** — the 2025 test cohort had been scored. |
