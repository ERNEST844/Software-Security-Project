# Activity 2 — Data and Lab Provenance, Data Dictionary, Environment Record

Machine-readable provenance (hashes, commits, versions): `data/processed/provenance_manifest.json`.

## 1. Sources, versions and licences

| Source | Version pinned | Licence / terms | Retrieved |
|---|---|---|---|
| GitHub Advisory Database, `advisories/github-reviewed` (OSV schema 1.4) | commit `36d4c87ce64759f762f4e3e0d65137da687b8272` (2026-10-13T03:35Z); 36,780 files, 35,568 non-withdrawn | CC BY 4.0 (LICENSE.md header) | 2026-10-13 |
| CISA Known Exploited Vulnerabilities | catalogVersion 2026.10.08, released 2026-10-08, 1,739 entries; SHA-256 in manifest | US-government publication — confirm terms at cisa.gov | 2026-10-13 via GitHub mirror `cisagov/kev-data` |
| nomi-sec/PoC-in-GitHub | commit `7bf2d8795e2ddf4e1669efe296f9eeabe6091ca8` (2026-10-13); 11,433 CVE files | Creative Commons (LICENSE header) | 2026-10-13 |
| npm registry / PyPI JSON API | release histories of the 379 packages that have findings | public APIs | 2026-10-13 |
| FIRST EPSS | four dated cohort snapshots, hashes and model versions in the provenance manifest | free to use per FIRST | 2026-10-27 |
| NVD, OSV API | **not used** (unreachable); CVSS recomputed from GitHub vectors with the `cvss` library (checked: Log4Shell vector → 10.0) | — | — |

### Repositories analysed (lockfiles only; snapshot = last commit on or before 2025-10-08)

| Repository | Commit | Licence header (first lines of LICENSE file) | Lockfiles read |
|---|---|---|---|
| mastodon/mastodon | 5bc7c4b7e8 | GNU AGPL v3 | yarn.lock |
| n8n-io/n8n | 65b1df9210 | custom ("Portions … licensed as follows") — source-available, not OSI | pnpm-lock.yaml |
| TryGhost/Ghost | f709a1a00b | MIT-style | yarn.lock |
| strapi/strapi | d6c661f8ab | custom ("Portions … licensed as follows") | yarn.lock |
| ether/etherpad-lite | 04c6c26690 | Apache 2.0 | pnpm-lock.yaml |
| outline/outline | 7a148b0353 | Business Source License 1.1 — not OSI | yarn.lock |
| calcom/cal.com | 4dfab874e0 | custom ("Portions … licensed as follows") | yarn.lock |
| nocodb/nocodb | 7e19067b84 | GNU AGPL v3 | pnpm-lock.yaml |
| langflow-ai/langflow | 312225bce9 | MIT | uv.lock, package-lock.json |
| open-webui/open-webui | 5043e7fc8c | custom BSD-style | uv.lock, package-lock.json |
| paperless-ngx/paperless-ngx | 495159f0b2 | GNU GPL v3 | uv.lock |
| getredash/redash | 9503cc9fb8 | BSD-style | poetry.lock, yarn.lock |
| PrefectHQ/prefect | 18000dd594 | Apache 2.0 | uv.lock |
| zulip/zulip | 7bce6361b3 | Apache 2.0 | uv.lock, pnpm-lock.yaml |
| mlflow/mlflow | 4f36b644a3 | Apache 2.0 | uv.lock |

Only dependency lockfiles and manifests were read; no source code is analysed or redistributed. Several projects are source-available rather than open-source; this study uses only the public lockfiles (package names and versions) and makes no use of their code. The hashes of every extracted file are in `data/processed/snapshot_file_manifest.json`, so the copies in `data/snapshots/` can be re-fetched and verified.

## 2. Labels
See protocol §6.2. L1 `kev_12m`, L2 `poc_12m`; candidate flags `cand_kev`, `cand_poc` define who can be a positive.

## 3. Data dictionary

### 3.1 `data/processed/population_cohorts.csv` (one row per CVE per cohort; 67,431 rows)
| Column | Type | Meaning |
|---|---|---|
| snapshot | date | Cohort date T (features as-of T) |
| window_end | date | End of the label window = min(T+12 months, 2026-10-08) |
| cve | str | CVE identifier (advisories without a CVE are excluded: cannot be linked to KEV/PoC/EPSS) |
| published | date | Earliest advisory publication date for this CVE |
| advisory_age_days | int | T − published |
| cvss_base | float | Highest base score among the CVE's advisories (v3.x preferred, else v4); missing for 6.7% |
| cvss_source | str | v3 or v4 |
| sev_rank | int | 0–4: none/low/moderate/high/critical (GitHub label) |
| AV, AC, PR, UI, SC, C, I, A | str | CVSS vector components (v4 VC/VI/VA mapped to C/I/A; SC = Scope, v3 only) |
| cwe_primary | str | First CWE id listed |
| n_advisories, n_affected_packages, n_ecosystems | int | Breadth of the advisory records |
| has_fix | bool | Any fixed-version event in the advisory |
| ecosystems, eco_* | str, 0/1 | Ecosystems affected |
| poc_count_at_T | int | Public GitHub PoC repositories created on or before T |
| epss_at_T, epss_pct_at_T | float | EPSS score/percentile at T from the matching dated snapshot |
| cand_kev, kev_12m, kev_date | 0/1, 0/1, date | KEV candidate flag, label, KEV date added (label support only; never a feature) |
| cand_poc, poc_12m, poc_first_date | 0/1, 0/1, date | PoC candidate flag, label, first PoC date (never a feature) |

### 3.2 `data/processed/project_findings_t0.csv` (one row per project × component × CVE/advisory at 2025-10-08; 374 rows)
| Column | Meaning |
|---|---|
| project, component (purl), name, version, ecosystem | Which dependency in which repository |
| ghsa_id, cve, finding_key | Advisory and CVE (finding_key = CVE else GHSA; 17 findings have no CVE) |
| is_direct | 1 if the component has no incoming edge in the lockfile graph (approximation) |
| depth | Shortest distance from a root in the dependency graph (NaN if unreachable from any root: 2.1%) |
| fan_in / fan_out | Number of direct dependants / dependencies |
| pagerank | PageRank (damping 0.85) on the dependency graph: high = widely depended upon |
| ancestors / descendants | Number of components that (transitively) depend on it / that it depends on |
| severity_label, cvss_base, cvss_source, cvss_v3_vector, cwe_ids | Advisory severity descriptors |
| published, advisory_age_days, has_fix | Advisory timing and fix flag |
| pkg_age_days, days_since_last_release, releases_prior_12m, n_releases_at_T | Package-health signals as-of T (immutable release dates) |
| installed_version_age_days, version_lag_days | Age of the installed version at T; days between installed and newest release at T (technical lag) |
| poc_count_at_T, epss_at_T, kev_at_T | Exploitation evidence as-of T |
| cand_kev, kev_12m, kev_date, cand_poc, poc_12m, poc_first_date | Candidate flags and labels (never features) |
| has_cve | 1 if the finding has a CVE |

### 3.3 Other tables
`advisories.csv` (35,568 advisories: parsed fields incl. computed CVSS), `advisory_affected.csv.gz` (66,201 package/range rows), `project_components_t0.csv` (all 23,827 components with graph features), `project_findings_raw_*.csv` (component × advisory matches before deduplication), and `data/sbom/*.cdx.json` (15 CycloneDX 1.7 SBOMs).

## 4. Environment record
The original SBOM-generation environment was Python 3.12.3 on Ubuntu with Syft 1.54.1. The current pipeline run uses Python 3.13.7 on Windows 11; Syft is not installed in this environment, which is recorded in `provenance_manifest.json`. That run resumes after SBOM generation and reuses the 15 existing SBOMs. Library versions are recorded in the provenance manifest. Random seeds are fixed (42).

## 5. What is not reproducible from this package alone
The raw clones (1.1 GB: advisory database, PoC index, treeless git clones) are not shipped; `scripts/fetch_raw_data.sh` re-creates them from the pinned commits. The advisory database and PoC index move forward daily, so re-fetching **must** use the pinned commit hashes.
