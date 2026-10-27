# Project 6 — Intelligent Software Supply-Chain Security (Activities 1–4)

UTAMU S26.CSC 7203 Security of Software. Goal: rank vulnerable third-party dependencies by likely future exploitation and compare transparent baselines with learned rankers, under a time-aware, leakage-checked design.

**Status:** Activities 1–4 complete. EPSS data not yet joined (see below). Activities 5–8 (models, hybrid engine, evaluation, prototype/paper) not started.

## Read first
1. `docs/01_research_protocol.md` and `docs/01_literature_matrix.csv` — Activity 1
2. `docs/02_data_provenance_and_dictionary.md` — Activity 2
3. `docs/03_preprocessing_features_eda_report.md` — Activity 3
4. `docs/04_baseline_report.md` — Activity 4

## Deliverables
- `deliverables/reports/` — Word reports and an alternate baseline report copy
- `deliverables/presentation/` — presentation and speech script
- `deliverables/references/` — spreadsheet and CSV literature matrices
- `deliverables/archive/` — original ZIP archive

## Reproduce
```
pip install -r requirements.txt
# Syft: https://github.com/anchore/syft (Linux/WSL: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b tools/bin ; or set env SYFT=/path/to/syft)
sh scripts/fetch_raw_data.sh              # pinned advisory DB + PoC index + KEV
python src/00_discover_repos.py           # treeless clones, no source downloaded
python src/01_select_and_snapshot.py
python src/02_make_sboms.py
python src/03_build_advisory_tables.py
python src/04_match_and_graph.py          # as-of 2025-10-08
ASOF=2026-10-13 TAG=now python src/04_match_and_graph.py   # optional: current-date scan (also feeds package-health fetch)
python src/05a_fetch_registry_metadata.py
python src/05b_build_datasets.py
python src/06_leakage_checks.py           # must say ALL PASSED
python src/07_baselines.py
python src/08_provenance_and_eda.py
```
## Do this next on your own machine (EPSS)
The EPSS host was unreachable from the environment that built this package.
```
python src/fetch_epss.py        # check the URL at https://www.first.org/epss/data_stats first
python src/05b_build_datasets.py && python src/06_leakage_checks.py && python src/07_baselines.py
```
`07_baselines.py` then adds baseline B2 (EPSS) automatically.

## Honest status notes
- The result tables in `results/` are written by the code in `src/`. Numbers quoted in the `docs/` were copied from those files by hand, so re-check them if you re-run with different data.
- The scripts were run step by step in the build environment; a single clean end-to-end re-run from an empty folder has not been done yet.
- 3 of the 20 references are marked "not verified / partially verified" in the matrix — re-check them before citing.
- `data/raw` (1.1 GB) is not shipped; the script re-creates it from pinned commits.
"# Software-Security-Project" 
"# Software-Security-Project" 
