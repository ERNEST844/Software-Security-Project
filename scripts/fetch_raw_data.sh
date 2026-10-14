#!/usr/bin/env sh
# Re-creates data/raw from PINNED sources. Run from the project root (Linux/macOS/WSL/Git Bash).
set -e
mkdir -p data/raw && cd data/raw
curl -sSfL https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json -o kev.json
echo "KEV used in this study: catalogVersion 2026.10.08 (see data/processed/provenance_manifest.json for its SHA-256)."
echo "NOTE: the mirror serves the LATEST catalogue. If its version differs, results will differ slightly; KEV entries carry dateAdded, so old cohorts are unaffected but the 2025 window may gain positives."
git clone --filter=blob:none --sparse https://github.com/github/advisory-database.git ghsa
(cd ghsa && git checkout 36d4c87ce64759f762f4e3e0d65137da687b8272 && git sparse-checkout set advisories/github-reviewed)
git clone https://github.com/nomi-sec/PoC-in-GitHub.git poc
(cd poc && git checkout 7bf2d8795e2ddf4e1669efe296f9eeabe6091ca8)
echo "Raw data ready. Next: python src/00_discover_repos.py ..."
