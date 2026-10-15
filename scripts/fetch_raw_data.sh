#!/usr/bin/env sh
# Re-creates data/raw from PINNED sources. Run from the project root (Linux/macOS/WSL/Git Bash).
# Every source is pinned to an exact commit, and KEV is additionally verified against the SHA-256
# recorded in data/processed/provenance_manifest.json, so a re-run reproduces the same inputs.
set -e

KEV_COMMIT=be330da604b41a3b29c84b3f0a0122d6d2167417      # cisagov/kev-data, catalogVersion 2026.10.08, 1739 entries
KEV_SHA256=fb1621beec7db19d99c1f919dede3d4cc01ad88acd16f79f1592929c4826dfee
GHSA_COMMIT=36d4c87ce64759f762f4e3e0d65137da687b8272     # github/advisory-database
POC_COMMIT=7bf2d8795e2ddf4e1669efe296f9eeabe6091ca8      # nomi-sec/PoC-in-GitHub

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

mkdir -p data/raw && cd data/raw

# --- CISA KEV (pinned by commit, then checksum-verified) ---
curl -sSfL "https://raw.githubusercontent.com/cisagov/kev-data/${KEV_COMMIT}/known_exploited_vulnerabilities.json" -o kev.json
GOT=$(sha256_of kev.json)
if [ "$GOT" != "$KEV_SHA256" ]; then
  echo "ERROR: kev.json checksum mismatch." >&2
  echo "  expected $KEV_SHA256" >&2
  echo "  got      $GOT" >&2
  exit 1
fi
echo "KEV OK: catalogVersion 2026.10.08, sha256 verified."

# --- GitHub Advisory Database (pinned commit) ---
if [ ! -d ghsa ]; then
  git clone --filter=blob:none --sparse https://github.com/github/advisory-database.git ghsa
fi
(cd ghsa && git checkout "$GHSA_COMMIT" && git sparse-checkout set advisories/github-reviewed)
[ "$(cd ghsa && git rev-parse HEAD)" = "$GHSA_COMMIT" ] || { echo "ERROR: ghsa is not at the pinned commit" >&2; exit 1; }

# --- PoC-in-GitHub index (pinned commit) ---
if [ ! -d poc ]; then
  git clone https://github.com/nomi-sec/PoC-in-GitHub.git poc
fi
(cd poc && git checkout "$POC_COMMIT")
[ "$(cd poc && git rev-parse HEAD)" = "$POC_COMMIT" ] || { echo "ERROR: poc is not at the pinned commit" >&2; exit 1; }

echo "Raw data ready (all sources at pinned versions). Next: python src/00_discover_repos.py ..."
echo "EPSS is separate: run  python src/fetch_epss.py  (it could not be fetched from the build environment)."
