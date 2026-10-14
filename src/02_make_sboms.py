"""Generate CycloneDX SBOMs with Syft for every snapshot directory (and optional extra dirs)."""
import subprocess, os, json, glob, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYFT = os.environ.get("SYFT", f"{ROOT}/tools/bin/syft"); env = {**os.environ, "SYFT_CHECK_FOR_APP_UPDATE": "false"}
os.makedirs(f"{ROOT}/data/sbom", exist_ok=True)
for d in sorted(glob.glob(f"{ROOT}/data/snapshots/*")):
    name = os.path.basename(d); out = f"{ROOT}/data/sbom/{name}.cdx.json"
    r = subprocess.run([SYFT, f"dir:{d}", "-o", f"cyclonedx-json={out}", "-q"], capture_output=True, text=True, env=env, timeout=1800)
    if r.returncode: print(name, "FAILED", r.stderr[-300:]); continue
    j = json.load(open(out)); comps = j.get("components", []); deps = j.get("dependencies", [])
    print(f"{name:40} components={len(comps):5} dependency_records={len(deps):5} edges={sum(len(x.get('dependsOn', [])) for x in deps):6}")
