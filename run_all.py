"""Run the whole Project 6 pipeline in order, stop at the first failure, and record what happened.

  python run_all.py                    full run in this folder (re-uses data/raw if it is already there)
  python run_all.py --from 05b         resume from a step id            python run_all.py --only 07 09   run just these steps
  python run_all.py --skip-epss        do not fetch EPSS (baseline B2 is then skipped, as in the original build)
  python run_all.py --dry-run          print the plan and the preflight checks, run nothing
  python run_all.py --clean-room       copy code+config (NO data, NO results) to a temporary folder, run everything there from
                                       scratch, then compare the key outputs with this folder's results (the reproducibility test)
  python run_all.py --clean-room --keep   same, and keep the temporary folder for inspection

Notes
  * Step ids: fetch, 00, 01, 02, 03, 04, 04now, 05a, epss, 05b, 06, 07, 08, 09.
  * After step 06 the run is stopped unless results/leakage_checks.json says all_passed.
  * Every step runs with PYTHONUTF8=1 so files are read/written as UTF-8 on Windows too.
  * results/run_manifest.json records step timings, versions and SHA-256 of the key outputs.
  * In --clean-room mode EPSS is skipped unless you pass --epss, because the comparison is only like-for-like when the
    original folder was built with the same EPSS setting.
"""
import argparse, datetime as dt, hashlib, json, os, platform, shutil, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable
NOW_ASOF = "2026-10-13"   # date of the pinned advisory snapshot; the optional 'now' scan and package-health fetch use it
STEPS = [  # id, label, command (relative to project root), extra environment
    ("fetch", "pinned raw data (KEV, advisories, PoC index)", ["sh", "scripts/fetch_raw_data.sh"], {}),
    ("00", "discover repositories", [PY, "src/00_discover_repos.py"], {}),
    ("01", "select repositories and snapshot lockfiles", [PY, "src/01_select_and_snapshot.py"], {}),
    ("02", "generate SBOMs", [PY, "src/02_make_sboms.py"], {}),
    ("03", "build advisory tables", [PY, "src/03_build_advisory_tables.py"], {}),
    ("04", "match advisories + dependency graph (as-of project snapshot)", [PY, "src/04_match_and_graph.py"], {}),
    ("04now", "current-date scan (feeds package-health fetch)", [PY, "src/04_match_and_graph.py"], {"ASOF": NOW_ASOF, "TAG": "now"}),
    ("05a", "fetch registry metadata", [PY, "src/05a_fetch_registry_metadata.py"], {}),
    ("epss", "fetch EPSS daily scores", [PY, "src/fetch_epss.py"], {}),
    ("05b", "build datasets", [PY, "src/05b_build_datasets.py"], {}),
    ("06", "leakage checks (gate)", [PY, "src/06_leakage_checks.py"], {}),
    ("07", "baselines", [PY, "src/07_baselines.py"], {}),
    ("08", "provenance manifest + EDA", [PY, "src/08_provenance_and_eda.py"], {}),
    ("09", "sync report tables and check quoted numbers", [PY, "src/09_render_report_tables.py"], {}),
]
KEY_OUTPUTS = ["data/processed/population_cohorts.csv", "data/processed/project_findings_t0.csv",
               "results/baseline_population_results.csv", "results/baseline_project_results.csv", "results/leakage_checks.json"]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""): h.update(chunk)
    return h.hexdigest()


def find_sh():
    p = shutil.which("sh")
    if p: return p
    for c in (r"C:\Program Files\Git\bin\sh.exe", r"C:\Program Files\Git\usr\bin\sh.exe", r"C:\Program Files (x86)\Git\bin\sh.exe"):
        if os.path.exists(c): return c
    return None


def find_syft(root):
    return (os.environ.get("SYFT") or shutil.which("syft")
            or next((p for p in (f"{root}/tools/bin/syft", f"{root}/tools/bin/syft.exe") if os.path.exists(p)), None))


def preflight(root, steps):
    ok = True
    print(f"python {platform.python_version()} on {platform.system()}")
    if sys.version_info < (3, 9): print("  WARNING: Python 3.9+ recommended"); 
    for mod in ("pandas", "numpy", "scipy", "sklearn", "networkx", "yaml", "requests", "cvss", "semantic_version", "packaging"):
        try: __import__(mod)
        except ImportError: print(f"  MISSING python module: {mod}  ->  pip install -r requirements.txt"); ok = False
    for tool in ("git",) + (("sh",) if any(s[0] == "fetch" for s in steps) else ()):
        if (find_sh() if tool == "sh" else shutil.which(tool)) is None:
            print(f"  MISSING tool on PATH: {tool}" + ("  (on Windows use Git Bash, or install Git for Windows)" if tool == "sh" else "")); ok = False
    syft = find_syft(root)
    if any(s[0] == "02" for s in steps) and not syft:
        print("  MISSING syft (needed for step 02): install from https://github.com/anchore/syft or set env SYFT=/path/to/syft"); ok = False
    elif syft: print(f"  syft: {syft}")
    return ok


def run_steps(root, steps, log):
    env_base = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
    syft = find_syft(root)
    if syft: env_base["SYFT"] = syft   # src/02_make_sboms.py only looks at $SYFT or tools/bin/syft, not PATH
    results = []
    for sid, label, cmd, extra in steps:
        cmd = list(cmd)
        if cmd[0] == "sh": cmd[0] = find_sh()
        print(f"\n=== [{sid}] {label}", flush=True); log.write(f"\n=== [{sid}] {label}\n"); log.flush()
        t0 = time.time()
        p = subprocess.Popen(cmd, cwd=root, env={**env_base, **extra}, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
        for line in p.stdout:
            sys.stdout.write(line); log.write(line)
        rc = p.wait(); secs = round(time.time() - t0, 1)
        results.append({"step": sid, "label": label, "returncode": rc, "seconds": secs})
        log.write(f"--- [{sid}] exit {rc} in {secs}s\n"); log.flush()
        if rc != 0:
            print(f"\nSTOPPED: step [{sid}] failed with exit code {rc}. Fix it, then resume with:  python run_all.py --from {sid}")
            return results, False
        if sid == "02":   # the script prints FAILED and still exits 0 when Syft fails on a snapshot, so check the outputs
            import glob
            n_snap = len(glob.glob(f"{root}/data/snapshots/*")); n_sbom = len(glob.glob(f"{root}/data/sbom/*.cdx.json"))
            if n_snap == 0 or n_sbom != n_snap:
                print(f"\nSTOPPED: {n_snap} snapshot folders but {n_sbom} SBOM files - Syft failed on some snapshots (see output above)."); return results, False
            print(f"SBOM gate: {n_sbom}/{n_snap} snapshots have an SBOM")
        if sid == "06":
            chk = json.load(open(f"{root}/results/leakage_checks.json"))
            if not chk.get("all_passed"):
                bad = [c["check"] for c in chk["checks"] if not c["passed"]]
                print("\nSTOPPED: leakage checks did not all pass:", *bad, sep="\n  - "); return results, False
            print("leakage gate: ALL PASSED")
    return results, True


def write_manifest(root, results, ok, mode):
    keys = {k: sha256(f"{root}/{k}") for k in KEY_OUTPUTS if os.path.exists(f"{root}/{k}")}
    commit = None
    try: commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=HERE, capture_output=True, text=True).stdout.strip() or None
    except Exception: pass
    os.makedirs(f"{root}/results", exist_ok=True)
    m = {"finished_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "mode": mode, "success": ok, "python": platform.python_version(),
         "platform": platform.platform(), "project_git_commit": commit, "steps": results, "key_output_sha256": keys}
    json.dump(m, open(f"{root}/results/run_manifest.json", "w"), indent=1)
    return m


def compare(a_root, b_root):
    import pandas as pd
    print("\n=== Reproducibility comparison (original folder vs clean-room run)")
    same_all = True
    for k in KEY_OUTPUTS:
        pa, pb = f"{a_root}/{k}", f"{b_root}/{k}"
        if not (os.path.exists(pa) and os.path.exists(pb)):
            print(f"  ?? {k}: missing in {'original' if not os.path.exists(pa) else 'clean-room'} folder"); same_all = False; continue
        if sha256(pa) == sha256(pb): print(f"  IDENTICAL  {k}"); continue
        same_all = False; print(f"  DIFFERENT  {k}")
        if k.endswith(".csv"):
            A, B = pd.read_csv(pa), pd.read_csv(pb)
            print(f"      rows {len(A)} vs {len(B)}; columns only in original: {sorted(set(A.columns) - set(B.columns))}; only in clean-room: {sorted(set(B.columns) - set(A.columns))}")
            if A.shape == B.shape and list(A.columns) == list(B.columns):
                num = A.select_dtypes("number").columns
                diff = ((A[num].fillna(-9e9) - B[num].fillna(-9e9)).abs() > 1e-9).sum()
                print("      numeric cells that differ per column:", {c: int(v) for c, v in diff.items() if v})
    print("\nRESULT:", "the clean-room run reproduces the original key outputs exactly." if same_all else "outputs differ - see above (small differences can come from registry metadata that changed since the original run).")
    return same_all


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--from", dest="from_step"); ap.add_argument("--only", nargs="+"); ap.add_argument("--skip-epss", action="store_true")
    ap.add_argument("--skip-now", action="store_true"); ap.add_argument("--epss", action="store_true", help="with --clean-room: include EPSS")
    ap.add_argument("--dry-run", action="store_true"); ap.add_argument("--clean-room", action="store_true"); ap.add_argument("--keep", action="store_true")
    a = ap.parse_args()
    steps = list(STEPS)
    if a.clean_room and not a.epss: a.skip_epss = True
    if a.skip_epss: steps = [s for s in steps if s[0] != "epss"]
    if a.skip_now: steps = [s for s in steps if s[0] != "04now"]
    ids = [s[0] for s in steps]
    if a.only:
        bad = [x for x in a.only if x not in ids]
        if bad: sys.exit(f"Unknown/disabled step id(s): {bad}. Available: {ids}")
        steps = [s for s in steps if s[0] in a.only]
    elif a.from_step:
        if a.from_step not in ids: sys.exit(f"Unknown/disabled step id '{a.from_step}'. Available: {ids}")
        steps = steps[ids.index(a.from_step):]
    root, tmp = HERE, None
    if a.clean_room:
        tmp = tempfile.mkdtemp(prefix="p6_cleanroom_"); root = tmp
        for d in ("src", "scripts", "config", "docs"): shutil.copytree(f"{HERE}/{d}", f"{tmp}/{d}", ignore=shutil.ignore_patterns("__pycache__"))
        for f in ("requirements.txt", "run_all.py"): shutil.copy(f"{HERE}/{f}", tmp)
        if os.path.isdir(f"{HERE}/tools"): shutil.copytree(f"{HERE}/tools", f"{tmp}/tools")
        if os.path.isdir(f"{HERE}/data/own"): shutil.copytree(f"{HERE}/data/own", f"{tmp}/data/own")  # the study's own-project inputs are not downloadable
        for d in ("data/raw", "data/processed", "data/snapshots", "data/sbom", "data/sbom_own", "results"): os.makedirs(f"{tmp}/{d}", exist_ok=True)
        print(f"clean-room folder: {tmp}  (no data/raw, no processed data, no results copied)")
    print("plan:", " -> ".join(s[0] for s in steps))
    ok_pre = preflight(root, steps)
    if a.dry_run: print("\n(dry run) preflight", "OK" if ok_pre else "has problems"); return
    if not ok_pre: sys.exit("Preflight failed - fix the items above, then re-run.")
    os.makedirs(f"{root}/results", exist_ok=True)
    with open(f"{root}/results/run_all.log", "a", encoding="utf-8") as log:
        log.write(f"\n##### run started {dt.datetime.now().isoformat(timespec='seconds')} steps={[s[0] for s in steps]}\n")
        results, ok = run_steps(root, steps, log)
    m = write_manifest(root, results, ok, "clean-room" if a.clean_room else "in-place")
    print(f"\n{'ALL STEPS OK' if ok else 'RUN FAILED'}  (manifest: results/run_manifest.json; log: results/run_all.log)")
    if ok and a.clean_room: compare(HERE, root)
    if tmp and not a.keep and ok: shutil.rmtree(tmp, ignore_errors=True)
    elif tmp: print("clean-room folder kept at", tmp)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
