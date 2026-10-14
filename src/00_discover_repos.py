"""Discover which candidate repositories satisfy the selection criteria at the snapshot date.
Uses treeless clones (commits only) so no source code is downloaded - only lockfile blobs later."""
import subprocess, sys, json, os, yaml, concurrent.futures as cf, datetime as dt
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
cfg = yaml.safe_load(open(f"{ROOT}/config/study.yaml"))
SNAP = cfg["snapshots"]["project_snapshot_date"]
LOCKS = {"npm": ["package-lock.json"], "pypi": ["poetry.lock", "uv.lock"]}
CLONES = f"{ROOT}/data/raw/clones"; os.makedirs(CLONES, exist_ok=True)

def sh(cmd, cwd=None, timeout=900):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)

def probe(eco, repo):
    name = repo.replace("/", "__"); path = f"{CLONES}/{name}"
    out = {"ecosystem": eco, "repo": repo, "status": "ok"}
    try:
        if not os.path.isdir(path):
            r = sh(["git", "clone", "--filter=tree:0", "--no-checkout", f"https://github.com/{repo}.git", path])
            if r.returncode: return {**out, "status": "clone_failed", "detail": r.stderr[-200:]}
        c = sh(["git", "rev-list", "-1", f"--before={SNAP}T23:59:59Z", "HEAD"], cwd=path).stdout.strip()
        if not c: return {**out, "status": "no_commit_before_snapshot"}
        out["commit"] = c
        out["commit_date"] = sh(["git", "show", "-s", "--format=%cI", c], cwd=path).stdout.strip()
        since = (dt.date.fromisoformat(SNAP).replace(year=dt.date.fromisoformat(SNAP).year - 1)).isoformat()
        out["commits_prior_12m"] = int(sh(["git", "rev-list", "--count", f"--since={since}", c], cwd=path).stdout.strip() or 0)
        files = sh(["git", "ls-tree", "-r", "--name-only", c], cwd=path, timeout=1200).stdout.split("\n")
        want = LOCKS[eco]
        found = [f for f in files if os.path.basename(f) in want and "node_modules" not in f and "/test" not in f.lower() and "fixture" not in f.lower() and "example" not in f.lower()]
        out["lockfiles"] = found[:10]
        out["has_license_file"] = any(os.path.basename(f).upper().startswith(("LICENSE", "COPYING")) for f in files if "/" not in f)
        if not found: out["status"] = "no_supported_lockfile"
        elif out["commits_prior_12m"] < 1: out["status"] = "inactive"
    except Exception as e:
        out["status"] = "error"; out["detail"] = str(e)[:200]
    return out

if __name__ == "__main__":
    cands = [l.strip().split("|") for l in open(f"{ROOT}/config/candidates.txt") if l.strip() and not l.startswith("#")]
    with cf.ThreadPoolExecutor(6) as ex:
        res = list(ex.map(lambda x: probe(*x), cands))
    json.dump(res, open(f"{ROOT}/data/processed/repo_discovery.json", "w"), indent=1)
    for r in res: print(r["ecosystem"], r["repo"], r["status"], r.get("commit", "")[:8], r.get("lockfiles", [])[:2])
