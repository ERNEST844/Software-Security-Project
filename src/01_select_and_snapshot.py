"""Select repositories by the pre-declared criteria and extract ONLY lockfiles/manifests at the snapshot commit."""
import subprocess, json, os, yaml, hashlib, datetime as dt
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
cfg = yaml.safe_load(open(f"{ROOT}/config/study.yaml"))
SNAP = cfg["snapshots"]["project_snapshot_date"]; N = cfg["selection_n_per_ecosystem"]
CLONES = f"{ROOT}/data/raw/clones"
LOCKS = {"npm": ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"], "pypi": ["uv.lock", "poetry.lock"]}
MANIFESTS = ["package.json", "pyproject.toml"]
sh = lambda cmd, cwd=None: subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=1200)

cands = [l.strip().split("|") for l in open(f"{ROOT}/config/candidates.txt") if l.strip() and not l.startswith("#")]
selected, report = {"npm": [], "pypi": []}, []
for eco, repo in cands:
    path = f"{CLONES}/{repo.replace('/', '__')}"
    row = {"primary_ecosystem": eco, "repo": repo}
    if not os.path.isdir(path): row["decision"] = "excluded: clone failed"; report.append(row); continue
    c = sh(["git", "rev-list", "-1", f"--before={SNAP}T23:59:59Z", "HEAD"], path).stdout.strip()
    root_files = sh(["git", "ls-tree", "--name-only", c], path).stdout.split("\n")
    since = dt.date.fromisoformat(SNAP).replace(year=dt.date.fromisoformat(SNAP).year - 1).isoformat()
    active = int(sh(["git", "rev-list", "--count", f"--since={since}", c], path).stdout.strip() or 0)
    locks = {e: [f for f in root_files if f in L] for e, L in LOCKS.items()}
    row.update(commit=c, commit_date=sh(["git", "show", "-s", "--format=%cI", c], path).stdout.strip(),
               commits_prior_12m=active, root_lockfiles=locks)
    if not locks[eco]: row["decision"] = f"excluded: no root-level {eco} lockfile"
    elif active < 1: row["decision"] = "excluded: inactive"
    elif len(selected[eco]) >= N: row["decision"] = "not needed: quota filled"
    else: row["decision"] = "SELECTED"; selected[eco].append(row)
    report.append(row)

chosen = {r["repo"]: r for L in selected.values() for r in L}
os.makedirs(f"{ROOT}/data/snapshots", exist_ok=True); manifest = []
for repo, r in chosen.items():
    path = f"{CLONES}/{repo.replace('/', '__')}"; out = f"{ROOT}/data/snapshots/{repo.replace('/', '__')}"; os.makedirs(out, exist_ok=True)
    files = [f for L in r["root_lockfiles"].values() for f in L] + [m for m in MANIFESTS if m in sh(["git", "ls-tree", "--name-only", r["commit"]], path).stdout.split("\n")]
    for f in files:
        data = subprocess.run(["git", "show", f"{r['commit']}:{f}"], cwd=path, capture_output=True, timeout=1200).stdout
        open(f"{out}/{f}", "wb").write(data)
        manifest.append({"repo": repo, "commit": r["commit"], "commit_date": r["commit_date"], "file": f, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
json.dump(report, open(f"{ROOT}/data/processed/repo_selection_report.json", "w"), indent=1)
json.dump(manifest, open(f"{ROOT}/data/processed/snapshot_file_manifest.json", "w"), indent=1)
for r in report: print(f"{r['primary_ecosystem']:5} {r['repo']:38} {r['decision']}")
print(len(chosen), "repos;", len(manifest), "files extracted")
