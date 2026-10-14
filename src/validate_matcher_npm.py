"""Independent validation of the advisory matcher against npm's own audit service (bulk advisories endpoint).
Compares GHSA sets per (package, version). Run with the 'now' scan (advisories as of today)."""
import pandas as pd, requests, random, json, os, concurrent.futures as cf, time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); random.seed(42)
comp = pd.read_csv(f"{ROOT}/data/processed/project_components_now.csv"); fnd = pd.read_csv(f"{ROOT}/data/processed/project_findings_raw_now.csv")
comp = comp[comp.ecosystem == "npm"].drop_duplicates(["name", "version"]); fnd = fnd[fnd.ecosystem == "npm"]
ours = fnd.groupby(["name", "version"]).ghsa_id.apply(set).to_dict()
flagged = [k for k in ours]; unflagged = [(r.name, r.version) for r in comp.itertuples() if (r.name, r.version) not in ours]
sample = random.sample(flagged, min(700, len(flagged))) + random.sample(unflagged, min(700, len(unflagged)))
def q(pair):
    n, v = pair
    for attempt in range(4):
        try:
            r = requests.post("https://registry.npmjs.org/-/npm/v1/security/advisories/bulk", json={n: [v]}, timeout=30)
            if r.status_code == 200:
                return pair, {a["url"].rstrip("/").split("/")[-1] for a in r.json().get(n, [])}
        except Exception: pass
        time.sleep(1.5 * (attempt + 1))
    return pair, None
with cf.ThreadPoolExecutor(12) as ex: res = list(ex.map(q, sample))
tp = fp = fn = failed = 0; fn_examples, fp_examples = [], []
for pair, theirs in res:
    if theirs is None: failed += 1; continue
    mine = ours.get(pair, set())
    tp += len(mine & theirs); fp += len(mine - theirs); fn += len(theirs - mine)
    if theirs - mine and len(fn_examples) < 8: fn_examples.append((pair, sorted(theirs - mine)[:3]))
    if mine - theirs and len(fp_examples) < 8: fp_examples.append((pair, sorted(mine - theirs)[:3]))
prec = tp / (tp + fp) if tp + fp else float("nan"); rec = tp / (tp + fn) if tp + fn else float("nan")
out = dict(pairs_sampled=len(sample), pairs_failed=failed, flagged_pairs_sampled=min(700, len(flagged)), random_unflagged_sampled=min(700, len(unflagged)),
           true_positive_pairs_ghsa=tp, only_in_ours=fp, only_in_npm=fn, precision_vs_npm=round(prec, 4), recall_vs_npm=round(rec, 4),
           fn_examples=fn_examples, fp_examples=fp_examples)
json.dump(out, open(f"{ROOT}/results/matcher_validation_npm.json", "w"), indent=1, default=list); print(json.dumps(out, indent=1, default=list))
