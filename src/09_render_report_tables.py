"""Keeps docs/04_baseline_report.md in sync with results/*.csv so numbers are never copied by hand.

  python src/09_render_report_tables.py          rewrite the AUTO blocks in the report from the CSVs, then check the prose claims
  python src/09_render_report_tables.py --check  change nothing; exit 1 if the report is out of date or a quoted number no longer holds

Tables and status lines live between  <!-- AUTO:name --> ... <!-- /AUTO:name -->  markers and are regenerated.
Numbers quoted in the prose (section 5) are not generated; they are CHECKED against the CSVs below, so after any re-run
(for example once EPSS is joined) the script tells you exactly which sentence needs to be rewritten.
"""
import ast, csv, os, re, sys, yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = f"{ROOT}/docs/04_baseline_report.md"
cfg = yaml.safe_load(open(f"{ROOT}/config/study.yaml"))
TEST = str(cfg["snapshots"]["test_cohort"])
pop = list(csv.DictReader(open(f"{ROOT}/results/baseline_population_results.csv", newline="")))
prj = list(csv.DictReader(open(f"{ROOT}/results/baseline_project_results.csv", newline="")))
COHORTS = sorted({r["snapshot"] for r in pop})

HDR = ("| Cohort | Baseline | Positives | Prevalence % | ROC AUC (95% CI) | Avg precision | Recall top 1% | Recall top 5% (95% CI) | Recall top 10% |\n"
       "|---|---|---|---|---|---|---|---|---|")


def pop_table(label):
    lines = [HDR]
    for r in pop:
        if r["label"] != label: continue
        lines.append(f"| {r['snapshot']} | {r['baseline']} | {r['positives']} | {r['prevalence_pct']} | {r['roc_auc']} ({r['auc_ci95']}) | "
                     f"{r['avg_precision']} | {r['recall_top1pct']} | {r['recall_top5pct']} ({r['recall_top5_ci95']}) | {r['recall_top10pct']} |")
    return "\n".join(lines)


def proj_table():
    lines = ["| Label | Candidate findings | Positives | CVSS-only AUC | Recall top 10% | Recall top 20% |", "|---|---|---|---|---|---|"]
    for r in prj:
        lines.append(f"| {r['label']} | {r['findings']} | {r['positives']} | {r['cvss_only_auc']} | {r['recall_top10pct']} | {r['recall_top20pct']} |")
    return "\n".join(lines)


def proj_note():
    p = {r["label"]: r for r in prj}
    poc, kev = p["poc_12m"], p["kev_12m"]
    pocs = ", ".join(str(x) for x in ast.literal_eval(poc["positive_cvss_scores"]))
    kevs = ", ".join(str(x) for x in ast.literal_eval(kev["positive_cvss_scores"]))
    kev_txt = f"The single KEV-positive finding scored {kevs}" if int(kev["positives"]) == 1 else f"The {kev['positives']} KEV-positive findings scored {kevs}"
    return (f"CVSS scores of the {poc['positives']} PoC-positive findings: {pocs} (median of all candidate findings: {poc['median_cvss_all']}). "
            f"{kev_txt} (all-findings median {kev['median_cvss_all']}).")


def b2_status():
    have = sorted({r["snapshot"] for r in pop if r["baseline"].startswith("B2_epss")})
    if not have:
        return ("**B2 status: NOT RUN.** No EPSS files were present when `07_baselines.py` last ran. "
                "Run `src/fetch_epss.py`, then `05b`, `06`, `07`, then `src/09_render_report_tables.py`.")
    missing = [c for c in COHORTS if c not in have]
    s = f"**B2 status: RUN** for cohorts {', '.join(have)} (rows named `B2_epss_then_cvss` in the tables below)."
    return s + (f" Missing cohorts: {', '.join(missing)}." if missing else "")


def h1_line():
    if not any(r["baseline"].startswith("B2_epss") for r in pop):
        return "5. **H1 is only partially tested.** The exploit-evidence part (PoC) supports it for KEV; the EPSS part is pending the EPSS download."
    kev_b1 = get(TEST, "kev_12m", "B1_cvss_only")
    kev_b2 = get(TEST, "kev_12m", "B2_epss_then_cvss")
    poc_b1 = get(TEST, "poc_12m", "B1_cvss_only")
    poc_b2 = get(TEST, "poc_12m", "B2_epss_then_cvss")
    return (f"5. **H1 — EPSS results are mixed.** On the test cohort, KEV top-5% recall is {kev_b2['recall_top5pct']} with EPSS vs "
            f"{kev_b1['recall_top5pct']} for CVSS-only; PoC top-5% recall is {poc_b2['recall_top5pct']} vs "
            f"{poc_b1['recall_top5pct']}. A paired bootstrap comparison of B2 against B1 was not run, so these differences do not confirm H1.")


BLOCKS = {"B2STATUS": b2_status, "L1": lambda: pop_table("kev_12m"), "L2": lambda: pop_table("poc_12m"),
          "PROJ": proj_table, "PROJNOTE": proj_note, "H1": h1_line}


def render(text):
    def sub(m):
        name = m.group(1)
        if name not in BLOCKS: raise SystemExit(f"Unknown AUTO block '{name}' in the report")
        return f"<!-- AUTO:{name} -->\n{BLOCKS[name]()}\n<!-- /AUTO:{name} -->"
    out, n = re.subn(r"<!-- AUTO:(\w+) -->\n.*?\n<!-- /AUTO:\1 -->", sub, text, flags=re.S)
    missing = [k for k in BLOCKS if f"<!-- AUTO:{k} -->" not in out]
    if missing: raise SystemExit(f"Report is missing AUTO markers for: {missing}")
    return out


def get(snap, label, base):
    return next(r for r in pop if r["snapshot"] == snap and r["label"] == label and r["baseline"] == base)


def ci(s):
    lo, hi = s.split("-"); return float(lo), float(hi)


def claims(doc_text):
    out = []
    def claim(text, ok): out.append((text, bool(ok)))
    r = get(TEST, "poc_12m", "B1_cvss_only")
    claim("PoC test cohort: CVSS-only top-5% recall is about 11%", round(float(r["recall_top5pct"]) * 100) == 11)
    claim("PoC test cohort: average precision is about 1.8x prevalence", round(float(r["avg_precision"]) / (float(r["prevalence_pct"]) / 100), 1) == 1.8)
    r = get(TEST, "kev_12m", "B1_cvss_only")
    claim("KEV test cohort: CVSS-only AUC 0.79, top-5% recall 0.30, interval 0.09-0.53",
          f"{float(r['roc_auc']):.2f}" == "0.79" and f"{float(r['recall_top5pct']):.2f}" == "0.30" and r["recall_top5_ci95"] == "0.09-0.53")
    b = get(TEST, "kev_12m", "B2b_poc_then_cvss")
    claim("KEV test cohort: PoC-first rule AUC 0.83, top-5% recall 0.42, interval 0.12-0.71",
          f"{float(b['roc_auc']):.2f}" == "0.83" and f"{float(b['recall_top5pct']):.2f}" == "0.42" and b["recall_top5_ci95"] == "0.12-0.71")
    claim("PoC-first rule does not beat CVSS-only on top-5% recall in every cohort",
          not all(float(get(c, "kev_12m", "B2b_poc_then_cvss")["recall_top5pct"]) > float(get(c, "kev_12m", "B1_cvss_only")["recall_top5pct"]) for c in COHORTS))
    gains = {c: float(get(c, "kev_12m", "B2b_poc_then_cvss")["roc_auc"]) - float(get(c, "kev_12m", "B1_cvss_only")["roc_auc"]) for c in COHORTS}
    a, bb = ci(get(COHORTS[0], "kev_12m", "B1_cvss_only")["auc_ci95"]), ci(get(COHORTS[0], "kev_12m", "B2b_poc_then_cvss")["auc_ci95"])
    claim(f"First cohort has the smallest AUC gain and overlapping intervals ({COHORTS[0]})",
          gains[COHORTS[0]] == min(gains.values()) and max(a[0], bb[0]) <= min(a[1], bb[1]))
    kp = [int(get(c, "kev_12m", "B1_cvss_only")["positives"]) for c in COHORTS]
    pp = [int(get(c, "poc_12m", "B1_cvss_only")["positives"]) for c in COHORTS]
    claim("L1 has 4-11 positives per cohort", (min(kp), max(kp)) == (4, 11))
    claim("L2 has 41-181 positives per cohort", (min(pp), max(pp)) == (41, 181))
    p = {r["label"]: r for r in prj}
    claim("Project level: 1 KEV and 12 PoC positives", (int(p["kev_12m"]["positives"]), int(p["poc_12m"]["positives"])) == (1, 12))
    claim(f"Report names the configured test cohort ({TEST})", TEST in doc_text)
    return out


def main(argv):
    check = "--check" in argv
    old = open(DOC, encoding="utf-8").read()
    new = render(old)
    stale = new != old
    if stale and not check:
        open(DOC, "w", encoding="utf-8", newline="\n").write(new); print("Updated AUTO blocks in", os.path.relpath(DOC, ROOT))
    elif stale:
        print("OUT OF DATE: the report differs from results/*.csv. Run without --check to regenerate.")
    else:
        print("AUTO blocks already match results/*.csv")
    bad = 0
    for text, ok in claims(new):
        print(("PASS " if ok else "FAIL ") + text); bad += (not ok)
    if bad: print(f"\n{bad} quoted number(s) no longer match the results - rewrite those sentences in section 5.")
    sys.exit(1 if (bad or (stale and check)) else 0)


if __name__ == "__main__":
    main(sys.argv[1:])
