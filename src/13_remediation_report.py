"""Activity 8 - static HTML view of the remediation plan (no extra dependencies).

  python src/13_remediation_report.py
  python src/13_remediation_report.py --top 50 --out results/remediation_report.html

Open the HTML file in a browser to review ranked findings, tiers, actions and reasons.
"""
import argparse, html, os
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLAN = f"{ROOT}/results/remediation_plan.csv"
DEFAULT_OUT = f"{ROOT}/results/remediation_report.html"
COLS = ["rank", "project", "name", "version", "ecosystem", "cve", "cvss_base", "tier", "action", "risk_score", "exploit_pct", "reasons"]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--top", type=int, default=100, help="rows to include (sorted by rank)")
    ap.add_argument("--out", default=DEFAULT_OUT)
    a = ap.parse_args()
    if not os.path.exists(PLAN):
        raise SystemExit(f"Missing {PLAN}. Run: python src/11_hybrid_engine.py")
    df = pd.read_csv(PLAN).head(a.top)
    rows = []
    for _, r in df.iterrows():
        cells = "".join(f"<td>{html.escape(str(r[c])) if pd.notna(r.get(c)) else ''}</td>" for c in COLS if c in df.columns)
        rows.append(f"<tr>{cells}</tr>")
    head = "".join(f"<th>{html.escape(c)}</th>" for c in COLS if c in df.columns)
    body = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Project 6 remediation plan</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 1.5rem; }}
h1 {{ font-size: 1.25rem; }}
table {{ border-collapse: collapse; width: 100%; font-size: 0.85rem; }}
th, td {{ border: 1px solid #ccc; padding: 0.35rem 0.5rem; text-align: left; vertical-align: top; }}
th {{ background: #f0f0f0; position: sticky; top: 0; }}
tr:nth-child(even) {{ background: #fafafa; }}
.tier-P1 {{ font-weight: 600; }}
</style></head><body>
<h1>Dependency remediation priority (top {len(df)} findings)</h1>
<p>Generated from <code>results/remediation_plan.csv</code>. Actions: upgrade, replace, isolate, monitor, accept.</p>
<table><thead><tr>{head}</tr></thead><tbody>
{"".join(rows)}
</tbody></table></body></html>"""
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    open(a.out, "w", encoding="utf-8").write(body)
    print(f"Wrote {a.out} ({len(df)} rows)")


if __name__ == "__main__":
    main()
