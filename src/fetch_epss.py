"""RUN THIS ON YOUR OWN MACHINE (the sandbox used to build this project cannot reach the EPSS host).
Downloads the daily EPSS score file for each cohort date into data/raw/epss/, then re-run 05b, 06 and 07.
Check the current download location at https://www.first.org/epss/data_stats before running; adjust BASE if it has moved."""
import requests, os, yaml, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = "https://epss.empiricalsecurity.com/epss_scores-{d}.csv.gz"
cfg = yaml.safe_load(open(f"{ROOT}/config/study.yaml")); os.makedirs(f"{ROOT}/data/raw/epss", exist_ok=True)
for d in cfg["snapshots"]["cohort_dates"]:
    out = f"{ROOT}/data/raw/epss/epss_scores-{d}.csv.gz"
    if os.path.exists(out): print("have", d); continue
    r = requests.get(BASE.format(d=d), timeout=120)
    if r.status_code != 200: print("FAILED", d, r.status_code, "- check the URL on first.org/epss/data_stats"); continue
    open(out, "wb").write(r.content); print("saved", out, len(r.content), "bytes")
