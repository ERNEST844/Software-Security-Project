"""Download the daily EPSS score file for each cohort date into data/raw/epss/ (run this on a machine with internet access).

After it succeeds, re-run:  05b_build_datasets.py -> 06_leakage_checks.py -> 07_baselines.py

What it does beyond a plain download:
  * tries the current host first (epss.empiricalsecurity.com), then the older one (epss.cyentia.com);
  * validates every file (gzip OK, '#model_version/score_date' header, columns cve/epss/percentile, >100k rows,
    scores in [0,1], score_date equals the requested date) so a bad or wrong-day file is never used silently;
  * records bytes, rows, SHA-256 and EPSS model version per file in data/raw/epss/epss_manifest.json and
    updates the EPSS entry of data/processed/provenance_manifest.json;
  * exits with a non-zero status if any cohort date is missing, so scripts cannot continue on partial data.

Options:  --force  re-download files that already exist     --check  only validate files already on disk
FIRST's page for the file format and model-version dates: https://www.first.org/epss/data_stats
"""
import gzip, hashlib, io, json, os, re, sys, time
import pandas as pd
import requests, yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOSTS = ["https://epss.empiricalsecurity.com/epss_scores-{d}.csv.gz", "https://epss.cyentia.com/epss_scores-{d}.csv.gz"]
OUT = f"{ROOT}/data/raw/epss"
MIN_ROWS = 100_000


def validate(raw_bytes, expected_date):
    """Return (info_dict, error_string). error_string is None when the file is acceptable."""
    try:
        text = gzip.decompress(raw_bytes).decode("utf-8")
    except Exception as e:
        return None, f"not a valid gzip/UTF-8 file ({e})"
    first = text.split("\n", 1)[0]
    info = {"model_version": None, "score_date": None}
    if first.startswith("#"):
        m = re.search(r"model_version:([^,\s]+)", first); info["model_version"] = m.group(1) if m else None
        m = re.search(r"score_date:(\d{4}-\d{2}-\d{2})", first); info["score_date"] = m.group(1) if m else None
    try:
        df = pd.read_csv(io.StringIO(text), comment="#")
    except Exception as e:
        return None, f"cannot parse as CSV ({e})"
    if list(df.columns[:3]) != ["cve", "epss", "percentile"]:
        return None, f"unexpected columns {list(df.columns)}"
    if len(df) < MIN_ROWS:
        return None, f"only {len(df)} rows (expected > {MIN_ROWS})"
    if not df.epss.between(0, 1).all() or not df.percentile.between(0, 1).all():
        return None, "scores outside [0,1]"
    if info["score_date"] and info["score_date"] != expected_date:
        return None, f"file says score_date {info['score_date']} but {expected_date} was requested"
    info.update(rows=int(len(df)), bytes=len(raw_bytes), sha256=hashlib.sha256(raw_bytes).hexdigest())
    return info, None


def download(d):
    last = "no host tried"
    for tmpl in HOSTS:
        url = tmpl.format(d=d)
        for attempt in range(3):
            try:
                r = requests.get(url, timeout=120, headers={"User-Agent": "supply-chain-study/1.0 (academic)"})
                if r.status_code == 200:
                    return r.content, url, None
                last = f"{url} -> HTTP {r.status_code}"
                if r.status_code == 404:
                    break  # this host does not have the file; try the next host
            except requests.RequestException as e:
                last = f"{url} -> {type(e).__name__}"
            time.sleep(2 * (attempt + 1))
    return None, None, last


def main(argv):
    force, check_only = "--force" in argv, "--check" in argv
    cfg = yaml.safe_load(open(f"{ROOT}/config/study.yaml"))
    dates = list(cfg["snapshots"]["cohort_dates"]); T0 = str(cfg["snapshots"].get("project_snapshot_date", ""))
    dates = [str(d) for d in dates] + ([T0] if T0 and T0 not in map(str, dates) else [])
    os.makedirs(OUT, exist_ok=True)
    manifest_path = f"{OUT}/epss_manifest.json"
    manifest = json.load(open(manifest_path)) if os.path.exists(manifest_path) else {}
    failed = []
    for d in dates:
        path = f"{OUT}/epss_scores-{d}.csv.gz"
        if os.path.exists(path) and not force:
            info, err = validate(open(path, "rb").read(), d)
            if err is None:
                manifest[d] = {**info, "source": manifest.get(d, {}).get("source", "existing file")}
                print(f"have  {d}  rows={info['rows']}  model={info['model_version']}"); continue
            print(f"BAD existing file for {d}: {err} -> re-downloading" if not check_only else f"BAD {d}: {err}")
        if check_only:
            failed.append(d); continue
        content, url, err = download(d)
        if content is None:
            print(f"FAILED {d}: {err}"); failed.append(d); continue
        info, err = validate(content, d)
        if err:
            print(f"REJECTED {d} from {url}: {err}"); failed.append(d); continue
        tmp = path + ".part"; open(tmp, "wb").write(content); os.replace(tmp, path)
        manifest[d] = {**info, "source": url}
        print(f"saved {d}  rows={info['rows']}  model={info['model_version']}  ({info['bytes']} bytes)")
    json.dump(manifest, open(manifest_path, "w"), indent=1, sort_keys=True)
    prov = f"{ROOT}/data/processed/provenance_manifest.json"
    if os.path.exists(prov):
        pm = json.load(open(prov))
        pm["sources"]["EPSS"] = {"url": "https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz (daily files; see data_stats on first.org/epss)",
                                 "status": "RETRIEVED" if not failed else f"INCOMPLETE - missing/invalid: {', '.join(failed)}",
                                 "files": {k: {x: v[x] for x in ("sha256", "rows", "model_version", "score_date")} for k, v in sorted(manifest.items())},
                                 "note": "EPSS model version differs by date; scores are a probability of exploitation in the 30 days after the score date."}
        json.dump(pm, open(prov, "w"), indent=1)
    if failed:
        print(f"\nINCOMPLETE: {len(failed)} date(s) missing or invalid: {failed}", file=sys.stderr)
        print("Check the file location on https://www.first.org/epss/data_stats , fix HOSTS above if it moved, and re-run.", file=sys.stderr)
        sys.exit(1)
    print(f"\nAll {len(dates)} EPSS files present and valid. Now run: python src/05b_build_datasets.py && python src/06_leakage_checks.py && python src/07_baselines.py")


if __name__ == "__main__":
    main(sys.argv[1:])
