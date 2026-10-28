"""Shared helpers for Activities 5-8. No file I/O here, so the unit tests can import this module on its own."""
import math
import numpy as np, pandas as pd
from scipy.stats import rankdata
from sklearn.metrics import average_precision_score

SEED = 42
LABELS = {"kev": ("cand_kev", "kev_12m"), "poc": ("cand_poc", "poc_12m")}
CAT = ["AV", "AC", "PR", "UI", "SC", "C", "I", "A", "cwe_primary"]
ECO = ["eco_npm", "eco_PyPI", "eco_Maven", "eco_Packagist", "eco_Go", "eco_NuGet", "eco_RubyGems", "eco_crates.io"]
NUM = ["cvss_base", "sev_rank", "advisory_age_days", "n_advisories", "n_affected_packages", "n_ecosystems", "has_fix", "poc_count_at_T"] + ECO
OPT = ["epss_at_T", "epss_pct_at_T"]          # only used when the EPSS files have been downloaded (step epss, then 05b)
# columns that describe the outcome, the future, or an identifier: never allowed to be a model input
FORBIDDEN = {"kev_12m", "poc_12m", "kev_date", "poc_first_date", "window_end", "cand_kev", "cand_poc", "snapshot", "cve", "published", "ecosystems", "cvss_source"}
W = {"exploit": 0.60, "exposure": 0.25, "health": 0.15}   # hybrid project risk weights (policy, fixed in advance, see docs/06)
TIER_CUTS = (0.70, 0.50, 0.30)                              # risk >= 0.70 -> P1, >= 0.50 -> P2, >= 0.30 -> P3, else P4
ACTIONS = ["upgrade", "replace", "isolate", "monitor", "accept"]


# ---------- ranking metrics (ties handled by expectation under uniform random tie-breaking) ----------
def recall_at(y, s, frac):
    n = len(y); k = math.ceil(frac * n); P = y.sum()
    if P == 0: return np.nan
    df = pd.DataFrame({"y": y, "s": s}).groupby("s").y.agg(["sum", "count"]).sort_index(ascending=False)
    got, left = 0.0, k
    for _, r in df.iterrows():
        if left <= 0: break
        take = min(left, r["count"]); got += r["sum"] * take / r["count"]; left -= take
    return got / P


def auc(y, s):
    r = rankdata(s); P = y.sum(); N = len(y) - P
    return (r[y == 1].sum() - P * (P + 1) / 2) / (P * N) if P and N else np.nan


def boot(y, s, fn, B=500, seed=SEED):
    rng = np.random.default_rng(seed); idx = np.arange(len(y)); v = []
    for _ in range(B):
        b = rng.choice(idx, len(idx))
        if y[b].sum() == 0: continue
        v.append(fn(y[b], s[b]))
    return (np.nanpercentile(v, 2.5), np.nanpercentile(v, 97.5)) if v else (np.nan, np.nan)


def paired_boot_diff(y, s1, s2, fn, B=1000, seed=SEED):
    """95% interval of fn(y,s1) - fn(y,s2) on the SAME resampled rows (paired bootstrap). Interval above 0 means s1 is better."""
    rng = np.random.default_rng(seed); idx = np.arange(len(y)); v = []
    for _ in range(B):
        b = rng.choice(idx, len(idx))
        if y[b].sum() == 0: continue
        v.append(fn(y[b], s1[b]) - fn(y[b], s2[b]))
    return (float(np.nanpercentile(v, 2.5)), float(np.nanpercentile(v, 97.5))) if v else (np.nan, np.nan)


def metrics(y, s):
    lo, hi = boot(y, s, auc); rlo, rhi = boot(y, s, lambda a, b: recall_at(a, b, 0.05))
    return dict(positives=int(y.sum()), prevalence_pct=round(100 * y.mean(), 3), roc_auc=round(auc(y, s), 3), auc_ci95=f"{lo:.2f}-{hi:.2f}",
                avg_precision=round(average_precision_score(y, s), 4), recall_top1pct=round(recall_at(y, s, .01), 3),
                recall_top5pct=round(recall_at(y, s, .05), 3), recall_top5_ci95=f"{rlo:.2f}-{rhi:.2f}", recall_top10pct=round(recall_at(y, s, .10), 3))


def confusion_at(y, s, frac):
    """Expected confusion counts when the top `frac` of the list is flagged (ties by expectation)."""
    n = len(y); P = int(y.sum()); k = math.ceil(frac * n); tp = recall_at(y, s, frac) * P
    return dict(flagged=k, tp=round(tp, 1), fp=round(k - tp, 1), fn=round(P - tp, 1), tn=round(n - P - (k - tp), 1),
                precision=round(tp / k, 4), recall=round(tp / P, 3) if P else np.nan, false_positive_rate=round((k - tp) / (n - P), 4))


def ece(y, p, bins=10):
    """Expected calibration error with equal-frequency bins (probabilities here are tiny, so equal-width bins would be useless)."""
    y = np.asarray(y, float); p = np.asarray(p, float); order = np.argsort(p, kind="stable"); rows = []; tot = 0.0
    for i, idx in enumerate(np.array_split(order, bins)):
        if len(idx) == 0: continue
        pm, ym = p[idx].mean(), y[idx].mean(); tot += len(idx) / len(y) * abs(pm - ym)
        rows.append(dict(bin=i + 1, n=len(idx), mean_predicted=pm, observed_rate=ym))
    return tot, pd.DataFrame(rows)


def logit(p):
    p = np.clip(np.asarray(p, float), 1e-6, 1 - 1e-6); return np.log(p / (1 - p))


def pct_rank(x):
    """Percentile in (0,1]; 1 = highest value."""
    x = np.asarray(x, float); return rankdata(x, method="average") / len(x)


# ---------- model inputs ----------
def prepare(df):
    X = df[NUM + OPT].copy(); X["has_fix"] = df["has_fix"].astype(float)
    for c in CAT: X[c] = df[c].fillna("NA").astype(str)
    return X


# ---------- transparent rule score and hybrid fusion ----------
def rule_score(df):
    """CVSS + exploit-evidence rule: severity (0-1) + 1 if a public PoC existed at T + EPSS (0-1) when available."""
    s = df["cvss_base"].fillna(0).values / 10.0 + (df["poc_count_at_T"].fillna(0).values > 0) * 1.0
    if "epss_at_T" in df and df["epss_at_T"].notna().any(): s = s + df["epss_at_T"].fillna(0).values
    return s


def fuse(model_p, rule_s, a):
    """Hybrid exploitation score: a * percentile(model) + (1 - a) * percentile(rule). a=1 model only, a=0 rule only."""
    return a * pct_rank(model_p) + (1 - a) * pct_rank(rule_s)


def gate_fuse(model_p, poc_count):
    """Rule-gated model: anything with public exploit code at T goes above everything else; the model orders items within each group."""
    return (np.asarray(poc_count, float) > 0) * 1.0 + pct_rank(model_p)


# ---------- project-level engine (graph exposure, package health, remediation decision) ----------
def graph_exposure(df):
    """Transparent graph score 0-1: PageRank, number of packages that depend on it (blast radius), direct-or-not, fan-in."""
    return (0.35 * pct_rank(df["pagerank"].fillna(0)) + 0.25 * pct_rank(df["descendants"].fillna(0))
            + 0.20 * df["is_direct"].fillna(0).astype(float).values + 0.20 * pct_rank(df["fan_in"].fillna(0)))


def health(df):
    """Package-health penalty 0-1 and an 'abandoned' flag (no release for 2 years, or none in the 12 months before T)."""
    abandoned = ((df["days_since_last_release"].fillna(0) > 730) | (df["releases_prior_12m"].fillna(1) == 0)).values
    return 0.6 * abandoned + 0.4 * pct_rank(df["version_lag_days"].fillna(0)), abandoned


def tier_of(risk):
    return "P1" if risk >= TIER_CUTS[0] else "P2" if risk >= TIER_CUTS[1] else "P3" if risk >= TIER_CUTS[2] else "P4"


def decide(tier, has_fix, abandoned, is_direct):
    """Remediation decision. Five outcomes: upgrade, replace, isolate, monitor, accept."""
    if tier == "P4": return "monitor" if (is_direct or abandoned) else "accept"
    if has_fix: return "upgrade"
    if abandoned: return "replace"
    return "isolate" if tier in ("P1", "P2") else "monitor"


def build_plan(df, exploit_pct):
    """df = project findings (one row per component x advisory); exploit_pct = predicted-exploitation percentile for each row."""
    df = df.reset_index(drop=True); exposure = graph_exposure(df); hp, abandoned = health(df); exploit_pct = np.asarray(exploit_pct, float)
    kev_override = df.get("kev_at_T", pd.Series(0, index=df.index)).fillna(0).astype(bool).values
    risk = W["exploit"] * exploit_pct + W["exposure"] * exposure + W["health"] * hp
    out = df.copy(); out["exploit_pct"] = exploit_pct; out["exposure"] = exposure; out["health_penalty"] = hp; out["abandoned"] = abandoned; out["risk_score"] = risk
    out["kev_override"] = kev_override
    out["tier"] = ["P1" if override else tier_of(r) for r, override in zip(risk, kev_override)]
    out["action"] = [decide(t, bool(f), bool(a), bool(d)) for t, f, a, d in zip(out.tier, out.has_fix, out.abandoned, out.is_direct.fillna(0))]
    dpct = pct_rank(df["descendants"].fillna(0)); reasons = []
    for i, r in df.iterrows():
        w = []
        if kev_override[i]: w.append("already listed in CISA KEV at snapshot")
        if exploit_pct[i] >= 0.90: w.append("top 10% predicted exploitation")
        if (r.get("poc_count_at_T") or 0) > 0: w.append("public exploit code exists")
        if (r.get("epss_at_T") or 0) >= 0.10: w.append("EPSS 10% or more")
        if (r.get("cvss_base") or 0) >= 9: w.append("critical severity")
        if r.get("is_direct") == 1: w.append("direct dependency")
        if dpct[i] >= 0.90: w.append("many packages depend on it")
        if abandoned[i]: w.append("package looks abandoned")
        if not r.get("has_fix"): w.append("no fixed version")
        reasons.append("; ".join(w) if w else "low on every factor")
    out["reasons"] = reasons
    return out
