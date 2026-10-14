"""Ecosystem-aware version comparison + OSV range evaluation."""
from packaging.version import Version as PepVersion, InvalidVersion
import semantic_version as sv, re


def parse(eco, v):
    eco = str(eco).strip().lower()
    v = str(v).strip().lstrip("vV=")
    if eco == "pypi":
        try:
            return PepVersion(v)
        except InvalidVersion:
            return None
    try:
        return sv.Version(v)
    except ValueError:
        try:
            return sv.Version.coerce(v)
        except ValueError:
            return None


def in_range(eco, version, ranges, versions):
    """OSV semantics. Returns (affected: bool|None). None = could not parse."""
    v = parse(eco, version)
    if v is None:
        return None

    exact_versions = {str(x).strip().lstrip("vV=") for x in (versions or [])}
    if str(version).strip().lstrip("vV=") in exact_versions:
        return True

    for r in ranges or []:
        if r.get("type") not in ("SEMVER", "ECOSYSTEM"):
            continue
        events = []
        for e in r.get("events", []):
            if not isinstance(e, dict):
                continue
            for key, val in e.items():
                if key == "limit":
                    continue
                if key not in {"introduced", "last_affected", "fixed"}:
                    continue
                pv = parse(eco, "0") if val == "0" else parse(eco, val)
                if pv is None:
                    return None
                events.append((key, pv))
        if not events:
            continue

        events.sort(key=lambda item: (item[1], {"introduced": 0, "last_affected": 1, "fixed": 2}[item[0]]))

        has_introduced = any(key == "introduced" for key, _ in events)
        affected = False
        for key, pv in events:
            if key == "introduced" and v >= pv:
                affected = True
            elif key == "fixed" and v >= pv:
                affected = False
            elif key == "last_affected" and v > pv:
                affected = False

        if not has_introduced and (
            any(key == "fixed" and v < pv for key, pv in events) or
            any(key == "last_affected" and v <= pv for key, pv in events)
        ):
            return True

        if affected:
            return True
    return False
