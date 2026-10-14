"""Ecosystem-aware version comparison + OSV range evaluation."""
from packaging.version import Version as PepVersion, InvalidVersion
import semantic_version as sv, re

def parse(eco, v):
    v = str(v).strip().lstrip("vV=")
    if eco == "PyPI":
        try: return PepVersion(v)
        except InvalidVersion: return None
    try: return sv.Version(v)
    except ValueError:
        try: return sv.Version.coerce(v)
        except ValueError: return None

def in_range(eco, version, ranges, versions):
    """OSV semantics. Returns (affected: bool|None). None = could not parse."""
    v = parse(eco, version)
    if v is None: return None
    if versions and str(version).strip().lstrip("vV=") in {x.lstrip("vV=") for x in versions}: return True
    for r in ranges:
        if r["type"] not in ("SEMVER", "ECOSYSTEM"): continue
        evs = []
        for e in r["events"]:
            k = next(iter(e)); val = e[k]
            if k == "limit": continue
            pv = parse(eco, "0") if val == "0" else parse(eco, val)
            if pv is None: return None
            evs.append((pv, {"introduced": 0, "last_affected": 1, "fixed": 2}[k], k, val))
        evs.sort(key=lambda t: (t[0], t[1]))
        affected = False
        for pv, _, k, val in evs:
            if k == "introduced" and v >= pv: affected = True
            elif k == "fixed" and v >= pv: affected = False
            elif k == "last_affected" and v > pv: affected = False
        if affected: return True
    return False
