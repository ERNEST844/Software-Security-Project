"""Minimal guards referenced by src/10_models.py and the presentation (leakage + version logic smoke tests)."""
import os, sys
import numpy as np
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, f"{ROOT}/src")
from common import (
    FORBIDDEN,
    NUM,
    OPT,
    CAT,
    build_plan,
    decide,
    gate_fuse,
    prepare,
    recall_at,
    tier_of,
)  # noqa: E402


def test_model_inputs_exclude_labels():
    assert not (set(NUM + OPT + CAT) & FORBIDDEN)


def test_prepare_runs_on_sample():
    path = f"{ROOT}/data/processed/population_cohorts.csv"
    if not os.path.exists(path):
        return
    df = pd.read_csv(path).head(50)
    X = prepare(df)
    assert len(X) == len(df)


def test_semantic_version_ranges():
    from packaging.specifiers import SpecifierSet
    from packaging import version
    assert version.parse("1.2.3") in SpecifierSet(">=1.0.0,<2.0.0")


def test_recall_at_uses_expected_fraction_for_ties():
    assert recall_at(np.array([1, 0, 1, 0]), np.array([1, 1, 0, 0]), 0.25) == 0.25


def test_gate_fusion_prioritizes_existing_public_poc():
    scores = gate_fuse([0.1, 0.9], [0, 1])
    assert scores[1] > scores[0]


def test_remediation_tiers_and_actions_follow_policy():
    assert [tier_of(score) for score in (0.70, 0.50, 0.30, 0.29)] == ["P1", "P2", "P3", "P4"]
    assert decide("P1", True, False, True) == "upgrade"
    assert decide("P1", False, True, False) == "replace"
    assert decide("P1", False, False, False) == "isolate"
    assert decide("P3", False, False, False) == "monitor"
    assert decide("P4", False, False, False) == "accept"


def test_current_kev_membership_overrides_project_tier():
    findings = pd.DataFrame(
        {
            "pagerank": [0.0, 1.0],
            "descendants": [0, 1],
            "is_direct": [0, 0],
            "fan_in": [0, 1],
            "days_since_last_release": [30, 30],
            "releases_prior_12m": [2, 2],
            "version_lag_days": [0, 100],
            "has_fix": [1, 1],
            "kev_at_T": [1, 0],
            "poc_count_at_T": [0, 0],
            "epss_at_T": [0.0, 0.0],
            "cvss_base": [1.0, 1.0],
        }
    )
    plan = build_plan(findings, np.array([0.0, 0.0]))
    assert plan.loc[0, "kev_override"]
    assert plan.loc[0, "tier"] == "P1"
    assert "already listed in CISA KEV at snapshot" in plan.loc[0, "reasons"]
