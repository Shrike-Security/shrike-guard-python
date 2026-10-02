"""Tests for shrike_guard.rotation — three-shape session rotation record.

Mirrors platform/sdks/typescript/tests/unit/rotation.test.ts. Keep the
two suites aligned when either module changes — parity across the
language surfaces is a launch requirement, not a nice-to-have.

Locks in:
  - Discriminated union shape (rotated: True vs rotated: False)
  - Ownership detection via effective_session_id vs module_session_id
  - Trigger semantics (session_locked, risk >= ROTATION_THRESHOLD)
  - Non-trigger cases return None
  - Per-event suggestion (each caller-owned recommendation mints a
    fresh suggested_new_session_id — none are stable across events)
"""

from __future__ import annotations

import re

from shrike_guard.rotation import (
    ROTATION_THRESHOLD,
    evaluate_rotation,
)


MODULE_SESSION = "module-fixed-uuid-11111111-1111-1111-1111-111111111111"
CALLER_SESSION = "caller-supplied-imds-traj"

UUID_RE = re.compile(r"^[0-9a-f-]{36}$")


# ---------------------------------------------------------------------------
# No-trigger cases
# ---------------------------------------------------------------------------


def test_returns_none_for_safe_response_with_no_risk():
    """Absence of both triggers must yield None — the SDK does not
    fabricate rotation records."""
    result = evaluate_rotation(
        effective_session_id=MODULE_SESSION,
        module_session_id=MODULE_SESSION,
    )
    assert result is None


def test_returns_none_when_risk_below_threshold():
    result = evaluate_rotation(
        threat_type="prompt_injection",
        session_risk_score=ROTATION_THRESHOLD - 0.01,
        effective_session_id=MODULE_SESSION,
        module_session_id=MODULE_SESSION,
    )
    assert result is None


def test_returns_none_when_no_session_locked_and_risk_absent():
    result = evaluate_rotation(
        threat_type="sql_injection",
        effective_session_id=MODULE_SESSION,
        module_session_id=MODULE_SESSION,
    )
    assert result is None


# ---------------------------------------------------------------------------
# Module-owned branch (caller did NOT supply session_id)
# ---------------------------------------------------------------------------


def test_module_owned_rotated_true_on_risk_over_threshold():
    result = evaluate_rotation(
        session_risk_score=0.85,
        effective_session_id=MODULE_SESSION,
        module_session_id=MODULE_SESSION,
    )
    assert result is not None
    assert result["rotated"] is True
    assert result["owner"] == "sdk_client"
    assert result["reason"] == "risk_threshold_exceeded"
    assert result["previous_session_id"] == MODULE_SESSION
    assert UUID_RE.match(result["new_session_id"])
    assert result["new_session_id"] != MODULE_SESSION
    assert result["triggering_risk_score"] == 0.85
    assert result["configured_threshold"] == ROTATION_THRESHOLD


def test_session_locked_does_not_rotate_and_offers_no_new_id():
    """The lock is the control. Rotating past it sidesteps the control
    rather than clearing it, which is what the backend's own recovery
    instruction tells the agent not to do. A lock lifts by a self-release
    under a live declared scope, or by an operator."""
    result = evaluate_rotation(
        threat_type="session_locked",
        effective_session_id=MODULE_SESSION,
        module_session_id=MODULE_SESSION,
    )
    assert result is not None
    assert result["reason"] == "session_locked"
    assert result["rotated"] is False
    assert result["rotation_recommended"] is False
    assert result["owner"] == "sdk_client"
    assert result["current_session_id"] == MODULE_SESSION
    assert "new_session_id" not in result
    assert "suggested_new_session_id" not in result


def test_session_locked_not_rotated_even_above_threshold():
    """The ordering is the whole fix: a locked session is ALREADY above the
    score threshold, so checking the score first would rotate it."""
    result = evaluate_rotation(
        threat_type="session_locked",
        session_risk_score=0.95,
        effective_session_id=MODULE_SESSION,
        module_session_id=MODULE_SESSION,
    )
    assert result is not None
    assert result["rotated"] is False
    assert result["rotation_recommended"] is False
    assert result["triggering_risk_score"] == 0.95


def test_session_locked_without_risk_omits_score():
    """The triggering_risk_score field is optional. session_locked with no
    numeric risk in the payload should omit it, not fabricate a 0.0."""
    result = evaluate_rotation(
        threat_type="session_locked",
        effective_session_id=MODULE_SESSION,
        module_session_id=MODULE_SESSION,
    )
    assert result is not None
    assert "triggering_risk_score" not in result
    assert result["configured_threshold"] == ROTATION_THRESHOLD


# ---------------------------------------------------------------------------
# Caller-owned branch (caller supplied their own session_id)
# ---------------------------------------------------------------------------


def test_caller_owned_recommendation_on_risk_over_threshold():
    result = evaluate_rotation(
        session_risk_score=0.85,
        effective_session_id=CALLER_SESSION,
        module_session_id=MODULE_SESSION,
    )
    assert result is not None
    assert result["rotated"] is False
    assert result["rotation_recommended"] is True
    assert result["owner"] == "caller"
    assert result["reason"] == "risk_threshold_exceeded"
    assert result["current_session_id"] == CALLER_SESSION
    assert UUID_RE.match(result["suggested_new_session_id"])
    assert result["suggested_new_session_id"] != CALLER_SESSION
    assert result["triggering_risk_score"] == 0.85
    assert result["configured_threshold"] == ROTATION_THRESHOLD


def test_caller_owned_does_not_mutate_module_session_id():
    """Caller-owned means the SDK stays hands-off. Passing module_session_id
    and reading it back after the call must not observe mutation — the
    module id is an input, not something evaluate_rotation touches."""
    original = MODULE_SESSION
    result = evaluate_rotation(
        threat_type="session_locked",
        effective_session_id=CALLER_SESSION,
        module_session_id=original,
    )
    assert result is not None
    assert result["rotated"] is False
    assert original == MODULE_SESSION


def test_caller_owned_session_locked_suggests_nothing():
    """A caller who owns the session still must not be told that minting a
    new id is the way past a lock."""
    result = evaluate_rotation(
        threat_type="session_locked",
        effective_session_id=CALLER_SESSION,
        module_session_id=MODULE_SESSION,
    )
    assert result is not None
    assert result["reason"] == "session_locked"
    assert result["owner"] == "caller"
    assert result["rotation_recommended"] is False
    assert result["current_session_id"] == CALLER_SESSION
    assert "suggested_new_session_id" not in result


# ---------------------------------------------------------------------------
# Per-event suggestion contract (docstring invariant)
# ---------------------------------------------------------------------------


def test_each_caller_owned_recommendation_mints_a_fresh_suggested_id():
    """Ten evaluations, ten distinct suggested ids — the value is
    per-event, not a stable "next id" the caller can cache-key on."""
    suggestions = set()
    for _ in range(10):
        rec = evaluate_rotation(
            session_risk_score=0.85,
            effective_session_id=CALLER_SESSION,
            module_session_id=MODULE_SESSION,
        )
        assert rec is not None
        suggestions.add(rec["suggested_new_session_id"])
    assert len(suggestions) == 10


# ---------------------------------------------------------------------------
# Threshold exactly (>= not >)
# ---------------------------------------------------------------------------


def test_risk_equal_to_threshold_triggers_rotation():
    result = evaluate_rotation(
        session_risk_score=ROTATION_THRESHOLD,
        effective_session_id=MODULE_SESSION,
        module_session_id=MODULE_SESSION,
    )
    assert result is not None
    assert result["rotated"] is True


# ---------------------------------------------------------------------------
# Public export contract
# ---------------------------------------------------------------------------


def test_evaluate_rotation_is_re_exported_at_shrike_guard_root():
    """Users must be able to `from shrike_guard import evaluate_rotation`
    without knowing the submodule layout."""
    from shrike_guard import evaluate_rotation as root_evaluate
    from shrike_guard import ROTATION_THRESHOLD as root_threshold

    assert root_evaluate is evaluate_rotation
    assert root_threshold == ROTATION_THRESHOLD
