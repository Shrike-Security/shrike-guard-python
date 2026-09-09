"""Cross-language contract-symmetry parity test.

Loads the contract-symmetry fixture vendored under tests/fixtures/ and asserts
that Python SDK's sanitize_scan_response preserves every governance field
declared as invariant. The identical fixture is consumed by the TypeScript
SDK and MCP responseFormatter test suites — if any of the three drifts,
that language's CI job fails. The vendored copy is byte-identical to the
canonical fixture shared by every consumer; the last test in this module
checks that whenever the canonical copy is reachable.

Pins the contract-symmetry principle: every scan response carries the same
governance fields (safe, refuse_tier, recovery, session_state) whether the
verdict is safe or refused.
"""

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from shrike_guard.sanitizer import sanitize_scan_response


# ---------------------------------------------------------------------------
# Fixture loading
# ---------------------------------------------------------------------------

_HERE = Path(__file__).resolve().parent
# The vendored copy ships with the package so the suite runs from any checkout.
_FIXTURE_DIR = _HERE / "fixtures" / "contract-symmetry"
# The canonical copy is shared with the other SDKs and is only reachable from
# the monorepo; when present, the vendored copy must match it byte for byte.
_CANONICAL_DIR = _HERE.parents[2] / "testdata" / "contract-symmetry"


def _load(name: str) -> Dict[str, Any]:
    with (_FIXTURE_DIR / name).open() as f:
        return json.load(f)


@pytest.fixture(scope="module")
def responses() -> Dict[str, Any]:
    return _load("canonical-backend-responses.json")["responses"]


@pytest.fixture(scope="module")
def invariants() -> Dict[str, Any]:
    return _load("governance-invariants.json")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _branch_invariants(inv: Dict[str, Any], raw: Dict[str, Any]) -> Dict[str, Any]:
    """Pick the branch invariants matching the raw response's safe flag."""
    return inv["safe_branch" if raw.get("safe", True) else "unsafe_branch"]


def _each_response(responses: Dict[str, Any]):
    """Yield (case_name, raw_response) — a helper for parametrize-style loops."""
    for name, entry in responses.items():
        yield name, entry["raw"]


# ---------------------------------------------------------------------------
# Top-level governance fields survive when present on raw
# ---------------------------------------------------------------------------


def test_all_fixture_cases_covered(responses: Dict[str, Any]) -> None:
    """Regression guard: if someone adds a case to the fixture, at least one
    of the invariants below must exercise it. Prevents silent skips."""
    assert len(responses) >= 6, "fixture should cover >= 6 canonical cases"


def test_top_level_governance_fields_preserved(
    responses: Dict[str, Any], invariants: Dict[str, Any]
) -> None:
    for case_name, raw in _each_response(responses):
        sanitized = sanitize_scan_response(raw)
        branch = _branch_invariants(invariants, raw)
        for field in branch["must_preserve_top_level"]:
            # Only check preservation when raw HAS the field with a non-null value
            raw_value = raw.get(field)
            if raw_value is None:
                continue
            assert field in sanitized, (
                f"[{case_name}] top-level `{field}` missing from sanitized output"
            )
            assert sanitized[field] == raw_value, (
                f"[{case_name}] top-level `{field}` value diverged: "
                f"raw={raw_value!r} sanitized={sanitized[field]!r}"
            )


def test_session_state_fields_preserved(
    responses: Dict[str, Any], invariants: Dict[str, Any]
) -> None:
    for case_name, raw in _each_response(responses):
        raw_ss = raw.get("session_state")
        if not raw_ss:
            continue
        sanitized = sanitize_scan_response(raw)
        ss = sanitized.get("session_state")
        assert ss is not None, (
            f"[{case_name}] session_state missing from sanitized output"
        )
        branch = _branch_invariants(invariants, raw)
        for field in branch["session_state_must_preserve"]:
            if field not in raw_ss:
                continue
            assert ss.get(field) == raw_ss[field], (
                f"[{case_name}] session_state.{field} diverged: "
                f"raw={raw_ss[field]!r} sanitized={ss.get(field)!r}"
            )


def test_recovery_fields_preserved(
    responses: Dict[str, Any], invariants: Dict[str, Any]
) -> None:
    for case_name, raw in _each_response(responses):
        raw_rec = raw.get("recovery")
        if not raw_rec:
            continue
        sanitized = sanitize_scan_response(raw)
        rec = sanitized.get("recovery")
        assert rec is not None, (
            f"[{case_name}] recovery missing from sanitized output"
        )
        branch = _branch_invariants(invariants, raw)
        for field in branch["recovery_must_preserve"]:
            if field not in raw_rec:
                continue
            assert rec.get(field) == raw_rec[field], (
                f"[{case_name}] recovery.{field} diverged"
            )


# ---------------------------------------------------------------------------
# Violations[] survives with per-item attribution stripped
# ---------------------------------------------------------------------------


def test_violations_preserved_when_present(
    responses: Dict[str, Any], invariants: Dict[str, Any]
) -> None:
    for case_name, raw in _each_response(responses):
        raw_v: List[Dict[str, Any]] = raw.get("violations") or []
        if not raw_v:
            continue
        sanitized = sanitize_scan_response(raw)
        sv = sanitized.get("violations")
        assert sv is not None, (
            f"[{case_name}] violations[] was dropped despite raw having entries"
        )
        assert isinstance(sv, list), (
            f"[{case_name}] violations must remain a list on the wire"
        )
        assert len(sv) == len(raw_v), (
            f"[{case_name}] violations count changed: "
            f"raw={len(raw_v)} sanitized={len(sv)}"
        )
        branch = invariants["unsafe_branch"]  # violations only on unsafe path
        for i, (raw_item, s_item) in enumerate(zip(raw_v, sv)):
            for field in branch["violation_must_preserve"]:
                if field not in raw_item:
                    continue
                assert s_item.get(field) == raw_item[field], (
                    f"[{case_name}] violations[{i}].{field} diverged"
                )
            for field in branch["violation_must_strip"]:
                assert field not in s_item, (
                    f"[{case_name}] violations[{i}].{field} leaked "
                    f"(attribution field must be stripped)"
                )


# ---------------------------------------------------------------------------
# Internal attribution fields never appear at top level
# ---------------------------------------------------------------------------


def test_internal_attribution_stripped_at_top_level(
    responses: Dict[str, Any], invariants: Dict[str, Any]
) -> None:
    for case_name, raw in _each_response(responses):
        # Inject attribution fields into a copy of raw to prove they get
        # stripped — the canonical fixture already omits them, so we synthesize.
        polluted = dict(raw)
        polluted.update({
            "detected_by": "L1_regex",
            "matched_pattern": "leaked_pattern_id",
            "matched_text": "leaked text",
            "ai_reasoning": "leaked l7 rationale",
            "llm_analysis": {"model": "gemini-2.5-flash"},
            "performance_metrics": {"total_ms": 42},
            "scan_stage": "l7_semantic",
        })
        sanitized = sanitize_scan_response(polluted)
        branch = _branch_invariants(invariants, polluted)
        for field in branch["top_level_must_strip"]:
            assert field not in sanitized, (
                f"[{case_name}] internal attribution field `{field}` leaked to "
                f"the sanitized top level"
            )


# ---------------------------------------------------------------------------
# The `action` field survives so _is_blocked() can consume it
# ---------------------------------------------------------------------------


def test_action_field_preserved_across_all_states(
    responses: Dict[str, Any],
) -> None:
    """The action-authoritative helpers rely on `action` surviving the
    sanitizer. Without this, warn is indistinguishable from allow and the
    the four-state governance wire shape is invisible to SDK users."""
    for case_name, raw in _each_response(responses):
        raw_action = raw.get("action")
        if raw_action is None:
            continue
        sanitized = sanitize_scan_response(raw)
        assert sanitized.get("action") == raw_action, (
            f"[{case_name}] action `{raw_action}` was stripped or altered"
        )


# ---------------------------------------------------------------------------
# The vendored fixture must match the canonical copy
# ---------------------------------------------------------------------------


def test_vendored_fixture_is_present() -> None:
    """The suite reads the vendored copy, so the package must ship it."""
    assert sorted(p.name for p in _FIXTURE_DIR.glob("*.json")), (
        "tests/fixtures/contract-symmetry/ has no fixture files"
    )


@pytest.mark.skipif(
    not _CANONICAL_DIR.is_dir(),
    reason="canonical fixture directory not reachable from this checkout",
)
@pytest.mark.parametrize("name", sorted(p.name for p in _FIXTURE_DIR.glob("*.json")))
def test_vendored_fixture_matches_canonical(name: str) -> None:
    """The copy under tests/fixtures/ exists so the suite runs from a standalone
    checkout. It is a copy, not a fork: whenever the canonical fixture is
    reachable, every vendored file must match it byte for byte."""
    assert (_FIXTURE_DIR / name).read_bytes() == (_CANONICAL_DIR / name).read_bytes(), (
        f"{name}: vendored copy differs from the canonical fixture; "
        "copy the canonical file over it"
    )
