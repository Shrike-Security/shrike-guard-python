"""Tests for shrike_guard.sanitizer.

Pins the SDK-output contract at the sanitizer boundary. An earlier sanitizer
stripped `action`, `refuse_tier`, `recovery`, `session_state`, `content_type`,
and `violations[]` from every response, which violated the contract-symmetry
principle and left the four-state Cooperative Governance wire shape invisible
to direct SDK callers.

These tests fail if the sanitizer regresses to that behaviour.
"""

from shrike_guard.sanitizer import (
    _INTERNAL_FIELDS,
    _sanitize_violation,
    sanitize_scan_response,
)


# ---------------------------------------------------------------------------
# Governance fields survive on BOTH safe and unsafe branches
# ---------------------------------------------------------------------------


def test_safe_branch_preserves_action_and_refuse_tier():
    raw = {"safe": True, "action": "allow", "refuse_tier": "allow"}
    result = sanitize_scan_response(raw)
    assert result["action"] == "allow"
    assert result["refuse_tier"] == "allow"


def test_safe_branch_preserves_warn_advisory_recovery():
    raw = {
        "safe": True,
        "action": "warn",
        "refuse_tier": "warn",
        "recovery": {"instruction": "Consider rephrasing to reduce risk."},
    }
    result = sanitize_scan_response(raw)
    assert result["action"] == "warn"
    assert result["refuse_tier"] == "warn"
    assert result["recovery"]["instruction"].startswith("Consider rephrasing")


def test_unsafe_branch_preserves_action_refuse_tier_recovery():
    raw = {
        "safe": False,
        "action": "block",
        "refuse_tier": "block",
        "threat_type": "prompt_injection",
        "recovery": {
            "instruction": "Rephrase without instruction-override phrasing.",
            "available_tools": ["scan_prompt", "session_status"],
            "patterns_triggered": ["multi_turn_reconnaissance"],
        },
    }
    result = sanitize_scan_response(raw)
    assert result["action"] == "block"
    assert result["refuse_tier"] == "block"
    assert result["recovery"]["instruction"].startswith("Rephrase")
    assert "scan_prompt" in result["recovery"]["available_tools"]
    assert "multi_turn_reconnaissance" in result["recovery"]["patterns_triggered"]


def test_session_state_passes_through_verbatim():
    raw = {
        "safe": False,
        "action": "block",
        "threat_type": "multi_turn_attack",
        "session_state": {
            "session_risk_score": 0.9,
            "session_turn_number": 4,
            "session_patterns": ["multi_turn_reconnaissance"],
            "session_locked": True,
        },
    }
    result = sanitize_scan_response(raw)
    assert result["session_state"]["session_risk_score"] == 0.9
    assert result["session_state"]["session_turn_number"] == 4
    assert result["session_state"]["session_patterns"] == ["multi_turn_reconnaissance"]
    assert result["session_state"]["session_locked"] is True


def test_content_type_preserved_on_specialized_endpoint():
    raw = {
        "safe": False,
        "action": "block",
        "threat_type": "sql_injection",
        "content_type": "sql",
    }
    result = sanitize_scan_response(raw)
    assert result["content_type"] == "sql"


def test_require_approval_action_preserved():
    raw = {
        "safe": False,
        "action": "require_approval",
        "refuse_tier": "block",
        "threat_type": "pii_exposure",
        "approval_info": {"reason": "PII disclosure requires approval"},
    }
    result = sanitize_scan_response(raw)
    assert result["action"] == "require_approval"
    assert result["approval_info"]["reason"].startswith("PII disclosure")


# ---------------------------------------------------------------------------
# violations[] survives with per-item attribution stripped
# ---------------------------------------------------------------------------


def test_violations_array_preserved_from_enforce_endpoint():
    # Exact shape observed from /api/scan/enforce.
    raw = {
        "safe": False,
        "action": "block",
        "refuse_tier": "block",
        "threat_type": None,
        "violations": [
            {
                "policy_id": "",
                "policy_name": "Security Policy",
                "action": "block",
                "severity": "critical",
                "threat_type": "data_exfiltration",
                "owasp_category": "LLM02",
                "user_message": "This request looks like data exfiltration.",
                "suggested_action": "Use authorized data-export workflow.",
            },
            {
                "policy_id": "",
                "policy_name": "Security Policy",
                "action": "block",
                "severity": "critical",
                "threat_type": "prompt_injection",
                "owasp_category": "LLM01",
                "user_message": "This request contains injection patterns.",
                "suggested_action": "Rephrase without 'ignore previous instructions'.",
            },
        ],
    }
    result = sanitize_scan_response(raw)
    assert "violations" in result
    assert len(result["violations"]) == 2
    types = {v["threat_type"] for v in result["violations"]}
    assert types == {"data_exfiltration", "prompt_injection"}
    owasp = {v["owasp_category"] for v in result["violations"]}
    assert owasp == {"LLM01", "LLM02"}


def test_violation_strips_policy_id_and_policy_name():
    v = _sanitize_violation(
        {
            "policy_id": "internal-policy-42",
            "policy_name": "Security Policy",
            "action": "block",
            "severity": "critical",
            "threat_type": "prompt_injection",
            "owasp_category": "LLM01",
            "user_message": "test",
            "suggested_action": "test",
        }
    )
    assert v is not None
    assert "policy_id" not in v
    assert "policy_name" not in v
    assert v["threat_type"] == "prompt_injection"
    assert v["owasp_category"] == "LLM01"
    assert v["severity"] == "critical"
    assert v["user_message"] == "test"


def test_violation_strips_all_internal_attribution_fields():
    v = _sanitize_violation(
        {
            "threat_type": "prompt_injection",
            "severity": "high",
            "detected_by": "L1_regex",
            "matched_pattern": "ignore_previous_instructions_v3",
            "matched_text": "ignore all prior instructions",
            "ai_reasoning": "L7 said...",
            "llm_analysis": {"model": "gemini-2.5-flash", "tokens": 42},
            "performance_metrics": {"total_ms": 1234},
        }
    )
    assert v is not None
    for stripped in _INTERNAL_FIELDS:
        assert stripped not in v, f"expected {stripped} to be stripped"
    assert v["threat_type"] == "prompt_injection"


def test_violation_empty_array_dropped():
    raw = {"safe": False, "threat_type": "prompt_injection", "violations": []}
    result = sanitize_scan_response(raw)
    assert "violations" not in result


def test_violation_non_list_ignored():
    raw = {"safe": False, "threat_type": "prompt_injection", "violations": "malformed"}
    result = sanitize_scan_response(raw)
    assert "violations" not in result


# ---------------------------------------------------------------------------
# Legacy threat_type derivation still works
# ---------------------------------------------------------------------------


def test_threat_type_falls_back_to_first_violation_when_top_level_null():
    # /api/scan/enforce puts classification in violations[] and returns
    # top-level threat_type=null. Legacy callers expect a top-level string.
    raw = {
        "safe": False,
        "action": "block",
        "threat_type": None,
        "violations": [
            {"threat_type": "prompt_injection", "owasp_category": "LLM01"},
        ],
    }
    result = sanitize_scan_response(raw)
    assert result["threat_type"] == "prompt_injection"


def test_unknown_threat_type_falls_through():
    raw = {"safe": False, "threat_type": "some_novel_type"}
    result = sanitize_scan_response(raw)
    assert result["threat_type"] == "unknown"


def test_safe_true_minimal_response():
    result = sanitize_scan_response({"safe": True})
    assert result == {"safe": True, "reason": ""}


# ---------------------------------------------------------------------------
# Regression: raw internal-attribution fields must NEVER appear on output
# ---------------------------------------------------------------------------


def test_internal_attribution_fields_never_appear_on_top_level():
    raw = {
        "safe": False,
        "action": "block",
        "threat_type": "prompt_injection",
        "detected_by": "L1",
        "matched_pattern": "ignore_previous_v3",
        "matched_text": "ignore all prior",
        "ai_reasoning": "L7 said malicious",
        "llm_analysis": {"model": "gemini-2.5-flash"},
        "performance_metrics": {"total_ms": 42},
        "scan_stage": "l7_semantic",
    }
    result = sanitize_scan_response(raw)
    for stripped in _INTERNAL_FIELDS:
        assert stripped not in result, (
            f"internal attribution field {stripped!r} leaked to sanitized output"
        )


def test_action_is_authoritative_signal_for_is_blocked_helper():
    """The sanitizer must preserve `action` so scanner._is_blocked() can
    consume it. Without this, warn is indistinguishable from allow.
    """
    warn_raw = {"safe": True, "action": "warn", "refuse_tier": "warn"}
    warn = sanitize_scan_response(warn_raw)
    assert warn["action"] == "warn"

    require_approval_raw = {
        "safe": False,
        "action": "require_approval",
        "threat_type": "pii_exposure",
    }
    ra = sanitize_scan_response(require_approval_raw)
    assert ra["action"] == "require_approval"
