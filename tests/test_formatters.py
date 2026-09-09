"""Tests for shrike_guard.formatters.

Verifies the canonical block-feedback rendering shape. The tests pin the
current shape and verify graceful handling of the `recovery` block.
"""

from shrike_guard.formatters import format_block_feedback


def test_format_block_feedback_minimal_verdict_renders_prefix():
    """A verdict with only threat_type still renders a well-formed message."""
    result = format_block_feedback({"threat_type": "prompt_injection"})
    assert result.startswith("Shrike blocked your last tool call.")
    assert "Threat type: prompt_injection" in result


def test_format_block_feedback_empty_dict_renders_prefix_only():
    """Empty verdict does not crash; renders the prefix so downstream
    can still detect a Shrike-originated system message."""
    result = format_block_feedback({})
    assert result == "Shrike blocked your last tool call."


def test_format_block_feedback_full_current_mcp_shape():
    """Full verdict shape as MCP sanitizer emits today (pre-Batch-2-D)."""
    verdict = {
        "action": "block",
        "threat_type": "data_exfiltration",
        "reason": "Command routes IMDS credentials to external endpoint",
        "session_state": {
            "session_risk_score": 0.85,
            "session_turn_number": 4,
            "session_patterns": [
                "multi_turn_reconnaissance",
                "multi_turn_escalation",
            ],
        },
    }
    result = format_block_feedback(verdict)
    assert "Shrike blocked your last tool call." in result
    assert "Reason: Command routes IMDS credentials to external endpoint" in result
    assert "Threat type: data_exfiltration" in result
    assert "Session risk: 0.85 (turn 4)" in result
    assert "multi_turn_reconnaissance, multi_turn_escalation" in result


def test_format_block_feedback_batch2d_recovery_shape():
    """The backend ships a `recovery` block — helper picks it up automatically
    without a signature change. Verifies the forward-compat contract."""
    verdict = {
        "action": "block",
        "threat_type": "session_locked",
        "session_state": {
            "session_risk_score": 0.9,
            "session_turn_number": 5,
            "session_patterns": ["multi_turn_reconnaissance"],
        },
        "recovery": {
            "instruction": (
                "Rotate session_id and re-verify user intent before retry"
            ),
            "available_tools": [
                "scan_prompt",
                "scan_response",
                "session_status",
            ],
            "patterns_triggered": ["multi_turn_reconnaissance"],
        },
    }
    result = format_block_feedback(verdict)
    assert "Recovery: Rotate session_id and re-verify user intent" in result
    assert (
        "Available tools: scan_prompt, scan_response, session_status" in result
    )


def test_format_block_feedback_recovery_patterns_override_session_patterns():
    """When both recovery.patterns_triggered and session_state.session_patterns
    are present, prefer recovery.patterns_triggered (scoped to THIS event
    rather than the whole-session accumulator)."""
    verdict = {
        "session_state": {
            "session_patterns": ["multi_turn_old_pattern"],
        },
        "recovery": {
            "patterns_triggered": ["multi_turn_new_pattern"],
        },
    }
    result = format_block_feedback(verdict)
    assert "multi_turn_new_pattern" in result
    assert "multi_turn_old_pattern" not in result


def test_format_block_feedback_uses_guidance_when_no_reason():
    """MCP sanitizer emits `guidance`, not `reason`. Helper falls back
    to guidance so current MCP-shaped verdicts render cleanly."""
    result = format_block_feedback({
        "threat_type": "sql_injection",
        "guidance": "This query contains dangerous SQL patterns.",
    })
    assert "Reason: This query contains dangerous SQL patterns." in result


def test_format_block_feedback_reason_wins_over_guidance():
    """When both are present, reason wins."""
    result = format_block_feedback({
        "reason": "Explicit reason",
        "guidance": "Fallback guidance",
    })
    assert "Reason: Explicit reason" in result
    assert "Fallback guidance" not in result


def test_format_block_feedback_partial_session_state_missing_turn():
    """Missing session_turn_number renders risk without the turn qualifier."""
    result = format_block_feedback({
        "session_state": {"session_risk_score": 0.5, "session_patterns": []}
    })
    assert "Session risk: 0.5" in result
    assert "(turn" not in result


def test_format_block_feedback_action_warn_uses_advisory_prefix():
    """The refuse_tier `warn` state uses the advisory prefix so
    the model recognizes the softer verdict."""
    result = format_block_feedback({
        "action": "warn",
        "threat_type": "prompt_injection",
        "reason": "Elevated risk on this turn — proceed with caveat",
    })
    assert result.startswith("Shrike flagged your last tool call (advisory).")
    assert "Reason: Elevated risk" in result


def test_format_block_feedback_action_require_approval_uses_hold_prefix():
    """require_approval verdicts use the hold prefix so the model knows
    to wait rather than retry."""
    result = format_block_feedback({
        "action": "require_approval",
        "threat_type": "destructive_operation",
    })
    assert result.startswith("Shrike is holding your last tool call for approval.")


def test_format_block_feedback_action_defaults_to_block_prefix():
    """When the verdict is non-empty and action is unset, treat it as a
    block — matches the primary use case where a developer catches a
    block verdict and doesn't want to thread action through explicitly."""
    result = format_block_feedback({"threat_type": "prompt_injection"})
    assert result.startswith("Shrike blocked your last tool call.")


def test_format_block_feedback_empty_session_patterns_stays_silent():
    """Empty session_patterns list does not render an empty 'Patterns
    triggered:' line — silence beats noise for the model."""
    result = format_block_feedback({
        "threat_type": "prompt_injection",
        "session_state": {
            "session_risk_score": 0.3,
            "session_turn_number": 2,
            "session_patterns": [],
        },
    })
    assert "Patterns triggered" not in result


def test_format_block_feedback_public_export():
    """Helper is re-exported at the top-level shrike_guard namespace so
    integrators can use `from shrike_guard import format_block_feedback`."""
    from shrike_guard import format_block_feedback as top_level

    assert top_level is format_block_feedback


def test_format_block_feedback_batch2d_wire_shape_session_locked():
    """Integration contract test — uses the EXACT JSON shape the backend
    emits on a session_locked verdict once the backend emits it.
    Locks in that the SDK helper and the backend agree on field names and
    values so the loop closes without a shape drift.

    The canonical instruction here MUST match the string in
    platform/common/models/recovery.go — if either side changes, this
    test fails and forces the other side to sync. That is the contract.
    """
    # This is the wire shape returned by /api/scan/specialized on a
    # session_locked verdict. Extracted verbatim from the backend
    # implementation. If the backend changes the canonical instruction,
    # this test must be updated in the same PR.
    canonical_instruction = (
        "Start a new session_id for the next call. This session has "
        "accumulated risk from prior turns that cannot be scanned out; "
        "a fresh session_id is the self-service recovery path. "
        "reset_session is administratively restricted at the block "
        "threshold, except under a live declared scope: an agent may "
        "release its own session up to three times per renewal window, "
        "and every release is audited."
    )
    verdict = {
        "safe": False,
        "refuse_tier": "block",
        "threat_type": "session_locked",
        "severity": "high",
        "session_state": {
            "session_risk_score": 0.9,
            "session_turn_number": 6,
            "session_patterns": [
                "multi_turn_reconnaissance",
                "multi_turn_crescendo",
                "multi_turn_escalation",
            ],
        },
        "recovery": {
            "instruction": canonical_instruction,
            "available_tools": [
                "scan_prompt",
                "scan_response",
                "session_status",
            ],
            # The session_locked short-circuit does NOT populate
            # patterns_triggered — the block fires on accumulated state
            # not a per-turn correlator report. session_patterns on
            # session_state carries the whole-session accumulator instead.
        },
    }

    result = format_block_feedback(verdict)

    # Prefix contract — must be the "blocked" prefix.
    assert result.startswith("Shrike blocked your last tool call.")

    # Threat type surfaces.
    assert "Threat type: session_locked" in result

    # Session state renders with turn qualifier.
    assert "Session risk: 0.9 (turn 6)" in result

    # Because recovery.patterns_triggered is absent, helper falls back to
    # session_state.session_patterns (whole-session accumulator).
    assert (
        "Patterns triggered: multi_turn_reconnaissance, "
        "multi_turn_crescendo, multi_turn_escalation"
    ) in result

    # Recovery block renders both instruction and available_tools.
    assert f"Recovery: {canonical_instruction}" in result
    assert (
        "Available tools: scan_prompt, scan_response, session_status"
    ) in result


def test_format_block_feedback_batch2d_wire_shape_generic_block():
    """Integration contract test for a generic block verdict (non-locked)
    on the specialized path. Recovery is populated by the handler after
    PopulateUserGuidance sets SuggestedAction. Verifies helper renders
    the shape emitted by handlers/scan_specialized_handler.go.
    """
    verdict = {
        "safe": False,
        "refuse_tier": "block",
        "threat_type": "data_exfiltration",
        "severity": "high",
        "guidance": (
            "This request looks like it could move sensitive data outside "
            "your environment."
        ),
        "suggested_action": (
            "If this is a legitimate export, use your platform's authorized "
            "data-export workflow. Your security team can grant scoped "
            "access if you explain the use case."
        ),
        "session_state": {
            "session_risk_score": 0.45,
            "session_turn_number": 1,
            "session_patterns": [],
        },
        "recovery": {
            "instruction": (
                "If this is a legitimate export, use your platform's "
                "authorized data-export workflow. Your security team can "
                "grant scoped access if you explain the use case."
            ),
            # Non-locked block: AvailableTools omitted so caller does NOT
            # interpret nil as an empty set (see PopulateRecovery docstring).
        },
    }

    result = format_block_feedback(verdict)

    # Renders the guidance as Reason line since no explicit "reason" field
    # is present (guidance is the current MCP sanitizer shape).
    assert result.startswith("Shrike blocked your last tool call.")
    assert "Reason: This request looks like it could move sensitive data" in result
    assert "Threat type: data_exfiltration" in result

    # Empty session_patterns must stay silent (no empty line).
    assert "Patterns triggered" not in result

    # Recovery instruction renders even without available_tools.
    assert "Recovery: If this is a legitimate export" in result
    assert "Available tools" not in result
