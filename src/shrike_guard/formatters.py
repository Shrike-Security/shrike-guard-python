"""Canonical formatters for Shrike verdict-to-prompt injection.

Implements the block-feedback layer (layer 4) of the four-layer
self-consultation stack:

    1. System prompt tells the agent HOW to work with Shrike
    2. MCP tools give the agent CHANNELS to consult Shrike
    3. SDK guard is the deterministic enforcement floor
    4. Block-feedback injection (this module) closes the learning loop

When the SDK guard blocks a tool call, the developer's control flow can
call ``format_block_feedback(verdict)`` and append the returned string
as a system message to the model's next turn. The model reads Shrike's
reason + recovery guidance and adjusts, rather than looping on the same
blocked action.

The rendering is stable across SDK versions so cookbook prompt templates
can teach the model to recognize the "Shrike blocked" prefix and act on
the structured fields inside.

This helper is verdict-shape-tolerant: it accepts partial dicts and
uses ``dict.get`` throughout. It picks up the ``recovery`` block
(``instruction``, ``available_tools``, ``patterns_triggered``) automatically
when present, without a signature change.
"""

from __future__ import annotations

from typing import Any, Mapping


_BLOCK_PREFIX = "Shrike blocked your last tool call."
_WARN_PREFIX = "Shrike flagged your last tool call (advisory)."
_APPROVAL_PREFIX = "Shrike is holding your last tool call for approval."


def format_block_feedback(verdict: Mapping[str, Any]) -> str:
    """Render a canonical prompt-shape string from a Shrike verdict.

    The rendered string is designed to be injected as a system message
    into the model's next turn, so it uses a stable prefix + a small
    set of well-named field lines the model can reason over.

    Recognized verdict keys (all optional):

    - ``action``: ``"block"`` | ``"warn"`` | ``"require_approval"`` | ``"allow"``.
      Selects the prefix. Defaults to ``"block"`` when the verdict is
      non-empty and no action is set — this matches the primary use case
      (a developer catching a block verdict and wanting the model to
      know why).
    - ``threat_type``: canonical Shrike threat type string.
    - ``reason``: human-readable explanation. Falls back to ``guidance``
      when ``reason`` is absent (the MCP sanitizer emits ``guidance``
      today; the future ``/api/scan/enforce`` shape emits ``reason``).
    - ``session_state.session_risk_score`` + ``session_turn_number`` +
      ``session_patterns``: the L9 session outcome block.
    - ``recovery.instruction``: the "what to do next" hint.
    - ``recovery.available_tools``: which tools remain callable under
      the current quarantine posture.
    - ``recovery.patterns_triggered``: which correlator patterns fired
      on THIS block. Prefers this over ``session_state.
      session_patterns`` when present, because the recovery block scopes
      to the triggering event rather than the whole session.

    Args:
        verdict: A dict-shaped verdict from a Shrike SDK scan call, the
            MCP sanitizer, or the future ``/api/scan/enforce`` endpoint.

    Returns:
        A single string suitable for use as the ``content`` of a system
        message in a downstream model call.

    Example:
        >>> v = {
        ...     "action": "block",
        ...     "threat_type": "data_exfiltration",
        ...     "reason": "Command routes IMDS credentials to external endpoint",
        ...     "session_state": {
        ...         "session_risk_score": 0.85,
        ...         "session_turn_number": 4,
        ...         "session_patterns": ["multi_turn_reconnaissance"],
        ...     },
        ... }
        >>> print(format_block_feedback(v))
        Shrike blocked your last tool call.
        Reason: Command routes IMDS credentials to external endpoint
        Threat type: data_exfiltration
        Session risk: 0.85 (turn 4)
        Patterns triggered: multi_turn_reconnaissance
    """
    action = (verdict.get("action") or "block").lower()
    if action == "warn":
        lines = [_WARN_PREFIX]
    elif action == "require_approval":
        lines = [_APPROVAL_PREFIX]
    else:
        # "block" is the default so callers can pass a raw block verdict
        # without threading action through explicitly.
        lines = [_BLOCK_PREFIX]

    reason = verdict.get("reason") or verdict.get("guidance")
    if reason:
        lines.append(f"Reason: {reason}")

    threat_type = verdict.get("threat_type")
    if threat_type:
        lines.append(f"Threat type: {threat_type}")

    session_state = verdict.get("session_state") or {}
    risk = session_state.get("session_risk_score")
    turn = session_state.get("session_turn_number")
    if risk is not None:
        if turn is not None:
            lines.append(f"Session risk: {risk} (turn {turn})")
        else:
            lines.append(f"Session risk: {risk}")

    # Prefer recovery.patterns_triggered (scoped to THIS triggering event)
    # over session_state.session_patterns (whole-session
    # accumulator). Falls through cleanly when neither is present.
    recovery = verdict.get("recovery") or {}
    patterns = (
        recovery.get("patterns_triggered")
        or session_state.get("session_patterns")
        or []
    )
    if patterns:
        lines.append(f"Patterns triggered: {', '.join(patterns)}")

    instruction = recovery.get("instruction")
    if instruction:
        lines.append(f"Recovery: {instruction}")

    available_tools = recovery.get("available_tools")
    if available_tools:
        lines.append(f"Available tools: {', '.join(available_tools)}")

    return "\n".join(lines)


__all__ = ["format_block_feedback"]
