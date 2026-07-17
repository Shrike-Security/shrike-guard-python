"""Canonical 'Working with Shrike' system-prompt block.

Exposes the ~180-word block that teaches an agent how to react to
Shrike verdicts (the four refuse_tier states, the injected-message
prefix contract emitted by ``format_block_feedback``, the per-event
rotation-recommendation contract). This module is the source of truth
for the block string — the docs page at
``docs/cookbook/working-with-shrike.md`` and the web UI's Cookbook
page render the same string.

Usage:

    from shrike_guard import system_prompt

    prompt = system_prompt()
    # returns the block string; drop into your agent's system prompt
    # as the first non-role paragraph.

Namespace shape: `shrike_guard.system_prompt` is a callable module (via
the top-level re-export in ``__init__.py``). Future archetype
templates (support, code-gen, RAG, research, multi-agent,
internal-copilot) will layer additions on top and expose as attribute
accessors on the same namespace — e.g. ``system_prompt.support()`` —
without changing this base signature.

Version: v1.0 (2026-07-06). See the version-history section below.
"""

from __future__ import annotations


_BLOCK_V1_0 = """\
You are operating in a Shrike-governed environment. Shrike scans every
prompt, tool call, and response before it takes effect and returns a
verdict: allow, warn (advisory — proceed with the caveat noted), block
(the action did not execute), or require_approval (the action is held
for a human).

If Shrike blocks or holds a tool call, you will receive a system
message on your next turn beginning with "Shrike blocked your last
tool call.", "Shrike flagged your last tool call (advisory).", or
"Shrike is holding your last tool call for approval." Read the Reason,
Threat type, and any Recovery or Available tools lines and adjust your
approach — do not retry the same action verbatim. If the message names
Patterns triggered, those are correlator signals across your recent
turns; treat them as evidence your current strategy is being read as
adversarial.

If Shrike returns a rotation recommendation (rotation_recommended:
true), adopt the suggested_new_session_id on your very next tool call.
Do not cache suggested ids across turns; they are minted per event.

Shrike is a collaborator, not an obstacle. When it flags something,
the fastest recovery is to explain your intent and pick a different
path."""


SYSTEM_PROMPT_VERSION = "1.0"


def system_prompt() -> str:
    """Return the canonical 'Working with Shrike' system-prompt block.

    The returned string is designed to be dropped into your agent's
    system prompt as the first non-role paragraph:

    .. code-block:: python

        from shrike_guard import system_prompt

        prompt = (
            "You are a customer support agent for Acme Corp.\\n\\n"
            + system_prompt()
            + "\\n\\n"
            + "When customers ask about refunds, first verify..."
        )

    Returns:
        The block string (~180 words, no trailing newline).

    Version:
        v1.0 (2026-07-06). Access via ``shrike_guard.SYSTEM_PROMPT_VERSION``.
    """
    return _BLOCK_V1_0


__all__ = ["system_prompt", "SYSTEM_PROMPT_VERSION"]
