"""Tests for shrike_guard.system_prompt.

Locks the ~180-word 'Working with Shrike' block content and shape so
silent drift doesn't ship. If the block is intentionally updated, this
test's assertions update alongside the constant AND the docs page and
the Cookbook UI's rendered string change in the same PR — the three
must stay aligned.
"""

from shrike_guard import SYSTEM_PROMPT_VERSION, system_prompt


def test_system_prompt_returns_non_empty_string():
    assert isinstance(system_prompt(), str)
    assert len(system_prompt()) > 0


def test_system_prompt_starts_with_governed_environment_intro():
    """First sentence establishes the scope of what Shrike governs."""
    result = system_prompt()
    assert result.startswith("You are operating in a Shrike-governed environment.")


def test_system_prompt_names_all_four_refuse_tier_states():
    """The block MUST teach the model to distinguish all four verdict
    states so it doesn't collapse them into a binary allow/deny."""
    result = system_prompt()
    assert "allow" in result
    assert "warn" in result
    assert "block" in result
    assert "require_approval" in result


def test_system_prompt_names_all_three_block_feedback_prefixes():
    """The block teaches the model to recognize each of the three
    prefixes emitted by format_block_feedback / formatBlockFeedback so
    it can react to the injected system message on the next turn.

    Uses whitespace-normalized comparison so intentional hard-wrapping
    of the block (for system-prompt friendliness) doesn't break the
    substring match — a wrapped 'blocked your last\\ntool call' still
    matches 'blocked your last tool call' after normalize.
    """
    normalized = " ".join(system_prompt().split())
    assert '"Shrike blocked your last tool call."' in normalized
    assert '"Shrike flagged your last tool call (advisory)."' in normalized
    assert '"Shrike is holding your last tool call for approval."' in normalized


def test_system_prompt_teaches_rotation_recommendation_contract():
    """The block MUST teach both halves of the rotation contract:
    adopt the suggested id on the next call; do not cache across
    turns because suggestions are per-event."""
    result = system_prompt()
    assert "rotation_recommended" in result
    assert "suggested_new_session_id" in result
    assert "per event" in result


def test_system_prompt_teaches_no_verbatim_retry():
    """The single most-common failure mode after a block is the model
    retrying the same action; the block must instruct otherwise."""
    result = system_prompt()
    assert "do not retry the same action verbatim" in result


def test_system_prompt_teaches_patterns_are_session_scoped():
    """Pattern names emitted by L9 correlator are session-scoped
    signals, not per-turn labels. The block must convey this so the
    model doesn't thrash correcting a single turn."""
    normalized = " ".join(system_prompt().split())
    assert "Patterns triggered" in normalized
    assert "correlator signals across your recent turns" in normalized


def test_system_prompt_uses_collaborator_framing_not_safety():
    """Design decision: the block frames Shrike as a collaborator the
    model listens to, not a safety filter it satisfies. The word
    'safety' is deliberately absent."""
    result = system_prompt()
    assert "collaborator" in result
    assert "safety" not in result.lower()


def test_system_prompt_length_within_target_range():
    """~180-word target. Longer blocks get truncated by devs trying
    to fit their archetype role in front."""
    result = system_prompt()
    word_count = len(result.split())
    assert 150 <= word_count <= 220, (
        f"block length is {word_count} words; target range is 150-220"
    )


def test_system_prompt_is_stable_across_calls():
    """Function returns the same string on repeated calls — no
    randomization, no per-call generation."""
    assert system_prompt() == system_prompt()


def test_system_prompt_version_string_matches_semver_shape():
    """Version metadata is exported alongside the function so
    integrators can pin behavior without pinning the whole SDK."""
    assert isinstance(SYSTEM_PROMPT_VERSION, str)
    parts = SYSTEM_PROMPT_VERSION.split(".")
    assert len(parts) == 2 or len(parts) == 3
    assert all(p.isdigit() for p in parts)


def test_system_prompt_public_export():
    """Helper is re-exported at the top-level shrike_guard namespace
    so integrators can use `from shrike_guard import system_prompt`."""
    from shrike_guard import system_prompt as top_level

    assert top_level is system_prompt
