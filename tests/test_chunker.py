"""Tests for shrike_guard.chunker — the client-side auto-chunk path for
large scan inputs. Mirrors platform/sdks/typescript/tests/unit/chunker.test.ts.
"""

from shrike_guard.chunker import (
    AUTO_CHUNK_THRESHOLD,
    CHUNK_TARGET_SIZE,
    aggregate_chunk_results,
    chunk_content,
)


class TestChunkContent:
    def test_returns_single_chunk_when_content_fits(self):
        assert chunk_content("short content") == ["short content"]

    def test_never_returns_zero_chunks_for_nonempty_input(self):
        assert len(chunk_content("x")) == 1

    def test_never_returns_zero_chunks_for_empty_input(self):
        assert len(chunk_content("")) == 1

    def test_splits_on_paragraph_boundaries(self):
        p = "a" * 4000
        chunks = chunk_content(f"{p}\n\n{p}\n\n{p}", target_size=5000)
        assert len(chunks) == 3
        for c in chunks:
            assert len(c) <= 5000

    def test_splits_oversized_paragraph_on_line_boundaries(self):
        line = "a" * 1000
        big_paragraph = "\n".join([line] * 10)
        chunks = chunk_content(big_paragraph, target_size=3500)
        assert len(chunks) > 1
        for c in chunks:
            assert len(c) <= 3500

    def test_hard_cuts_single_oversized_line_as_last_resort(self):
        single_line = "a" * 20_000
        chunks = chunk_content(single_line, target_size=5000)
        assert len(chunks) > 1
        for c in chunks:
            assert len(c) <= 5000
        # Every byte of the original is preserved somewhere
        assert len("".join(chunks)) == 20_000

    def test_auto_chunk_threshold_is_20kb(self):
        assert AUTO_CHUNK_THRESHOLD == 20 * 1024

    def test_chunk_target_size_is_8kb(self):
        assert CHUNK_TARGET_SIZE == 8 * 1024


class TestAggregateChunkResults:
    def test_returns_safe_verdict_for_empty_results(self):
        agg = aggregate_chunk_results([])
        assert agg["safe"] is True
        assert agg["action"] == "allow"

    def test_returns_single_result_verbatim(self):
        input_result = {"safe": False, "threat_type": "x"}
        assert aggregate_chunk_results([input_result]) is input_result

    def test_all_safe_aggregates_to_safe(self):
        results = [
            {"safe": True, "action": "allow"},
            {"safe": True, "action": "allow"},
            {"safe": True, "action": "allow"},
        ]
        agg = aggregate_chunk_results(results)
        assert agg["safe"] is True
        assert agg["action"] == "allow"
        assert agg["refuse_tier"] == "allow"

    def test_picks_worst_action(self):
        results = [
            {"safe": True, "action": "allow"},
            {"safe": True, "action": "warn"},
            {"safe": False, "action": "block"},
        ]
        agg = aggregate_chunk_results(results)
        assert agg["safe"] is False
        assert agg["action"] == "block"
        assert agg["refuse_tier"] == "block"

    def test_tags_reason_with_chunk_index(self):
        results = [
            {"safe": True, "action": "allow"},
            {"safe": False, "action": "block", "reason": "prompt injection detected"},
            {"safe": True, "action": "allow"},
        ]
        agg = aggregate_chunk_results(results)
        assert "chunk 2 of 3" in agg["reason"]
        assert "prompt injection detected" in agg["reason"]

    def test_deduplicates_violations(self):
        results = [
            {
                "safe": False,
                "action": "block",
                "violations": [
                    {"threat_type": "prompt_injection", "severity": "high", "action": "block"}
                ],
            },
            {
                "safe": False,
                "action": "block",
                "violations": [
                    {"threat_type": "prompt_injection", "severity": "high", "action": "block"},
                    {"threat_type": "pii_exposure", "severity": "medium", "action": "redact"},
                ],
            },
        ]
        agg = aggregate_chunk_results(results)
        assert len(agg["violations"]) == 2

    def test_preserves_recovery_from_first_unsafe_chunk(self):
        results = [
            {"safe": True, "action": "allow"},
            {
                "safe": False,
                "action": "block",
                "recovery": {"instruction": "stop and start new session"},
            },
            {
                "safe": False,
                "action": "block",
                "recovery": {"instruction": "different, not this one"},
            },
        ]
        agg = aggregate_chunk_results(results)
        assert agg["recovery"]["instruction"] == "stop and start new session"

    def test_takes_session_state_from_last_chunk(self):
        results = [
            {"safe": True, "action": "allow", "session_state": {"session_risk_score": 0.1}},
            {"safe": True, "action": "allow", "session_state": {"session_risk_score": 0.5}},
        ]
        agg = aggregate_chunk_results(results)
        assert agg["session_state"]["session_risk_score"] == 0.5

    def test_require_approval_beats_warn(self):
        results = [
            {"safe": True, "action": "allow"},
            {"safe": True, "action": "warn"},
            {"safe": False, "action": "require_approval"},
        ]
        agg = aggregate_chunk_results(results)
        assert agg["action"] == "require_approval"
