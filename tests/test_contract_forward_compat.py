"""Contract FORWARD-COMPATIBILITY suite (Python SDK).

Mirror of the TypeScript SDK's contract-forward-compat.test.ts. Pins one
promise: an ADDITIVE change on the backend scanner (a new response field, a
new threat-type string, a new refuse tier) must NOT
  (a) crash a shipped client,
  (b) fail OPEN (treat a blocked verdict as safe), or
  (c) require an emergency republish to stay correct.

Complement of test_contract_symmetry.py (which pins the PRESERVATION
direction). A failure here means a scanner change is one release away from
breaking every installed copy of this SDK — treat as publish-blocking.
"""

from shrike_guard.scanner import _is_blocked
from shrike_guard.sanitizer import (
    sanitize_scan_response,
    normalize_threat_type,
    derive_severity,
    bucket_confidence,
)


class TestAdditiveChangesDoNotCrash:
    def test_ignores_unrecognized_top_level_field(self):
        raw = {
            "safe": False,
            "action": "block",
            "threat_type": "jailbreak",
            "cognitive_load_index": {"score": 0.91, "band": "elevated"},
        }
        out = sanitize_scan_response(raw)  # must not raise
        assert out["safe"] is False
        assert out["action"] == "block"
        assert out["threat_type"] == "jailbreak"

    def test_unrecognized_violation_field_passes_through(self):
        raw = {
            "safe": False,
            "action": "block",
            "violations": [
                {
                    "threat_type": "sql_injection",
                    "severity": "critical",
                    "remediation_playbook_id": "pb-42",
                }
            ],
        }
        out = sanitize_scan_response(raw)
        assert out["violations"][0]["remediation_playbook_id"] == "pb-42"
        # ...but attribution is still stripped.
        polluted = sanitize_scan_response(
            {
                "safe": False,
                "violations": [
                    {"threat_type": "sql_injection", "matched_pattern": "LEAK",
                     "ai_reasoning": "LEAK"}
                ],
            }
        )
        assert "matched_pattern" not in polluted["violations"][0]
        assert "ai_reasoning" not in polluted["violations"][0]

    def test_unknown_threat_type_buckets_to_unknown(self):
        assert normalize_threat_type("quantum_prompt_smuggling_v3") == "unknown"
        out = sanitize_scan_response(
            {"safe": False, "action": "block",
             "threat_type": "quantum_prompt_smuggling_v3"}
        )
        assert out["threat_type"] == "unknown"
        assert out["guidance"]

    def test_unknown_severity_falls_back(self):
        assert derive_severity("sql_injection", "catastrophic") == "critical"
        assert derive_severity("unknown", "catastrophic") == "medium"

    def test_confidence_wrong_type_does_not_crash(self):
        assert bucket_confidence(None) == "medium"
        out = sanitize_scan_response(
            {"safe": False, "action": "block", "confidence": "very-high"}
        )
        assert out["confidence"] == "medium"


class TestOmittedFieldsDegradeSafely:
    def test_blocks_when_action_absent_but_unsafe(self):
        assert _is_blocked({"safe": False}) is True
        assert _is_blocked({"safe": True}) is False

    def test_recovery_and_session_state_optional(self):
        out = sanitize_scan_response({"safe": True, "action": "allow"})
        assert out["safe"] is True
        assert "recovery" not in out
        assert "session_state" not in out


class TestMalformedShapesDoNotCrash:
    def test_non_list_violations_dropped(self):
        sanitize_scan_response({"safe": False, "violations": {"not": "a list"}})

    def test_null_and_nonobject_violation_entries_filtered(self):
        out = sanitize_scan_response(
            {"safe": False,
             "violations": [None, "a string", {"threat_type": "jailbreak"}]}
        )
        assert len(out["violations"]) == 1
        assert out["violations"][0]["threat_type"] == "jailbreak"

    def test_empty_body_does_not_crash(self):
        sanitize_scan_response({})


class TestRefuseTierEnumFailsClosed:
    def test_known_non_blocking_tiers_proceed(self):
        assert _is_blocked({"safe": True, "action": "allow"}) is False
        assert _is_blocked({"safe": True, "action": "warn"}) is False

    def test_known_blocking_tiers_refuse(self):
        assert _is_blocked({"safe": False, "action": "block"}) is True
        assert _is_blocked({"safe": False, "action": "require_approval"}) is True

    def test_unknown_blocking_tier_fails_closed(self):
        # THE CRUX: a new blocking tier the SDK has never seen, carrying
        # safe=False, must refuse — not proceed. Fail-OPEN here would force an
        # emergency republish the moment the scanner adds a tier.
        assert _is_blocked({"safe": False, "action": "quarantine"}) is True
        assert _is_blocked({"safe": False, "action": "block_and_lock"}) is True

    def test_unknown_tier_with_safe_verdict_proceeds(self):
        assert _is_blocked({"safe": True, "action": "observe_only"}) is False
