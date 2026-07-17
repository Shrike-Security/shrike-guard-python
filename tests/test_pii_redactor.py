"""Tests for shrike_guard.pii_redactor — roundtrip parity with MCP server."""

import re

import pytest

from shrike_guard.pii_redactor import (
    PIIPattern,
    RedactionEntry,
    get_pii_pattern_count,
    get_redaction_summary,
    redact_pii,
    rehydrate_pii,
    update_pii_patterns,
)


@pytest.fixture(autouse=True)
def restore_default_patterns():
    """Snapshot + restore the active pattern list per test."""
    from shrike_guard import pii_redactor

    snapshot = list(pii_redactor._active_patterns)
    yield
    pii_redactor._active_patterns = snapshot


class TestRedactPII:
    def test_returns_unchanged_text_when_no_pii(self):
        result = redact_pii("Hello, this is a normal message.")
        assert result.pii_detected is False
        assert result.redacted_text == "Hello, this is a normal message."
        assert result.redaction_count == 0
        assert result.redactions == []

    def test_redacts_single_email(self):
        result = redact_pii("Contact john@acme.com for details.")
        assert result.pii_detected is True
        assert result.redacted_text == "Contact [EMAIL_1] for details."
        assert result.redaction_count == 1
        assert result.redactions[0].token == "[EMAIL_1]"
        assert result.redactions[0].original == "john@acme.com"
        assert result.redactions[0].type == "email"

    def test_redacts_multiple_emails_with_unique_tokens(self):
        result = redact_pii("Email john@acme.com and jane@acme.com about the meeting.")
        assert result.redacted_text == "Email [EMAIL_1] and [EMAIL_2] about the meeting."
        assert result.redaction_count == 2
        assert result.redactions[0].token == "[EMAIL_1]"
        assert result.redactions[1].token == "[EMAIL_2]"

    def test_redacts_phone_numbers(self):
        result = redact_pii("Call me at 555-123-4567.")
        assert result.pii_detected is True
        assert result.redacted_text == "Call me at [PHONE_1]."
        assert result.redactions[0].type == "phone"

    def test_redacts_ssn(self):
        result = redact_pii("My SSN is 123-45-6789.")
        assert result.pii_detected is True
        assert result.redacted_text == "My SSN is [SSN_1]."
        assert result.redactions[0].type == "ssn"

    def test_redacts_credit_card_contiguous(self):
        result = redact_pii("Card number: 4111111111111111")
        assert result.pii_detected is True
        assert result.redacted_text == "Card number: [CARD_1]"
        assert result.redactions[0].type == "credit_card"

    def test_redacts_credit_card_hyphenated(self):
        result = redact_pii("My card is 4532-8721-0039-4456")
        assert result.pii_detected is True
        assert result.redacted_text == "My card is [CARD_1]"
        assert result.redactions[0].original == "4532-8721-0039-4456"

    def test_redacts_credit_card_spaced(self):
        result = redact_pii("Card: 5425 2334 3010 9903")
        assert result.pii_detected is True
        assert result.redacted_text == "Card: [CARD_1]"
        assert result.redactions[0].type == "credit_card"

    def test_redacts_aws_key(self):
        result = redact_pii("Key: AKIAIOSFODNN7EXAMPLE")
        assert result.pii_detected is True
        assert result.redacted_text == "Key: [AWSKEY_1]"
        assert result.redactions[0].type == "aws_key"

    def test_redacts_ip_address(self):
        result = redact_pii("Server at 192.168.1.100")
        assert result.pii_detected is True
        assert result.redacted_text == "Server at [IP_1]"
        assert result.redactions[0].type == "ip_address"

    def test_redacts_multiple_pii_types(self):
        result = redact_pii("Send to john@acme.com at 555-123-4567. SSN: 123-45-6789")
        assert result.pii_detected is True
        assert result.redaction_count == 3
        types = [r.type for r in result.redactions]
        assert "email" in types
        assert "phone" in types
        assert "ssn" in types

    def test_redacts_private_key_marker(self):
        result = redact_pii("-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAK...")
        assert result.pii_detected is True
        assert result.redactions[0].type == "private_key"

    def test_redacts_dob(self):
        result = redact_pii("DOB: 01/15/1990")
        assert result.pii_detected is True
        assert result.redactions[0].type == "dob"

    def test_redacts_street_address(self):
        result = redact_pii("Lives at 123 Main Street")
        assert result.pii_detected is True
        assert result.redactions[0].type == "address"


class TestRehydratePII:
    def test_replaces_tokens_with_original_values(self):
        redactions = [RedactionEntry("[EMAIL_1]", "john@acme.com", "email", 8)]
        result = rehydrate_pii("Contact [EMAIL_1] for details.", redactions)
        assert result == "Contact john@acme.com for details."

    def test_handles_multiple_tokens(self):
        redactions = [
            RedactionEntry("[EMAIL_1]", "john@acme.com", "email", 0),
            RedactionEntry("[EMAIL_2]", "jane@acme.com", "email", 20),
        ]
        result = rehydrate_pii(
            "Email [EMAIL_1] and [EMAIL_2] about the meeting.", redactions
        )
        assert result == "Email john@acme.com and jane@acme.com about the meeting."

    def test_handles_repeated_tokens_from_llm_output(self):
        redactions = [RedactionEntry("[EMAIL_1]", "john@acme.com", "email", 0)]
        result = rehydrate_pii(
            "I sent to [EMAIL_1]. Confirming [EMAIL_1] received it.", redactions
        )
        assert result == "I sent to john@acme.com. Confirming john@acme.com received it."

    def test_returns_text_unchanged_when_no_redactions(self):
        assert rehydrate_pii("No PII here.", []) == "No PII here."

    def test_roundtrip_redact_then_rehydrate(self):
        original = "Email john@acme.com and call 555-123-4567."
        redacted = redact_pii(original)
        restored = rehydrate_pii(redacted.redacted_text, redacted.redactions)
        assert restored == original


class TestRedactionSummary:
    def test_counts_pii_types(self):
        redactions = [
            RedactionEntry("[EMAIL_1]", "a@b.com", "email", 0),
            RedactionEntry("[EMAIL_2]", "c@d.com", "email", 10),
            RedactionEntry("[PHONE_1]", "555-1234", "phone", 20),
        ]
        assert get_redaction_summary(redactions) == {"email": 2, "phone": 1}

    def test_returns_empty_for_no_redactions(self):
        assert get_redaction_summary([]) == {}


class TestUpdatePatterns:
    def test_initial_pattern_count_nonzero(self):
        assert get_pii_pattern_count() > 0

    def test_replaces_patterns_with_custom_set(self):
        custom = [
            PIIPattern(
                name="test_iban",
                regex=re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}[A-Z0-9]{0,16}\b"),
                prefix="IBAN",
            ),
        ]
        update_pii_patterns(custom)
        assert get_pii_pattern_count() == 1

        result = redact_pii("Transfer to GB29NWBK60161331926819")
        assert result.pii_detected is True
        assert result.redacted_text == "Transfer to [IBAN_1]"
        assert result.redactions[0].type == "test_iban"

    def test_replacement_removes_default_patterns(self):
        update_pii_patterns([])
        assert get_pii_pattern_count() == 0
        result = redact_pii("Email john@acme.com")
        assert result.pii_detected is False
