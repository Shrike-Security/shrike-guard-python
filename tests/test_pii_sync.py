"""Tests for shrike_guard.pii_sync — mocks the backend via httpx.MockTransport."""

from __future__ import annotations

import json
from typing import Any, Callable, Dict

import httpx
import pytest

from shrike_guard import pii_redactor
from shrike_guard.pii_sync import sync_pii_patterns


@pytest.fixture(autouse=True)
def restore_default_patterns():
    """Snapshot + restore the active pattern list per test."""
    snapshot = list(pii_redactor._active_patterns)
    yield
    pii_redactor._active_patterns = snapshot


GOOD_PAYLOAD: Dict[str, Any] = {
    "patterns": [
        {
            "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
            "threat_type": "pii_ssn",
            "confidence": 0.95,
            "description": "US SSN",
        },
        {
            "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            "threat_type": "pii_email",
            "confidence": 0.9,
            "description": "Email address",
        },
        {
            "pattern": r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}[A-Z0-9]{0,16}\b",
            "threat_type": "pii_iban",
            "confidence": 0.85,
            "description": "IBAN",
        },
    ],
    "total": 3,
    "version": "2026-06-30",
}


def _mock_client(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.Client:
    """Build an httpx.Client wired to a MockTransport using `handler`."""
    return httpx.Client(transport=httpx.MockTransport(handler))


class TestSyncSuccess:
    def test_replaces_bootstrap_patterns_with_backend_set(self):
        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=GOOD_PAYLOAD)

        with _mock_client(handler) as c:
            ok = sync_pii_patterns("https://api.shrikesecurity.com", client=c)

        assert ok is True
        assert pii_redactor.get_pii_pattern_count() == 3

        # Confirm the wider coverage actually fires on an IBAN — proves the
        # backend set replaced the bootstrap.
        result = pii_redactor.redact_pii("Transfer to GB29NWBK60161331926819 please")
        assert result.pii_detected
        assert result.redactions[0].type == "iban"
        assert result.redacted_text.startswith("Transfer to [IBAN_")

    def test_sends_authorization_header_when_api_key_given(self):
        seen: Dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["headers"] = dict(request.headers)
            seen["url"] = str(request.url)
            return httpx.Response(200, json=GOOD_PAYLOAD)

        with _mock_client(handler) as c:
            sync_pii_patterns(
                "https://api.shrikesecurity.com/",
                api_key="shrike_test_key",
                client=c,
            )

        assert seen["headers"].get("authorization") == "Bearer shrike_test_key"
        assert seen["url"] == "https://api.shrikesecurity.com/api/pii/patterns"

    def test_skips_authorization_when_no_api_key(self):
        seen: Dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["headers"] = dict(request.headers)
            return httpx.Response(200, json=GOOD_PAYLOAD)

        with _mock_client(handler) as c:
            sync_pii_patterns("https://api.shrikesecurity.com", client=c)

        assert "authorization" not in seen["headers"]


class TestSyncFailurePreservesFallback:
    def test_network_error_keeps_bootstrap(self):
        fallback_count = pii_redactor.get_pii_pattern_count()

        def handler(_request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("conn refused")

        with _mock_client(handler) as c:
            ok = sync_pii_patterns("https://api.shrikesecurity.com", client=c)

        assert ok is False
        assert pii_redactor.get_pii_pattern_count() == fallback_count

    def test_timeout_keeps_bootstrap(self):
        fallback_count = pii_redactor.get_pii_pattern_count()

        def handler(_request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("slow")

        with _mock_client(handler) as c:
            ok = sync_pii_patterns("https://api.shrikesecurity.com", client=c)

        assert ok is False
        assert pii_redactor.get_pii_pattern_count() == fallback_count

    def test_non_200_keeps_bootstrap(self):
        fallback_count = pii_redactor.get_pii_pattern_count()

        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="oops")

        with _mock_client(handler) as c:
            ok = sync_pii_patterns("https://api.shrikesecurity.com", client=c)

        assert ok is False
        assert pii_redactor.get_pii_pattern_count() == fallback_count

    def test_malformed_json_keeps_bootstrap(self):
        fallback_count = pii_redactor.get_pii_pattern_count()

        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="not json")

        with _mock_client(handler) as c:
            ok = sync_pii_patterns("https://api.shrikesecurity.com", client=c)

        assert ok is False
        assert pii_redactor.get_pii_pattern_count() == fallback_count

    def test_empty_pattern_list_keeps_bootstrap(self):
        fallback_count = pii_redactor.get_pii_pattern_count()

        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"patterns": [], "total": 0, "version": "v"})

        with _mock_client(handler) as c:
            ok = sync_pii_patterns("https://api.shrikesecurity.com", client=c)

        assert ok is False
        assert pii_redactor.get_pii_pattern_count() == fallback_count

    def test_all_unparseable_regex_keeps_bootstrap(self):
        """Post-2026-07-02 contract: unknown threat_types no longer silently
        drop — they derive a fallback prefix (see the backend-owned prefix
        class below). So "everything → keep fallback" only fires when the
        backend gives us nothing PARSEABLE.
        """
        fallback_count = pii_redactor.get_pii_pattern_count()
        payload = {
            "patterns": [
                {"pattern": r"[invalid", "threat_type": "pii_ssn", "confidence": 0.9, "description": "broken"},
            ],
            "total": 1,
            "version": "v",
        }

        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=payload)

        with _mock_client(handler) as c:
            ok = sync_pii_patterns("https://api.shrikesecurity.com", client=c)

        assert ok is False
        assert pii_redactor.get_pii_pattern_count() == fallback_count

    def test_unparseable_regex_is_skipped_but_others_apply(self):
        """One bad regex among many shouldn't kill the whole sync."""
        payload = {
            "patterns": [
                {"pattern": r"[invalid", "threat_type": "pii_ssn", "confidence": 0.9, "description": "broken"},
                {"pattern": r"\bok@example\.com\b", "threat_type": "pii_email", "confidence": 0.9, "description": "ok"},
            ],
            "total": 2,
            "version": "v",
        }

        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=payload)

        with _mock_client(handler) as c:
            ok = sync_pii_patterns("https://api.shrikesecurity.com", client=c)

        assert ok is True
        # Only the valid pattern got applied
        assert pii_redactor.get_pii_pattern_count() == 1


class TestCaseInsensitiveMatching:
    """Regression: backend patterns are authored lowercase without a `(?i)`
    inline flag. Sync must compile them case-insensitively to match MCP TS
    behavior. Otherwise a customer prompt like "Phone: 555-123-4567" won't
    match the backend's `phone...` pattern.
    """

    def test_capitalized_input_matches_lowercase_backend_pattern(self):
        # The backend serves this pattern lowercase. Without (?i), an input
        # containing "Phone" (capitalized — the realistic user case) wouldn't
        # match. The phone pattern is the cleanest case-insensitivity test
        # because its anchor word is unambiguously letter-cased.
        payload = {
            "patterns": [
                {
                    "pattern": r"(?:phone|tel|mobile|cell)[\s:]*\+?\d[\d\s().-]{7,}",
                    "threat_type": "pii_phone",
                    "confidence": 0.9,
                    "description": "Phone with context",
                },
            ],
            "total": 1,
            "version": "v",
        }

        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=payload)

        with _mock_client(handler) as c:
            sync_pii_patterns("https://api.shrikesecurity.com", client=c)

        result = pii_redactor.redact_pii("Phone: 555-123-4567")
        assert result.pii_detected, "Capitalized 'Phone' must match lowercase backend pattern"
        assert result.redactions[0].type == "phone"


class TestEndpointConstruction:
    def test_strips_trailing_slash(self):
        seen: Dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["url"] = str(request.url)
            return httpx.Response(200, json=GOOD_PAYLOAD)

        with _mock_client(handler) as c:
            sync_pii_patterns("https://api.shrikesecurity.com///", client=c)

        assert seen["url"] == "https://api.shrikesecurity.com/api/pii/patterns"


class TestBackendOwnedPrefixContract:
    """Regression guard: the SDK's _PREFIX_MAP allowlist once silently
    dropped any backend PII pattern whose threat_type wasn't in the
    hardcoded list. A newly-added ``pii_ip_address`` recognizer never
    redacted client-side even though the backend detected it. Same bug
    the MCP + TS SDK had; retired the allowlist and switched to
    backend-shipped prefix + fallback derivation.
    """

    def test_uses_backend_shipped_prefix_verbatim(self):
        payload = {
            "patterns": [
                {
                    "pattern": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
                    "threat_type": "pii_ip_address",
                    "prefix": "IP",
                    "confidence": 0.75,
                    "description": "IPv4",
                },
            ],
            "total": 1,
            "version": "2026-07-02",
        }

        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=payload)

        with _mock_client(handler) as c:
            ok = sync_pii_patterns("https://api.shrikesecurity.com", client=c)

        assert ok is True
        result = pii_redactor.redact_pii("server at 192.168.1.100")
        assert "192.168.1.100" not in result.redacted_text
        # Backend-shipped `IP` — different tag than the fallback `IP_ADDRESS`.
        assert any(r.token.startswith("[IP_") and not r.token.startswith("[IP_ADDRESS") for r in result.redactions)

    def test_falls_back_when_backend_omits_prefix(self):
        """Older backends (pre-2026-07-02) don't ship the prefix field. The
        client must NOT drop the pattern — derives IP_ADDRESS from the
        threat_type instead. Different tag than a modern backend's `IP`
        but redaction still fires. Point: no silent drop.
        """
        payload = {
            "patterns": [
                {
                    "pattern": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
                    "threat_type": "pii_ip_address",
                    "confidence": 0.75,
                    "description": "IPv4",
                },
            ],
            "total": 1,
            "version": "2026-06-01",
        }

        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=payload)

        with _mock_client(handler) as c:
            ok = sync_pii_patterns("https://api.shrikesecurity.com", client=c)

        assert ok is True
        result = pii_redactor.redact_pii("server at 192.168.1.100")
        assert "192.168.1.100" not in result.redacted_text
        assert any(r.token.startswith("[IP_ADDRESS_") for r in result.redactions)

    def test_never_silently_drops_unknown_threat_types(self):
        """The backend can add a brand-new pattern the SDK has never seen
        and it must land, not disappear. Prior _PREFIX_MAP behavior: drop.
        """
        payload = {
            "patterns": [
                {
                    "pattern": r"0x[a-fA-F0-9]{40}",
                    "threat_type": "pii_wallet_eth",
                    "confidence": 0.9,
                    "description": "ETH wallet",
                },
            ],
            "total": 1,
            "version": "2026-08-01",
        }

        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=payload)

        with _mock_client(handler) as c:
            ok = sync_pii_patterns("https://api.shrikesecurity.com", client=c)

        assert ok is True
        result = pii_redactor.redact_pii(
            "send funds to 0x742d35Cc6634C0532925a3b844Bc9e7595f89999"
        )
        assert "0x742d35Cc6634C0532925a3b844Bc9e7595f89999" not in result.redacted_text
        assert any(r.token.startswith("[WALLET_ETH_") for r in result.redactions)
