"""Tests pinning the /api/scan/enforce wire migration.

Verifies:
1. All wrapper URLs point at /api/scan/enforce (never /scan or /api/scan).
2. _is_blocked() prefers the server-authoritative `action` field.
3. Downgrade fallback: verdicts without `action` fall back to `safe`.

Contract-symmetry test — must pass for every SDK release. If the TypeScript
SDK diverges on these invariants, that is a bug in one of the two SDKs.
"""

from unittest import mock

import httpx
import pytest

from shrike_guard import ShrikeAsyncOpenAI, ShrikeBlockedError, ShrikeOpenAI
from shrike_guard.scanner import AsyncScanClient, ScanClient, _is_blocked


# ---------------------------------------------------------------------------
# _is_blocked — action-authoritative block decision
# ---------------------------------------------------------------------------


class TestIsBlocked:
    """The single source of truth for proceed-vs-refuse in the SDK."""

    def test_action_block_returns_true(self) -> None:
        assert _is_blocked({"action": "block", "safe": False}) is True

    def test_action_require_approval_returns_true(self) -> None:
        # Held actions are refused at the tool-call boundary. Caller can
        # re-issue after approval lands.
        assert _is_blocked({"action": "require_approval", "safe": False}) is True

    def test_action_allow_returns_false(self) -> None:
        assert _is_blocked({"action": "allow", "safe": True}) is False

    def test_action_warn_returns_false(self) -> None:
        # warn is advisory — surface via block-feedback but do not refuse.
        assert _is_blocked({"action": "warn", "safe": True}) is False

    def test_action_overrides_safe_when_present(self) -> None:
        # If action is authoritative, safe becomes descriptive-only.
        assert _is_blocked({"action": "block", "safe": True}) is True
        assert _is_blocked({"action": "allow", "safe": False}) is False

    def test_missing_action_falls_back_to_safe_false(self) -> None:
        # Old backend / circuit-breaker synthetic verdict.
        assert _is_blocked({"safe": False, "reason": "..."}) is True

    def test_missing_action_falls_back_to_safe_true(self) -> None:
        assert _is_blocked({"safe": True}) is False

    def test_missing_action_and_safe_defaults_to_allow(self) -> None:
        # Fail-open on empty verdict — matches historical SDK behavior.
        assert _is_blocked({}) is False

    def test_empty_action_string_falls_back_to_safe(self) -> None:
        # Falsy action → treat as absent, fall through to safe.
        assert _is_blocked({"action": "", "safe": False}) is True
        assert _is_blocked({"action": "", "safe": True}) is False


# ---------------------------------------------------------------------------
# URL migration — every wrapper POSTs to /api/scan/enforce
# ---------------------------------------------------------------------------


def _stub_ok(monkeypatch_target: object, method_name: str) -> mock.Mock:
    """Return a Mock that impersonates a 200 OK httpx.Response."""
    resp = mock.Mock()
    resp.status_code = 200
    resp.headers = {}
    resp.raise_for_status = mock.Mock()
    resp.json = mock.Mock(return_value={"safe": True, "action": "allow"})
    return resp


class TestUrlMigration:
    """URL swap must land in every wrapper. Contract-symmetry pinned."""

    def test_scan_client_scan_hits_enforce_endpoint(self) -> None:
        client = ScanClient(api_key="test-key", endpoint="https://example.test")
        with mock.patch.object(client._http, "post") as mock_post:
            mock_post.return_value = _stub_ok(client, "scan")
            client.scan("hello")
        url = mock_post.call_args[0][0]
        assert url == "https://example.test/api/scan/enforce", (
            f"ScanClient.scan must POST to /api/scan/enforce; got {url}"
        )

    def test_scan_client_scan_sql_hits_enforce_specialized(self) -> None:
        client = ScanClient(api_key="test-key", endpoint="https://example.test")
        with mock.patch.object(client._http, "post") as mock_post:
            mock_post.return_value = _stub_ok(client, "scan_sql")
            client.scan_sql("SELECT 1")
        url = mock_post.call_args[0][0]
        assert url == "https://example.test/api/scan/enforce/specialized", (
            f"ScanClient.scan_sql must POST to /api/scan/enforce/specialized; got {url}"
        )

    def test_scan_client_scan_file_hits_enforce_specialized(self) -> None:
        client = ScanClient(api_key="test-key", endpoint="https://example.test")
        with mock.patch.object(client._http, "post") as mock_post:
            mock_post.return_value = _stub_ok(client, "scan_file")
            client.scan_file("/tmp/x")
        url = mock_post.call_args[0][0]
        assert url == "https://example.test/api/scan/enforce/specialized", (
            f"ScanClient.scan_file must POST to /api/scan/enforce/specialized; got {url}"
        )

    @pytest.mark.asyncio
    async def test_async_scan_client_scan_hits_enforce_endpoint(self) -> None:
        client = AsyncScanClient(api_key="test-key", endpoint="https://example.test")

        async def fake_post(url, **kwargs):
            return _stub_ok(client, "scan")

        with mock.patch.object(client._http, "post", side_effect=fake_post) as mock_post:
            await client.scan("hello")
        url = mock_post.call_args[0][0]
        assert url == "https://example.test/api/scan/enforce", (
            f"AsyncScanClient.scan must POST to /api/scan/enforce; got {url}"
        )

    def test_shrike_openai_wrapper_hits_enforce_endpoint(self) -> None:
        client = ShrikeOpenAI(
            api_key="sk-test",
            shrike_api_key="shrike-test",
            shrike_endpoint="https://example.test",
        )
        with mock.patch.object(client._http, "post") as mock_post:
            mock_post.return_value = _stub_ok(client, "remote_scan")
            client._remote_scan("hello")
        url = mock_post.call_args[0][0]
        assert url == "https://example.test/api/scan/enforce"
        client.close()


# ---------------------------------------------------------------------------
# ShrikeOpenAI end-to-end: enforce-shape verdict routes through _is_blocked
# ---------------------------------------------------------------------------


class TestShrikeOpenAIEnforceIntegration:
    """The wrapper honors the server-authoritative action field."""

    def _make_client(self) -> ShrikeOpenAI:
        return ShrikeOpenAI(
            api_key="sk-test",
            shrike_api_key="shrike-test",
            shrike_endpoint="https://example.test",
        )

    def test_action_block_raises_shrike_blocked_error(self) -> None:
        client = self._make_client()
        blocked_verdict = {
            "action": "block",
            "safe": False,
            "reason": "prompt injection detected",
            "threat_type": "prompt_injection",
            "violations": [{"threat_type": "prompt_injection"}],
        }
        stub = mock.Mock()
        stub.status_code = 200
        stub.headers = {}
        stub.raise_for_status = mock.Mock()
        stub.json = mock.Mock(return_value=blocked_verdict)
        with mock.patch.object(client._http, "post", return_value=stub):
            with pytest.raises(ShrikeBlockedError):
                client.chat.completions.create(
                    messages=[{"role": "user", "content": "malicious"}]
                )
        client.close()

    def test_action_allow_proceeds_to_openai(self) -> None:
        client = self._make_client()
        allow_verdict = {"action": "allow", "safe": True}
        stub = mock.Mock()
        stub.status_code = 200
        stub.headers = {}
        stub.raise_for_status = mock.Mock()
        stub.json = mock.Mock(return_value=allow_verdict)
        # Stub the OpenAI call so we can assert the wrapper reached it.
        with mock.patch.object(client._http, "post", return_value=stub), \
             mock.patch.object(client._openai.chat.completions, "create") as mock_openai:
            mock_openai.return_value = mock.Mock()
            client.chat.completions.create(
                messages=[{"role": "user", "content": "hello"}]
            )
        assert mock_openai.called, "allow verdict should reach OpenAI proxy call"
        client.close()

    def test_missing_action_falls_back_to_safe_field(self) -> None:
        """Downgrade path: server predates enforce endpoint."""
        client = self._make_client()
        # No `action` field — legacy /api/scan shape.
        legacy_blocked_verdict = {
            "safe": False,
            "reason": "prompt injection",
            "threat_type": "prompt_injection",
            "violations": [],
        }
        stub = mock.Mock()
        stub.status_code = 200
        stub.headers = {}
        stub.raise_for_status = mock.Mock()
        stub.json = mock.Mock(return_value=legacy_blocked_verdict)
        with mock.patch.object(client._http, "post", return_value=stub):
            with pytest.raises(ShrikeBlockedError):
                client.chat.completions.create(
                    messages=[{"role": "user", "content": "malicious"}]
                )
        client.close()

    def test_action_warn_does_not_block(self) -> None:
        """Warn is advisory — proceed but surface via block-feedback."""
        client = self._make_client()
        warn_verdict = {"action": "warn", "safe": True, "refuse_tier": "warn"}
        stub = mock.Mock()
        stub.status_code = 200
        stub.headers = {}
        stub.raise_for_status = mock.Mock()
        stub.json = mock.Mock(return_value=warn_verdict)
        with mock.patch.object(client._http, "post", return_value=stub), \
             mock.patch.object(client._openai.chat.completions, "create") as mock_openai:
            mock_openai.return_value = mock.Mock()
            client.chat.completions.create(
                messages=[{"role": "user", "content": "borderline"}]
            )
        assert mock_openai.called, "warn should proceed to OpenAI, not raise"
        client.close()
