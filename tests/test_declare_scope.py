"""Tests for the Scope Tier 1 declare_scope helper on ScanClient +
AsyncScanClient.

The helper is a thin HTTP wrapper — the backend owns the validation
semantics. These tests verify the wire shape stays contract-symmetric
with the backend endpoint (POST /api/v1/agent/scope/declare) and that
optional fields are only serialized when explicitly set.
"""

from typing import Any, Dict, List
from unittest import mock

import httpx
import pytest

from shrike_guard.scanner import AsyncScanClient, ScanClient


def _mock_response(json_body: Dict[str, Any]) -> mock.MagicMock:
    """Build a mock httpx.Response with the given JSON body."""
    resp = mock.MagicMock(spec=httpx.Response)
    resp.status_code = 200
    resp.json.return_value = json_body
    resp.raise_for_status = mock.MagicMock()
    return resp


class TestDeclareScopeSync:
    """Sync ScanClient.declare_scope"""

    def _fixture_client(self) -> ScanClient:
        return ScanClient(api_key="shrike-test", endpoint="https://mock.test")

    def test_minimal_required_fields_only(self) -> None:
        """A minimal call posts only agent_id + allowed_tools."""
        client = self._fixture_client()
        with mock.patch.object(
            client._http,
            "post",
            return_value=_mock_response({"scope_id": "sc_1", "agent_id": "a1"}),
        ) as post:
            result = client.declare_scope(
                agent_id="recon_agent",
                allowed_tools=["read_invoice"],
            )
            url, kwargs = post.call_args.args[0], post.call_args.kwargs
            assert url == "https://mock.test/api/v1/agent/scope/declare"
            assert kwargs["json"] == {
                "agent_id": "recon_agent",
                "allowed_tools": ["read_invoice"],
            }
            assert result["scope_id"] == "sc_1"
        client.close()

    def test_all_optional_fields_serialized_when_set(self) -> None:
        """Every optional field flows to the wire when the caller sets it."""
        client = self._fixture_client()
        with mock.patch.object(
            client._http, "post", return_value=_mock_response({"scope_id": "sc_2"})
        ) as post:
            client.declare_scope(
                agent_id="triage_bot",
                allowed_tools=["read_invoice", "match_ledger_entry"],
                purpose="invoice reconciliation",
                forbidden_tools=["exec_shell", "network_egress"],
                max_duration_seconds=28800,
                expires_at="2026-07-14T23:59:59Z",
            )
            body = post.call_args.kwargs["json"]
            assert body == {
                "agent_id": "triage_bot",
                "allowed_tools": ["read_invoice", "match_ledger_entry"],
                "purpose": "invoice reconciliation",
                "forbidden_tools": ["exec_shell", "network_egress"],
                "max_duration_seconds": 28800,
                "expires_at": "2026-07-14T23:59:59Z",
            }
        client.close()

    def test_optional_fields_absent_when_not_set(self) -> None:
        """Unset optionals must NOT appear as null keys — backend
        distinguishes 'field absent' from 'null value'."""
        client = self._fixture_client()
        with mock.patch.object(
            client._http, "post", return_value=_mock_response({"scope_id": "sc_3"})
        ) as post:
            client.declare_scope(
                agent_id="scoped_agent",
                allowed_tools=["*"],
            )
            body = post.call_args.kwargs["json"]
            for absent in (
                "purpose",
                "forbidden_tools",
                "max_duration_seconds",
                "expires_at",
            ):
                assert absent not in body, f"{absent} should be omitted, got body={body}"
        client.close()

    def test_backend_error_propagates(self) -> None:
        """Non-2xx responses raise via raise_for_status."""
        client = self._fixture_client()
        err_response = mock.MagicMock(spec=httpx.Response)
        err_response.status_code = 400
        err_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "bad request",
            request=mock.MagicMock(),
            response=mock.MagicMock(status_code=400),
        )
        with mock.patch.object(client._http, "post", return_value=err_response):
            with pytest.raises(httpx.HTTPStatusError):
                client.declare_scope(
                    agent_id="ag",
                    allowed_tools=["*"],
                    expires_at="2020-01-01T00:00:00Z",
                )
        client.close()

    def test_wildcard_allowed_tools_passes_through(self) -> None:
        """allowed_tools=['*'] serializes verbatim; the backend interprets it."""
        client = self._fixture_client()
        with mock.patch.object(
            client._http, "post", return_value=_mock_response({"scope_id": "sc_4"})
        ) as post:
            client.declare_scope(agent_id="wide_scope", allowed_tools=["*"])
            body = post.call_args.kwargs["json"]
            assert body["allowed_tools"] == ["*"]
        client.close()


class TestDeclareScopeAsync:
    """Async AsyncScanClient.declare_scope — mirrors sync suite for parity."""

    @pytest.mark.asyncio
    async def test_minimal_required_fields_only(self) -> None:
        client = AsyncScanClient(api_key="shrike-test", endpoint="https://mock.test")
        async_mock = mock.AsyncMock(
            return_value=_mock_response({"scope_id": "sc_1", "agent_id": "a1"})
        )
        with mock.patch.object(client._http, "post", async_mock):
            result = await client.declare_scope(
                agent_id="recon_agent",
                allowed_tools=["read_invoice"],
            )
            url, kwargs = async_mock.call_args.args[0], async_mock.call_args.kwargs
            assert url == "https://mock.test/api/v1/agent/scope/declare"
            assert kwargs["json"] == {
                "agent_id": "recon_agent",
                "allowed_tools": ["read_invoice"],
            }
            assert result["scope_id"] == "sc_1"
        await client.close()

    @pytest.mark.asyncio
    async def test_all_optional_fields_serialized_when_set(self) -> None:
        client = AsyncScanClient(api_key="shrike-test", endpoint="https://mock.test")
        async_mock = mock.AsyncMock(return_value=_mock_response({"scope_id": "sc_2"}))
        with mock.patch.object(client._http, "post", async_mock):
            await client.declare_scope(
                agent_id="triage_bot",
                allowed_tools=["read_invoice"],
                purpose="reconciliation",
                forbidden_tools=["exec_shell"],
                max_duration_seconds=3600,
                expires_at="2026-07-14T23:59:59Z",
            )
            body = async_mock.call_args.kwargs["json"]
            assert body == {
                "agent_id": "triage_bot",
                "allowed_tools": ["read_invoice"],
                "purpose": "reconciliation",
                "forbidden_tools": ["exec_shell"],
                "max_duration_seconds": 3600,
                "expires_at": "2026-07-14T23:59:59Z",
            }
        await client.close()

    @pytest.mark.asyncio
    async def test_optional_fields_absent_when_not_set(self) -> None:
        client = AsyncScanClient(api_key="shrike-test", endpoint="https://mock.test")
        async_mock = mock.AsyncMock(return_value=_mock_response({"scope_id": "sc_3"}))
        with mock.patch.object(client._http, "post", async_mock):
            await client.declare_scope(agent_id="scoped_agent", allowed_tools=["*"])
            body = async_mock.call_args.kwargs["json"]
            for absent in (
                "purpose",
                "forbidden_tools",
                "max_duration_seconds",
                "expires_at",
            ):
                assert absent not in body
        await client.close()
