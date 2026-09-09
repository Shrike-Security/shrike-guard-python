"""Session identity is configured per client, not per process.

Session identity is the key the backend accumulates multi-turn risk against.
Every caller sharing one id shares one risk score, so a server that scans on
behalf of many end users must give each user its own session; otherwise one
user's refusal counts against the next user's action.

Contract-symmetric with tests/unit/session-identity.test.ts and
scanner/session_identity_test.go: if the three disagree about what lands in
the request context, one of them is a bug.
"""

import json
from pathlib import Path
from typing import Any, Dict
from unittest import mock

import httpx
import pytest

from shrike_guard import config
from shrike_guard.scanner import AsyncScanClient, ScanClient

_FIXTURE = json.loads(
    (
        Path(__file__).resolve().parent
        / "fixtures"
        / "contract-symmetry"
        / "canonical-request-shapes.json"
    ).read_text()
)

REQUIRED_IDENTITY = _FIXTURE["session_identity"]["required_context_keys"]
SOURCE_APP = _FIXTURE["session_identity"]["source_application_by_sdk"]["python"]


def _mock_response() -> mock.MagicMock:
    resp = mock.MagicMock(spec=httpx.Response)
    resp.status_code = 200
    resp.json.return_value = {
        "safe": True,
        "action": "allow",
        "refuse_tier": "allow",
        "recovery": {},
        "session_state": {},
    }
    resp.raise_for_status = mock.MagicMock()
    return resp


def _sent_context(post: mock.MagicMock) -> Dict[str, Any]:
    """The context object of the most recent scan request."""
    return post.call_args.kwargs["json"]["context"]


# --- the override reaches the wire ---------------------------------------


def test_explicit_session_id_is_what_gets_sent():
    client = ScanClient(api_key="k", endpoint="https://mock.test", session_id="sess-explicit")
    with mock.patch.object(client._http, "post", return_value=_mock_response()) as post:
        client.scan_command("ls -la")

    ctx = _sent_context(post)
    assert ctx["session_id"] == "sess-explicit"
    # The identity block stays complete — an override replaces one value, it
    # does not drop the others.
    for key in REQUIRED_IDENTITY:
        assert key in ctx, f"{key} missing from the scan context"
    assert ctx["source_application"] == SOURCE_APP


def test_explicit_agent_id_is_what_gets_sent():
    client = ScanClient(api_key="k", endpoint="https://mock.test", agent_id="agent-billing")
    with mock.patch.object(client._http, "post", return_value=_mock_response()) as post:
        client.scan_command("ls -la")

    assert _sent_context(post)["agent_id"] == "agent-billing"


def test_default_still_sends_the_process_identity():
    """No regression for the single-agent caller.

    Removing the default would silently delete multi-turn correlation for every
    CLI and worker that never sets a session id. The default stays; the warning
    is what changed.
    """
    client = ScanClient(api_key="k", endpoint="https://mock.test")
    with mock.patch.object(client._http, "post", return_value=_mock_response()) as post:
        client.scan_command("ls -la")

    ctx = _sent_context(post)
    assert ctx["session_id"] == config.get_session_id()
    assert ctx["agent_id"] == config.get_agent_id()


def test_agent_id_env_override_is_honoured(monkeypatch):
    """The variable named by the fixture (``agent_id_env_override``) names the
    process's agent.

    All three SDKs pin this against the same declaration so they cannot drift
    on the variable name.
    """
    env_var = _FIXTURE["session_identity"]["agent_id_env_override"]
    assert env_var, "fixture declares no agent_id_env_override — the contract moved"
    monkeypatch.setenv(env_var, "agent-from-env")

    # The env override beats the generated process id.
    client = ScanClient(api_key="k", endpoint="https://mock.test")
    with mock.patch.object(client._http, "post", return_value=_mock_response()) as post:
        client.scan_command("ls -la")
        assert _sent_context(post)["agent_id"] == "agent-from-env"

    # An explicit client argument beats the env override.
    explicit = ScanClient(api_key="k", endpoint="https://mock.test", agent_id="agent-explicit")
    with mock.patch.object(explicit._http, "post", return_value=_mock_response()) as post:
        explicit.scan_command("ls -la")
        assert _sent_context(post)["agent_id"] == "agent-explicit", (
            f"an explicit agent_id must outrank {env_var}"
        )


# --- for_session -----------------------------------------------------------


def test_for_session_sends_the_derived_id():
    guard = ScanClient(api_key="k", endpoint="https://mock.test")
    scoped = guard.for_session("sess-request-42")

    with mock.patch.object(guard._http, "post", return_value=_mock_response()) as post:
        scoped.scan_command("ls -la")

    assert _sent_context(post)["session_id"] == "sess-request-42"


def test_two_derived_clients_do_not_share_a_session():
    """The whole point: two end users must not accumulate into one risk score."""
    guard = ScanClient(api_key="k", endpoint="https://mock.test")
    alice = guard.for_session("sess-alice")
    bob = guard.for_session("sess-bob")

    with mock.patch.object(guard._http, "post", return_value=_mock_response()) as post:
        alice.scan_command("ls -la")
        alice_ctx = _sent_context(post)
        bob.scan_command("ls -la")
        bob_ctx = _sent_context(post)

    assert alice_ctx["session_id"] == "sess-alice"
    assert bob_ctx["session_id"] == "sess-bob"
    assert alice_ctx["session_id"] != bob_ctx["session_id"]


def test_for_session_shares_the_connection_pool():
    """Deriving per request must be cheap, or nobody will do it per request."""
    guard = ScanClient(api_key="k", endpoint="https://mock.test")
    scoped = guard.for_session("sess-1")
    assert scoped._http is guard._http


def test_closing_a_derived_client_does_not_close_the_shared_pool():
    """A derived client closing the pool would break every request in flight."""
    guard = ScanClient(api_key="k", endpoint="https://mock.test")
    scoped = guard.for_session("sess-1")

    scoped.close()
    assert not guard._http.is_closed

    guard.close()
    assert guard._http.is_closed


def test_for_session_inherits_the_agent_id_but_can_override_it():
    guard = ScanClient(api_key="k", endpoint="https://mock.test", agent_id="agent-parent")

    inherited = guard.for_session("sess-1")
    overridden = guard.for_session("sess-2", agent_id="agent-child")

    with mock.patch.object(guard._http, "post", return_value=_mock_response()) as post:
        inherited.scan_command("ls -la")
        assert _sent_context(post)["agent_id"] == "agent-parent"
        overridden.scan_command("ls -la")
        assert _sent_context(post)["agent_id"] == "agent-child"


def test_every_channel_carries_the_derived_session():
    """One method wired to the client identity is not enough — all of them.

    This is the shape of bug the act-plane work kept finding: the value exists,
    one path uses it, another path was never connected.
    """
    guard = ScanClient(api_key="k", endpoint="https://mock.test")
    scoped = guard.for_session("sess-everywhere")

    # scan_mcp_schema is deliberately absent — see
    # test_mcp_schema_carries_no_session_identity below.
    calls = [
        ("scan", lambda: scoped.scan("summarize this")),
        ("scan_command", lambda: scoped.scan_command("ls -la")),
        ("scan_sql", lambda: scoped.scan_sql("SELECT 1")),
        ("scan_file", lambda: scoped.scan_file("/tmp/a.txt")),
        ("scan_web_search", lambda: scoped.scan_web_search("owasp")),
        ("scan_rag_context", lambda: scoped.scan_rag_context(["chunk"])),
        ("scan_a2a_message", lambda: scoped.scan_a2a_message("done")),
        ("scan_agent_card", lambda: scoped.scan_agent_card('{"name":"a"}')),
    ]

    with mock.patch.object(guard._http, "post", return_value=_mock_response()) as post:
        for name, call in calls:
            call()
            assert _sent_context(post)["session_id"] == "sess-everywhere", (
                f"{name} did not carry the client's session id — it is reading "
                f"the process default instead of the client"
            )


def test_mcp_schema_carries_no_session_identity():
    """Records current behaviour rather than asserting the target behaviour.

    /api/scan/mcp_schema is not yet part of the session contract: its request
    accepts no context object, and its response carries no refuse_tier,
    recovery or session_state. When the endpoint adopts the contract, this
    test fails and mcp_schema moves into the channel loop above.
    """
    guard = ScanClient(api_key="k", endpoint="https://mock.test")
    scoped = guard.for_session("sess-everywhere")

    with mock.patch.object(guard._http, "post", return_value=_mock_response()) as post:
        scoped.scan_mcp_schema("t", "desc", {})
        payload = post.call_args.kwargs["json"]

    assert "context" not in payload, (
        "scan_mcp_schema now sends a context — if the backend learned to read "
        "it, delete this test and add mcp_schema to the channel loop above"
    )


@pytest.mark.asyncio
async def test_async_client_supports_the_same_shape():
    """Parity within the SDK: the async client is the multi-user case.

    An async server is the deployment most likely to serve many end users from
    one process, so the async client losing this would defeat the fix.
    """
    guard = AsyncScanClient(api_key="k", endpoint="https://mock.test")
    scoped = guard.for_session("sess-async")

    assert scoped._http is guard._http

    resp = _mock_response()
    with mock.patch.object(guard._http, "post", new=mock.AsyncMock(return_value=resp)) as post:
        await scoped.scan_command("ls -la")

    assert post.call_args.kwargs["json"]["context"]["session_id"] == "sess-async"

    await scoped.close()
    assert not guard._http.is_closed
    await guard.close()


# --- the warning -----------------------------------------------------------


def test_the_process_default_warns_once(caplog, monkeypatch):
    """A silent default is how this shipped in the first place."""
    monkeypatch.setattr(config, "_process_session_warned", False)
    monkeypatch.delenv("SHRIKE_SUPPRESS_SESSION_WARNING", raising=False)

    client = ScanClient(api_key="k", endpoint="https://mock.test")
    with mock.patch.object(client._http, "post", return_value=_mock_response()):
        with caplog.at_level("WARNING", logger="shrike-guard"):
            client.scan_command("ls -la")
            client.scan_command("ls -la")
            client.scan_command("ls -la")

    warnings = [r for r in caplog.records if "process-wide session id" in r.message]
    assert len(warnings) == 1, "the session warning must fire once per process, not per scan"


def test_an_explicit_session_does_not_warn(caplog, monkeypatch):
    monkeypatch.setattr(config, "_process_session_warned", False)
    monkeypatch.delenv("SHRIKE_SUPPRESS_SESSION_WARNING", raising=False)

    client = ScanClient(api_key="k", endpoint="https://mock.test", session_id="sess-explicit")
    with mock.patch.object(client._http, "post", return_value=_mock_response()):
        with caplog.at_level("WARNING", logger="shrike-guard"):
            client.scan_command("ls -la")

    assert not [r for r in caplog.records if "process-wide session id" in r.message], (
        "a caller who supplied a session id has nothing to be warned about"
    )


def test_the_warning_can_be_suppressed(caplog, monkeypatch):
    monkeypatch.setattr(config, "_process_session_warned", False)
    monkeypatch.setenv("SHRIKE_SUPPRESS_SESSION_WARNING", "1")

    client = ScanClient(api_key="k", endpoint="https://mock.test")
    with mock.patch.object(client._http, "post", return_value=_mock_response()):
        with caplog.at_level("WARNING", logger="shrike-guard"):
            client.scan_command("ls -la")

    assert not [r for r in caplog.records if "process-wide session id" in r.message]
