"""Wire-shape tests for the act-plane scan methods.

The parity test asserts that each channel has a method. That is a structural
check: it cannot see a wrong endpoint, a misspelled ``content_type``, or an
optional argument that never reaches the payload. These tests assert the
request each method actually sends, and that the response fields the SDK
documents survive sanitization.

Contract-symmetric with tests/unit/actplane-transport.test.ts on the TypeScript
SDK. If the two disagree on a body shape below, one of them is a bug.
"""

import json
from pathlib import Path
from typing import Any, Dict
from unittest import mock

import httpx
import pytest

from shrike_guard.scanner import AsyncScanClient, ScanClient

# The shared request-shape declaration. One file, three consumers (this suite,
# the TypeScript suite, the Go suite), so a divergence is a CI failure rather
# than something someone notices by eye. Sibling of
# canonical-backend-responses.json, which does the same job for the response.
_FIXTURE = json.loads(
    (
        Path(__file__).resolve().parent
        / "fixtures"
        / "contract-symmetry"
        / "canonical-request-shapes.json"
    ).read_text()
)

SPECIALIZED_URL = "https://mock.test" + _FIXTURE["specialized_endpoint"]
MCP_SCHEMA_URL = "https://mock.test" + _FIXTURE["non_specialized"]["mcp_schema"]["endpoint"]
REQUIRED_IDENTITY = _FIXTURE["session_identity"]["required_context_keys"]
SOURCE_APP = _FIXTURE["session_identity"]["source_application_by_sdk"]["python"]


def _mock_response(json_body: Dict[str, Any]) -> mock.MagicMock:
    resp = mock.MagicMock(spec=httpx.Response)
    resp.status_code = 200
    resp.json.return_value = json_body
    resp.raise_for_status = mock.MagicMock()
    return resp


def _safe_verdict(**extra: Any) -> Dict[str, Any]:
    """The minimum a backend reply carries on the act plane."""
    body = {
        "safe": True,
        "action": "allow",
        "refuse_tier": "allow",
        "content_origin": "agent_action",
    }
    body.update(extra)
    return body


def _client() -> ScanClient:
    return ScanClient(api_key="shrike-test", endpoint="https://mock.test")


def _sent(post: mock.MagicMock) -> Dict[str, Any]:
    """The url and json body of the last post call."""
    args, kwargs = post.call_args
    return {"url": args[0], "body": kwargs["json"], "headers": kwargs.get("headers", {})}


# --- endpoint + content_type, per channel ---------------------------------

# The whole point of the shared _scan_specialized transport is that adding a
# channel is one line. The risk that creates is that the one line is wrong, and
# every channel looks identical from the outside.
CHANNEL_CALLS = [
    ("command", lambda c: c.scan_command("ls -la")),
    ("sql", lambda c: c.scan_sql("SELECT 1")),
    ("web_search", lambda c: c.scan_web_search("owasp")),
    ("rag_context", lambda c: c.scan_rag_context("chunk")),
    ("a2a_message", lambda c: c.scan_a2a_message("hello")),
    ("agent_card", lambda c: c.scan_agent_card("{}")),
]


def test_every_fixture_channel_is_exercised():
    """The fixture is the channel list. A channel added there without a test
    here is a channel nobody checks the wire shape of."""
    declared = set(_FIXTURE["channels"])
    exercised = {ct for ct, _ in CHANNEL_CALLS} | {"file_path", "file_content"}
    assert declared <= exercised, f"channels in the fixture with no test: {declared - exercised}"


@pytest.mark.parametrize("content_type,call", CHANNEL_CALLS)
def test_channel_posts_right_content_type(content_type, call):
    client = _client()
    with mock.patch.object(
        client._http, "post", return_value=_mock_response(_safe_verdict())
    ) as post:
        call(client)

    sent = _sent(post)
    assert sent["url"] == SPECIALIZED_URL
    assert sent["body"]["content_type"] == _FIXTURE["channels"][content_type]["content_type"]
    assert isinstance(sent["body"]["content"], str)

    # Identity rides on every act-plane request.
    ctx = sent["body"]["context"]
    for key in REQUIRED_IDENTITY:
        assert ctx.get(key), f"{content_type}: context is missing {key}"
    assert ctx["source_application"] == SOURCE_APP


def test_scan_file_path_vs_content():
    """One method, two channels, decided by an argument.

    Getting this backwards would scan a file body against path-traversal rules.
    """
    client = _client()
    with mock.patch.object(
        client._http, "post", return_value=_mock_response(_safe_verdict())
    ) as post:
        client.scan_file("/etc/passwd")
    assert _sent(post)["body"]["content_type"] == "file_path"

    with mock.patch.object(
        client._http, "post", return_value=_mock_response(_safe_verdict())
    ) as post:
        client.scan_file("/tmp/config.py", 'api_key = "sk-x"')
    assert _sent(post)["body"]["content_type"] == "file_content"


# --- optional arguments must actually reach the payload -------------------


def test_scan_command_carries_cwd():
    client = _client()
    with mock.patch.object(
        client._http, "post", return_value=_mock_response(_safe_verdict())
    ) as post:
        client.scan_command("git status", cwd="/srv/app")
    assert _sent(post)["body"]["context"]["cwd"] == "/srv/app"


def test_scan_command_omits_cwd_but_keeps_identity():
    """Absent cwd must not take the session identity with it.

    The context object carries the identity whether or not a per-call key is
    present.
    """
    client = _client()
    with mock.patch.object(
        client._http, "post", return_value=_mock_response(_safe_verdict())
    ) as post:
        client.scan_command("git status")
    ctx = _sent(post)["body"]["context"]
    assert "cwd" not in ctx
    for key in REQUIRED_IDENTITY:
        assert ctx.get(key), f"identity key {key} lost when cwd was absent"


def test_scan_rag_context_carries_query():
    client = _client()
    with mock.patch.object(
        client._http, "post", return_value=_mock_response(_safe_verdict())
    ) as post:
        client.scan_rag_context(["a", "b"], query="what is the refund policy")
    assert _sent(post)["body"]["context"]["query"] == "what is the refund policy"


def test_scan_rag_context_serializes_a_list_as_json():
    """The backend splits chunks back apart.

    Sending "a,b" (a naive join) would merge two documents into one and lose
    the boundary an injection usually sits on.
    """
    import json

    client = _client()
    with mock.patch.object(
        client._http, "post", return_value=_mock_response(_safe_verdict())
    ) as post:
        client.scan_rag_context(["first chunk", "second chunk"])
    assert _sent(post)["body"]["content"] == json.dumps(["first chunk", "second chunk"])


def test_scan_rag_context_passes_a_string_through():
    client = _client()
    with mock.patch.object(
        client._http, "post", return_value=_mock_response(_safe_verdict())
    ) as post:
        client.scan_rag_context("just one chunk")
    assert _sent(post)["body"]["content"] == "just one chunk"


# --- mcp_schema is the odd one out ----------------------------------------


def test_scan_mcp_schema_uses_its_own_endpoint_and_body():
    """Not a specialized content type: its own route, its own detector, and a
    body that is not {content, content_type}. Routing it through the
    specialized endpoint would scan the description as opaque text."""
    client = _client()
    with mock.patch.object(
        client._http, "post", return_value=_mock_response(_safe_verdict())
    ) as post:
        client.scan_mcp_schema("read_file", "Reads a file from disk.")

    sent = _sent(post)
    assert sent["url"] == MCP_SCHEMA_URL
    assert sent["body"]["name"] == "read_file"
    assert sent["body"]["description"] == "Reads a file from disk."
    assert "content_type" not in sent["body"]


def test_scan_mcp_schema_input_schema_is_optional():
    client = _client()
    with mock.patch.object(
        client._http, "post", return_value=_mock_response(_safe_verdict())
    ) as post:
        client.scan_mcp_schema("t", "d", {"type": "object"})
    assert _sent(post)["body"]["input_schema"] == {"type": "object"}

    with mock.patch.object(
        client._http, "post", return_value=_mock_response(_safe_verdict())
    ) as post:
        client.scan_mcp_schema("t", "d")
    assert "input_schema" not in _sent(post)["body"]


# --- the response side ----------------------------------------------------


def test_content_origin_survives_the_sanitizer():
    """This is the 4.1.0 bug, pinned.

    The sanitizer is an allow-list: a field the backend sends is dropped unless
    it is named in PRESERVED_GOVERNANCE_FIELDS.
    """
    client = _client()
    with mock.patch.object(
        client._http,
        "post",
        return_value=_mock_response(_safe_verdict(content_origin="third_party")),
    ):
        result = client.scan_rag_context("retrieved text")
    assert result["content_origin"] == "third_party"


def test_governance_surface_survives_a_refusal():
    client = _client()
    with mock.patch.object(
        client._http,
        "post",
        return_value=_mock_response(
            {
                "safe": False,
                "action": "block",
                "refuse_tier": "block",
                "threat_type": "sql_injection",
                "content_origin": "agent_action",
                "recovery": {"instruction": "rewrite with bound parameters"},
                "session_state": {"session_risk_score": 0.4},
            }
        ),
    ):
        result = client.scan_command('psql -c "SELECT 1 OR 1=1--"')

    assert result["safe"] is False
    assert result["refuse_tier"] == "block"
    assert result["recovery"]
    assert result["session_state"]
    assert result["content_origin"] == "agent_action"


def test_non_200_raises_rather_than_returning_safe():
    """Fail-closed: an enforcement gate that returns "safe" when it could not
    evaluate is a fail-open in disguise."""
    client = _client()
    resp = mock.MagicMock(spec=httpx.Response)
    resp.status_code = 500
    resp.json.return_value = {}
    resp.raise_for_status.side_effect = httpx.HTTPStatusError(
        "500", request=mock.MagicMock(), response=resp
    )
    with mock.patch.object(client._http, "post", return_value=resp):
        with pytest.raises(httpx.HTTPStatusError):
            client.scan_command("ls")


def test_sends_the_scan_auth_header_never_x_api_key():
    """OptionalAuth reads Authorization: Bearer or X-Shrike-API-Key only.

    An X-API-Key request carries no recognized credential, silently resolves to
    the anonymous tier, and every scan looks like a fast L1-L5 pass.
    """
    client = _client()
    with mock.patch.object(
        client._http, "post", return_value=_mock_response(_safe_verdict())
    ) as post:
        client.scan_command("ls")

    names = {k.lower() for k in _sent(post)["headers"]}
    assert "x-api-key" not in names
    assert names & {"authorization", "x-shrike-api-key"}


# --- async parity ---------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "content_type,method,args",
    [
        ("command", "scan_command", ("ls -la",)),
        ("web_search", "scan_web_search", ("owasp",)),
        ("rag_context", "scan_rag_context", ("chunk",)),
        ("a2a_message", "scan_a2a_message", ("hello",)),
    ],
)
async def test_async_client_posts_the_same_shape(content_type, method, args):
    """Sync and async must put the same bytes on the wire.

    A divergence here is invisible to the parity test, which only checks that
    both classes have the method.
    """
    client = AsyncScanClient(api_key="shrike-test", endpoint="https://mock.test")
    with mock.patch.object(
        client._http,
        "post",
        new=mock.AsyncMock(return_value=_mock_response(_safe_verdict())),
    ) as post:
        await getattr(client, method)(*args)

    args_, kwargs = post.call_args
    assert args_[0] == SPECIALIZED_URL
    assert kwargs["json"]["content_type"] == content_type


# --- the general prompt path, now aligned ---------------------------------


def test_general_scan_sends_identity_and_conversation_history_separately():
    """The general-scan request shape.

    A string ``context`` is not the identity object: the backend treats it as
    a source label and leaves session and agent identity empty, so session
    correlation has no key to group turns by and scope enforcement has no
    agent to attribute the scan to.

    After: identity in `context`, history in `conversation_history` — the shape
    the TypeScript and Go SDKs have always sent.
    """
    client = _client()
    with mock.patch.object(
        client._http, "post", return_value=_mock_response(_safe_verdict())
    ) as post:
        client.scan("hello", context="earlier turn")

    sent = _sent(post)
    assert sent["url"] == "https://mock.test" + _FIXTURE["general_endpoint"]

    body = sent["body"]
    for key in _FIXTURE["general_scan"]["required_body_keys"]:
        assert key in body, f"general scan body is missing {key}"
    assert body["scan_type"] == _FIXTURE["general_scan"]["scan_type"]

    ctx = body["context"]
    assert isinstance(ctx, dict), (
        "context must be an object. A string here is parsed into "
        "SourceApplication and silently discards the session identity."
    )
    for key in REQUIRED_IDENTITY:
        assert ctx.get(key), f"general scan context is missing {key}"
    assert ctx["source_application"] == SOURCE_APP

    assert body[_FIXTURE["general_scan"]["conversation_history_key"]] == "earlier turn"


def test_general_scan_carries_identity_with_no_conversation_history():
    client = _client()
    with mock.patch.object(
        client._http, "post", return_value=_mock_response(_safe_verdict())
    ) as post:
        client.scan("hello")

    body = _sent(post)["body"]
    assert "conversation_history" not in body
    for key in REQUIRED_IDENTITY:
        assert body["context"].get(key), f"identity key {key} lost with no history"
