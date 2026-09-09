"""Live integration tests: real backend, real HTTP, no mocks.

The unit suites assert what the SDK sends. Only the backend can confirm that it
accepts the request and returns the fields the SDK documents: an unrecognized
content_type, a renamed endpoint, a rejected auth header, or a response field
that is present on one route and absent on another all look identical to a
passing mock.

Skipped unless both are set:

    SHRIKE_LIVE_ENDPOINT   e.g. https://api.shrikesecurity.com/agent
    SHRIKE_LIVE_API_KEY

Run:  SHRIKE_LIVE_ENDPOINT=... SHRIKE_LIVE_API_KEY=... pytest tests/test_actplane_live.py -v

These probes write real scan rows, including refused scans, to the account the
key belongs to. Use a dedicated test account.

Assertions are deliberately coarse. Which layer catches a probe may change
freely; that the call round-trips and returns a well-formed governance verdict
may not. No exact prose, no confidences, no severities: those are attribution
and are allowed to change.

Contract-symmetric with tests/integration/actplane-live.test.ts (TypeScript)
and scanner/actplane_live_test.go (Go). If the three disagree about what the
backend returns, one of them is a bug.
"""

import json
import os
import uuid
from pathlib import Path

import pytest

from shrike_guard.scanner import ScanClient

ENDPOINT = os.environ.get("SHRIKE_LIVE_ENDPOINT")
API_KEY = os.environ.get("SHRIKE_LIVE_API_KEY")

pytestmark = pytest.mark.skipif(
    not (ENDPOINT and API_KEY),
    reason="live backend not configured (set SHRIKE_LIVE_ENDPOINT + SHRIKE_LIVE_API_KEY)",
)

_FIXTURE = json.loads(
    (
        Path(__file__).resolve().parent
        / "fixtures"
        / "contract-symmetry"
        / "canonical-request-shapes.json"
    ).read_text()
)


# The suite identifies itself: one agent id per SDK suite and one session id
# per run, so its rows are recognisable on the Agents screen and in incidents.
# The session id is fresh each run because backend session state persists
# between runs; a reused id would carry the previous run's history into this
# one.
LIVE_AGENT_ID = "sdk-live-test-python"
LIVE_RUN_SESSION_ID = f"{LIVE_AGENT_ID}-run-{uuid.uuid4().hex[:12]}"


@pytest.fixture(scope="module")
def client():
    with ScanClient(
        api_key=API_KEY,
        endpoint=ENDPOINT,
        timeout=30.0,
        session_id=LIVE_RUN_SESSION_ID,
        agent_id=LIVE_AGENT_ID,
    ) as c:
        yield c


def _assert_well_formed(result, label):
    """The four-state governance surface must be present on every verdict.

    Contract symmetry is a shipped promise: safe / refuse_tier / recovery /
    session_state on every response, refused or not. A live check is the only
    place that promise is tested against the thing that actually makes it.
    """
    assert isinstance(result, dict), f"{label}: no result"
    assert "safe" in result, f"{label}: verdict has no `safe`"
    assert result.get("refuse_tier"), f"{label}: no refuse_tier — contract symmetry broken"
    assert result["refuse_tier"] in {
        "allow",
        "warn",
        "require_approval",
        "block",
    }, f"{label}: unknown refuse_tier {result.get('refuse_tier')!r}"


# --- every channel round-trips -------------------------------------------

# Benign content per channel. The point is that the REQUEST is accepted and a
# verdict comes back, not that anything is caught.
LIVE_CHANNELS = [
    ("command", lambda c: c.scan_command("git status", cwd="/tmp")),
    ("sql", lambda c: c.scan_sql("SELECT id FROM users WHERE id = 1", database="postgres")),
    ("file_path", lambda c: c.scan_file("/tmp/report.csv")),
    ("file_content", lambda c: c.scan_file("/tmp/notes.txt", "meeting notes for thursday")),
    ("web_search", lambda c: c.scan_web_search("sql injection prevention owasp cheat sheet")),
    ("rag_context", lambda c: c.scan_rag_context(["the refund window is 30 days"], query="refunds")),
    ("a2a_message", lambda c: c.scan_a2a_message("task complete, 3 records updated")),
    ("agent_card", lambda c: c.scan_agent_card('{"name":"reporter","version":"1.0"}')),
]


@pytest.mark.parametrize("channel,call", LIVE_CHANNELS)
def test_channel_round_trips_against_the_real_backend(client, channel, call):
    """Every act-plane channel the SDK exposes must be one the backend accepts.

    A mock cannot fail this. Only the backend can.
    """
    assert channel in _FIXTURE["channels"], f"{channel} is not in the shared fixture"
    result = call(client)
    _assert_well_formed(result, channel)


@pytest.mark.xfail(
    strict=True,
    reason=(
        "/api/scan/mcp_schema does not yet return refuse_tier, recovery or "
        "session_state, and does not accept a session context. strict=True: "
        "once the endpoint adopts the response contract this test passes, the "
        "run fails on the unexpected pass, and the marker is removed."
    ),
)
def test_mcp_schema_round_trips(client):
    result = client.scan_mcp_schema(
        "read_report",
        "Reads a report file from the reports directory and returns its contents.",
        {"type": "object", "properties": {"path": {"type": "string"}}},
    )
    _assert_well_formed(result, "mcp_schema")


def test_general_scan_round_trips_with_the_new_shape(client):
    """The general-scan request shape, against the real backend.

    The SDK sends {prompt, scan_type, context: {identity}, conversation_history}.
    If the backend rejects that shape or ignores the identity, it shows up here
    rather than in a customer's logs.
    """
    result = client.scan("summarize the quarterly report", context="user asked about Q3 earlier")
    _assert_well_formed(result, "general scan")


# --- the verdict carries what we tell customers it carries ---------------


def test_content_origin_arrives_on_an_act_plane_verdict(client):
    """content_origin is the field 4.1.0 exists to deliver.

    It was computed by the backend and dropped by every SDK's sanitizer for
    months. Now that all three preserve it, this asserts the backend is
    actually sending it — the other half nobody had checked.
    """
    result = client.scan_command("ls -la", cwd="/tmp")
    origin = result.get("content_origin")
    assert origin, "backend sent no content_origin on an act-plane scan"
    assert origin in {
        "human_prompt",
        "agent_output",
        "agent_action",
        "third_party",
    }, f"unknown content_origin {origin!r}"
    assert origin != "human_prompt", (
        "an act-plane scan must never be attributed to the operator — "
        "unknown content types resolve to agent_action by design"
    )


def test_benign_technical_prose_is_not_refused(client):
    """The other half of the gate.

    A detector that refuses ordinary work is a detector nobody keeps switched
    on. These are known false-positive cases; they must stay fixed in the
    deployed system, not only in the local corpus.

    ORDER IS LOAD-BEARING: this runs BEFORE the attack probes below, and pytest
    executes in file order. The shared ``client`` scans under one session id
    for the whole run, so every scan it makes lands in one session. Run these
    after that session has accumulated enough risk and they come back held,
    correctly, and read as false positives that are not there.

    A client derived with ``for_session()`` is a different session and is not
    subject to this; see test_sessions_are_isolated_end_to_end. But a
    false-positive probe on the SHARED client added below the attack probes
    will fail for a reason that has nothing to do with false positives.
    """
    for label, call in [
        ("git pathspec separator", lambda: client.scan_command("git log --oneline -5 --")),
        ("defensive research", lambda: client.scan_web_search("owasp top 10 for llm applications")),
        ("legitimate union", lambda: client.scan_sql("SELECT name FROM staff UNION SELECT name FROM contractors")),
    ]:
        result = call()
        _assert_well_formed(result, label)
        assert result["refuse_tier"] == "allow", (
            f"FALSE POSITIVE on the live backend: {label} was "
            f"{result['refuse_tier']}, expected allow"
        )


def test_a_real_attack_is_refused(client):
    """One end-to-end proof that enforcement actually enforces.

    Coarse on purpose: refuse_tier must escalate past allow. Which layer caught
    it, at what confidence, is attribution and may change freely.
    """
    result = client.scan_command('psql -c "SELECT * FROM users WHERE id = 1 OR 1=1--"')
    _assert_well_formed(result, "sqli in a command")
    assert result["refuse_tier"] != "allow", (
        "SQL injection carried inside a database CLI argument was ALLOWED by "
        "the live backend. This is the exact case the 4.1.0 command channel "
        "exists for."
    )


def test_session_quarantine_holds_later_actions(client):
    """Once a session's accumulated risk crosses the quarantine threshold,
    later actions in that session are held.

    Session quarantine is a function of accumulated session risk, not of a
    single refusal. By this point the shared client carries a dozen turns of
    history plus a refused injection, which is what takes it over the
    threshold. A fresh session's first refusal does not (one block scores well
    below the threshold and decays over the following turns); see
    test_sessions_are_isolated_end_to_end for what a single refusal does prove.

    This is also end-to-end proof that the session identity reaches the
    backend: with no session_id, nothing accumulates.

    Ordering matters: this runs after the SQL-injection probe on the shared
    module-scoped client, deliberately.
    """
    result = client.scan_command("git log --oneline -5 --")
    _assert_well_formed(result, "post-refusal benign command")
    assert result["refuse_tier"] != "allow", (
        "a benign command was ALLOWED in a session that just refused a SQL "
        "injection — session correlation is not accumulating, which means the "
        "session identity is not reaching the backend"
    )


def test_sessions_are_isolated_end_to_end(client):
    """Two views derived with ``for_session`` are two sessions to the backend.

    Session correlation keys on (customer, session, agent), so two views with
    different session ids are separate sessions even though they share the
    agent id and the connection pool. The proof is what the backend reports on
    every response: ``session_state.session_turn_number`` and
    ``session_state.session_risk_score``. Session A's turns must count up and
    carry risk after its refusal; session B, scanning right after, must be on
    its first turn with no risk and allowed.

    Not asserted: that A's next action is held. Quarantine is a function of
    accumulated session risk, and a fresh session's single refusal stays below
    the threshold.

    Fresh ids per run, on purpose: backend session state persists across runs,
    so a fixed id would carry a previous run's history into this one and the
    test would fail for a reason unrelated to isolation.
    """
    a = client.for_session(f"{LIVE_AGENT_ID}-iso-a-{uuid.uuid4().hex[:12]}")
    b = client.for_session(f"{LIVE_AGENT_ID}-iso-b-{uuid.uuid4().hex[:12]}")

    refused = a.scan_command('psql -c "SELECT * FROM users WHERE id = 1 OR 1=1--"')
    _assert_well_formed(refused, "session A: sqli in a command")
    assert refused["refuse_tier"] != "allow", "session A's attack probe was allowed"

    after = a.scan_command("git log --oneline -5 --")
    _assert_well_formed(after, "session A: benign command after its own refusal")

    clean = b.scan_command("git log --oneline -5 --")
    _assert_well_formed(clean, "session B: same benign command, different session")

    a_state = after.get("session_state") or {}
    b_state = clean.get("session_state") or {}

    # Session A correlates its own turns: the id from for_session() reached the
    # backend and the backend kept state under it.
    assert a_state.get("session_turn_number") == 2, (
        f"session A's second scan was turn {a_state.get('session_turn_number')!r}, "
        "expected 2 — the session id from for_session() is not being correlated"
    )
    assert (a_state.get("session_risk_score") or 0) > 0, (
        "session A carries no risk after its own refusal — nothing accumulated"
    )

    # Session B is a different session to the backend: first turn, no risk,
    # allowed. A's refusal did not touch it.
    assert clean["refuse_tier"] == "allow", (
        "session B was held because of session A's refusal — sessions are not "
        "isolated, which is the cross-user hold for_session() exists to prevent"
    )
    assert b_state.get("session_turn_number") == 1, (
        f"session B's first scan was turn {b_state.get('session_turn_number')!r}, "
        "expected 1 — B is being correlated into another session"
    )
    assert (b_state.get("session_risk_score") or 0) == 0, (
        f"session B carries risk {b_state.get('session_risk_score')!r} it never earned"
    )


# Ordering: no probe below the attack probes may assert "allow" on the shared
# client. It scans under the run's session id, so once that session has
# accumulated enough risk, every later scan in it is legitimately held. See
# test_benign_technical_prose_is_not_refused. Probes on explicit fresh sessions
# (``for_session``) are not subject to this; see the isolation test above.
#
# Not yet exposed by any SDK: a session reset. The backend and the MCP server
# provide one.
