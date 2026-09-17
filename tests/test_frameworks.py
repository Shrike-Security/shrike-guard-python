"""Conformance: every framework starter answers the same table the same way.

Each driver translates one scenario into its framework's hook shape, drives
the starter, and reports ``("allowed" | "refused", message)``. The table is
the contract; a starter that cannot pass a row is not a starter. Rows run
only where the framework is installed (``pytest.importorskip``).
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Tuple

import httpx
import pytest

from tests.test_govern import ALLOW, BLOCK, HOLD, WARN, FakeGuard, refused

SCENARIOS = [
    ("allow", ALLOW, None, "allowed", ""),
    ("warn is allowed", WARN, None, "allowed", ""),
    ("block", BLOCK, None, "refused", "Shrike blocked this sql: exfil pattern"),
    ("hold names the recovery", HOLD, None, "refused", "Shrike held this sql"),
    ("backend down fails closed", None, httpx.ConnectError("down"), "refused", "Shrike could not check this sql"),
]

Driver = Callable[[Any, str, Dict[str, Any]], Tuple[str, str]]


def build(module: Any, verdict: Any, raise_with: Any, **kw: Any) -> Any:
    guard = FakeGuard(verdict or ALLOW, raise_with=raise_with)
    gov = module.govern(guard, agent_id="conformance", **kw)
    gov.map_tool("run_query", "sql", arg="query")
    return gov


def check_row(module: Any, drive: Driver, verdict: Any, raise_with: Any, expected: str, prefix: str) -> None:
    gov = build(module, verdict, raise_with)
    result, message = drive(gov, "run_query", {"query": "select 1"})
    assert result == expected, (result, message)
    assert message.startswith(prefix), message
    if expected == "refused":
        assert gov.decisions and gov.decisions[-1].tier in ("block", "require_approval", "unavailable")


def check_unmapped(module: Any, drive: Driver) -> None:
    gov = build(module, ALLOW, None)
    result, message = drive(gov, "send_mail", {"to": "x"})
    assert result == "refused" and "map_tool('send_mail'" in message


def check_scope(module: Any) -> None:
    gov = build(module, ALLOW, None)
    gov.guard.declare_raises = refused("widening")
    res = gov.request_scope(["command"])
    assert not res.ok and res.message.startswith("Refused (widening)")


# --- Claude Agent SDK --------------------------------------------------------

def _claude_drive(gov: Any, name: str, args: Dict[str, Any]) -> Tuple[str, str]:
    # Map the custom tool through the widened matcher path: the hook itself.
    out = asyncio.run(gov.pre_tool_use({"tool_name": name, "tool_input": args}))
    hso = out.get("hookSpecificOutput", {})
    if hso.get("permissionDecision") in ("deny", "ask"):
        return "refused", hso.get("permissionDecisionReason", "")
    return "allowed", hso.get("additionalContext", "")


@pytest.mark.parametrize("label,verdict,raise_with,expected,prefix", SCENARIOS)
def test_claude_agent(label: str, verdict: Any, raise_with: Any, expected: str, prefix: str) -> None:
    pytest.importorskip("claude_agent_sdk")
    from shrike_guard import claude_agent

    check_row(claude_agent, _claude_drive, verdict, raise_with, expected, prefix)


def test_claude_agent_unmapped_and_scope() -> None:
    pytest.importorskip("claude_agent_sdk")
    from shrike_guard import claude_agent

    gov = build(claude_agent, ALLOW, None, on_unmapped="deny")
    result, message = _claude_drive(gov, "send_mail", {"to": "x"})
    assert result == "refused" and "map_tool('send_mail'" in message
    check_scope(claude_agent)


# --- OpenAI Agents SDK -------------------------------------------------------

def _openai_drive(gov: Any, name: str, args: Dict[str, Any]) -> Tuple[str, str]:
    data = SimpleNamespace(context=SimpleNamespace(tool_name=name, tool_arguments=json.dumps(args), tool_call_id="c1"), agent=None)
    out = asyncio.run(gov.tool_input_guardrail(data))
    if out.behavior["type"] == "reject_content":
        return "refused", out.behavior["message"]
    return "allowed", ""


@pytest.mark.parametrize("label,verdict,raise_with,expected,prefix", SCENARIOS)
def test_openai_agents(label: str, verdict: Any, raise_with: Any, expected: str, prefix: str) -> None:
    pytest.importorskip("agents")
    from shrike_guard import openai_agents

    check_row(openai_agents, _openai_drive, verdict, raise_with, expected, prefix)


def test_openai_agents_unmapped_scope_and_wiring() -> None:
    pytest.importorskip("agents")
    from agents import Agent, function_tool

    from shrike_guard import openai_agents

    check_unmapped(openai_agents, _openai_drive)
    check_scope(openai_agents)

    @function_tool
    def run_query(query: str) -> str:
        """Run a query."""
        return query

    gov = build(openai_agents, ALLOW, None)
    agent = gov.govern_agent(Agent(name="t", tools=[run_query]))
    assert gov.guardrail in run_query.tool_input_guardrails
    assert [t.name for t in agent.tools][-1] == "request_scope"
    assert gov.input_guardrail in agent.input_guardrails
    assert openai_agents.parse_arguments("not json") == {"input": "not json"}
    assert openai_agents.input_text([{"role": "user", "content": "hi"}]) == "hi"


# --- Google ADK ----------------------------------------------------------------

def _adk_drive(gov: Any, name: str, args: Dict[str, Any]) -> Tuple[str, str]:
    res = asyncio.run(gov.before_tool_callback(SimpleNamespace(name=name), args, None))
    if res is not None:
        return "refused", res.get("error", "")
    return "allowed", ""


@pytest.mark.parametrize("label,verdict,raise_with,expected,prefix", SCENARIOS)
def test_google_adk(label: str, verdict: Any, raise_with: Any, expected: str, prefix: str) -> None:
    pytest.importorskip("google.adk")
    from shrike_guard import google_adk

    check_row(google_adk, _adk_drive, verdict, raise_with, expected, prefix)


def test_google_adk_unmapped_scope_and_wiring() -> None:
    pytest.importorskip("google.adk")
    from google.adk.agents import LlmAgent

    from shrike_guard import google_adk

    check_unmapped(google_adk, _adk_drive)
    check_scope(google_adk)

    def run_query(query: str) -> str:
        """Run a query."""
        return query

    gov = build(google_adk, ALLOW, None)
    agent = gov.govern_agent(LlmAgent(name="t", model="gemini-2.5-flash", tools=[run_query]))
    assert agent.before_tool_callback[0] == gov.before_tool_callback
    assert agent.before_model_callback[0] == gov.before_model_callback
    assert getattr(agent.tools[-1], "name", None) == "request_scope"

    # observe: a new user message is scanned once and the note is appended
    gov2 = build(google_adk, BLOCK, None)
    req = SimpleNamespace(contents=[SimpleNamespace(role="user", parts=[SimpleNamespace(text="do the thing")])], notes=[])
    req.append_instructions = lambda notes: req.notes.extend(notes)
    asyncio.run(gov2.before_model_callback(None, req))
    asyncio.run(gov2.before_model_callback(None, req))
    assert len(req.notes) == 1 and req.notes[0].startswith("Shrike observe-plane note")


# --- LangChain / LangGraph ------------------------------------------------------

def _langgraph_drive(gov: Any, name: str, args: Dict[str, Any]) -> Tuple[str, str]:
    from langchain_core.messages import ToolMessage

    request = SimpleNamespace(tool_call={"name": name, "args": args, "id": "c1"})
    ran: List[Any] = []
    out = gov.wrap_tool_call(request, lambda r: ran.append(r) or ToolMessage(content="ran", tool_call_id="c1"))
    if not ran:
        assert isinstance(out, ToolMessage) and out.status == "error"
        return "refused", str(out.content)
    return "allowed", ""


@pytest.mark.parametrize("label,verdict,raise_with,expected,prefix", SCENARIOS)
def test_langgraph(label: str, verdict: Any, raise_with: Any, expected: str, prefix: str) -> None:
    pytest.importorskip("langchain_core")
    from shrike_guard import langgraph_agent

    check_row(langgraph_agent, _langgraph_drive, verdict, raise_with, expected, prefix)


def test_langgraph_unmapped_scope_wrapped_tools_and_middleware() -> None:
    pytest.importorskip("langchain_core")
    from langchain_core.tools import tool

    from shrike_guard import langgraph_agent

    check_unmapped(langgraph_agent, _langgraph_drive)
    check_scope(langgraph_agent)

    @tool
    def run_query(query: str) -> str:
        """Run a query."""
        return f"ran:{query}"

    gov = build(langgraph_agent, HOLD, None)
    governed = gov.govern_tools([run_query])[0]
    assert governed.name == "run_query" and governed.args == run_query.args
    assert governed.invoke({"query": "select 1"}).startswith("Shrike held this sql")
    gov_ok = build(langgraph_agent, ALLOW, None)
    assert gov_ok.govern_tools([run_query])[0].invoke({"query": "select 1"}) == "ran:select 1"
    assert asyncio.run(gov_ok.govern_tools([run_query])[0].ainvoke({"query": "select 2"})) == "ran:select 2"

    pytest.importorskip("langchain.agents.middleware")
    mw = gov.middleware
    assert [t.name for t in mw.tools] == ["request_scope"]
    assert gov.tool.invoke({"tools": ["command"], "reason": "x"}).startswith("Scope now:")


# --- CrewAI ----------------------------------------------------------------------

def _crewai_drive(gov: Any, name: str, args: Dict[str, Any]) -> Tuple[str, str]:
    ctx = SimpleNamespace(tool_name=name, tool_input=dict(args))
    blocked = gov.before_tool_call(ctx) is False
    if blocked:
        return "refused", gov.decisions[-1].message() if gov.decisions[-1].tier != "block" or gov.decisions[-1].surface != "unmapped" else f"Shrike refused this tool: {gov.decisions[-1].reason}"
    return "allowed", ""


def _require_crewai() -> None:
    """Skip when the extra is absent; FAIL when it is present but unusable.

    ``importorskip("crewai")`` is too weak a guard here. It asks whether the
    framework imports, while the starter needs ``crewai.hooks``, which arrived
    later. On 2026-09-17 the lock resolved crewai 1.6.1: the import succeeded,
    the guard waved the tests through, and six rows failed on a package the
    error message called "not installed".

    Skipping on the narrower import would only move the blindness. A pinned
    crewai that cannot drive the starter is a CONSTRAINT bug and has to be
    loud, so the two cases are separated deliberately.
    """
    pytest.importorskip("crewai")
    from shrike_guard import crewai_agent

    if not crewai_agent.CREWAI_AVAILABLE:
        import crewai

        pytest.fail(
            f"crewai {getattr(crewai, '__version__', 'unknown')} is installed but "
            "shrike_guard.crewai_agent could not import crewai.hooks. The pinned "
            "version is older than the starter requires: fix the constraint in "
            "pyproject.toml and re-lock. Do not skip this."
        )


@pytest.mark.parametrize("label,verdict,raise_with,expected,prefix", SCENARIOS)
def test_crewai(label: str, verdict: Any, raise_with: Any, expected: str, prefix: str) -> None:
    _require_crewai()
    from shrike_guard import crewai_agent

    check_row(crewai_agent, _crewai_drive, verdict, raise_with, expected, prefix)


def test_crewai_unmapped_scope_and_wrapped_tools() -> None:
    _require_crewai()
    from crewai.tools import BaseTool
    from pydantic import BaseModel

    from shrike_guard import crewai_agent

    check_unmapped(crewai_agent, _crewai_drive)
    check_scope(crewai_agent)

    class QueryInput(BaseModel):
        query: str

    class RunQuery(BaseTool):
        name: str = "run_query"
        description: str = "Run a query."
        args_schema: type = QueryInput

        def _run(self, query: str) -> str:
            return f"ran:{query}"

    gov = build(crewai_agent, HOLD, None)
    tools = gov.govern_tools([RunQuery()])
    assert [t.name for t in tools] == ["run_query", "request_scope"]
    assert tools[0].run(query="select 1").startswith("Shrike held this sql")
    gov_ok = build(crewai_agent, ALLOW, None)
    assert gov_ok.govern_tools([RunQuery()])[0].run(query="select 1") == "ran:select 1"

    # install registers and uninstall removes, without raising
    uninstall = gov_ok.install(tools=["run_query"])
    uninstall()
