"""Outcome reports: once a governed action ran or failed, the adapter says so,
naming the scan the backend kept a record of. The report never reads the
tool's result and never blocks the call."""

import asyncio
from types import SimpleNamespace
from typing import Any, Dict

import pytest

from shrike_guard.govern import Governance, ToolMapping
from shrike_guard.langgraph_agent import LANGCHAIN_AVAILABLE, Governance as LangGraphGovernance
from shrike_guard.claude_agent import Governance as ClaudeAgentGovernance

from .test_govern import ALLOW, BLOCK, FakeGuard

ALLOW_WITH_ID: Dict[str, Any] = {**ALLOW, "scan_id": "scan_allow_1"}
RUN = {"run": ToolMapping("command", arg="cmd")}


def test_core_reports_each_recorded_decision_with_the_event_as_source() -> None:
    guard = FakeGuard(ALLOW_WITH_ID)
    gov = Governance(guard, agent_id="a", tools=RUN)
    out = gov.evaluate("run", {"cmd": "ls"}, event="unit")
    gov.report_outcome(out, "executed", exit_status=0)
    assert guard.outcomes == [{"scan_id": "scan_allow_1", "outcome": "executed", "exit_status": 0, "source": "unit"}]


def test_no_scan_id_names_nothing_and_a_guard_without_the_method_is_fine() -> None:
    guard = FakeGuard(ALLOW)
    gov = Governance(guard, agent_id="a", tools=RUN)
    gov.report_outcome(gov.evaluate("run", {"cmd": "ls"}), "executed")
    assert not getattr(guard, "outcomes", [])
    bare = SimpleNamespace(scan_command=lambda cmd, cwd=None: ALLOW_WITH_ID)
    gov2 = Governance(bare, agent_id="a", tools=RUN)
    gov2.report_outcome(gov2.evaluate("run", {"cmd": "ls"}), "failed")  # no report_outcome on the guard: nothing raised


def test_langgraph_wrap_tool_call_reports_executed_or_failed_never_on_refusal() -> None:
    guard = FakeGuard(ALLOW_WITH_ID)
    gov = LangGraphGovernance(guard, agent_id="a", tools=RUN)
    request = SimpleNamespace(tool_call={"name": "run", "args": {"cmd": "ls"}, "id": "t1"})
    assert gov.wrap_tool_call(request, lambda r: "ok") == "ok"

    def boom(_r: Any) -> Any:
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        gov.wrap_tool_call(request, boom)
    assert [o["outcome"] for o in guard.outcomes] == ["executed", "failed"]
    assert all(o["source"] == "wrap_tool_call" for o in guard.outcomes)

    async def run_async() -> None:
        async def ok(_r: Any) -> str:
            return "ok"

        assert await gov.awrap_tool_call(request, ok) == "ok"

    asyncio.run(run_async())
    assert [o["outcome"] for o in guard.outcomes] == ["executed", "failed", "executed"]

    # A refusal never runs the handler, so nothing is reported. The refusal
    # message itself is a LangChain ToolMessage, so this half needs it.
    blocked = FakeGuard({**BLOCK, "scan_id": "scan_block_1"})
    gov2 = LangGraphGovernance(blocked, agent_id="a", tools=RUN)
    if LANGCHAIN_AVAILABLE:
        gov2.wrap_tool_call(request, lambda r: "never")
    else:
        assert gov2.evaluate("run", {"cmd": "ls"}).denied
    assert not getattr(blocked, "outcomes", [])


def test_claude_agent_hooks_pair_the_outcome_with_the_call_by_tool_use_id() -> None:
    guard = FakeGuard(ALLOW_WITH_ID)
    gov = ClaudeAgentGovernance(guard, agent_id="a")
    pre = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}}

    async def drive() -> None:
        await gov.pre_tool_use(pre, "tu1")
        await gov.pre_tool_use(pre, "tu2")
        await gov.post_tool_use({"hook_event_name": "PostToolUse", "tool_name": "Bash"}, "tu1")
        await gov.post_tool_use({"hook_event_name": "PostToolUseFailure", "tool_name": "Bash"}, "tu2")
        await gov.post_tool_use({"hook_event_name": "PostToolUse", "tool_name": "Bash"}, "unknown")

    asyncio.run(drive())
    assert [(o["outcome"], o["source"]) for o in guard.outcomes] == [("executed", "PreToolUse"), ("failed", "PreToolUse")]
    assert gov._pending == {}
