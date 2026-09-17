"""Govern an agent built on the OpenAI Agents SDK.

Three lines in the caller, and every tool the agent calls is judged by Shrike
before it runs::

    from agents import Agent, Runner
    from shrike_guard import ScanClient
    from shrike_guard.openai_agents import govern

    guard = ScanClient(api_key=KEY, agent_id="invoice-agent", session_id=run_id)
    gov = govern(guard, agent_id="invoice-agent").map_tool("run_query", "sql", arg="query")
    agent = gov.govern_agent(Agent(name="invoices", tools=[run_query, save_report]))

A thin adapter over :mod:`shrike_guard.govern`, the framework-free core.

What it wires
-------------

**The act plane: a tool input guardrail on every function tool.** The SDK
runs tool input guardrails before a function tool executes. Shrike's
guardrail evaluates the call through the tool's mapping (see
:meth:`Governance.map_tool`); a refused or held call is answered with
``reject_content``, so the tool never runs and the model receives Shrike's
reason and the recovery as the tool's output. Tools with no mapping are
refused by default (``on_unmapped="deny"``) with a message that says how to
map them.

**The observe plane: an input guardrail that never trips.** The run's input
is scanned on the way in and recorded; it is never blocked. The finding is
on :attr:`Governance.decisions` and in the guardrail's ``output_info``.

**One tool, ``request_scope``.** Added to the agent by
:meth:`Governance.govern_agent`, so the model can ask for more than it holds.
The backend decides; a widening is refused unless an operator grants it.

Holds
-----

The SDK's tool guardrails cannot pause a run for a person, so a held action
is answered like a refusal here whatever ``on_hold`` says: the model is told
an operator can grant the tool on the Shrike Agents screen, and it should
stop and report. Use the SDK's ``needs_approval`` on the tool if you want the
run itself to pause.

Requires ``pip install shrike-guard[openai-agents]``.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Mapping, Optional, Union

from .govern import (
    REQUEST_SCOPE_DESCRIPTION,
    REQUEST_SCOPE_NAME,
    Decision,
    Governance as _CoreGovernance,
    Outcome,
    ToolMapping,
)

try:
    from agents import Agent, FunctionTool, function_tool
    from agents.guardrail import GuardrailFunctionOutput, InputGuardrail
    from agents.tool_guardrails import ToolGuardrailFunctionOutput, ToolInputGuardrail

    OPENAI_AGENTS_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without the extra
    OPENAI_AGENTS_AVAILABLE = False
    Agent = FunctionTool = function_tool = None  # type: ignore
    GuardrailFunctionOutput = InputGuardrail = None  # type: ignore
    ToolGuardrailFunctionOutput = ToolInputGuardrail = None  # type: ignore

__all__ = ["OPENAI_AGENTS_AVAILABLE", "Decision", "Outcome", "ToolMapping", "Governance", "govern"]

GUARDRAIL_NAME = "shrike"


def parse_arguments(raw: Any) -> Dict[str, Any]:
    """The SDK hands tool arguments as a JSON string; make them a dict.

    Non-JSON text is kept under ``input`` so the mapping can still reach it.
    """
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return {"input": str(raw)}
    return parsed if isinstance(parsed, dict) else {"input": parsed}


def input_text(value: Any) -> str:
    """The person's text in a run input: a string, or the last user item."""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        for item in reversed(value):
            if isinstance(item, dict) and item.get("role") == "user":
                content = item.get("content")
                if isinstance(content, str):
                    return content
                if isinstance(content, list):
                    return " ".join(str(p.get("text") or "") for p in content if isinstance(p, dict))
    return ""


class Governance(_CoreGovernance):
    """The guardrails, the scope tool and the record for one governed agent."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._tool_guardrail: Any = None
        self._input_guardrail: Any = None
        self._tool: Any = None

    # -- the act plane -------------------------------------------------------

    async def tool_input_guardrail(self, data: Any) -> Any:
        """The guardrail function. Public so it can be driven without a run."""
        ctx = data.context
        out = await self.evaluate_async(str(ctx.tool_name), parse_arguments(getattr(ctx, "tool_arguments", None)), event="tool_input_guardrail")
        return self.guardrail_output(out)

    @staticmethod
    def guardrail_output(out: Outcome) -> Any:
        """Translate an :class:`Outcome` into the SDK's guardrail output."""
        info = {"decision": out.decision, "tool": out.tool, "advisories": out.advisories}
        if out.held or out.denied:
            return ToolGuardrailFunctionOutput.reject_content(out.message, output_info=info)
        return ToolGuardrailFunctionOutput.allow(output_info=info)

    @property
    def guardrail(self) -> Any:
        """The tool input guardrail; attach it to any ``FunctionTool``."""
        _require_sdk()
        if self._tool_guardrail is None:
            self._tool_guardrail = ToolInputGuardrail(guardrail_function=self.tool_input_guardrail, name=GUARDRAIL_NAME)
        return self._tool_guardrail

    def govern_tools(self, tools: List[Any]) -> List[Any]:
        """Attach the guardrail to every function tool in ``tools``; returns them."""
        for t in tools:
            if isinstance(t, FunctionTool):
                existing = list(t.tool_input_guardrails or [])
                if self.guardrail not in existing:
                    t.tool_input_guardrails = [self.guardrail, *existing]
        return tools

    # -- the observe plane ---------------------------------------------------

    async def input_guardrail_function(self, context: Any, agent: Any, value: Any) -> Any:
        d = await self.observe_prompt_async(input_text(value), event="input_guardrail")
        return GuardrailFunctionOutput(output_info={"note": self.observe_note(d)}, tripwire_triggered=False)

    @property
    def input_guardrail(self) -> Any:
        """The observe-plane input guardrail. It never trips."""
        _require_sdk()
        if self._input_guardrail is None:
            self._input_guardrail = InputGuardrail(guardrail_function=self.input_guardrail_function, name=GUARDRAIL_NAME)
        return self._input_guardrail

    # -- the scope tool ------------------------------------------------------

    @property
    def tool(self) -> Any:
        """``request_scope`` as a function tool."""
        _require_sdk()
        if self._tool is None:
            gov = self

            async def request_scope(tools: List[str], reason: str = "") -> str:
                """Ask Shrike to add tools to this agent's declared scope. A widening is refused unless an operator grants it."""
                res = await gov.request_scope_async(tools, reason or None)
                return res.message

            self._tool = function_tool(request_scope, name_override=REQUEST_SCOPE_NAME, description_override=REQUEST_SCOPE_DESCRIPTION)
        return self._tool

    # -- one call ------------------------------------------------------------

    def govern_agent(self, agent: Any) -> Any:
        """Guard every function tool on ``agent``, add ``request_scope``, and add
        the observe guardrail. Returns the same agent."""
        _require_sdk()
        self.govern_tools(list(agent.tools))
        if all(getattr(t, "name", None) != REQUEST_SCOPE_NAME for t in agent.tools):
            agent.tools.append(self.tool)
        if self.observe and self.input_guardrail not in agent.input_guardrails:
            agent.input_guardrails.append(self.input_guardrail)
        return agent


def _require_sdk() -> None:
    if not OPENAI_AGENTS_AVAILABLE:
        raise ImportError("openai-agents is not installed. Install it with: pip install shrike-guard[openai-agents]")


def govern(
    guard: Any,
    *,
    agent_id: str,
    on_hold: str = "deny",
    fail_mode: str = "closed",
    observe: bool = True,
    on_decision: Optional[Callable[[Decision], None]] = None,
    tools: Optional[Mapping[str, Union[ToolMapping, str]]] = None,
    on_unmapped: str = "deny",
) -> Governance:
    """Build the governance for one agent. See :mod:`shrike_guard.govern` for the arguments."""
    _require_sdk()
    return Governance(
        guard,
        agent_id=agent_id,
        on_hold=on_hold,
        fail_mode=fail_mode,
        observe=observe,
        on_decision=on_decision,
        tools=tools,
        on_unmapped=on_unmapped,
    )
