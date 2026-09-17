"""Govern an agent built with LangChain ``create_agent`` or a LangGraph tool node.

Three lines in the caller, and every tool the agent calls is judged by Shrike
before it runs::

    from langchain.agents import create_agent
    from shrike_guard import ScanClient
    from shrike_guard.langgraph_agent import govern

    guard = ScanClient(api_key=KEY, agent_id="invoice-agent", session_id=run_id)
    gov = govern(guard, agent_id="invoice-agent").map_tool("run_query", "sql", arg="query")
    agent = create_agent(MODEL, tools=[run_query, save_report], middleware=[gov.middleware])

For a hand-built LangGraph with a ``ToolNode``, wrap the tools instead::

    tool_node = ToolNode(gov.govern_tools([run_query, save_report]))

A thin adapter over :mod:`shrike_guard.govern`, the framework-free core.

What it wires
-------------

**The act plane, two ways.** :attr:`Governance.middleware` is a LangChain
agent middleware whose ``wrap_tool_call`` evaluates every tool call through
the tool's mapping (see :meth:`Governance.map_tool`) before handing it to
the tool. A refused or held call never runs; the middleware returns a
``ToolMessage`` carrying Shrike's reason and the recovery, so the model
reads it as the tool's result. :meth:`Governance.govern_tools` does the
same by wrapping each tool for graphs that do not use the middleware.
Tools with no mapping are refused by default (``on_unmapped="deny"``) with
a message that says how to map them.

**The observe plane.** The middleware's ``before_agent`` scans the latest
human message on the way in and records the finding. It never blocks and
it does not alter the conversation; the finding is on
:attr:`Governance.decisions` and in ``on_decision``.

**One tool, ``request_scope``.** Registered by the middleware, so the model
can ask for more than it holds. The backend decides; a widening is refused
unless an operator grants it.

Holds
-----

A held action is answered like a refusal whatever ``on_hold`` says: the
model is told an operator can grant the tool on the Shrike Agents screen,
and to stop and report. Use LangGraph's interrupts if the run itself should
pause.

Requires ``pip install shrike-guard[langgraph]``.
"""

from __future__ import annotations

import asyncio
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
    from langchain_core.messages import HumanMessage, ToolMessage
    from langchain_core.tools import BaseTool, tool as make_tool

    LANGCHAIN_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without the extra
    LANGCHAIN_AVAILABLE = False
    HumanMessage = ToolMessage = BaseTool = make_tool = None  # type: ignore

try:
    from langchain.agents.middleware import AgentMiddleware

    LANGCHAIN_AGENTS_AVAILABLE = True
except ImportError:  # pragma: no cover
    LANGCHAIN_AGENTS_AVAILABLE = False
    AgentMiddleware = object  # type: ignore

__all__ = [
    "LANGCHAIN_AVAILABLE",
    "LANGCHAIN_AGENTS_AVAILABLE",
    "Decision",
    "Outcome",
    "ToolMapping",
    "Governance",
    "GovernedTool",
    "govern",
]


def last_human_text(messages: Any) -> str:
    """The latest human message's text in a LangChain message list."""
    for m in reversed(list(messages or [])):
        if HumanMessage is not None and isinstance(m, HumanMessage):
            content = m.content
            if isinstance(content, str):
                return content
            if isinstance(content, list):
                return " ".join(str(p.get("text") or "") for p in content if isinstance(p, dict))
    return ""


def refusal_message(out: Outcome, tool_call_id: str, name: str) -> Any:
    """The ``ToolMessage`` the model reads when a call is refused or held."""
    return ToolMessage(content=out.message, tool_call_id=tool_call_id, name=name, status="error")


if LANGCHAIN_AVAILABLE:

    class GovernedTool(BaseTool):  # type: ignore[misc]
        """A tool wrapped so Shrike judges every call before the inner tool runs."""

        inner: Any
        governance: Any

        def _run(self, *args: Any, **kwargs: Any) -> Any:
            out = self.governance.evaluate(self.name, kwargs, event="governed_tool")
            if out.held or out.denied:
                return out.message
            return self.inner.invoke(kwargs)

        async def _arun(self, *args: Any, **kwargs: Any) -> Any:
            out = await self.governance.evaluate_async(self.name, kwargs, event="governed_tool")
            if out.held or out.denied:
                return out.message
            return await self.inner.ainvoke(kwargs)

else:  # pragma: no cover

    class GovernedTool:  # type: ignore[no-redef]
        pass


class Governance(_CoreGovernance):
    """The middleware, the wrapped tools, the scope tool and the record for one governed agent."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._tool: Any = None
        self._middleware: Any = None
        self._last_observed: Optional[str] = None

    # -- the act plane: one tool call ---------------------------------------

    def wrap_tool_call(self, request: Any, handler: Callable[[Any], Any]) -> Any:
        """The middleware's sync hook. Public so it can be driven without a graph."""
        call = request.tool_call
        out = self.evaluate(str(call.get("name") or ""), call.get("args") or {}, event="wrap_tool_call")
        if out.held or out.denied:
            return refusal_message(out, str(call.get("id") or ""), str(call.get("name") or ""))
        return handler(request)

    async def awrap_tool_call(self, request: Any, handler: Callable[[Any], Any]) -> Any:
        call = request.tool_call
        out = await self.evaluate_async(str(call.get("name") or ""), call.get("args") or {}, event="wrap_tool_call")
        if out.held or out.denied:
            return refusal_message(out, str(call.get("id") or ""), str(call.get("name") or ""))
        return await handler(request)

    def govern_tools(self, tools: List[Any]) -> List[Any]:
        """Wrap each tool so Shrike judges its calls. Returns the wrapped tools."""
        _require_langchain()
        wrapped: List[Any] = []
        for t in tools:
            inner = t if isinstance(t, BaseTool) else make_tool(t)
            wrapped.append(GovernedTool(name=inner.name, description=inner.description, args_schema=inner.args_schema, inner=inner, governance=self))
        return wrapped

    # -- the observe plane ---------------------------------------------------

    def observe_state(self, state: Any) -> None:
        """Scan the latest human message in an agent state, once."""
        messages = state.get("messages") if isinstance(state, dict) else getattr(state, "messages", None)
        text = last_human_text(messages)
        if not text or text == self._last_observed:
            return None
        self._last_observed = text
        self.observe_prompt(text, event="before_agent")
        return None

    # -- the scope tool ------------------------------------------------------

    @property
    def tool(self) -> Any:
        """``request_scope`` as a LangChain tool."""
        _require_langchain()
        if self._tool is None:
            gov = self

            def request_scope(tools: List[str], reason: str = "") -> str:
                """Ask Shrike to add tools to this agent's declared scope. A widening is refused unless an operator grants it."""
                return gov.request_scope(tools, reason or None).message

            request_scope.__name__ = REQUEST_SCOPE_NAME
            self._tool = make_tool(request_scope)
            self._tool.description = REQUEST_SCOPE_DESCRIPTION
        return self._tool

    # -- the middleware ------------------------------------------------------

    @property
    def middleware(self) -> Any:
        """An ``AgentMiddleware`` for ``create_agent(..., middleware=[...])``."""
        if not LANGCHAIN_AGENTS_AVAILABLE:
            raise ImportError("langchain (1.x) is not installed. Install it with: pip install shrike-guard[langgraph]")
        if self._middleware is None:
            gov = self

            class ShrikeMiddleware(AgentMiddleware):  # type: ignore[misc,valid-type]
                tools = [gov.tool]

                @property
                def name(self) -> str:  # type: ignore[override]
                    return "shrike"

                def before_agent(self, state: Any, runtime: Any) -> Optional[Dict[str, Any]]:
                    if gov.observe:
                        gov.observe_state(state)
                    return None

                async def abefore_agent(self, state: Any, runtime: Any) -> Optional[Dict[str, Any]]:
                    if gov.observe:
                        await asyncio.to_thread(gov.observe_state, state)
                    return None

                def wrap_tool_call(self, request: Any, handler: Callable[[Any], Any]) -> Any:
                    return gov.wrap_tool_call(request, handler)

                async def awrap_tool_call(self, request: Any, handler: Callable[[Any], Any]) -> Any:
                    return await gov.awrap_tool_call(request, handler)

            self._middleware = ShrikeMiddleware()
        return self._middleware


def _require_langchain() -> None:
    if not LANGCHAIN_AVAILABLE:
        raise ImportError("langchain-core is not installed. Install it with: pip install shrike-guard[langgraph]")


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
    _require_langchain()
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
