"""Govern an agent built on Google's Agent Development Kit (ADK).

Three lines in the caller, and every tool the agent calls is judged by Shrike
before it runs::

    from google.adk.agents import LlmAgent
    from shrike_guard import ScanClient
    from shrike_guard.google_adk import govern

    guard = ScanClient(api_key=KEY, agent_id="invoice-agent", session_id=run_id)
    gov = govern(guard, agent_id="invoice-agent").map_tool("run_query", "sql", arg="query")
    agent = gov.govern_agent(LlmAgent(name="invoices", model=MODEL, tools=[run_query, save_report]))

A thin adapter over :mod:`shrike_guard.govern`, the framework-free core.

What it wires
-------------

**The act plane: a ``before_tool_callback``.** ADK runs it before every tool
call with the tool, its arguments and the tool context. Shrike's callback
evaluates the call through the tool's mapping (see
:meth:`Governance.map_tool`). Returning a dict from a before-tool callback
makes that dict the tool's response and skips the tool, so a refused or held
call never runs and the model receives Shrike's reason and the recovery as
the tool's result. Tools with no mapping are refused by default
(``on_unmapped="deny"``) with a message that says how to map them.

**The observe plane: a ``before_model_callback``.** The latest user message
is scanned on the way in, once per message, and never blocked. A finding is
appended to the request's instructions so the model knows to treat embedded
instructions with suspicion.

**One tool, ``request_scope``.** Added to the agent by
:meth:`Governance.govern_agent`, so the model can ask for more than it holds.
The backend decides; a widening is refused unless an operator grants it.

Holds
-----

ADK has no built-in pause for a person inside a tool call, so a held action
is answered like a refusal whatever ``on_hold`` says: the model is told an
operator can grant the tool on the Shrike Agents screen, and to stop and
report.

Requires ``pip install shrike-guard[google-adk]``.
"""

from __future__ import annotations

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
    from google.adk.tools.function_tool import FunctionTool

    GOOGLE_ADK_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without the extra
    GOOGLE_ADK_AVAILABLE = False
    FunctionTool = None  # type: ignore

__all__ = ["GOOGLE_ADK_AVAILABLE", "Decision", "Outcome", "ToolMapping", "Governance", "govern"]


def last_user_text(contents: Any) -> str:
    """The text of the latest user turn in an ADK ``LlmRequest.contents``."""
    for content in reversed(list(contents or [])):
        if getattr(content, "role", None) != "user":
            continue
        parts = getattr(content, "parts", None) or []
        text = " ".join(str(getattr(p, "text", "") or "") for p in parts).strip()
        if text:
            return text
    return ""


class Governance(_CoreGovernance):
    """The callbacks, the scope tool and the record for one governed agent."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._tool: Any = None
        self._last_observed: Optional[str] = None

    # -- the act plane -------------------------------------------------------

    async def before_tool_callback(self, tool: Any, args: Dict[str, Any], tool_context: Any = None) -> Optional[Dict[str, Any]]:
        """ADK's before-tool callback. A dict return replaces the tool's result."""
        name = str(getattr(tool, "name", None) or tool)
        out = await self.evaluate_async(name, dict(args or {}), event="before_tool_callback")
        return self.tool_response(out)

    @staticmethod
    def tool_response(out: Outcome) -> Optional[Dict[str, Any]]:
        """The dict handed back as the tool's result, or ``None`` to let it run."""
        if out.held or out.denied:
            return {"status": "refused", "decision": out.decision, "error": out.message}
        return None

    # -- the observe plane ---------------------------------------------------

    async def before_model_callback(self, callback_context: Any, llm_request: Any) -> None:
        """ADK's before-model callback. Scans a new user message; never blocks."""
        if not self.observe:
            return None
        text = last_user_text(getattr(llm_request, "contents", None))
        if not text or text == self._last_observed:
            return None
        self._last_observed = text
        d = await self.observe_prompt_async(text, event="before_model_callback")
        note = self.observe_note(d)
        if note and hasattr(llm_request, "append_instructions"):
            llm_request.append_instructions([note])
        return None

    # -- the scope tool ------------------------------------------------------

    @property
    def tool(self) -> Any:
        """``request_scope`` as an ADK ``FunctionTool``."""
        _require_sdk()
        if self._tool is None:
            gov = self

            def request_scope(tools: List[str], reason: str = "") -> Dict[str, Any]:
                """Ask Shrike to add tools to this agent's declared scope. A widening is refused unless an operator grants it.

                Args:
                    tools: Runtime tool names to add: command, file_path, file_content, sql, web_search.
                    reason: Why the task needs them.
                """
                res = gov.request_scope(tools, reason or None)
                return {"ok": res.ok, "message": res.message, "scope": res.scope.get("allowed_tools", [])}

            request_scope.__name__ = REQUEST_SCOPE_NAME
            self._tool = FunctionTool(request_scope)
            self._tool.description = REQUEST_SCOPE_DESCRIPTION
        return self._tool

    # -- one call ------------------------------------------------------------

    def govern_agent(self, agent: Any) -> Any:
        """Prepend Shrike's callbacks on ``agent`` and add ``request_scope``. Returns the same agent."""
        _require_sdk()
        agent.before_tool_callback = [self.before_tool_callback, *_as_list(agent.before_tool_callback)]
        if self.observe:
            agent.before_model_callback = [self.before_model_callback, *_as_list(agent.before_model_callback)]
        names = {getattr(t, "name", None) or getattr(t, "__name__", None) for t in agent.tools}
        if REQUEST_SCOPE_NAME not in names:
            agent.tools = [*agent.tools, self.tool]
        return agent


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _require_sdk() -> None:
    if not GOOGLE_ADK_AVAILABLE:
        raise ImportError("google-adk is not installed. Install it with: pip install shrike-guard[google-adk]")


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
