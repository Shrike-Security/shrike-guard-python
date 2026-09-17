"""Govern a CrewAI agent.

Three lines in the caller, and every tool the agent calls is judged by Shrike
before it runs::

    from crewai import Agent
    from shrike_guard import ScanClient
    from shrike_guard.crewai_agent import govern

    guard = ScanClient(api_key=KEY, agent_id="invoice-agent", session_id=run_id)
    gov = govern(guard, agent_id="invoice-agent").map_tool("run_query", "sql", arg="query")
    agent = Agent(role="Invoice clerk", goal=..., backstory=..., tools=gov.govern_tools([run_query, save_report]))

A thin adapter over :mod:`shrike_guard.govern`, the framework-free core.

What it wires
-------------

**The act plane: wrapped tools.** :meth:`Governance.govern_tools` wraps
each CrewAI tool so Shrike evaluates every call through the tool's mapping
(see :meth:`Governance.map_tool`) before the inner tool runs. A refused or
held call never runs; the wrapper returns Shrike's reason and the recovery
as the tool's result, so the model reads why and what to do next. Tools
with no mapping are refused by default (``on_unmapped="deny"``) with a
message that says how to map them. ``request_scope`` is appended to the
list, so the model can ask for more than it holds.

**A global backstop: a ``before_tool_call`` hook.** :meth:`Governance.install`
registers Shrike's hook for every tool call in the process, or for the
tools and agents you name. CrewAI answers a blocked hook with a fixed line
("Tool execution blocked by hook") that carries no reason, so prefer the
wrapped tools where the model should be told why; use the hook where you
cannot reach the tool list. The hook records the decision either way.

**The observe plane: a ``before_llm_call`` hook.** Installed with the tool
hook, it scans the latest user message on the way in, once per message, and
never blocks. A finding is appended to the messages as a system note.

Holds
-----

A held action is answered like a refusal whatever ``on_hold`` says: the
model is told an operator can grant the tool on the Shrike Agents screen,
and to stop and report.

Requires ``pip install shrike-guard[crewai]``.
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
    from crewai.hooks import before_llm_call, before_tool_call
    from crewai.hooks.dispatch import HookAborted
    from crewai.tools import BaseTool
    from pydantic import BaseModel, Field

    CREWAI_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without the extra
    CREWAI_AVAILABLE = False
    before_llm_call = before_tool_call = HookAborted = BaseTool = BaseModel = Field = None  # type: ignore

__all__ = ["CREWAI_AVAILABLE", "Decision", "Outcome", "ToolMapping", "Governance", "GovernedTool", "govern"]


def last_user_text(messages: Any) -> str:
    """The latest user message's text in a CrewAI message list."""
    for m in reversed(list(messages or [])):
        if isinstance(m, dict) and m.get("role") == "user":
            content = m.get("content")
            if isinstance(content, str):
                return content
    return ""


if CREWAI_AVAILABLE:

    class _RequestScopeInput(BaseModel):  # type: ignore[misc]
        tools: List[str] = Field(description="Runtime tool names to add: command, file_path, file_content, sql, web_search.")
        reason: str = Field(default="", description="Why the task needs them.")

    class GovernedTool(BaseTool):  # type: ignore[misc]
        """A CrewAI tool wrapped so Shrike judges every call before the inner tool runs."""

        inner: Any = None
        governance: Any = None

        def _run(self, **kwargs: Any) -> Any:
            out = self.governance.evaluate(self.name, kwargs, event="governed_tool")
            if out.held or out.denied:
                return out.message
            return self.inner.run(**kwargs)

    class _RequestScopeTool(BaseTool):  # type: ignore[misc]
        name: str = REQUEST_SCOPE_NAME
        description: str = REQUEST_SCOPE_DESCRIPTION
        args_schema: type = _RequestScopeInput
        governance: Any = None

        def _run(self, tools: List[str], reason: str = "") -> str:
            return self.governance.request_scope(tools, reason or None).message

else:  # pragma: no cover

    class GovernedTool:  # type: ignore[no-redef]
        pass


class Governance(_CoreGovernance):
    """The wrapped tools, the hooks, the scope tool and the record for one governed agent."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._tool: Any = None
        self._last_observed: Optional[str] = None
        self._installed: List[Callable[[], Any]] = []

    # -- the act plane: wrapped tools ---------------------------------------

    def govern_tools(self, tools: List[Any]) -> List[Any]:
        """Wrap each tool so Shrike judges its calls, and append ``request_scope``."""
        _require_sdk()
        wrapped: List[Any] = []
        for t in tools:
            if getattr(t, "name", None) == REQUEST_SCOPE_NAME:
                continue
            wrapped.append(GovernedTool(name=t.name, description=t.description, args_schema=t.args_schema, inner=t, governance=self))
        wrapped.append(self.tool)
        return wrapped

    # -- the act plane: the global hook -------------------------------------

    def before_tool_call(self, context: Any) -> Optional[bool]:
        """CrewAI's before-tool hook. ``False`` blocks the call."""
        if getattr(context, "tool_name", "") == REQUEST_SCOPE_NAME:
            return None
        out = self.evaluate(str(context.tool_name), dict(context.tool_input or {}), event="before_tool_call")
        if out.held or out.denied:
            return False
        return None

    # -- the observe plane ---------------------------------------------------

    def before_llm_call(self, context: Any) -> Optional[bool]:
        """CrewAI's before-LLM hook. Scans a new user message; never blocks."""
        if not self.observe:
            return None
        messages = getattr(context, "messages", None)
        text = last_user_text(messages)
        if not text or text == self._last_observed:
            return None
        self._last_observed = text
        note = self.observe_note(self.observe_prompt(text, event="before_llm_call"))
        if note and isinstance(messages, list):
            messages.append({"role": "system", "content": note})
        return None

    def install(self, *, tools: Optional[List[str]] = None, agents: Optional[List[str]] = None) -> Callable[[], None]:
        """Register the hooks globally (or for the named tools and agents).

        Returns a function that unregisters them.
        """
        _require_sdk()
        from crewai.hooks import unregister_before_llm_call_hook, unregister_before_tool_call_hook

        # CrewAI marks the hook function with an attribute, which a bound
        # method refuses, so the registered hooks are plain closures.
        def shrike_before_tool_call(context: Any) -> Optional[bool]:
            return self.before_tool_call(context)

        def shrike_before_llm_call(context: Any) -> Optional[bool]:
            return self.before_llm_call(context)

        tool_hook = before_tool_call(tools=tools, agents=agents)(shrike_before_tool_call)
        undo = [lambda: unregister_before_tool_call_hook(tool_hook)]
        if self.observe:
            llm_hook = before_llm_call(agents=agents)(shrike_before_llm_call)
            undo.append(lambda: unregister_before_llm_call_hook(llm_hook))

        def uninstall() -> None:
            for fn in undo:
                try:
                    fn()
                except Exception:
                    pass

        self._installed.append(uninstall)
        return uninstall

    # -- the scope tool ------------------------------------------------------

    @property
    def tool(self) -> Any:
        """``request_scope`` as a CrewAI tool."""
        _require_sdk()
        if self._tool is None:
            self._tool = _RequestScopeTool(governance=self)
        return self._tool


def _require_sdk() -> None:
    """Refuse to run without the hook API, and say which of the two is wrong.

    "Not installed" and "installed but too old" need different answers, and
    reporting the first for the second sends the reader to reinstall a package
    they already have. 1.6.1 satisfied an older floor and carried no
    ``crewai.hooks``, which is exactly how that message got in front of a
    working install.
    """
    if CREWAI_AVAILABLE:
        return
    try:
        import crewai
    except ImportError:
        raise ImportError(
            "crewai is not installed. Install it with: pip install shrike-guard[crewai]"
        ) from None
    version = getattr(crewai, "__version__", "unknown")
    raise ImportError(
        f"crewai {version} is installed but does not provide the hook API this starter "
        "wires (crewai.hooks). Upgrade with: pip install -U 'shrike-guard[crewai]'"
    )


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
