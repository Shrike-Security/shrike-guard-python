"""Govern an agent built on the Claude Agent SDK.

Three lines in the caller, and every action the agent takes is judged by
Shrike before it executes::

    from claude_agent_sdk import ClaudeAgentOptions
    from shrike_guard import ScanClient
    from shrike_guard.claude_agent import govern

    guard = ScanClient(api_key=KEY, agent_id="invoice-agent", session_id=run_id)
    gov = govern(guard, agent_id="invoice-agent")
    options = ClaudeAgentOptions(hooks=gov.hooks, mcp_servers={"shrike": gov.mcp_server})

This is a thin adapter over :mod:`shrike_guard.govern`, the framework-free
core. It maps the SDK's built-in tools to Shrike surfaces and translates the
SDK's hook shapes to and from the core.

What it wires
-------------

**The act plane: a ``PreToolUse`` hook.** Every built-in tool call goes to
Shrike first. ``Bash`` goes to ``scan_command``; ``Write``, ``Edit``,
``MultiEdit`` and ``NotebookEdit`` go to ``scan_file`` for the path and again
for the content they write; ``Read`` goes to ``scan_file`` for the path;
``WebSearch`` and ``WebFetch`` go to ``scan_web_search``. The verdict becomes
the SDK's permission decision: ``allow`` lets the tool run; ``warn`` lets it
run with the advisory attached as context; ``block`` denies it; a hold
(``require_approval``) denies it by default, or asks (see ``on_hold``). A
denied action hands the model the reason and the recovery, so the agent can
stop and ask instead of retrying or working around it.

The hook matches the built-in tools it has mappings for. Tools from your own
MCP servers are not matched unless you map them (``gov.map_tool``) and widen
the matcher (``gov.hooks_for(...)``). An unmapped tool that does reach the
hook is AUTHORIZED (``on_unmapped="authorize"``, this adapter's default):
its arguments stay put, and its name goes to the backend so the operator's
declared scope can answer. A tool outside the allowlist is refused by name
even though nothing read what it was carrying. Pass ``on_unmapped="deny"``
to refuse anything you have not mapped, or ``"allow"`` to record it and
move on without asking.

**The observe plane: a ``UserPromptSubmit`` hook.** The person's prompt is
scanned on the way in. It is never blocked: a non-allow verdict becomes a
note in the model's context, so the agent knows to treat instructions
embedded in that prompt with suspicion. Turn it off with ``observe=False``.
The model's own final text is not scanned by this adapter.

**One MCP tool, ``request_scope``.** The agent's channel for asking for more
than it holds. The backend answers it: a narrowing or a refresh succeeds, a
widening is refused unless an operator grants it. The agent gets to ask. It
does not get to decide.

**Fail closed.** A backend that cannot be reached is a deny on the act plane
(``fail_mode="closed"``). Pass ``fail_mode="open"`` where liveness matters
more; the decision is recorded either way. The observe plane is always
fail-open.

Holds: deny or ask
------------------

``on_hold="deny"`` (the default) refuses a held action and tells the model an
operator can grant it on the Shrike dashboard. ``on_hold="ask"`` returns the
SDK's ``ask`` decision instead, which routes the hold, with Shrike's reason,
to the ``can_use_tool`` callback you pass to ``ClaudeAgentOptions``; use it
when a person is present to approve inline. Without that callback the SDK
treats ``ask`` as a refusal.

Every decision is recorded on ``Governance.decisions`` and, when given,
handed to ``on_decision`` as it happens.

Requires ``pip install shrike-guard[claude-agent]``.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple, Union

from .govern import (
    REQUEST_SCOPE_DESCRIPTION,
    REQUEST_SCOPE_NAME,
    REQUEST_SCOPE_SCHEMA,
    Decision,
    Governance as _CoreGovernance,
    Outcome,
    ToolMapping,
    read_verdict,
)

try:
    from claude_agent_sdk import HookMatcher, create_sdk_mcp_server, tool

    CLAUDE_AGENT_SDK_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without the extra
    CLAUDE_AGENT_SDK_AVAILABLE = False
    HookMatcher = None  # type: ignore
    create_sdk_mcp_server = None  # type: ignore
    tool = None  # type: ignore

__all__ = [
    "CLAUDE_AGENT_SDK_AVAILABLE",
    "MCP_SERVER_NAME",
    "REQUEST_SCOPE_TOOL",
    "ACT_PLANE_TOOLS",
    "DEFAULT_TOOLS",
    "Decision",
    "Outcome",
    "Governance",
    "govern",
    "checks_for",
    "read_verdict",
]

#: Name of the in-process MCP server the adapter builds.
MCP_SERVER_NAME = "shrike"
#: The tool name the model sees for the scope request.
REQUEST_SCOPE_TOOL = f"mcp__{MCP_SERVER_NAME}__{REQUEST_SCOPE_NAME}"


def _edit_content(tool_input: Dict[str, Any]) -> str:
    """The text a write-shaped tool will put on disk.

    ``Write`` carries the whole file, ``Edit`` the replacement, ``NotebookEdit``
    the new cell source, and ``MultiEdit`` a list of edits whose replacements
    are joined so the scan sees everything that changes.
    """
    for key in ("content", "new_string", "new_source"):
        v = tool_input.get(key)
        if v:
            return str(v)
    edits = tool_input.get("edits")
    if isinstance(edits, list):
        parts = [str(e.get("new_string") or "") for e in edits if isinstance(e, dict)]
        return "\n".join(p for p in parts if p)
    return ""


def _path(tool_input: Dict[str, Any]) -> str:
    for key in ("file_path", "notebook_path"):
        v = tool_input.get(key)
        if v:
            return str(v)
    return ""


#: The SDK's built-in tools and the Shrike surface each one is.
DEFAULT_TOOLS: Dict[str, ToolMapping] = {
    "Bash": ToolMapping("command", arg="command", cwd_arg="cwd"),
    "Write": ToolMapping("file", content_arg=_edit_content, path_arg="file_path"),
    "Edit": ToolMapping("file", content_arg=_edit_content, path_arg="file_path"),
    "MultiEdit": ToolMapping("file", content_arg=_edit_content, path_arg="file_path"),
    "NotebookEdit": ToolMapping("file", content_arg=_edit_content, path_arg="notebook_path"),
    "Read": ToolMapping("file_path", arg="file_path"),
    "WebSearch": ToolMapping("web_search", arg="query"),
    "WebFetch": ToolMapping("web_search", arg="url"),
}

#: Tools the act-plane hook matches by default. The matcher is the SDK's regex form.
ACT_PLANE_TOOLS = tuple(DEFAULT_TOOLS)


def checks_for(guard: Any, tool_name: str, tool_input: Dict[str, Any]) -> List[Tuple[str, str, Callable[[], Dict[str, Any]]]]:
    """The scans one built-in tool call needs, as ``(surface, target, run)`` triples.

    Pure: nothing is scanned until ``run()`` is called. Tools not on the act
    plane yield no checks. Kept as a module function for callers that drive
    the gate without a :class:`Governance`.
    """
    return _CoreGovernance(guard, agent_id="-", tools=DEFAULT_TOOLS).checks_for(tool_name, tool_input)


def _pre_tool_output(decision: str, reason: str) -> Dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }


class Governance(_CoreGovernance):
    """The hooks, the MCP server and the record for one governed agent.

    Build it with :func:`govern`. The hook and tool methods are plain async
    methods, so they can be driven without a model (a preflight, a test).
    """

    def __init__(
        self,
        guard: Any,
        *,
        agent_id: str,
        on_hold: str = "deny",
        fail_mode: str = "closed",
        observe: bool = True,
        on_decision: Optional[Callable[[Decision], None]] = None,
        tools: Optional[Mapping[str, Union[ToolMapping, str]]] = None,
        on_unmapped: str = "authorize",
    ) -> None:
        merged: Dict[str, Union[ToolMapping, str]] = dict(DEFAULT_TOOLS)
        merged.update(tools or {})
        super().__init__(
            guard,
            agent_id=agent_id,
            on_hold=on_hold,
            fail_mode=fail_mode,
            observe=observe,
            on_decision=on_decision,
            tools=merged,
            on_unmapped=on_unmapped,
        )
        self.tool_names: List[str] = [REQUEST_SCOPE_TOOL]
        self._hooks: Optional[Dict[str, Any]] = None
        self._mcp_server: Any = None
        #: Outcomes of calls that may still run, by tool_use_id, until the
        #: SDK says what became of them (PostToolUse, PostToolUseFailure).
        self._pending: Dict[str, Any] = {}

    # -- the request_scope MCP tool -----------------------------------------

    async def request_scope_tool(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """The ``request_scope`` MCP tool: ask the backend for more tools.

        Returns the MCP tool result shape. A refusal is an ``is_error`` result
        whose text tells the model to stop and report.
        """
        res = await self.request_scope_async(args.get("tools") or [], args.get("reason"))
        if not res.ok:
            return {"content": [{"type": "text", "text": res.message}], "is_error": True}
        return {"content": [{"type": "text", "text": res.message}]}

    # -- hooks ---------------------------------------------------------------

    async def pre_tool_use(self, input_data: Dict[str, Any], tool_use_id: Optional[str] = None, context: Any = None) -> Dict[str, Any]:
        """The act-plane hook. Returns the SDK's hook output."""
        tool_name = str(input_data.get("tool_name") or "")
        tool_input = input_data.get("tool_input") or {}
        out = await self.evaluate_async(tool_name, tool_input, event="PreToolUse")
        if out.denied:
            return _pre_tool_output("deny", out.message)
        # Allowed, warned, or held for a person's answer: the call may still
        # run, and the SDK says so later under the same tool_use_id.
        if tool_use_id:
            self._pending[tool_use_id] = out
            if len(self._pending) > 512:
                self._pending.pop(next(iter(self._pending)))
        if out.held:
            return _pre_tool_output("ask" if self.on_hold == "ask" else "deny", out.message)
        if out.advisories:
            return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "additionalContext": " ".join(out.advisories)}}
        return {}

    async def post_tool_use(self, input_data: Dict[str, Any], tool_use_id: Optional[str] = None, context: Any = None) -> Dict[str, Any]:
        """The outcome hook: reports executed (PostToolUse) or failed
        (PostToolUseFailure) for the call the act-plane hook gated. Never
        blocks and never reads the tool's result."""
        out = self._pending.pop(tool_use_id, None) if tool_use_id else None
        if out is not None:
            event = str(input_data.get("hook_event_name") or "PostToolUse")
            await self.report_outcome_async(out, "failed" if event == "PostToolUseFailure" else "executed")
        return {}

    async def user_prompt_submit(self, input_data: Dict[str, Any], tool_use_id: Optional[str] = None, context: Any = None) -> Dict[str, Any]:
        """The observe-plane hook. Never blocks; a finding becomes context."""
        d = await self.observe_prompt_async(str(input_data.get("prompt") or ""), event="UserPromptSubmit")
        note = self.observe_note(d)
        if not note:
            return {}
        return {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": note}}

    # -- what the caller hands to ClaudeAgentOptions -------------------------

    def hooks_for(self, tool_names: Optional[List[str]] = None) -> Dict[str, Any]:
        """``hooks=`` for ``ClaudeAgentOptions``, matching the given tools.

        Defaults to EVERY tool the agent can call, not only the mapped ones.
        A tool this SDK has no reader for is exactly the tool whose
        authorization nobody has checked, so the gate has to see it;
        ``on_unmapped`` then decides what happens. Pass an explicit list to
        narrow the matcher, at the cost of the tools left outside it going
        unseen.
        """
        _require_sdk()
        if tool_names is None:
            matchers = {
                "PreToolUse": [HookMatcher(hooks=[self.pre_tool_use])],
                "PostToolUse": [HookMatcher(hooks=[self.post_tool_use])],
                "PostToolUseFailure": [HookMatcher(hooks=[self.post_tool_use])],
            }
        else:
            pattern = "|".join(tool_names)
            matchers = {
                "PreToolUse": [HookMatcher(matcher=pattern, hooks=[self.pre_tool_use])],
                "PostToolUse": [HookMatcher(matcher=pattern, hooks=[self.post_tool_use])],
                "PostToolUseFailure": [HookMatcher(matcher=pattern, hooks=[self.post_tool_use])],
            }
        if self.observe:
            matchers["UserPromptSubmit"] = [HookMatcher(hooks=[self.user_prompt_submit])]
        return matchers

    @property
    def hooks(self) -> Dict[str, Any]:
        """``hooks=`` for ``ClaudeAgentOptions``."""
        if self._hooks is None:
            self._hooks = self.hooks_for()
        return self._hooks

    @property
    def mcp_server(self) -> Any:
        """The in-process MCP server carrying ``request_scope``; pass it as
        ``mcp_servers={"shrike": gov.mcp_server}``."""
        _require_sdk()
        if self._mcp_server is None:
            request_scope = tool(REQUEST_SCOPE_NAME, REQUEST_SCOPE_DESCRIPTION, REQUEST_SCOPE_SCHEMA)(self.request_scope_tool)
            self._mcp_server = create_sdk_mcp_server(MCP_SERVER_NAME, version="1.0.0", tools=[request_scope])
        return self._mcp_server


def _require_sdk() -> None:
    if not CLAUDE_AGENT_SDK_AVAILABLE:
        raise ImportError(
            "claude-agent-sdk is not installed. Install it with: pip install shrike-guard[claude-agent]"
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
    on_unmapped: str = "authorize",
) -> Governance:
    """Build the governance for one agent.

    Args:
        guard: A :class:`shrike_guard.ScanClient` built with this agent's
            ``agent_id`` and a ``session_id`` that means one run.
        agent_id: The agent identity the scope is declared under. Pass the
            same string the guard was built with.
        on_hold: ``"deny"`` refuses a held action; ``"ask"`` routes it to
            the SDK's ``can_use_tool`` callback with Shrike's reason.
        fail_mode: ``"closed"`` denies an action Shrike could not check;
            ``"open"`` lets it run and records that it was not checked.
        observe: Scan the person's prompt on the way in (never blocking).
        on_decision: Called with every :class:`Decision` as it is made.
        tools: Extra tool mappings, added to the built-in ones.
        on_unmapped: What an unmapped tool that reaches the hook gets:
            ``"allow"`` (default here), ``"deny"``, or ``"scan"`` its arguments.

    Raises:
        ImportError: when ``claude-agent-sdk`` is not installed.
    """
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
