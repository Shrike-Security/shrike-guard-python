# Changelog

## [4.2.0] - 2026-09-17

### Added
- **An unmapped tool can still be judged by its name.** A tool with no
  mapping has no readable surface, so the content plane has nothing to say
  about it. The authorization plane still does: the operator's declared scope
  judges a tool by NAME, which is the one thing every tool call has.
  `on_unmapped="authorize"` sends the tool's name (and nothing else) to the
  backend, so a tool outside the allowlist is refused even though nothing
  read what it was carrying, and an expired or exhausted scope holds it. The
  permit is narrower than a mapped tool's and the record says so: the
  decision's surface is `authorization`, never a scanned surface. A client
  too old to ask fails according to `fail_mode` rather than assuming.
  `ScanClient.authorize_tool` is the call underneath, on both the sync and
  async clients.
- **Observe-plane scans say so.** `ScanClient.scan` takes `plane=`, and
  `observe_prompt` sends `plane="observe"`. A verdict on a prompt nobody is
  gated on is advice: it is recorded and returned, and the model still reads
  the note, but it is no longer filed as an action that was stopped.

- **Framework starters over one core.** `shrike_guard.govern` is the
  framework-free core of a governed agent: a tool mapping table
  (`ToolMapping`, `map_tool`, `exempt`), `evaluate` (every scan a tool call
  needs, stopping at the first refusal, into one `Outcome`: allow, warn, hold
  or deny, with the message written for the model), `observe_prompt` (never
  blocks), `request_scope` (the backend decides; a widening is refused unless
  an operator grants it), and the record (`decisions`, `on_decision`). Each
  starter is a thin translation of one framework's hooks:
  - `shrike_guard.claude_agent` (Claude Agent SDK): `PreToolUse` and
    `UserPromptSubmit` hooks, an in-process MCP tool. Ships mappings for the
    SDK's built-in tools. `pip install shrike-guard[claude-agent]`.
  - `shrike_guard.openai_agents` (OpenAI Agents SDK): a tool input guardrail
    attached to every function tool (a refused call is answered with
    `reject_content`, so the model reads the reason as the tool's output), a
    non-tripping input guardrail for the observe plane, and `request_scope`
    as a function tool. `pip install shrike-guard[openai-agents]`.
  - `shrike_guard.google_adk` (Google ADK): `before_tool_callback` (a refused
    call returns the reason as the tool's response), `before_model_callback`
    (a finding is appended to the request's instructions), and
    `request_scope` as a `FunctionTool`. `pip install shrike-guard[google-adk]`.
  - `shrike_guard.langgraph_agent` (LangChain `create_agent` and LangGraph):
    an agent middleware whose `wrap_tool_call` answers a refused call with a
    `ToolMessage`, or `govern_tools` for a hand-built `ToolNode`, and
    `request_scope` as a LangChain tool. `pip install shrike-guard[langgraph]`.
  - `shrike_guard.crewai_agent` (CrewAI): `govern_tools` wraps each tool so
    the reason reaches the model, `install` registers a global
    `before_tool_call` backstop and a `before_llm_call` observe hook, and
    `request_scope` as a CrewAI tool. `pip install shrike-guard[crewai]`.
  - `pip install shrike-guard[frameworks]` installs every framework.
- **Tool mappings.** A tool is a surface (`command`, `file`, `file_path`,
  `sql`, `web_search`, `rag_context`, `a2a_message`, `agent_card`, or
  `none`) and the argument that carries its payload. A tool with no mapping
  is refused with a message that says how to map it (`on_unmapped="deny"`),
  or allowed and recorded (`"allow"`), or has its arguments scanned as text
  (`"scan"`), or judged by name alone (`"authorize"`, see below). The Claude
  Agent SDK starter defaults to `"authorize"`, and its hook now sees every
  tool the agent can call rather than only the mapped ones, because a tool
  with no reader is exactly the one whose authorization nobody has checked.
  Pass an explicit tool list to `hooks_for` to narrow the matcher.
- **A conformance suite.** `tests/test_frameworks.py` drives every starter
  through the same table (allow, warn, block, hold, backend down, unmapped,
  a refused widening); each starter must answer it the same way.

### Changed
- **The CrewAI extra now requires crewai >= 1.15.** The starter wires
  `crewai.hooks` and `crewai.hooks.dispatch.HookAborted`, which 1.6.x does not
  carry. The floor said `>=1.0.0`, so a resolver was free to pick a release the
  starter cannot drive.

### Fixed
- **A too-old CrewAI no longer reports itself as missing.** The import guard
  answered "crewai is not installed" whatever the reason, sending anyone on an
  older release to reinstall a package they already had. It now names the
  installed version and says to upgrade.

## [4.1.0] - 2026-09-09

### Added
- **Act-plane scanning: every channel the backend scans is now reachable from
  the SDK.** The backend has scanned eight specialized content types since the
  act plane shipped; this SDK exposed two. `scan_command` — the highest-volume
  surface, the one an agent hits before every shell-out — had no method at all,
  so the only way to reach it was to hand-roll an HTTP call or route through the
  MCP server. New on **both** ``ScanClient`` and ``AsyncScanClient``:
  - ``scan_command(command, cwd=None)`` — shell commands, screened before the
    ``subprocess`` call. Commands are decomposed, so SQL passed to ``psql -c``,
    ``mysql -e``, or a heredoc is scanned as SQL rather than as opaque shell text.
  - ``scan_web_search(query)`` — search queries that acquire attack tooling,
    credentials, or evasion tradecraft.
  - ``scan_a2a_message(message)`` — instructions smuggled between agents.
  - ``scan_agent_card(agent_card, verify_signature=False)`` — capability
    misrepresentation in A2A discovery.
  - ``scan_rag_context(chunks, query=None)`` — retrieved context, the standard
    carrier for indirect prompt injection. Accepts a string or a list of strings.
  - ``scan_mcp_schema(name, description, input_schema=None)`` — a single MCP tool
    definition, for tool poisoning in a ``tools/list`` response. Screened once at
    registration, not per call.
- **``content_origin`` on every scan result.** Says where the scanned content
  came from: ``human_prompt``, ``agent_output``, ``agent_action``, or
  ``third_party``. This answers the question a verdict alone cannot — was that my
  prompt, or the agent acting on its own — which decides who a refusal message is
  addressed to. Unknown content types resolve to ``agent_action``, never to
  ``human_prompt``.
- **Act-plane parity tests** (``tests/test_actplane_parity.py``). Iterate the
  canonical channel list and fail when a channel has no SDK method, or when the
  sync and async clients expose different scan surfaces. The gap above went
  unnoticed because "the backend supports it" and "a customer can call it" were
  two facts with nothing comparing them. This is the comparison.

- **Per-request session identity — ``session_id``/``agent_id`` on the client,
  and ``for_session()``.** Session identity is the key the backend accumulates
  multi-turn risk against, so it has to mean one unit of work: one agent run,
  one conversation, one user's request. It defaults to a process-wide id, which
  suits a CLI or a worker but not a server serving many end users, where every
  user would share one risk score and one user's refusal would count against
  the next user's action. ``for_session()`` returns a view that shares the parent's
  connection pool, so deriving one per request is cheap::

      guard = ScanClient(api_key=KEY)          # once, at startup

      def handle(request):                     # per request
          scoped = guard.for_session(request.session_id)
          verdict = scoped.scan_command(request.command)

  Available on ``ScanClient`` and ``AsyncScanClient``. The process-wide default
  is unchanged when nothing is supplied, so single-agent callers keep multi-turn
  correlation; the SDK now warns once when it is in force. Silence that with
  ``SHRIKE_SUPPRESS_SESSION_WARNING=1``.

  ``evaluate_rotation``'s caller-owned branch now applies: a caller that
  supplies its own session id receives a rotation recommendation rather than a
  module-owned rotation.

### Fixed
- **``content_origin`` was computed by the backend and dropped before the caller.**
  The response sanitizer is an allow-list, and the field was never added to
  ``PRESERVED_GOVERNANCE_FIELDS``, so it was serialized by the server and stripped
  one layer before the application. It now survives sanitization.

## [4.0.5] - 2026-08-31

### Added
- **Custom endpoint for the Gemini wrapper (`base_url`).** `ShrikeGemini` now
  accepts `base_url=` (and passes through arbitrary `genai.Client` keyword
  arguments such as `http_options`), so Gemini calls can be routed to a
  compatible gateway or proxy — parity with the OpenAI and Anthropic wrappers,
  which already forwarded `base_url` via `**kwargs`. Honored by the
  `google-genai` SDK; the legacy `google-generativeai` SDK logs that it cannot
  redirect its endpoint. A caller-supplied `http_options` takes precedence.
- **Documented local / self-hosted LLM governance.** New README section and
  `examples/local_llm.py` show governing an OpenAI-compatible local runtime
  (Ollama, vLLM, LM Studio) by forwarding `base_url` to `ShrikeOpenAI`. The
  plumbing already worked; this makes it a supported, documented path.

### Changed
- **Provider dependency caps raised to allow current majors.** `openai` was
  capped `<3.0.0` and `anthropic` `<1.0.0`, which excluded the current releases
  (openai 3.x, anthropic 1.x) and could block installs for apps already on those
  majors. Raised to `openai <4.0.0` and `anthropic <2.0.0` after verifying the
  wrapper API surface we call (`chat.completions.create`, `messages.create`) is
  unchanged on the new majors — the full test suite passes against openai 3.6.0
  and anthropic 1.2.0. `google-genai` stays `<3.0.0` (current major is 2.x).

## [4.0.4] - 2026-07-30

### Fixed
- **Package docstring pointed at an unresolvable docs domain.** The top-level `shrike_guard` docstring (shown by `help(shrike_guard)` and IDE hovers) linked to `docs.shrike.security`, which does not resolve. It now points at `shrikesecurity.com/docs/sdk/python`. Documentation-only fix.
- **Stated Python floor corrected to match the package requirement.** The README badge and requirements section advertised Python 3.8+, while the package requires `>=3.10`. A 3.9 environment would have hit a resolver failure after reading the badge. Both now read 3.10+. No change to the actual supported range.

## [4.0.3] - 2026-07-17

### Fixed
- **Package module docstring corrected to match the actual defaults.** The top-level `shrike_guard` docstring (shown by `help(shrike_guard)` and IDE hovers) still described `fail_mode="open"` as the default and `scan_timeout` as 2.0 seconds. The real defaults are `fail_mode="closed"` (secure by default, since 2.0.0) and `scan_timeout=10.0`. Documentation-only fix — behavior is unchanged. `ShrikeScanError` and both READMEs were already correct; this was the last surface where the docstring inverted the fail-mode default.

## [4.0.2] - 2026-07-16

### Security
- **Fail-open verdicts now carry `degraded=True` on every wrapper.** The Anthropic and Gemini wrappers — and the timeout / backend-error fail-open paths on the OpenAI sync and async clients — previously returned a plain allow verdict under `fail_mode='open'` when the backend was unreachable, so a caller could not distinguish "scanned and clean" from "not scanned, enforcement skipped." All fail-open returns now route through `_results.fail_open_result`. The default remains fail-**closed**; this affects only callers who explicitly opt into fail-open.

### Changed
- **Provider dependency caps raised to allow current majors.** `openai` and `google-genai` were capped `<2.0.0`, which excluded the current releases (openai 2.x, google-genai 2.x) and could block installs for apps already on those majors. Raised to `<3.0.0` after verifying the wrapper API surface we call (`chat.completions.create`, `models.generate_content`) is unchanged on the new majors. Added a real-package shape test.

### Fixed
- **`__version__` no longer drifts from the distribution version.** 4.0.1 shipped with `_version.py` still reading `4.0.0`, so every scan stamped the `X-Shrike-SDK-Version` audit header as 4.0.0. `__version__` is now derived from the installed distribution metadata and guarded by a test so it cannot diverge again.

## [4.0.1] - 2026-07-16

### Fixed
- Corrected the `ShrikeScanError` docstring, which incorrectly described `fail_mode='open'` as the default. The default is `fail_mode='closed'` (secure by default across the 4.x line) — behavior is unchanged; this is a documentation-only fix so the source matches the shipped default on a clean install.

## [4.0.0] - 2026-07-13

### Version alignment (no breaking changes)
All Shrike client surfaces — MCP server (`shrike-mcp`), TypeScript SDK, and Python SDK — now share a single version line starting at 4.0.0. The jump aligns the surfaces on one major, not an API break: every prior release runs unchanged on 4.0.0. (The fail-closed default is unchanged across the 4.x line.)

### Added
- **Client-side auto-chunk for large inputs.** Prompts over 20KB are automatically split on natural boundaries (paragraph → line → hard cut) into ~8KB chunks and scanned sequentially with fail-fast on the first blocking verdict. Applies to both `ScanClient.scan()` and `AsyncScanClient.scan()`. New `chunker` module exports `AUTO_CHUNK_THRESHOLD`, `CHUNK_TARGET_SIZE`, `chunk_content()`, and `aggregate_chunk_results()` for callers who want to drive chunking directly.
- **Aggregation contract:** worst-action wins across chunks; violations dedup by (threat_type, severity, action); `session_state` from the last scanned chunk; `recovery` from the first blocking chunk.

### Why
Large single-shot scan inputs (agent transcripts, RAG context dumps, file contents) previously rode through the cascade as one oversized request — slower verdicts and more LLM-layer tokens burned per scan. Chunked inputs land in the backend cascade's small-content band, which allows earlier early-exit on clean content and cheaper verdicts on both sides of the wire. Fail-fast on the first blocked chunk means a threat at the top of a large document blocks without paying to scan the rest.

## [2.2.0] - 2026-07-06

### Added
- **Session rotation module — `evaluate_rotation`, `ROTATION_THRESHOLD`, `ModuleOwnedRotation`, `CallerOwnedRotationRecommendation`, `SessionRotation`** (mirrors TypeScript SDK). Pure function inspects a scan verdict and returns a two-shape rotation record — module-owned when the SDK's fallback `SESSION_ID` was in force, caller-owned recommendation when the caller supplied their own `session_id`. Discriminate on `rotated`. Triggers on `threat_type == "session_locked"` OR `session_risk_score >= ROTATION_THRESHOLD` (0.7). Per-event suggestion contract — each caller-owned recommendation mints a fresh `suggested_new_session_id` that is NOT stable across events; do not cache.
- **`ShrikeRateLimitError`** — new typed exception raised on backend 429 responses. Extends `ShrikeScanError` so existing `except ShrikeScanError:` handlers continue to work unchanged; new callers wanting to back off on rate-limit specifically can catch this class. Parses `Retry-After` header when present.

### Why
Cross-language SDK parity. The TypeScript SDK ships `evaluateRotation` + `ShrikeRateLimitError` today; this brings the Python SDK to feature-equivalence so customers flipping between languages see identical rotation and rate-limit semantics.

## [2.1.0] - 2026-07-02

### Added
- **Client-side PII redaction.** `redact_pii()`, `rehydrate_pii()`, `get_redaction_summary()`, `update_pii_patterns()`, and `get_pii_pattern_count()` exported from `shrike_guard`. Detects and tokenizes 20+ PII types (SSN, credit card, email, phone, address, medical record, wallet, etc.) BEFORE the prompt leaves customer environment — Shrike backend never sees the raw PII.
- **`sync_pii_patterns(endpoint, api_key=None)`** — one-shot startup call fetches the canonical Presidio-derived pattern set from the Shrike backend so client-side detection stays uniform with the server-side scan. Uses httpx (already a hard SDK dep) to inherit certifi's bundled root certs and route around the Python.org macOS installer's empty cert store. Fails safe: on any error (network / timeout / malformed / non-200) the bootstrap patterns stay in place; sync never blocks scans.
- **Backend-owned prefix contract.** The recognizer ships its client-side redaction tag (e.g. `[IP_1]`) as part of the pattern payload; the client uses it verbatim. When the backend omits the field (pre-2026-07-02 releases), the SDK derives the prefix from the threat_type. No pattern is ever silently dropped for an unmapped prefix. Adding a new backend pattern requires zero SDK changes.

### Why
Client-side redaction removes PII before it crosses the network to Shrike's backend — defense-in-depth for HIPAA / PCI / GLBA / CMMC workloads on top of the BAA/DPA that already covers transmission. The `sync_pii_patterns` step keeps client patterns in step with backend patterns without shipping SDK updates every time Presidio adds a recognizer.

## [2.0.0] - 2026-06-28

### Changed (BREAKING)
- **Default `fail_mode` flipped from `"open"` to `"closed"`.** When the Shrike backend is unreachable, returns an error, or times out, the SDK now blocks the request by raising `ShrikeScanError` instead of allowing it through with `{"safe": true}`. This matches the Zero Trust contract published on the Shrike platform: if the guard cannot evaluate the action, the action does not proceed. To restore the previous behavior, pass `fail_mode="open"` explicitly when constructing any wrapper.

### Why
The prior fail-open default contradicted the Shrike Marketplace listing's headline promise ("evaluated before execution, no implicit trust"). A security SDK that lets traffic through during a backend outage provides no guard exactly when adversarial pressure is highest. Bumped to a major version so upgraders see the change.

### Migration
- Most users: no action needed. The new default is the more secure posture.
- If you depend on availability over enforcement (e.g. non-production experiments, internal tools where outages must not block users): pass `fail_mode="open"` explicitly to every wrapper. The flag itself is unchanged.

### Fixed
- Aligned `_version.py` (`1.1.1`) with `pyproject.toml` (`1.1.2`); both now report `2.0.0`. Prior drift caused the `X-Shrike-SDK-Version` header to misreport.

## [1.1.0] - 2026-02-19

### Added
- README now documents all three providers (OpenAI, Anthropic Claude, Gemini)
- "What Shrike Detects" section: 86+ rules across 6 compliance frameworks
- Installation instructions for optional providers (anthropic, gemini, all extras)
- SQL injection and file scanning documented in README

### Changed
- Updated backend tier description: all tiers now get full 9-layer cascade (L1-L8)

## [1.0.0] - 2026-01-15

### Added
- Initial release
- Drop-in OpenAI, Anthropic, and Gemini client wrappers
- Automatic prompt scanning via Shrike backend
- Fail-open and fail-closed modes
- Async support for OpenAI
- SQL injection scanning
- File path and content scanning
- Response sanitization (IP protection)
