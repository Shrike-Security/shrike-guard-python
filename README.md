# Shrike Guard

[![PyPI version](https://badge.fury.io/py/shrike-guard.svg)](https://badge.fury.io/py/shrike-guard)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Shrike Guard** is a Python SDK for the [Shrike](https://shrikesecurity.com) platform — AI governance for every AI interaction. It wraps OpenAI, Anthropic (Claude), and Google Gemini clients to automatically evaluate all prompts against policy before they reach the LLM. Govern LangChain agents, RAG pipelines, FastAPI chatbots, and any Python AI application with the same 9-layer cognitive pipeline.

It scans two different things. **Prompts and responses**, which is what a guardrail library normally means. And **agent actions** — the shell command, the SQL query, the web search, the retrieved document, the MCP tool definition — screened before they run, which is where an autonomous agent actually causes harm. See [Scanning agent actions](#scanning-agent-actions-shell-commands-sql-web-search-rag-mcp-tools).

## Features

- **Drop-in replacement** for OpenAI, Anthropic, and Gemini clients
- **Automatic prompt scanning** for:
  - Prompt injection attacks
  - PII/sensitive data leakage
  - Jailbreak attempts
  - SQL injection
  - Path traversal
  - Malicious instructions
- **Pre-execution scanning for agent actions**: shell commands, SQL, file writes, web searches, RAG context, agent-to-agent messages, agent cards, and MCP tool schemas
- **Content provenance** (`content_origin`): every verdict says whether a human typed it, the model wrote it, the agent is about to do it, or it arrived from outside
- **Fail-safe modes**: Defaults to fail-closed (Zero Trust posture); opt into fail-open explicitly when availability outranks enforcement
- **Async support**: Works with both sync and async clients, with identical scan surfaces
- **Zero code changes**: Just replace your import

## What Shrike Detects

Shrike's 9-layer cognitive pipeline includes sensitive-data detection aligned to 5 major regulatory frameworks:

| Framework | Coverage |
|-----------|----------|
| **GDPR** | EU personal data — names, addresses, national IDs |
| **HIPAA** | Protected health information (PHI) |
| **ISO 27001** | Information security — passwords, tokens, certificates |
| **SOC 2** | Secrets, credentials, API keys, cloud tokens |
| **NIST** | AI risk management (IR 8596), cybersecurity framework (CSF 2.0) |

Detection coverage is not a certification claim — see [shrikesecurity.com/compliance](https://shrikesecurity.com/compliance) for our current certification status. Plus built-in detection for prompt injection, jailbreaks, social engineering, and dangerous requests.

### Tiers

Detection depth depends on your tier. All tiers get the same SDK wrappers — tiers control which backend layers run.

| | Anonymous | Community | Pro | Enterprise |
|---|---|---|---|---|
| Detection Layers | L1-L5 | L1-L5 | L1-L9 (full) | L1-L9 (full) |
| API Key | Not needed | Free signup | Paid | Paid |
| Rate Limit | — | 10/min | 100/min | 1,000/min |
| Scans/month | — | 1,000 | 25,000 | 1,000,000 |

**Anonymous** (no API key): Pattern-based detection (L1-L5). **Community** (free): Same L1-L5 detection with a dashboard and higher limits; LLM-powered semantic analysis (L6-L9) is Pro+. Register at [shrikesecurity.com/signup](https://shrikesecurity.com/signup) — instant, no credit card.

## Installation

```bash
pip install shrike-guard                      # OpenAI (included by default)
pip install shrike-guard[anthropic]            # + Anthropic Claude
pip install shrike-guard[gemini]               # + Google Gemini
pip install shrike-guard[all]                  # All providers
```

## Quick Start

### OpenAI

```python
from shrike_guard import ShrikeOpenAI

# Replace 'from openai import OpenAI' with this
client = ShrikeOpenAI(
    api_key="sk-...",           # Your OpenAI API key
    shrike_api_key="shrike-...", # Your Shrike API key
)

# Use exactly like the regular OpenAI client
response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello, how are you?"}]
)

print(response.choices[0].message.content)
```

### Anthropic (Claude)

```python
from shrike_guard import ShrikeAnthropic

client = ShrikeAnthropic(
    api_key="sk-ant-...",
    shrike_api_key="shrike-...",
)

response = client.messages.create(
    model="claude-sonnet-4-5-20250929",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Hello!"}]
)

print(response.content[0].text)
```

### Google Gemini

```python
from shrike_guard import ShrikeGemini

client = ShrikeGemini(
    api_key="AIza...",
    shrike_api_key="shrike-...",
)

model = client.GenerativeModel("gemini-pro")
response = model.generate_content("Hello!")

print(response.text)
```

### Framework starters

Shrike governs an agent from inside its tool loop: every tool call is judged
before it executes, the person's prompt is scanned on the way in and never
blocked, and the agent gets one tool, `request_scope`, to ask for more than
it holds. One framework-free core, `shrike_guard.govern`, carries that
behaviour; each starter is a thin translation of one framework's hooks.

| Framework | Module | Install | What it wires |
|---|---|---|---|
| Claude Agent SDK | `shrike_guard.claude_agent` | `shrike-guard[claude-agent]` | `PreToolUse` and `UserPromptSubmit` hooks, an in-process MCP tool |
| OpenAI Agents SDK | `shrike_guard.openai_agents` | `shrike-guard[openai-agents]` | a tool input guardrail on every function tool, a non-tripping input guardrail, a function tool |
| Google ADK | `shrike_guard.google_adk` | `shrike-guard[google-adk]` | `before_tool_callback` and `before_model_callback`, a `FunctionTool` |
| LangChain `create_agent` / LangGraph | `shrike_guard.langgraph_agent` | `shrike-guard[langgraph]` | an agent middleware (`wrap_tool_call`, `before_agent`) or wrapped tools for a `ToolNode` |
| CrewAI | `shrike_guard.crewai_agent` | `shrike-guard[crewai]` | wrapped tools, plus a global `before_tool_call` hook and a `before_llm_call` hook |

Every starter has the same shape. Build it, map your tools to Shrike's
surfaces, hand it to the framework:

```python
from shrike_guard import ScanClient
from shrike_guard.openai_agents import govern   # or claude_agent, google_adk, langgraph_agent, crewai_agent

guard = ScanClient(api_key="shrike-...", agent_id="invoice-agent", session_id=run_id)
gov = govern(guard, agent_id="invoice-agent")
gov.declare(["file_path", "file_content", "sql"], purpose="Reconcile Q3 vendor invoices")

gov.map_tool("run_query", "sql", arg="query")
gov.map_tool("save_report", "file", path_arg="path", content_arg="text")
gov.exempt("get_time")

agent = gov.govern_agent(Agent(name="invoices", tools=[run_query, save_report, get_time]))
```

A tool mapping says which surface a tool is and which argument carries the
payload: `command` (with an optional `cwd_arg`), `file` (a path and the
content written to it), `file_path`, `sql`, `web_search`, `rag_context`,
`a2a_message`, `agent_card`, or `none` for a tool allowed without a scan.
The Claude Agent SDK starter ships mappings for the SDK's built-in tools;
the others govern the tools you write, so they need your mappings.

A tool with no mapping is refused, with a message that says how to map it,
until you map it or choose what an unmapped tool gets. `on_unmapped="authorize"` asks the
backend whether the agent may call it at all: the arguments stay put, and the
tool's NAME goes up, where the operator's declared scope answers. A tool
outside the allowlist is refused by name even though nothing read what it was
carrying, and an expired or exhausted scope holds it. That permit is narrower
than a mapped tool's and the record says so, with the decision's surface
recorded as `authorization`. `"allow"` records the call and moves on without
asking; `"scan"` sends the arguments to be read as text.

What the model sees is the same everywhere: an allowed call runs; a warned
call runs with the advisory; a blocked call does not run and the model gets
the reason; a held call (an action outside the declared scope) does not run
and the model gets the reason, the recovery, and the instruction to ask with
`request_scope` and then stop. An action Shrike could not check is refused
(`fail_mode="closed"`). Every decision lands on `gov.decisions` and on your
`on_decision` callback, with the axis that objected.

Where a framework can route a hold to a person, `on_hold="ask"` does that
(the Claude Agent SDK's `can_use_tool`). Where it cannot, a hold is answered
like a refusal and the model is told an operator can grant it on the Shrike
Agents screen.

The Claude Agent SDK starter in full:

```python
from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient
from shrike_guard import ScanClient
from shrike_guard.claude_agent import govern

guard = ScanClient(api_key="shrike-...", agent_id="invoice-agent", session_id=run_id)
gov = govern(guard, agent_id="invoice-agent")
gov.declare(["file_path", "file_content"], purpose="Reconcile Q3 vendor invoices")

options = ClaudeAgentOptions(
    hooks=gov.hooks,
    mcp_servers={"shrike": gov.mcp_server},
    allowed_tools=["Read", "Write", "Bash", *gov.tool_names],
    strict_mcp_config=True,
)
```

`Bash` goes to `scan_command`; `Write`, `Edit`, `MultiEdit` and `NotebookEdit`
go to `scan_file` for the path and for the content; `Read` to `scan_file`;
`WebSearch` and `WebFetch` to `scan_web_search`.

### Async Usage

```python
import asyncio
from shrike_guard import ShrikeAsyncOpenAI

async def main():
    client = ShrikeAsyncOpenAI(
        api_key="sk-...",
        shrike_api_key="shrike-...",
    )

    response = await client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Hello!"}]
    )

    print(response.choices[0].message.content)
    await client.close()

asyncio.run(main())
```

## Configuration

### Fail Modes

Choose how the SDK behaves when the security scan fails (timeout, network error, etc.):

```python
# Fail-closed (the default across the 4.x line): Block requests if scan fails
# Best for: Production security workloads. If the Shrike backend is down,
# the SDK raises ShrikeScanError instead of allowing traffic through unguarded.
client = ShrikeOpenAI(
    api_key="sk-...",
    shrike_api_key="shrike-...",
    fail_mode="closed",  # This is the default
)

# Fail-open: Allow requests if scan fails
# Best for: Non-production experiments, internal tools where availability must
# outrank enforcement. Trades the guard's enforcement promise for uptime.
client = ShrikeOpenAI(
    api_key="sk-...",
    shrike_api_key="shrike-...",
    fail_mode="open",
)
```

### Timeout Configuration

```python
client = ShrikeOpenAI(
    api_key="sk-...",
    shrike_api_key="shrike-...",
    scan_timeout=2.0,  # Timeout in seconds (default: 10.0)
)
```

### Custom Endpoint

For self-hosted Shrike deployments:

```python
client = ShrikeOpenAI(
    api_key="sk-...",
    shrike_api_key="shrike-...",
    shrike_endpoint="https://your-shrike-instance.com",
)
```

### Sessions: one per unit of work, not one per process

Shrike correlates risk across a session. After a refusal, later actions in the
same session are held until the session recovers. That is the multi-turn
defence, and it means the session id has to mean one unit of work: one agent
run, one conversation, one user's request.

By default the SDK scans under one id for the whole process. That suits a CLI,
a worker, or a single agent. It does not suit a server that scans on behalf of
many end users, because every user then shares one risk score, and one user's
refusal counts against the next user's action.

Build one client at startup and derive a per-request view from it. The view
shares the connection pool, so it costs nothing to make one per request:

```python
from shrike_guard.scanner import ScanClient

guard = ScanClient(api_key="shrike-...")          # once, at startup

def handle(request):                               # per request
    scoped = guard.for_session(request.session_id)
    verdict = scoped.scan_command(request.command)
    if verdict["refuse_tier"] != "allow":
        ...
```

Or pin the identity at construction when one client serves one unit of work:

```python
client = ScanClient(api_key="shrike-...", session_id="job-42", agent_id="ingest")
```

`agent_id` is separate on purpose: it names *which agent* a scope is enforced
against and who an incident is attributed to. Set it when one process drives
several distinct agents.

The SDK warns once per process when it is scanning under the shared default.
Set `SHRIKE_SUPPRESS_SESSION_WARNING=1` to silence it once you have decided
the default is what you want.

### Local and self-hosted LLMs

Shrike governs the model you point it at — it does not have to be a hosted
frontier API. Local runtimes like [Ollama](https://ollama.com),
[vLLM](https://docs.vllm.ai), and LM Studio expose an OpenAI-compatible
endpoint, so `ShrikeOpenAI` guards them by forwarding a `base_url`:

```python
from shrike_guard import ShrikeOpenAI

# Ollama serving llama3 locally, governed by Shrike before every call
client = ShrikeOpenAI(
    api_key="ollama",                       # local servers ignore the value
    base_url="http://localhost:11434/v1",   # your local/self-hosted endpoint
    shrike_api_key="shrike-...",            # governance still runs server-side
)

response = client.chat.completions.create(
    model="llama3",
    messages=[{"role": "user", "content": "Summarize this ticket…"}],
)
```

Any keyword argument other than `shrike_*` is passed straight through to the
underlying provider client, so this also covers `ShrikeAnthropic(base_url=...)`
for Anthropic-compatible gateways. For Gemini, point it at a compatible
endpoint the same way (added in 4.0.5):

```python
from shrike_guard import ShrikeGemini

client = ShrikeGemini(
    api_key="…",
    shrike_api_key="shrike-...",
    base_url="https://your-gemini-gateway.example",  # google-genai SDK only
)
```

The prompt still leaves your process to reach the Shrike backend for scanning;
the *model call* stays on your local/self-hosted endpoint.

## Scanning agent actions (shell commands, SQL, web search, RAG, MCP tools)

Scanning the prompt protects the model. It does not protect the shell. An agent
that was never told anything malicious can still be talked into running
`curl … | sh` by a poisoned README, and the prompt scan has no view of that.

`ScanClient` exposes a method per action channel. Call the one that matches
what the agent is about to do, before it does it:

| Channel | Method | Screens for |
|---|---|---|
| Shell command | `scan_command(command, cwd=None)` | destructive commands, data exfiltration, credential dumps, embedded SQL injection |
| SQL query | `scan_sql(query, database=None, allow_destructive=False)` | SQL injection, unauthorized destructive statements |
| File path | `scan_file(path)` | path traversal, writes outside the working tree |
| File content | `scan_file(path, content)` | secrets, credentials, PII before they land on disk |
| Web search | `scan_web_search(query)` | searches that acquire attack tooling, credentials, or evasion tradecraft |
| RAG context | `scan_rag_context(chunks, query=None)` | indirect prompt injection in retrieved documents |
| Agent message | `scan_a2a_message(message)` | instructions smuggled between agents |
| Agent card | `scan_agent_card(agent_card, verify_signature=False)` | capability misrepresentation in A2A discovery |
| MCP tool schema | `scan_mcp_schema(name, description, input_schema=None)` | tool poisoning in `tools/list` responses |

```python
from shrike_guard import ScanClient

with ScanClient(api_key="shrike-...") as scanner:
    # Before shelling out
    cmd = scanner.scan_command('psql -c "SELECT * FROM users"', cwd="/srv/app")
    if not cmd["safe"]:
        raise RuntimeError(f"Refused: {cmd['reason']}")

    # Before querying
    sql = scanner.scan_sql("SELECT * FROM users WHERE id = %s", database="postgres")

    # Before writing
    write = scanner.scan_file("/tmp/config.py", "api_key = 'sk-...'")

    # Before searching the web
    search = scanner.scan_web_search("sql injection prevention owasp")
```

A shell command is not one thing. `scan_command` decomposes it, so SQL passed to
`psql -c`, `mysql -e`, or a heredoc is scanned as SQL rather than as an opaque
string of shell text.

Every method above exists on `AsyncScanClient` with the same signature:

```python
from shrike_guard import AsyncScanClient

async with AsyncScanClient(api_key="shrike-...") as scanner:
    verdict = await scanner.scan_command("rm -rf /var/data")
```

### Indirect prompt injection in RAG pipelines

Retrieved chunks are text somebody else wrote. They are the standard carrier for
indirect prompt injection: the user asks nothing unusual, the document tells the
model what to do, and the model complies. Scan on the way in, not after the
model has acted:

```python
chunks = vector_store.similarity_search(user_query, k=5)

verdict = scanner.scan_rag_context(
    [c.page_content for c in chunks],
    query=user_query,
)

if not verdict["safe"]:
    # The retrieved context is hostile, not the user's question.
    logger.warning("Poisoned context: %s", verdict["reason"])
```

### MCP tool poisoning

An MCP tool description is read by the model as guidance. A hostile server can
put instructions in the `description` field of a tool that never executes, and
the agent will act on them at registration time. Screen every entry of a
`tools/list` response from a server you do not control:

```python
for tool in (await mcp_client.list_tools()).tools:
    verdict = scanner.scan_mcp_schema(
        tool.name,
        tool.description or "",
        tool.inputSchema,
    )
    if not verdict["safe"]:
        logger.warning("Not registering %s: %s", tool.name, verdict["reason"])
        continue
    register(tool)
```

Screening happens once per tool at registration, not on every call.

## Who is answerable: `content_origin`

Every verdict carries `content_origin`, which says where the scanned content
came from. It answers the question a verdict alone cannot: *was that my prompt,
or the agent acting on its own?*

| Value | Meaning |
|---|---|
| `human_prompt` | the operator typed it |
| `agent_output` | the model generated it |
| `agent_action` | the agent is about to do it (every act-plane channel) |
| `third_party` | it arrived from outside: a tool result, a retrieved document, a peer agent |

```python
verdict = scanner.scan_rag_context(chunks)

if not verdict["safe"]:
    if verdict.get("content_origin") == "human_prompt":
        show_user(f"Your request was blocked: {verdict['reason']}")
    else:
        # The agent poisoned its own context. Telling the user "your request
        # was blocked" would be both wrong and unhelpful.
        logger.warning("agent-side refusal: %s", verdict["reason"])
        retry_with_clean_context()
```

Unknown content types resolve to `agent_action`, never to `human_prompt`:
attributing an unattributable action to the operator is the one error that is
never safe to make by default.

## Error Handling

```python
from shrike_guard import ShrikeOpenAI, ShrikeBlockedError, ShrikeScanError

client = ShrikeOpenAI(
    api_key="sk-...",
    shrike_api_key="shrike-...",
    fail_mode="closed",  # To see scan errors
)

try:
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Some prompt..."}]
    )
except ShrikeBlockedError as e:
    # Prompt was blocked due to security threat
    print(f"Blocked: {e.message}")
    print(f"Threat type: {e.threat_type}")
    print(f"Confidence: {e.confidence}")
except ShrikeScanError as e:
    # Scan failed (only raised with fail_mode="closed")
    print(f"Scan error: {e.message}")
```

## Low-Level Scan Client

For more control, use the scan client directly:

```python
from shrike_guard import ScanClient

with ScanClient(api_key="shrike-...") as scanner:
    result = scanner.scan("Check this prompt for threats")

    if result["safe"]:
        print("Prompt is safe!")
    else:
        print(f"Threat detected: {result['reason']}")
```

## Compatibility

- **Python**: 3.10+
- **LLM SDKs**:
  - OpenAI SDK `>=1.0.0`
  - Anthropic SDK `>=0.18.0` (optional: `pip install shrike-guard[anthropic]`)
  - Google Generative AI `>=0.3.0` (optional: `pip install shrike-guard[gemini]`)
- Works with:
  - OpenAI API
  - Azure OpenAI
  - OpenAI-compatible APIs (Ollama, vLLM, etc.)

## Environment Variables

You can configure the SDK using environment variables:

```bash
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."
export SHRIKE_API_KEY="shrike-..."
export SHRIKE_ENDPOINT="https://your-shrike-instance.com"
export SHRIKE_AGENT_ID="ingest"                 # names this process's agent; see Sessions
export SHRIKE_SUPPRESS_SESSION_WARNING=1        # once you have decided the shared session is right
```

## Scope and Limitations

| Scanned | Not Scanned |
|---------|-------------|
| Input prompts (user messages) | Streaming output from LLM |
| System prompts | Image/audio content |
| Multi-modal text content | Non-chat API calls |
| SQL queries | |
| File paths and content | |
| Shell commands | |
| Web search queries | |
| Retrieved RAG context | |
| Agent-to-agent messages and agent cards | |
| MCP tool schemas | |

### Why Pre-Execution Scanning?

Shrike Guard focuses on **pre-flight protection** — evaluating a prompt before it
reaches the LLM, and an action before it runs. This:
- Prevents prompt injection attacks at the source
- Has zero latency impact on LLM responses
- Puts the decision point before the side effect, where refusing still costs nothing

An action already taken cannot be un-taken by detecting it afterwards. That is the
distinction between this and after-the-fact monitoring: the verdict arrives while
refusing is still free.

## Other Integration Surfaces

Shrike Guard is one of several ways to integrate with the Shrike platform:

- **MCP Server** — `npx shrike-mcp` ([GitHub](https://github.com/Shrike-Security/shrike-mcp))
- **TypeScript SDK** — `npm install shrike-guard` ([GitHub](https://github.com/Shrike-Security/shrike-guard-js))
- **REST API** — `POST https://api.shrikesecurity.com/agent/scan`
- **LLM Gateway** — Change one URL, scan everything
- **Browser Extension** — Chrome/Edge for ChatGPT, Claude, Gemini
- **Dashboard** — [shrikesecurity.com](https://shrikesecurity.com)

## Use Cases

| Scenario | How Shrike Guard Helps |
|---|---|
| **Coding agents that shell out** | `scan_command` before every `subprocess` call. Destructive commands, exfiltration, and SQL smuggled through `psql -c` are caught before the process starts. |
| **LangChain / LangGraph / CrewAI agents** | Wrap your LLM client for prompts, call the act-plane methods before tool execution. |
| **RAG pipelines** | `scan_rag_context` on retrieved chunks for indirect prompt injection, plus PII leakage on the query. |
| **MCP clients** | `scan_mcp_schema` on every `tools/list` entry from a server you do not control, to catch tool poisoning at registration. |
| **Multi-agent systems** | `scan_a2a_message` and `scan_agent_card` for instructions smuggled between agents. |
| **FastAPI chatbot** | Middleware-style integration. Scan every request before it hits the model. |
| **Internal AI tools** | Protect Slack bots, email assistants, and internal AI applications. |

## How This Differs From a Prompt Scanner

If you are evaluating Python AI security SDKs, this is the distinction worth
testing against your own workload.

Most guardrail libraries answer one question: **is this text hostile?** They read
the prompt, and sometimes the response. That is necessary, and Shrike Guard does
it through a 9-layer cascade with PII redaction and multi-turn session
correlation.

But an autonomous agent does not cause harm by saying something. It causes harm
by *doing* something: running a command, writing a file, querying a database,
calling a tool. Shrike Guard scans those too, before they execute:

- **A verdict per action channel** — shell commands, SQL, file writes, web
  searches, RAG context, agent-to-agent messages, agent cards, MCP tool schemas.
  See [Scanning agent actions](#scanning-agent-actions-shell-commands-sql-web-search-rag-mcp-tools).
- **Pre-execution, not after the fact.** The verdict arrives while refusing is
  still free. An action already taken cannot be un-taken by detecting it.
- **Provenance on every verdict** (`content_origin`) — whether a human typed it,
  the model wrote it, the agent is about to do it, or it arrived from outside.
- **A governance contract, not just a boolean** — `refuse_tier`
  (allow / warn / require_approval / block), a `recovery` block telling the agent
  how to proceed legitimately, and `session_state`. Present on safe verdicts too.
- **Drop-in wrappers** for OpenAI, Anthropic, and Gemini, so the prompt-scanning
  half needs no code changes.
- **Identical sync and async surfaces**, enforced by a test rather than by habit.
- **Free tier with no API key**, and an Apache 2.0 client you can read.

## License

Apache 2.0

## Support

- [Shrike](https://shrikesecurity.com) — Sign up, dashboard, docs
- [Documentation](https://shrikesecurity.com/docs) — Quick start, API reference
- [GitHub Issues](https://github.com/Shrike-Security/shrike-guard-python/issues) — Bug reports
- [MCP Server](https://github.com/Shrike-Security/shrike-mcp) — For MCP/agent integration
- [TypeScript SDK](https://github.com/Shrike-Security/shrike-guard-js) — TypeScript equivalent
