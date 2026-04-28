# Shrike Guard

[![PyPI version](https://badge.fury.io/py/shrike-guard.svg)](https://badge.fury.io/py/shrike-guard)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Shrike Guard** is a Python SDK for the [Shrike](https://shrikesecurity.com) platform — AI governance for every AI interaction. It wraps OpenAI, Anthropic (Claude), and Google Gemini clients to automatically evaluate all prompts against policy before they reach the LLM. Govern LangChain agents, RAG pipelines, FastAPI chatbots, and any Python AI application with the same multi-layered cognitive pipeline.

## Features

- **Drop-in replacement** for OpenAI, Anthropic, and Gemini clients
- **Automatic prompt scanning** for:
  - Prompt injection attacks
  - PII/sensitive data leakage
  - Jailbreak attempts
  - SQL injection
  - Path traversal
  - Malicious instructions
- **Fail-safe modes**: Choose between fail-open (default) or fail-closed behavior
- **Async support**: Works with both sync and async clients
- **Zero code changes**: Just replace your import

## What Shrike Detects

Shrike's backend runs a multi-stage detection pipeline with security rules across **7 compliance frameworks**:

| Framework | Coverage |
|-----------|----------|
| **GDPR** | EU personal data — names, addresses, national IDs |
| **HIPAA** | Protected health information (PHI) |
| **ISO 27001** | Information security — passwords, tokens, certificates |
| **SOC 2** | Secrets, credentials, API keys, cloud tokens |
| **NIST** | AI risk management (IR 8596), cybersecurity framework (CSF 2.0) |
| **PCI-DSS** | Cardholder data — PAN, CVV, expiry, track data |
| **WebMCP** | MCP tool description injection, data exfiltration |

Plus built-in detection for prompt injection, jailbreaks, social engineering, and dangerous requests.

### Tiers

Detection depth depends on your tier. All tiers get the same SDK wrappers — tiers control which backend layers run.

| | Anonymous | Community | Pro | Enterprise |
|---|---|---|---|---|
| Detection Layers | L1-L5 | L1-L7 | L1-L8 | L1-L9 |
| API Key | Not needed | Free signup | Paid | Paid |
| Rate Limit | — | 10/min | 100/min | 1,000/min |
| Scans/month | — | 1,000 | 25,000 | 1,000,000 |

**Anonymous** (no API key): Pattern-based detection (L1-L5). **Community** (free): Adds LLM-powered semantic analysis. Register at [shrikesecurity.com/signup](https://shrikesecurity.com/signup) — instant, no credit card.

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
# Fail-open (default): Allow requests if scan fails
# Best for: Most applications where availability is important
client = ShrikeOpenAI(
    api_key="sk-...",
    shrike_api_key="shrike-...",
    fail_mode="open",  # This is the default
)

# Fail-closed: Block requests if scan fails
# Best for: Security-critical applications
client = ShrikeOpenAI(
    api_key="sk-...",
    shrike_api_key="shrike-...",
    fail_mode="closed",
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

## SQL and File Scanning

```python
from shrike_guard import ScanClient

with ScanClient(api_key="shrike-...") as scanner:
    # Scan SQL queries for injection attacks
    sql_result = scanner.scan_sql("SELECT * FROM users WHERE id = 1")
    if not sql_result["safe"]:
        print(f"SQL threat: {sql_result['reason']}")

    # Scan file paths for path traversal
    file_result = scanner.scan_file("/app/data/output.csv")

    # Scan file content for secrets/PII
    content_result = scanner.scan_file("/tmp/config.py", "api_key = 'sk-...'")
```

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

- **Python**: 3.8+
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
```

## Scope and Limitations

| Scanned | Not Scanned |
|---------|-------------|
| Input prompts (user messages) | Streaming output from LLM |
| System prompts | Image/audio content |
| Multi-modal text content | Non-chat API calls |
| SQL queries | |
| File paths and content | |

### Why Input-Only Scanning?

Shrike Guard focuses on **pre-flight protection** — blocking malicious prompts BEFORE they reach the LLM. This:
- Prevents prompt injection attacks at the source
- Has zero latency impact on LLM responses
- Catches the vast majority of threats at the input layer

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
| **LangChain / CrewAI agents** | Wrap your LLM client. Every agent action scanned before execution. |
| **RAG pipelines** | Scan retrieved context + user queries for PII leakage and injection. |
| **FastAPI chatbot** | Middleware-style integration. Scan every request before it hits the model. |
| **Internal AI tools** | Protect Slack bots, email assistants, and internal AI applications. |

## Alternatives

Looking for a Python AI security SDK? Here's how Shrike Guard compares:

| Feature | Shrike Guard | Lakera | Prompt Armor |
|---|---|---|---|
| Drop-in OpenAI/Anthropic/Gemini wrapper | Yes | No | No |
| Multi-layered evaluation pipeline | Yes | Limited | Limited |
| PII detection + redaction | Yes | Partial | No |
| Async support | Yes | Partial | No |
| Free tier (no API key) | Yes | No | No |
| Open source client | Yes (Apache 2.0) | No | No |

## License

Apache 2.0

## Support

- [Shrike](https://shrikesecurity.com) — Sign up, dashboard, docs
- [Documentation](https://shrikesecurity.com/docs) — Quick start, API reference
- [GitHub Issues](https://github.com/Shrike-Security/shrike-guard-python/issues) — Bug reports
- [MCP Server](https://github.com/Shrike-Security/shrike-mcp) — For MCP/agent integration
- [TypeScript SDK](https://github.com/Shrike-Security/shrike-guard-js) — TypeScript equivalent
