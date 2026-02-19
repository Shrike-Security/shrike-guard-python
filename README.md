# Shrike Guard

[![PyPI version](https://badge.fury.io/py/shrike-guard.svg)](https://badge.fury.io/py/shrike-guard)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Shrike Guard** is a Python SDK that provides security protection for your LLM applications. It wraps OpenAI, Anthropic (Claude), and Google Gemini clients to automatically scan all prompts for security threats before they reach the LLM.

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

Shrike's backend runs a 9-layer detection cascade with **86+ security rules** across **6 compliance frameworks**:

| Framework | Rules | Coverage |
|-----------|-------|----------|
| **HIPAA** | 19 | Protected health information (PHI) — 19 Safe Harbor identifiers |
| **SOC 2** | 21 | Secrets, credentials, API keys, cloud tokens |
| **ISO 27001** | 19 | Information security — passwords, tokens, certificates |
| **PCI-DSS** | 8 | Cardholder data — PAN, CVV, expiry, track data, PINs |
| **GDPR** | 11 | EU personal data — names, addresses, national IDs |
| **WebMCP Tool Safety** | 8 | MCP tool description injection, data exfiltration |

Plus built-in detection for prompt injection, jailbreaks, social engineering, dangerous requests, and 130+ threat patterns.

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

Shrike Guard focuses on **pre-flight protection** - blocking malicious prompts BEFORE they reach the LLM. This:
- Prevents prompt injection attacks at the source
- Has zero latency impact on LLM responses
- Catches 95%+ of threats (attacks are in the INPUT)

## License

Apache 2.0

## Support

- Documentation: https://docs.shrike.security/sdk/python
- Issues: https://github.com/Shrike-Security/shrike-guard-python/issues
- Email: support@shrike.security
