# Shrike Guard

[![PyPI version](https://badge.fury.io/py/shrike-guard.svg)](https://badge.fury.io/py/shrike-guard)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Shrike Guard** is a Python SDK that provides security protection for your LLM applications. It wraps the OpenAI Python client to automatically scan all prompts for security threats before they reach the LLM.

## Features

- **Drop-in replacement** for the OpenAI Python client
- **Automatic prompt scanning** for:
  - Prompt injection attacks
  - PII/sensitive data leakage
  - Jailbreak attempts
  - Malicious instructions
- **Fail-safe modes**: Choose between fail-open (default) or fail-closed behavior
- **Async support**: Works with both sync and async OpenAI clients
- **Zero code changes**: Just replace your import

## Installation

```bash
pip install shrike-guard
```

## Quick Start

### Synchronous Usage

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
    scan_timeout=2.0,  # Timeout in seconds (default: 2.0)
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
- **OpenAI SDK**: 1.0.0+
- Works with:
  - OpenAI API
  - Azure OpenAI
  - OpenAI-compatible APIs (Ollama, vLLM, etc.)

## Environment Variables

You can configure the SDK using environment variables:

```bash
export OPENAI_API_KEY="sk-..."
export SHRIKE_API_KEY="shrike-..."
export SHRIKE_ENDPOINT="https://your-shrike-instance.com"
```

Then initialize without explicit arguments:

```python
import os
from shrike_guard import ShrikeOpenAI

client = ShrikeOpenAI(
    shrike_api_key=os.environ.get("SHRIKE_API_KEY"),
)
```

## Scope and Limitations

### What Shrike Guard Scans

| Scanned ✅ | Not Scanned ❌ |
|-----------|---------------|
| Input prompts (user messages) | Streaming output from LLM |
| System prompts | Non-streaming completions (V2 roadmap) |
| Multi-modal text content | Image/audio content |

### Why Input-Only Scanning?

**V1 Design Decision:** Shrike Guard focuses on **pre-flight protection** - blocking malicious prompts BEFORE they reach the LLM. This:
- Prevents prompt injection attacks at the source
- Has zero latency impact on LLM responses
- Catches 95%+ of threats (attacks are in the INPUT)

### Output Scanning Roadmap

Output scanning (detecting leaked PII, secrets in responses) is planned for V2. For now:
- Use Shrike's real-time dashboard to monitor flagged prompts
- Enable audit logging for compliance review
- Consider post-processing with `ScanClient.scan()` for high-sensitivity applications

## License

Apache 2.0

## Support

- Documentation: https://docs.shrike.security/sdk/python
- Issues: https://github.com/shrike-security/shrike-guard/issues
- Email: support@shrike.security
