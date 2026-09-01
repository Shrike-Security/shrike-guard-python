"""Govern a local / self-hosted LLM with Shrike.

Local runtimes (Ollama, vLLM, LM Studio, LocalAI, llama.cpp server) expose an
OpenAI-compatible endpoint, so ShrikeOpenAI guards them by forwarding a
`base_url` to the underlying client. The model call stays on your machine; only
the governance scan reaches the Shrike backend.

Run a local server first, e.g. Ollama:

    ollama serve
    ollama pull llama3

Then:

    export SHRIKE_API_KEY=shrike-...
    python examples/local_llm.py
"""

import os

from shrike_guard import ShrikeBlockedError, ShrikeOpenAI

# Point Shrike at any OpenAI-compatible local endpoint. The api_key value is
# ignored by most local servers but the OpenAI client still requires a string.
client = ShrikeOpenAI(
    api_key=os.environ.get("LOCAL_LLM_API_KEY", "local"),
    base_url=os.environ.get("LOCAL_LLM_BASE_URL", "http://localhost:11434/v1"),
    shrike_api_key=os.environ.get("SHRIKE_API_KEY", ""),
)

try:
    response = client.chat.completions.create(
        model=os.environ.get("LOCAL_LLM_MODEL", "llama3"),
        messages=[{"role": "user", "content": "In one sentence, what is Shrike?"}],
    )
    print(response.choices[0].message.content)
except ShrikeBlockedError as exc:
    # The prompt was blocked by policy before it reached the local model.
    print(f"Blocked by Shrike: {exc}")
finally:
    client.close()
