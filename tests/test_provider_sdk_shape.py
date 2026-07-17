"""Real-package shape guard for the provider SDKs.

Asserts the provider API surface our wrappers actually call still exists on the
installed provider major. CI installs the current major (the dependency caps
allow openai 2.x and google-genai 2.x), so a breaking provider API change fails
here instead of in a customer's runtime. Mirrors the TS gemini-sdk-shape test —
the lesson from the Gemini wrapper break was that mocked tests hide real-SDK
mismatches, so this loads the real packages.
"""

import pytest


def test_openai_chat_completions_surface() -> None:
    from openai import OpenAI

    client = OpenAI(api_key="test-key")
    assert hasattr(client.chat.completions, "create")


def test_anthropic_messages_surface() -> None:
    try:
        import anthropic
    except ImportError:
        pytest.skip("anthropic extra not installed")

    client = anthropic.Anthropic(api_key="test-key")
    assert hasattr(client.messages, "create")
    async_client = anthropic.AsyncAnthropic(api_key="test-key")
    assert hasattr(async_client.messages, "create")


def test_google_genai_models_surface() -> None:
    try:
        from google import genai
    except ImportError:
        pytest.skip("gemini extra (google-genai) not installed")

    client = genai.Client(api_key="test-key")
    assert hasattr(client.models, "generate_content")
