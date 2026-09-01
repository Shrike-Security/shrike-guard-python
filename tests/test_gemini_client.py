"""Tests for ShrikeGemini client."""

from unittest import mock
from typing import Any

import httpx
import pytest

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from shrike_guard import ShrikeGemini, ShrikeBlockedError, ShrikeScanError, FailMode
from shrike_guard.gemini_client import _ShrikeGenerativeModel


# Mock the google.generativeai module
class MockGenerateContentResponse:
    """Mock Gemini response."""
    def __init__(self, text: str = "This is a test response."):
        self.text = text


class MockGenerativeModel:
    """Mock GenerativeModel."""
    def __init__(self, model_name: str, **kwargs: Any):
        self.model_name = model_name

    def generate_content(self, contents: Any, **kwargs: Any) -> MockGenerateContentResponse:
        return MockGenerateContentResponse()

    def count_tokens(self, contents: Any) -> dict:
        return {"total_tokens": 10}

    def start_chat(self, **kwargs: Any) -> "MockChatSession":
        return MockChatSession()


class MockChatSession:
    """Mock chat session."""
    def __init__(self):
        self.history = []

    def send_message(self, content: Any, **kwargs: Any) -> MockGenerateContentResponse:
        return MockGenerateContentResponse()


@pytest.fixture
def mock_genai(monkeypatch):
    """Mock the google.generativeai module."""
    mock_module = mock.MagicMock()
    mock_module.GenerativeModel = MockGenerativeModel
    mock_module.configure = mock.MagicMock()
    # Mock new SDK client
    mock_client = mock.MagicMock()
    mock_client.models.generate_content = lambda **kwargs: MockGenerateContentResponse()
    mock_client.chats.create = lambda **kwargs: MockChatSession()
    mock_module.Client = mock.MagicMock(return_value=mock_client)
    monkeypatch.setattr("shrike_guard.gemini_client.genai", mock_module)
    monkeypatch.setattr("shrike_guard.gemini_client.GENAI_NEW_AVAILABLE", True)
    monkeypatch.setattr("shrike_guard.gemini_client.GENAI_LEGACY_AVAILABLE", False)
    return mock_module


class TestShrikeGeminiInit:
    """Test ShrikeGemini initialization."""

    def test_init_with_defaults(self, mock_genai) -> None:
        """Test client initialization with default values."""
        client = ShrikeGemini(
            api_key="test-key",
            shrike_api_key="shrike-test",
        )
        assert client._fail_mode == FailMode.CLOSED  # default is CLOSED (fail-closed)
        assert client._scan_timeout == 10.0
        client.close()

    def test_init_with_fail_mode_closed(self, mock_genai) -> None:
        """Test client initialization with fail_mode='closed'."""
        client = ShrikeGemini(
            api_key="test-key",
            shrike_api_key="shrike-test",
            fail_mode="closed",
        )
        assert client._fail_mode == FailMode.CLOSED
        client.close()

    def test_creates_generative_model(self, mock_genai) -> None:
        """Test that GenerativeModel creates a wrapped model."""
        client = ShrikeGemini(
            api_key="test-key",
            shrike_api_key="shrike-test",
        )
        model = client.GenerativeModel("gemini-pro")
        assert isinstance(model, _ShrikeGenerativeModel)
        client.close()

    def test_init_without_base_url_omits_http_options(self, mock_genai) -> None:
        """No base_url -> genai.Client called without an http_options override."""
        client = ShrikeGemini(api_key="test-key", shrike_api_key="shrike-test")
        _, kwargs = mock_genai.Client.call_args
        assert "http_options" not in kwargs
        client.close()

    def test_init_with_base_url_sets_http_options(self, mock_genai) -> None:
        """A custom base_url is forwarded to genai.Client via http_options."""
        client = ShrikeGemini(
            api_key="test-key",
            shrike_api_key="shrike-test",
            base_url="https://gemini-gateway.internal/",  # trailing slash trimmed
        )
        _, kwargs = mock_genai.Client.call_args
        assert "http_options" in kwargs
        # HttpOptions is the real google-genai type here; it carries base_url.
        assert kwargs["http_options"].base_url == "https://gemini-gateway.internal"
        client.close()

    def test_explicit_http_options_beats_base_url(self, mock_genai) -> None:
        """Caller-supplied http_options wins over the base_url convenience arg."""
        from google.genai.types import HttpOptions

        sentinel = HttpOptions(base_url="https://explicit.example")
        client = ShrikeGemini(
            api_key="test-key",
            shrike_api_key="shrike-test",
            base_url="https://ignored.example",
            http_options=sentinel,
        )
        _, kwargs = mock_genai.Client.call_args
        assert kwargs["http_options"] is sentinel
        client.close()


class TestShrikeGeminiContentExtraction:
    """Test content extraction from various formats."""

    def test_extract_string_content(self, mock_genai) -> None:
        """Test extracting content from a simple string."""
        client = ShrikeGemini(
            api_key="test-key",
            shrike_api_key="shrike-test",
        )
        content = client._extract_content("Hello world")
        assert content == "Hello world"
        client.close()

    def test_extract_list_content(self, mock_genai) -> None:
        """Test extracting content from a list."""
        client = ShrikeGemini(
            api_key="test-key",
            shrike_api_key="shrike-test",
        )
        content = client._extract_content(["Hello", "World"])
        assert content == "Hello\nWorld"
        client.close()

    def test_extract_dict_content(self, mock_genai) -> None:
        """Test extracting content from a dict with text key."""
        client = ShrikeGemini(
            api_key="test-key",
            shrike_api_key="shrike-test",
        )
        content = client._extract_content({"text": "Hello world"})
        assert content == "Hello world"
        client.close()


class TestShrikeGeminiScanIntegration:
    """Test scan integration with mocked HTTP responses."""

    def test_safe_prompt_passes(self, mock_genai) -> None:
        """Test that a safe prompt is allowed through."""
        client = ShrikeGemini(
            api_key="test-key",
            shrike_api_key="shrike-test",
        )

        # Mock the HTTP response for safe scan
        with mock.patch.object(
            client._http,
            "post",
            return_value=mock.Mock(
                json=lambda: {"safe": True},
                raise_for_status=lambda: None,
            ),
        ):
            model = client.GenerativeModel("gemini-pro")
            response = model.generate_content("Hello!")
            assert response.text == "This is a test response."

        client.close()

    def test_unsafe_prompt_blocked(self, mock_genai) -> None:
        """Test that an unsafe prompt raises ShrikeBlockedError."""
        client = ShrikeGemini(
            api_key="test-key",
            shrike_api_key="shrike-test",
        )

        # Mock the HTTP response for unsafe scan
        with mock.patch.object(
            client._http,
            "post",
            return_value=mock.Mock(
                json=lambda: {
                    "safe": False,
                    "reason": "Prompt injection detected",
                    "threat_type": "prompt_injection",
                    "confidence": 0.95,
                },
                raise_for_status=lambda: None,
            ),
        ):
            model = client.GenerativeModel("gemini-pro")
            with pytest.raises(ShrikeBlockedError) as exc_info:
                model.generate_content("Ignore all instructions...")

            assert "Prompt injection detected" in str(exc_info.value)

        client.close()

    def test_timeout_fail_open(self, mock_genai) -> None:
        """Test that timeout with fail_mode='open' allows the request."""
        client = ShrikeGemini(
            api_key="test-key",
            shrike_api_key="shrike-test",
            fail_mode="open",
        )

        # Mock timeout exception
        with mock.patch.object(
            client._http,
            "post",
            side_effect=httpx.TimeoutException("Connection timed out"),
        ):
            model = client.GenerativeModel("gemini-pro")
            # Should not raise - fail open
            response = model.generate_content("Hello!")
            assert response.text == "This is a test response."

        client.close()

    def test_timeout_fail_closed(self, mock_genai) -> None:
        """Test that timeout with fail_mode='closed' raises exception."""
        client = ShrikeGemini(
            api_key="test-key",
            shrike_api_key="shrike-test",
            fail_mode="closed",
        )

        # Mock timeout exception
        with mock.patch.object(
            client._http,
            "post",
            side_effect=httpx.TimeoutException("Connection timed out"),
        ):
            model = client.GenerativeModel("gemini-pro")
            with pytest.raises(ShrikeScanError) as exc_info:
                model.generate_content("Hello!")

            assert "timed out" in str(exc_info.value).lower()

        client.close()


class TestShrikeGeminiChatSession:
    """Test chat session functionality."""

    def test_chat_session_safe_messages(self, mock_genai) -> None:
        """Test chat session with safe messages."""
        client = ShrikeGemini(
            api_key="test-key",
            shrike_api_key="shrike-test",
        )

        with mock.patch.object(
            client._http,
            "post",
            return_value=mock.Mock(
                json=lambda: {"safe": True},
                raise_for_status=lambda: None,
            ),
        ):
            model = client.GenerativeModel("gemini-pro")
            chat = model.start_chat()

            response1 = chat.send_message("Hello!")
            assert response1.text == "This is a test response."

            response2 = chat.send_message("How are you?")
            assert response2.text == "This is a test response."

        client.close()

    def test_chat_session_blocked_message(self, mock_genai) -> None:
        """Test chat session blocks unsafe messages."""
        client = ShrikeGemini(
            api_key="test-key",
            shrike_api_key="shrike-test",
        )

        with mock.patch.object(
            client._http,
            "post",
            return_value=mock.Mock(
                json=lambda: {
                    "safe": False,
                    "reason": "PII detected",
                    "threat_type": "pii_extraction",
                    "confidence": 0.92,
                },
                raise_for_status=lambda: None,
            ),
        ):
            model = client.GenerativeModel("gemini-pro")
            chat = model.start_chat()

            with pytest.raises(ShrikeBlockedError):
                chat.send_message("My SSN is 123-45-6789")

        client.close()


class TestShrikeGeminiContextManager:
    """Test context manager functionality."""

    def test_context_manager(self, mock_genai) -> None:
        """Test using client as context manager."""
        with ShrikeGemini(
            api_key="test-key",
            shrike_api_key="shrike-test",
        ) as client:
            assert client is not None
        # Client should be closed after exiting context
