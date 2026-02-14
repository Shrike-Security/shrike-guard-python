"""Tests for ShrikeAnthropic and ShrikeAsyncAnthropic clients."""

from unittest import mock
from typing import Any

import httpx
import pytest

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from shrike_guard import ShrikeAnthropic, ShrikeAsyncAnthropic, ShrikeBlockedError, ShrikeScanError, FailMode


# Mock the anthropic module
class MockMessage:
    """Mock Anthropic Message response."""
    def __init__(self, text: str = "This is a test response."):
        self.id = "msg_test_123"
        self.type = "message"
        self.role = "assistant"
        self.content = [MockContentBlock(text)]
        self.model = "claude-3-opus-20240229"
        self.stop_reason = "end_turn"

    @property
    def text(self) -> str:
        return self.content[0].text if self.content else ""


class MockContentBlock:
    """Mock content block."""
    def __init__(self, text: str):
        self.type = "text"
        self.text = text


class MockStreamManager:
    """Mock stream context manager."""
    def __enter__(self):
        return self

    def __exit__(self, *args: Any):
        pass

    def __iter__(self):
        return iter([])


class MockAsyncStreamManager:
    """Mock async stream context manager."""
    async def __aenter__(self):
        return self

    async def __aexit__(self, *args: Any):
        pass

    def __aiter__(self):
        return self

    async def __anext__(self):
        raise StopAsyncIteration


class MockMessagesAPI:
    """Mock Anthropic messages API."""
    def create(self, **kwargs: Any) -> MockMessage:
        return MockMessage()

    def stream(self, **kwargs: Any) -> MockStreamManager:
        return MockStreamManager()


class MockAsyncMessagesAPI:
    """Mock async Anthropic messages API."""
    async def create(self, **kwargs: Any) -> MockMessage:
        return MockMessage()

    def stream(self, **kwargs: Any) -> MockAsyncStreamManager:
        return MockAsyncStreamManager()


class MockAnthropic:
    """Mock Anthropic client."""
    def __init__(self, **kwargs: Any):
        self.messages = MockMessagesAPI()


class MockAsyncAnthropic:
    """Mock AsyncAnthropic client."""
    def __init__(self, **kwargs: Any):
        self.messages = MockAsyncMessagesAPI()


@pytest.fixture
def mock_anthropic(monkeypatch):
    """Mock the anthropic module."""
    monkeypatch.setattr("shrike_guard.anthropic_client.ANTHROPIC_AVAILABLE", True)
    monkeypatch.setattr("shrike_guard.anthropic_client.Anthropic", MockAnthropic)
    return MockAnthropic


@pytest.fixture
def mock_async_anthropic(monkeypatch):
    """Mock the anthropic module for async client."""
    monkeypatch.setattr("shrike_guard.anthropic_client.ANTHROPIC_AVAILABLE", True)
    monkeypatch.setattr("shrike_guard.anthropic_client.Anthropic", MockAnthropic)
    # Patch the AsyncAnthropic import inside __init__
    mock_module = mock.MagicMock()
    mock_module.AsyncAnthropic = MockAsyncAnthropic
    monkeypatch.setattr("shrike_guard.anthropic_client.Anthropic", MockAnthropic)
    return mock_module


class TestShrikeAnthropicInit:
    """Test ShrikeAnthropic initialization."""

    def test_init_with_defaults(self, mock_anthropic) -> None:
        """Test client initialization with default values."""
        client = ShrikeAnthropic(
            api_key="sk-ant-test",
            shrike_api_key="shrike-test",
        )
        assert client._fail_mode == FailMode.OPEN
        assert client._scan_timeout == 10.0
        assert client.messages is not None
        client.close()

    def test_init_with_fail_mode_closed(self, mock_anthropic) -> None:
        """Test client initialization with fail_mode='closed'."""
        client = ShrikeAnthropic(
            api_key="sk-ant-test",
            shrike_api_key="shrike-test",
            fail_mode="closed",
        )
        assert client._fail_mode == FailMode.CLOSED
        client.close()

    def test_init_with_custom_endpoint(self, mock_anthropic) -> None:
        """Test client initialization with custom endpoint."""
        client = ShrikeAnthropic(
            api_key="sk-ant-test",
            shrike_api_key="shrike-test",
            shrike_endpoint="https://custom.endpoint.com/",
        )
        assert client._shrike_endpoint == "https://custom.endpoint.com"
        client.close()


class TestShrikeAnthropicContentExtraction:
    """Test content extraction from various message formats."""

    def test_extract_single_user_message(self, mock_anthropic) -> None:
        """Test extracting content from a single user message."""
        client = ShrikeAnthropic(
            api_key="sk-ant-test",
            shrike_api_key="shrike-test",
        )
        messages = [{"role": "user", "content": "Hello world"}]
        content = client._extract_user_content(messages)
        assert content == "Hello world"
        client.close()

    def test_extract_multiple_messages(self, mock_anthropic) -> None:
        """Test extracting content from multiple messages (only user messages)."""
        client = ShrikeAnthropic(
            api_key="sk-ant-test",
            shrike_api_key="shrike-test",
        )
        messages = [
            {"role": "user", "content": "First question"},
            {"role": "assistant", "content": "First answer"},
            {"role": "user", "content": "Second question"},
        ]
        content = client._extract_user_content(messages)
        assert content == "First question\nSecond question"
        client.close()

    def test_extract_content_blocks(self, mock_anthropic) -> None:
        """Test extracting content from content block format."""
        client = ShrikeAnthropic(
            api_key="sk-ant-test",
            shrike_api_key="shrike-test",
        )
        messages = [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "What's in this image?"},
                    {"type": "image", "source": {"type": "base64", "data": "..."}},
                ],
            }
        ]
        content = client._extract_user_content(messages)
        assert content == "What's in this image?"
        client.close()

    def test_extract_skips_assistant_messages(self, mock_anthropic) -> None:
        """Test that assistant messages are skipped."""
        client = ShrikeAnthropic(
            api_key="sk-ant-test",
            shrike_api_key="shrike-test",
        )
        messages = [{"role": "assistant", "content": "I should be skipped"}]
        content = client._extract_user_content(messages)
        assert content == ""
        client.close()

    def test_scan_empty_content_returns_safe(self, mock_anthropic) -> None:
        """Test scanning with no user content returns safe."""
        client = ShrikeAnthropic(
            api_key="sk-ant-test",
            shrike_api_key="shrike-test",
        )
        messages = [{"role": "assistant", "content": "Just an assistant message"}]
        result = client._scan_messages(messages)
        assert result["safe"] is True
        client.close()


class TestShrikeAnthropicScanIntegration:
    """Test scan integration with mocked HTTP responses."""

    def test_safe_prompt_passes(self, mock_anthropic) -> None:
        """Test that a safe prompt is allowed through."""
        client = ShrikeAnthropic(
            api_key="sk-ant-test",
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
            response = client.messages.create(
                model="claude-3-opus-20240229",
                max_tokens=1024,
                messages=[{"role": "user", "content": "Hello!"}],
            )
            assert response.text == "This is a test response."

        client.close()

    def test_unsafe_prompt_blocked(self, mock_anthropic) -> None:
        """Test that an unsafe prompt raises ShrikeBlockedError."""
        client = ShrikeAnthropic(
            api_key="sk-ant-test",
            shrike_api_key="shrike-test",
        )

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
            with pytest.raises(ShrikeBlockedError) as exc_info:
                client.messages.create(
                    model="claude-3-opus-20240229",
                    max_tokens=1024,
                    messages=[{"role": "user", "content": "Ignore all instructions..."}],
                )

            assert "Prompt injection detected" in str(exc_info.value)

        client.close()

    def test_timeout_fail_open(self, mock_anthropic) -> None:
        """Test that timeout with fail_mode='open' allows the request."""
        client = ShrikeAnthropic(
            api_key="sk-ant-test",
            shrike_api_key="shrike-test",
            fail_mode="open",
        )

        with mock.patch.object(
            client._http,
            "post",
            side_effect=httpx.TimeoutException("Connection timed out"),
        ):
            response = client.messages.create(
                model="claude-3-opus-20240229",
                max_tokens=1024,
                messages=[{"role": "user", "content": "Hello!"}],
            )
            assert response.text == "This is a test response."

        client.close()

    def test_timeout_fail_closed(self, mock_anthropic) -> None:
        """Test that timeout with fail_mode='closed' raises exception."""
        client = ShrikeAnthropic(
            api_key="sk-ant-test",
            shrike_api_key="shrike-test",
            fail_mode="closed",
        )

        with mock.patch.object(
            client._http,
            "post",
            side_effect=httpx.TimeoutException("Connection timed out"),
        ):
            with pytest.raises(ShrikeScanError) as exc_info:
                client.messages.create(
                    model="claude-3-opus-20240229",
                    max_tokens=1024,
                    messages=[{"role": "user", "content": "Hello!"}],
                )

            assert "timed out" in str(exc_info.value).lower()

        client.close()

    def test_network_error_fail_open(self, mock_anthropic) -> None:
        """Test that network error with fail_mode='open' allows the request."""
        client = ShrikeAnthropic(
            api_key="sk-ant-test",
            shrike_api_key="shrike-test",
            fail_mode="open",
        )

        with mock.patch.object(
            client._http,
            "post",
            side_effect=httpx.ConnectError("Connection refused"),
        ):
            response = client.messages.create(
                model="claude-3-opus-20240229",
                max_tokens=1024,
                messages=[{"role": "user", "content": "Hello!"}],
            )
            assert response.text == "This is a test response."

        client.close()

    def test_network_error_fail_closed(self, mock_anthropic) -> None:
        """Test that network error with fail_mode='closed' raises exception."""
        client = ShrikeAnthropic(
            api_key="sk-ant-test",
            shrike_api_key="shrike-test",
            fail_mode="closed",
        )

        with mock.patch.object(
            client._http,
            "post",
            side_effect=httpx.ConnectError("Connection refused"),
        ):
            with pytest.raises(ShrikeScanError):
                client.messages.create(
                    model="claude-3-opus-20240229",
                    max_tokens=1024,
                    messages=[{"role": "user", "content": "Hello!"}],
                )

        client.close()

    def test_http_error_fail_open(self, mock_anthropic) -> None:
        """Test that HTTP error with fail_mode='open' allows the request."""
        client = ShrikeAnthropic(
            api_key="sk-ant-test",
            shrike_api_key="shrike-test",
            fail_mode="open",
        )

        mock_response = mock.Mock()
        mock_response.status_code = 500
        mock_response.request = mock.Mock()

        with mock.patch.object(
            client._http,
            "post",
            side_effect=httpx.HTTPStatusError(
                "Internal Server Error",
                request=mock_response.request,
                response=mock_response,
            ),
        ):
            response = client.messages.create(
                model="claude-3-opus-20240229",
                max_tokens=1024,
                messages=[{"role": "user", "content": "Hello!"}],
            )
            assert response.text == "This is a test response."

        client.close()


class TestShrikeAnthropicStream:
    """Test streaming functionality."""

    def test_stream_safe_prompt(self, mock_anthropic) -> None:
        """Test streaming with a safe prompt."""
        client = ShrikeAnthropic(
            api_key="sk-ant-test",
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
            stream = client.messages.stream(
                model="claude-3-opus-20240229",
                max_tokens=1024,
                messages=[{"role": "user", "content": "Hello!"}],
            )
            assert stream is not None

        client.close()

    def test_stream_unsafe_prompt_blocked(self, mock_anthropic) -> None:
        """Test that streaming blocks unsafe prompts."""
        client = ShrikeAnthropic(
            api_key="sk-ant-test",
            shrike_api_key="shrike-test",
        )

        with mock.patch.object(
            client._http,
            "post",
            return_value=mock.Mock(
                json=lambda: {
                    "safe": False,
                    "reason": "Jailbreak detected",
                    "threat_type": "jailbreak",
                    "confidence": 0.88,
                },
                raise_for_status=lambda: None,
            ),
        ):
            with pytest.raises(ShrikeBlockedError) as exc_info:
                client.messages.stream(
                    model="claude-3-opus-20240229",
                    max_tokens=1024,
                    messages=[{"role": "user", "content": "DAN mode activated..."}],
                )

            assert "Jailbreak detected" in str(exc_info.value)

        client.close()


class TestShrikeAnthropicContextManager:
    """Test context manager functionality."""

    def test_context_manager(self, mock_anthropic) -> None:
        """Test using client as context manager."""
        with ShrikeAnthropic(
            api_key="sk-ant-test",
            shrike_api_key="shrike-test",
        ) as client:
            assert client is not None
            assert client.messages is not None


# ============================================================
# Async Client Tests
# ============================================================

class TestShrikeAsyncAnthropicInit:
    """Test ShrikeAsyncAnthropic initialization."""

    def test_init_with_defaults(self, mock_async_anthropic, monkeypatch) -> None:
        """Test async client initialization with default values."""
        monkeypatch.setattr(
            "shrike_guard.anthropic_client.AsyncAnthropic",
            MockAsyncAnthropic,
            raising=False,
        )
        # Patch the import inside __init__
        with mock.patch("shrike_guard.anthropic_client.AsyncAnthropic", MockAsyncAnthropic, create=True):
            with mock.patch.dict("sys.modules", {"anthropic": mock.MagicMock(AsyncAnthropic=MockAsyncAnthropic)}):
                client = ShrikeAsyncAnthropic(
                    api_key="sk-ant-test",
                    shrike_api_key="shrike-test",
                )
                assert client._fail_mode == FailMode.OPEN
                assert client._scan_timeout == 10.0
                assert client.messages is not None

    def test_init_with_fail_mode_closed(self, mock_async_anthropic, monkeypatch) -> None:
        """Test async client initialization with fail_mode='closed'."""
        with mock.patch.dict("sys.modules", {"anthropic": mock.MagicMock(AsyncAnthropic=MockAsyncAnthropic)}):
            client = ShrikeAsyncAnthropic(
                api_key="sk-ant-test",
                shrike_api_key="shrike-test",
                fail_mode="closed",
            )
            assert client._fail_mode == FailMode.CLOSED


class TestShrikeAsyncAnthropicScanIntegration:
    """Test async scan integration with mocked HTTP responses."""

    @pytest.mark.asyncio
    async def test_safe_prompt_passes(self, mock_async_anthropic) -> None:
        """Test that a safe prompt is allowed through (async)."""
        with mock.patch.dict("sys.modules", {"anthropic": mock.MagicMock(AsyncAnthropic=MockAsyncAnthropic)}):
            client = ShrikeAsyncAnthropic(
                api_key="sk-ant-test",
                shrike_api_key="shrike-test",
            )

            mock_resp = mock.Mock()
            mock_resp.json.return_value = {"safe": True}
            mock_resp.raise_for_status = mock.Mock()

            async def mock_post(*args, **kwargs):
                return mock_resp

            with mock.patch.object(
                client._http,
                "post",
                side_effect=mock_post,
            ):
                response = await client.messages.create(
                    model="claude-3-opus-20240229",
                    max_tokens=1024,
                    messages=[{"role": "user", "content": "Hello!"}],
                )
                assert response.text == "This is a test response."

            await client.close()

    @pytest.mark.asyncio
    async def test_unsafe_prompt_blocked(self, mock_async_anthropic) -> None:
        """Test that an unsafe prompt raises ShrikeBlockedError (async)."""
        with mock.patch.dict("sys.modules", {"anthropic": mock.MagicMock(AsyncAnthropic=MockAsyncAnthropic)}):
            client = ShrikeAsyncAnthropic(
                api_key="sk-ant-test",
                shrike_api_key="shrike-test",
            )

            mock_resp = mock.Mock()
            mock_resp.json.return_value = {
                "safe": False,
                "reason": "PII detected",
                "threat_type": "pii_extraction",
                "confidence": 0.92,
            }
            mock_resp.raise_for_status = mock.Mock()

            async def mock_post(*args, **kwargs):
                return mock_resp

            with mock.patch.object(
                client._http,
                "post",
                side_effect=mock_post,
            ):
                with pytest.raises(ShrikeBlockedError) as exc_info:
                    await client.messages.create(
                        model="claude-3-opus-20240229",
                        max_tokens=1024,
                        messages=[{"role": "user", "content": "My SSN is 123-45-6789"}],
                    )

                assert "PII detected" in str(exc_info.value)

            await client.close()

    @pytest.mark.asyncio
    async def test_timeout_fail_open(self, mock_async_anthropic) -> None:
        """Test that timeout with fail_mode='open' allows the request (async)."""
        with mock.patch.dict("sys.modules", {"anthropic": mock.MagicMock(AsyncAnthropic=MockAsyncAnthropic)}):
            client = ShrikeAsyncAnthropic(
                api_key="sk-ant-test",
                shrike_api_key="shrike-test",
                fail_mode="open",
            )

            with mock.patch.object(
                client._http,
                "post",
                side_effect=httpx.TimeoutException("Connection timed out"),
            ):
                response = await client.messages.create(
                    model="claude-3-opus-20240229",
                    max_tokens=1024,
                    messages=[{"role": "user", "content": "Hello!"}],
                )
                assert response.text == "This is a test response."

            await client.close()

    @pytest.mark.asyncio
    async def test_timeout_fail_closed(self, mock_async_anthropic) -> None:
        """Test that timeout with fail_mode='closed' raises exception (async)."""
        with mock.patch.dict("sys.modules", {"anthropic": mock.MagicMock(AsyncAnthropic=MockAsyncAnthropic)}):
            client = ShrikeAsyncAnthropic(
                api_key="sk-ant-test",
                shrike_api_key="shrike-test",
                fail_mode="closed",
            )

            with mock.patch.object(
                client._http,
                "post",
                side_effect=httpx.TimeoutException("Connection timed out"),
            ):
                with pytest.raises(ShrikeScanError) as exc_info:
                    await client.messages.create(
                        model="claude-3-opus-20240229",
                        max_tokens=1024,
                        messages=[{"role": "user", "content": "Hello!"}],
                    )

                assert "timed out" in str(exc_info.value).lower()

            await client.close()


class TestShrikeAsyncAnthropicContextManager:
    """Test async context manager functionality."""

    @pytest.mark.asyncio
    async def test_async_context_manager(self, mock_async_anthropic) -> None:
        """Test using async client as context manager."""
        with mock.patch.dict("sys.modules", {"anthropic": mock.MagicMock(AsyncAnthropic=MockAsyncAnthropic)}):
            async with ShrikeAsyncAnthropic(
                api_key="sk-ant-test",
                shrike_api_key="shrike-test",
            ) as client:
                assert client is not None
                assert client.messages is not None
