"""Tests for ShrikeAsyncOpenAI async client."""

from unittest import mock

import httpx
import pytest

from shrike_guard import ShrikeAsyncOpenAI, ShrikeBlockedError, ShrikeScanError, FailMode


class TestShrikeAsyncOpenAI:
    """Test suite for ShrikeAsyncOpenAI client."""

    def test_init_with_defaults(self) -> None:
        """Test client initialization with default values."""
        client = ShrikeAsyncOpenAI(
            api_key="sk-test",
            shrike_api_key="shrike-test",
        )
        assert client._fail_mode == FailMode.OPEN
        assert client._scan_timeout == 10.0

    def test_init_with_fail_mode_closed(self) -> None:
        """Test client initialization with fail_mode='closed'."""
        client = ShrikeAsyncOpenAI(
            api_key="sk-test",
            shrike_api_key="shrike-test",
            fail_mode="closed",
        )
        assert client._fail_mode == FailMode.CLOSED

    def test_extract_user_content_single_message(self) -> None:
        """Test extracting content from a single user message."""
        client = ShrikeAsyncOpenAI(
            api_key="sk-test",
            shrike_api_key="shrike-test",
        )
        messages = [{"role": "user", "content": "Hello world"}]
        content = client._extract_user_content(messages)
        assert content == "Hello world"

    def test_extract_user_content_multiple_messages(self) -> None:
        """Test extracting content from multiple messages."""
        client = ShrikeAsyncOpenAI(
            api_key="sk-test",
            shrike_api_key="shrike-test",
        )
        messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "First question"},
            {"role": "assistant", "content": "First answer"},
            {"role": "user", "content": "Second question"},
        ]
        content = client._extract_user_content(messages)
        assert content == "First question\nSecond question"


class TestShrikeAsyncOpenAIScanIntegration:
    """Test async scan integration with mocked HTTP responses."""

    @pytest.mark.asyncio
    async def test_safe_prompt_passes(self) -> None:
        """Test that a safe prompt is allowed through."""
        client = ShrikeAsyncOpenAI(
            api_key="sk-test",
            shrike_api_key="shrike-test",
        )

        # Create async mock response
        async def mock_post(*args, **kwargs):
            response = mock.Mock()
            response.json = lambda: {"safe": True}
            response.raise_for_status = lambda: None
            return response

        with mock.patch.object(client._http, "post", side_effect=mock_post):
            result = await client._scan_messages([{"role": "user", "content": "Hello!"}])
            assert result["safe"] is True

        await client.close()

    @pytest.mark.asyncio
    async def test_unsafe_prompt_returns_blocked(self) -> None:
        """Test that an unsafe prompt scan returns blocked status."""
        client = ShrikeAsyncOpenAI(
            api_key="sk-test",
            shrike_api_key="shrike-test",
        )

        # Create async mock response
        async def mock_post(*args, **kwargs):
            response = mock.Mock()
            response.json = lambda: {
                "safe": False,
                "reason": "PII detected",
                "threat_type": "pii_extraction",
                "confidence": 0.95,
            }
            response.raise_for_status = lambda: None
            return response

        with mock.patch.object(client._http, "post", side_effect=mock_post):
            result = await client._scan_messages(
                [{"role": "user", "content": "My SSN is 123-45-6789"}]
            )
            assert result["safe"] is False
            assert result["threat_type"] == "pii_exposure"

        await client.close()

    @pytest.mark.asyncio
    async def test_timeout_fail_open(self) -> None:
        """Test that timeout with fail_mode='open' allows the request."""
        client = ShrikeAsyncOpenAI(
            api_key="sk-test",
            shrike_api_key="shrike-test",
            fail_mode="open",
        )

        # Mock timeout exception
        async def mock_post(*args, **kwargs):
            raise httpx.TimeoutException("Connection timed out")

        with mock.patch.object(client._http, "post", side_effect=mock_post):
            result = await client._scan_messages([{"role": "user", "content": "Hello!"}])
            assert result["safe"] is True
            assert "timeout" in result["reason"].lower()

        await client.close()

    @pytest.mark.asyncio
    async def test_timeout_fail_closed(self) -> None:
        """Test that timeout with fail_mode='closed' raises exception."""
        client = ShrikeAsyncOpenAI(
            api_key="sk-test",
            shrike_api_key="shrike-test",
            fail_mode="closed",
        )

        # Mock timeout exception
        async def mock_post(*args, **kwargs):
            raise httpx.TimeoutException("Connection timed out")

        with mock.patch.object(client._http, "post", side_effect=mock_post):
            with pytest.raises(ShrikeScanError) as exc_info:
                await client._scan_messages([{"role": "user", "content": "Hello!"}])
            assert "timed out" in str(exc_info.value).lower()

        await client.close()

    @pytest.mark.asyncio
    async def test_scan_empty_content(self) -> None:
        """Test scanning with no user content."""
        client = ShrikeAsyncOpenAI(
            api_key="sk-test",
            shrike_api_key="shrike-test",
        )
        messages = [{"role": "system", "content": "You are helpful."}]
        result = await client._scan_messages(messages)
        assert result["safe"] is True
        await client.close()


class TestShrikeAsyncOpenAIContextManager:
    """Test async context manager functionality."""

    @pytest.mark.asyncio
    async def test_async_context_manager(self) -> None:
        """Test using client as async context manager."""
        async with ShrikeAsyncOpenAI(
            api_key="sk-test", shrike_api_key="shrike-test"
        ) as client:
            assert client is not None
        # Client should be closed after exiting context
