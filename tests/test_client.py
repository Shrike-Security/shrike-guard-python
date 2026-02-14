"""Tests for ShrikeOpenAI synchronous client."""

from unittest import mock

import httpx
import pytest

from shrike_guard import ShrikeOpenAI, ShrikeBlockedError, ShrikeScanError, FailMode


class TestShrikeOpenAI:
    """Test suite for ShrikeOpenAI client."""

    def test_init_with_defaults(self) -> None:
        """Test client initialization with default values."""
        client = ShrikeOpenAI(
            api_key="sk-test",
            shrike_api_key="shrike-test",
        )
        assert client._fail_mode == FailMode.OPEN
        assert client._scan_timeout == 10.0
        client.close()

    def test_init_with_fail_mode_closed(self) -> None:
        """Test client initialization with fail_mode='closed'."""
        client = ShrikeOpenAI(
            api_key="sk-test",
            shrike_api_key="shrike-test",
            fail_mode="closed",
        )
        assert client._fail_mode == FailMode.CLOSED
        client.close()

    def test_extract_user_content_single_message(self) -> None:
        """Test extracting content from a single user message."""
        client = ShrikeOpenAI(
            api_key="sk-test",
            shrike_api_key="shrike-test",
        )
        messages = [{"role": "user", "content": "Hello world"}]
        content = client._extract_user_content(messages)
        assert content == "Hello world"
        client.close()

    def test_extract_user_content_multiple_messages(self) -> None:
        """Test extracting content from multiple messages."""
        client = ShrikeOpenAI(
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
        client.close()

    def test_extract_user_content_multimodal(self) -> None:
        """Test extracting content from multimodal messages."""
        client = ShrikeOpenAI(
            api_key="sk-test",
            shrike_api_key="shrike-test",
        )
        messages = [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "What's in this image?"},
                    {"type": "image_url", "image_url": {"url": "https://example.com/image.jpg"}},
                ],
            }
        ]
        content = client._extract_user_content(messages)
        assert content == "What's in this image?"
        client.close()

    def test_scan_messages_empty_content(self) -> None:
        """Test scanning with no user content."""
        client = ShrikeOpenAI(
            api_key="sk-test",
            shrike_api_key="shrike-test",
        )
        messages = [{"role": "system", "content": "You are helpful."}]
        result = client._scan_messages(messages)
        assert result["safe"] is True
        client.close()


class TestShrikeOpenAIScanIntegration:
    """Test scan integration with mocked HTTP responses."""

    def test_safe_prompt_passes(self) -> None:
        """Test that a safe prompt is allowed through."""
        client = ShrikeOpenAI(
            api_key="sk-test",
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
            result = client._scan_messages([{"role": "user", "content": "Hello!"}])
            assert result["safe"] is True

        client.close()

    def test_unsafe_prompt_returns_blocked(self) -> None:
        """Test that an unsafe prompt scan returns blocked status."""
        client = ShrikeOpenAI(
            api_key="sk-test",
            shrike_api_key="shrike-test",
        )

        # Mock the HTTP response for unsafe scan
        with mock.patch.object(
            client._http,
            "post",
            return_value=mock.Mock(
                json=lambda: {
                    "safe": False,
                    "reason": "PII detected",
                    "threat_type": "pii_extraction",
                    "confidence": 0.95,
                },
                raise_for_status=lambda: None,
            ),
        ):
            result = client._scan_messages([{"role": "user", "content": "My SSN is 123-45-6789"}])
            assert result["safe"] is False
            assert result["threat_type"] == "pii_exposure"

        client.close()

    def test_timeout_fail_open(self) -> None:
        """Test that timeout with fail_mode='open' allows the request."""
        client = ShrikeOpenAI(
            api_key="sk-test",
            shrike_api_key="shrike-test",
            fail_mode="open",
        )

        # Mock timeout exception
        with mock.patch.object(
            client._http,
            "post",
            side_effect=httpx.TimeoutException("Connection timed out"),
        ):
            result = client._scan_messages([{"role": "user", "content": "Hello!"}])
            assert result["safe"] is True
            assert "timeout" in result["reason"].lower()

        client.close()

    def test_timeout_fail_closed(self) -> None:
        """Test that timeout with fail_mode='closed' raises exception."""
        client = ShrikeOpenAI(
            api_key="sk-test",
            shrike_api_key="shrike-test",
            fail_mode="closed",
        )

        # Mock timeout exception
        with mock.patch.object(
            client._http,
            "post",
            side_effect=httpx.TimeoutException("Connection timed out"),
        ):
            with pytest.raises(ShrikeScanError) as exc_info:
                client._scan_messages([{"role": "user", "content": "Hello!"}])
            assert "timed out" in str(exc_info.value).lower()

        client.close()

    def test_network_error_fail_open(self) -> None:
        """Test that network error with fail_mode='open' allows the request."""
        client = ShrikeOpenAI(
            api_key="sk-test",
            shrike_api_key="shrike-test",
            fail_mode="open",
        )

        # Mock network error
        with mock.patch.object(
            client._http,
            "post",
            side_effect=httpx.ConnectError("Connection refused"),
        ):
            result = client._scan_messages([{"role": "user", "content": "Hello!"}])
            assert result["safe"] is True

        client.close()

    def test_network_error_fail_closed(self) -> None:
        """Test that network error with fail_mode='closed' raises exception."""
        client = ShrikeOpenAI(
            api_key="sk-test",
            shrike_api_key="shrike-test",
            fail_mode="closed",
        )

        # Mock network error
        with mock.patch.object(
            client._http,
            "post",
            side_effect=httpx.ConnectError("Connection refused"),
        ):
            with pytest.raises(ShrikeScanError):
                client._scan_messages([{"role": "user", "content": "Hello!"}])

        client.close()


class TestShrikeOpenAIScanSQL:
    """Test SQL scanning functionality."""

    def test_scan_sql_safe_query(self) -> None:
        """Test that a safe SQL query passes."""
        client = ShrikeOpenAI(
            api_key="sk-test",
            shrike_api_key="shrike-test",
        )

        with mock.patch.object(
            client._http,
            "post",
            return_value=mock.Mock(
                json=lambda: {"safe": True, "threat_level": "none"},
                raise_for_status=lambda: None,
            ),
        ):
            result = client.scan_sql("SELECT * FROM users WHERE id = 1")
            assert result["safe"] is True

        client.close()

    def test_scan_sql_injection_blocked(self) -> None:
        """Test that SQL injection is blocked."""
        client = ShrikeOpenAI(
            api_key="sk-test",
            shrike_api_key="shrike-test",
        )

        with mock.patch.object(
            client._http,
            "post",
            return_value=mock.Mock(
                json=lambda: {
                    "safe": False,
                    "threat_type": "sql_injection",
                    "reason": "SQL injection detected",
                    "confidence": 0.95,
                },
                raise_for_status=lambda: None,
            ),
        ):
            result = client.scan_sql("SELECT * FROM users UNION SELECT * FROM passwords")
            assert result["safe"] is False
            assert result["threat_type"] == "sql_injection"

        client.close()

    def test_scan_sql_timeout_fail_open(self) -> None:
        """Test SQL scan timeout with fail_mode='open'."""
        client = ShrikeOpenAI(
            api_key="sk-test",
            shrike_api_key="shrike-test",
            fail_mode="open",
        )

        with mock.patch.object(
            client._http,
            "post",
            side_effect=httpx.TimeoutException("Timeout"),
        ):
            result = client.scan_sql("SELECT 1")
            assert result["safe"] is True

        client.close()

    def test_scan_sql_timeout_fail_closed(self) -> None:
        """Test SQL scan timeout with fail_mode='closed'."""
        client = ShrikeOpenAI(
            api_key="sk-test",
            shrike_api_key="shrike-test",
            fail_mode="closed",
        )

        with mock.patch.object(
            client._http,
            "post",
            side_effect=httpx.TimeoutException("Timeout"),
        ):
            with pytest.raises(ShrikeScanError):
                client.scan_sql("SELECT 1")

        client.close()


class TestShrikeOpenAIScanFile:
    """Test file path scanning functionality."""

    def test_scan_file_safe_path(self) -> None:
        """Test that a safe file path passes."""
        client = ShrikeOpenAI(
            api_key="sk-test",
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
            result = client.scan_file("/tmp/output.txt")
            assert result["safe"] is True

        client.close()

    def test_scan_file_sensitive_path_blocked(self) -> None:
        """Test that sensitive file paths are blocked."""
        client = ShrikeOpenAI(
            api_key="sk-test",
            shrike_api_key="shrike-test",
        )

        with mock.patch.object(
            client._http,
            "post",
            return_value=mock.Mock(
                json=lambda: {
                    "safe": False,
                    "threat_type": "sensitive_file",
                    "reason": "Blocked sensitive file path: .env",
                },
                raise_for_status=lambda: None,
            ),
        ):
            result = client.scan_file("/app/.env")
            assert result["safe"] is False
            assert result["threat_type"] == "secrets_exposure"

        client.close()

    def test_scan_file_with_content(self) -> None:
        """Test scanning file with content for secrets."""
        client = ShrikeOpenAI(
            api_key="sk-test",
            shrike_api_key="shrike-test",
        )

        with mock.patch.object(
            client._http,
            "post",
            return_value=mock.Mock(
                json=lambda: {
                    "safe": False,
                    "threat_type": "sensitive_content",
                    "reason": "API key in content",
                },
                raise_for_status=lambda: None,
            ),
        ):
            result = client.scan_file(
                "/tmp/config.py",
                content="api_key = 'sk-1234567890abcdef'"
            )
            assert result["safe"] is False

        client.close()

    def test_scan_file_timeout_fail_open(self) -> None:
        """Test file scan timeout with fail_mode='open'."""
        client = ShrikeOpenAI(
            api_key="sk-test",
            shrike_api_key="shrike-test",
            fail_mode="open",
        )

        with mock.patch.object(
            client._http,
            "post",
            side_effect=httpx.TimeoutException("Timeout"),
        ):
            result = client.scan_file("/tmp/file.txt")
            assert result["safe"] is True

        client.close()


class TestShrikeOpenAIContextManager:
    """Test context manager functionality."""

    def test_context_manager(self) -> None:
        """Test using client as context manager."""
        with ShrikeOpenAI(api_key="sk-test", shrike_api_key="shrike-test") as client:
            assert client is not None
        # Client should be closed after exiting context
