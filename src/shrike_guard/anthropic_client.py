"""Shrike-protected Anthropic client wrapper."""

import logging
from typing import Any, Dict, Iterator, List, Optional, Union

import httpx

from .config import DEFAULT_ENDPOINT, DEFAULT_FAIL_MODE, DEFAULT_SCAN_TIMEOUT, FailMode
from .exceptions import ShrikeBlockedError, ShrikeScanError
from .sanitizer import sanitize_scan_response
from .scanner import get_scan_headers

logger = logging.getLogger("shrike-guard")

try:
    from anthropic import Anthropic
    from anthropic.types import Message, MessageStreamEvent
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    Anthropic = None  # type: ignore
    Message = None  # type: ignore
    MessageStreamEvent = None  # type: ignore


class ShrikeAnthropic:
    """Drop-in replacement for anthropic.Anthropic with Shrike protection.

    Intercepts all messages.create() calls to scan prompts before
    they reach Claude.

    Example:
        from shrike_guard import ShrikeAnthropic

        client = ShrikeAnthropic(
            api_key="sk-ant-...",
            shrike_api_key="shrike-...",
        )

        response = client.messages.create(
            model="claude-3-opus-20240229",
            max_tokens=1024,
            messages=[{"role": "user", "content": "Hello!"}]
        )
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        shrike_api_key: Optional[str] = None,
        shrike_endpoint: str = DEFAULT_ENDPOINT,
        fail_mode: Union[str, FailMode] = DEFAULT_FAIL_MODE,
        scan_timeout: float = DEFAULT_SCAN_TIMEOUT,
        **anthropic_kwargs: Any,
    ) -> None:
        """Initialize the Shrike-protected Anthropic client.

        Args:
            api_key: Anthropic API key
            shrike_api_key: Shrike API key for authentication
            shrike_endpoint: Shrike backend URL
            fail_mode: "open" (allow on scan failure) or "closed" (block on failure)
            scan_timeout: Timeout for scan requests in seconds
            **anthropic_kwargs: Additional arguments passed to Anthropic client
        """
        if not ANTHROPIC_AVAILABLE:
            raise ImportError(
                "anthropic package is not installed. "
                "Install it with: pip install anthropic"
            )

        self._anthropic = Anthropic(api_key=api_key, **anthropic_kwargs)
        self._shrike_endpoint = shrike_endpoint.rstrip("/")
        self._shrike_api_key = shrike_api_key or ""
        self._fail_mode = FailMode(fail_mode) if isinstance(fail_mode, str) else fail_mode
        self._scan_timeout = scan_timeout
        self._http = httpx.Client(timeout=scan_timeout)

        # Note: All scanning is done via backend API (tier-based: free=L1-L4, paid=L1-L8)
        # No local scanning - backend has full regex patterns (~50+) and normalizers

        # Expose messages interface
        self.messages = _MessagesNamespace(self)

    def _extract_user_content(self, messages: List[Dict[str, Any]]) -> str:
        """Extract text content from user messages.

        Handles both simple string content and content blocks.
        """
        user_texts: List[str] = []

        for msg in messages:
            if msg.get("role") != "user":
                continue

            content = msg.get("content")
            if isinstance(content, str):
                user_texts.append(content)
            elif isinstance(content, list):
                # Handle content blocks (text, image, etc.)
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        user_texts.append(block.get("text", ""))
                    elif isinstance(block, str):
                        user_texts.append(block)

        return "\n".join(user_texts)

    def _scan_messages(self, messages: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Scan user messages for security threats via backend API.

        Always calls backend - backend handles tier-based scanning:
        - Free tier (no API key): L1-L4 (regex, unicode, encoding, token normalization)
        - Paid tier: L1-L8 (full scan including LLM)
        """
        user_content = self._extract_user_content(messages)

        if not user_content.strip():
            return {"safe": True, "reason": "No user content to scan"}

        # Always call backend API - tier detection happens server-side
        return self._remote_scan(user_content)

    def _remote_scan(self, prompt: str) -> Dict[str, Any]:
        """Full scan via Shrike backend API.

        Backend handles tier-based scanning automatically based on API key presence.
        """
        try:
            response = self._http.post(
                f"{self._shrike_endpoint}/scan",
                json={"prompt": prompt},
                headers=get_scan_headers(self._shrike_api_key),
            )
            response.raise_for_status()
            return sanitize_scan_response(response.json())
        except httpx.TimeoutException:
            if self._fail_mode == FailMode.OPEN:
                # No local fallback - just fail open
                logger.warning("Scan request timed out, failing open (allowing request)")
                return {"safe": True, "reason": "Scan timeout, failing open"}
            raise ShrikeScanError("Scan request timed out and fail_mode is 'closed'")
        except httpx.HTTPStatusError as e:
            if self._fail_mode == FailMode.OPEN:
                return {"safe": True, "reason": f"Scan API error: {e.response.status_code}"}
            raise ShrikeScanError(f"Scan API returned error: {e.response.status_code}")
        except Exception as e:
            if self._fail_mode == FailMode.OPEN:
                return {"safe": True, "reason": f"Scan error: {str(e)}"}
            raise ShrikeScanError(f"Scan failed: {str(e)}")

    def close(self) -> None:
        """Close the HTTP client."""
        self._http.close()

    def __enter__(self) -> "ShrikeAnthropic":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


class _MessagesNamespace:
    """Namespace for messages API."""

    def __init__(self, client: ShrikeAnthropic) -> None:
        self._client = client

    def create(
        self,
        *,
        model: str,
        max_tokens: int,
        messages: List[Dict[str, Any]],
        stream: bool = False,
        **kwargs: Any,
    ) -> Union["Message", Iterator["MessageStreamEvent"]]:
        """Create a message with Shrike protection.

        Scans all user messages before sending to Claude.
        Raises ShrikeBlockedError if threats are detected.

        Args:
            model: The model to use (e.g., "claude-3-opus-20240229")
            max_tokens: Maximum tokens in the response
            messages: List of message dictionaries
            stream: Whether to stream the response
            **kwargs: Additional arguments passed to Anthropic API

        Returns:
            Message object or iterator of MessageStreamEvent objects if streaming
        """
        # 1. Scan messages BEFORE streaming starts
        scan_result = self._client._scan_messages(messages)

        # 2. Block if unsafe
        if not scan_result.get("safe", True):
            raise ShrikeBlockedError(
                message=scan_result.get("reason", "Request blocked by Shrike"),
                threat_type=scan_result.get("threat_type"),
                confidence=scan_result.get("confidence"),
            )

        # 3. Proxy to Anthropic
        return self._client._anthropic.messages.create(
            model=model,
            max_tokens=max_tokens,
            messages=messages,
            stream=stream,
            **kwargs,
        )

    def stream(
        self,
        *,
        model: str,
        max_tokens: int,
        messages: List[Dict[str, Any]],
        **kwargs: Any,
    ) -> Any:
        """Stream a message with Shrike protection.

        Alternative streaming API using context manager.
        Scans all user messages before streaming starts.
        """
        # 1. Scan messages BEFORE streaming starts
        scan_result = self._client._scan_messages(messages)

        # 2. Block if unsafe
        if not scan_result.get("safe", True):
            raise ShrikeBlockedError(
                message=scan_result.get("reason", "Request blocked by Shrike"),
                threat_type=scan_result.get("threat_type"),
                confidence=scan_result.get("confidence"),
            )

        # 3. Proxy to Anthropic stream API
        return self._client._anthropic.messages.stream(
            model=model,
            max_tokens=max_tokens,
            messages=messages,
            **kwargs,
        )


class ShrikeAsyncAnthropic:
    """Async drop-in replacement for anthropic.AsyncAnthropic with Shrike protection.

    Example:
        import asyncio
        from shrike_guard import ShrikeAsyncAnthropic

        async def main():
            client = ShrikeAsyncAnthropic(
                api_key="sk-ant-...",
                shrike_api_key="shrike-...",
            )

            response = await client.messages.create(
                model="claude-3-opus-20240229",
                max_tokens=1024,
                messages=[{"role": "user", "content": "Hello!"}]
            )
            await client.close()

        asyncio.run(main())
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        shrike_api_key: Optional[str] = None,
        shrike_endpoint: str = DEFAULT_ENDPOINT,
        fail_mode: Union[str, FailMode] = DEFAULT_FAIL_MODE,
        scan_timeout: float = DEFAULT_SCAN_TIMEOUT,
        **anthropic_kwargs: Any,
    ) -> None:
        if not ANTHROPIC_AVAILABLE:
            raise ImportError(
                "anthropic package is not installed. "
                "Install it with: pip install anthropic"
            )

        from anthropic import AsyncAnthropic

        self._anthropic = AsyncAnthropic(api_key=api_key, **anthropic_kwargs)
        self._shrike_endpoint = shrike_endpoint.rstrip("/")
        self._shrike_api_key = shrike_api_key or ""
        self._fail_mode = FailMode(fail_mode) if isinstance(fail_mode, str) else fail_mode
        self._scan_timeout = scan_timeout
        self._http = httpx.AsyncClient(timeout=scan_timeout)

        # Note: All scanning is done via backend API (tier-based: free=L1-L4, paid=L1-L8)
        # No local scanning - backend has full regex patterns (~50+) and normalizers

        self.messages = _AsyncMessagesNamespace(self)

    def _extract_user_content(self, messages: List[Dict[str, Any]]) -> str:
        """Extract text content from user messages."""
        user_texts: List[str] = []

        for msg in messages:
            if msg.get("role") != "user":
                continue

            content = msg.get("content")
            if isinstance(content, str):
                user_texts.append(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        user_texts.append(block.get("text", ""))
                    elif isinstance(block, str):
                        user_texts.append(block)

        return "\n".join(user_texts)

    async def _scan_messages(self, messages: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Scan user messages for security threats via backend API.

        Always calls backend - backend handles tier-based scanning:
        - Free tier (no API key): L1-L4 (regex, unicode, encoding, token normalization)
        - Paid tier: L1-L8 (full scan including LLM)
        """
        user_content = self._extract_user_content(messages)

        if not user_content.strip():
            return {"safe": True, "reason": "No user content to scan"}

        # Always call backend API - tier detection happens server-side
        return await self._remote_scan(user_content)

    async def _remote_scan(self, prompt: str) -> Dict[str, Any]:
        """Full scan via Shrike backend API (async).

        Backend handles tier-based scanning automatically based on API key presence.
        """
        try:
            response = await self._http.post(
                f"{self._shrike_endpoint}/scan",
                json={"prompt": prompt},
                headers=get_scan_headers(self._shrike_api_key),
            )
            response.raise_for_status()
            return sanitize_scan_response(response.json())
        except httpx.TimeoutException:
            if self._fail_mode == FailMode.OPEN:
                # No local fallback - just fail open
                logger.warning("Scan request timed out, failing open (allowing request)")
                return {"safe": True, "reason": "Scan timeout, failing open"}
            raise ShrikeScanError("Scan request timed out and fail_mode is 'closed'")
        except httpx.HTTPStatusError as e:
            if self._fail_mode == FailMode.OPEN:
                return {"safe": True, "reason": f"Scan API error: {e.response.status_code}"}
            raise ShrikeScanError(f"Scan API returned error: {e.response.status_code}")
        except Exception as e:
            if self._fail_mode == FailMode.OPEN:
                return {"safe": True, "reason": f"Scan error: {str(e)}"}
            raise ShrikeScanError(f"Scan failed: {str(e)}")

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._http.aclose()

    async def __aenter__(self) -> "ShrikeAsyncAnthropic":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()


class _AsyncMessagesNamespace:
    """Async namespace for messages API."""

    def __init__(self, client: ShrikeAsyncAnthropic) -> None:
        self._client = client

    async def create(
        self,
        *,
        model: str,
        max_tokens: int,
        messages: List[Dict[str, Any]],
        stream: bool = False,
        **kwargs: Any,
    ) -> Union["Message", Any]:
        """Create a message with Shrike protection (async).

        Args:
            model: The model to use
            max_tokens: Maximum tokens in the response
            messages: List of message dictionaries
            stream: Whether to stream the response
            **kwargs: Additional arguments passed to Anthropic API

        Returns:
            Message object or async iterator if streaming
        """
        # 1. Scan messages BEFORE streaming starts
        scan_result = await self._client._scan_messages(messages)

        # 2. Block if unsafe
        if not scan_result.get("safe", True):
            raise ShrikeBlockedError(
                message=scan_result.get("reason", "Request blocked by Shrike"),
                threat_type=scan_result.get("threat_type"),
                confidence=scan_result.get("confidence"),
            )

        # 3. Proxy to Anthropic
        return await self._client._anthropic.messages.create(
            model=model,
            max_tokens=max_tokens,
            messages=messages,
            stream=stream,
            **kwargs,
        )

    async def stream(
        self,
        *,
        model: str,
        max_tokens: int,
        messages: List[Dict[str, Any]],
        **kwargs: Any,
    ) -> Any:
        """Stream a message with Shrike protection (async).

        Alternative streaming API using async context manager.
        Scans all user messages before streaming starts.
        """
        # 1. Scan messages BEFORE streaming starts
        scan_result = await self._client._scan_messages(messages)

        # 2. Block if unsafe
        if not scan_result.get("safe", True):
            raise ShrikeBlockedError(
                message=scan_result.get("reason", "Request blocked by Shrike"),
                threat_type=scan_result.get("threat_type"),
                confidence=scan_result.get("confidence"),
            )

        # 3. Proxy to Anthropic stream API
        return self._client._anthropic.messages.stream(
            model=model,
            max_tokens=max_tokens,
            messages=messages,
            **kwargs,
        )
