"""ShrikeAsyncOpenAI - Async OpenAI client wrapper with security scanning."""

import logging
from typing import Any, AsyncIterator, Dict, List, Optional, Union

import httpx
from openai import AsyncOpenAI
from openai.types.chat import ChatCompletion, ChatCompletionChunk

from .config import DEFAULT_ENDPOINT, DEFAULT_FAIL_MODE, DEFAULT_SCAN_TIMEOUT, FailMode
from .exceptions import ShrikeBlockedError, ShrikeScanError
from .sanitizer import sanitize_scan_response
from .scanner import get_scan_headers

logger = logging.getLogger("shrike-guard")


class ShrikeAsyncOpenAI:
    """Async drop-in replacement for openai.AsyncOpenAI with Shrike security protection.

    This class wraps the official AsyncOpenAI client and automatically scans
    all prompts before they are sent to the LLM. If a prompt is detected
    as unsafe, the request is blocked and a ShrikeBlockedError is raised.

    Example:
        >>> import asyncio
        >>> from shrike_guard import ShrikeAsyncOpenAI
        >>>
        >>> async def main():
        ...     client = ShrikeAsyncOpenAI(
        ...         api_key="sk-...",
        ...         shrike_api_key="shrike-..."
        ...     )
        ...     response = await client.chat.completions.create(
        ...         model="gpt-4",
        ...         messages=[{"role": "user", "content": "Hello!"}]
        ...     )
        ...     print(response.choices[0].message.content)
        >>>
        >>> asyncio.run(main())

    Attributes:
        chat: Namespace for chat-related operations (chat.completions.create).
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        shrike_api_key: Optional[str] = None,
        shrike_endpoint: str = DEFAULT_ENDPOINT,
        fail_mode: Union[str, FailMode] = DEFAULT_FAIL_MODE,
        scan_timeout: float = DEFAULT_SCAN_TIMEOUT,
        **openai_kwargs: Any,
    ) -> None:
        """Initialize the ShrikeAsyncOpenAI client.

        Args:
            api_key: OpenAI API key. If not provided, uses OPENAI_API_KEY env var.
            shrike_api_key: Shrike API key for authentication with the scan service.
            shrike_endpoint: Shrike API endpoint URL.
            fail_mode: Behavior on scan failure - "open" (allow) or "closed" (block).
            scan_timeout: Timeout for scan requests in seconds.
            **openai_kwargs: Additional arguments passed to the AsyncOpenAI client.
        """
        self._openai = AsyncOpenAI(api_key=api_key, **openai_kwargs)
        self._shrike_endpoint = shrike_endpoint.rstrip("/")
        self._shrike_api_key = shrike_api_key or ""
        self._fail_mode = FailMode(fail_mode) if isinstance(fail_mode, str) else fail_mode
        self._scan_timeout = scan_timeout
        self._http = httpx.AsyncClient(timeout=scan_timeout)

        # Note: All scanning is done via backend API (tier-based: free=L1-L4, paid=L1-L8)
        # No local scanning - backend has full regex patterns (~50+) and normalizers

        # Expose chat interface
        self.chat = _AsyncChatNamespace(self)

    def _extract_user_content(self, messages: List[Dict[str, Any]]) -> str:
        """Extract all user message content from a messages list.

        Args:
            messages: List of message dictionaries with 'role' and 'content'.

        Returns:
            Concatenated string of all user message content.
        """
        user_contents = []
        for msg in messages:
            if msg.get("role") == "user":
                content = msg.get("content")
                if isinstance(content, str):
                    user_contents.append(content)
                elif isinstance(content, list):
                    # Handle multimodal content (list of content parts)
                    for part in content:
                        if isinstance(part, dict) and part.get("type") == "text":
                            user_contents.append(part.get("text", ""))
        return "\n".join(user_contents)

    async def _scan_messages(self, messages: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Scan user messages for security threats via backend API.

        Always calls backend - backend handles tier-based scanning:
        - Free tier (no API key): L1-L4 (regex, unicode, encoding, token normalization)
        - Paid tier: L1-L8 (full scan including LLM)

        Args:
            messages: List of message dictionaries to scan.

        Returns:
            Scan result dictionary with 'safe' boolean and additional details.
        """
        user_content = self._extract_user_content(messages)

        if not user_content.strip():
            return {"safe": True, "reason": "No user content to scan"}

        # Always call backend API - tier detection happens server-side
        return await self._remote_scan(user_content)

    async def _remote_scan(self, prompt: str) -> Dict[str, Any]:
        """Full scan via Shrike backend API.

        Backend handles tier-based scanning automatically based on API key presence.

        Args:
            prompt: The prompt text to scan.

        Returns:
            Scan result dictionary.
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

    async def scan_sql(
        self,
        query: str,
        database: Optional[str] = None,
        allow_destructive: bool = False,
    ) -> Dict[str, Any]:
        """Scan a SQL query for injection attacks and dangerous operations.

        Use this to validate AI-generated SQL before execution.

        Args:
            query: The SQL query to scan.
            database: Optional database name for context.
            allow_destructive: If True, allows DROP/TRUNCATE operations.

        Returns:
            Scan result with 'safe' boolean, 'threat_level', 'issues', etc.

        Example:
            >>> result = await client.scan_sql("SELECT * FROM users WHERE id = 1")
            >>> if result['safe']:
            ...     await cursor.execute(query)
        """
        try:
            response = await self._http.post(
                f"{self._shrike_endpoint}/api/scan/specialized",
                json={
                    "content": query,
                    "content_type": "sql",
                    "context": {
                        "database": database or "",
                        "allow_destructive": str(allow_destructive).lower(),
                    },
                },
                headers=get_scan_headers(self._shrike_api_key),
            )
            response.raise_for_status()
            return sanitize_scan_response(response.json())
        except httpx.TimeoutException:
            if self._fail_mode == FailMode.OPEN:
                return {"safe": True, "reason": "Scan timeout, failing open"}
            raise ShrikeScanError("SQL scan request timed out")
        except Exception as e:
            if self._fail_mode == FailMode.OPEN:
                return {"safe": True, "reason": f"Scan error: {str(e)}"}
            raise ShrikeScanError(f"SQL scan failed: {str(e)}")

    async def scan_file(
        self,
        path: str,
        content: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Scan a file path (and optionally content) for security risks.

        Use this to validate AI-suggested file paths before writing.

        Args:
            path: The file path to validate.
            content: Optional file content to scan for secrets/PII.

        Returns:
            Scan result with 'safe' boolean, 'threat_type', 'reason', etc.

        Example:
            >>> result = await client.scan_file("/tmp/config.json", content)
            >>> if result['safe']:
            ...     async with aiofiles.open(path, 'w') as f:
            ...         await f.write(content)
        """
        content_type = "file_content" if content else "file_path"
        payload: Dict[str, Any] = {
            "content": path,
            "content_type": content_type,
        }
        if content:
            payload["context"] = {"file_content": content}

        try:
            response = await self._http.post(
                f"{self._shrike_endpoint}/api/scan/specialized",
                json=payload,
                headers=get_scan_headers(self._shrike_api_key),
            )
            response.raise_for_status()
            return sanitize_scan_response(response.json())
        except httpx.TimeoutException:
            if self._fail_mode == FailMode.OPEN:
                return {"safe": True, "reason": "Scan timeout, failing open"}
            raise ShrikeScanError("File scan request timed out")
        except Exception as e:
            if self._fail_mode == FailMode.OPEN:
                return {"safe": True, "reason": f"Scan error: {str(e)}"}
            raise ShrikeScanError(f"File scan failed: {str(e)}")

    async def close(self) -> None:
        """Close HTTP connections."""
        await self._http.aclose()
        await self._openai.close()

    async def __aenter__(self) -> "ShrikeAsyncOpenAI":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()


class _AsyncChatNamespace:
    """Async namespace for chat-related operations."""

    def __init__(self, client: ShrikeAsyncOpenAI) -> None:
        self._client = client
        self.completions = _AsyncCompletionsNamespace(client)


class _AsyncCompletionsNamespace:
    """Async namespace for chat.completions operations."""

    def __init__(self, client: ShrikeAsyncOpenAI) -> None:
        self._client = client

    async def create(
        self,
        messages: List[Dict[str, Any]],
        stream: bool = False,
        **kwargs: Any,
    ) -> Union[ChatCompletion, AsyncIterator[ChatCompletionChunk]]:
        """Create a chat completion with security scanning.

        This method scans the user messages before sending them to OpenAI.
        If the scan detects a security threat, a ShrikeBlockedError is raised.

        Args:
            messages: List of message dictionaries for the conversation.
            stream: Whether to stream the response.
            **kwargs: Additional arguments passed to the OpenAI API.

        Returns:
            ChatCompletion object or async iterator of ChatCompletionChunk objects.

        Raises:
            ShrikeBlockedError: If the prompt is blocked by security scan.
            ShrikeScanError: If scan fails and fail_mode is 'closed'.
        """
        # 1. Scan messages for security threats
        scan_result = await self._client._scan_messages(messages)

        # 2. Block if unsafe
        if not scan_result.get("safe", True):
            violations = scan_result.get("violations", [])
            raise ShrikeBlockedError(
                message=f"Request blocked: {scan_result.get('reason', 'Security threat detected')}",
                threat_type=scan_result.get("threat_type"),
                confidence=scan_result.get("confidence"),
                violations=violations,
            )

        # 3. Proxy to OpenAI
        return await self._client._openai.chat.completions.create(
            messages=messages,  # type: ignore[arg-type]
            stream=stream,
            **kwargs,
        )
