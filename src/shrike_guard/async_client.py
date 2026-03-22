"""ShrikeAsyncOpenAI - Async OpenAI client wrapper with security scanning."""

import logging
from typing import Any, AsyncIterator, Dict, List, Optional, Union

import httpx
from openai import AsyncOpenAI
from openai.types.chat import ChatCompletion, ChatCompletionChunk

from .config import DEFAULT_ENDPOINT, DEFAULT_FAIL_MODE, DEFAULT_SCAN_TIMEOUT, FailMode
from .exceptions import ShrikeBlockedError, ShrikeScanError
from .resilience import CircuitBreaker, CircuitOpenError, async_retry_with_backoff
from .sanitizer import sanitize_scan_response
from .scanner import get_scan_headers

logger = logging.getLogger("shrike-guard")


def _is_retryable(e: Exception) -> bool:
    """Determine if an error should be retried."""
    if isinstance(e, CircuitOpenError):
        return False
    if isinstance(e, httpx.HTTPStatusError):
        return e.response.status_code >= 500
    return isinstance(e, (httpx.TimeoutException, httpx.ConnectError, ConnectionError))


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
        circuit_breaker: Optional[CircuitBreaker] = None,
        **openai_kwargs: Any,
    ) -> None:
        """Initialize the ShrikeAsyncOpenAI client.

        Args:
            api_key: OpenAI API key. If not provided, uses OPENAI_API_KEY env var.
            shrike_api_key: Shrike API key for authentication with the scan service.
            shrike_endpoint: Shrike API endpoint URL.
            fail_mode: Behavior on scan failure - "open" (allow) or "closed" (block).
            scan_timeout: Timeout for scan requests in seconds.
            circuit_breaker: Optional shared CircuitBreaker instance.
            **openai_kwargs: Additional arguments passed to the AsyncOpenAI client.
        """
        self._openai = AsyncOpenAI(api_key=api_key, **openai_kwargs)
        self._shrike_endpoint = shrike_endpoint.rstrip("/")
        self._shrike_api_key = shrike_api_key or ""
        self._fail_mode = FailMode(fail_mode) if isinstance(fail_mode, str) else fail_mode
        self._scan_timeout = scan_timeout
        self._http = httpx.AsyncClient(timeout=scan_timeout)
        self._circuit_breaker = circuit_breaker or CircuitBreaker()

        # Expose chat interface
        self.chat = _AsyncChatNamespace(self)

    def _extract_user_content(self, messages: List[Dict[str, Any]]) -> str:
        """Extract all user message content from a messages list."""
        user_contents = []
        for msg in messages:
            if msg.get("role") == "user":
                content = msg.get("content")
                if isinstance(content, str):
                    user_contents.append(content)
                elif isinstance(content, list):
                    for part in content:
                        if isinstance(part, dict) and part.get("type") == "text":
                            user_contents.append(part.get("text", ""))
        return "\n".join(user_contents)

    async def _scan_messages(self, messages: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Scan user messages for security threats via backend API."""
        user_content = self._extract_user_content(messages)

        if not user_content.strip():
            return {"safe": True, "reason": "No user content to scan"}

        return await self._remote_scan(user_content)

    async def _remote_scan(self, prompt: str) -> Dict[str, Any]:
        """Full scan via Shrike backend API with circuit breaker and retry."""
        async def _do_scan() -> Dict[str, Any]:
            return await async_retry_with_backoff(
                lambda: self._do_http_scan(
                    f"{self._shrike_endpoint}/scan",
                    {"prompt": prompt},
                ),
                max_attempts=3,
                is_retryable=_is_retryable,
            )

        try:
            return await self._circuit_breaker.execute_async(_do_scan)
        except CircuitOpenError:
            if self._fail_mode == FailMode.OPEN:
                logger.warning("Circuit breaker open, failing open (allowing request)")
                return {"safe": True, "reason": "Circuit breaker open, failing open", "degraded": True}
            raise ShrikeScanError("Security service circuit breaker open")
        except httpx.TimeoutException:
            if self._fail_mode == FailMode.OPEN:
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

    async def _do_http_scan(self, url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single async HTTP scan request."""
        response = await self._http.post(
            url,
            json=payload,
            headers=get_scan_headers(self._shrike_api_key),
        )
        response.raise_for_status()
        return sanitize_scan_response(response.json())

    async def scan_sql(
        self,
        query: str,
        database: Optional[str] = None,
        allow_destructive: bool = False,
    ) -> Dict[str, Any]:
        """Scan a SQL query for injection attacks and dangerous operations."""
        payload = {
            "content": query,
            "content_type": "sql",
            "context": {
                "database": database or "",
                "allow_destructive": str(allow_destructive).lower(),
            },
        }
        url = f"{self._shrike_endpoint}/api/scan/specialized"

        try:
            return await self._circuit_breaker.execute_async(
                lambda: async_retry_with_backoff(
                    lambda: self._do_http_scan(url, payload),
                    max_attempts=3,
                    is_retryable=_is_retryable,
                )
            )
        except CircuitOpenError:
            if self._fail_mode == FailMode.OPEN:
                return {"safe": True, "reason": "Circuit breaker open, failing open", "degraded": True}
            raise ShrikeScanError("Security service circuit breaker open")
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
        """Scan a file path (and optionally content) for security risks."""
        content_type = "file_content" if content else "file_path"
        payload: Dict[str, Any] = {
            "content": path,
            "content_type": content_type,
        }
        if content:
            payload["context"] = {"file_content": content}

        url = f"{self._shrike_endpoint}/api/scan/specialized"
        try:
            return await self._circuit_breaker.execute_async(
                lambda: async_retry_with_backoff(
                    lambda: self._do_http_scan(url, payload),
                    max_attempts=3,
                    is_retryable=_is_retryable,
                )
            )
        except CircuitOpenError:
            if self._fail_mode == FailMode.OPEN:
                return {"safe": True, "reason": "Circuit breaker open, failing open", "degraded": True}
            raise ShrikeScanError("Security service circuit breaker open")
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
        """Create a chat completion with security scanning."""
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
