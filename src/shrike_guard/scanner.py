"""HTTP client for the Shrike scan API."""

import logging
import uuid
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger("shrike-guard")

from ._version import __version__
from .chunker import AUTO_CHUNK_THRESHOLD, aggregate_chunk_results, chunk_content
from .config import DEFAULT_ENDPOINT, DEFAULT_SCAN_TIMEOUT, SDK_NAME
from .exceptions import ShrikeRateLimitError
from .sanitizer import sanitize_scan_response


def _check_rate_limited(response: httpx.Response) -> None:
    """Raise :class:`ShrikeRateLimitError` on 429; return None otherwise.

    Callers should invoke this before ``response.raise_for_status()`` so the
    typed rate-limit error surfaces instead of a generic
    :class:`httpx.HTTPStatusError`. All other 4xx/5xx flow through
    ``raise_for_status`` unchanged.
    """
    if response.status_code != 429:
        return
    retry_after_raw = response.headers.get("Retry-After") or response.headers.get("retry-after")
    retry_after: Optional[float] = None
    if retry_after_raw:
        try:
            retry_after = float(retry_after_raw)
        except (TypeError, ValueError):
            retry_after = None
    raise ShrikeRateLimitError(
        "Shrike backend returned 429 Too Many Requests",
        retry_after=retry_after,
    )


def _is_blocked(verdict: Dict[str, Any]) -> bool:
    """Decide whether a scan verdict should be enforced as a block.

    Prefers the server-authoritative ``action`` field emitted by
    ``/api/scan/enforce``. Falls back to the legacy
    ``safe`` boolean for verdicts that predate the enforce endpoint (older
    backends, circuit-breaker fail-open synthetic verdicts, cached responses).

    Behavior:
        - ``action == "block"``            → True
        - ``action == "require_approval"`` → True (held actions are refused
                                             at the tool-call boundary; the
                                             caller can re-issue after
                                             approval lands)
        - ``action == "allow"``            → False
        - ``action == "warn"``             → False (advisory; caller should
                                             surface via block-feedback but
                                             not refuse)
        - ``action`` absent OR unknown     → fall back to ``not safe``
                                             (a new blocking tier the backend
                                             adds — e.g. "quarantine" — also
                                             sets safe=False, so an
                                             unrecognized tier fails CLOSED
                                             instead of open. Forward-compat
                                             contract, see
                                             tests/test_contract_forward_compat.py)

    This helper is the ONLY place the SDK converts a verdict into a
    proceed-vs-refuse decision. Every LLM wrapper (OpenAI, Anthropic, Gemini,
    sync + async) routes through it so behavior stays uniform.
    """
    action = verdict.get("action")
    if action:
        if action in ("allow", "warn"):
            return False
        if action in ("block", "require_approval"):
            return True
        # Unknown/future tier: do NOT fail open on an unrecognized name —
        # fall through to ``safe``.
    return not verdict.get("safe", True)

# Phase 8b: Client-side size limits to fail fast before network round-trip.
# These limits match the backend limits for consistency.
MAX_CONTENT_SIZE = 100 * 1024  # 100KB - matches backend MaxRequestBodySize


def _check_content_size(content: str, context: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Check if content exceeds the maximum size limit.

    Returns a blocked result dict if too large, None otherwise.
    """
    total_size = len(content) + (len(context) if context else 0)
    if total_size > MAX_CONTENT_SIZE:
        return {
            "safe": False,
            "reason": f"Content too large ({total_size // 1024}KB > {MAX_CONTENT_SIZE // 1024}KB limit)",
            "threat_type": "size_limit_exceeded",
            "confidence": 1.0,
            "violations": [
                {
                    "type": "size_limit",
                    "description": f"Content exceeds maximum size of {MAX_CONTENT_SIZE // 1024}KB",
                }
            ],
        }
    return None


def maybe_add_signup_hint(result: Dict[str, Any], api_key: str) -> Dict[str, Any]:
    """Append a signup hint to scan results when running without an API key.

    When no API key is configured, the user gets L1-L5 only scanning.
    This hint tells agents/users how to register for cognitive threat detection.
    """
    if api_key:
        return result
    # Don't override if backend already provided upgrade_hint
    if result.get("upgrade_hint"):
        return result
    return {
        **result,
        "_note": (
            "Running without API key (L1-L5 only). "
            "Register free for cognitive threat detection: npx shrike-mcp --signup"
        ),
    }


def get_scan_headers(shrike_api_key: str, request_id: Optional[str] = None) -> Dict[str, str]:
    """Generate headers for scan API requests.

    Args:
        shrike_api_key: The Shrike API key for authentication.
        request_id: Optional request ID for tracing. If not provided,
                   a new UUID will be generated.

    Returns:
        Dictionary of HTTP headers to include in the request.
    """
    return {
        "Authorization": f"Bearer {shrike_api_key}",
        "Content-Type": "application/json",
        "X-Shrike-SDK": SDK_NAME,
        "X-Shrike-SDK-Version": __version__,
        "X-Shrike-Request-ID": request_id or str(uuid.uuid4()),
    }


class ScanClient:
    """Synchronous HTTP client for the Shrike scan API."""

    def __init__(
        self,
        api_key: str,
        endpoint: str = DEFAULT_ENDPOINT,
        timeout: float = DEFAULT_SCAN_TIMEOUT,
    ) -> None:
        """Initialize the scan client.

        Args:
            api_key: Shrike API key for authentication.
            endpoint: Shrike API endpoint URL.
            timeout: Request timeout in seconds.
        """
        self._api_key = api_key
        self._endpoint = endpoint.rstrip("/")
        self._timeout = timeout
        self._http = httpx.Client(timeout=timeout)

        if not self._api_key:
            logger.warning("[shrike-guard] No API key provided — running in free tier (regex-only).")
            logger.warning("[shrike-guard] For full scanning: npx shrike-mcp --signup")

    def scan(self, prompt: str, context: Optional[str] = None) -> Dict[str, Any]:
        """Scan a prompt for security threats.

        Args:
            prompt: The user prompt to scan.
            context: Optional conversation context for better analysis.

        Returns:
            Scan result dictionary with 'safe' boolean and additional details.

        Raises:
            httpx.TimeoutException: If the request times out.
            httpx.HTTPError: If the request fails.
        """
        # Phase 8b: Client-side size validation to fail fast
        size_result = _check_content_size(prompt, context)
        if size_result:
            return size_result

        # Auto-chunk large prompts. Below the threshold the single-shot path
        # is unchanged; above it we split on natural boundaries, scan each
        # chunk sequentially, and stop on the first block verdict.
        if len(prompt) > AUTO_CHUNK_THRESHOLD:
            return self._scan_chunked(prompt, context)

        return self._scan_single(prompt, context)

    def _scan_single(self, prompt: str, context: Optional[str] = None) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"prompt": prompt}
        if context:
            payload["context"] = context

        response = self._http.post(
            f"{self._endpoint}/api/scan/enforce",
            json=payload,
            headers=get_scan_headers(self._api_key),
        )
        _check_rate_limited(response)
        response.raise_for_status()
        return maybe_add_signup_hint(sanitize_scan_response(response.json()), self._api_key)

    def _scan_chunked(self, prompt: str, context: Optional[str] = None) -> Dict[str, Any]:
        """Sequential fail-fast chunked scan. See chunker.py header for design.

        Known limit: same session ID rides every chunk, so L9 turn count
        inflates by chunk-count. Fix post-launch via backend chunk_group.
        """
        chunks = chunk_content(prompt)
        results: List[Dict[str, Any]] = []
        for chunk in chunks:
            chunk_result = self._scan_single(chunk, context)
            results.append(chunk_result)
            action = chunk_result.get("action") or chunk_result.get("refuse_tier")
            if action == "block":
                break
        return maybe_add_signup_hint(aggregate_chunk_results(results), self._api_key)

    def scan_sql(
        self,
        query: str,
        database: Optional[str] = None,
        allow_destructive: bool = False,
    ) -> Dict[str, Any]:
        """Scan a SQL query for injection attacks.

        Args:
            query: The SQL query to scan.
            database: Optional database name for context.
            allow_destructive: If True, allows DROP/TRUNCATE operations.

        Returns:
            Scan result dictionary with 'safe' boolean and additional details.
        """
        size_result = _check_content_size(query)
        if size_result:
            return size_result

        payload: Dict[str, Any] = {
            "content": query,
            "content_type": "sql",
            "context": {
                "database": database or "",
                "allow_destructive": str(allow_destructive),
            },
        }

        response = self._http.post(
            f"{self._endpoint}/api/scan/enforce/specialized",
            json=payload,
            headers=get_scan_headers(self._api_key),
        )
        _check_rate_limited(response)
        response.raise_for_status()
        return maybe_add_signup_hint(sanitize_scan_response(response.json()), self._api_key)

    def scan_file(
        self,
        path: str,
        content: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Scan a file path for security risks.

        Args:
            path: The file path to validate.
            content: Optional file content to scan for secrets/PII.

        Returns:
            Scan result dictionary with 'safe' boolean and additional details.
        """
        size_result = _check_content_size(path, content)
        if size_result:
            return size_result

        content_type = "file_content" if content else "file_path"
        payload: Dict[str, Any] = {
            "content": path,
            "content_type": content_type,
        }
        if content:
            payload["context"] = {"file_content": content}

        response = self._http.post(
            f"{self._endpoint}/api/scan/enforce/specialized",
            json=payload,
            headers=get_scan_headers(self._api_key),
        )
        _check_rate_limited(response)
        response.raise_for_status()
        return maybe_add_signup_hint(sanitize_scan_response(response.json()), self._api_key)

    def declare_scope(
        self,
        agent_id: str,
        allowed_tools: List[str],
        purpose: Optional[str] = None,
        forbidden_tools: Optional[List[str]] = None,
        max_duration_seconds: Optional[int] = None,
        expires_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Declare (or refresh) the operating scope for a task-scoped agent.

        Once declared, every subsequent scan for this agent_id is enforced
        against the scope on the backend. Tool calls outside allowed_tools
        (or explicitly on forbidden_tools) route to
        refuse_tier="require_approval" with threat_type="scope_violation".
        Expired scopes emit threat_type="scope_expired". Absent a
        declaration, no scope check runs — every existing SDK integration
        is unaffected until it opts in.

        Args:
            agent_id: The agent identity this scope applies to. Same string
                you'll pass in scan context on subsequent calls.
            allowed_tools: Exact tool names permitted. Pass ``["*"]`` to
                allow any tool.
            purpose: Optional human-readable description (audit + dashboard).
            forbidden_tools: Tool names explicitly forbidden; wins over
                allowed_tools.
            max_duration_seconds: Optional TTL relative to created_at.
            expires_at: Optional ISO-8601 absolute expiry; the earlier of
                this and max_duration_seconds wins.

        Returns:
            The persisted scope row including scope_id, active_until, and
            expired flag.

        Raises:
            httpx.HTTPError: On network failure or non-2xx backend response.
        """
        payload: Dict[str, Any] = {
            "agent_id": agent_id,
            "allowed_tools": allowed_tools,
        }
        if purpose is not None:
            payload["purpose"] = purpose
        if forbidden_tools is not None:
            payload["forbidden_tools"] = forbidden_tools
        if max_duration_seconds is not None:
            payload["max_duration_seconds"] = max_duration_seconds
        if expires_at is not None:
            payload["expires_at"] = expires_at

        response = self._http.post(
            f"{self._endpoint}/api/v1/agent/scope/declare",
            json=payload,
            headers=get_scan_headers(self._api_key),
        )
        _check_rate_limited(response)
        response.raise_for_status()
        return response.json()

    def close(self) -> None:
        """Close the HTTP client."""
        self._http.close()

    def __enter__(self) -> "ScanClient":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


class AsyncScanClient:
    """Asynchronous HTTP client for the Shrike scan API."""

    def __init__(
        self,
        api_key: str,
        endpoint: str = DEFAULT_ENDPOINT,
        timeout: float = DEFAULT_SCAN_TIMEOUT,
    ) -> None:
        """Initialize the async scan client.

        Args:
            api_key: Shrike API key for authentication.
            endpoint: Shrike API endpoint URL.
            timeout: Request timeout in seconds.
        """
        self._api_key = api_key
        self._endpoint = endpoint.rstrip("/")
        self._timeout = timeout
        self._http = httpx.AsyncClient(timeout=timeout)

        if not self._api_key:
            logger.warning("[shrike-guard] No API key provided — running in free tier (regex-only).")
            logger.warning("[shrike-guard] For full scanning: npx shrike-mcp --signup")

    async def scan(self, prompt: str, context: Optional[str] = None) -> Dict[str, Any]:
        """Scan a prompt for security threats.

        Args:
            prompt: The user prompt to scan.
            context: Optional conversation context for better analysis.

        Returns:
            Scan result dictionary with 'safe' boolean and additional details.

        Raises:
            httpx.TimeoutException: If the request times out.
            httpx.HTTPError: If the request fails.
        """
        # Phase 8b: Client-side size validation to fail fast
        size_result = _check_content_size(prompt, context)
        if size_result:
            return size_result

        if len(prompt) > AUTO_CHUNK_THRESHOLD:
            return await self._scan_chunked(prompt, context)

        return await self._scan_single(prompt, context)

    async def _scan_single(self, prompt: str, context: Optional[str] = None) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"prompt": prompt}
        if context:
            payload["context"] = context

        response = await self._http.post(
            f"{self._endpoint}/api/scan/enforce",
            json=payload,
            headers=get_scan_headers(self._api_key),
        )
        _check_rate_limited(response)
        response.raise_for_status()
        return maybe_add_signup_hint(sanitize_scan_response(response.json()), self._api_key)

    async def _scan_chunked(self, prompt: str, context: Optional[str] = None) -> Dict[str, Any]:
        """Sequential fail-fast chunked scan — async twin of ScanClient._scan_chunked."""
        chunks = chunk_content(prompt)
        results: List[Dict[str, Any]] = []
        for chunk in chunks:
            chunk_result = await self._scan_single(chunk, context)
            results.append(chunk_result)
            action = chunk_result.get("action") or chunk_result.get("refuse_tier")
            if action == "block":
                break
        return maybe_add_signup_hint(aggregate_chunk_results(results), self._api_key)

    async def scan_sql(
        self,
        query: str,
        database: Optional[str] = None,
        allow_destructive: bool = False,
    ) -> Dict[str, Any]:
        """Scan a SQL query for injection attacks.

        Args:
            query: The SQL query to scan.
            database: Optional database name for context.
            allow_destructive: If True, allows DROP/TRUNCATE operations.

        Returns:
            Scan result dictionary with 'safe' boolean and additional details.
        """
        size_result = _check_content_size(query)
        if size_result:
            return size_result

        payload: Dict[str, Any] = {
            "content": query,
            "content_type": "sql",
            "context": {
                "database": database or "",
                "allow_destructive": str(allow_destructive),
            },
        }

        response = await self._http.post(
            f"{self._endpoint}/api/scan/enforce/specialized",
            json=payload,
            headers=get_scan_headers(self._api_key),
        )
        _check_rate_limited(response)
        response.raise_for_status()
        return maybe_add_signup_hint(sanitize_scan_response(response.json()), self._api_key)

    async def scan_file(
        self,
        path: str,
        content: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Scan a file path for security risks.

        Args:
            path: The file path to validate.
            content: Optional file content to scan for secrets/PII.

        Returns:
            Scan result dictionary with 'safe' boolean and additional details.
        """
        size_result = _check_content_size(path, content)
        if size_result:
            return size_result

        content_type = "file_content" if content else "file_path"
        payload: Dict[str, Any] = {
            "content": path,
            "content_type": content_type,
        }
        if content:
            payload["context"] = {"file_content": content}

        response = await self._http.post(
            f"{self._endpoint}/api/scan/enforce/specialized",
            json=payload,
            headers=get_scan_headers(self._api_key),
        )
        _check_rate_limited(response)
        response.raise_for_status()
        return maybe_add_signup_hint(sanitize_scan_response(response.json()), self._api_key)

    async def declare_scope(
        self,
        agent_id: str,
        allowed_tools: List[str],
        purpose: Optional[str] = None,
        forbidden_tools: Optional[List[str]] = None,
        max_duration_seconds: Optional[int] = None,
        expires_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Declare (or refresh) the operating scope for a task-scoped agent.

        Async twin of :meth:`ScanClient.declare_scope`. Same wire contract.
        """
        payload: Dict[str, Any] = {
            "agent_id": agent_id,
            "allowed_tools": allowed_tools,
        }
        if purpose is not None:
            payload["purpose"] = purpose
        if forbidden_tools is not None:
            payload["forbidden_tools"] = forbidden_tools
        if max_duration_seconds is not None:
            payload["max_duration_seconds"] = max_duration_seconds
        if expires_at is not None:
            payload["expires_at"] = expires_at

        response = await self._http.post(
            f"{self._endpoint}/api/v1/agent/scope/declare",
            json=payload,
            headers=get_scan_headers(self._api_key),
        )
        _check_rate_limited(response)
        response.raise_for_status()
        return response.json()

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._http.aclose()

    async def __aenter__(self) -> "AsyncScanClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()
