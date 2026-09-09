"""HTTP client for the Shrike scan API."""

import json
import logging
import uuid
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger("shrike-guard")

from ._version import __version__
from .chunker import AUTO_CHUNK_THRESHOLD, aggregate_chunk_results, chunk_content
from .config import (
    DEFAULT_ENDPOINT,
    DEFAULT_SCAN_TIMEOUT,
    SDK_NAME,
    build_session_context,
)
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
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> None:
        """Initialize the scan client.

        Args:
            api_key: Shrike API key for authentication.
            endpoint: Shrike API endpoint URL.
            timeout: Request timeout in seconds.
            session_id: The session this client scans under. Session identity
                is the key the backend accumulates multi-turn risk against, so
                it should mean one unit of work: one agent run, one
                conversation, one user's request. Defaults to a process-wide
                id, which suits a CLI or a worker but not a server serving many
                end users, where each user needs its own session. Prefer
                :meth:`for_session` per request.
            agent_id: The agent this client scans as. Defaults to the
                process-wide id (``SHRIKE_AGENT_ID`` when set). Set it when one
                process drives several distinct agents, so scope enforcement
                and agent attribution land on the right one.
        """
        self._api_key = api_key
        self._endpoint = endpoint.rstrip("/")
        self._timeout = timeout
        self._session_id = session_id
        self._agent_id = agent_id
        self._http = httpx.Client(timeout=timeout)
        # Only the client that created the pool may close it — see for_session.
        self._owns_http = True

        if not self._api_key:
            logger.warning("[shrike-guard] No API key provided — running in free tier (regex-only).")
            logger.warning("[shrike-guard] For full scanning: npx shrike-mcp --signup")

    def for_session(
        self, session_id: str, agent_id: Optional[str] = None
    ) -> "ScanClient":
        """Return a view of this client that scans under ``session_id``.

        The returned client SHARES this one's connection pool, so calling it
        per request is cheap — that is the point. Build one ScanClient at
        startup and derive a per-request view from it::

            guard = ScanClient(api_key=KEY)          # once, at startup

            def handle(request):                     # per request
                scoped = guard.for_session(request.session_id)
                verdict = scoped.scan_command(request.command)

        Without this, every end user shares one session id and therefore one
        risk score, and one user's refusal counts against the next user's
        action.

        Closing the derived client is a no-op. The pool belongs to the client
        that opened it, and closing it here would break every other request in
        flight.
        """
        view = object.__new__(ScanClient)
        view._api_key = self._api_key
        view._endpoint = self._endpoint
        view._timeout = self._timeout
        view._session_id = session_id
        view._agent_id = agent_id if agent_id is not None else self._agent_id
        view._http = self._http
        view._owns_http = False
        return view

    def _session_context(self, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Session identity for this client, with any per-call extras merged."""
        return build_session_context(
            extra, session_id=self._session_id, agent_id=self._agent_id
        )

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
        # `context` is the CONVERSATION history, and it belongs in
        # conversation_history — not in `context`, which is where the backend
        # reads session identity from.
        #
        # The backend reads session and agent identity from the ``context``
        # object; a string ``context`` is treated as a source label, not as
        # identity. So the identity travels in ``context`` and the history in
        # ``conversation_history``, the same shape the TypeScript and Go SDKs
        # send.
        payload: Dict[str, Any] = {
            "prompt": prompt,
            "scan_type": "full",
            "context": self._session_context(),
        }
        if context:
            payload["conversation_history"] = context

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

        Known limit: the same session id rides every chunk, so the session
        turn count grows by the number of chunks.
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
            "context": self._session_context(
                {
                    "database": database or "",
                    "allow_destructive": str(allow_destructive),
                }
            ),
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
        payload["context"] = self._session_context(
            {"file_content": content} if content else None
        )

        response = self._http.post(
            f"{self._endpoint}/api/scan/enforce/specialized",
            json=payload,
            headers=get_scan_headers(self._api_key),
        )
        _check_rate_limited(response)
        response.raise_for_status()
        return maybe_add_signup_hint(sanitize_scan_response(response.json()), self._api_key)

    def _scan_specialized(
        self,
        content: str,
        content_type: str,
        label: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Shared transport for the act-plane surfaces.

        Every specialized scan differs only in content type and context.
        Before 4.1.0 each one hand-rolled this block, which is how the SDK
        shipped with six of the eight channels missing: adding one meant
        copying thirty lines. Now it means one method.
        """
        size_result = _check_content_size(content)
        if size_result:
            return size_result

        payload: Dict[str, Any] = {
            "content": content,
            "content_type": content_type,
        }
        payload["context"] = self._session_context(context)

        response = self._http.post(
            f"{self._endpoint}/api/scan/enforce/specialized",
            json=payload,
            headers=get_scan_headers(self._api_key),
        )
        _check_rate_limited(response)
        response.raise_for_status()
        return maybe_add_signup_hint(sanitize_scan_response(response.json()), self._api_key)

    def scan_command(self, command: str, cwd: Optional[str] = None) -> Dict[str, Any]:
        """Scan a shell command before executing it.

        The highest-volume act-plane surface, and one the SDK could not reach
        until 4.1.0. Catches destructive operations, fetch-and-execute chains,
        reverse shells, credential reads, anti-forensics, and SQL injection
        carried inside a database CLI argument (``psql -c "..."``) that the
        command's own grammar cannot see.

        Args:
            command: The command line about to be executed.
            cwd: Optional working directory, for context.

        Returns:
            Scan result dict; check ``safe`` and ``refuse_tier`` before running.
        """
        return self._scan_specialized(
            command, "command", "Command", {"cwd": cwd} if cwd else None
        )

    def scan_web_search(self, query: str) -> Dict[str, Any]:
        """Scan a web search query before it reaches an external engine.

        Catches PII and credentials leaving through a search box, credential
        dorking, evasion tradecraft, illicit acquisition and attack-tool
        acquisition — while leaving ordinary defensive research alone.
        """
        return self._scan_specialized(query, "web_search", "Web search")

    def scan_a2a_message(self, message: str) -> Dict[str, Any]:
        """Scan an agent-to-agent message before acting on it.

        A peer agent's message is untrusted input, whatever the peer claims
        to be.
        """
        return self._scan_specialized(message, "a2a_message", "A2A message")

    def scan_agent_card(self, agent_card: str, verify_signature: bool = False) -> Dict[str, Any]:
        """Scan a remote agent's card before trusting or connecting to it.

        Catches injection and capability spoofing in the metadata a peer
        advertises about itself.
        """
        return self._scan_specialized(
            agent_card,
            "agent_card",
            "Agent card",
            {"verify_signature": "true"} if verify_signature else None,
        )

    def scan_rag_context(
        self, chunks: Any, query: Optional[str] = None
    ) -> Dict[str, Any]:
        """Scan retrieved context before feeding it to the model.

        RAG chunks are untrusted text from documents someone else wrote — the
        standard carrier for indirect prompt injection. Scan on the way in,
        not after the model has acted on them.

        Args:
            chunks: The retrieved chunks, as a string or a list of strings.
            query: Optional user query the chunks were retrieved for.
        """
        content = json.dumps(chunks) if isinstance(chunks, (list, tuple)) else str(chunks)
        return self._scan_specialized(
            content, "rag_context", "RAG context", {"query": query} if query else None
        )

    def scan_mcp_schema(
        self,
        name: str,
        description: str,
        input_schema: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Scan a single MCP tool definition before trusting or registering it.

        Detects tool poisoning: instructions hidden in a tool's own
        ``description``, which an agent reads as guidance and acts on without
        the tool ever executing. Call this on every entry of a ``tools/list``
        response from a server you do not control.

        Args:
            name: The tool name as advertised.
            description: The tool description to screen.
            input_schema: Optional JSON schema; also screened.

        Returns:
            Scan result dict; do not register the tool when ``safe`` is False.
        """
        payload: Dict[str, Any] = {"name": name, "description": description}
        if input_schema:
            payload["input_schema"] = input_schema

        response = self._http.post(
            f"{self._endpoint}/api/scan/mcp_schema",
            json=payload,
            headers=get_scan_headers(self._api_key),
        )
        _check_rate_limited(response)
        response.raise_for_status()
        return maybe_add_signup_hint(sanitize_scan_response(response.json()), self._api_key)

    def declare_scope(
        self,
        agent_id: str,
        allowed_tools: Optional[List[str]] = None,
        purpose: Optional[str] = None,
        forbidden_tools: Optional[List[str]] = None,
        max_duration_seconds: Optional[int] = None,
        expires_at: Optional[str] = None,
        renewable_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Declare (or refresh) the operating scope for a task-scoped agent.

        Once declared, every subsequent scan for this agent_id is enforced
        against the scope on the backend. Tool calls outside allowed_tools
        (or explicitly on forbidden_tools) route to
        refuse_tier="require_approval" with threat_type="scope_violation".
        Expired scopes emit threat_type="scope_expired". Absent a
        declaration, no scope check runs — every existing SDK integration
        is unaffected until it opts in.

        Refreshing: once the scope exists, calling again from the agent's own
        key is a refresh. Every argument left as ``None`` is inherited from
        the scope on file, so ``declare_scope(agent_id, max_duration_seconds=7200)``
        is a complete refresh: the time limit starts again and everything
        else stays as the operator set it. A refresh may narrow but never
        widen (HTTP 403, ``reason: "widening"``), and stops working once the
        operator's renewal window closes (HTTP 403, ``reason: "ceiling_reached"``).

        Args:
            agent_id: The agent identity this scope applies to. Same string
                you'll pass in scan context on subsequent calls.
            allowed_tools: Exact tool names permitted. Pass ``["*"]`` to
                allow any tool. Required on a first declaration; leave
                ``None`` on a refresh to inherit.
            purpose: Optional human-readable description (audit + dashboard).
            forbidden_tools: Tool names explicitly forbidden; wins over
                allowed_tools.
            max_duration_seconds: Optional TTL relative to the latest declaration.
            expires_at: Optional ISO-8601 absolute expiry; the earlier of
                this and max_duration_seconds wins.
            renewable_seconds: Optional renewal window: how long, from the
                operator's grant, this key may keep refreshing the scope.
                Honoured on a first declaration; on a refresh the stored
                value always wins.

        Returns:
            The persisted scope row including scope_id, active_until,
            expired, renewable_until and ceiling_reached.

        Raises:
            httpx.HTTPError: On network failure or non-2xx backend response.
        """
        payload: Dict[str, Any] = {
            "agent_id": agent_id,
        }
        if allowed_tools is not None:
            payload["allowed_tools"] = allowed_tools
        if purpose is not None:
            payload["purpose"] = purpose
        if forbidden_tools is not None:
            payload["forbidden_tools"] = forbidden_tools
        if max_duration_seconds is not None:
            payload["max_duration_seconds"] = max_duration_seconds
        if expires_at is not None:
            payload["expires_at"] = expires_at
        if renewable_seconds is not None:
            payload["renewable_seconds"] = renewable_seconds

        response = self._http.post(
            f"{self._endpoint}/api/v1/agent/scope/declare",
            json=payload,
            headers=get_scan_headers(self._api_key),
        )
        _check_rate_limited(response)
        response.raise_for_status()
        return response.json()

    def close(self) -> None:
        """Close the HTTP client.

        A no-op on a client derived with :meth:`for_session`: that view shares
        the parent's connection pool, and closing it would break every other
        request in flight.
        """
        if self._owns_http:
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
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> None:
        """Initialize the async scan client.

        Args:
            api_key: Shrike API key for authentication.
            endpoint: Shrike API endpoint URL.
            timeout: Request timeout in seconds.
            session_id: The session this client scans under. See
                :class:`ScanClient` — the concern is sharper here, because an
                async server is the deployment most likely to serve many end
                users from one process. Prefer :meth:`for_session` per request.
            agent_id: The agent this client scans as. Defaults to the
                process-wide id (``SHRIKE_AGENT_ID`` when set).
        """
        self._api_key = api_key
        self._endpoint = endpoint.rstrip("/")
        self._timeout = timeout
        self._session_id = session_id
        self._agent_id = agent_id
        self._http = httpx.AsyncClient(timeout=timeout)
        # Only the client that created the pool may close it — see for_session.
        self._owns_http = True

        if not self._api_key:
            logger.warning("[shrike-guard] No API key provided — running in free tier (regex-only).")
            logger.warning("[shrike-guard] For full scanning: npx shrike-mcp --signup")

    def for_session(
        self, session_id: str, agent_id: Optional[str] = None
    ) -> "AsyncScanClient":
        """Return a view of this client that scans under ``session_id``.

        Shares this client's connection pool, so deriving one per request is
        cheap. Build one AsyncScanClient at startup and derive per request::

            guard = AsyncScanClient(api_key=KEY)      # once, at startup

            async def handle(request):                # per request
                scoped = guard.for_session(request.session_id)
                verdict = await scoped.scan_command(request.command)

        Without this, every end user shares one session id and therefore one
        risk score, and one user's refusal counts against the next user's
        action.

        Closing the derived client is a no-op — the pool belongs to the client
        that opened it.
        """
        view = object.__new__(AsyncScanClient)
        view._api_key = self._api_key
        view._endpoint = self._endpoint
        view._timeout = self._timeout
        view._session_id = session_id
        view._agent_id = agent_id if agent_id is not None else self._agent_id
        view._http = self._http
        view._owns_http = False
        return view

    def _session_context(self, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Session identity for this client, with any per-call extras merged."""
        return build_session_context(
            extra, session_id=self._session_id, agent_id=self._agent_id
        )

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
        # `context` is the CONVERSATION history, and it belongs in
        # conversation_history — not in `context`, which is where the backend
        # reads session identity from.
        #
        # The backend reads session and agent identity from the ``context``
        # object; a string ``context`` is treated as a source label, not as
        # identity. So the identity travels in ``context`` and the history in
        # ``conversation_history``, the same shape the TypeScript and Go SDKs
        # send.
        payload: Dict[str, Any] = {
            "prompt": prompt,
            "scan_type": "full",
            "context": self._session_context(),
        }
        if context:
            payload["conversation_history"] = context

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
            "context": self._session_context(
                {
                    "database": database or "",
                    "allow_destructive": str(allow_destructive),
                }
            ),
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
        payload["context"] = self._session_context(
            {"file_content": content} if content else None
        )

        response = await self._http.post(
            f"{self._endpoint}/api/scan/enforce/specialized",
            json=payload,
            headers=get_scan_headers(self._api_key),
        )
        _check_rate_limited(response)
        response.raise_for_status()
        return maybe_add_signup_hint(sanitize_scan_response(response.json()), self._api_key)

    async def _scan_specialized(
        self,
        content: str,
        content_type: str,
        label: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Async twin of :meth:`ScanClient._scan_specialized`."""
        size_result = _check_content_size(content)
        if size_result:
            return size_result

        payload: Dict[str, Any] = {
            "content": content,
            "content_type": content_type,
        }
        payload["context"] = self._session_context(context)

        response = await self._http.post(
            f"{self._endpoint}/api/scan/enforce/specialized",
            json=payload,
            headers=get_scan_headers(self._api_key),
        )
        _check_rate_limited(response)
        response.raise_for_status()
        return maybe_add_signup_hint(sanitize_scan_response(response.json()), self._api_key)

    async def scan_command(self, command: str, cwd: Optional[str] = None) -> Dict[str, Any]:
        """Scan a shell command before executing it.

        Async twin of :meth:`ScanClient.scan_command`.
        """
        return await self._scan_specialized(
            command, "command", "Command", {"cwd": cwd} if cwd else None
        )

    async def scan_web_search(self, query: str) -> Dict[str, Any]:
        """Scan a web search query. Async twin of :meth:`ScanClient.scan_web_search`."""
        return await self._scan_specialized(query, "web_search", "Web search")

    async def scan_a2a_message(self, message: str) -> Dict[str, Any]:
        """Scan an agent-to-agent message. Async twin of :meth:`ScanClient.scan_a2a_message`."""
        return await self._scan_specialized(message, "a2a_message", "A2A message")

    async def scan_agent_card(
        self, agent_card: str, verify_signature: bool = False
    ) -> Dict[str, Any]:
        """Scan a remote agent card. Async twin of :meth:`ScanClient.scan_agent_card`."""
        return await self._scan_specialized(
            agent_card,
            "agent_card",
            "Agent card",
            {"verify_signature": "true"} if verify_signature else None,
        )

    async def scan_rag_context(
        self, chunks: Any, query: Optional[str] = None
    ) -> Dict[str, Any]:
        """Scan retrieved context. Async twin of :meth:`ScanClient.scan_rag_context`."""
        content = json.dumps(chunks) if isinstance(chunks, (list, tuple)) else str(chunks)
        return await self._scan_specialized(
            content, "rag_context", "RAG context", {"query": query} if query else None
        )

    async def scan_mcp_schema(
        self,
        name: str,
        description: str,
        input_schema: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Scan an MCP tool definition. Async twin of :meth:`ScanClient.scan_mcp_schema`."""
        payload: Dict[str, Any] = {"name": name, "description": description}
        if input_schema:
            payload["input_schema"] = input_schema

        response = await self._http.post(
            f"{self._endpoint}/api/scan/mcp_schema",
            json=payload,
            headers=get_scan_headers(self._api_key),
        )
        _check_rate_limited(response)
        response.raise_for_status()
        return maybe_add_signup_hint(sanitize_scan_response(response.json()), self._api_key)

    async def declare_scope(
        self,
        agent_id: str,
        allowed_tools: Optional[List[str]] = None,
        purpose: Optional[str] = None,
        forbidden_tools: Optional[List[str]] = None,
        max_duration_seconds: Optional[int] = None,
        expires_at: Optional[str] = None,
        renewable_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Declare (or refresh) the operating scope for a task-scoped agent.

        Async twin of :meth:`ScanClient.declare_scope`. Same wire contract,
        including refresh-by-inheritance and the renewal window.
        """
        payload: Dict[str, Any] = {
            "agent_id": agent_id,
        }
        if allowed_tools is not None:
            payload["allowed_tools"] = allowed_tools
        if purpose is not None:
            payload["purpose"] = purpose
        if forbidden_tools is not None:
            payload["forbidden_tools"] = forbidden_tools
        if max_duration_seconds is not None:
            payload["max_duration_seconds"] = max_duration_seconds
        if expires_at is not None:
            payload["expires_at"] = expires_at
        if renewable_seconds is not None:
            payload["renewable_seconds"] = renewable_seconds

        response = await self._http.post(
            f"{self._endpoint}/api/v1/agent/scope/declare",
            json=payload,
            headers=get_scan_headers(self._api_key),
        )
        _check_rate_limited(response)
        response.raise_for_status()
        return response.json()

    async def close(self) -> None:
        """Close the HTTP client.

        A no-op on a client derived with :meth:`for_session`: that view shares
        the parent's connection pool, and closing it would break every other
        request in flight.
        """
        if self._owns_http:
            await self._http.aclose()

    async def __aenter__(self) -> "AsyncScanClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()
