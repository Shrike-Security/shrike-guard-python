"""HTTP client for the Shrike scan API."""

import uuid
from typing import Any, Dict, Optional

import httpx

from ._version import __version__
from .config import DEFAULT_ENDPOINT, DEFAULT_SCAN_TIMEOUT, SDK_NAME
from .sanitizer import sanitize_scan_response

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

        payload: Dict[str, Any] = {"prompt": prompt}
        if context:
            payload["context"] = context

        response = self._http.post(
            f"{self._endpoint}/scan",
            json=payload,
            headers=get_scan_headers(self._api_key),
        )
        response.raise_for_status()
        return sanitize_scan_response(response.json())

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
            f"{self._endpoint}/api/scan/specialized",
            json=payload,
            headers=get_scan_headers(self._api_key),
        )
        response.raise_for_status()
        return sanitize_scan_response(response.json())

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
            f"{self._endpoint}/api/scan/specialized",
            json=payload,
            headers=get_scan_headers(self._api_key),
        )
        response.raise_for_status()
        return sanitize_scan_response(response.json())

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

        payload: Dict[str, Any] = {"prompt": prompt}
        if context:
            payload["context"] = context

        response = await self._http.post(
            f"{self._endpoint}/scan",
            json=payload,
            headers=get_scan_headers(self._api_key),
        )
        response.raise_for_status()
        return sanitize_scan_response(response.json())

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
            f"{self._endpoint}/api/scan/specialized",
            json=payload,
            headers=get_scan_headers(self._api_key),
        )
        response.raise_for_status()
        return sanitize_scan_response(response.json())

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
            f"{self._endpoint}/api/scan/specialized",
            json=payload,
            headers=get_scan_headers(self._api_key),
        )
        response.raise_for_status()
        return sanitize_scan_response(response.json())

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._http.aclose()

    async def __aenter__(self) -> "AsyncScanClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()
