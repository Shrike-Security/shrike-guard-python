"""Shrike-protected Google Gemini client wrapper.

Supports both the new google.genai SDK (recommended) and the legacy
google.generativeai SDK for backwards compatibility.
"""

import logging
from typing import Any, Dict, List, Optional, Union

import httpx

from .config import DEFAULT_ENDPOINT, DEFAULT_FAIL_MODE, DEFAULT_SCAN_TIMEOUT, FailMode
from .exceptions import ShrikeBlockedError, ShrikeScanError
from .sanitizer import sanitize_scan_response
from .scanner import get_scan_headers

logger = logging.getLogger("shrike-guard")

# Try the new google.genai SDK first (recommended)
try:
    from google import genai
    from google.genai.types import GenerateContentResponse
    GENAI_NEW_AVAILABLE = True
except ImportError:
    GENAI_NEW_AVAILABLE = False
    genai = None  # type: ignore
    GenerateContentResponse = None  # type: ignore

# Fall back to legacy google.generativeai SDK
GENAI_LEGACY_AVAILABLE = False
genai_legacy = None
if not GENAI_NEW_AVAILABLE:
    try:
        import google.generativeai as genai_legacy
        from google.generativeai.types import GenerateContentResponse as LegacyResponse
        GENAI_LEGACY_AVAILABLE = True
        GenerateContentResponse = LegacyResponse  # type: ignore
    except ImportError:
        pass


class ShrikeGemini:
    """Shrike-protected wrapper for Google's Generative AI (Gemini).

    Intercepts all generate_content() calls to scan prompts before
    they reach Gemini.

    Example:
        from shrike_guard import ShrikeGemini

        client = ShrikeGemini(
            api_key="AIza...",
            shrike_api_key="shrike-...",
        )

        # Get a protected model
        model = client.GenerativeModel("gemini-2.5-flash")

        response = model.generate_content("Hello!")
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        shrike_api_key: Optional[str] = None,
        shrike_endpoint: str = DEFAULT_ENDPOINT,
        fail_mode: Union[str, FailMode] = DEFAULT_FAIL_MODE,
        scan_timeout: float = DEFAULT_SCAN_TIMEOUT,
    ) -> None:
        """Initialize the Shrike-protected Gemini client.

        Args:
            api_key: Google AI API key
            shrike_api_key: Shrike API key for authentication
            shrike_endpoint: Shrike backend URL
            fail_mode: "open" (allow on scan failure) or "closed" (block on failure)
            scan_timeout: Timeout for scan requests in seconds
        """
        if not GENAI_NEW_AVAILABLE and not GENAI_LEGACY_AVAILABLE:
            raise ImportError(
                "Neither google-genai nor google-generativeai package is installed. "
                "Install with: pip install google-genai"
            )

        self._api_key = api_key
        self._use_new_sdk = GENAI_NEW_AVAILABLE

        # Initialize the appropriate SDK
        if self._use_new_sdk:
            self._client = genai.Client(api_key=api_key)
        else:
            # Legacy SDK uses global configuration
            if api_key:
                genai_legacy.configure(api_key=api_key)
            self._client = None

        self._shrike_endpoint = shrike_endpoint.rstrip("/")
        self._shrike_api_key = shrike_api_key or ""
        self._fail_mode = FailMode(fail_mode) if isinstance(fail_mode, str) else fail_mode
        self._scan_timeout = scan_timeout
        self._http = httpx.Client(timeout=scan_timeout)

        # Note: All scanning is done via backend API (tier-based: free=L1-L4, paid=L1-L8)
        # No local scanning - backend has full regex patterns (~50+) and normalizers

    def GenerativeModel(
        self,
        model_name: str,
        **kwargs: Any,
    ) -> "_ShrikeGenerativeModel":
        """Create a Shrike-protected GenerativeModel.

        Args:
            model_name: The Gemini model to use (e.g., "gemini-2.5-flash")
            **kwargs: Additional arguments passed to the model

        Returns:
            A wrapped GenerativeModel with Shrike protection
        """
        return _ShrikeGenerativeModel(
            model_name=model_name,
            shrike_client=self,
            **kwargs,
        )

    def _extract_content(self, contents: Any) -> str:
        """Extract text content from various input formats.

        Gemini accepts:
        - str: Simple text
        - list: Multiple parts
        - dict: Content with parts
        """
        if isinstance(contents, str):
            return contents

        if isinstance(contents, list):
            texts = []
            for item in contents:
                if isinstance(item, str):
                    texts.append(item)
                elif isinstance(item, dict):
                    # Handle content parts
                    if "text" in item:
                        texts.append(item["text"])
                    elif "parts" in item:
                        for part in item["parts"]:
                            if isinstance(part, str):
                                texts.append(part)
                            elif isinstance(part, dict) and "text" in part:
                                texts.append(part["text"])
            return "\n".join(texts)

        if isinstance(contents, dict):
            if "text" in contents:
                return contents["text"]
            if "parts" in contents:
                return self._extract_content(contents["parts"])

        return str(contents)

    def _scan_content(self, contents: Any) -> Dict[str, Any]:
        """Scan content via backend API.

        Always calls backend - backend handles tier-based scanning:
        - Free tier (no API key): L1-L4 (regex, unicode, encoding, token normalization)
        - Paid tier: L1-L8 (full scan including LLM)
        """
        text_content = self._extract_content(contents)

        if not text_content.strip():
            return {"safe": True, "reason": "No text content to scan"}

        # Always call backend API - tier detection happens server-side
        return self._remote_scan(text_content)

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

    def __enter__(self) -> "ShrikeGemini":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


class _ShrikeGenerativeModel:
    """Wrapped GenerativeModel with Shrike protection."""

    def __init__(
        self,
        model_name: str,
        shrike_client: ShrikeGemini,
        **kwargs: Any,
    ) -> None:
        self._model_name = model_name
        self._shrike_client = shrike_client
        self._kwargs = kwargs

    def generate_content(
        self,
        contents: Any,
        stream: bool = False,
        **kwargs: Any,
    ) -> Any:
        """Generate content with Shrike protection.

        Scans the input before sending to Gemini.
        Raises ShrikeBlockedError if threats are detected.

        Args:
            contents: The content to generate from
            stream: Whether to stream the response
            **kwargs: Additional arguments passed to Gemini API

        Returns:
            GenerateContentResponse or iterator of response chunks if streaming
        """
        # 1. Scan content BEFORE streaming starts
        scan_result = self._shrike_client._scan_content(contents)

        # 2. Block if unsafe
        if not scan_result.get("safe", True):
            raise ShrikeBlockedError(
                message=scan_result.get("reason", "Request blocked by Shrike"),
                threat_type=scan_result.get("threat_type"),
                confidence=scan_result.get("confidence"),
            )

        # 3. Proxy to Gemini
        if self._shrike_client._use_new_sdk:
            # New google.genai SDK
            if stream:
                return self._shrike_client._client.models.generate_content_stream(
                    model=self._model_name,
                    contents=contents,
                    **kwargs,
                )
            return self._shrike_client._client.models.generate_content(
                model=self._model_name,
                contents=contents,
                **kwargs,
            )
        else:
            # Legacy google.generativeai SDK
            model = genai_legacy.GenerativeModel(self._model_name, **self._kwargs)
            return model.generate_content(contents, stream=stream, **kwargs)

    def generate_content_stream(
        self,
        contents: Any,
        **kwargs: Any,
    ) -> Any:
        """Stream content generation with Shrike protection.

        Alternative streaming API. Scans the input before streaming starts.
        Raises ShrikeBlockedError if threats are detected.

        Returns:
            Iterator of response chunks
        """
        return self.generate_content(contents, stream=True, **kwargs)

    async def generate_content_async(
        self,
        contents: Any,
        **kwargs: Any,
    ) -> Any:
        """Async generate content with Shrike protection."""
        # 1. Scan content (sync - scanning should be fast)
        scan_result = self._shrike_client._scan_content(contents)

        # 2. Block if unsafe
        if not scan_result.get("safe", True):
            raise ShrikeBlockedError(
                message=scan_result.get("reason", "Request blocked by Shrike"),
                threat_type=scan_result.get("threat_type"),
                confidence=scan_result.get("confidence"),
            )

        # 3. Proxy to Gemini
        if self._shrike_client._use_new_sdk:
            # New SDK - use async method
            return await self._shrike_client._client.aio.models.generate_content(
                model=self._model_name,
                contents=contents,
                **kwargs,
            )
        else:
            # Legacy SDK
            model = genai_legacy.GenerativeModel(self._model_name, **self._kwargs)
            return await model.generate_content_async(contents, **kwargs)

    def start_chat(self, **kwargs: Any) -> "_ShrikeChatSession":
        """Start a chat session with Shrike protection."""
        if self._shrike_client._use_new_sdk:
            # New SDK uses chats API
            chat = self._shrike_client._client.chats.create(
                model=self._model_name,
                **kwargs,
            )
        else:
            # Legacy SDK
            model = genai_legacy.GenerativeModel(self._model_name, **self._kwargs)
            chat = model.start_chat(**kwargs)

        return _ShrikeChatSession(
            chat=chat,
            shrike_client=self._shrike_client,
        )

    @property
    def model_name(self) -> str:
        return self._model_name


class _ShrikeChatSession:
    """Wrapped chat session with Shrike protection."""

    def __init__(
        self,
        chat: Any,
        shrike_client: ShrikeGemini,
    ) -> None:
        self._chat = chat
        self._shrike_client = shrike_client

    def send_message(
        self,
        content: Any,
        **kwargs: Any,
    ) -> Any:
        """Send a message with Shrike protection."""
        # 1. Scan content
        scan_result = self._shrike_client._scan_content(content)

        # 2. Block if unsafe
        if not scan_result.get("safe", True):
            raise ShrikeBlockedError(
                message=scan_result.get("reason", "Request blocked by Shrike"),
                threat_type=scan_result.get("threat_type"),
                confidence=scan_result.get("confidence"),
            )

        # 3. Proxy to Gemini
        return self._chat.send_message(content, **kwargs)

    async def send_message_async(
        self,
        content: Any,
        **kwargs: Any,
    ) -> Any:
        """Async send a message with Shrike protection."""
        # 1. Scan content
        scan_result = self._shrike_client._scan_content(content)

        # 2. Block if unsafe
        if not scan_result.get("safe", True):
            raise ShrikeBlockedError(
                message=scan_result.get("reason", "Request blocked by Shrike"),
                threat_type=scan_result.get("threat_type"),
                confidence=scan_result.get("confidence"),
            )

        # 3. Proxy to Gemini
        if hasattr(self._chat, 'send_message_async'):
            return await self._chat.send_message_async(content, **kwargs)
        else:
            # New SDK might use different async pattern
            return self._chat.send_message(content, **kwargs)

    @property
    def history(self) -> List[Any]:
        return self._chat.history if hasattr(self._chat, 'history') else []
