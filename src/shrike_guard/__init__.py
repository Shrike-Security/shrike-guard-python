"""Shrike Guard - Security SDK for LLM applications.

Shrike Guard provides drop-in replacements for popular LLM clients
that automatically scan all prompts for security threats before sending
them to the LLM.

Supported Providers:
    - OpenAI (GPT-4, GPT-3.5, etc.)
    - Anthropic Claude (Claude 3, etc.)
    - Google Gemini (Gemini Pro, Gemini Flash, etc.)

Quick Start (OpenAI):
    >>> from shrike_guard import ShrikeOpenAI
    >>> client = ShrikeOpenAI(
    ...     api_key="sk-...",
    ...     shrike_api_key="shrike-..."
    ... )
    >>> response = client.chat.completions.create(
    ...     model="gpt-4",
    ...     messages=[{"role": "user", "content": "Hello!"}]
    ... )

Claude:
    >>> from shrike_guard import ShrikeAnthropic
    >>> client = ShrikeAnthropic(
    ...     api_key="sk-ant-...",
    ...     shrike_api_key="shrike-..."
    ... )
    >>> response = client.messages.create(
    ...     model="claude-3-opus-20240229",
    ...     max_tokens=1024,
    ...     messages=[{"role": "user", "content": "Hello!"}]
    ... )

Gemini:
    >>> from shrike_guard import ShrikeGemini
    >>> client = ShrikeGemini(
    ...     api_key="AIza...",
    ...     shrike_api_key="shrike-..."
    ... )
    >>> model = client.GenerativeModel("gemini-pro")
    >>> response = model.generate_content("Hello!")

Configuration:
    - fail_mode="open" (default): Allow requests on scan failure
    - fail_mode="closed": Block requests on scan failure
    - scan_timeout: Timeout for scan requests (default: 2.0 seconds)

For more information, see: https://docs.shrike.security/sdk/python
"""

from .async_client import ShrikeAsyncOpenAI
from .client import ShrikeOpenAI
from .config import DEFAULT_ENDPOINT, DEFAULT_FAIL_MODE, DEFAULT_SCAN_TIMEOUT, FailMode
from .exceptions import (
    ShrikeBlockedError,
    ShrikeConfigError,
    ShrikeError,
    ShrikeScanError,
)
from .scanner import AsyncScanClient, ScanClient, get_scan_headers
from .sanitizer import sanitize_scan_response, normalize_threat_type, bucket_confidence, derive_severity
from ._version import __version__, __version_info__

# Optional provider imports (available when dependencies are installed)
try:
    from .anthropic_client import ShrikeAnthropic, ShrikeAsyncAnthropic
    _ANTHROPIC_AVAILABLE = True
except ImportError:
    _ANTHROPIC_AVAILABLE = False
    ShrikeAnthropic = None  # type: ignore
    ShrikeAsyncAnthropic = None  # type: ignore

try:
    from .gemini_client import ShrikeGemini
    _GEMINI_AVAILABLE = True
except ImportError:
    _GEMINI_AVAILABLE = False
    ShrikeGemini = None  # type: ignore

__all__ = [
    # OpenAI clients
    "ShrikeOpenAI",
    "ShrikeAsyncOpenAI",
    # Anthropic clients (requires: pip install shrike-guard[anthropic])
    "ShrikeAnthropic",
    "ShrikeAsyncAnthropic",
    # Gemini client (requires: pip install shrike-guard[gemini])
    "ShrikeGemini",
    # Low-level scan clients
    "ScanClient",
    "AsyncScanClient",
    "get_scan_headers",
    # Sanitizer
    "sanitize_scan_response",
    "normalize_threat_type",
    "bucket_confidence",
    "derive_severity",
    # Configuration
    "FailMode",
    "DEFAULT_ENDPOINT",
    "DEFAULT_FAIL_MODE",
    "DEFAULT_SCAN_TIMEOUT",
    # Exceptions
    "ShrikeError",
    "ShrikeScanError",
    "ShrikeBlockedError",
    "ShrikeConfigError",
    # Version
    "__version__",
    "__version_info__",
]
