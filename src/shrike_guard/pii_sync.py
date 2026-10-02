"""PII Pattern Sync — fetches canonical PII patterns from the Shrike backend
at startup and updates the client-side redactor so detection coverage matches
the backend's canonical set.

On any failure (network, timeout, malformed response, unrecognized threat
type) the function logs a warning and keeps the hardcoded bootstrap patterns.
Pattern sync is a quality feature, NOT a security boundary — failing closed
on it would block legitimate scans.

Mirrors mcp/src/utils/piiSync.ts to keep client-side coverage uniform across
MCP server, Python SDK, TS SDK, and Go SDK.

Uses httpx (already a hard SDK dep) to keep HTTP behavior consistent with
the rest of the Python SDK and to inherit certifi's bundled root certs
(the Python.org macOS installer ships an empty cert store, which would
break stdlib urllib).
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, Final, List, Optional

import httpx

from .pii_redactor import PIIPattern, get_pii_pattern_count, update_pii_patterns

logger = logging.getLogger(__name__)

DEFAULT_SYNC_TIMEOUT: Final[float] = 5.0


def _threat_type_to_name(threat_type: str) -> str:
    """`pii_credit_card` → `credit_card` for the RedactionEntry.type field."""
    return threat_type[4:] if threat_type.startswith("pii_") else threat_type


def _fallback_prefix_for(threat_type: str) -> str:
    """Derive a client-side redaction prefix from a threat_type when the
    backend ships without one. Mirrors the backend's ``derivePIIPrefix()``
    in ``pii_handler.go`` and the MCP + TS SDK equivalents — strip ``pii_``
    and uppercase. Never returns empty: unknown threat_types become their
    own uppercase tag (e.g. ``pii_wallet_eth`` → ``WALLET_ETH``).

    Retired ``_PREFIX_MAP`` in favor of this + backend-shipped prefixes
    because the hardcoded allowlist silently dropped any new pattern the
    backend added. Now no
    threat_type ever disappears and adding a new backend pattern requires
    zero SDK changes.
    """
    stripped = threat_type[4:] if threat_type.startswith("pii_") else threat_type
    return stripped.upper() or "PII"


def _compile_regex(pattern_str: str) -> Optional[re.Pattern[str]]:
    """Compile a backend regex into a Python re.Pattern.

    Backend patterns are authored lowercase without a `(?i)` inline flag —
    the convention is "match case-insensitively on the client side". The
    MCP TypeScript sync enforces this with the `'gi'` constructor flag; we
    mirror that by compiling every backend pattern with `re.IGNORECASE` so
    SDK detection coverage matches MCP byte-for-byte.

    Anything that fails compilation is skipped (caller logs + keeps going).
    """
    try:
        return re.compile(pattern_str, re.IGNORECASE)
    except re.error:
        return None


def _convert_patterns(
    raw_patterns: List[Dict[str, Any]],
    fallback_count: int,
) -> Optional[List[PIIPattern]]:
    """Convert the backend response into PIIPattern entries.

    Returns None when the backend gave us nothing applicable (caller keeps
    the bootstrap patterns). Otherwise returns the sorted list, ready to
    pass to update_pii_patterns.
    """
    converted: List[PIIPattern] = []
    confidence_by_name: Dict[str, float] = {}
    derived_fallback_count = 0

    for entry in raw_patterns:
        if not isinstance(entry, dict):
            continue
        threat_type = entry.get("threat_type")
        pattern_str = entry.get("pattern")
        if not isinstance(threat_type, str) or not isinstance(pattern_str, str):
            continue

        # Backend is the source of truth for the redaction tag. If it ships
        # a `prefix` field (backends as of July 2026 and later), use it
        # verbatim. If not, derive locally so no pattern is ever silently
        # dropped — that's the whole point of retiring _PREFIX_MAP.
        prefix_raw = entry.get("prefix")
        if isinstance(prefix_raw, str) and prefix_raw:
            prefix = prefix_raw
        else:
            prefix = _fallback_prefix_for(threat_type)
            derived_fallback_count += 1

        regex = _compile_regex(pattern_str)
        if regex is None:
            logger.warning("PII pattern sync: skipping unparseable pattern for %s", threat_type)
            continue

        name = _threat_type_to_name(threat_type)
        confidence_raw = entry.get("confidence", 0)
        try:
            confidence = float(confidence_raw)
        except (TypeError, ValueError):
            confidence = 0.0

        confidence_by_name[name] = max(confidence_by_name.get(name, 0.0), confidence)
        converted.append(PIIPattern(name=name, regex=regex, prefix=prefix))

    if derived_fallback_count > 0:
        # Not an error — expected for older backends. Log so operators can
        # see if a backend upgrade would give them explicit prefixes.
        logger.info(
            "PII pattern sync: %d/%d patterns used locally-derived prefix "
            "(backend older than 2026-07-02)",
            derived_fallback_count,
            len(raw_patterns),
        )

    if not converted:
        logger.warning(
            "PII pattern sync: all %d backend patterns failed conversion; keeping %d fallback",
            len(raw_patterns),
            fallback_count,
        )
        return None

    # Higher confidence first so more specific patterns win the redact_pii()
    # document-order dedup.
    converted.sort(key=lambda p: confidence_by_name.get(p.name, 0.0), reverse=True)
    return converted


def sync_pii_patterns(
    endpoint: str,
    api_key: Optional[str] = None,
    timeout: float = DEFAULT_SYNC_TIMEOUT,
    *,
    client: Optional[httpx.Client] = None,
) -> bool:
    """Fetch canonical PII patterns from the Shrike backend and apply them locally.

    Args:
        endpoint: Backend base URL (e.g. ``https://api.shrikesecurity.com``).
                  The function appends ``/api/pii/patterns``.
        api_key: Optional API key. Sent as ``Authorization: Bearer <key>`` when
                 provided. The endpoint is currently unauthenticated, but
                 sending the key is forward-compatible.
        timeout: Network timeout in seconds. Default 5s. Ignored when an
                 explicit ``client`` is provided.
        client: Optional ``httpx.Client`` — lets callers inject a custom
                client (custom transports, instrumented round-trippers,
                MockTransport in tests). When omitted, a short-lived client
                is created with ``timeout``.

    Returns:
        True if patterns were updated. False if anything failed and the
        bootstrap patterns were preserved.

    This function never raises. Sync is a quality feature, not a security
    boundary — failing to reach the backend should not block scans.
    """
    fallback_count = get_pii_pattern_count()
    url = endpoint.rstrip("/") + "/api/pii/patterns"

    headers: Dict[str, str] = {"Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    owns_client = client is None
    http_client = client if client is not None else httpx.Client(timeout=timeout)

    try:
        try:
            response = http_client.get(url, headers=headers)
        except httpx.TimeoutException:
            logger.warning(
                "PII pattern sync timed out; keeping %d fallback patterns", fallback_count
            )
            return False
        except httpx.HTTPError as exc:
            logger.warning(
                "PII pattern sync failed (%s); keeping %d fallback patterns",
                type(exc).__name__,
                fallback_count,
            )
            return False

        if response.status_code != 200:
            logger.warning(
                "PII pattern sync: backend returned %d; keeping %d fallback patterns",
                response.status_code,
                fallback_count,
            )
            return False

        try:
            data: Dict[str, Any] = response.json()
        except ValueError:
            logger.warning(
                "PII pattern sync: malformed JSON; keeping %d fallback patterns",
                fallback_count,
            )
            return False
    finally:
        if owns_client:
            http_client.close()

    raw_patterns = data.get("patterns") or []
    if not raw_patterns:
        logger.warning(
            "PII pattern sync: backend returned 0 patterns; keeping %d fallback patterns",
            fallback_count,
        )
        return False

    converted = _convert_patterns(raw_patterns, fallback_count)
    if converted is None:
        return False

    update_pii_patterns(converted)
    version = data.get("version", "unknown")
    logger.info(
        "PII pattern sync: applied %d patterns from backend (was %d), version=%s",
        len(converted),
        fallback_count,
        version,
    )
    return True
