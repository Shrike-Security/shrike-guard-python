"""PII Redactor — client-side PII redaction and rehydration.

Detects PII in text, replaces with indexed tokens, and provides a reversible
map for rehydration after LLM processing. PII never leaves the caller's
process — neither the backend nor the downstream LLM sees raw PII.

Ported from the MCP server's piiRedactor.ts (the canonical, roundtrip-tested
implementation).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Pattern


@dataclass(frozen=True)
class PIIPattern:
    name: str
    regex: Pattern[str]
    prefix: str


@dataclass(frozen=True)
class RedactionEntry:
    token: str       # "[EMAIL_1]"
    original: str    # "john@acme.com"
    type: str        # "email"
    position: int    # char offset in original text


@dataclass(frozen=True)
class RedactionResult:
    redacted_text: str
    redactions: List[RedactionEntry]
    pii_detected: bool
    redaction_count: int


# Default PII patterns (fallback when backend is unreachable).
# Order matters: more specific patterns first to avoid partial matches.
_DEFAULT_PATTERNS: List[PIIPattern] = [
    # AWS keys (very specific, check first)
    PIIPattern(
        name="aws_key",
        regex=re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        prefix="AWSKEY",
    ),
    # Private keys
    PIIPattern(
        name="private_key",
        regex=re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
        prefix="PRIVKEY",
    ),
    # Credit card numbers (Visa, MC, Amex, Discover) with optional hyphens/spaces
    PIIPattern(
        name="credit_card",
        regex=re.compile(
            r"\b(?:"
            r"4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|"
            r"5[1-5][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|"
            r"3[47][0-9]{2}[-\s]?[0-9]{6}[-\s]?[0-9]{5}|"
            r"6(?:011|5[0-9]{2})[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}"
            r")\b"
        ),
        prefix="CARD",
    ),
    # SSN (US)
    PIIPattern(
        name="ssn",
        regex=re.compile(r"\b\d{3}-?\d{2}-?\d{4}\b"),
        prefix="SSN",
    ),
    # Email addresses
    PIIPattern(
        name="email",
        regex=re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        prefix="EMAIL",
    ),
    # Phone numbers (US/International)
    PIIPattern(
        name="phone",
        regex=re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        prefix="PHONE",
    ),
    # API keys (generic)
    PIIPattern(
        name="api_key",
        regex=re.compile(
            r"\b(?:api[_-]?key|apikey|access[_-]?token)[:\s=]+[A-Za-z0-9_\-]{20,}\b",
            re.IGNORECASE,
        ),
        prefix="APIKEY",
    ),
    # Medical record numbers
    PIIPattern(
        name="medical_record",
        regex=re.compile(r"\b(?:MRN|Medical Record)[:\s#]*[A-Z0-9]{6,12}\b", re.IGNORECASE),
        prefix="MRN",
    ),
    # Date of birth
    PIIPattern(
        name="dob",
        regex=re.compile(
            r"\b(?:DOB|D\.O\.B\.|Date of Birth|Birth Date)[:\s]+"
            r"(?:\d{1,2}[-/]\d{1,2}[-/]\d{2,4}|\d{4}[-/]\d{1,2}[-/]\d{1,2})\b",
            re.IGNORECASE,
        ),
        prefix="DOB",
    ),
    # Bank account numbers
    PIIPattern(
        name="bank_account",
        regex=re.compile(r"\b(?:Account|Acct)[:\s#]*\d{8,17}\b", re.IGNORECASE),
        prefix="ACCOUNT",
    ),
    # Routing numbers (US - 9 digits)
    PIIPattern(
        name="routing_number",
        regex=re.compile(r"\b(?:Routing|ABA)[:\s#]*\d{9}\b", re.IGNORECASE),
        prefix="ROUTING",
    ),
    # IP addresses
    PIIPattern(
        name="ip_address",
        regex=re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        prefix="IP",
    ),
    # Street addresses (simple pattern)
    PIIPattern(
        name="address",
        regex=re.compile(
            r"\b\d+\s+[A-Za-z0-9\s]+(?:Street|St|Avenue|Ave|Road|Rd|"
            r"Boulevard|Blvd|Lane|Ln|Drive|Dr)\b",
            re.IGNORECASE,
        ),
        prefix="ADDR",
    ),
]

_active_patterns: List[PIIPattern] = list(_DEFAULT_PATTERNS)


def redact_pii(text: str) -> RedactionResult:
    """Redact PII from text, replacing with indexed tokens.

    Example:
        >>> r = redact_pii("Email john@acme.com and jane@acme.com about Q4")
        >>> r.redacted_text
        'Email [EMAIL_1] and [EMAIL_2] about Q4'
    """
    matches: List[Dict[str, object]] = []
    for pattern in _active_patterns:
        for m in pattern.regex.finditer(text):
            matches.append({
                "start": m.start(),
                "end": m.end(),
                "original": m.group(0),
                "pattern": pattern,
            })

    # Sort ascending by position for dedup + token numbering
    matches.sort(key=lambda m: m["start"])  # type: ignore[arg-type, return-value]

    # Deduplicate overlapping matches (keep the earlier/first match)
    filtered: List[Dict[str, object]] = []
    for m in matches:
        overlaps = any(
            m["start"] < existing["end"] and m["end"] > existing["start"]  # type: ignore[operator]
            for existing in filtered
        )
        if not overlaps:
            filtered.append(m)

    # Assign token numbers in document order
    counters: Dict[str, int] = {}
    tokens: List[str] = []
    for m in filtered:
        pattern: PIIPattern = m["pattern"]  # type: ignore[assignment]
        counters[pattern.prefix] = counters.get(pattern.prefix, 0) + 1
        tokens.append(f"[{pattern.prefix}_{counters[pattern.prefix]}]")

    # Replace from end to start to preserve earlier positions
    redacted_text = text
    redactions_reversed: List[RedactionEntry] = []
    for m, token in zip(reversed(filtered), reversed(tokens)):
        pattern = m["pattern"]  # type: ignore[assignment]
        redactions_reversed.append(RedactionEntry(
            token=token,
            original=m["original"],  # type: ignore[arg-type]
            type=pattern.name,
            position=m["start"],  # type: ignore[arg-type]
        ))
        redacted_text = (
            redacted_text[: m["start"]] + token + redacted_text[m["end"]:]  # type: ignore[index]
        )

    # Return in document order
    redactions = list(reversed(redactions_reversed))

    return RedactionResult(
        redacted_text=redacted_text,
        redactions=redactions,
        pii_detected=len(redactions) > 0,
        redaction_count=len(redactions),
    )


def rehydrate_pii(text: str, redactions: List[RedactionEntry]) -> str:
    """Rehydrate text by replacing indexed tokens with original PII values.

    Replaces ALL occurrences of each token (LLM may repeat tokens in output).

    Example:
        >>> redactions = [RedactionEntry("[EMAIL_1]", "john@acme.com", "email", 8)]
        >>> rehydrate_pii("Email sent to [EMAIL_1].", redactions)
        'Email sent to john@acme.com.'
    """
    result = text
    for entry in redactions:
        result = result.replace(entry.token, entry.original)
    return result


def get_redaction_summary(redactions: List[RedactionEntry]) -> Dict[str, int]:
    """Summarize redactions by type (no raw PII values). Safe for logging."""
    summary: Dict[str, int] = {}
    for entry in redactions:
        summary[entry.type] = summary.get(entry.type, 0) + 1
    return summary


def update_pii_patterns(patterns: List[PIIPattern]) -> None:
    """Replace the active PII patterns (e.g. with a backend-fetched canonical set)."""
    global _active_patterns
    _active_patterns = list(patterns)


def get_pii_pattern_count() -> int:
    """Return the current number of active PII patterns."""
    return len(_active_patterns)
