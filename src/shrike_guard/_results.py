"""Shared constructor for SDK-side fail-open verdicts.

Centralized so every wrapper builds the fail-open result identically. Prior to
this, the ``degraded`` marker was added inline per call-site and had drifted —
only the circuit-breaker path carried it, while timeout / backend-error
fail-open paths (and the Anthropic/Gemini wrappers entirely) allowed silently.
Route all fail-open returns through :func:`fail_open_result` so the marker can
never be forgotten again.
"""

from typing import Any, Dict


def fail_open_result(reason: str) -> Dict[str, Any]:
    """Build a fail-open ALLOW verdict.

    Returned only when ``fail_mode='open'`` is explicitly set and the scan could
    not complete (circuit open, timeout, backend error). Marked
    ``degraded=True`` so a caller can distinguish a scanned-and-clean verdict
    from one where enforcement was skipped because the backend was unreachable.
    """
    return {"safe": True, "reason": reason, "degraded": True}
