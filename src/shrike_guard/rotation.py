"""Session rotation contract, ported from the MCP client's two-shape record.

Mirrors :mod:`shrike-guard/rotation` (TypeScript) exactly. When a scan
response indicates the session should rotate — either the backend
returned an explicit ``session_locked`` verdict or the ``session_state``
carries an accumulated risk score above the configured threshold —
integrators need a stable record they can act on.

Two shapes, one discriminated union:

- ``ModuleOwnedRotation`` — the SDK's fallback ``SESSION_ID`` was in
  force for this scan (the developer did not thread their own
  ``session_id`` through the scan call). The SDK caller should adopt
  ``new_session_id`` for subsequent scans (or generate its own — the
  ``new_session_id`` is a suggestion).
- ``CallerOwnedRotationRecommendation`` — the developer supplied their
  own ``session_id`` on the scan call. The SDK does not know how they
  manage session lifecycle, so it can only recommend rotation. The
  caller decides whether to adopt ``suggested_new_session_id``, mint
  their own, or ignore.

Discriminate on ``rotated``.

The rotation module is deliberately decoupled from ``ScanClient``:
``evaluate_rotation`` is a pure function that takes a structural input
so callers can invoke it after any scan without threading state through
the scanner. To integrate: call it with the scan verdict + the session
IDs you know about, act on the returned record if non-``None``.
"""

from __future__ import annotations

import uuid
from typing import Literal, Optional, TypedDict, Union


#: Configured risk-score threshold above which :func:`evaluate_rotation`
#: emits a ``risk_threshold_exceeded`` recommendation. Mirrors the MCP
#: client's ``ROTATION_THRESHOLD`` and the TypeScript SDK's constant.
ROTATION_THRESHOLD: float = 0.7


class ModuleOwnedRotation(TypedDict, total=False):
    """Rotation record when the SDK's fallback ``SESSION_ID`` was used.

    Discriminant: ``rotated: True`` + ``owner: "sdk_client"``.
    """

    rotated: Literal[True]
    owner: Literal["sdk_client"]
    reason: Literal["session_locked", "risk_threshold_exceeded"]
    previous_session_id: str
    new_session_id: str
    triggering_risk_score: float
    configured_threshold: float


class CallerOwnedRotationRecommendation(TypedDict, total=False):
    """Rotation recommendation when the caller supplied their own
    ``session_id``. The SDK does NOT rotate its module ``SESSION_ID``;
    the record signals that the caller should consider rotating theirs.

    Per-event suggestion contract: ``suggested_new_session_id`` is minted
    per recommendation and is NOT a stable "next id" the caller should
    cache. If the caller stays on ``current_session_id`` for turn N+1,
    the SDK will mint a fresh suggestion. Persisting a stale suggestion
    de-correlates it from the event that produced it. Adopt at the moment
    of the recommendation or ignore it; do not cache-key on the value.

    Discriminant: ``rotated: False`` + ``rotation_recommended: True``.
    """

    rotated: Literal[False]
    rotation_recommended: Literal[True]
    owner: Literal["caller"]
    reason: Literal["session_locked", "risk_threshold_exceeded"]
    current_session_id: str
    suggested_new_session_id: str
    triggering_risk_score: float
    configured_threshold: float


#: Discriminated union of the two rotation record shapes.
SessionRotation = Union[ModuleOwnedRotation, CallerOwnedRotationRecommendation]


def evaluate_rotation(
    *,
    threat_type: Optional[str] = None,
    session_risk_score: Optional[float] = None,
    effective_session_id: str,
    module_session_id: str,
) -> Optional[SessionRotation]:
    """Inspect a scan verdict and return a :data:`SessionRotation` record
    when rotation is warranted, or ``None`` when no trigger fired.

    Triggers:

    - ``threat_type == "session_locked"`` — the backend has explicitly
      told the SDK the session is done.
    - ``session_risk_score >= ROTATION_THRESHOLD`` — the L9 correlator
      has accumulated risk past the safe-continuation floor.

    Ownership detection compares ``effective_session_id`` (the id
    actually used for this scan) against ``module_session_id`` (the SDK's
    fallback ``SESSION_ID``). Match → module-owned rotation. Mismatch →
    caller-owned recommendation.

    The function is pure — no side effects, no mutation of module state.
    Rotation of the SDK's module ``SESSION_ID`` is the caller's
    responsibility once they act on a returned :class:`ModuleOwnedRotation`.

    Args:
        threat_type: Backend-returned ``threat_type`` (or ``None``).
        session_risk_score: Accumulated session risk (0.0 – 1.0) from
            the response's ``session_state``, or ``None`` if the scan did
            not carry L9 state.
        effective_session_id: The ``session_id`` used for this scan.
        module_session_id: The SDK's current module ``SESSION_ID``.

    Returns:
        A :class:`ModuleOwnedRotation`, a
        :class:`CallerOwnedRotationRecommendation`, or ``None`` when no
        rotation is warranted.
    """
    locked = threat_type == "session_locked"
    over_threshold = (
        isinstance(session_risk_score, (int, float))
        and float(session_risk_score) >= ROTATION_THRESHOLD
    )

    if not locked and not over_threshold:
        return None

    reason: Literal["session_locked", "risk_threshold_exceeded"] = (
        "session_locked" if locked else "risk_threshold_exceeded"
    )

    if effective_session_id != module_session_id:
        rec: CallerOwnedRotationRecommendation = {
            "rotated": False,
            "rotation_recommended": True,
            "owner": "caller",
            "reason": reason,
            "current_session_id": effective_session_id,
            "suggested_new_session_id": str(uuid.uuid4()),
            "configured_threshold": ROTATION_THRESHOLD,
        }
        if isinstance(session_risk_score, (int, float)):
            rec["triggering_risk_score"] = float(session_risk_score)
        return rec

    rotation: ModuleOwnedRotation = {
        "rotated": True,
        "owner": "sdk_client",
        "reason": reason,
        "previous_session_id": module_session_id,
        "new_session_id": str(uuid.uuid4()),
        "configured_threshold": ROTATION_THRESHOLD,
    }
    if isinstance(session_risk_score, (int, float)):
        rotation["triggering_risk_score"] = float(session_risk_score)
    return rotation
