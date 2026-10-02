"""Session rotation contract, ported from the MCP client's three-shape record.

Mirrors :mod:`shrike-guard/rotation` (TypeScript) exactly. When a scan
response indicates the session should rotate — either the backend
returned an explicit ``session_locked`` verdict or the ``session_state``
carries an accumulated risk score above the configured threshold —
integrators need a stable record they can act on.

Three shapes, one discriminated union:

- ``SessionLockedNotice`` — the backend returned ``session_locked``.
  Nothing rotates: a fresh ``session_id`` sidesteps the lock instead of
  clearing it. Carries no new id on either ownership. A lock lifts by a
  self-release under a live declared scope, or by an operator.
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

Discriminate on ``rotated``, then on ``rotation_recommended``. The two
rotation shapes are reached only by the risk-score trigger, which stays
in force strictly BELOW a lock as proactive hygiene.

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
    #: A locked session never rotates, so the score is the only trigger here.
    reason: Literal["risk_threshold_exceeded"]
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
    #: A locked session never rotates, so the score is the only trigger here.
    reason: Literal["risk_threshold_exceeded"]
    current_session_id: str
    suggested_new_session_id: str
    triggering_risk_score: float
    configured_threshold: float


class SessionLockedNotice(TypedDict, total=False):
    """Emitted when the backend locked the session.

    Nothing rotated and nothing should: a fresh ``session_id`` sidesteps
    the lock instead of clearing it. No ``suggested_new_session_id`` on
    this shape, deliberately. A lock lifts by a self-release under a live
    declared scope, or by an operator.

    Discriminant: ``rotated: False`` + ``rotation_recommended: False``.
    """

    rotated: Literal[False]
    rotation_recommended: Literal[False]
    owner: Literal["sdk_client", "caller"]
    reason: Literal["session_locked"]
    current_session_id: str
    triggering_risk_score: float
    configured_threshold: float


#: Discriminated union of the three rotation record shapes.
SessionRotation = Union[
    ModuleOwnedRotation,
    CallerOwnedRotationRecommendation,
    SessionLockedNotice,
]


def evaluate_rotation(
    *,
    threat_type: Optional[str] = None,
    session_risk_score: Optional[float] = None,
    effective_session_id: str,
    module_session_id: str,
) -> Optional[SessionRotation]:
    """Inspect a scan verdict and return a :data:`SessionRotation` record
    when rotation is warranted, or ``None`` when no trigger fired.

    Outcomes:

    - ``threat_type == "session_locked"`` — returns a
      :class:`SessionLockedNotice`. NOTHING rotates: the lock is the
      control and a fresh id sidesteps it. Checked first, because a
      locked session is already above the score threshold.
    - ``session_risk_score >= ROTATION_THRESHOLD`` (and not locked) —
      the L9 correlator has accumulated risk past the safe-continuation
      floor, so rotation is warranted as proactive hygiene.

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
    caller_owned = effective_session_id != module_session_id

    # A locked session is never rotated and never recommended for
    # rotation. Checked BEFORE the score branch, because a locked session
    # is already above the threshold and would otherwise fall through.
    if locked:
        notice: SessionLockedNotice = {
            "rotated": False,
            "rotation_recommended": False,
            "owner": "caller" if caller_owned else "sdk_client",
            "reason": "session_locked",
            "current_session_id": effective_session_id,
            "configured_threshold": ROTATION_THRESHOLD,
        }
        if isinstance(session_risk_score, (int, float)):
            notice["triggering_risk_score"] = float(session_risk_score)
        return notice

    if not over_threshold:
        return None

    # The lock branch returned already, so this is the only reachable value.
    reason: Literal["risk_threshold_exceeded"] = "risk_threshold_exceeded"

    if caller_owned:
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
