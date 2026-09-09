"""Configuration constants and types for the Shrike Guard SDK."""

import logging
import os
import uuid
from enum import Enum
from typing import Any, Dict, Final, Optional

logger = logging.getLogger("shrike-guard")


class FailMode(str, Enum):
    """Defines behavior when scan operations fail (timeout, network error, backend 5xx).

    CLOSED: Block the request and raise ShrikeScanError when the scanner cannot
            decide (default). This is the Zero Trust posture promised by the
            Shrike platform — if the guard cannot evaluate the action, the action
            does not proceed. Choose this for any security-sensitive workload.

    OPEN: Allow the request to proceed if the scanner fails. Use this when
          availability is strictly prioritized over enforcement (e.g. non-
          production experiments, internal tools where outages must not block
          users). Note: a fail-open SDK provides no guard during backend outages,
          which is when adversarial pressure is highest.
    """

    OPEN = "open"
    CLOSED = "closed"


# Default configuration values
DEFAULT_SCAN_TIMEOUT: Final[float] = 10.0  # seconds (Cloud Run can have cold starts)
# CLOSED is the secure default (matches the platform's Zero Trust contract).
# Change to FailMode.OPEN explicitly if availability must outrank enforcement.
DEFAULT_FAIL_MODE: Final[FailMode] = FailMode.CLOSED
# Default uses load balancer for scalability. Override with endpoint param for VPC deployments.
DEFAULT_ENDPOINT: Final[str] = "https://api.shrikesecurity.com/agent"

# Note: Scan depth is set by the backend from the license tier (community = L1-L5
# deterministic layers; Pro and above = full L1-L9 including LLM semantic, response
# intel and session correlation).
# Enterprise tier includes priority processing, higher rate limits, and custom policies.

# SDK identification
SDK_NAME: Final[str] = "python"
SDK_USER_AGENT: Final[str] = "shrike-guard-python"

# Process-wide session and agent identity.
#
# The session id is the backend's multi-turn correlation key; the agent id is
# what a declared scope is enforced against and what an incident is attributed
# to. Both can be overridden per client (``ScanClient(session_id=, agent_id=)``
# and ``for_session``). Mirrors getSessionId()/getAgentId() in the TypeScript
# SDK and the process identifiers in the Go SDK.
_SESSION_ID: Final[str] = str(uuid.uuid4())
_AGENT_ID: Final[str] = f"sdk-py-{uuid.uuid4().hex[:8]}"


def get_session_id() -> str:
    """The stable session id for this SDK process (L9 correlation key)."""
    return _SESSION_ID


def get_agent_id() -> str:
    """The agent id for this SDK process.

    ``SHRIKE_AGENT_ID`` when set, so a deployment can name its agents;
    otherwise an id generated once per process. The variable is read at call
    time rather than at import, matching the Go and TypeScript SDKs, so setting
    it after import still takes effect and the shared contract
    (``agent_id_env_override`` in canonical-request-shapes.json) can be tested
    in-process.
    """
    return os.environ.get("SHRIKE_AGENT_ID") or _AGENT_ID


_process_session_warned = False


def _warn_once_about_the_process_session() -> None:
    """Log, once per process, that scans are using the process-wide session id.

    The process-wide default suits a CLI, a worker or a single agent, and gives
    those callers multi-turn correlation without configuration.

    It does not suit a server handling many end users: session identity is the
    key the backend accumulates risk against, so every user sharing one id
    shares one risk score, and one user's refusal counts against the next
    user's action. The SDK cannot tell the two deployments apart, so the
    default is kept and stated once. Pass ``session_id`` to the client, or
    derive a per-request client with ``for_session()``, and the message is not
    emitted.

    Silence it with ``SHRIKE_SUPPRESS_SESSION_WARNING=1``.
    """
    global _process_session_warned
    if _process_session_warned:
        return
    _process_session_warned = True

    if os.environ.get("SHRIKE_SUPPRESS_SESSION_WARNING"):
        return

    logger.warning(
        "[shrike-guard] Using the process-wide session id. This suits a single "
        "agent; a server handling many end users should pass session_id=... or "
        "use client.for_session(<per-request id>) so each user has its own "
        "session. Set SHRIKE_SUPPRESS_SESSION_WARNING=1 to silence this message."
    )


def build_session_context(
    extra: Optional[Dict[str, Any]] = None,
    session_id: Optional[str] = None,
    agent_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Build the scan context carrying session identity.

    ``extra`` is merged on top, so a per-call key (``cwd``, ``query``) travels
    alongside the identity rather than replacing it.

    ``session_id`` / ``agent_id`` override the process-wide defaults. Supply
    them for anything serving more than one end user — see
    :func:`_warn_once_about_the_process_session`.
    """
    if session_id is None:
        _warn_once_about_the_process_session()

    ctx: Dict[str, Any] = {
        "session_id": session_id or get_session_id(),
        "agent_id": agent_id or get_agent_id(),
        "source_application": "shrike-guard-py",
    }
    if extra:
        ctx.update(extra)
    return ctx
