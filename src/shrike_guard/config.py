"""Configuration constants and types for the Shrike Guard SDK."""

from enum import Enum
from typing import Final


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

# Note: All scanning is done via backend API. All tiers get full 9-layer cascade (L1-L8).
# Enterprise tier includes priority processing, higher rate limits, and custom policies.

# SDK identification
SDK_NAME: Final[str] = "python"
SDK_USER_AGENT: Final[str] = "shrike-guard-python"
