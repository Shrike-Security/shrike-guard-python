"""Configuration constants and types for the Shrike Guard SDK."""

from enum import Enum
from typing import Final


class FailMode(str, Enum):
    """Defines behavior when scan operations fail.

    OPEN: Allow the request to proceed (fail-open). This is the default
          behavior suitable for most applications where availability is
          prioritized over strict security.

    CLOSED: Block the request and raise an exception (fail-closed). Use
            this mode for security-critical applications where you'd rather
            block potentially safe requests than allow unsafe ones through.
    """

    OPEN = "open"
    CLOSED = "closed"


# Default configuration values
DEFAULT_SCAN_TIMEOUT: Final[float] = 10.0  # seconds (Cloud Run can have cold starts)
DEFAULT_FAIL_MODE: Final[FailMode] = FailMode.OPEN
# Default uses load balancer for scalability. Override with endpoint param for VPC deployments.
DEFAULT_ENDPOINT: Final[str] = "https://api.shrikesecurity.com/agent"

# Note: All scanning is done via backend API. All tiers get full 9-layer cascade (L1-L8).
# Enterprise tier includes priority processing, higher rate limits, and custom policies.

# SDK identification
SDK_NAME: Final[str] = "python"
SDK_USER_AGENT: Final[str] = "shrike-guard-python"
