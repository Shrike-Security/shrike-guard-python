"""Custom exceptions for the Shrike Guard SDK."""

from typing import Any, Dict, Optional


class ShrikeError(Exception):
    """Base exception for all Shrike SDK errors."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ShrikeScanError(ShrikeError):
    """Raised when a scan operation fails and fail_mode is 'closed'.

    This exception is raised when:
    - The Shrike API times out
    - A network error occurs
    - The API returns an unexpected error

    When fail_mode is 'open' (default), these errors are silently
    handled and the request is allowed to proceed.
    """

    pass


class ShrikeBlockedError(ShrikeError):
    """Raised when a prompt is blocked by Shrike security checks.

    This exception indicates that the prompt was scanned and determined
    to be unsafe. The scan result details are available in the `details`
    attribute.

    Attributes:
        threat_type: The type of threat detected (e.g., 'prompt_injection', 'pii')
        confidence: The confidence score of the detection (0.0-1.0)
        violations: List of specific violations detected
    """

    def __init__(
        self,
        message: str,
        threat_type: Optional[str] = None,
        confidence: Optional[float] = None,
        violations: Optional[list] = None,
    ) -> None:
        details = {
            "threat_type": threat_type,
            "confidence": confidence,
            "violations": violations or [],
        }
        super().__init__(message, details)
        self.threat_type = threat_type
        self.confidence = confidence
        self.violations = violations or []


class ShrikeConfigError(ShrikeError):
    """Raised when there's a configuration error in the SDK."""

    pass
