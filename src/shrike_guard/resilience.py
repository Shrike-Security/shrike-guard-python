"""Circuit breaker and retry patterns for Shrike SDK resilience."""

import asyncio
import logging
import threading
import time
from enum import Enum
from typing import Any, Awaitable, Callable, Optional, TypeVar

logger = logging.getLogger("shrike-guard")

T = TypeVar("T")


class CircuitState(str, Enum):
    """Circuit breaker states."""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing — requests rejected
    HALF_OPEN = "half_open"  # Recovery testing


class CircuitOpenError(Exception):
    """Raised when circuit breaker is open and rejecting requests."""

    pass


class CircuitBreaker:
    """Three-state circuit breaker for HTTP calls.

    Tracks consecutive failures. After ``failure_threshold`` failures, the
    circuit opens and rejects requests for ``timeout`` seconds. After the
    timeout, a limited number of test requests are allowed (half-open).
    If they succeed, the circuit closes; if they fail, it reopens.

    Example:
        >>> cb = CircuitBreaker(failure_threshold=5, timeout=30.0)
        >>> result = cb.execute(lambda: httpx_client.post(url, ...))

    Thread-safe: uses a lock for state transitions.
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        success_threshold: int = 2,
        timeout: float = 30.0,
        max_half_open_requests: int = 3,
        on_state_change: Optional[Callable[[CircuitState, CircuitState], None]] = None,
    ) -> None:
        self._failure_threshold = failure_threshold
        self._success_threshold = success_threshold
        self._timeout = timeout
        self._max_half_open = max_half_open_requests
        self._on_state_change = on_state_change

        self._lock = threading.Lock()
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._half_open_count = 0
        self._opened_at: float = 0.0
        self._last_state_change: float = time.monotonic()
        self._last_failure_time: float = 0.0

    @property
    def state(self) -> CircuitState:
        """Current circuit breaker state."""
        with self._lock:
            if (
                self._state == CircuitState.OPEN
                and time.monotonic() - self._opened_at >= self._timeout
            ):
                return CircuitState.HALF_OPEN
            return self._state

    @property
    def stats(self) -> dict:
        """Circuit breaker statistics."""
        with self._lock:
            return {
                "state": self._state.value,
                "failure_count": self._failure_count,
                "success_count": self._success_count,
                "last_failure_time": self._last_failure_time,
            }

    def execute(self, fn: Callable[[], T]) -> T:
        """Execute fn through the circuit breaker (synchronous).

        Args:
            fn: Callable to execute.

        Returns:
            The return value of fn.

        Raises:
            CircuitOpenError: If the circuit is open.
        """
        self._before_request()
        try:
            result = fn()
            self._on_success()
            return result
        except Exception as e:
            self._on_failure()
            raise

    async def execute_async(self, fn: Callable[[], Awaitable[T]]) -> T:
        """Execute fn through the circuit breaker (async).

        Args:
            fn: Async callable to execute.

        Returns:
            The return value of fn.

        Raises:
            CircuitOpenError: If the circuit is open.
        """
        self._before_request()
        try:
            result = await fn()
            self._on_success()
            return result
        except Exception as e:
            self._on_failure()
            raise

    def _before_request(self) -> None:
        with self._lock:
            if self._state == CircuitState.CLOSED:
                return
            elif self._state == CircuitState.OPEN:
                if time.monotonic() - self._opened_at >= self._timeout:
                    self._set_state(CircuitState.HALF_OPEN)
                    self._half_open_count = 1
                    return
                raise CircuitOpenError("Circuit breaker is open")
            elif self._state == CircuitState.HALF_OPEN:
                self._half_open_count += 1
                if self._half_open_count > self._max_half_open:
                    self._half_open_count -= 1
                    raise CircuitOpenError("Too many requests in half-open state")

    def _on_success(self) -> None:
        with self._lock:
            if self._state == CircuitState.CLOSED:
                self._failure_count = 0
                self._success_count += 1
            elif self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self._success_threshold:
                    self._set_state(CircuitState.CLOSED)
                    self._failure_count = 0
                    self._success_count = 0
                    self._half_open_count = 0

    def _on_failure(self) -> None:
        with self._lock:
            self._last_failure_time = time.monotonic()
            if self._state == CircuitState.CLOSED:
                self._failure_count += 1
                if self._failure_count >= self._failure_threshold:
                    self._set_state(CircuitState.OPEN)
                    self._opened_at = time.monotonic()
            elif self._state == CircuitState.HALF_OPEN:
                self._set_state(CircuitState.OPEN)
                self._opened_at = time.monotonic()
                self._success_count = 0
                self._half_open_count = 0

    def _set_state(self, to: CircuitState) -> None:
        from_state = self._state
        if from_state == to:
            return
        self._state = to
        self._last_state_change = time.monotonic()
        logger.info("Circuit breaker: %s → %s", from_state.value, to.value)
        if self._on_state_change:
            try:
                self._on_state_change(from_state, to)
            except Exception:
                pass


def retry_with_backoff(
    fn: Callable[[], T],
    max_attempts: int = 3,
    initial_backoff: float = 0.2,
    max_backoff: float = 5.0,
    multiplier: float = 2.0,
    is_retryable: Optional[Callable[[Exception], bool]] = None,
) -> T:
    """Execute fn with exponential backoff retry (synchronous).

    Args:
        fn: Callable to execute.
        max_attempts: Maximum number of attempts.
        initial_backoff: Initial delay in seconds before first retry.
        max_backoff: Maximum delay between retries.
        multiplier: Backoff multiplier.
        is_retryable: Function to determine if an error is retryable.

    Returns:
        The return value of fn.

    Raises:
        The last exception if all attempts fail.
    """
    if is_retryable is None:
        is_retryable = lambda e: not isinstance(e, CircuitOpenError)

    last_error: Optional[Exception] = None
    backoff = initial_backoff

    for attempt in range(max_attempts):
        try:
            return fn()
        except Exception as e:
            last_error = e
            if not is_retryable(e):
                raise
            if attempt == max_attempts - 1:
                break
            logger.debug(
                "Retry attempt %d/%d after error: %s (backoff: %.1fs)",
                attempt + 1,
                max_attempts,
                str(e),
                backoff,
            )
            time.sleep(backoff)
            backoff = min(backoff * multiplier, max_backoff)

    raise last_error  # type: ignore[misc]


async def async_retry_with_backoff(
    fn: Callable[[], Awaitable[T]],
    max_attempts: int = 3,
    initial_backoff: float = 0.2,
    max_backoff: float = 5.0,
    multiplier: float = 2.0,
    is_retryable: Optional[Callable[[Exception], bool]] = None,
) -> T:
    """Execute fn with exponential backoff retry (async).

    Same as retry_with_backoff but uses asyncio.sleep instead of time.sleep.
    """
    if is_retryable is None:
        is_retryable = lambda e: not isinstance(e, CircuitOpenError)

    last_error: Optional[Exception] = None
    backoff = initial_backoff

    for attempt in range(max_attempts):
        try:
            return await fn()
        except Exception as e:
            last_error = e
            if not is_retryable(e):
                raise
            if attempt == max_attempts - 1:
                break
            logger.debug(
                "Async retry attempt %d/%d after error: %s (backoff: %.1fs)",
                attempt + 1,
                max_attempts,
                str(e),
                backoff,
            )
            await asyncio.sleep(backoff)
            backoff = min(backoff * multiplier, max_backoff)

    raise last_error  # type: ignore[misc]
