"""Tests for ShrikeRateLimitError.

Mirrors the TypeScript SDK's ShrikeRateLimitError behavior. The class
extends ShrikeScanError so callers with generic scan-error handling
continue to work unchanged, while callers that want to distinguish
rate-limit failure from other scan failures can catch this class.

Also verifies scanner.py surfaces the typed error on a 429 response
before letting httpx.raise_for_status raise a generic HTTPStatusError.
"""

from __future__ import annotations

from unittest.mock import Mock

import httpx
import pytest

from shrike_guard import ShrikeError, ShrikeRateLimitError, ShrikeScanError
from shrike_guard.scanner import _check_rate_limited


def _mock_response(status_code: int, headers: dict | None = None) -> Mock:
    r = Mock(spec=httpx.Response)
    r.status_code = status_code
    r.headers = headers or {}
    return r


class TestShrikeRateLimitErrorClass:
    def test_extends_shrike_scan_error(self):
        """Callers with `except ShrikeScanError:` must catch this too."""
        assert issubclass(ShrikeRateLimitError, ShrikeScanError)
        assert issubclass(ShrikeRateLimitError, ShrikeError)

    def test_stores_retry_after_and_status_code_in_details(self):
        err = ShrikeRateLimitError("rate limited", retry_after=5.0)
        assert err.retry_after == 5.0
        assert err.details["status_code"] == 429
        assert err.details["retry_after"] == 5.0

    def test_omits_retry_after_when_none(self):
        err = ShrikeRateLimitError("rate limited")
        assert err.retry_after is None
        assert err.details["status_code"] == 429
        assert "retry_after" not in err.details

    def test_re_exported_at_shrike_guard_root(self):
        """Users must be able to `from shrike_guard import ShrikeRateLimitError`."""
        from shrike_guard import ShrikeRateLimitError as root

        assert root is ShrikeRateLimitError


class TestCheckRateLimitedHelper:
    def test_passes_through_2xx(self):
        """No exception on success path."""
        _check_rate_limited(_mock_response(200))

    def test_passes_through_other_4xx(self):
        """Only 429 becomes ShrikeRateLimitError. 400/401/403/500 flow
        through raise_for_status unchanged."""
        for code in (400, 401, 403, 404, 500, 503):
            _check_rate_limited(_mock_response(code))

    def test_raises_shrike_rate_limit_error_on_429(self):
        with pytest.raises(ShrikeRateLimitError):
            _check_rate_limited(_mock_response(429))

    def test_parses_retry_after_header_as_seconds(self):
        with pytest.raises(ShrikeRateLimitError) as excinfo:
            _check_rate_limited(_mock_response(429, headers={"Retry-After": "10"}))
        assert excinfo.value.retry_after == 10.0

    def test_parses_lowercase_retry_after_header(self):
        """httpx normalizes header case but downstream / mocked responses
        may use lower-case. Accept either form."""
        with pytest.raises(ShrikeRateLimitError) as excinfo:
            _check_rate_limited(_mock_response(429, headers={"retry-after": "3.5"}))
        assert excinfo.value.retry_after == 3.5

    def test_missing_retry_after_leaves_none(self):
        with pytest.raises(ShrikeRateLimitError) as excinfo:
            _check_rate_limited(_mock_response(429))
        assert excinfo.value.retry_after is None

    def test_malformed_retry_after_leaves_none(self):
        """A malformed header must not crash — the caller still needs to
        see the 429 raised as ShrikeRateLimitError."""
        with pytest.raises(ShrikeRateLimitError) as excinfo:
            _check_rate_limited(_mock_response(429, headers={"Retry-After": "not-a-number"}))
        assert excinfo.value.retry_after is None
