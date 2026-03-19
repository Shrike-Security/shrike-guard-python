"""Authentication client for the Shrike API.

Provides account registration, login, and token management.

Example:
    >>> from shrike_guard.auth import AuthClient
    >>> auth = AuthClient()
    >>> result = auth.register(email="user@example.com", password="securepass123")
    >>> print(result["api_key"])
"""

from typing import Any, Dict, Optional

import httpx

from .config import DEFAULT_ENDPOINT, DEFAULT_SCAN_TIMEOUT


class AuthClient:
    """HTTP client for Shrike authentication endpoints."""

    def __init__(
        self,
        endpoint: str = DEFAULT_ENDPOINT,
        timeout: float = DEFAULT_SCAN_TIMEOUT,
    ) -> None:
        self._endpoint = endpoint.rstrip("/")
        self._http = httpx.Client(timeout=timeout)
        self._access_token: Optional[str] = None

    def _auth_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if self._access_token:
            headers["Authorization"] = f"Bearer {self._access_token}"
        return headers

    def register(
        self,
        email: str,
        password: str,
        company_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Register a new community account.

        Returns a dict with api_key, access_token, refresh_token, etc.
        The api_key is only returned once — save it immediately.

        Args:
            email: Account email address.
            password: Account password (min 8 characters).
            company_name: Optional company name.
        """
        payload: Dict[str, str] = {"email": email, "password": password}
        if company_name:
            payload["company_name"] = company_name

        response = self._http.post(
            f"{self._endpoint}/api/v1/community/register",
            json=payload,
            headers={"Content-Type": "application/json"},
        )
        response.raise_for_status()
        data = response.json()
        if "access_token" in data:
            self._access_token = data["access_token"]
        return data

    def login(self, email: str, password: str) -> Dict[str, Any]:
        """Login with email and password.

        Returns access_token and refresh_token.
        """
        response = self._http.post(
            f"{self._endpoint}/api/v1/auth/login",
            json={"email": email, "password": password},
            headers={"Content-Type": "application/json"},
        )
        response.raise_for_status()
        data = response.json()
        if "access_token" in data:
            self._access_token = data["access_token"]
        return data

    def refresh(self, refresh_token: str) -> Dict[str, Any]:
        """Refresh the access token."""
        response = self._http.post(
            f"{self._endpoint}/api/v1/auth/refresh",
            json={"refresh_token": refresh_token},
            headers=self._auth_headers(),
        )
        response.raise_for_status()
        data = response.json()
        if "access_token" in data:
            self._access_token = data["access_token"]
        return data

    def me(self) -> Dict[str, Any]:
        """Get the current user's profile."""
        response = self._http.get(
            f"{self._endpoint}/api/v1/auth/me",
            headers=self._auth_headers(),
        )
        response.raise_for_status()
        return response.json()

    def logout(self) -> None:
        """Logout and invalidate the current session."""
        self._http.post(
            f"{self._endpoint}/api/v1/auth/logout",
            headers=self._auth_headers(),
        )
        self._access_token = None

    def close(self) -> None:
        """Close the HTTP client."""
        self._http.close()

    def __enter__(self) -> "AuthClient":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
