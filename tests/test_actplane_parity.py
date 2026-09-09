"""Every act-plane channel the backend scans must be reachable from the SDK.

This test exists because it would have failed for a year. The backend has
scanned eight specialized content types since the act plane shipped; the Python
SDK exposed two of them. `scan_command` — the highest-volume surface, the one
an agent hits before every shell-out — had no method at all, so the only way to
reach it was to hand-roll an HTTP call or route through the MCP server.

Nothing caught that, because "the backend supports it" and "a customer can call
it" were two facts with nothing comparing them. This is the comparison.

The canonical list is models.SpecializedContentTypes() in the Go backend
(common/models/policy.go). It is duplicated here as a literal on purpose: the
SDK ships to PyPI without the backend source, so it cannot import it, and a
silent divergence is exactly what this test is for. When the backend adds a
channel, this list and a method have to move together — which is the point.
"""

import inspect

import pytest

from shrike_guard.scanner import AsyncScanClient, ScanClient

# Mirrors models.SpecializedContentTypes() — keep in sync deliberately.
SPECIALIZED_CONTENT_TYPES = [
    "sql",
    "file_path",
    "file_content",
    "web_search",
    "command",
    "a2a_message",
    "agent_card",
    "rag_context",
]

# How each channel is reached. file_path and file_content share one method
# (scan_file decides by whether content was supplied), which is why this is a
# mapping rather than a name transformation.
CHANNEL_METHODS = {
    "sql": "scan_sql",
    "file_path": "scan_file",
    "file_content": "scan_file",
    "web_search": "scan_web_search",
    "command": "scan_command",
    "a2a_message": "scan_a2a_message",
    "agent_card": "scan_agent_card",
    "rag_context": "scan_rag_context",
}


def test_every_channel_is_mapped_to_a_method():
    """No channel may exist without a declared way to call it."""
    missing = [ct for ct in SPECIALIZED_CONTENT_TYPES if ct not in CHANNEL_METHODS]
    assert not missing, (
        f"content types with no SDK method declared: {missing}. "
        "A channel the backend scans but the SDK cannot reach is a channel our "
        "customers do not have."
    )


@pytest.mark.parametrize("content_type", SPECIALIZED_CONTENT_TYPES)
def test_sync_client_exposes_channel(content_type):
    method = CHANNEL_METHODS[content_type]
    assert hasattr(ScanClient, method), (
        f"ScanClient has no {method}() for content type {content_type!r}. "
        "The backend scans this channel; the SDK cannot reach it."
    )
    assert callable(getattr(ScanClient, method))


@pytest.mark.parametrize("content_type", SPECIALIZED_CONTENT_TYPES)
def test_async_client_exposes_channel(content_type):
    method = CHANNEL_METHODS[content_type]
    assert hasattr(AsyncScanClient, method), (
        f"AsyncScanClient has no {method}() — sync/async parity is part of the "
        "contract, and an async caller is not a second-class one."
    )
    assert inspect.iscoroutinefunction(getattr(AsyncScanClient, method)), (
        f"AsyncScanClient.{method} is not a coroutine function"
    )


def test_mcp_schema_is_reachable():
    """scan_mcp_schema is not a specialized content type — it has its own
    endpoint (/api/scan/mcp_schema) and its own detector — but it is an
    act-plane surface and must be callable."""
    for cls in (ScanClient, AsyncScanClient):
        assert hasattr(cls, "scan_mcp_schema"), (
            f"{cls.__name__} cannot screen an MCP tool definition. Tool "
            "poisoning needs no execution, so a caller that cannot screen a "
            "tools/list response has no defence against it at all."
        )


def test_sync_and_async_surfaces_match():
    """The two clients must expose the same scan surface.

    A method that exists on one and not the other is the same class of gap as
    a channel missing from both, just harder to notice.
    """

    def scan_methods(cls):
        return {
            name
            for name in dir(cls)
            if name.startswith("scan_") and callable(getattr(cls, name))
        }

    sync_only = scan_methods(ScanClient) - scan_methods(AsyncScanClient)
    async_only = scan_methods(AsyncScanClient) - scan_methods(ScanClient)
    assert not sync_only, f"only on ScanClient: {sorted(sync_only)}"
    assert not async_only, f"only on AsyncScanClient: {sorted(async_only)}"
