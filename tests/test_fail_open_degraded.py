"""F-2 conformance: every fail-open ALLOW verdict must carry ``degraded=True``.

Under ``fail_mode='open'`` a caller must be able to tell "scanned and clean"
apart from "not scanned, enforcement skipped". Every fail-open return routes
through ``shrike_guard._results.fail_open_result``; these
tests lock the ``degraded`` marker in per surface so a new wrapper cannot
regress it.
"""

from unittest import mock

import httpx
import pytest

from shrike_guard import (
    ShrikeAnthropic,
    ShrikeAsyncOpenAI,
    ShrikeGemini,
    ShrikeOpenAI,
)


def _assert_degraded(result: dict) -> None:
    assert result["safe"] is True
    assert result.get("degraded") is True, f"fail-open result missing degraded=True: {result}"


def test_openai_fail_open_degraded() -> None:
    client = ShrikeOpenAI(api_key="sk-test", shrike_api_key="shrike-test", fail_mode="open")
    with mock.patch.object(client._http, "post", side_effect=httpx.TimeoutException("t")):
        _assert_degraded(client._scan_messages([{"role": "user", "content": "Hello!"}]))
    client.close()


async def test_async_openai_fail_open_degraded() -> None:
    client = ShrikeAsyncOpenAI(api_key="sk-test", shrike_api_key="shrike-test", fail_mode="open")
    with mock.patch.object(client._http, "post", side_effect=httpx.TimeoutException("t")):
        _assert_degraded(await client._scan_messages([{"role": "user", "content": "Hello!"}]))
    await client.close()


@pytest.mark.skipif(ShrikeAnthropic is None, reason="anthropic extra not installed")
def test_anthropic_fail_open_degraded() -> None:
    client = ShrikeAnthropic(api_key="sk-test", shrike_api_key="shrike-test", fail_mode="open")
    with mock.patch.object(client._http, "post", side_effect=httpx.TimeoutException("t")):
        _assert_degraded(client._scan_messages([{"role": "user", "content": "Hello!"}]))
    client.close()


@pytest.mark.skipif(ShrikeGemini is None, reason="gemini extra not installed")
def test_gemini_fail_open_degraded() -> None:
    client = ShrikeGemini(api_key="test-key", shrike_api_key="shrike-test", fail_mode="open")
    with mock.patch.object(client._http, "post", side_effect=httpx.TimeoutException("t")):
        _assert_degraded(client._scan_content("Hello!"))
    client.close()
