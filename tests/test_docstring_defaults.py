"""Guard: the package module docstring must match the real config defaults.

`help(shrike_guard)` and IDE hovers render the top-level docstring, so a stale
default there is a documentation lie on the most-read surface. 4.0.2 shipped
with the docstring claiming `fail_mode="open"` was the default (it is
`closed`, secure by default) and `scan_timeout` 2.0s (it is 10.0). This test
ties the docstring to config.DEFAULT_FAIL_MODE / DEFAULT_SCAN_TIMEOUT so the
two cannot diverge again — if config changes, update the docstring and this
test passes; if the docstring drifts, CI fails before publish.
"""

import ast
from pathlib import Path

from shrike_guard.config import DEFAULT_FAIL_MODE, DEFAULT_SCAN_TIMEOUT, FailMode


def _module_docstring() -> str:
    src = (Path(__file__).parent.parent / "src" / "shrike_guard" / "__init__.py").read_text()
    doc = ast.get_docstring(ast.parse(src))
    assert doc, "shrike_guard package docstring is missing"
    return doc


def test_docstring_names_the_real_default_fail_mode() -> None:
    doc = _module_docstring()
    # The default is closed; the docstring must label closed (not open) as default.
    assert DEFAULT_FAIL_MODE == FailMode.CLOSED, "source-of-truth default changed"
    assert 'fail_mode="closed" (default)' in doc, "docstring must mark closed as the default"
    assert 'fail_mode="open" (default)' not in doc, "docstring falsely marks open as default"


def test_docstring_names_the_real_default_timeout() -> None:
    doc = _module_docstring()
    # e.g. 10.0 -> match "10.0 second" without pinning trailing punctuation.
    assert f"{DEFAULT_SCAN_TIMEOUT} second" in doc, (
        f"docstring timeout default does not match config ({DEFAULT_SCAN_TIMEOUT}s)"
    )
