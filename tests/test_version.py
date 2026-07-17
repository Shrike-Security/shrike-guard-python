"""F-1 guard: the in-code version must match the installed distribution version.

4.0.1 shipped with ``_version.py`` still reading 4.0.0, so every scan stamped
the ``X-Shrike-SDK-Version`` audit header with the wrong version. ``__version__``
is now derived from installed metadata; this test fails the build if that link
is ever broken (e.g. by hard-coding the string again).
"""

import importlib.metadata

import shrike_guard


def test_version_matches_distribution_metadata() -> None:
    dist_version = importlib.metadata.version("shrike-guard")
    assert shrike_guard.__version__ == dist_version, (
        f"__version__ ({shrike_guard.__version__}) != distribution "
        f"metadata ({dist_version}) — the audit header would mis-stamp"
    )
