"""Version information for shrike-guard.

``__version__`` is derived from the installed distribution metadata so it can
never drift from the version declared in ``pyproject.toml`` — the drift that
shipped in 4.0.1, where the distribution was 4.0.1 but this string still read
4.0.0 and mis-stamped the ``X-Shrike-SDK-Version`` audit header on every scan.
The literal fallback is only used in a source checkout with no dist metadata.
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _dist_version

# Keep this fallback in step with pyproject.toml for source-only checkouts.
_FALLBACK_VERSION = "4.3.0"

try:
    __version__ = _dist_version("shrike-guard")
except PackageNotFoundError:  # not installed (raw source tree) — use fallback
    __version__ = _FALLBACK_VERSION

__version_info__ = tuple(int(x) for x in __version__.split(".") if x.isdigit())
