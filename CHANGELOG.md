# Changelog

## [4.0.3] - 2026-07-17

### Fixed
- **Package module docstring corrected to match the actual defaults.** The top-level `shrike_guard` docstring (shown by `help(shrike_guard)` and IDE hovers) still described `fail_mode="open"` as the default and `scan_timeout` as 2.0 seconds. The real defaults are `fail_mode="closed"` (secure by default, since 2.0.0) and `scan_timeout=10.0`. Documentation-only fix — behavior is unchanged. `ShrikeScanError` and both READMEs were already correct; this was the last surface where the docstring inverted the fail-mode default.

## [4.0.2] - 2026-07-16

### Security
- **Fail-open verdicts now carry `degraded=True` on every wrapper.** The Anthropic and Gemini wrappers — and the timeout / backend-error fail-open paths on the OpenAI sync and async clients — previously returned a plain allow verdict under `fail_mode='open'` when the backend was unreachable, so a caller could not distinguish "scanned and clean" from "not scanned, enforcement skipped." All fail-open returns now route through `_results.fail_open_result`. The default remains fail-**closed**; this affects only callers who explicitly opt into fail-open.

### Changed
- **Provider dependency caps raised to allow current majors.** `openai` and `google-genai` were capped `<2.0.0`, which excluded the current releases (openai 2.x, google-genai 2.x) and could block installs for apps already on those majors. Raised to `<3.0.0` after verifying the wrapper API surface we call (`chat.completions.create`, `models.generate_content`) is unchanged on the new majors. Added a real-package shape test.

### Fixed
- **`__version__` no longer drifts from the distribution version.** 4.0.1 shipped with `_version.py` still reading `4.0.0`, so every scan stamped the `X-Shrike-SDK-Version` audit header as 4.0.0. `__version__` is now derived from the installed distribution metadata and guarded by a test so it cannot diverge again.

## [4.0.1] - 2026-07-16

### Fixed
- Corrected the `ShrikeScanError` docstring, which incorrectly described `fail_mode='open'` as the default. The default is `fail_mode='closed'` (secure by default across the 4.x line) — behavior is unchanged; this is a documentation-only fix so the source matches the shipped default on a clean install.

## [4.0.0] - 2026-07-13

### Version alignment (no breaking changes)
All Shrike client surfaces — MCP server (`shrike-mcp`), TypeScript SDK, and Python SDK — now share a single version line starting at 4.0.0. The jump aligns the surfaces on one major, not an API break: every prior release runs unchanged on 4.0.0. (The fail-closed default is unchanged across the 4.x line.)

### Added
- **Client-side auto-chunk for large inputs.** Prompts over 20KB are automatically split on natural boundaries (paragraph → line → hard cut) into ~8KB chunks and scanned sequentially with fail-fast on the first blocking verdict. Applies to both `ScanClient.scan()` and `AsyncScanClient.scan()`. New `chunker` module exports `AUTO_CHUNK_THRESHOLD`, `CHUNK_TARGET_SIZE`, `chunk_content()`, and `aggregate_chunk_results()` for callers who want to drive chunking directly.
- **Aggregation contract:** worst-action wins across chunks; violations dedup by (threat_type, severity, action); `session_state` from the last scanned chunk; `recovery` from the first blocking chunk.

### Why
Large single-shot scan inputs (agent transcripts, RAG context dumps, file contents) previously rode through the cascade as one oversized request — slower verdicts and more LLM-layer tokens burned per scan. Chunked inputs land in the backend cascade's small-content band, which allows earlier early-exit on clean content and cheaper verdicts on both sides of the wire. Fail-fast on the first blocked chunk means a threat at the top of a large document blocks without paying to scan the rest.

## [2.2.0] - 2026-07-06

### Added
- **Session rotation module — `evaluate_rotation`, `ROTATION_THRESHOLD`, `ModuleOwnedRotation`, `CallerOwnedRotationRecommendation`, `SessionRotation`** (mirrors TypeScript SDK). Pure function inspects a scan verdict and returns a two-shape rotation record — module-owned when the SDK's fallback `SESSION_ID` was in force, caller-owned recommendation when the caller supplied their own `session_id`. Discriminate on `rotated`. Triggers on `threat_type == "session_locked"` OR `session_risk_score >= ROTATION_THRESHOLD` (0.7). Per-event suggestion contract — each caller-owned recommendation mints a fresh `suggested_new_session_id` that is NOT stable across events; do not cache.
- **`ShrikeRateLimitError`** — new typed exception raised on backend 429 responses. Extends `ShrikeScanError` so existing `except ShrikeScanError:` handlers continue to work unchanged; new callers wanting to back off on rate-limit specifically can catch this class. Parses `Retry-After` header when present.

### Why
Cross-language SDK parity. The TypeScript SDK ships `evaluateRotation` + `ShrikeRateLimitError` today; this brings the Python SDK to feature-equivalence so customers flipping between languages see identical rotation and rate-limit semantics.

## [2.1.0] - 2026-07-02

### Added
- **Client-side PII redaction.** `redact_pii()`, `rehydrate_pii()`, `get_redaction_summary()`, `update_pii_patterns()`, and `get_pii_pattern_count()` exported from `shrike_guard`. Detects and tokenizes 20+ PII types (SSN, credit card, email, phone, address, medical record, wallet, etc.) BEFORE the prompt leaves customer environment — Shrike backend never sees the raw PII.
- **`sync_pii_patterns(endpoint, api_key=None)`** — one-shot startup call fetches the canonical Presidio-derived pattern set from the Shrike backend so client-side detection stays uniform with the server-side scan. Uses httpx (already a hard SDK dep) to inherit certifi's bundled root certs and route around the Python.org macOS installer's empty cert store. Fails safe: on any error (network / timeout / malformed / non-200) the bootstrap patterns stay in place; sync never blocks scans.
- **Backend-owned prefix contract.** The recognizer ships its client-side redaction tag (e.g. `[IP_1]`) as part of the pattern payload; the client uses it verbatim. When the backend omits the field (pre-2026-07-02 releases), the SDK derives the prefix from the threat_type. No pattern is ever silently dropped for an unmapped prefix. Adding a new backend pattern requires zero SDK changes.

### Why
Client-side redaction removes PII before it crosses the network to Shrike's backend — defense-in-depth for HIPAA / PCI / GLBA / CMMC workloads on top of the BAA/DPA that already covers transmission. The `sync_pii_patterns` step keeps client patterns in step with backend patterns without shipping SDK updates every time Presidio adds a recognizer.

## [2.0.0] - 2026-06-28

### Changed (BREAKING)
- **Default `fail_mode` flipped from `"open"` to `"closed"`.** When the Shrike backend is unreachable, returns an error, or times out, the SDK now blocks the request by raising `ShrikeScanError` instead of allowing it through with `{"safe": true}`. This matches the Zero Trust contract published on the Shrike platform: if the guard cannot evaluate the action, the action does not proceed. To restore the previous behavior, pass `fail_mode="open"` explicitly when constructing any wrapper.

### Why
The prior fail-open default contradicted the Shrike Marketplace listing's headline promise ("evaluated before execution, no implicit trust"). A security SDK that lets traffic through during a backend outage provides no guard exactly when adversarial pressure is highest. Bumped to a major version so upgraders see the change.

### Migration
- Most users: no action needed. The new default is the more secure posture.
- If you depend on availability over enforcement (e.g. non-production experiments, internal tools where outages must not block users): pass `fail_mode="open"` explicitly to every wrapper. The flag itself is unchanged.

### Fixed
- Aligned `_version.py` (`1.1.1`) with `pyproject.toml` (`1.1.2`); both now report `2.0.0`. Prior drift caused the `X-Shrike-SDK-Version` header to misreport.

## [1.1.0] - 2026-02-19

### Added
- README now documents all three providers (OpenAI, Anthropic Claude, Gemini)
- "What Shrike Detects" section: 86+ rules across 6 compliance frameworks
- Installation instructions for optional providers (anthropic, gemini, all extras)
- SQL injection and file scanning documented in README

### Changed
- Updated backend tier description: all tiers now get full 9-layer cascade (L1-L8)

## [1.0.0] - 2026-01-15

### Added
- Initial release
- Drop-in OpenAI, Anthropic, and Gemini client wrappers
- Automatic prompt scanning via Shrike backend
- Fail-open and fail-closed modes
- Async support for OpenAI
- SQL injection scanning
- File path and content scanning
- Response sanitization (IP protection)
