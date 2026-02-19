# Changelog

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
