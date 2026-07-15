# Changelog

All notable changes to this project will be documented here. The project uses
semantic versioning once tagged releases begin.

## Unreleased

### Added

- HTTP/1.1 last-byte synchronization and TLS HTTP/2 synchronized release.
- Status and response-body success matchers with configurable success budgets.
- Post-signal control probes and explicit JSON/text verdicts.
- Per-request error evidence, bounded body capture, fuzz targets, and local
  vulnerable-server integration tests.
- Cross-platform CI and tag-driven release packaging.

### Safety and correctness

- Response divergence is informational and no longer treated as proof of a
  race.
- Invalid, incomplete, and inconclusive runs use exit code 2.
- HTTP/2 response bodies are retained for body matching.
- HTTP/1.1 body reads are bounded and read failures are preserved.
- HTTP/2 peer frame, concurrency, and flow-control limits are enforced.
- Request metadata is validated before serialization to prevent line/header
  injection.
