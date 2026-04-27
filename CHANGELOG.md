# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] - 2026-04-27

### Added

- Publish GitHub releases automatically from the matching `CHANGELOG.md` entry when a `v*` release tag is pushed
- Add npm package build and package-content verification scripts
- Add npm Trusted Publishing workflow support for GitHub Actions

### Changed

- Publish generated `dist` artifacts instead of shipping source, tests, benchmarks, workflows, and development config
- Build the package with Bun's bundler API and TypeScript declaration output
- Update GitHub Actions workflow actions to current major versions

## [1.3.1] - 2026-03-16

### Added

- Automatically skip the security scan when a CI environment is detected (`CI=true`), since TTY access is required

### Changed

- Replace unsafe type assertions with runtime validation guards

## [1.3.0] - 2026-02-26

### Added

- Benchmark command (`bun run bench:scan`) with scenario-based and fixed-count package runs (`--count`)
- Persistent vulnerability detail cache for OSV vulnerability lookups
- Deterministic scanner tests by mocking OSV API responses

### Changed

- Deduplicate package scan inputs by `name@version` before querying OSV batch API
- Split cache persistence/loading logic into a dedicated cache module
- Keep vulnerability severity fidelity by hydrating vulnerability details from OSV IDs

### Fixed

- Preserve already resolved vulnerabilities when fallback `queryOSV` calls fail, avoiding false negatives
- Prevent concurrent cache-load race conditions with shared in-flight cache initialization
- Add missing direct dev dependency `@eslint/js` to fix CI lint resolution

## [1.2.2] - 2025-12-17

### Fixed

- Downgrade semver mismatch advisory level from `fatal` to `warn` if the package is explicitly defined in `overrides` or `resolutions` in `package.json`

## [1.2.1] - 2025-11-18

### Fixed

- Ensure the scanner returns unique advisories so Bun doesn’t show duplicates
- Fix OSV client to fetch vulnerability details by ID using the correct endpoint and align batch response types with the OSV API

## [1.2.0] - 2025-11-14

### Added

- Semver validation to scanner to detect version mismatches
- ESLint configuration with TypeScript support
- CI workflows for linting and testing with proper permissions

### Changed

- Moved checkPackageVulnerabilities to separate osv-check module
- Simplified scanning logic and error handling
- Updated README for improved clarity and conciseness
- Improved variable naming throughout codebase for better readability

### Fixed

- Simplified error handling by removing unused error variables

## [1.1.0] - 2025-11-12

### Added

- Batch processing support for improved performance with multiple packages
- Fallback mechanism to individual queries when batch processing fails

### Changed

- Improve variable naming throughout codebase for better readability and maintainability
- Enhance code documentation with more descriptive variable names

## [1.0.0] - 2025-11-12

### Added

- Initial release with OSV.dev vulnerability database integration
- Security scanner implementation for Bun packages
- Comprehensive test suite with 10 test cases covering various scenarios
- Proper error handling and graceful degradation
- Enhance security advisory structure with detailed vulnerability information
- Severity mapping (CRITICAL → fatal, others → warn)

[1.4.0]: https://github.com/AHaldner/bun-guard/releases/tag/v1.4.0
[1.3.1]: https://github.com/AHaldner/bun-guard/releases/tag/v1.3.1
[1.3.0]: https://github.com/AHaldner/bun-guard/releases/tag/v1.3.0
[1.2.2]: https://github.com/AHaldner/bun-guard/releases/tag/v1.2.2
[1.2.1]: https://github.com/AHaldner/bun-guard/releases/tag/v1.2.1
[1.2.0]: https://github.com/AHaldner/bun-guard/releases/tag/v1.2.0
[1.1.0]: https://github.com/AHaldner/bun-guard/releases/tag/v1.1.0
[1.0.0]: https://github.com/AHaldner/bun-guard/releases/tag/v1.0.0
