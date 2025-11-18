# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.2.1]: https://github.com/AHaldner/bun-guard/releases/tag/v1.2.1
[1.2.0]: https://github.com/AHaldner/bun-guard/releases/tag/v1.2.0
[1.1.0]: https://github.com/AHaldner/bun-guard/releases/tag/v1.1.0
[1.0.0]: https://github.com/AHaldner/bun-guard/releases/tag/v1.0.0
