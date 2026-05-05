# 🛡️ Bun Guard

Security scanner for Bun installs. Bun Guard checks resolved npm packages against the [OSV vulnerability database](https://osv.dev) and reports advisories through Bun's Security Scanner API.

## Setup

```bash
bun add -D @tihn/bun-guard
```

Add the scanner to `bunfig.toml`:

```toml
[install.security]
scanner = "@tihn/bun-guard"
```

Bun Guard now runs during `bun install`.

## What It Checks

- 🚨 **Known vulnerabilities:** queries OSV with Bun's resolved package names and versions.
- 📦 **Semver mismatches:** warns when the resolved version does not satisfy the requested range.
- 🧭 **Override intent:** downgrades semver mismatch failures to warnings when the package is explicitly listed in `overrides` or `resolutions`.
- ⚡ **Severity:** treats OSV `CRITICAL` advisories and high-impact CVSS v3 advisories as fatal.

The scanner uses OSV's batch API first, falls back to individual package queries when needed, and caches vulnerability details locally to reduce repeated OSV requests.

## Advisory Levels

- `fatal`: stops installation for critical/high-impact vulnerabilities or unexpected semver resolutions.
- `warn`: allows installation to continue for lower-severity advisories or intentional overrides/resolutions.

## Runtime Notes

- Bun security scanners require TTY access, so Bun Guard skips scans in CI and non-TTY installs.
- OSV requests have a timeout budget. If OSV is slow or unavailable, Bun Guard warns and falls back where possible.
- Local cache data is treated as untrusted optimization data; fresh OSV responses decide blocking severity.

## API

```typescript
export const scanner: Bun.Security.Scanner;
```

Bun Guard implements Bun's [Security Scanner API](https://bun.com/docs/install/security-scanner-api) version `1`.

## Development

```bash
bun install
bun test
bun run lint
bun run format:check
bun run build
bun run package:check
```

The npm package publishes only `dist`, package metadata, license, readme, and changelog.

## Disclaimer

This project is not affiliated with, endorsed by, or in any way officially connected to the Bun project. All product names, logos, and brands are property of their respective owners.

## License

MIT © [Andrin Haldner](https://github.com/AHaldner)
