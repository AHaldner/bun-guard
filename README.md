# 🛡️ Bun Guard

Security scanner for Bun that checks packages against the [OSV vulnerability database](https://osv.dev) during installation.

## Installation

```bash
bun add -D @tihn/bun-guard
```

## Configuration

Add to your `bunfig.toml`:

```toml
[install.security]
scanner = "@tihn/bun-guard"
```

That's it! The scanner will now run automatically during `bun install`.

## What It Does

For each package during installation, Bun Guard:

- ✅ **Validates semver ranges** — Ensures resolved versions match requested ranges
- 🔍 **Queries OSV database** — Checks for known vulnerabilities via batch API
- ⚡ **Evaluates severity** — Maps CVSS scores to fatal/warn levels
- 🚨 **Reports advisories** — Returns security findings to Bun
- 🤖 **Skips in CI environments** — Automatically detects `CI=true` and skips the scan, since TTY access is required

### Severity Levels

- **Fatal** (`level: 'fatal'`) — Stops installation
  - OSV marks vulnerability as CRITICAL
  - CVSS v3 has High impact (C:H, I:H, or A:H)
  - Semver range mismatch

- **Warning** (`level: 'warn'`) — Allows installation to continue
  - Other detected vulnerabilities

## API Usage

The package exports a single scanner implementation:

```typescript
export const scanner: Bun.Security.Scanner;
```

Implements Bun's [Security Scanner API](https://bun.com/docs/install/security-scanner-api) version `1`.

### OSV Endpoints Used

- `POST /v1/querybatch` — Batch vulnerability lookup
- `GET /v1/vulns?ids=...` — Detailed vulnerability information
- `POST /v1/query` — Fallback for individual packages

## Development

### Running Tests

```bash
bun test
```

### Building

```bash
bun run build
```

The npm package publishes the generated `dist` files plus package metadata, license, readme, and changelog.

### Checking Package Contents

```bash
bun run package:check
```

This verifies that the package tarball excludes source, tests, benchmarks, workflows, and development config.

### Local Tarball Smoke Test

```bash
bun run build
TARBALL="$(npm_config_cache=/tmp/bun-guard-npm-cache npm pack --silent)"
TARBALL_PATH="$(pwd)/$TARBALL"

mkdir -p /tmp/bun-guard-smoke
cd /tmp/bun-guard-smoke
bun init -y
bun add -d "$TARBALL_PATH"
printf '[install.security]\nscanner = "@tihn/bun-guard"\n' > bunfig.toml
bun install
```

### Testing Locally

```bash
# In this repo
bun link

# In your test project
bun link @tihn/bun-guard
```

### Linting

```bash
bun run lint
bun run lint:fix
bun run format
bun run format:check
```

### Publishing

Publishing runs from GitHub Actions when a numeric semver tag is pushed:

```bash
git tag v1.5.0
git push origin v1.5.0
```

The tag must match `package.json`'s version with a leading `v`.

## Contributing

Contributions welcome! Please open an issue or pull request on [GitHub](https://github.com/AHaldner/bun-guard).

## Useful Links

- [OSV Database](https://osv.dev)
- [OSV API Documentation](https://osv.dev/docs/)
- [Bun Security Scanner API](https://bun.com/docs/install/security-scanner-api)
- [Open an Issue](https://github.com/AHaldner/bun-guard/issues)
- [Submit a Pull Request](https://github.com/AHaldner/bun-guard/pulls)

## Disclaimer

This project is not affiliated with, endorsed by, or in any way officially connected to the Bun project. All product names, logos, and brands are property of their respective owners.

## License

MIT © [Andrin Haldner](https://github.com/AHaldner)
