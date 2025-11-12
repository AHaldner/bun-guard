# 🛡️ Bun Guard — OSV‑Powered Security Scanner for Bun

`@tihn/bun-guard` is a security scanner for Bun’s package installation flow. It checks every package being installed against the Open Source Vulnerabilities (OSV) database and returns advisories that can stop or gate installations based on severity.

## Usage

1. Install the scanner in your project:

```bash
bun add -D @tihn/bun-guard
```

2. Configure Bun to use the scanner in your `bunfig.toml`.

```toml
[install.security]
scanner = "@tihn/bun-guard"
```

Once configured, Bun will call the scanner’s exported `scanner` during `bun install`.

## What It Does

For each package (name + version) that Bun plans to install, Bun Guard:

1. Validates that the resolved version satisfies its requested semver range (when provided) using `Bun.semver.satisfies`; mismatches are reported as fatal advisories.
2. Queries OSV in batches (`https://api.osv.dev/v1/querybatch`) for known vulnerabilities, then fetches full details via `GET /v1/vulns`.
3. Maps each finding to an advisory with a severity level.
4. Returns all advisories to Bun to determine whether to continue.

Advisories are always shown to the user. Fatal advisories stop installation immediately, while warnings may allow the user to continue depending on TTY and settings.

## Advisory Rules

- Fatal (`level: 'fatal'`)
  - OSV marks a vulnerability as CRITICAL, or
  - CVSS v3 impact indicates High for Confidentiality, Integrity, or Availability (C:H, I:H, or A:H)

- Warning (`level: 'warn'`)
  - Any other detected vulnerability

Each advisory includes the package name, a description (summary/details), and a reference URL when available.

## Behavior and Failure Modes

- Network: The scanner queries OSV over HTTPS. If the API call fails or returns a non‑OK status, Bun Guard returns an empty advisory list for the affected packages (installation proceeds).
- Query strategy:
  - Primary: `POST /v1/querybatch` for all name@version pairs.
  - Enrichment: When batch results only include vulnerability IDs, resolve full records via `GET /v1/vulns?ids=...` (deduplicated and chunked).
  - Fallback: If enrichment fails for a batch, fall back to `POST /v1/query` per package to preserve correctness.
- Performance: Requests are chunked to keep payloads manageable. Batch + enrichment minimizes round‑trips while retaining full vulnerability details for severity evaluation.

## OSV Endpoints Used

- `POST https://api.osv.dev/v1/querybatch` — initial batch lookup by package and version.
- `GET  https://api.osv.dev/v1/vulns?ids=...` — resolves full vulnerability details for returned IDs.
- `POST https://api.osv.dev/v1/query` — per‑package fallback when enrichment cannot be resolved.

## Development

Build and type-check with Bun and TypeScript (configured via `tsconfig.json`).

Run tests with:

```bash
bun test
```

Tests verify:

- fatal detection for event-stream@3.3.6
- handling of common benign packages
- empty input behavior
- semver mismatch handling
- API failure handling


To test locally using `bun link`:

```bash
# In this repo
bun link

# In a separate test project
bun link @tihn/bun-guard
```

## API Surface

This package exports a single named export:

```ts
export const scanner: Bun.Security.Scanner
```

Where `Bun.Security.Scanner` follows Bun’s Security Scanner API (version `"1"`).

## Limitations

- OSV coverage: Advisories depend on OSV’s dataset. Not all risks (e.g., protestware, license issues) are represented.
- No local caching: Queries are performed at install time without persistent caching.
- Conservative failure handling: Network/API errors return no advisories rather than failing the install.

## Changelog

See `CHANGELOG.md` for release notes.

## License

MIT © Andrin Haldner

## Support

- Bun Security Scanner API: <https://bun.com/docs/install/security-scanner-api>
- Issues and contributions: open an issue or PR on this repository.
