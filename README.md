# Bun Guard — OSV‑Powered Security Scanner for Bun

`@tihn/bun-guard` is a security scanner for Bun’s package installation flow. It checks every package being installed against the Open Source Vulnerabilities (OSV) database and returns advisories that can stop or gate installations based on severity.

📦 Package: `@tihn/bun-guard`

📚 Scanner API docs: <https://bun.com/docs/install/security-scanner-api>

## What It Does

For each package (name + version) that Bun plans to install, Bun Guard:

1. Queries OSV (`https://api.osv.dev/v1/query`) for known vulnerabilities.
2. Maps each finding to an advisory with a severity level.
3. Returns all advisories to Bun to determine whether to continue.

Advisories are always shown to the user. Fatal advisories stop installation immediately, while warnings may allow the user to continue depending on TTY and settings.

## Advisory Rules

- Fatal (`level: 'fatal'`)
  - OSV marks a vulnerability as CRITICAL, or
  - CVSS v3 impact indicates High for Confidentiality, Integrity, or Availability (C:H, I:H, or A:H)

- Warning (`level: 'warn'`)
  - Any other detected vulnerability

Each advisory includes the package name, a description (summary/details), and a reference URL when available.

## Usage

1) Install the scanner in your project:

```bash
bun add -D @tihn/bun-guard
```

2) Configure Bun to use the scanner in your `bunfig.toml`.

See Bun’s Security Scanner configuration guide for the exact configuration keys and examples:
<https://bun.com/docs/install/security-scanner-api>

Once configured, Bun will call the scanner’s exported `scanner` during `bun install`.

## Behavior and Failure Modes

- Network: The scanner queries OSV over HTTPS. If the API call fails or returns a non‑OK status, Bun Guard currently returns an empty advisory list for that package (installation proceeds).
- Performance: Packages are queried sequentially. Typical scans remain fast; the test suite asserts completion within a reasonable time window for a small set of packages.

## Development

- Build and typecheck: handled by Bun + TypeScript (`tsconfig.json`).
- Test:

```bash
bun test
```

The tests cover expected fatal detection for `event-stream@3.3.6`, benign popular packages, empty inputs, and API failure handling.

## Publishing

Publish to npm:

```bash
bun publish
```

To test locally before publishing, use `bun link`:

```bash
# In this repo
bun link

# In a separate test project
bun link @tihn/bun-guard
```

## API Surface

This package exports a single named export:

```ts
export const scanner: Scanner
```

Where `Scanner` follows Bun’s Security Scanner API (version `"1"`). See `src/types/scanner-types.d.ts` for local type shapes.

## Limitations

- OSV coverage: Advisories depend on OSV’s dataset. Not all risks (e.g., protestware, license issues) are represented.
- No local caching: Queries are performed at install time without persistent caching.
- Conservative failure handling: Network/API errors return no advisories rather than failing the install.

## Changelog

See `CHANGELOG.md` for release notes. Current version: `1.0.0`.

## License

MIT © Andrin Haldner

## Support

- Bun Security Scanner API: <https://bun.com/docs/install/security-scanner-api>
- Issues and contributions: open an issue or PR on this repository.
