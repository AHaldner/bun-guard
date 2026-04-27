import { describe, expect, test } from 'bun:test';
import { formatReleaseNotes } from '../scripts/release-notes';

describe('release notes', () => {
	test('adds a Whats New heading before the matching changelog section', () => {
		const changelog = `# Changelog

## [1.4.0] - 2026-04-27

### Added

- Publish GitHub releases automatically

## [1.3.1] - 2026-03-16

### Fixed

- Previous fix
`;

		expect(formatReleaseNotes(changelog, 'v1.4.0')).toBe(`## What's New

### Added

- Publish GitHub releases automatically`);
	});
});
