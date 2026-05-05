import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { scanner } from 'src';
import {
	createMockBunFile,
	createMockOSVFetch,
	createMockPackage,
	restoreTTYAvailability,
	setTTYAvailability,
} from './helpers/scanner-fixtures';

const originalFetch = globalThis.fetch;
const originalXdgCacheHome = process.env.XDG_CACHE_HOME;
const originalStdinIsTTYDescriptor = Object.getOwnPropertyDescriptor(process.stdin, 'isTTY');
const originalStdoutIsTTYDescriptor = Object.getOwnPropertyDescriptor(process.stdout, 'isTTY');
const testCacheHome = `/tmp/bun-guard-semver-tests-${Date.now()}-${Math.random()
	.toString(16)
	.slice(2)}`;

beforeAll(() => {
	process.env.XDG_CACHE_HOME = testCacheHome;
	globalThis.fetch = createMockOSVFetch(originalFetch);
});

beforeEach(() => {
	setTTYAvailability(true);
});

afterAll(() => {
	globalThis.fetch = originalFetch;
	restoreTTYAvailability(originalStdinIsTTYDescriptor, originalStdoutIsTTYDescriptor);

	if (typeof originalXdgCacheHome === 'string') {
		process.env.XDG_CACHE_HOME = originalXdgCacheHome;
	} else {
		delete process.env.XDG_CACHE_HOME;
	}
});

describe('Semver range checks', () => {
	const originalBunFile = Bun.file;
	let originalCI: string | undefined;

	beforeEach(() => {
		originalCI = Bun.env.CI;
		delete Bun.env.CI;

		Bun.file = ((path: string) => {
			if (path === 'package.json') {
				return createMockBunFile(
					JSON.stringify({
						overrides: { 'overridden-pkg': '1.0.0' },
						resolutions: { 'resolved-pkg': '1.0.0' },
					}),
				);
			}
			return originalBunFile(path);
		}) as typeof Bun.file;
	});

	afterEach(() => {
		Bun.file = originalBunFile;

		if (typeof originalCI === 'string') {
			Bun.env.CI = originalCI;
		} else {
			delete Bun.env.CI;
		}
	});

	test('flags when resolved version does not satisfy requestedRange', async () => {
		const packageWithMismatchedRange = createMockPackage('semver-mismatch-test', '1.0.0');
		(
			packageWithMismatchedRange as Bun.Security.Package & { requestedRange: string }
		).requestedRange = '^2.0.0';

		const scanResults = await scanner.scan({ packages: [packageWithMismatchedRange] });

		expect(
			scanResults.some(
				result => result.package === 'semver-mismatch-test' && result.level === 'fatal',
			),
		).toBe(true);
	});

	test('warns when mismatched package is listed in overrides', async () => {
		const pkg = createMockPackage('overridden-pkg', '1.0.0');
		(pkg as Bun.Security.Package & { requestedRange: string }).requestedRange = '^2.0.0';

		const scanResults = await scanner.scan({ packages: [pkg] });

		const advisory = scanResults.find(result => result.package === 'overridden-pkg');
		expect(advisory).toBeDefined();
		expect(advisory!.level).toBe('warn');
		expect(advisory!.description).toContain('allowed via overrides/resolutions');
	});

	test('warns when mismatched package is listed in resolutions', async () => {
		const pkg = createMockPackage('resolved-pkg', '1.0.0');
		(pkg as Bun.Security.Package & { requestedRange: string }).requestedRange = '^2.0.0';

		const scanResults = await scanner.scan({ packages: [pkg] });

		const advisory = scanResults.find(result => result.package === 'resolved-pkg');
		expect(advisory).toBeDefined();
		expect(advisory!.level).toBe('warn');
		expect(advisory!.description).toContain('allowed via overrides/resolutions');
	});

	test('keeps mismatched package fatal when not in overrides or resolutions', async () => {
		const pkg = createMockPackage('non-overridden-pkg', '1.0.0');
		(pkg as Bun.Security.Package & { requestedRange: string }).requestedRange = '^2.0.0';

		const scanResults = await scanner.scan({ packages: [pkg] });

		const advisory = scanResults.find(result => result.package === 'non-overridden-pkg');
		expect(advisory).toBeDefined();
		expect(advisory!.level).toBe('fatal');
		expect(advisory!.description).not.toContain('allowed via overrides/resolutions');
	});

	test('sets advisory levels independently for overridden and non-overridden packages', async () => {
		const overriddenPkg = createMockPackage('overridden-pkg', '1.0.0');
		(overriddenPkg as Bun.Security.Package & { requestedRange: string }).requestedRange = '^2.0.0';

		const nonOverriddenPkg = createMockPackage('non-overridden-pkg', '1.0.0');
		(nonOverriddenPkg as Bun.Security.Package & { requestedRange: string }).requestedRange =
			'^2.0.0';

		const scanResults = await scanner.scan({ packages: [overriddenPkg, nonOverriddenPkg] });

		const overriddenAdvisory = scanResults.find(result => result.package === 'overridden-pkg');
		const nonOverriddenAdvisory = scanResults.find(
			result => result.package === 'non-overridden-pkg',
		);

		expect(overriddenAdvisory?.level).toBe('warn');
		expect(nonOverriddenAdvisory?.level).toBe('fatal');
	});

	test('does not read package.json when all packages satisfy requested ranges', async () => {
		let packageJsonReadCount = 0;

		Bun.file = ((path: string) => {
			if (path === 'package.json') {
				packageJsonReadCount += 1;
				return createMockBunFile(JSON.stringify({}));
			}
			return originalBunFile(path);
		}) as typeof Bun.file;

		const scanResults = await scanner.scan({
			packages: [createMockPackage('safe-range-pkg', '1.0.0')],
		});

		expect(scanResults).toEqual([]);
		expect(packageJsonReadCount).toBe(0);
	});
});
