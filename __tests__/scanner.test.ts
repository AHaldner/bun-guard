import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { scanner } from 'src';
import { shouldSkipScan } from '@utils/helpers';
import {
	createMockOSVFetch,
	createMockPackage,
	restoreTTYAvailability,
	setTTYAvailability,
} from './helpers/scanner-fixtures';

const originalFetch = globalThis.fetch;
const originalXdgCacheHome = process.env.XDG_CACHE_HOME;
const originalStdinIsTTYDescriptor = Object.getOwnPropertyDescriptor(process.stdin, 'isTTY');
const originalStdoutIsTTYDescriptor = Object.getOwnPropertyDescriptor(process.stdout, 'isTTY');
const testCacheHome = `/tmp/bun-guard-scanner-tests-${Date.now()}-${Math.random()
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

describe('Security Scanner', () => {
	test('has the expected scanner contract', () => {
		expect(scanner.version).toBe('1');
		expect(typeof scanner.scan).toBe('function');
	});

	test('handles an empty package list', async () => {
		const scanResults = await scanner.scan({ packages: [] });

		expect(scanResults).toEqual([]);
	});

	test('returns advisories with the expected shape', async () => {
		const scanResults = await scanner.scan({
			packages: [createMockPackage('event-stream', '3.3.6')],
		});

		expect(scanResults.length).toBeGreaterThan(0);

		const firstAdvisory = scanResults[0];
		expect(firstAdvisory).toBeDefined();
		expect(firstAdvisory!).toHaveProperty('level');
		expect(firstAdvisory!).toHaveProperty('package');
		expect(firstAdvisory!).toHaveProperty('url');
		expect(firstAdvisory!).toHaveProperty('description');
		expect(['fatal', 'warn']).toContain(firstAdvisory!.level);
		expect(typeof firstAdvisory!.package).toBe('string');
		expect(typeof firstAdvisory!.description).toBe('string');
		expect(firstAdvisory!.url === null || typeof firstAdvisory!.url === 'string').toBe(true);
	});

	test('completes scan within reasonable time', async () => {
		const packagesToScan = [
			createMockPackage('react', '18.2.0'),
			createMockPackage('vue', '3.3.0'),
			createMockPackage('lodash', '4.17.21'),
		];

		const scanStartTime = Date.now();
		const scanResults = await scanner.scan({ packages: packagesToScan });
		const elapsedDurationMs = Date.now() - scanStartTime;

		expect(elapsedDurationMs).toBeLessThan(10000);
		expect(Array.isArray(scanResults)).toBe(true);
	});

	test('handles API failures gracefully', async () => {
		const scanResults = await scanner.scan({
			packages: [createMockPackage('', '')],
		});

		expect(Array.isArray(scanResults)).toBe(true);
	});
});

describe('Scanner skip logic', () => {
	test.each([['true'], ['1']])('shouldSkipScan returns true when CI="%s"', ciValue => {
		expect(shouldSkipScan({ ciValue, stdinIsTTY: true, stdoutIsTTY: true })).toBe(true);
	});

	test('shouldSkipScan returns true when CI is unset and TTY is unavailable', () => {
		expect(shouldSkipScan({ stdinIsTTY: false, stdoutIsTTY: true })).toBe(true);
		expect(shouldSkipScan({ stdinIsTTY: true, stdoutIsTTY: false })).toBe(true);
	});

	test('shouldSkipScan returns false when CI is unset and TTY is available', () => {
		expect(shouldSkipScan({ ciValue: '', stdinIsTTY: true, stdoutIsTTY: true })).toBe(false);
	});

	test.each([['true'], ['1']])('skips scan when CI="%s" is detected', async ciValue => {
		const originalCI = Bun.env.CI;

		try {
			Bun.env.CI = ciValue;

			const scanResults = await scanner.scan({
				packages: [createMockPackage('event-stream', '3.3.6')],
			});

			expect(scanResults).toEqual([]);
		} finally {
			if (typeof originalCI === 'string') {
				Bun.env.CI = originalCI;
			} else {
				delete Bun.env.CI;
			}
		}
	});

	test('skips scan when CI is unset and TTY is unavailable', async () => {
		const originalCI = Bun.env.CI;
		let requestCount = 0;
		const previousFetch = globalThis.fetch;

		const countingFetch = (async (
			input: Parameters<typeof fetch>[0],
			init?: Parameters<typeof fetch>[1],
		): ReturnType<typeof fetch> => {
			requestCount += 1;
			return createMockOSVFetch(originalFetch)(input, init);
		}) as typeof fetch;
		countingFetch.preconnect = originalFetch.preconnect.bind(originalFetch);

		try {
			delete Bun.env.CI;
			setTTYAvailability(false);
			globalThis.fetch = countingFetch;

			const scanResults = await scanner.scan({
				packages: [createMockPackage('event-stream', '3.3.6')],
			});

			expect(scanResults).toEqual([]);
			expect(requestCount).toBe(0);
		} finally {
			globalThis.fetch = previousFetch;
			if (typeof originalCI === 'string') {
				Bun.env.CI = originalCI;
			} else {
				delete Bun.env.CI;
			}
		}
	});
});
