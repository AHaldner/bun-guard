import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { scanner } from 'src';
import { queryOSVBatch } from '@api/osv-client';
import {
	asJsonResponse,
	createMockOSVFetch,
	createMockPackage,
	getUrlString,
	restoreTTYAvailability,
	setTTYAvailability,
} from './helpers/scanner-fixtures';

const originalFetch = globalThis.fetch;
const originalXdgCacheHome = process.env.XDG_CACHE_HOME;
const originalStdinIsTTYDescriptor = Object.getOwnPropertyDescriptor(process.stdin, 'isTTY');
const originalStdoutIsTTYDescriptor = Object.getOwnPropertyDescriptor(process.stdout, 'isTTY');
const testCacheHome = `/tmp/bun-guard-osv-client-tests-${Date.now()}-${Math.random()
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

describe('OSV vulnerability scanning', () => {
	test('detects a known vulnerable package', async () => {
		const scanResults = await scanner.scan({
			packages: [createMockPackage('event-stream', '3.3.6')],
		});

		expect(scanResults.length).toBeGreaterThan(0);
		expect(scanResults[0]?.package).toBe('event-stream');
		expect(scanResults[0]?.level).toBe('fatal');
		expect(scanResults[0]?.description).toContain('event-stream');
	});

	test('does not flag a safe version of a vulnerable package', async () => {
		const scanResults = await scanner.scan({
			packages: [createMockPackage('event-stream', '3.3.4')],
		});

		expect(scanResults.length).toBe(0);
	});

	test('does not flag popular safe packages', async () => {
		const scanResults = await scanner.scan({
			packages: [createMockPackage('lodash', '4.17.21'), createMockPackage('react', '18.2.0')],
		});

		expect(scanResults.length).toBe(0);
	});

	test('handles non-existent packages gracefully', async () => {
		const scanResults = await scanner.scan({
			packages: [createMockPackage('this-package-does-not-exist-12345', '1.0.0')],
		});

		expect(scanResults.length).toBe(0);
	});

	test('detects vulnerabilities in a mixed package list', async () => {
		const scanResults = await scanner.scan({
			packages: [
				createMockPackage('lodash', '4.17.21'),
				createMockPackage('event-stream', '3.3.6'),
				createMockPackage('react', '18.2.0'),
			],
		});

		expect(scanResults.length).toBe(1);
		expect(scanResults[0]?.package).toBe('event-stream');
		expect(scanResults[0]?.level).toBe('fatal');
	});
});

describe('OSV batch degradation', () => {
	test('falls back to individual queries when batch query returns non-2xx', async () => {
		let individualQueryCount = 0;
		const baseMockFetch = createMockOSVFetch(originalFetch);

		const failingBatchFetch = (async (
			input: Parameters<typeof fetch>[0],
			init?: Parameters<typeof fetch>[1],
		): ReturnType<typeof fetch> => {
			const url = new URL(getUrlString(input as string | URL | Request));

			if (url.pathname === '/v1/querybatch') {
				return asJsonResponse({ message: 'server error' }, 500);
			}

			if (url.pathname === '/v1/query') {
				individualQueryCount += 1;
			}

			return baseMockFetch(input, init);
		}) as typeof fetch;
		failingBatchFetch.preconnect = originalFetch.preconnect.bind(originalFetch);

		const previousFetch = globalThis.fetch;
		globalThis.fetch = failingBatchFetch;

		try {
			const scanResults = await scanner.scan({
				packages: [
					createMockPackage('lodash', '4.17.21'),
					createMockPackage('event-stream', '3.3.6'),
				],
			});

			expect(individualQueryCount).toBe(2);
			expect(scanResults.length).toBe(1);
			expect(scanResults[0]?.package).toBe('event-stream');
			expect(scanResults[0]?.level).toBe('fatal');
		} finally {
			globalThis.fetch = previousFetch;
		}
	});

	test('falls back to individual queries when batch query returns invalid payload', async () => {
		let individualQueryCount = 0;
		const baseMockFetch = createMockOSVFetch(originalFetch);

		const invalidBatchFetch = (async (
			input: Parameters<typeof fetch>[0],
			init?: Parameters<typeof fetch>[1],
		): ReturnType<typeof fetch> => {
			const url = new URL(getUrlString(input as string | URL | Request));

			if (url.pathname === '/v1/querybatch') {
				return asJsonResponse({ unexpected: [] });
			}

			if (url.pathname === '/v1/query') {
				individualQueryCount += 1;
			}

			return baseMockFetch(input, init);
		}) as typeof fetch;
		invalidBatchFetch.preconnect = originalFetch.preconnect.bind(originalFetch);

		const previousFetch = globalThis.fetch;
		globalThis.fetch = invalidBatchFetch;

		try {
			const scanResults = await scanner.scan({
				packages: [
					createMockPackage('lodash', '4.17.21'),
					createMockPackage('event-stream', '3.3.6'),
				],
			});

			expect(individualQueryCount).toBe(2);
			expect(scanResults.length).toBe(1);
			expect(scanResults[0]?.package).toBe('event-stream');
			expect(scanResults[0]?.level).toBe('fatal');
		} finally {
			globalThis.fetch = previousFetch;
		}
	});

	test('falls back to individual queries when batch query returns fewer results than requested', async () => {
		let individualQueryCount = 0;
		const baseMockFetch = createMockOSVFetch(originalFetch);

		const truncatedBatchFetch = (async (
			input: Parameters<typeof fetch>[0],
			init?: Parameters<typeof fetch>[1],
		): ReturnType<typeof fetch> => {
			const url = new URL(getUrlString(input as string | URL | Request));

			if (url.pathname === '/v1/querybatch') {
				return asJsonResponse({ results: [{ vulns: [] }] });
			}

			if (url.pathname === '/v1/query') {
				individualQueryCount += 1;
			}

			return baseMockFetch(input, init);
		}) as typeof fetch;
		truncatedBatchFetch.preconnect = originalFetch.preconnect.bind(originalFetch);

		const previousFetch = globalThis.fetch;
		globalThis.fetch = truncatedBatchFetch;

		try {
			const scanResults = await scanner.scan({
				packages: [
					createMockPackage('lodash', '4.17.21'),
					createMockPackage('event-stream', '3.3.6'),
				],
			});

			expect(individualQueryCount).toBe(2);
			expect(scanResults.length).toBe(1);
			expect(scanResults[0]?.package).toBe('event-stream');
			expect(scanResults[0]?.level).toBe('fatal');
		} finally {
			globalThis.fetch = previousFetch;
		}
	});

	test('preserves successful batch chunks and only falls back failed chunks', async () => {
		let individualQueryCount = 0;
		const baseMockFetch = createMockOSVFetch(originalFetch);

		const firstChunkFailingFetch = (async (
			input: Parameters<typeof fetch>[0],
			init?: Parameters<typeof fetch>[1],
		): ReturnType<typeof fetch> => {
			const url = new URL(getUrlString(input as string | URL | Request));

			if (url.pathname === '/v1/querybatch') {
				const payload = JSON.parse(String(init?.body)) as OSVBatchRequest;
				if (payload.queries.length === 100) {
					return asJsonResponse({ message: 'server error' }, 500);
				}
			}

			if (url.pathname === '/v1/query') {
				individualQueryCount += 1;
			}

			return baseMockFetch(input, init);
		}) as typeof fetch;
		firstChunkFailingFetch.preconnect = originalFetch.preconnect.bind(originalFetch);

		const previousFetch = globalThis.fetch;
		globalThis.fetch = firstChunkFailingFetch;

		try {
			const packagesToScan = [
				...Array.from({ length: 100 }, (_, index) =>
					createMockPackage(`safe-package-${index}`, '1.0.0'),
				),
				createMockPackage('event-stream', '3.3.6'),
			];

			const scanResults = await scanner.scan({ packages: packagesToScan });

			expect(individualQueryCount).toBe(100);
			expect(scanResults.length).toBe(1);
			expect(scanResults[0]?.package).toBe('event-stream');
		} finally {
			globalThis.fetch = previousFetch;
		}
	});

	test('runs individual fallback queries with bounded concurrency', async () => {
		let activeIndividualQueries = 0;
		let maxActiveIndividualQueries = 0;

		const concurrentFallbackFetch = (async (
			input: Parameters<typeof fetch>[0],
			_init: Parameters<typeof fetch>[1],
		): ReturnType<typeof fetch> => {
			const url = new URL(getUrlString(input as string | URL | Request));

			if (url.pathname === '/v1/querybatch') {
				return asJsonResponse({ message: 'server error' }, 500);
			}

			if (url.pathname === '/v1/query') {
				activeIndividualQueries += 1;
				maxActiveIndividualQueries = Math.max(maxActiveIndividualQueries, activeIndividualQueries);

				await new Promise(resolve => setTimeout(resolve, 5));
				activeIndividualQueries -= 1;

				return asJsonResponse({ vulns: [] });
			}

			return asJsonResponse({ message: `Unhandled endpoint: ${url.pathname}` }, 404);
		}) as typeof fetch;
		concurrentFallbackFetch.preconnect = originalFetch.preconnect.bind(originalFetch);

		const previousFetch = globalThis.fetch;
		globalThis.fetch = concurrentFallbackFetch;

		try {
			await queryOSVBatch(
				Array.from({ length: 12 }, (_, index) =>
					createMockPackage(`fallback-package-${index}`, '1.0.0'),
				),
			);

			expect(maxActiveIndividualQueries).toBeGreaterThan(1);
			expect(maxActiveIndividualQueries).toBeLessThanOrEqual(8);
		} finally {
			globalThis.fetch = previousFetch;
		}
	});

	test('preserves batch vulnerability IDs when detail hydration and individual fallback miss', async () => {
		const batchOnlyVulnerabilityId = 'GHSA-batch-only';

		const unresolvedDetailsFetch = (async (
			input: Parameters<typeof fetch>[0],
			_init: Parameters<typeof fetch>[1],
		): ReturnType<typeof fetch> => {
			const url = new URL(getUrlString(input as string | URL | Request));

			if (url.pathname === '/v1/querybatch') {
				return asJsonResponse({
					results: [{ vulns: [{ id: batchOnlyVulnerabilityId }] }],
				});
			}

			if (url.pathname.startsWith('/v1/vulns/')) {
				return asJsonResponse({ message: 'Not found' }, 404);
			}

			if (url.pathname === '/v1/query') {
				return asJsonResponse({ vulns: [] });
			}

			return asJsonResponse({ message: `Unhandled endpoint: ${url.pathname}` }, 404);
		}) as typeof fetch;
		unresolvedDetailsFetch.preconnect = originalFetch.preconnect.bind(originalFetch);

		const previousFetch = globalThis.fetch;
		globalThis.fetch = unresolvedDetailsFetch;

		try {
			const scanResults = await scanner.scan({
				packages: [createMockPackage('event-stream', '3.3.6')],
			});

			expect(scanResults.length).toBe(1);
			expect(scanResults[0]?.package).toBe('event-stream');
			expect(scanResults[0]?.level).toBe('warn');
			expect(scanResults[0]?.description).toBe(`Vulnerability ${batchOnlyVulnerabilityId}`);
		} finally {
			globalThis.fetch = previousFetch;
		}
	});
});

describe('OSV request timeouts', () => {
	test('passes timeout signals to OSV batch, detail, and individual query requests', async () => {
		const batchOnlyVulnerabilityId = 'GHSA-timeout-signal';
		const endpointsWithTimeoutSignals = new Set<string>();

		const signalRecordingFetch = (async (
			input: Parameters<typeof fetch>[0],
			init?: Parameters<typeof fetch>[1],
		): ReturnType<typeof fetch> => {
			const url = new URL(getUrlString(input as string | URL | Request));

			if (init?.signal instanceof AbortSignal) {
				if (url.pathname.startsWith('/v1/vulns/')) {
					endpointsWithTimeoutSignals.add('/v1/vulns/:id');
				} else {
					endpointsWithTimeoutSignals.add(url.pathname);
				}
			}

			if (url.pathname === '/v1/querybatch') {
				return asJsonResponse({
					results: [{ vulns: [{ id: batchOnlyVulnerabilityId }] }],
				});
			}

			if (url.pathname.startsWith('/v1/vulns/')) {
				return asJsonResponse({ message: 'Not found' }, 404);
			}

			if (url.pathname === '/v1/query') {
				return asJsonResponse({ vulns: [] });
			}

			return asJsonResponse({ message: `Unhandled endpoint: ${url.pathname}` }, 404);
		}) as typeof fetch;
		signalRecordingFetch.preconnect = originalFetch.preconnect.bind(originalFetch);

		const previousFetch = globalThis.fetch;
		globalThis.fetch = signalRecordingFetch;

		try {
			await scanner.scan({
				packages: [createMockPackage('event-stream', '3.3.6')],
			});

			expect(endpointsWithTimeoutSignals.has('/v1/querybatch')).toBe(true);
			expect(endpointsWithTimeoutSignals.has('/v1/vulns/:id')).toBe(true);
			expect(endpointsWithTimeoutSignals.has('/v1/query')).toBe(true);
		} finally {
			globalThis.fetch = previousFetch;
		}
	});

	test('warns and falls back to individual queries when batch query times out', async () => {
		const originalTimeoutMs = Bun.env.BUN_GUARD_OSV_REQUEST_TIMEOUT_MS;
		const originalConsoleWarn = console.warn;
		const warnings: string[] = [];
		let individualQueryCount = 0;
		const baseMockFetch = createMockOSVFetch(originalFetch);

		const timeoutBatchFetch = (async (
			input: Parameters<typeof fetch>[0],
			init?: Parameters<typeof fetch>[1],
		): ReturnType<typeof fetch> => {
			const url = new URL(getUrlString(input as string | URL | Request));

			if (url.pathname === '/v1/querybatch') {
				return new Promise<Response>((_resolve, reject) => {
					init?.signal?.addEventListener('abort', () => {
						reject(new DOMException('The operation timed out.', 'TimeoutError'));
					});
				}) as ReturnType<typeof fetch>;
			}

			if (url.pathname === '/v1/query') {
				individualQueryCount += 1;
			}

			return baseMockFetch(input, init);
		}) as typeof fetch;
		timeoutBatchFetch.preconnect = originalFetch.preconnect.bind(originalFetch);

		const previousFetch = globalThis.fetch;
		globalThis.fetch = timeoutBatchFetch;
		Bun.env.BUN_GUARD_OSV_REQUEST_TIMEOUT_MS = '1';
		console.warn = (message?: unknown): void => {
			warnings.push(String(message));
		};

		try {
			const scanResults = await scanner.scan({
				packages: [
					createMockPackage('lodash', '4.17.21'),
					createMockPackage('event-stream', '3.3.6'),
				],
			});

			expect(individualQueryCount).toBe(2);
			expect(scanResults.length).toBe(1);
			expect(scanResults[0]?.package).toBe('event-stream');
			expect(warnings.some(message => message.includes('timed out'))).toBe(true);
		} finally {
			globalThis.fetch = previousFetch;
			console.warn = originalConsoleWarn;
			if (typeof originalTimeoutMs === 'string') {
				Bun.env.BUN_GUARD_OSV_REQUEST_TIMEOUT_MS = originalTimeoutMs;
			} else {
				delete Bun.env.BUN_GUARD_OSV_REQUEST_TIMEOUT_MS;
			}
		}
	});
});
