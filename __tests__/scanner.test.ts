import { beforeAll, afterAll, beforeEach, afterEach, describe, test, expect } from 'bun:test';
import { scanner } from 'src';
import { isValidCachedVulnerability, isValidVulnerability, shouldSkipScan } from '@utils/helpers';

const createMockPackage = (name: string, version: string) => {
	return {
		name,
		version,
		tarball: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`,
		requestedRange: `^${version}`,
	};
};

const VULN_ID_EVENT_STREAM = 'GHSA-mh6f-8j2x-4483';
const VULN_ID_CACHE_ONLY = 'GHSA-cache-only';
const VULN_ID_CACHE_MISMATCH = 'GHSA-cache-mismatch';

const VULNERABILITY_DETAILS: Record<string, OSVVulnerability> = {
	[VULN_ID_EVENT_STREAM]: {
		id: VULN_ID_EVENT_STREAM,
		modified: '2021-09-15T20:08:26Z',
		summary: 'Critical vulnerability affecting event-stream and flatmap-stream',
		details:
			'Critical severity vulnerability that affects event-stream and flatmap-stream packages.',
		database_specific: { severity: 'CRITICAL' },
		severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
		references: [{ type: 'WEB', url: 'https://github.com/dominictarr/event-stream/issues/116' }],
	},
};

const PACKAGE_VULNERABILITY_IDS: Record<string, string[]> = {
	'event-stream@3.3.6': [VULN_ID_EVENT_STREAM],
	'cache-only-critical@1.0.0': [VULN_ID_CACHE_ONLY],
	'cache-mismatch@1.0.0': [VULN_ID_CACHE_MISMATCH],
};

const asJsonResponse = (data: unknown, status = 200): Response =>
	new Response(JSON.stringify(data), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});

const getUrlString = (input: string | URL | Request): string => {
	if (typeof input === 'string') return input;
	if (input instanceof URL) return input.toString();
	return input.url;
};

const parseRequestBody = (init?: RequestInit | BunFetchRequestInit): unknown => {
	if (!init?.body || typeof init.body !== 'string') return null;
	try {
		return JSON.parse(init.body);
	} catch {
		return null;
	}
};

const createMockOSVFetch = (baseFetch: typeof fetch): typeof fetch => {
	const mockFetch = (async (
		input: Parameters<typeof fetch>[0],
		init?: Parameters<typeof fetch>[1],
	): ReturnType<typeof fetch> => {
		const url = new URL(getUrlString(input as string | URL | Request));
		const pathname = url.pathname;

		if (pathname === '/v1/querybatch') {
			const payload = parseRequestBody(init) as {
				queries?: Array<{ package?: { name?: string }; version?: string }>;
			};
			const queries = payload?.queries || [];
			const results = queries.map(query => {
				const packageName = query?.package?.name || '';
				const packageVersion = query?.version || '';
				const packageKey = `${packageName}@${packageVersion}`;
				const vulnerabilityIds = PACKAGE_VULNERABILITY_IDS[packageKey] || [];

				return {
					vulns: vulnerabilityIds.map(vulnerabilityId => ({
						id: vulnerabilityId,
						modified: VULNERABILITY_DETAILS[vulnerabilityId]?.modified,
					})),
				};
			});

			return asJsonResponse({ results });
		}

		if (pathname.startsWith('/v1/vulns/')) {
			const vulnerabilityId = decodeURIComponent(pathname.split('/').pop() || '');
			const vulnerability = VULNERABILITY_DETAILS[vulnerabilityId];
			if (!vulnerability) return asJsonResponse({ message: 'Not found' }, 404);
			return asJsonResponse(vulnerability);
		}

		if (pathname === '/v1/query') {
			const payload = parseRequestBody(init) as { package?: { name?: string }; version?: string };
			const packageName = payload?.package?.name || '';
			const packageVersion = payload?.version || '';
			const packageKey = `${packageName}@${packageVersion}`;
			const vulnerabilityIds = PACKAGE_VULNERABILITY_IDS[packageKey] || [];
			const vulnerabilities = vulnerabilityIds
				.map(vulnerabilityId => VULNERABILITY_DETAILS[vulnerabilityId])
				.filter((vulnerability): vulnerability is OSVVulnerability => Boolean(vulnerability));

			return asJsonResponse({ vulns: vulnerabilities });
		}

		return asJsonResponse({ message: `Unhandled endpoint: ${pathname}` }, 404);
	}) as typeof fetch;

	mockFetch.preconnect = baseFetch.preconnect.bind(baseFetch);
	return mockFetch;
};

const originalFetch = globalThis.fetch;
const originalXdgCacheHome = process.env.XDG_CACHE_HOME;
const originalStdinIsTTYDescriptor = Object.getOwnPropertyDescriptor(process.stdin, 'isTTY');
const originalStdoutIsTTYDescriptor = Object.getOwnPropertyDescriptor(process.stdout, 'isTTY');
const testCacheHome = `/tmp/bun-guard-tests-${Date.now()}-${Math.random().toString(16).slice(2)}`;

const setTTYAvailability = (isTTY: boolean): void => {
	Object.defineProperty(process.stdin, 'isTTY', {
		configurable: true,
		value: isTTY,
	});
	Object.defineProperty(process.stdout, 'isTTY', {
		configurable: true,
		value: isTTY,
	});
};

const restoreTTYAvailability = (): void => {
	if (originalStdinIsTTYDescriptor) {
		Object.defineProperty(process.stdin, 'isTTY', originalStdinIsTTYDescriptor);
	} else {
		delete (process.stdin as { isTTY?: boolean }).isTTY;
	}

	if (originalStdoutIsTTYDescriptor) {
		Object.defineProperty(process.stdout, 'isTTY', originalStdoutIsTTYDescriptor);
	} else {
		delete (process.stdout as { isTTY?: boolean }).isTTY;
	}
};

beforeAll(async () => {
	process.env.XDG_CACHE_HOME = testCacheHome;
	globalThis.fetch = createMockOSVFetch(originalFetch);

	await Bun.write(
		`${testCacheHome}/bun-guard/osv-vuln-cache.json`,
		JSON.stringify({
			entries: {
				[VULN_ID_CACHE_ONLY]: {
					fetchedAt: Date.now(),
					modified: '2026-01-01T00:00:00Z',
					vulnerability: {
						id: VULN_ID_CACHE_ONLY,
						modified: '2026-01-01T00:00:00Z',
						summary: 'Critical severity supplied only by local cache',
						database_specific: { severity: 'CRITICAL' },
						severity: [
							{
								type: 'CVSS_V3',
								score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
							},
						],
					},
				},
				[VULN_ID_CACHE_MISMATCH]: {
					fetchedAt: Date.now(),
					modified: '2026-01-01T00:00:00Z',
					vulnerability: {
						id: 'GHSA-cache-poisoned',
						modified: '2026-01-01T00:00:00Z',
						summary: 'Poisoned cache entry with mismatched id',
						database_specific: { severity: 'CRITICAL' },
					},
				},
			},
		}),
	);
});

beforeEach(() => {
	setTTYAvailability(true);
});

afterAll(() => {
	globalThis.fetch = originalFetch;
	restoreTTYAvailability();
	if (typeof originalXdgCacheHome === 'string') {
		process.env.XDG_CACHE_HOME = originalXdgCacheHome;
	} else {
		delete process.env.XDG_CACHE_HOME;
	}
});

describe('Security Scanner', () => {
	test('should flag when resolved version does not satisfy requestedRange', async () => {
		const packageWithMismatchedRange = createMockPackage('semver-mismatch-test', '1.0.0');
		(packageWithMismatchedRange as any).requestedRange = '^2.0.0';

		const scanResults = await scanner.scan({ packages: [packageWithMismatchedRange] });

		expect(
			scanResults.some(
				result => result.package === 'semver-mismatch-test' && result.level === 'fatal',
			),
		).toBe(true);
	});

	test('should not treat disk-cached severity as fatal blocking data', async () => {
		const scanResults = await scanner.scan({
			packages: [
				createMockPackage('cache-only-critical', '1.0.0'),
				createMockPackage('cache-mismatch', '1.0.0'),
			],
		});

		const cacheOnlyAdvisory = scanResults.find(
			advisory => advisory.package === 'cache-only-critical',
		);
		expect(cacheOnlyAdvisory?.level).toBe('warn');
		expect(cacheOnlyAdvisory?.description).toBe(
			'Critical severity supplied only by local cache',
		);

		const mismatchAdvisory = scanResults.find(advisory => advisory.package === 'cache-mismatch');
		expect(mismatchAdvisory?.level).toBe('warn');
		expect(mismatchAdvisory?.description).toBe(`Vulnerability ${VULN_ID_CACHE_MISMATCH}`);
	});

	test('should detect known vulnerable package (event-stream 3.3.6)', async () => {
		const packagesToScan = [createMockPackage('event-stream', '3.3.6')];

		const scanResults = await scanner.scan({ packages: packagesToScan });

		expect(scanResults.length).toBeGreaterThan(0);
		expect(scanResults[0]?.package).toBe('event-stream');
		expect(scanResults[0]?.level).toBe('fatal');
		expect(scanResults[0]?.description).toContain('event-stream');
	});

	test('should not flag safe version of event-stream', async () => {
		const packagesToScan = [createMockPackage('event-stream', '3.3.4')];

		const scanResults = await scanner.scan({ packages: packagesToScan });

		expect(scanResults.length).toBe(0);
	});

	test('should not flag popular safe packages', async () => {
		const packagesToScan = [
			createMockPackage('lodash', '4.17.21'),
			createMockPackage('react', '18.2.0'),
		];

		const scanResults = await scanner.scan({ packages: packagesToScan });

		expect(scanResults.length).toBe(0);
	});

	test('should handle non-existent packages gracefully', async () => {
		const packagesToScan = [createMockPackage('this-package-does-not-exist-12345', '1.0.0')];

		const scanResults = await scanner.scan({ packages: packagesToScan });

		expect(scanResults.length).toBe(0);
	});

	test('should detect vulnerabilities in mixed package list', async () => {
		const packagesToScan = [
			createMockPackage('lodash', '4.17.21'),
			createMockPackage('event-stream', '3.3.6'),
			createMockPackage('react', '18.2.0'),
		];

		const scanResults = await scanner.scan({ packages: packagesToScan });

		expect(scanResults.length).toBe(1);
		expect(scanResults[0]?.package).toBe('event-stream');
		expect(scanResults[0]?.level).toBe('fatal');
	});

	test('should fall back to individual queries when batch query returns non-2xx', async () => {
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
			const packagesToScan = [
				createMockPackage('lodash', '4.17.21'),
				createMockPackage('event-stream', '3.3.6'),
			];

			const scanResults = await scanner.scan({ packages: packagesToScan });

			expect(individualQueryCount).toBe(2);
			expect(scanResults.length).toBe(1);
			expect(scanResults[0]?.package).toBe('event-stream');
			expect(scanResults[0]?.level).toBe('fatal');
		} finally {
			globalThis.fetch = previousFetch;
		}
	});

	test('should fall back to individual queries when batch query returns invalid payload', async () => {
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
			const packagesToScan = [
				createMockPackage('lodash', '4.17.21'),
				createMockPackage('event-stream', '3.3.6'),
			];

			const scanResults = await scanner.scan({ packages: packagesToScan });

			expect(individualQueryCount).toBe(2);
			expect(scanResults.length).toBe(1);
			expect(scanResults[0]?.package).toBe('event-stream');
			expect(scanResults[0]?.level).toBe('fatal');
		} finally {
			globalThis.fetch = previousFetch;
		}
	});

	test('should fall back to individual queries when batch query returns fewer results than requested', async () => {
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
			const packagesToScan = [
				createMockPackage('lodash', '4.17.21'),
				createMockPackage('event-stream', '3.3.6'),
			];

			const scanResults = await scanner.scan({ packages: packagesToScan });

			expect(individualQueryCount).toBe(2);
			expect(scanResults.length).toBe(1);
			expect(scanResults[0]?.package).toBe('event-stream');
			expect(scanResults[0]?.level).toBe('fatal');
		} finally {
			globalThis.fetch = previousFetch;
		}
	});

	test('should preserve batch vulnerability IDs when detail hydration and individual fallback miss', async () => {
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

	test('should pass timeout signals to OSV batch, detail, and individual query requests', async () => {
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

	test('should warn and fall back to individual queries when batch query times out', async () => {
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

	test('should return correct advisory structure', async () => {
		const packagesToScan = [createMockPackage('event-stream', '3.3.6')];

		const scanResults = await scanner.scan({ packages: packagesToScan });

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

	test('should handle empty package list', async () => {
		const emptyPackageList: Bun.Security.Package[] = [];

		const scanResults = await scanner.scan({ packages: emptyPackageList });

		expect(scanResults).toEqual([]);
	});

	test('should complete scan within reasonable time', async () => {
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

	test('scanner should have correct version', () => {
		expect(scanner.version).toBe('1');
		expect(typeof scanner.scan).toBe('function');
	});

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

	test('cache validators reject mismatched ids and malformed optional fields', () => {
		expect(
			isValidCachedVulnerability(
				{
					fetchedAt: Date.now(),
					vulnerability: { id: 'GHSA-other' },
				},
				'GHSA-expected',
			),
		).toBe(false);

		expect(
			isValidVulnerability({
				id: 'GHSA-invalid-severity',
				severity: [{ type: 'CVSS_V3', score: 9.8 }],
			}),
		).toBe(false);

		expect(
			isValidVulnerability({
				id: 'GHSA-invalid-reference',
				references: [{ type: 'WEB', url: null }],
			}),
		).toBe(false);
	});

	test.each([['true'], ['1']])('should skip scan when CI="%s" is detected', async ciValue => {
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

	test('should skip scan when CI is unset and TTY is unavailable', async () => {
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

const createMockBunFile = (content: string): ReturnType<typeof Bun.file> => {
	return {
		text: () => Promise.resolve(content),
		json: () => Promise.resolve(JSON.parse(content)),
	} as unknown as ReturnType<typeof Bun.file>;
};

describe('Semver Override', () => {
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

	test('should produce warn when mismatched package is listed in overrides', async () => {
		const pkg = createMockPackage('overridden-pkg', '1.0.0');
		(pkg as any).requestedRange = '^2.0.0';

		const scanResults = await scanner.scan({ packages: [pkg] });

		const advisory = scanResults.find(r => r.package === 'overridden-pkg');
		expect(advisory).toBeDefined();
		expect(advisory!.level).toBe('warn');
		expect(advisory!.description).toContain('allowed via overrides/resolutions');
	});

	test('should produce warn when mismatched package is listed in resolutions', async () => {
		const pkg = createMockPackage('resolved-pkg', '1.0.0');
		(pkg as any).requestedRange = '^2.0.0';

		const scanResults = await scanner.scan({ packages: [pkg] });

		const advisory = scanResults.find(r => r.package === 'resolved-pkg');
		expect(advisory).toBeDefined();
		expect(advisory!.level).toBe('warn');
		expect(advisory!.description).toContain('allowed via overrides/resolutions');
	});

	test('should still produce fatal when mismatched package is not in overrides or resolutions', async () => {
		const pkg = createMockPackage('non-overridden-pkg', '1.0.0');
		(pkg as any).requestedRange = '^2.0.0';

		const scanResults = await scanner.scan({ packages: [pkg] });

		const advisory = scanResults.find(r => r.package === 'non-overridden-pkg');
		expect(advisory).toBeDefined();
		expect(advisory!.level).toBe('fatal');
		expect(advisory!.description).not.toContain('allowed via overrides/resolutions');
	});

	test('should produce correct advisory level for each package independently', async () => {
		const overriddenPkg = createMockPackage('overridden-pkg', '1.0.0');
		(overriddenPkg as any).requestedRange = '^2.0.0';

		const nonOverriddenPkg = createMockPackage('non-overridden-pkg', '1.0.0');
		(nonOverriddenPkg as any).requestedRange = '^2.0.0';

		const scanResults = await scanner.scan({ packages: [overriddenPkg, nonOverriddenPkg] });

		const overriddenAdvisory = scanResults.find(r => r.package === 'overridden-pkg');
		const nonOverriddenAdvisory = scanResults.find(r => r.package === 'non-overridden-pkg');

		expect(overriddenAdvisory?.level).toBe('warn');
		expect(nonOverriddenAdvisory?.level).toBe('fatal');
	});
});

describe('Scanner Integration', () => {
	test('should handle API failures gracefully', async () => {
		const packagesToScan = [createMockPackage('', '')];

		const scanResults = await scanner.scan({ packages: packagesToScan });
		expect(Array.isArray(scanResults)).toBe(true);
	});
});
