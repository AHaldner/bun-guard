import { beforeAll, afterAll, describe, test, expect } from 'bun:test';
import { scanner } from 'src';

const createMockPackage = (name: string, version: string) => {
	return {
		name,
		version,
		tarball: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`,
		requestedRange: `^${version}`,
	};
};

const VULN_ID_EVENT_STREAM = 'GHSA-mh6f-8j2x-4483';

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

beforeAll(() => {
	const testCacheHome = `/tmp/bun-guard-tests-${Date.now()}-${Math.random().toString(16).slice(2)}`;
	process.env.XDG_CACHE_HOME = testCacheHome;
	globalThis.fetch = createMockOSVFetch(originalFetch);
});

afterAll(() => {
	globalThis.fetch = originalFetch;
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
});

describe('Scanner Integration', () => {
	test('should handle API failures gracefully', async () => {
		const packagesToScan = [createMockPackage('', '')];

		const scanResults = await scanner.scan({ packages: packagesToScan });
		expect(Array.isArray(scanResults)).toBe(true);
	});
});
