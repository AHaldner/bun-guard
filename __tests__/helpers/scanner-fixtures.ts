export const VULN_ID_EVENT_STREAM = 'GHSA-mh6f-8j2x-4483';
export const VULN_ID_CACHE_ONLY = 'GHSA-cache-only';
export const VULN_ID_CACHE_MISMATCH = 'GHSA-cache-mismatch';

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

export const createMockPackage = (name: string, version: string): Bun.Security.Package => ({
	name,
	version,
	tarball: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`,
	requestedRange: `^${version}`,
});

export const asJsonResponse = (data: unknown, status = 200): Response =>
	new Response(JSON.stringify(data), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});

export const getUrlString = (input: string | URL | Request): string => {
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

export const createMockOSVFetch = (baseFetch: typeof fetch): typeof fetch => {
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

export const createMockBunFile = (content: string): ReturnType<typeof Bun.file> => {
	return {
		text: () => Promise.resolve(content),
		json: () => Promise.resolve(JSON.parse(content)),
	} as unknown as ReturnType<typeof Bun.file>;
};

export const setTTYAvailability = (isTTY: boolean): void => {
	Object.defineProperty(process.stdin, 'isTTY', {
		configurable: true,
		value: isTTY,
	});
	Object.defineProperty(process.stdout, 'isTTY', {
		configurable: true,
		value: isTTY,
	});
};

export const restoreTTYAvailability = (
	originalStdinIsTTYDescriptor: PropertyDescriptor | undefined,
	originalStdoutIsTTYDescriptor: PropertyDescriptor | undefined,
): void => {
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

export const writeCacheTrustFixture = async (testCacheHome: string): Promise<void> => {
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
};
