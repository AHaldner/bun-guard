import {
	getCachedVulnerabilityDetails,
	cacheVulnerabilityDetails,
	persistVulnerabilityCache,
} from '@cache/osv-vulnerability-cache';
import { isValidOSVBatchResponse, isValidOSVResponse, isValidVulnerability } from '@utils/helpers';
import { logger } from '@utils/logger';

const BATCH_SIZE = 100;
const BATCH_QUERY_CONCURRENCY = 4;
const FALLBACK_QUERY_CONCURRENCY = 8;
const VULN_DETAIL_CONCURRENCY = 12;
const DEFAULT_OSV_REQUEST_TIMEOUT_MS = 10_000;
const OSV_REQUEST_TIMEOUT_ENV = 'BUN_GUARD_OSV_REQUEST_TIMEOUT_MS';
const inFlightVulnerabilityRequests = new Map<string, Promise<OSVVulnerability | null>>();

class OSVBatchQueryError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'OSVBatchQueryError';
	}
}

const getOSVRequestTimeoutMs = (): number => {
	const configuredTimeoutMs = Number(Bun.env[OSV_REQUEST_TIMEOUT_ENV]);

	if (Number.isFinite(configuredTimeoutMs) && configuredTimeoutMs > 0) {
		return configuredTimeoutMs;
	}

	return DEFAULT_OSV_REQUEST_TIMEOUT_MS;
};

const isAbortError = (error: unknown): boolean => {
	if (!(error instanceof Error || error instanceof DOMException)) return false;

	return error.name === 'AbortError' || error.name === 'TimeoutError';
};

const fetchOSV = async (endpoint: string, init: Parameters<typeof fetch>[1]): Promise<Response> => {
	const timeoutMs = getOSVRequestTimeoutMs();

	try {
		return await fetch(`https://api.osv.dev${endpoint}`, {
			...init,
			signal: AbortSignal.timeout(timeoutMs),
		});
	} catch (error) {
		if (isAbortError(error)) {
			logger.warn(
				`OSV request to ${endpoint} timed out after ${timeoutMs}ms. Falling back where possible; vulnerability results may be incomplete.`,
			);
		}

		throw error;
	}
};

const runWithConcurrency = async <T>(
	items: T[],
	concurrency: number,
	worker: (item: T) => Promise<void>,
): Promise<void> => {
	if (items.length === 0) return;

	let currentIndex = 0;
	const workerCount = Math.min(concurrency, items.length);

	const workers = Array.from({ length: workerCount }, async () => {
		while (currentIndex < items.length) {
			const itemIndex = currentIndex;
			currentIndex += 1;
			const item = items[itemIndex];

			if (item === undefined) continue;
			await worker(item);
		}
	});

	await Promise.all(workers);
};

const fetchVulnerabilityById = async (id: string): Promise<OSVVulnerability | null> => {
	const inFlightRequest = inFlightVulnerabilityRequests.get(id);
	if (inFlightRequest) return inFlightRequest;

	const requestPromise = (async () => {
		return fetchOSV(`/v1/vulns/${encodeURIComponent(id)}`, {
			method: 'GET',
		})
			.then(async (response): Promise<OSVVulnerability | null> => {
				if (!response.ok) return null;

				const vulnerability = await response.json();
				return isValidVulnerability(vulnerability) ? vulnerability : null;
			})
			.catch(() => {
				return null;
			})
			.finally(() => inFlightVulnerabilityRequests.delete(id));
	})();

	inFlightVulnerabilityRequests.set(id, requestPromise);
	return requestPromise;
};

const fetchVulnDetailsByIds = async (ids: string[]): Promise<Map<string, OSVVulnerability>> => {
	const vulnerabilityDetailsMap = new Map<string, OSVVulnerability>();
	if (ids.length === 0) return vulnerabilityDetailsMap;

	await runWithConcurrency(ids, VULN_DETAIL_CONCURRENCY, async id => {
		const vulnerability = await fetchVulnerabilityById(id);
		if (vulnerability?.id) {
			vulnerabilityDetailsMap.set(vulnerability.id, vulnerability);
		}
	});

	return vulnerabilityDetailsMap;
};

const preserveUnresolvedVulnerabilityRefs = (
	vulnerabilityRefs: VulnerabilityRef[],
	resolvedVulnerabilities: OSVVulnerability[],
	fallbackVulnerabilities: OSVVulnerability[],
): OSVVulnerability[] => {
	const vulnerabilitiesById = new Map<string, OSVVulnerability>();

	for (const vulnerability of resolvedVulnerabilities) {
		vulnerabilitiesById.set(vulnerability.id, vulnerability);
	}

	for (const vulnerability of fallbackVulnerabilities) {
		vulnerabilitiesById.set(vulnerability.id, vulnerability);
	}

	for (const vulnerabilityRef of vulnerabilityRefs) {
		if (!vulnerabilitiesById.has(vulnerabilityRef.id)) {
			vulnerabilitiesById.set(vulnerabilityRef.id, { id: vulnerabilityRef.id });
		}
	}

	return [...vulnerabilitiesById.values()];
};

type PackageGroup = {
	packageInfo: Bun.Security.Package;
	resultIndexes: number[];
};

type FallbackPackageGroup = PackageGroup & {
	vulnerabilityRefs?: VulnerabilityRef[];
	resolvedVulnerabilities?: OSVVulnerability[];
};

const applyIndividualFallback = async (
	packageGroups: FallbackPackageGroup[],
	allResults: OSVVulnerability[][],
): Promise<void> => {
	await runWithConcurrency(packageGroups, FALLBACK_QUERY_CONCURRENCY, async packageGroup => {
		const fallbackVulnerabilities = await queryOSV(packageGroup.packageInfo);
		const vulnerabilitiesToReport = packageGroup.vulnerabilityRefs
			? preserveUnresolvedVulnerabilityRefs(
					packageGroup.vulnerabilityRefs,
					packageGroup.resolvedVulnerabilities || [],
					fallbackVulnerabilities,
				)
			: fallbackVulnerabilities;

		for (const resultIndex of packageGroup.resultIndexes) {
			allResults[resultIndex] = vulnerabilitiesToReport;
		}
	});
};

const resolveVulnerabilityDetails = async (
	vulnerabilityRefs: VulnerabilityRef[],
): Promise<Map<string, OSVVulnerability>> => {
	const resolvedVulnerabilityDetails = await getCachedVulnerabilityDetails(vulnerabilityRefs);
	const modifiedById = new Map<string, string | undefined>();

	for (const vulnerabilityRef of vulnerabilityRefs) {
		if (!modifiedById.has(vulnerabilityRef.id)) {
			modifiedById.set(vulnerabilityRef.id, vulnerabilityRef.modified);
		}
	}

	const missingVulnerabilityIds: string[] = [];

	for (const [id] of modifiedById) {
		const existingVulnerability = resolvedVulnerabilityDetails.get(id);
		if (existingVulnerability) continue;

		missingVulnerabilityIds.push(id);
	}

	if (missingVulnerabilityIds.length === 0) {
		return resolvedVulnerabilityDetails;
	}

	const fetchedVulnerabilityDetails = await fetchVulnDetailsByIds(missingVulnerabilityIds);
	cacheVulnerabilityDetails(fetchedVulnerabilityDetails, vulnerabilityRefs);

	for (const [id, vulnerability] of fetchedVulnerabilityDetails) {
		resolvedVulnerabilityDetails.set(id, vulnerability);
	}

	return resolvedVulnerabilityDetails;
};

const queryOSVBatch = async (packages: Bun.Security.Package[]): Promise<OSVVulnerability[][]> => {
	if (packages.length === 0) return [];

	const allResults: OSVVulnerability[][] = Array.from({ length: packages.length }, () => []);
	const packageGroupsByKey = new Map<string, PackageGroup>();

	for (let packageIndex = 0; packageIndex < packages.length; packageIndex++) {
		const packageInfo = packages[packageIndex];
		if (!packageInfo) continue;

		const packageKey = `${packageInfo.name}@${packageInfo.version}`;
		const existingGroup = packageGroupsByKey.get(packageKey);
		if (existingGroup) {
			existingGroup.resultIndexes.push(packageIndex);
		} else {
			packageGroupsByKey.set(packageKey, {
				packageInfo,
				resultIndexes: [packageIndex],
			});
		}
	}

	const packageGroups = [...packageGroupsByKey.values()];
	const packageGroupChunks: PackageGroup[][] = [];

	for (let i = 0; i < packageGroups.length; i += BATCH_SIZE) {
		packageGroupChunks.push(packageGroups.slice(i, i + BATCH_SIZE));
	}

	await runWithConcurrency(packageGroupChunks, BATCH_QUERY_CONCURRENCY, async packageGroupChunk => {
		try {
			const batchRequestBody: OSVBatchRequest = {
				queries: packageGroupChunk.map(({ packageInfo }) => ({
					version: packageInfo.version,
					package: { name: packageInfo.name, ecosystem: 'npm' },
				})),
			};

			const response = await fetchOSV('/v1/querybatch', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify(batchRequestBody),
			});

			if (!response.ok) {
				throw new OSVBatchQueryError(`OSV batch query failed with status ${response.status}`);
			}

			const batchResponseData = await response.json();
			if (!isValidOSVBatchResponse(batchResponseData)) {
				throw new OSVBatchQueryError('OSV batch query returned an invalid response payload');
			}

			const batchResults = batchResponseData.results || [];
			if (batchResults.length !== packageGroupChunk.length) {
				throw new OSVBatchQueryError(
					`OSV batch query returned ${batchResults.length} results for ${packageGroupChunk.length} queries`,
				);
			}

			const vulnerabilityRefsPerPackage: VulnerabilityRef[][] = [];
			const allVulnerabilityRefs: VulnerabilityRef[] = [];

			for (let packageOffset = 0; packageOffset < packageGroupChunk.length; packageOffset++) {
				const queryResult = batchResults[packageOffset];
				const vulnerabilityRefs = (queryResult?.vulns || [])
					.filter(
						vulnerability => typeof vulnerability.id === 'string' && vulnerability.id.length > 0,
					)
					.map(vulnerability => ({
						id: vulnerability.id,
						modified: vulnerability.modified,
					}));

				vulnerabilityRefsPerPackage.push(vulnerabilityRefs);
				allVulnerabilityRefs.push(...vulnerabilityRefs);
			}

			const resolvedVulnerabilityDetails = await resolveVulnerabilityDetails(allVulnerabilityRefs);
			const fallbackPackageGroups: FallbackPackageGroup[] = [];

			for (let packageOffset = 0; packageOffset < packageGroupChunk.length; packageOffset++) {
				const packageGroup = packageGroupChunk[packageOffset];
				if (!packageGroup) continue;

				const { resultIndexes } = packageGroup;
				const vulnerabilityRefs = vulnerabilityRefsPerPackage[packageOffset] || [];
				if (vulnerabilityRefs.length === 0) {
					for (const resultIndex of resultIndexes) {
						allResults[resultIndex] = [];
					}

					continue;
				}

				const resolvedVulnerabilities = vulnerabilityRefs
					.map(vulnerabilityRef => resolvedVulnerabilityDetails.get(vulnerabilityRef.id))
					.filter((vulnerability): vulnerability is OSVVulnerability => Boolean(vulnerability));

				if (resolvedVulnerabilities.length === vulnerabilityRefs.length) {
					for (const resultIndex of resultIndexes) {
						allResults[resultIndex] = resolvedVulnerabilities;
					}

					continue;
				}

				fallbackPackageGroups.push({
					...packageGroup,
					vulnerabilityRefs,
					resolvedVulnerabilities,
				});
			}

			await applyIndividualFallback(fallbackPackageGroups, allResults);
		} catch {
			logger.error(
				'Batch vulnerability chunk failed. Falling back to individual package queries for that chunk.',
			);
			await applyIndividualFallback(packageGroupChunk, allResults);
		}
	});

	await persistVulnerabilityCache();

	return allResults;
};

const queryOSV = async (packageInfo: Bun.Security.Package): Promise<OSVVulnerability[]> => {
	const osvQueryRequest: OSVQuery = {
		version: packageInfo.version,
		package: {
			name: packageInfo.name,
			ecosystem: 'npm',
		},
	};

	return fetchOSV('/v1/query', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
		},
		body: JSON.stringify(osvQueryRequest),
	})
		.then(async (response): Promise<OSVVulnerability[]> => {
			if (!response.ok) return [];

			const vulnerabilityResponse = await response.json();
			if (!isValidOSVResponse(vulnerabilityResponse)) return [];

			return vulnerabilityResponse.vulns || [];
		})
		.catch(() => []);
};

const hasHighImpactCvssV3Metric = (score: string): boolean => {
	const metrics = score.split('/');
	const [version] = metrics;

	if (version !== 'CVSS:3.0' && version !== 'CVSS:3.1') return false;

	const metricValues = new Map(
		metrics.slice(1).map(metric => {
			const [key, value] = metric.split(':', 2);
			return [key, value];
		}),
	);

	return (
		metricValues.get('C') === 'H' ||
		metricValues.get('I') === 'H' ||
		metricValues.get('A') === 'H'
	);
};

const getAdvisoryLevel = (vulnerability: OSVVulnerability): 'fatal' | 'warn' => {
	if (vulnerability.database_specific?.severity === 'CRITICAL') {
		return 'fatal';
	}

	if (vulnerability.severity) {
		for (const severityInfo of vulnerability.severity) {
			if (
				severityInfo.type === 'CVSS_V3' &&
				severityInfo.score &&
				hasHighImpactCvssV3Metric(severityInfo.score)
			) {
				return 'fatal';
			}
		}
	}

	return 'warn';
};

const listVulnerablePackages = (
	vulnerabilities: OSVVulnerability[],
	packageName: string,
): Bun.Security.Advisory[] => {
	const advisoryResults = [];

	for (const vulnerability of vulnerabilities) {
		const severityLevel = getAdvisoryLevel(vulnerability);
		const referenceUrl =
			vulnerability.references?.find(reference => reference.type === 'WEB')?.url || null;

		advisoryResults.push({
			level: severityLevel,
			package: packageName,
			url: referenceUrl,
			description:
				vulnerability.summary || vulnerability.details || `Vulnerability ${vulnerability.id}`,
		});
	}

	return advisoryResults;
};

export { queryOSV, queryOSVBatch, listVulnerablePackages };
