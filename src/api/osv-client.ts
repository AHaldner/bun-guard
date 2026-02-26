import {
	type VulnerabilityRef,
	getCachedVulnerabilityDetails,
	cacheVulnerabilityDetails,
	persistVulnerabilityCache,
} from '@cache/osv-vulnerability-cache';
import { isValidVulnerability } from '@utils/helpers';

const BATCH_SIZE = 100;
const BATCH_QUERY_CONCURRENCY = 4;
const VULN_DETAIL_CONCURRENCY = 12;
const inFlightVulnerabilityRequests = new Map<string, Promise<OSVVulnerability | null>>();

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
		try {
			const response = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, {
				method: 'GET',
			});

			if (!response.ok) return null;

			const vulnerability = (await response.json()) as OSVVulnerability;
			return isValidVulnerability(vulnerability) ? vulnerability : null;
		} catch {
			return null;
		} finally {
			inFlightVulnerabilityRequests.delete(id);
		}
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
		if (existingVulnerability) {
			continue;
		}

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
	const packageGroupsByKey = new Map<
		string,
		{
			packageInfo: Bun.Security.Package;
			resultIndexes: number[];
		}
	>();

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
	const packageGroupChunks: Array<Array<{ packageInfo: Bun.Security.Package; resultIndexes: number[] }>> = [];

	for (let i = 0; i < packageGroups.length; i += BATCH_SIZE) {
		packageGroupChunks.push(packageGroups.slice(i, i + BATCH_SIZE));
	}

	await runWithConcurrency(packageGroupChunks, BATCH_QUERY_CONCURRENCY, async packageGroupChunk => {
		const batchRequestBody: OSVBatchRequest = {
			queries: packageGroupChunk.map(({ packageInfo }) => ({
				version: packageInfo.version,
				package: { name: packageInfo.name, ecosystem: 'npm' },
			})),
		};

		try {
			const response = await fetch('https://api.osv.dev/v1/querybatch', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify(batchRequestBody),
			});

			if (!response.ok) {
				return;
			}

			const batchResponseData = (await response.json()) as OSVBatchResponse;
			const batchResults = batchResponseData.results || [];
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

			for (let packageOffset = 0; packageOffset < packageGroupChunk.length; packageOffset++) {
				const packageGroup = packageGroupChunk[packageOffset];
				if (!packageGroup) continue;

				const { packageInfo, resultIndexes } = packageGroup;
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

				const fallbackVulnerabilities = await queryOSV(packageInfo);
				for (const resultIndex of resultIndexes) {
					allResults[resultIndex] = fallbackVulnerabilities;
				}
			}
		} catch {
			// Leave empty result slots on batch failures.
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

	try {
		const response = await fetch('https://api.osv.dev/v1/query', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
			},
			body: JSON.stringify(osvQueryRequest),
		});

		if (!response.ok) {
			return [];
		}

		const vulnerabilityResponse = (await response.json()) as OSVResponse;
		const vulnerabilities = vulnerabilityResponse.vulns || [];

		return vulnerabilities;
	} catch {
		return [];
	}
};

const getAdvisoryLevel = (vulnerability: OSVVulnerability): 'fatal' | 'warn' => {
	if (vulnerability.database_specific?.severity === 'CRITICAL') {
		return 'fatal';
	}

	if (vulnerability.severity) {
		for (const severityInfo of vulnerability.severity) {
			if (severityInfo.type === 'CVSS_V3' && severityInfo.score) {
				const cvssScoreMatch = severityInfo.score.match(
					/CVSS:3\.[01]\/.*?\/.*?\/.*?\/.*?\/.*?\/.*?\/(C:[HML])\/(?:I:[HML])\/(?:A:[HML])/,
				);

				if (!cvssScoreMatch) continue;

				if (
					severityInfo.score.includes('C:H') ||
					severityInfo.score.includes('I:H') ||
					severityInfo.score.includes('A:H')
				) {
					return 'fatal';
				}
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
