const BATCH_SIZE = 100;

const fetchVulnDetailsByIds = async (ids: string[]): Promise<Map<string, OSVVulnerability>> => {
	const vulnerabilityDetailsMap = new Map<string, OSVVulnerability>();
	if (ids.length === 0) return vulnerabilityDetailsMap;

	const ID_BATCH_SIZE = 100;
	for (let i = 0; i < ids.length; i += ID_BATCH_SIZE) {
		const vulnerabilityIdsBatch = ids.slice(i, i + ID_BATCH_SIZE);
		const queryString = vulnerabilityIdsBatch.map(id => `ids=${encodeURIComponent(id)}`).join('&');

		try {
			const response = await fetch(`https://api.osv.dev/v1/vulns?${queryString}`, {
				method: 'GET',
			});

			if (!response.ok) continue;
			const vulnerabilityData = (await response.json()) as OSVResponse;

			for (const vulnerability of vulnerabilityData.vulns || []) {
				if (vulnerability?.id) vulnerabilityDetailsMap.set(vulnerability.id, vulnerability);
			}
		} catch (_err) {
			continue;
		}
	}

	return vulnerabilityDetailsMap;
};

const queryOSVBatch = async (packages: Bun.Security.Package[]): Promise<OSVVulnerability[][]> => {
	if (packages.length === 0) return [];

	const packageChunks: Bun.Security.Package[][] = [];

	for (let i = 0; i < packages.length; i += BATCH_SIZE) {
		packageChunks.push(packages.slice(i, i + BATCH_SIZE));
	}

	const allResults: OSVVulnerability[][] = [];

	for (const packageChunk of packageChunks) {
		const batchRequestBody: OSVBatchRequest = {
			queries: packageChunk.map((packageInfo: Bun.Security.Package) => ({
				version: packageInfo.version,
				package: {name: packageInfo.name, ecosystem: 'npm'},
			})),
		};

		try {
			const response = await fetch('https://api.osv.dev/v1/querybatch', {
				method: 'POST',
				headers: {'Content-Type': 'application/json'},
				body: JSON.stringify(batchRequestBody),
			});

			if (!response.ok) {
				for (let i = 0; i < packageChunk.length; i++) allResults.push([]);
				continue;
			}

			const batchResponseData = (await response.json()) as OSVBatchResponse;

			const vulnerabilityIdsPerPackage: string[][] = [];
			const allVulnerabilityIds: string[] = [];

			for (const queryResult of batchResponseData.results || []) {
				const vulnerabilityIds = (queryResult.vulns || [])
					.map((vulnerability: any) => (vulnerability as OSVVulnerability).id)
					.filter((id: any): id is string => typeof id === 'string' && id.length > 0);
				vulnerabilityIdsPerPackage.push(vulnerabilityIds);
				allVulnerabilityIds.push(...vulnerabilityIds);
			}

			const uniqueVulnerabilityIds = Array.from(new Set(allVulnerabilityIds));
			const vulnerabilityDetailsMap = await fetchVulnDetailsByIds(uniqueVulnerabilityIds);

			const anyIdsPresent = uniqueVulnerabilityIds.length > 0;
			const resolvedCount = vulnerabilityDetailsMap.size;
			const resolutionFailed = anyIdsPresent && resolvedCount === 0;

			if (resolutionFailed) {
				for (const packageInfo of packageChunk) {
					const vulnerabilities = await queryOSV(packageInfo);
					allResults.push(vulnerabilities || []);
				}

				continue;
			}

			for (const vulnerabilityIds of vulnerabilityIdsPerPackage) {
				const vulnerabilitiesForPackage: OSVVulnerability[] = [];

				for (const vulnerabilityId of vulnerabilityIds) {
					const vulnerabilityDetails = vulnerabilityDetailsMap.get(vulnerabilityId);
					if (vulnerabilityDetails) vulnerabilitiesForPackage.push(vulnerabilityDetails);
				}

				allResults.push(vulnerabilitiesForPackage);
			}
		} catch (_err) {
			for (let i = 0; i < packageChunk.length; i++) allResults.push([]);
		}
	}

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
		return vulnerabilityResponse.vulns || [];
	} catch (error) {
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

export {queryOSV, queryOSVBatch, listVulnerablePackages};
