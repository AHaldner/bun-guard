const queryOSV = async (pkg: Package): Promise<OSVVulnerability[]> => {
	const query: OSVQuery = {
		version: pkg.version,
		package: {
			name: pkg.name,
			ecosystem: 'npm',
		},
	};

	try {
		const response = await fetch('https://api.osv.dev/v1/query', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
			},
			body: JSON.stringify(query),
		});

		if (!response.ok) {
			return [];
		}

		const data = (await response.json()) as OSVResponse;
		return data.vulns || [];
	} catch (error) {
		return [];
	}
};

const getAdvisoryLevel = (vuln: OSVVulnerability): 'fatal' | 'warn' => {
	if (vuln.database_specific?.severity === 'CRITICAL') {
		return 'fatal';
	}

	if (vuln.severity) {
		for (const sev of vuln.severity) {
			if (sev.type === 'CVSS_V3' && sev.score) {
				const scoreMatch = sev.score.match(
					/CVSS:3\.[01]\/.*?\/.*?\/.*?\/.*?\/.*?\/.*?\/(C:[HML])\/(?:I:[HML])\/(?:A:[HML])/,
				);

				if (!scoreMatch) continue;

				if (sev.score.includes('C:H') || sev.score.includes('I:H') || sev.score.includes('A:H')) {
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
): Advisory[] => {
	const results = [];

	for (const vulnerability of vulnerabilities) {
		const level = getAdvisoryLevel(vulnerability);
		const url = vulnerability.references?.find(ref => ref.type === 'WEB')?.url || null;

		results.push({
			level,
			package: packageName,
			url,
			description:
				vulnerability.summary || vulnerability.details || `Vulnerability ${vulnerability.id}`,
		});
	}

	return results;
};

export {queryOSV, listVulnerablePackages};
