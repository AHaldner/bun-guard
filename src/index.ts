import {queryOSV, listVulnerablePackages} from '@api/osv-client';

export const scanner: Scanner = {
	version: '1',
	async scan({packages}) {
		const results: Advisory[] = [];

		for (const pkg of packages) {
			const vulnerabilities = await queryOSV(pkg);
			if (vulnerabilities.length === 0) continue;

			const advisories = listVulnerablePackages(vulnerabilities, pkg.name);
			results.push(...advisories);
		}

		return results;
	},
};
