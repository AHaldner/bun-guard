import {queryOSVBatch, queryOSV, listVulnerablePackages} from '@api/osv-client';

export const scanner: Bun.Security.Scanner = {
	version: '1',
	async scan({packages}) {
		const securityAdvisories: Bun.Security.Advisory[] = [];

		if (packages.length === 0) return securityAdvisories;

		try {
			const batchedVulnerabilities = await queryOSVBatch(packages);

			for (let packageIndex = 0; packageIndex < packages.length; packageIndex++) {
				const packageVulnerabilities = batchedVulnerabilities[packageIndex] || [];
				if (packageVulnerabilities.length === 0) continue;

				const currentPackage = packages[packageIndex];
				if (!currentPackage) continue;

				const packageAdvisories = listVulnerablePackages(
					packageVulnerabilities,
					currentPackage.name,
				);
				securityAdvisories.push(...packageAdvisories);
			}
		} catch (_batchError) {
			for (const packageInfo of packages) {
				const individualPackageVulnerabilities = await queryOSV(packageInfo);
				if (individualPackageVulnerabilities.length === 0) continue;

				const individualPackageAdvisories = listVulnerablePackages(
					individualPackageVulnerabilities,
					packageInfo.name,
				);
				securityAdvisories.push(...individualPackageAdvisories);
			}
		}

		return securityAdvisories;
	},
};
