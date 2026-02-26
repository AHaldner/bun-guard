import { listVulnerablePackages, queryOSVBatch } from '@api/osv-client';

export const checkPackageVulnerabilities = async (
	packages: Bun.Security.Package[],
): Promise<Bun.Security.Advisory[]> => {
	const advisoryResults: Bun.Security.Advisory[] = [];
	const batchedVulnerabilities = await queryOSVBatch(packages);

	for (let packageIndex = 0; packageIndex < packages.length; packageIndex++) {
		const packageVulnerabilities = batchedVulnerabilities[packageIndex] || [];
		if (packageVulnerabilities.length === 0) continue;

		const currentPackage = packages[packageIndex];
		if (!currentPackage) continue;

		const packageAdvisories = listVulnerablePackages(packageVulnerabilities, currentPackage.name);
		advisoryResults.push(...packageAdvisories);
	}

	return advisoryResults;
};
