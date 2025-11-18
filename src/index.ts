import {queryOSV, listVulnerablePackages} from '@api/osv-client';
import {validateSemverRange} from '@validators/semver-check';
import {checkPackageVulnerabilities} from '@validators/osv-check';

export const scanner: Bun.Security.Scanner = {
	version: '1',
	async scan({packages}) {
		const securityAdvisories: Bun.Security.Advisory[] = [];

		if (packages.length === 0) {
			return securityAdvisories;
		}

		const semverAdvisories = validateSemverRange(packages);
		securityAdvisories.push(...semverAdvisories);

		try {
			const packageAdvisories = await checkPackageVulnerabilities(packages);
			securityAdvisories.push(...packageAdvisories);
		} catch {
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

		const uniqueAdvisories = Array.from(
			new Map(
				securityAdvisories.map(advisory => [
					`${advisory.package}:${advisory.url}:${advisory.description}`,
					advisory,
				]),
			).values(),
		);

		return uniqueAdvisories;
	},
};
