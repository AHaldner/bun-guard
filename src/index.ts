import { queryOSV, listVulnerablePackages } from '@api/osv-client';
import { shouldSkipScan } from '@utils/helpers';
import { logger } from '@utils/logger';
import { validateSemverRange } from '@validators/semver-check';
import { checkPackageVulnerabilities } from '@validators/osv-check';

export const scanner: Bun.Security.Scanner = {
	version: '1',
	async scan({ packages }) {
		const securityAdvisories: Bun.Security.Advisory[] = [];

		if (shouldSkipScan()) {
			logger.warn('Skipping security scan because TTY access is required.');

			return securityAdvisories;
		}

		if (packages.length === 0) {
			return securityAdvisories;
		}

		const semverAdvisories = await validateSemverRange(packages);
		securityAdvisories.push(...semverAdvisories);

		await checkPackageVulnerabilities(packages)
			.then(packageAdvisories => {
				securityAdvisories.push(...packageAdvisories);
			})
			.catch(async () => {
				logger.error(
					'Batch vulnerability scan failed. Falling back to individual package queries.',
				);

				for (const packageInfo of packages) {
					const individualPackageVulnerabilities = await queryOSV(packageInfo);
					if (individualPackageVulnerabilities.length === 0) continue;

					const individualPackageAdvisories = listVulnerablePackages(
						individualPackageVulnerabilities,
						packageInfo.name,
					);
					securityAdvisories.push(...individualPackageAdvisories);
				}
			});

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
