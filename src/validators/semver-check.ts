import { isValidPackageJson } from '@utils/helpers';
import { logger } from '@utils/logger';

export const validateSemverRange = async (
	packages: Bun.Security.Package[],
): Promise<Bun.Security.Advisory[]> => {
	const advisoryResults: Bun.Security.Advisory[] = [];

	const overriddenPackages = await getOverriddenPackages();

	for (const packageInfo of packages) {
		const resolvedVersion = packageInfo?.version;
		const requestedVersionRange = packageInfo?.requestedRange;

		if (!resolvedVersion || !requestedVersionRange) continue;

		Promise.resolve()
			.then(() => {
				const satisfiesRequestedRange = Bun.semver.satisfies(
					resolvedVersion,
					requestedVersionRange,
				);

				if (!satisfiesRequestedRange) {
					const isOverridden = overriddenPackages.has(packageInfo.name);
					const level = isOverridden ? 'warn' : 'fatal';

					advisoryResults.push({
						level,
						package: packageInfo.name,
						url: null,
						description: `Resolved version ${resolvedVersion} does not satisfy requested range ${requestedVersionRange}${
							isOverridden ? ' (allowed via overrides/resolutions)' : ''
						}`,
					});
				}
			})
			.catch(() => {
				logger.warn(
					`Could not parse semver range "${requestedVersionRange}" for package "${packageInfo.name}". Skipping semver check.`,
				);
			});
	}

	return advisoryResults;
};

const getOverriddenPackages = async (): Promise<Set<string>> => {
	return Bun.file('package.json')
		.json()
		.then((packageJson): Set<string> => {
			if (!isValidPackageJson(packageJson)) return new Set();

			const overrides = packageJson.overrides || {};
			const resolutions = packageJson.resolutions || {};

			return new Set([...Object.keys(overrides), ...Object.keys(resolutions)]);
		})
		.catch(() => new Set<string>());
};
