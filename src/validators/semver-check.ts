import { isValidPackageJson } from '@utils/helpers';
import { logger } from '@utils/logger';

export const validateSemverRange = async (
	packages: Bun.Security.Package[],
): Promise<Bun.Security.Advisory[]> => {
	const mismatchedPackages: Array<{
		packageInfo: Bun.Security.Package;
		resolvedVersion: string;
		requestedVersionRange: string;
	}> = [];

	for (const packageInfo of packages) {
		const resolvedVersion = packageInfo?.version;
		const requestedVersionRange = packageInfo?.requestedRange;

		if (!resolvedVersion || !requestedVersionRange) continue;

		try {
			if (Bun.semver.satisfies(resolvedVersion, requestedVersionRange)) continue;

			mismatchedPackages.push({
				packageInfo,
				resolvedVersion,
				requestedVersionRange,
			});
		} catch {
			logger.warn(
				`Could not parse semver range "${requestedVersionRange}" for package "${packageInfo.name}". Skipping semver check.`,
			);
		}
	}

	if (mismatchedPackages.length === 0) return [];

	const overriddenPackages = await getOverriddenPackages();

	return mismatchedPackages.map(({ packageInfo, resolvedVersion, requestedVersionRange }) => {
		const isOverridden = overriddenPackages.has(packageInfo.name);

		return {
			level: isOverridden ? 'warn' : 'fatal',
			package: packageInfo.name,
			url: null,
			description: `Resolved version ${resolvedVersion} does not satisfy requested range ${requestedVersionRange}${
				isOverridden ? ' (allowed via overrides/resolutions)' : ''
			}`,
		};
	});
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
