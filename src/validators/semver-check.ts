export const validateSemverRange = async (
	packages: Bun.Security.Package[],
): Promise<Bun.Security.Advisory[]> => {
	const advisoryResults: Bun.Security.Advisory[] = [];

	const overriddenPackages = await getOverriddenPackages();

	for (const packageInfo of packages) {
		const resolvedVersion = packageInfo?.version;
		const requestedVersionRange = packageInfo?.requestedRange;

		if (!resolvedVersion || !requestedVersionRange) continue;

		try {
			const satisfiesRequestedRange = Bun.semver.satisfies(resolvedVersion, requestedVersionRange);
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
		} catch {
			console.warn(
				`Warning: Could not parse semver range "${requestedVersionRange}" for package "${packageInfo.name}". Skipping semver check.`,
			);
		}
	}

	return advisoryResults;
};

const getOverriddenPackages = async (): Promise<Set<string>> => {
	try {
		const packageJson = (await Bun.file('package.json').json()) as PackageJson;
		const overrides = packageJson.overrides || {};
		const resolutions = packageJson.resolutions || {};

		return new Set([...Object.keys(overrides), ...Object.keys(resolutions)]);
	} catch {
		return new Set();
	}
};
