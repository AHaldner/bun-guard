export const validateSemverRange = (packages: Bun.Security.Package[]): Bun.Security.Advisory[] => {
	const advisoryResults: Bun.Security.Advisory[] = [];

	for (const packageInfo of packages) {
		const resolvedVersion = packageInfo?.version;
		const requestedVersionRange = packageInfo?.requestedRange;

		if (!resolvedVersion || !requestedVersionRange) continue;

		try {
			const satisfiesRequestedRange = Bun.semver.satisfies(resolvedVersion, requestedVersionRange);
			if (!satisfiesRequestedRange) {
				advisoryResults.push({
					level: 'fatal',
					package: packageInfo.name,
					url: null,
					description: `Resolved version ${resolvedVersion} does not satisfy requested range ${requestedVersionRange}`,
				});
			}
		} catch (_semverError) {
			console.warn(
				`Warning: Could not parse semver range "${requestedVersionRange}" for package "${packageInfo.name}". Skipping semver check.`,
			);
		}
	}

	return advisoryResults;
};
