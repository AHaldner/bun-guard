const whatsNewHeading = `## What's New`;

const normalizeVersion = (rawVersion: string) =>
	rawVersion.startsWith('v') ? rawVersion.slice(1) : rawVersion;

export const formatReleaseNotes = (changelog: string, rawVersion: string) => {
	const version = normalizeVersion(rawVersion);
	const lines = changelog.split(/\r?\n/);
	const releaseHeadingPattern = new RegExp(
		`^## \\[${version.replaceAll('.', '\\.')}\\](?: - .+)?$`,
	);

	let isCollectingReleaseNotes = false;
	const releaseNotes: string[] = [];

	for (const line of lines) {
		if (releaseHeadingPattern.test(line)) {
			isCollectingReleaseNotes = true;
			continue;
		}

		if (isCollectingReleaseNotes && line.startsWith('## ')) break;

		if (isCollectingReleaseNotes) {
			releaseNotes.push(line);
		}
	}

	const formattedReleaseNotes = releaseNotes.join('\n').trim();
	if (!formattedReleaseNotes) return '';

	return `${whatsNewHeading}\n\n${formattedReleaseNotes}`;
};

if (import.meta.main) {
	const rawVersion = Bun.argv[2];

	if (!rawVersion) {
		console.error('Usage: bun scripts/release-notes.ts <version>');
		process.exit(1);
	}

	const changelog = await Bun.file('CHANGELOG.md').text();
	const formattedReleaseNotes = formatReleaseNotes(changelog, rawVersion);

	if (!formattedReleaseNotes) {
		const version = normalizeVersion(rawVersion);
		console.error(`Could not find changelog notes for version ${version}.`);
		console.error(`Expected a heading like: ## [${version}] - YYYY-MM-DD`);
		process.exit(1);
	}

	console.log(formattedReleaseNotes);
}
