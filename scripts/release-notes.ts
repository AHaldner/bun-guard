const rawVersion = Bun.argv[2];

if (!rawVersion) {
	console.error('Usage: bun scripts/release-notes.ts <version>');
	process.exit(1);
}

const version = rawVersion.startsWith('v') ? rawVersion.slice(1) : rawVersion;
const changelog = await Bun.file('CHANGELOG.md').text();
const lines = changelog.split(/\r?\n/);
const releaseHeadingPattern = new RegExp(`^## \\[${version.replaceAll('.', '\\.')}\\](?: - .+)?$`);

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

if (!formattedReleaseNotes) {
	console.error(`Could not find changelog notes for version ${version}.`);
	console.error(`Expected a heading like: ## [${version}] - YYYY-MM-DD`);
	process.exit(1);
}

console.log(formattedReleaseNotes);
