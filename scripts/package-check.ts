import { spawnSync } from 'node:child_process';
import path from 'node:path';

type PackedFile = {
	path: string;
	size: number;
};

type PackResult = {
	files: PackedFile[];
	unpackedSize: number;
};

const MAX_UNPACKED_SIZE_BYTES = 40 * 1024;
const NPM_CACHE_DIR = '/tmp/bun-guard-npm-cache';

const forbiddenPublishedPaths = [
	/^src\//,
	/^__tests__\//,
	/^bench\//,
	/^\.github\//,
	/^scripts\//,
	/^bun\.lock$/,
	/^\.ox(?:lint|fmt)rc\.json$/,
	/^tsdown\.config\.mts$/,
	/^tsconfig(?:\.build)?\.json$/,
];

const isRecord = (value: unknown): value is Record<string, unknown> =>
	typeof value === 'object' && value !== null;

const isPackedFile = (value: unknown): value is PackedFile => {
	if (!isRecord(value)) return false;

	return typeof value.path === 'string' && typeof value.size === 'number';
};

const isPackResult = (value: unknown): value is PackResult => {
	if (!isRecord(value)) return false;

	return (
		Array.isArray(value.files) &&
		value.files.every(isPackedFile) &&
		typeof value.unpackedSize === 'number'
	);
};

const isPackResultArray = (value: unknown): value is PackResult[] =>
	Array.isArray(value) && value.every(isPackResult);

const extractPackJson = (output: string): string | null => {
	const jsonStartIndex = output.indexOf('[\n');
	if (jsonStartIndex === -1) return null;

	return output.slice(jsonStartIndex);
};

const sanitizedPath = (process.env.PATH || '')
	.split(path.delimiter)
	.filter(pathEntry => !pathEntry.endsWith(`${path.sep}node_modules${path.sep}.bin`))
	.join(path.delimiter);

const packResult = spawnSync('npm', ['pack', '--dry-run', '--json'], {
	encoding: 'utf8',
	env: {
		HOME: process.env.HOME || '',
		PATH: sanitizedPath,
		npm_config_cache: process.env.npm_config_cache || NPM_CACHE_DIR,
	},
});

if (packResult.status !== 0) {
	process.stderr.write(packResult.stderr);
	process.stdout.write(packResult.stdout);
	process.exit(packResult.status ?? 1);
}

let parsedPackOutput: unknown;
const packJsonOutput = extractPackJson(packResult.stdout);

if (!packJsonOutput) {
	console.error('npm pack did not include JSON output.');
	process.stdout.write(packResult.stdout);
	process.exit(1);
}

try {
	parsedPackOutput = JSON.parse(packJsonOutput);
} catch (error) {
	console.error('Could not parse npm pack JSON output.');
	console.error(error);
	process.stdout.write(packResult.stdout);
	process.exit(1);
}

if (!isPackResultArray(parsedPackOutput)) {
	console.error('npm pack JSON output did not match the expected shape.');
	process.stdout.write(packResult.stdout);
	process.exit(1);
}

const [packageInfo] = parsedPackOutput;

if (!packageInfo) {
	console.error('npm pack did not report package contents.');
	process.exit(1);
}

const publishedPaths = packageInfo.files.map(file => file.path);
const forbiddenPaths = publishedPaths.filter(path =>
	forbiddenPublishedPaths.some(forbiddenPath => forbiddenPath.test(path)),
);

if (forbiddenPaths.length > 0) {
	console.error('Package contains files that must not be published:');
	for (const path of forbiddenPaths) {
		console.error(`- ${path}`);
	}
	process.exit(1);
}

if (packageInfo.unpackedSize > MAX_UNPACKED_SIZE_BYTES) {
	console.error(
		`Package unpacked size ${packageInfo.unpackedSize} bytes exceeds ${MAX_UNPACKED_SIZE_BYTES} bytes.`,
	);
	process.exit(1);
}

console.log('Package contents verified:');
for (const path of publishedPaths) {
	console.log(`- ${path}`);
}
console.log(`Unpacked size: ${packageInfo.unpackedSize} bytes`);
