const isRecord = (value: unknown): value is Record<string, unknown> =>
	typeof value === 'object' && value !== null;

type SkipScanOptions = {
	ciValue?: string;
	stdinIsTTY?: boolean;
	stdoutIsTTY?: boolean;
};

export const shouldSkipScan = ({
	ciValue = Bun.env.CI,
	stdinIsTTY = process.stdin.isTTY,
	stdoutIsTTY = process.stdout.isTTY,
}: SkipScanOptions = {}): boolean => {
	if (ciValue === 'true' || ciValue === '1') return true;

	return stdinIsTTY !== true || stdoutIsTTY !== true;
};

const isOptionalString = (value: unknown): value is string | undefined =>
	value === undefined || typeof value === 'string';

const isValidSeverityInfo = (value: unknown): value is { type: string; score: string } => {
	if (!isRecord(value)) return false;

	return typeof value.type === 'string' && typeof value.score === 'string';
};

const isValidReference = (value: unknown): value is { type: string; url: string } => {
	if (!isRecord(value)) return false;

	return typeof value.type === 'string' && typeof value.url === 'string';
};

const isValidDatabaseSpecific = (value: unknown): value is { severity?: string } => {
	if (!isRecord(value)) return false;

	return isOptionalString(value.severity);
};

export const isValidVulnerability = (vulnerability: unknown): vulnerability is OSVVulnerability => {
	if (!isRecord(vulnerability)) return false;

	return (
		typeof vulnerability.id === 'string' &&
		vulnerability.id.length > 0 &&
		isOptionalString(vulnerability.summary) &&
		isOptionalString(vulnerability.details) &&
		isOptionalString(vulnerability.modified) &&
		(vulnerability.severity === undefined ||
			(Array.isArray(vulnerability.severity) &&
				vulnerability.severity.every(isValidSeverityInfo))) &&
		(vulnerability.database_specific === undefined ||
			isValidDatabaseSpecific(vulnerability.database_specific)) &&
		(vulnerability.references === undefined ||
			(Array.isArray(vulnerability.references) && vulnerability.references.every(isValidReference)))
	);
};

const isValidVulnerabilityArray = (value: unknown): value is OSVVulnerability[] =>
	Array.isArray(value) && value.every(isValidVulnerability);

export const isValidOSVResponse = (value: unknown): value is OSVResponse => {
	if (!isRecord(value)) return false;
	if (value.vulns === undefined) return true;

	return isValidVulnerabilityArray(value.vulns);
};

export const isValidOSVBatchResponse = (value: unknown): value is OSVBatchResponse => {
	if (!isRecord(value) || !Array.isArray(value.results)) return false;

	return value.results.every(result => {
		if (!isRecord(result)) return false;
		if (result.vulns === undefined) return true;

		return isValidVulnerabilityArray(result.vulns);
	});
};

const isValidPackageRecord = (value: unknown): value is Record<string, unknown> =>
	value === undefined || isRecord(value);

export const isValidPackageJson = (value: unknown): value is PackageJson => {
	if (!isRecord(value)) return false;

	return (
		isValidPackageRecord(value.overrides) &&
		isValidPackageRecord(value.resolutions) &&
		(value.name === undefined || typeof value.name === 'string') &&
		(value.version === undefined || typeof value.version === 'string')
	);
};

type CacheEntryShape = {
	fetchedAt: number;
	modified?: string;
	vulnerability: OSVVulnerability;
};

type CacheData = {
	entries: Record<string, CacheEntryShape>;
};

export const isValidCachedVulnerability = (
	value: unknown,
	expectedId?: string,
): value is CacheEntryShape => {
	if (!isRecord(value)) return false;

	return (
		typeof value.fetchedAt === 'number' &&
		value.fetchedAt > 0 &&
		(value.modified === undefined || typeof value.modified === 'string') &&
		isValidVulnerability(value.vulnerability) &&
		(expectedId === undefined || value.vulnerability.id === expectedId)
	);
};

export const isValidCacheData = (value: unknown): value is CacheData => {
	if (!isRecord(value)) return false;

	return isRecord(value.entries);
};
