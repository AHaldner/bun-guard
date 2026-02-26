import {scanner} from '../src/index';

type ScenarioName = 'small' | 'medium' | 'large' | 'duplicate-heavy';

type PackageFixture = {
	name: string;
	version: string;
};

type EndpointStat = {
	count: number;
	totalMs: number;
};

type RunResult = {
	durationMs: number;
	advisoryCount: number;
	requestCount: number;
	endpoints: Map<string, EndpointStat>;
};

type BenchmarkOptions = {
	scenario: ScenarioName;
	iterations: number;
	warmup: number;
};

const PACKAGE_FIXTURES: PackageFixture[] = [
	{name: 'react', version: '18.2.0'},
	{name: 'react-dom', version: '18.2.0'},
	{name: 'next', version: '14.2.0'},
	{name: 'vue', version: '3.4.21'},
	{name: 'svelte', version: '4.2.15'},
	{name: 'typescript', version: '5.9.2'},
	{name: 'eslint', version: '9.14.0'},
	{name: 'prettier', version: '3.4.2'},
	{name: 'lodash', version: '4.17.21'},
	{name: 'axios', version: '1.7.9'},
	{name: 'express', version: '4.21.1'},
	{name: 'zod', version: '3.23.8'},
	{name: 'date-fns', version: '4.1.0'},
	{name: 'rxjs', version: '7.8.1'},
	{name: 'chalk', version: '5.3.0'},
	{name: 'commander', version: '12.1.0'},
	{name: 'dotenv', version: '16.4.5'},
	{name: 'uuid', version: '11.0.3'},
	{name: 'ws', version: '8.18.0'},
	{name: 'debug', version: '4.3.7'},
	{name: 'minimist', version: '1.2.8'},
	{name: 'yargs', version: '17.7.2'},
	{name: 'tslib', version: '2.8.1'},
	{name: 'nanoid', version: '5.0.7'},
	{name: 'ms', version: '2.1.3'},
	{name: 'glob', version: '11.0.0'},
	{name: 'semver', version: '7.6.3'},
	{name: 'vite', version: '5.4.10'},
	{name: 'tailwindcss', version: '3.4.14'},
	{name: 'pinia', version: '2.2.6'},
	{name: 'mobx', version: '6.13.5'},
	{name: 'redux', version: '5.0.1'},
	{name: 'graphql', version: '16.9.0'},
	{name: 'prisma', version: '5.22.0'},
	{name: 'typeorm', version: '0.3.20'},
	{name: 'mongoose', version: '8.8.0'},
	{name: 'three', version: '0.170.0'},
	{name: 'd3', version: '7.9.0'},
	{name: 'vitest', version: '2.1.5'},
	{name: 'cypress', version: '13.15.0'},
	{name: 'playwright', version: '1.48.2'},
	{name: 'pino', version: '9.5.0'},
	{name: 'winston', version: '3.16.0'},
	{name: 'event-stream', version: '3.3.6'},
	{name: 'serialize-javascript', version: '3.1.0'},
];

const parseOptions = (argv: string[]): BenchmarkOptions => {
	const options: BenchmarkOptions = {
		scenario: 'medium',
		iterations: 5,
		warmup: 1,
	};

	for (const arg of argv) {
		if (arg.startsWith('--scenario=')) {
			const value = arg.replace('--scenario=', '') as ScenarioName;
			if (['small', 'medium', 'large', 'duplicate-heavy'].includes(value)) {
				options.scenario = value;
			}
		}

		if (arg.startsWith('--iterations=')) {
			const value = Number(arg.replace('--iterations=', ''));
			if (Number.isInteger(value) && value > 0) {
				options.iterations = value;
			}
		}

		if (arg.startsWith('--warmup=')) {
			const value = Number(arg.replace('--warmup=', ''));
			if (Number.isInteger(value) && value >= 0) {
				options.warmup = value;
			}
		}
	}

	return options;
};

const fixtureToPackage = (fixture: PackageFixture): Bun.Security.Package => ({
	name: fixture.name,
	version: fixture.version,
	tarball: `https://registry.npmjs.org/${fixture.name}/-/${fixture.name}-${fixture.version}.tgz`,
	requestedRange: `^${fixture.version}`,
});

const repeatPackages = (
	basePackages: Bun.Security.Package[],
	copies: number,
): Bun.Security.Package[] => {
	const result: Bun.Security.Package[] = [];
	for (let i = 0; i < copies; i++) {
		result.push(...basePackages);
	}
	return result;
};

const buildScenario = (scenario: ScenarioName): Bun.Security.Package[] => {
	if (scenario === 'small') return PACKAGE_FIXTURES.slice(0, 15).map(fixtureToPackage);
	if (scenario === 'medium') return PACKAGE_FIXTURES.slice(0, 35).map(fixtureToPackage);
	if (scenario === 'large') return PACKAGE_FIXTURES.map(fixtureToPackage);
	return repeatPackages(PACKAGE_FIXTURES.slice(0, 15).map(fixtureToPackage), 10);
};

const normalizeEndpoint = (input: string | URL | Request): string => {
	const requestUrl =
		typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;

	try {
		const path = new URL(requestUrl).pathname;
		if (path.startsWith('/v1/vulns/')) return '/v1/vulns/:id';
		return path;
	} catch {
		return requestUrl;
	}
};

const runScanOnce = async (packages: Bun.Security.Package[]): Promise<RunResult> => {
	const endpointStats = new Map<string, EndpointStat>();
	let requestCount = 0;
	const originalFetch = globalThis.fetch;

	const instrumentedFetch = (async (
		input: Parameters<typeof fetch>[0],
		init?: Parameters<typeof fetch>[1],
	): ReturnType<typeof fetch> => {
		const endpoint = normalizeEndpoint(input as string | URL | Request);
		const startedAt = performance.now();

		try {
			return await originalFetch(input, init);
		} finally {
			const elapsedMs = performance.now() - startedAt;
			const existing = endpointStats.get(endpoint);
			if (existing) {
				existing.count += 1;
				existing.totalMs += elapsedMs;
			} else {
				endpointStats.set(endpoint, {count: 1, totalMs: elapsedMs});
			}

			requestCount += 1;
		}
	}) as typeof fetch;

	instrumentedFetch.preconnect = originalFetch.preconnect.bind(originalFetch);

	globalThis.fetch = instrumentedFetch;
	const startedAt = performance.now();

	try {
		const advisories = await scanner.scan({packages});

		return {
			durationMs: performance.now() - startedAt,
			advisoryCount: advisories.length,
			requestCount,
			endpoints: endpointStats,
		};
	} finally {
		globalThis.fetch = originalFetch;
	}
};

const percentile = (values: number[], point: number): number => {
	if (values.length === 0) return 0;
	const sortedValues = [...values].sort((a, b) => a - b);
	const rank = Math.min(
		sortedValues.length - 1,
		Math.max(0, Math.ceil(point * sortedValues.length) - 1),
	);
	return sortedValues[rank] || 0;
};

const average = (values: number[]): number => {
	if (values.length === 0) return 0;
	return values.reduce((sum, value) => sum + value, 0) / values.length;
};

const formatMs = (value: number): string => `${value.toFixed(2)}ms`;

const main = async (): Promise<void> => {
	const options = parseOptions(Bun.argv.slice(2));
	const packages = buildScenario(options.scenario);
	const uniquePackageKeys = new Set(
		packages.map(packageInfo => `${packageInfo.name}@${packageInfo.version}`),
	);

	console.log(`Scenario: ${options.scenario}`);
	console.log(`Packages: ${packages.length} total / ${uniquePackageKeys.size} unique`);
	console.log(`Warmup: ${options.warmup}, Iterations: ${options.iterations}`);
	console.log('');

	for (let i = 0; i < options.warmup; i++) {
		const warmupResult = await runScanOnce(packages);
		console.log(
			`Warmup ${i + 1}/${options.warmup}: ${formatMs(warmupResult.durationMs)} (${warmupResult.requestCount} requests)`,
		);
	}

	if (options.warmup > 0) {
		console.log('');
	}

	const runResults: RunResult[] = [];

	for (let iteration = 1; iteration <= options.iterations; iteration++) {
		const runResult = await runScanOnce(packages);
		runResults.push(runResult);
		console.log(
			`Run ${iteration}/${options.iterations}: ${formatMs(runResult.durationMs)} | advisories=${runResult.advisoryCount} | requests=${runResult.requestCount}`,
		);
	}

	const durations = runResults.map(result => result.durationMs);
	const requestCounts = runResults.map(result => result.requestCount);
	const advisoryCounts = runResults.map(result => result.advisoryCount);

	console.log('\nSummary');
	console.log(`avg: ${formatMs(average(durations))}`);
	console.log(`p50: ${formatMs(percentile(durations, 0.5))}`);
	console.log(`p95: ${formatMs(percentile(durations, 0.95))}`);
	console.log(`avg requests/run: ${average(requestCounts).toFixed(2)}`);
	console.log(`avg advisories/run: ${average(advisoryCounts).toFixed(2)}`);

	const endpointTotals = new Map<string, EndpointStat>();

	for (const runResult of runResults) {
		for (const [endpoint, endpointStat] of runResult.endpoints) {
			const existing = endpointTotals.get(endpoint);
			if (existing) {
				existing.count += endpointStat.count;
				existing.totalMs += endpointStat.totalMs;
			} else {
				endpointTotals.set(endpoint, {...endpointStat});
			}
		}
	}

	if (endpointTotals.size > 0) {
		console.log('\nEndpoint breakdown (avg per run)');
		const sortedEndpoints = [...endpointTotals.entries()].sort(
			(a, b) => b[1].totalMs - a[1].totalMs,
		);
		for (const [endpoint, endpointStat] of sortedEndpoints) {
			console.log(
				`- ${endpoint}: ${(endpointStat.count / options.iterations).toFixed(
					2,
				)} req/run, ${(endpointStat.totalMs / options.iterations).toFixed(2)}ms/run`,
			);
		}
	}
};

await main();
