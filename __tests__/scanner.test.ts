import {describe, test, expect} from 'bun:test';
import {scanner} from 'src';

const createMockPackage = (name: string, version: string) => {
	return {
		name,
		version,
		tarball: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`,
		requestedRange: `^${version}`,
	};
};

describe('Security Scanner', () => {
	test('should flag when resolved version does not satisfy requestedRange', async () => {
		const packageWithMismatchedRange = createMockPackage('semver-mismatch-test', '1.0.0');
		(packageWithMismatchedRange as any).requestedRange = '^2.0.0';

		const scanResults = await scanner.scan({packages: [packageWithMismatchedRange]});

		expect(
			scanResults.some(
				result => result.package === 'semver-mismatch-test' && result.level === 'fatal',
			),
		).toBe(true);
	});
	test('should detect known vulnerable package (event-stream 3.3.6)', async () => {
		const packagesToScan = [createMockPackage('event-stream', '3.3.6')];

		const scanResults = await scanner.scan({packages: packagesToScan});

		expect(scanResults.length).toBeGreaterThan(0);
		expect(scanResults[0]?.package).toBe('event-stream');
		expect(scanResults[0]?.level).toBe('fatal');
		expect(scanResults[0]?.description).toContain('event-stream');
	});

	test('should not flag safe version of event-stream', async () => {
		const packagesToScan = [createMockPackage('event-stream', '3.3.4')];

		const scanResults = await scanner.scan({packages: packagesToScan});

		expect(scanResults.length).toBe(0);
	});

	test('should not flag popular safe packages', async () => {
		const packagesToScan = [
			createMockPackage('lodash', '4.17.21'),
			createMockPackage('react', '18.2.0'),
		];

		const scanResults = await scanner.scan({packages: packagesToScan});

		expect(scanResults.length).toBe(0);
	});

	test('should handle non-existent packages gracefully', async () => {
		const packagesToScan = [createMockPackage('this-package-does-not-exist-12345', '1.0.0')];

		const scanResults = await scanner.scan({packages: packagesToScan});

		expect(scanResults.length).toBe(0);
	});

	test('should detect vulnerabilities in mixed package list', async () => {
		const packagesToScan = [
			createMockPackage('lodash', '4.17.21'),
			createMockPackage('event-stream', '3.3.6'),
			createMockPackage('react', '18.2.0'),
		];

		const scanResults = await scanner.scan({packages: packagesToScan});

		expect(scanResults.length).toBe(1);
		expect(scanResults[0]?.package).toBe('event-stream');
		expect(scanResults[0]?.level).toBe('fatal');
	});

	test('should return correct advisory structure', async () => {
		const packagesToScan = [createMockPackage('event-stream', '3.3.6')];

		const scanResults = await scanner.scan({packages: packagesToScan});

		expect(scanResults.length).toBeGreaterThan(0);

		const firstAdvisory = scanResults[0];
		expect(firstAdvisory).toBeDefined();
		expect(firstAdvisory!).toHaveProperty('level');
		expect(firstAdvisory!).toHaveProperty('package');
		expect(firstAdvisory!).toHaveProperty('url');
		expect(firstAdvisory!).toHaveProperty('description');

		expect(['fatal', 'warn']).toContain(firstAdvisory!.level);
		expect(typeof firstAdvisory!.package).toBe('string');
		expect(typeof firstAdvisory!.description).toBe('string');
		expect(firstAdvisory!.url === null || typeof firstAdvisory!.url === 'string').toBe(true);
	});

	test('should handle empty package list', async () => {
		const emptyPackageList: Bun.Security.Package[] = [];

		const scanResults = await scanner.scan({packages: emptyPackageList});

		expect(scanResults).toEqual([]);
	});

	test('should complete scan within reasonable time', async () => {
		const packagesToScan = [
			createMockPackage('react', '18.2.0'),
			createMockPackage('vue', '3.3.0'),
			createMockPackage('lodash', '4.17.21'),
		];

		const scanStartTime = Date.now();
		const scanResults = await scanner.scan({packages: packagesToScan});
		const elapsedDurationMs = Date.now() - scanStartTime;

		expect(elapsedDurationMs).toBeLessThan(10000);
		expect(Array.isArray(scanResults)).toBe(true);
	});

	test('scanner should have correct version', () => {
		expect(scanner.version).toBe('1');
		expect(typeof scanner.scan).toBe('function');
	});
});

describe('Scanner Integration', () => {
	test('should handle API failures gracefully', async () => {
		const packagesToScan = [createMockPackage('', '')];

		const scanResults = await scanner.scan({packages: packagesToScan});
		expect(Array.isArray(scanResults)).toBe(true);
	});
});
