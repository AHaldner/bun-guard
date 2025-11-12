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
	test('should detect known vulnerable package (event-stream 3.3.6)', async () => {
		const packages = [createMockPackage('event-stream', '3.3.6')];

		const results = await scanner.scan({packages});

		expect(results.length).toBeGreaterThan(0);
		expect(results[0]?.package).toBe('event-stream');
		expect(results[0]?.level).toBe('fatal');
		expect(results[0]?.description).toContain('event-stream');
	});

	test('should not flag safe version of event-stream', async () => {
		const packages = [createMockPackage('event-stream', '3.3.4')];

		const results = await scanner.scan({packages});

		expect(results.length).toBe(0);
	});

	test('should not flag popular safe packages', async () => {
		const packages = [createMockPackage('lodash', '4.17.21'), createMockPackage('react', '18.2.0')];

		const results = await scanner.scan({packages});

		expect(results.length).toBe(0);
	});

	test('should handle non-existent packages gracefully', async () => {
		const packages = [createMockPackage('this-package-does-not-exist-12345', '1.0.0')];

		const results = await scanner.scan({packages});

		expect(results.length).toBe(0);
	});

	test('should detect vulnerabilities in mixed package list', async () => {
		const packages = [
			createMockPackage('lodash', '4.17.21'),
			createMockPackage('event-stream', '3.3.6'),
			createMockPackage('react', '18.2.0'),
		];

		const results = await scanner.scan({packages});

		expect(results.length).toBe(1);
		expect(results[0]?.package).toBe('event-stream');
		expect(results[0]?.level).toBe('fatal');
	});

	test('should return correct advisory structure', async () => {
		const packages = [createMockPackage('event-stream', '3.3.6')];

		const results = await scanner.scan({packages});

		expect(results.length).toBeGreaterThan(0);

		const advisory = results[0];
		expect(advisory).toBeDefined();
		expect(advisory!).toHaveProperty('level');
		expect(advisory!).toHaveProperty('package');
		expect(advisory!).toHaveProperty('url');
		expect(advisory!).toHaveProperty('description');

		expect(['fatal', 'warn']).toContain(advisory!.level);
		expect(typeof advisory!.package).toBe('string');
		expect(typeof advisory!.description).toBe('string');
		expect(advisory!.url === null || typeof advisory!.url === 'string').toBe(true);
	});

	test('should handle empty package list', async () => {
		const packages: Bun.Security.Package[] = [];

		const results = await scanner.scan({packages});

		expect(results).toEqual([]);
	});

	test('should complete scan within reasonable time', async () => {
		const packages = [
			createMockPackage('react', '18.2.0'),
			createMockPackage('vue', '3.3.0'),
			createMockPackage('lodash', '4.17.21'),
		];

		const startTime = Date.now();
		const results = await scanner.scan({packages});
		const duration = Date.now() - startTime;

		expect(duration).toBeLessThan(10000);
		expect(Array.isArray(results)).toBe(true);
	});

	test('scanner should have correct version', () => {
		expect(scanner.version).toBe('1');
		expect(typeof scanner.scan).toBe('function');
	});
});

describe('Scanner Integration', () => {
	test('should handle API failures gracefully', async () => {
		const packages = [createMockPackage('', '')];

		const results = await scanner.scan({packages});
		expect(Array.isArray(results)).toBe(true);
	});
});
