import { describe, expect, test } from 'bun:test';

describe('publish workflow hardening', () => {
	test('pins privileged release actions and Bun version', async () => {
		const workflow = await Bun.file('.github/workflows/publish.yml').text();

		expect(workflow).toContain(
			'uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2',
		);
		expect(workflow).toContain(
			'uses: oven-sh/setup-bun@0c5077e51419868618aeaa5fe8019c62421857d6 # v2.2.0',
		);
		expect(workflow).toContain(
			'uses: actions/setup-node@48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e # v6.4.0',
		);
		expect(workflow).toContain("bun-version: '1.3.13'");
		expect(workflow).not.toContain('bun-version: latest');
	});

	test('requires release tags to point at commits reachable from main', async () => {
		const workflow = await Bun.file('.github/workflows/publish.yml').text();

		expect(workflow).toContain('fetch-depth: 0');
		expect(workflow).toContain('git fetch --no-tags origin main:refs/remotes/origin/main');
		expect(workflow).toContain('RELEASE_COMMIT="$(git rev-list -n 1 "$GITHUB_SHA")"');
		expect(workflow).toContain(
			'git merge-base --is-ancestor "$RELEASE_COMMIT" refs/remotes/origin/main',
		);
	});
});
