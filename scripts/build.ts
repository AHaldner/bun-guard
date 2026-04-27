import { spawnSync } from 'node:child_process';
import { rm } from 'node:fs/promises';

const run = (command: string, args: string[]): void => {
	const result = spawnSync(command, args, {
		stdio: 'inherit',
		env: process.env,
	});

	if (result.status !== 0) {
		process.exit(result.status ?? 1);
	}
};

await rm('dist', { recursive: true, force: true });

const buildResult = await Bun.build({
	entrypoints: ['src/index.ts'],
	outdir: 'dist',
	target: 'bun',
	format: 'esm',
	naming: 'index.mjs',
});

if (!buildResult.success) {
	for (const log of buildResult.logs) {
		console.error(log);
	}

	process.exit(1);
}

run('tsc', ['-p', 'tsconfig.build.json']);
