import { defineConfig } from 'tsdown/config';

export default defineConfig({
	entry: 'src/index.ts',
	format: 'esm',
	outDir: 'dist',
	platform: 'node',
	target: 'esnext',
	clean: true,
	dts: true,
	hash: false,
	report: false,
	outExtensions: () => ({
		js: '.mjs',
		dts: '.d.ts',
	}),
});
