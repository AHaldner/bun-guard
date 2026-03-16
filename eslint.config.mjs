import js from '@eslint/js';
import tseslint from '@typescript-eslint/eslint-plugin';
import tsparser from '@typescript-eslint/parser';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const tsconfigRootDir = dirname(fileURLToPath(import.meta.url));

const config = [
	js.configs.recommended,
	{
		files: ['**/*.ts'],
		languageOptions: {
			parser: tsparser,
			parserOptions: {
				ecmaVersion: 'latest',
				sourceType: 'module',
				project: './tsconfig.json',
				tsconfigRootDir,
			},
			globals: {
				Bun: 'readonly',
				fetch: 'readonly',
				console: 'readonly',
			},
		},
		plugins: {
			'@typescript-eslint': tseslint,
		},
		rules: {
			...tseslint.configs?.recommended?.rules,
			'@typescript-eslint/no-unused-vars': [
				'error',
				{
					argsIgnorePattern: '^_',
					varsIgnorePattern: '^_',
				},
			],
			'@typescript-eslint/no-explicit-any': 'warn',
			'@typescript-eslint/explicit-function-return-type': 'off',
			'@typescript-eslint/no-non-null-assertion': 'warn',
			'@typescript-eslint/consistent-type-assertions': ['error', { assertionStyle: 'never' }],
			'@typescript-eslint/no-unnecessary-type-assertion': 'error',
			'no-console': 'off',
			'no-undef': 'off',
		},
	},
	{
		ignores: ['node_modules/**', 'dist/**', '__tests__/**', 'bench/**'],
	},
];

export default config;
