const PREFIX = '[bun-guard]';

const ANSI = {
	reset: '\x1b[0m',
	yellow: '\x1b[33m',
	red: '\x1b[31m',
} as const;

export const logger = {
	warn: (message: string): void => {
		console.warn(`${ANSI.yellow}${PREFIX} ${message}${ANSI.reset}`);
	},
	error: (message: string): void => {
		console.error(`${ANSI.red}${PREFIX} ${message}${ANSI.reset}`);
	},
};
