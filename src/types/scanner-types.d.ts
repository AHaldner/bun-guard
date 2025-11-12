interface Package {
	name: string;
	version: string;
}

interface Advisory {
	level: 'fatal' | 'warn';
	package: string;
	url: string | null;
	description: string | null;
}

interface ScanContext {
	packages: Package[];
}

interface Scanner {
	version: string;
	scan(context: ScanContext): Promise<Advisory[]>;
}
