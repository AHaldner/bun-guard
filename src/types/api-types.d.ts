interface OSVQuery {
	version: string;
	package: {
		name: string;
		ecosystem: string;
	};
}

interface OSVVulnerability {
	id: string;
	summary?: string;
	details?: string;
	modified?: string;
	severity?: Array<{ type: string; score: string }>;
	database_specific?: { severity?: string };
	references?: Array<{ type: string; url: string }>;
}

interface OSVResponse {
	vulns: OSVVulnerability[];
}

interface OSVBatchRequest {
	queries: OSVQuery[];
}

interface OSVBatchResult {
	vulns?: OSVVulnerability[];
}

interface OSVBatchResponse {
	results: OSVBatchResult[];
}

interface PackageJson {
	name?: string;
	version?: string;
	overrides?: Record<string, unknown>;
	resolutions?: Record<string, unknown>;
	[key: string]: unknown;
}
