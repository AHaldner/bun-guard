interface OSVQuery {
	version: string;
	package: {
		name: string;
		ecosystem: string;
	};
}

interface OSVVulnerability {
	id: string;
	summary: string;
	details: string;
	severity?: Array<{type: string; score: string}>;
	database_specific?: {severity?: string};
	references?: Array<{type: string; url: string}>;
}

interface OSVResponse {
	vulns: OSVVulnerability[];
}
