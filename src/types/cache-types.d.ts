type VulnerabilityRef = {
	id: string;
	modified?: string;
};

type CachedVulnerability = {
	fetchedAt: number;
	modified?: string;
	vulnerability: OSVVulnerability;
};
