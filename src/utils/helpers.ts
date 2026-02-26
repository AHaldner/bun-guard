export const isValidVulnerability = (vulnerability: unknown): vulnerability is OSVVulnerability =>
	typeof vulnerability === 'object' &&
	vulnerability !== null &&
	typeof (vulnerability as OSVVulnerability).id === 'string' &&
	(vulnerability as OSVVulnerability).id.length > 0;
