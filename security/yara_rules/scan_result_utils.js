(function () {
	// Normalize various scan result shapes into an array so callers can safely do .forEach(...)
	function normalizeResults(results) {
		// null/undefined -> empty array
		if (!results) return [];

		// Already an array -> return as-is
		if (Array.isArray(results)) return results;

		// If it's an object wrapper containing arrays under common keys
		if (typeof results === 'object') {
			if (Array.isArray(results.results)) return results.results;
			if (Array.isArray(results.hits)) return results.hits;
			if (Array.isArray(results.items)) return results.items;
			if (Array.isArray(results.data)) return results.data;

			// Numeric-keyed object (e.g. { "0": {...}, "1": {...} })
			const numericKeys = Object.keys(results).filter(k => /^\d+$/.test(k)).sort((a,b) => Number(a) - Number(b));
			if (numericKeys.length) {
				return numericKeys.map(k => results[k]);
			}

			// Single result object -> wrap it
			return [results];
		}

		// Not an object/array -> return empty
		return [];
	}

	// Export for Node and browser globals
	if (typeof module !== 'undefined' && module.exports) {
		module.exports = { normalizeResults };
	} else if (typeof define === 'function' && define.amd) {
		define(function () { return { normalizeResults }; });
	} else {
		if (typeof window !== 'undefined') window.normalizeResults = normalizeResults;
		if (typeof global !== 'undefined') global.normalizeResults = normalizeResults;
	}
})();
