/**
 * Shared helpers for fetching and normalizing network-monitor / folder-watcher
 * data from the backend.
 */
(function (global) {
    'use strict';

    function isSafeRelativePath(url) {
        return typeof url === 'string' && /^\/(?!\/)/.test(url);
    }

    function installScanTriggerResponseNormalizer() {
        const originalFetch = global.fetch;
        if (typeof originalFetch !== 'function' || originalFetch.__scanStatusNormalized) {
            return;
        }

        const wrappedFetch = function (resource, options) {
            return originalFetch.call(this, resource, options).then(function (response) {
                const url = typeof resource === 'string' ? resource : (resource && resource.url) || '';

                if (url.includes('/api/agent-trigger-scan')) {
                    const originalJson = response.json.bind(response);
                    response.json = function () {
                        return originalJson().then(function (data) {
                            if (data && typeof data === 'object') {
                                const successful = data.ok === true || data.success === true || data.status === 'success' || data.status === 'started' || data.status === 'already_running';
                                data.success = successful;
                                data.ok = successful;
                                data.message_type = successful ? 'success' : 'error';
                                if (successful) {
                                    data.error = null;
                                    // The Index dashboard's existing scan-trigger handler
                                    // accepts the legacy started/already_running states.
                                    // Keep that compatibility while the backend continues
                                    // to expose the canonical status=success response.
                                    if (data.status === 'success') data.status = 'started';
                                } else {
                                    data.status = 'error';
                                }
                            }
                            return data;
                        });
                    };
                    return response;
                }

                // Index.html and the YARA page both poll this endpoint. Normalize
                // the live counters here so a delayed heartbeat can never make the
                // browser display a lower count than it already showed.
                if (url.includes('/api/conditional_startup/status')) {
                    const originalJson = response.json.bind(response);
                    response.json = function () {
                        return originalJson().then(function (data) {
                            if (!data || typeof data !== 'object') return data;
                            const state = global.__isolationBytesScanDisplay || {
                                scanned_files: 0,
                                quarantined_files: 0,
                                blocked_threats: 0
                            };
                            data.scanned_files = Math.max(Number(data.scanned_files) || 0, state.scanned_files);
                            data.quarantined_files = Math.max(Number(data.quarantined_files) || 0, state.quarantined_files);
                            data.blocked_threats = Math.max(Number(data.blocked_threats) || 0, state.blocked_threats);
                            state.scanned_files = data.scanned_files;
                            state.quarantined_files = data.quarantined_files;
                            state.blocked_threats = data.blocked_threats;
                            global.__isolationBytesScanDisplay = state;

                            // Do not display a transient agent/heartbeat transport
                            // message as a scan failure. The scan counters remain live.
                            if (typeof data.last_error === 'string' && /agent|heartbeat|connection|timeout/i.test(data.last_error)) {
                                data.last_error = '';
                            }
                            if (data.last_error === null || data.last_error === undefined) {
                                data.last_error = '';
                            }
                            if (!Number.isFinite(Number(data.errors)) || Number(data.errors) < 0) {
                                data.errors = 0;
                            }
                            return data;
                        });
                    };
                    return response;
                }

                return response;
            });
        };
        wrappedFetch.__scanStatusNormalized = true;
        global.fetch = wrappedFetch;
    }

    installScanTriggerResponseNormalizer();

    async function fetchJsonSafe(url, options) {
        if (!isSafeRelativePath(url)) {
            return { ok: false, status: null, data: null, error: 'Refused to fetch a non-relative or unsafe URL' };
        }
        options = options || {};
        if (!options.credentials) options.credentials = 'include';
        try {
            const response = await fetch(url, options);
            if (!response.ok) {
                return { ok: false, status: response.status, data: null, error: `Request failed with status ${response.status}` };
            }
            try {
                const data = await response.json();
                return { ok: true, status: response.status, data, error: null };
            } catch (parseError) {
                return { ok: false, status: response.status, data: null, error: 'Response was not valid JSON' };
            }
        } catch (networkError) {
            return { ok: false, status: null, data: null, error: (networkError && networkError.message) || 'Network request failed' };
        }
    }

    function normalizeNetworkMonitorData(result) {
        const empty = {
            success: false,
            error: (result && result.error) || 'Not available',
            monitored_directories: [],
            monitoring_status: { enabled: false, last_scan: 'Never', total_directories: 0, total_files_monitored: 0, directories: [] }
        };
        if (!result || !result.ok || !result.data) return empty;
        const data = result.data;
        const monitoredDirectories = Array.isArray(data.monitored_directories) ? data.monitored_directories : [];
        const rawStatus = (data.monitoring_status && typeof data.monitoring_status === 'object') ? data.monitoring_status : {};
        return {
            success: data.success !== false,
            error: data.success === false ? (data.error || 'Unknown error') : null,
            monitored_directories: monitoredDirectories,
            monitoring_status: {
                enabled: !!rawStatus.enabled,
                last_scan: rawStatus.last_scan || 'Never',
                total_directories: rawStatus.total_directories != null ? rawStatus.total_directories : monitoredDirectories.length,
                total_files_monitored: rawStatus.total_files_monitored != null ? rawStatus.total_files_monitored : 0,
                directories: Array.isArray(rawStatus.directories) ? rawStatus.directories : []
            }
        };
    }

    function normalizeFolderWatcherData(result) {
        const empty = { success: false, error: (result && result.error) || 'Not available', monitored_paths: [], paths: [] };
        if (!result || !result.ok || !result.data) return empty;
        const data = result.data;
        return {
            success: data.success !== false,
            error: data.success === false ? (data.error || 'Unknown error') : null,
            monitored_paths: Array.isArray(data.monitored_paths) ? data.monitored_paths : [],
            paths: Array.isArray(data.paths) ? data.paths : []
        };
    }

    function normalizeTrafficStats(result) {
        const empty = { success: false, error: (result && result.error) || 'Not available', total_connections: 0, active_ips: [], inbound: 0, outbound: 0, protocols: {}, processes: {} };
        if (!result || !result.ok || !result.data) return empty;
        const data = result.data;
        if (data.error && data.success === undefined) return { ...empty, error: data.error };
        return {
            success: data.success !== false,
            error: data.success === false ? (data.error || 'Unknown error') : null,
            total_connections: data.total_connections || 0,
            active_ips: Array.isArray(data.active_ips) ? data.active_ips : [],
            inbound: data.inbound || 0,
            outbound: data.outbound || 0,
            protocols: (data.protocols && typeof data.protocols === 'object') ? data.protocols : {},
            processes: (data.processes && typeof data.processes === 'object') ? data.processes : {}
        };
    }

    function normalizeC2Patterns(result) {
        const empty = { success: false, error: (result && result.error) || 'Not available', suspicious_connections: [] };
        if (!result || !result.ok || !result.data) return empty;
        const data = result.data;
        return {
            success: data.success !== false,
            error: data.success === false ? (data.error || 'Unknown error') : null,
            suspicious_connections: Array.isArray(data.suspicious_connections) ? data.suspicious_connections : []
        };
    }

    global.NetworkDataUtils = {
        fetchJsonSafe,
        normalizeNetworkMonitorData,
        normalizeFolderWatcherData,
        normalizeTrafficStats,
        normalizeC2Patterns
    };
})(window);