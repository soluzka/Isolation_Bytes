/**
 * Shared helpers for fetching and normalizing network-monitor / folder-watcher
 * data from the backend.
 *
 * Why this exists:
 * - Several pages (index.html, yara_scanner.html) independently implemented
 *   ad hoc fetch + fallback logic for the same endpoints. Each implementation
 *   handled failures (network errors, non-2xx responses, non-JSON bodies)
 *   differently, and none of the failure-fallback objects matched the shape
 *   the success-path rendering code expected (e.g. a failed fetch would
 *   return an object without `monitored_directories`, while the success path
 *   always assumed that key existed). That mismatch is what caused errors
 *   like "networkData.monitored_directories is not iterable" whenever the
 *   server was briefly unreachable (restarting, etc).
 * - This file centralizes that logic in one place with a single, always-
 *   consistent shape for both the success and failure cases, so consumers
 *   never need to guess (or crash on) what fields are present.
 */
(function (global) {
    'use strict';

    /**
     * Only allow same-origin, relative API paths (e.g. "/get_traffic_stats").
     * This function is only ever called today with hardcoded literal
     * endpoint strings, never with user/query-string-derived input -- but
     * since it's a shared utility, this guard ensures that if a future
     * caller ever passes untrusted input by mistake, it can't be used to
     * make this app fetch an arbitrary external URL (e.g. "https://evil.com"
     * or a protocol-relative "//evil.com") on the user's behalf.
     */
    function isSafeRelativePath(url) {
        return typeof url === 'string' && /^\/(?!\/)/.test(url);
    }

    /**
     * Fetch JSON from a URL. Never rejects/throws: resolves to
     * { ok: boolean, status: number|null, data: any, error: string|null }.
     */
    async function fetchJsonSafe(url, options) {
        if (!isSafeRelativePath(url)) {
            return { ok: false, status: null, data: null, error: 'Refused to fetch a non-relative or unsafe URL' };
        }
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

    /**
     * Normalize a response from /get_network_monitored_directories (or a
     * failed fetch) into a single canonical shape that is always safe to
     * destructure/iterate, regardless of whether the request succeeded.
     *
     * Canonical shape:
     * {
     *   success: boolean,
     *   error: string|null,
     *   monitored_directories: string[],
     *   monitoring_status: {
     *     enabled: boolean,
     *     last_scan: string,
     *     total_directories: number,
     *     total_files_monitored: number,
     *     directories: Array<{path, exists, accessible, file_count, ...}>
     *   }
     * }
     */
    function normalizeNetworkMonitorData(result) {
        const empty = {
            success: false,
            error: (result && result.error) || 'Not available',
            monitored_directories: [],
            monitoring_status: {
                enabled: false,
                last_scan: 'Never',
                total_directories: 0,
                total_files_monitored: 0,
                directories: []
            }
        };

        if (!result || !result.ok || !result.data) {
            return empty;
        }

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
                total_files_monitored: rawStatus.total_files_monitored || 0,
                directories: Array.isArray(rawStatus.directories) ? rawStatus.directories : []
            }
        };
    }

    /**
     * Normalize a response from /get_folder_watcher_paths (or a failed
     * fetch) into a single canonical shape.
     *
     * Canonical shape:
     * {
     *   success: boolean,
     *   error: string|null,
     *   monitored_paths: string[],           // plain path strings
     *   paths: Array<{path, exists, accessible, file_count, ...}>  // detailed entries
     * }
     */
    function normalizeFolderWatcherData(result) {
        const empty = {
            success: false,
            error: (result && result.error) || 'Not available',
            monitored_paths: [],
            paths: []
        };

        if (!result || !result.ok || !result.data) {
            return empty;
        }

        const data = result.data;
        return {
            success: data.success !== false,
            error: data.success === false ? (data.error || 'Unknown error') : null,
            monitored_paths: Array.isArray(data.monitored_paths) ? data.monitored_paths : [],
            paths: Array.isArray(data.paths) ? data.paths : []
        };
    }

    /**
     * Normalize a response from /get_traffic_stats (or a failed fetch) into
     * a single canonical shape.
     *
     * Canonical shape:
     * {
     *   success: boolean,
     *   error: string|null,
     *   total_connections: number,
     *   active_ips: string[],
     *   inbound: number,
     *   outbound: number,
     *   protocols: Record<string, number>,
     *   processes: Record<string, {connections: number}>
     * }
     */
    function normalizeTrafficStats(result) {
        const empty = {
            success: false,
            error: (result && result.error) || 'Not available',
            total_connections: 0,
            active_ips: [],
            inbound: 0,
            outbound: 0,
            protocols: {},
            processes: {}
        };

        if (!result || !result.ok || !result.data) {
            return empty;
        }

        const data = result.data;
        if (data.error && data.success === undefined) {
            // Some legacy endpoints report {error: '...'} without a success flag.
            return { ...empty, error: data.error };
        }

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

    /**
     * Normalize a response from /get_c2_patterns (or a failed fetch) into a
     * single canonical shape.
     *
     * Canonical shape:
     * {
     *   success: boolean,
     *   error: string|null,
     *   suspicious_connections: Array<{process, remote_ip, remote_port, reason}>
     * }
     */
    function normalizeC2Patterns(result) {
        const empty = { success: false, error: (result && result.error) || 'Not available', suspicious_connections: [] };

        if (!result || !result.ok || !result.data) {
            return empty;
        }

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
