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

    // Index.html and yara_scanner.html now use the same renderer and the same
    // /api/agent-scan-results payload. This prevents either page from inventing
    // its own counters or displaying a different set of findings.
    function renderUnifiedAgentScanResults(data) {
        const el = document.getElementById('agent_scan_results');
        if (!el) return;
        const agents = (data && data.agents) || [];
        if (!agents.length) {
            el.innerHTML = '<p>No connected agents reporting scan results.</p>';
            return;
        }

        let html = '';
        const sevColor = {critical: '#dc3545', high: '#fd7e14', medium: '#ffc107', low: '#28a745'};
        for (const ag of agents) {
            const findings = Array.isArray(ag.findings) ? ag.findings : (Array.isArray(ag.results) ? ag.results : []);
            const scanDirs = Array.isArray(ag.scan_dirs) ? ag.scan_dirs : [];
            let findingsHtml = '';
            if (findings.length) {
                findingsHtml = '<table class="table" style="margin-top:8px;"><thead><tr><th>Path</th><th>Rule</th><th>Severity</th><th>Type</th><th>Quarantined</th></tr></thead><tbody>';
                for (const f of findings) {
                    const sev = String(f.severity || 'low').toLowerCase();
                    const color = sevColor[sev] || '#6c757d';
                    const qIcon = f.quarantined ? '✓ Yes' : (f.quarantine_error ? '✗ Failed' : '—');
                    findingsHtml += '<tr><td style="word-break:break-all;">' + escapeHtml(f.path || '') + '</td><td>' + escapeHtml(f.rule || '') + '</td><td style="color:' + color + ';font-weight:bold;">' + escapeHtml(sev) + '</td><td>' + escapeHtml(f.threat_type || '') + '</td><td>' + escapeHtml(qIcon) + '</td></tr>';
                }
                findingsHtml += '</tbody></table>';
            } else {
                findingsHtml = '<p style="margin-top:8px;color:#28a745;">No threats found on last scan.</p>';
            }

            let dirsHtml = '';
            if (scanDirs.length) {
                dirsHtml = '<details style="margin-top:6px;"><summary style="cursor:pointer;font-size:13px;">Scanned areas (' + scanDirs.length + ')</summary><ul style="font-size:12px;color:#555;max-height:200px;overflow:auto;">';
                for (const d of scanDirs) dirsHtml += '<li>' + escapeHtml(d) + '</li>';
                dirsHtml += '</ul></details>';
            }

            const filesScanned = Number(ag.files_scanned) || 0;
            const findingCount = Number(ag.finding_count) || findings.length;
            const quarantinedCount = Number(ag.quarantined_count) || 0;
            html += '<div style="border:1px solid #dee2e6;border-radius:6px;padding:12px;margin-bottom:12px;"><h4 style="margin:0 0 6px 0;">' + escapeHtml(ag.hostname || ag.device_id || 'Agent') + '</h4><p style="margin:2px 0;font-size:13px;">Files scanned: <strong>' + filesScanned + '</strong> &middot; Findings: <strong style="color:' + (findingCount ? '#dc3545' : '#28a745') + ';">' + findingCount + '</strong> &middot; Quarantined: <strong>' + quarantinedCount + '</strong> &middot; Last scan: ' + escapeHtml(ag.last_scan || 'N/A') + '</p>' + dirsHtml + findingsHtml + '</div>';
        }
        el.innerHTML = html;
    }

    function escapeHtml(value) {
        const d = document.createElement('div');
        d.textContent = value == null ? '' : String(value);
        return d.innerHTML;
    }

    let unifiedAgentResultsTimer = null;
    let unifiedAgentResultsStarted = false;

    async function refreshUnifiedAgentScanResults() {
        const el = document.getElementById('agent_scan_results');
        if (!el) return;
        try {
            const result = await fetchJsonSafe('/api/agent-scan-results', {credentials: 'same-origin', cache: 'no-store'});
            if (!result.ok) throw new Error(result.error || 'Unable to load agent scan results');
            renderUnifiedAgentScanResults(result.data);
            const loading = document.getElementById('loadingIndicator');
            if (loading) loading.style.display = 'none';
        } catch (error) {
            // Keep the last good scan state visible during transient polling errors.
            if (!el.dataset.hasAgentResults) {
                el.innerHTML = '<p class="alert alert-warning">Unable to load agent scan results.</p>';
            }
        }
        if (el.innerHTML && !el.innerHTML.includes('Unable to load')) {
            el.dataset.hasAgentResults = 'true';
        }
    }

    function installUnifiedAgentScanResults() {
        if (unifiedAgentResultsStarted) return;
        if (!document.getElementById('agent_scan_results')) return;
        unifiedAgentResultsStarted = true;
        refreshUnifiedAgentScanResults();
        unifiedAgentResultsTimer = global.setInterval(refreshUnifiedAgentScanResults, 5000);
    }

    global.NetworkDataUtils = {
        fetchJsonSafe,
        normalizeNetworkMonitorData,
        normalizeFolderWatcherData,
        normalizeTrafficStats,
        normalizeC2Patterns,
        renderUnifiedAgentScanResults,
        refreshUnifiedAgentScanResults,
        installUnifiedAgentScanResults
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', installUnifiedAgentScanResults);
    } else {
        installUnifiedAgentScanResults();
    }
})(window);