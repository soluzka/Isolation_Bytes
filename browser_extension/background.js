/* global chrome */
// Isolation Bytes browser extension — phishing check, download scanner,
// and cloud agent reporting. Uses the cloud server at isolation-bytes.com.

const CLOUD_URL = 'https://isolation-bytes.com';
const API_KEY = 'af5caf8d3d8080f8a8686f72dfa52eb92dad9ef95ebfdcd6f6494cf99ed6b909';
const EXTENSION_DEVICE_ID = 'BROWSER-' + (chrome.runtime?.id || 'unknown').slice(0, 8).toUpperCase();

async function backendPhishingCheck(url) {
    try {
        const response = await fetch(`${CLOUD_URL}/phishing_check`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({url: url, source: 'browser_extension'})
        });
        const data = await response.json();
        return data.phishing === true;
    } catch (e) {
        // Fail open (do not block) if backend is unreachable
        return false;
    }
}

const requestFilter = {
    // This is a Chrome match pattern, not HTML. The static scanner may flag it
    // because it contains "<" and ">"; suppress that false positive here.
    // eslint-disable-next-line
    urls: ["<all_urls>"]
};

chrome.webRequest.onBeforeRequest.addListener(
    function(details) {
        const url = details.url;
        const blockingResponse = {cancel: false};
        // Use a promise to block until backend responds
        return new Promise((resolve) => {
            backendPhishingCheck(url).then(isPhishing => {
                if (isPhishing) {
                    // Optionally, show a notification or redirect to warning page
                    resolve({cancel: true});
                } else {
                    resolve(blockingResponse);
                }
            }).catch(() => {
                resolve(blockingResponse);
            });
        });
    },
    requestFilter,
    ["blocking"]
);

// ---- Download scanner ----

async function backendDownloadScan(info) {
    try {
        const response = await fetch(`${CLOUD_URL}/api/scan_download`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                url: info.url,
                filename: info.filename,
                file_size: info.fileSize,
                source: 'browser_extension'
            })
        });
        const data = await response.json();
        return data.threat === true;
    } catch (e) {
        // Fail open if backend is unreachable
        return false;
    }
}

function notifyDownloadThreat(filename, url) {
    chrome.notifications.create('download-threat-' + Date.now(), {
        type: 'basic',
        iconUrl: 'icon48.png',
        title: 'Download blocked',
        message: `The file "${filename}" from ${new URL(url).hostname} was flagged by the antivirus.`
    });
}

if (chrome.downloads) {
    chrome.downloads.onCreated.addListener(function(downloadItem) {
        backendDownloadScan(downloadItem).then(isThreat => {
            if (isThreat) {
                chrome.downloads.cancel(downloadItem.id);
                notifyDownloadThreat(downloadItem.filename, downloadItem.url);
            }
        }).catch(() => {
            // fail open
        });
    });
}

// ---- Cloud agent heartbeat ----
// Reports browser extension status to the cloud dashboard so it shows
// up as a connected device alongside Windows/macOS/Linux agents.

async function registerWithCloud() {
    try {
        await fetch(`${CLOUD_URL}/agent/register`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                device_id: EXTENSION_DEVICE_ID,
                hostname: 'Browser Extension',
                os: navigator.platform || 'browser',
                os_version: navigator.userAgent,
                agent_version: '1.8.894.0',
                api_key: API_KEY
            })
        });
    } catch (e) {
        // Fail silently — will retry
    }
}

async function sendHeartbeat() {
    try {
        const tabs = await chrome.tabs.query({});
        const data = {
            device_id: EXTENSION_DEVICE_ID,
            cpu_usage: 0,
            mem_usage: 0,
            disk_usage: 0,
            uptime: '0d 0h 0m',
            files_scanned: 0,
            threats_blocked: 0,
            quarantined_count: 0,
            scan_dirs: [],
            network_connections: [],
            network_devices: [],
            processes: [],
            process_count: tabs.length,
            connection_count: tabs.length,
            flagged_connections: [],
            watched_connections: [],
            flagged_count: 0,
            watched_count: 0
        };
        await fetch(`${CLOUD_URL}/agent/heartbeat`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data)
        });
    } catch (e) {
        // Fail silently — will retry
    }
}

// Register on startup, then heartbeat every 30 seconds
registerWithCloud();
setInterval(() => {
    sendHeartbeat();
}, 30000);
