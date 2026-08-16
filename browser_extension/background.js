/* global chrome */
// Simple real-time phishing check and download scanner for the local dashboard.
// Replace the phishingCheck and downloadScan functions with your own logic or API calls.

async function backendPhishingCheck(url) {
    try {
        const response = await fetch('http://localhost:5000/phishing_check', {
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
        const response = await fetch('http://localhost:5000/api/scan_download', {
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
