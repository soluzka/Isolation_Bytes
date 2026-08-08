// Simple real-time phishing check (template)
// Replace the phishingCheck function with your own logic or API call

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
    {urls: ["<all_urls>"]},
    ["blocking"]
);
