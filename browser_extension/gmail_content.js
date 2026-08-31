// Content script for Gmail: extracts email body and sends to phishing detector
function extractGmailEmailBody() {
    // Gmail uses 'div.a3s' for the email body
    let body = document.querySelector('div.a3s');
    return body ? body.innerText : '';
}

function sendToPhishingDetector(emailText) {
    fetch('http://localhost:5000/phishing_check', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({email_content: emailText})
    })
    .then(response => response.json())
    .then(data => {
        if (data.phishing) {
            blurAndDisableEmailBody();
        }
    });
}

// Observe for email open events
const observer = new MutationObserver(() => {
    let emailText = extractGmailEmailBody();
    if (emailText) {
        sendToPhishingDetector(emailText);
    }
});

observer.observe(document.body, {childList: true, subtree: true});

function blurAndDisableEmailBody() {
    let body = document.querySelector('div.a3s');
    if (!body) return;
    // Hide/blur the email body
    body.style.filter = 'blur(8px)';
    body.style.pointerEvents = 'none';
    // Disable all links
    let links = body.querySelectorAll('a');
    links.forEach(link => {
        link.removeAttribute('href');
        link.style.pointerEvents = 'none';
        link.style.color = 'gray';
        link.title = 'Disabled due to phishing risk';
    });
    // Add warning overlay
    if (!document.getElementById('phishing-warning-overlay')) {
        let overlay = document.createElement('div');
        overlay.id = 'phishing-warning-overlay';
        overlay.style.position = 'absolute';
        overlay.style.top = '0';
        overlay.style.left = '0';
        overlay.style.width = '100%';
        overlay.style.background = 'rgba(255,0,0,0.9)';
        overlay.style.color = 'white';
        overlay.style.padding = '1.5em';
        overlay.style.zIndex = '9999';
        overlay.style.textAlign = 'center';
        overlay.innerHTML = '<b>Phishing detected!</b> This email has been hidden for your safety.<br><button id="show-anyway-btn" style="margin-top:1em;font-size:1em;">Show Anyway (Unsafe)</button>';
        body.parentElement.insertBefore(overlay, body);
        document.getElementById('show-anyway-btn').onclick = function() {
            body.style.filter = '';
            body.style.pointerEvents = '';
            overlay.remove();
        };
    }
}
