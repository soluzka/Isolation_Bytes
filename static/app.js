// Escape a string for safe HTML insertion
function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    return String(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
window.escapeHtml = escapeHtml;

$(document).ready(function() {
    updateSystemStatus();
    updateThreatDetection();
    updateNetworkMonitor();

    // Update status periodically
    setInterval(updateSystemStatus, 30000); // Every 30 seconds
    setInterval(updateThreatDetection, 60000); // Every minute
    setInterval(updateNetworkMonitor, 10000); // Every 10 seconds

    // Delegated handler for dynamically-created quarantine buttons
    $(document).on('click', '.quarantine-btn', function() {
        const id = $(this).data('id');
        const type = $(this).data('type');
        handleThreat(id, type);
    });

    // Prompt desktop users to install the background agent
    checkAgentInstalled();
});

function checkAgentInstalled() {
    if (localStorage.getItem('ib_agent_prompted') === '1') return;

    fetch('/api/agents', { credentials: 'include' })
        .then(r => r.ok ? r.json() : null)
        .then(data => {
            const agents = (data && data.agents) || [];
            const myHost = (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || '';
            const hasAgent = agents.some(a => a.hostname && a.hostname.toLowerCase().includes(myHost.split(' ')[0].toLowerCase()));
            if (!hasAgent) showAgentInstallPrompt();
        })
        .catch(() => {
            showAgentInstallPrompt();
        });
}

function detectOS() {
    const ua = navigator.userAgent || '';
    const platform = (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || '';
    if (/Win/i.test(platform) || /Windows/i.test(ua)) return 'windows';
    if (/Mac/i.test(platform) || /Macintosh|Mac OS X/i.test(ua)) return 'macos';
    if (/Linux/i.test(platform) || /Linux|X11/i.test(ua)) return 'linux';
    if (/CrOS/i.test(ua)) return 'chromeos';
    if (/Android/i.test(ua)) return 'android';
    if (/iPhone|iPad|iPod/i.test(ua)) return 'ios';
    return 'unknown';
}

function getInstallInfo(os) {
    const installs = {
        windows: {
            url: '/download/install-windows.ps1',
            label: 'Install Agent (PowerShell)',
            cmd: 'iwr https://isolation-bytes.com/download/install-windows.ps1 -UseBasicParsing | iex',
            cmdLabel: 'Or run in PowerShell:'
        },
        macos: {
            url: '/download/install-macos.sh',
            label: 'Install Agent (macOS)',
            cmd: 'curl -fsSL https://isolation-bytes.com/download/install-macos.sh | bash',
            cmdLabel: 'Or run in Terminal:'
        },
        linux: {
            url: '/download/install-linux.sh',
            label: 'Install Agent (Linux)',
            cmd: 'curl -fsSL https://isolation-bytes.com/download/install-linux.sh | bash',
            cmdLabel: 'Or run in Terminal:'
        },
        chromeos: {
            url: '/download/install-chromeos.sh',
            label: 'Install Agent (ChromeOS)',
            cmd: 'curl -fsSL https://isolation-bytes.com/download/install-chromeos.sh | bash',
            cmdLabel: 'Run in Terminal (Linux container):'
        },
        android: {
            url: '/download/install-android.sh',
            label: 'Install Agent (Termux)',
            cmd: 'curl -fsSL https://isolation-bytes.com/download/install-android.sh | bash',
            cmdLabel: 'Run in Termux:'
        },
        ios: {
            url: '/install',
            label: 'Install Agent (iOS)',
            cmd: '',
            cmdLabel: ''
        }
    };
    return installs[os] || installs.windows;
}

function showAgentInstallPrompt() {
    localStorage.setItem('ib_agent_prompted', '1');
    const os = detectOS();
    const info = getInstallInfo(os);

    const banner = document.createElement('div');
    banner.style.cssText = 'position:fixed;bottom:0;left:0;right:0;background:#0b1321;color:#e0e1dd;padding:14px 20px;z-index:9999;border-top:2px solid #00b4d8;font-family:Segoe UI,sans-serif;display:flex;align-items:center;gap:16px;flex-wrap:wrap';

    const text = document.createElement('div');
    text.style.cssText = 'flex:1;min-width:200px';
    text.innerHTML = '<strong style="color:#90e0ef">Network Agent Not Detected</strong><br><span style="font-size:0.9em;color:#778da9">Install the background agent for real-time threat monitoring, network scanning, and automatic reporting to this dashboard.</span>';
    banner.appendChild(text);

    const installBtn = document.createElement('a');
    installBtn.href = info.url;
    installBtn.textContent = info.label;
    installBtn.style.cssText = 'background:#00b4d8;color:#0b1321;padding:8px 18px;border-radius:6px;text-decoration:none;font-weight:600;white-space:nowrap';
    banner.appendChild(installBtn);

    if (info.cmd) {
        const cmdDiv = document.createElement('div');
        cmdDiv.style.cssText = 'flex-basis:100%;margin-top:8px';
        const labelSpan = document.createElement('span');
        labelSpan.style.cssText = 'font-size:0.8em;color:#778da9';
        labelSpan.textContent = info.cmdLabel || '';
        const br = document.createElement('br');
        const code = document.createElement('code');
        code.style.cssText = 'background:#1a2a3a;color:#90e0ef;padding:4px 8px;border-radius:4px;font-size:0.85em;display:inline-block;margin-top:4px;user-select:all';
        code.textContent = info.cmd;
        cmdDiv.appendChild(labelSpan);
        cmdDiv.appendChild(br);
        cmdDiv.appendChild(code);
        banner.appendChild(cmdDiv);
    }

    const closeBtn = document.createElement('button');
    closeBtn.textContent = 'Later';
    closeBtn.style.cssText = 'background:transparent;color:#778da9;border:1px solid #415a77;padding:8px 14px;border-radius:6px;cursor:pointer';
    closeBtn.onclick = function() { banner.remove(); };
    banner.appendChild(closeBtn);

    document.body.appendChild(banner);
}

function updateSystemStatus() {
    $.get('/status', function(data) {
        const container = document.getElementById('system-status');
        if (!container) return;
        while (container.lastChild) container.removeChild(container.lastChild);

        function makeIndicator(cls) {
            const el = document.createElement('div');
            el.className = 'status-indicator ' + cls;
            return el;
        }

        const rtClass = data.realtime_protection ? 'status-ok' : 'status-error';
        const rtText = data.realtime_protection ? 'Enabled' : 'Disabled';

        container.appendChild(makeIndicator(rtClass));
        container.appendChild(document.createTextNode(' Real-time protection: ' + rtText));
        container.appendChild(document.createElement('br'));
        container.appendChild(makeIndicator('status-ok'));
        container.appendChild(document.createTextNode(' Network Monitor: ' + (data.network_monitor ? 'Enabled' : 'Disabled')));
        container.appendChild(document.createElement('br'));
        container.appendChild(makeIndicator('status-ok'));
        container.appendChild(document.createTextNode(' Safe Downloader: ' + (data.safe_downloader ? 'Enabled' : 'Disabled')));
    }).fail(function() {
        const container = document.getElementById('system-status');
        if (container) {
            while (container.lastChild) container.removeChild(container.lastChild);
            const el = document.createElement('div');
            el.className = 'status-indicator status-error';
            container.appendChild(el);
            container.appendChild(document.createTextNode(' Failed to load status'));
        }
    });
}

function updateThreatDetection() {
    $.get('/threats', function(data) {
        const container = document.getElementById('threat-detection');
        if (!container) return;
        while (container.lastChild) container.removeChild(container.lastChild);

        if (data.threats.length > 0) {
            const title = document.createElement('div');
            title.className = 'alert alert-warning';
            title.textContent = 'Detected Threats:';
            container.appendChild(title);

            data.threats.forEach(threat => {
                const div = document.createElement('div');
                div.className = 'alert alert-info';

                const strongType = document.createElement('strong');
                strongType.textContent = threat.type;
                div.appendChild(strongType);
                div.appendChild(document.createTextNode(' detected in '));
                const strongLoc = document.createElement('strong');
                strongLoc.textContent = threat.location;
                div.appendChild(strongLoc);

                const btn = document.createElement('button');
                btn.className = 'btn btn-sm btn-danger float-end quarantine-btn';
                btn.setAttribute('data-id', String(threat.id));
                btn.setAttribute('data-type', threat.type);
                btn.textContent = 'Quarantine';
                div.appendChild(btn);

                container.appendChild(div);
            });
        } else {
            const alert = document.createElement('div');
            alert.className = 'alert alert-success';
            alert.textContent = 'No threats detected';
            container.appendChild(alert);
        }
    }).fail(function() {
        const container = document.getElementById('threat-detection');
        if (container) {
            while (container.lastChild) container.removeChild(container.lastChild);
            const alert = document.createElement('div');
            alert.className = 'alert alert-danger';
            alert.textContent = 'Failed to load threat detection status';
            container.appendChild(alert);
        }
    });
}

function updateNetworkMonitor() {
    $.get('/network', function(data) {
        const container = document.getElementById('network-monitor');
        if (!container) return;
        while (container.lastChild) container.removeChild(container.lastChild);

        const conn = document.createElement('div');
        conn.textContent = 'Active Connections: ' + String(data.active_connections);
        container.appendChild(conn);

        const rate = document.createElement('div');
        rate.textContent = 'Data Rate: ' + String(data.data_rate) + ' KB/s';
        container.appendChild(rate);

        const packet = document.createElement('div');
        packet.textContent = 'Packet Rate: ' + String(data.packet_rate) + ' pps';
        container.appendChild(packet);
    }).fail(function() {
        const container = document.getElementById('network-monitor');
        if (container) {
            while (container.lastChild) container.removeChild(container.lastChild);
            const alert = document.createElement('div');
            alert.className = 'alert alert-danger';
            alert.textContent = 'Failed to load network status';
            container.appendChild(alert);
        }
    });
}

function handleThreat(threatId, threatType) {
    if (!confirm('Are you sure you want to quarantine this threat?')) {
        return;
    }

    $.post('/quarantine', {
        threat_id: threatId,
        threat_type: threatType
    }, function(response) {
        if (response.success) {
            alert('Threat has been quarantined successfully');
            updateThreatDetection();
        } else {
            alert('Failed to quarantine threat: ' + response.error);
        }
    });
}
