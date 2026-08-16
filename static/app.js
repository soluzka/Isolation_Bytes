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
});

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
