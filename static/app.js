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
        const container = $('#system-status').empty();
        const rtClass = data.realtime_protection ? 'status-ok' : 'status-error';
        const rtText = data.realtime_protection ? 'Enabled' : 'Disabled';
        container
            .append($('<div>').addClass('status-indicator ' + rtClass))
            .append(document.createTextNode(' Real-time protection: ' + rtText))
            .append($('<br>'))
            .append($('<div>').addClass('status-indicator status-ok'))
            .append(document.createTextNode(' Network Monitor: ' + (data.network_monitor ? 'Enabled' : 'Disabled')))
            .append($('<br>'))
            .append($('<div>').addClass('status-indicator status-ok'))
            .append(document.createTextNode(' Safe Downloader: ' + (data.safe_downloader ? 'Enabled' : 'Disabled')));
    }).fail(function() {
        $('#system-status').empty()
            .append($('<div>').addClass('status-indicator status-error'))
            .append(document.createTextNode(' Failed to load status'));
    });
}

function updateThreatDetection() {
    $.get('/threats', function(data) {
        const container = $('#threat-detection').empty();
        if (data.threats.length > 0) {
            container.append($('<div>').addClass('alert alert-warning').text('Detected Threats:'));
            data.threats.forEach(threat => {
                const div = $('<div>').addClass('alert alert-info');
                div.append($('<strong>').text(threat.type))
                   .append(document.createTextNode(' detected in '))
                   .append($('<strong>').text(threat.location));
                const btn = $('<button>')
                    .addClass('btn btn-sm btn-danger float-end quarantine-btn')
                    .attr('data-id', String(threat.id))
                    .attr('data-type', threat.type)
                    .text('Quarantine');
                div.append(btn);
                container.append(div);
            });
        } else {
            container.append($('<div>').addClass('alert alert-success').text('No threats detected'));
        }
    }).fail(function() {
        $('#threat-detection').empty().append($('<div>').addClass('alert alert-danger').text('Failed to load threat detection status'));
    });
}

function updateNetworkMonitor() {
    $.get('/network', function(data) {
        const container = $('#network-monitor').empty();
        container.append($('<div>').text('Active Connections: ' + String(data.active_connections)));
        container.append($('<div>').text('Data Rate: ' + String(data.data_rate) + ' KB/s'));
        container.append($('<div>').text('Packet Rate: ' + String(data.packet_rate) + ' pps'));
    }).fail(function() {
        $('#network-monitor').empty().append($('<div>').addClass('alert alert-danger').text('Failed to load network status'));
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
