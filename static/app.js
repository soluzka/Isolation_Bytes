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
        let statusHtml = '';
        if (data.realtime_protection) {
            statusHtml += '<div class="status-indicator status-ok"></div> Real-time protection: Enabled<br>';
        } else {
            statusHtml += '<div class="status-indicator status-error"></div> Real-time protection: Disabled<br>';
        }

        statusHtml += '<div class="status-indicator status-ok"></div> Network Monitor: ' + (data.network_monitor ? 'Enabled' : 'Disabled') + '<br>';
        statusHtml += '<div class="status-indicator status-ok"></div> Safe Downloader: ' + (data.safe_downloader ? 'Enabled' : 'Disabled');

        // eslint-disable-next-line no-unsanitized/method
        $('#system-status').html(statusHtml);
    }).fail(function() {
        // eslint-disable-next-line no-unsanitized/method
        $('#system-status').html('<div class="status-indicator status-error"></div> Failed to load status');
    });
}

function updateThreatDetection() {
    $.get('/threats', function(data) {
        let threatHtml = '';
        if (data.threats.length > 0) {
            threatHtml += '<div class="alert alert-warning">Detected Threats:</div>';
            data.threats.forEach(threat => {
                threatHtml += '<div class="alert alert-info">' +
                    '<strong>' + escapeHtml(threat.type) + '</strong> detected in <strong>' + escapeHtml(threat.location) + '</strong>' +
                    '<button class="btn btn-sm btn-danger float-end quarantine-btn" data-id="' + escapeHtml(threat.id) + '" data-type="' + escapeHtml(threat.type) + '">Quarantine</button>' +
                    '</div>';
            });
        } else {
            threatHtml += '<div class="alert alert-success">No threats detected</div>';
        }

        // eslint-disable-next-line no-unsanitized/method
        $('#threat-detection').html(threatHtml);
    }).fail(function() {
        // eslint-disable-next-line no-unsanitized/method
        $('#threat-detection').html('<div class="alert alert-danger">Failed to load threat detection status</div>');
    });
}

function updateNetworkMonitor() {
    $.get('/network', function(data) {
        let networkHtml = '';
        networkHtml += '<div>Active Connections: ' + escapeHtml(data.active_connections) + '</div>';
        networkHtml += '<div>Data Rate: ' + escapeHtml(data.data_rate) + ' KB/s</div>';
        networkHtml += '<div>Packet Rate: ' + escapeHtml(data.packet_rate) + ' pps</div>';

        // eslint-disable-next-line no-unsanitized/method
        $('#network-monitor').html(networkHtml);
    }).fail(function() {
        // eslint-disable-next-line no-unsanitized/method
        $('#network-monitor').html('<div class="alert alert-danger">Failed to load network status</div>');
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
