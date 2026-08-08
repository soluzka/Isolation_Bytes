// Initialize status indicators
$(document).ready(function() {
    updateSystemStatus();
    updateThreatDetection();
    updateNetworkMonitor();

    // Update status periodically
    setInterval(updateSystemStatus, 30000); // Every 30 seconds
    setInterval(updateThreatDetection, 60000); // Every minute
    setInterval(updateNetworkMonitor, 10000); // Every 10 seconds
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
        
        $('#system-status').html(statusHtml);
    }).fail(function() {
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
                    '<strong>' + threat.type + '</strong> detected in <strong>' + threat.location + '</strong>' +
                    '<button class="btn btn-sm btn-danger float-end" onclick="handleThreat(\'' + threat.id + '\', \'' + threat.type + '\')">Quarantine</button>' +
                    '</div>';
            });
        } else {
            threatHtml += '<div class="alert alert-success">No threats detected</div>';
        }
        
        $('#threat-detection').html(threatHtml);
    }).fail(function() {
        $('#threat-detection').html('<div class="alert alert-danger">Failed to load threat detection status</div>');
    });
}

function updateNetworkMonitor() {
    $.get('/network', function(data) {
        let networkHtml = '';
        networkHtml += '<div>Active Connections: ' + data.active_connections + '</div>';
        networkHtml += '<div>Data Rate: ' + data.data_rate + ' KB/s</div>';
        networkHtml += '<div>Packet Rate: ' + data.packet_rate + ' pps</div>';
        
        $('#network-monitor').html(networkHtml);
    }).fail(function() {
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
