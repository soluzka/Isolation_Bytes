/* eslint-disable no-unsanitized/method, no-unsanitized/property, no-unsanitized/function-call */
/**
 * Network traffic monitoring display functions
 */

// Unwrap payloads that nest the data under a success/stats or success/patterns envelope
function unwrapPayload(payload, key) {
    if (payload && typeof payload === 'object' && typeof key === 'string') {
        const match = Object.entries(payload).find(([k, v]) => k === key && v && typeof v === 'object');
        if (match) return match[1];
    }
    return payload;
}

// Escape a string so it can be safely embedded in HTML
function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    return String(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// Tagged template that escapes all interpolated values
function safe(strings, ...values) {

    return strings.reduce((acc, str, i) => acc + str + (i < values.length ? escapeHtml(values[i]) : ''), '');
}

// Update traffic statistics display
function updateTrafficDisplay(trafficData, c2Data) {
    trafficData = unwrapPayload(trafficData, 'stats');
    c2Data = unwrapPayload(c2Data, 'patterns');

    const trafficContainer = document.getElementById('traffic_stats');
    if (!trafficContainer) return;
    
    // Clear the "will appear here" message
    if (trafficContainer.innerText.includes('appear here when')) {
        trafficContainer.innerHTML = '';
    }

    // Format bytes to KB/MB/GB
    const formatBytes = (bytes) => {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1048576) return (bytes / 1024).toFixed(2) + ' KB';
        if (bytes < 1073741824) return (bytes / 1048576).toFixed(2) + ' MB';
        return (bytes / 1073741824).toFixed(2) + ' GB';
    };

    // Create container for statistics if it doesn't exist
    if (!document.getElementById('traffic_content')) {
        const contentDiv = document.createElement('div');
        contentDiv.id = 'traffic_content';
        trafficContainer.appendChild(contentDiv);
    }

    // Build HTML content
    const trafficContent = document.getElementById('traffic_content');
    
    // Return if no traffic data available
    if (!trafficData || trafficData.error) {
        trafficContent.innerHTML = '';
    

        // eslint-disable-next-line no-unsanitized/method
    trafficContent.appendChild(document.createRange().createContextualFragment(safe`
            <div class="alert alert-info">
                ${trafficData && trafficData.error ? 'Error: ' + trafficData.error : 'No traffic data available yet. Monitoring is initializing...'}
            </div>`)); // nosem
        return;
    }

    // Format timestamp
    const timestamp = trafficData.timestamp ? new Date(trafficData.timestamp * 1000).toLocaleString() : 'N/A';
    
    // Build statistics HTML
    let html = safe`
        <div style="margin-bottom: 15px; padding-bottom: 10px; border-bottom: 1px solid #eee;">
            <h4>Connection Summary</h4>
            <div style="display: flex; flex-wrap: wrap; gap: 15px;">
                <div style="flex: 1; min-width: 150px;">
                    <strong>Total Connections:</strong> ${trafficData.total_connections || 0}
                </div>
                <div style="flex: 1; min-width: 150px;">
                    <strong>Inbound Traffic:</strong> ${formatBytes(trafficData.inbound || 0)}
                </div>
                <div style="flex: 1; min-width: 150px;">
                    <strong>Outbound Traffic:</strong> ${formatBytes(trafficData.outbound || 0)}
                </div>
                <div style="flex: 1; min-width: 150px;">
                    <strong>Last Updated:</strong> ${timestamp}
                </div>
            </div>
        </div>`;

    // Active IP addresses
    if (trafficData.active_ips && trafficData.active_ips.length > 0) {
        html += safe`
            <div style="margin-bottom: 15px;">
                <h4>Active IP Connections (${trafficData.active_ips.length})</h4>
                <div style="max-height: 150px; overflow-y: auto; padding: 5px; background: #f8f8f8; border-radius: 4px;">`;
        
        trafficData.active_ips.forEach(ip => {
            html += safe`<div style="margin: 3px 0; padding: 2px 5px;">${ip}</div>`;
        });
        
        html += safe`</div></div>`;
    }

    // Protocol breakdown
    if (trafficData.protocols && Object.keys(trafficData.protocols).length > 0) {
        html += safe`
            <div style="margin-bottom: 15px;">
                <h4>Protocol Breakdown</h4>
                <div style="display: flex; flex-wrap: wrap; gap: 10px;">`;
        
        for (const [protocol, count] of Object.entries(trafficData.protocols)) {
            html += safe`
                <div style="flex: 1; min-width: 100px; padding: 8px; background: #f0f0f0; border-radius: 4px; text-align: center;">
                    <strong>${protocol}:</strong> ${count}
                </div>`;
        }
        
        html += safe`</div></div>`;
    }

    // Process information
    if (trafficData.processes && Object.keys(trafficData.processes).length > 0) {
        html += safe`
            <div style="margin-bottom: 15px;">
                <h4>Process Network Activity</h4>
                <div style="max-height: 200px; overflow-y: auto;">
                    <table style="width: 100%; border-collapse: collapse;">
                        <thead>
                            <tr style="background: #f0f0f0;">
                                <th style="text-align: left; padding: 8px;">Process</th>
                                <th style="text-align: center; padding: 8px;">Connections</th>
                            </tr>
                        </thead>
                        <tbody>`;
        
        for (const [process, data] of Object.entries(trafficData.processes)) {
            html += safe`
                <tr style="border-bottom: 1px solid #eee;">
                    <td style="padding: 8px;">${process}</td>
                    <td style="text-align: center; padding: 8px;">${data.connections || 0}</td>
                </tr>`;
        }
        
        html += safe`</tbody></table></div></div>`;
    }

    // Display C2 detection information if available
    if (c2Data && !c2Data.error) {
        if (c2Data.suspicious_connections && c2Data.suspicious_connections.length > 0) {
            html += safe`
                <div style="margin-top: 20px; border-top: 1px solid #eee; padding-top: 15px;">
                    <h4 style="color: #e74c3c;">Suspicious Connection Alerts</h4>
                    <div style="max-height: 200px; overflow-y: auto;">`;
            
            c2Data.suspicious_connections.forEach(conn => {
                html += safe`
                    <div style="margin: 8px 0; padding: 8px; background: #fff3f3; border-left: 3px solid #e74c3c; border-radius: 4px;">
                        <div><strong>Process:</strong> ${conn.process} (PID: ${conn.pid})</div>
                        <div><strong>Remote:</strong> ${conn.remote_ip}:${conn.remote_port}</div>
                        <div><strong>Reason:</strong> <span style="color: #e74c3c;">${conn.reason}</span></div>
                    </div>`;
            });
            
            html += safe`</div></div>`;
        }
    }

    // Update the content
    trafficContent.innerHTML = '';
    // eslint-disable-next-line no-unsanitized/method
    trafficContent.appendChild(document.createRange().createContextualFragment(html)); // nosem
}

// Function to fetch traffic statistics from the API
function updateTrafficStats() {
    Promise.all([
        fetch('/get_traffic_stats'),
        fetch('/get_c2_patterns')
    ])
    .then(responses => Promise.all(responses.map(r => r.json())))
    .then(([trafficData, c2Data]) => {
        updateTrafficDisplay(trafficData, c2Data);
    })
    .catch(error => {
        console.error('Error fetching traffic stats:', error);
        const trafficContent = document.getElementById('traffic_content') || document.getElementById('traffic_stats');
        if (trafficContent) {
            trafficContent.innerHTML = '';
        

            // eslint-disable-next-line no-unsanitized/method
    trafficContent.appendChild(document.createRange().createContextualFragment(safe`
                <div class="alert alert-warning">
                    Error retrieving traffic statistics: ${error.message || 'Unknown error'}
                </div>`)); // nosem
        }
    });
}

// Function to safely interact with DOM elements
function safeDomOperation(elementId, operation) {
    try {
        const element = document.getElementById(elementId);
        if (element) {
            operation(element);
            return true;
        } else {
            console.warn(`Element with ID '${elementId}' not found.`);
            return false;
        }
    } catch (err) {
        console.error(`Error with element '${elementId}':`, err);
        return false;
    }
}

// Function to start traffic monitoring with enhanced error handling
function startTrafficMonitoring() {
    // Safely check if traffic_stats element exists
    if (!safeDomOperation('traffic_stats', function() {})) {
        console.error('Traffic stats container not found, cannot start monitoring');
        return;
    }
    
    // Initialize window.serviceStates if it doesn't exist
    if (!window.serviceStates) {
        window.serviceStates = {
            networkMonitorRunning: false
        };
    }
    
    fetch('/start_traffic_monitoring', {
        method: 'POST',
        credentials: 'include' // Ensure cookies are sent with the request
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`Network response was not ok: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        console.log('Traffic monitoring started:', data);
        window.serviceStates.networkMonitorRunning = true;
        
        // Start updating traffic stats only if monitoring started successfully
        if (typeof updateTrafficStats === 'function') {
            updateTrafficStats();
        }
        
        // Safely update the network monitor status if the function exists
        if (typeof window.updateNetworkMonitorStatus === 'function') {
            window.updateNetworkMonitorStatus(true);
        }
        
        // Show monitored network directories if the function exists
        if (typeof fetchMonitoredNetworkDirectories === 'function') {
            fetchMonitoredNetworkDirectories();
        }
    })
    .catch(error => {
        console.error('Error starting traffic monitoring:', error);
        // Display error in traffic stats container
        safeDomOperation('traffic_stats', function(container) {
            container.innerHTML = '';
        

            // eslint-disable-next-line no-unsanitized/method
            container.appendChild(document.createRange().createContextualFragment(safe`
                <div class="alert alert-warning">
                    Failed to start network monitoring: ${error.message || 'Unknown error'}
                </div>`)); // nosem
        });
    });
    
    // Set up interval to update stats every 3 seconds
    window.trafficStatsInterval = setInterval(updateTrafficStats, 3000);
}

/**
 * Function to fetch and display monitored network directories
 * This connects to the network_monitor_integration.py endpoint
 */
function fetchMonitoredNetworkDirectories() {
    safeDomOperation('monitored_directories', function(container) {
        container.innerHTML = '<div class="loading">Loading monitored directories...</div>';
        
        fetch('/api/network/monitored_directories')
            .then(response => {
                if (!response.ok) {
                    throw new Error(`Failed to fetch monitored directories: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                if (data.directories && Array.isArray(data.directories)) {
                    updateMonitoredDirectoriesDisplay(data);
                } else {
                    container.innerHTML = '<div class="alert alert-info">No monitored directories available.</div>';
                }
            })
            .catch(error => {
                console.error('Error fetching monitored directories:', error);
                container.innerHTML = '';
            

                // eslint-disable-next-line no-unsanitized/method
            container.appendChild(document.createRange().createContextualFragment(safe`<div class="alert alert-warning">Error loading monitored directories: ${error.message}</div>`)); // nosem
            });
    });
}

/**
 * Function to update the displayed list of monitored directories
 */
function updateMonitoredDirectoriesDisplay(data) {
    safeDomOperation('monitored_directories', function(container) {
        // Clear previous content
        container.innerHTML = '';
        
        // Create header
        const header = document.createElement('h4');
        header.textContent = 'Monitored Network Directories';
        container.appendChild(header);
        
        // Create timestamp info
        if (data.last_scan) {
            const timestamp = document.createElement('p');
            timestamp.className = 'timestamp';
            timestamp.textContent = `Last scan: ${data.last_scan}`;
            container.appendChild(timestamp);
        }
        
        // Create list of directories
        if (data.directories && data.directories.length > 0) {
            const list = document.createElement('ul');
            list.className = 'directory-list';
            
            data.directories.forEach(dir => {
                const item = document.createElement('li');
                const dirName = document.createElement('strong');
                dirName.textContent = dir.path || 'Unknown';
                
                item.appendChild(dirName);
                
                if (dir.status) {
                    const status = document.createElement('span');
                    status.className = `status ${dir.status.toLowerCase()}`;
                    status.textContent = ` - ${dir.status}`;
                    item.appendChild(status);
                }
                
                if (dir.description) {
                    const desc = document.createElement('p');
                    desc.className = 'description';
                    desc.textContent = dir.description;
                    item.appendChild(desc);
                }
                
                list.appendChild(item);
            });
            
            container.appendChild(list);
        } else {
            const noData = document.createElement('p');
            noData.className = 'alert alert-info';
            noData.textContent = 'No monitored directories found.';
            container.appendChild(noData);
        }
    });
}

// Start traffic monitoring and fetch monitored directories when page loads
document.addEventListener('DOMContentLoaded', function() {
    // Initialize service states object
    window.serviceStates = window.serviceStates || {
        networkMonitorRunning: false
    };
    
    // Start traffic monitoring
    startTrafficMonitoring();
    
    // Fetch monitored directories if the container exists
    safeDomOperation('monitored_directories', function() {
        fetchMonitoredNetworkDirectories();
    });
});
