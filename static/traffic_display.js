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

function clearChildren(node) {
    while (node.lastChild) {
        node.removeChild(node.lastChild);
    }
}

// Update traffic statistics display
function updateTrafficDisplay(trafficData, c2Data) {
    trafficData = unwrapPayload(trafficData, 'stats');
    c2Data = unwrapPayload(c2Data, 'patterns');

    const trafficContainer = document.getElementById('traffic_stats');
    if (!trafficContainer) return;

    // Clear the "will appear here" message
    if (trafficContainer.innerText.includes('appear here when')) {
        clearChildren(trafficContainer);
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

    const trafficContent = document.getElementById('traffic_content');

    // Return if no traffic data available
    if (!trafficData || trafficData.error) {
        clearChildren(trafficContent);
        const alert = document.createElement('div');
        alert.className = 'alert alert-info';
        alert.textContent = trafficData && trafficData.error ? 'Error: ' + trafficData.error : 'No traffic data available yet. Monitoring is initializing...';
        trafficContent.appendChild(alert);
        return;
    }

    const timestamp = trafficData.timestamp ? new Date(trafficData.timestamp * 1000).toLocaleString() : 'N/A';

    clearChildren(trafficContent);
    const fragment = document.createDocumentFragment();

    // Connection Summary
    const summary = document.createElement('div');
    summary.style.cssText = 'margin-bottom: 15px; padding-bottom: 10px; border-bottom: 1px solid #eee;';
    const summaryTitle = document.createElement('h4');
    summaryTitle.textContent = 'Connection Summary';
    summary.appendChild(summaryTitle);

    const summaryFlex = document.createElement('div');
    summaryFlex.style.cssText = 'display: flex; flex-wrap: wrap; gap: 15px;';
    [
        ['Total Connections:', trafficData.total_connections || 0],
        ['Inbound Traffic:', formatBytes(trafficData.inbound || 0)],
        ['Outbound Traffic:', formatBytes(trafficData.outbound || 0)],
        ['Last Updated:', timestamp]
    ].forEach(([label, value]) => {
        const col = document.createElement('div');
        col.style.cssText = 'flex: 1; min-width: 150px;';
        const strong = document.createElement('strong');
        strong.textContent = label + ' ';
        col.appendChild(strong);
        col.appendChild(document.createTextNode(value));
        summaryFlex.appendChild(col);
    });
    summary.appendChild(summaryFlex);
    fragment.appendChild(summary);

    // Active IP addresses
    if (trafficData.active_ips && trafficData.active_ips.length > 0) {
        const ipSection = document.createElement('div');
        ipSection.style.cssText = 'margin-bottom: 15px;';
        const ipTitle = document.createElement('h4');
        ipTitle.textContent = 'Active IP Connections (' + trafficData.active_ips.length + ')';
        ipSection.appendChild(ipTitle);
        const ipList = document.createElement('div');
        ipList.style.cssText = 'max-height: 150px; overflow-y: auto; padding: 5px; background: #f8f8f8; border-radius: 4px;';
        trafficData.active_ips.forEach(ip => {
            const row = document.createElement('div');
            row.style.cssText = 'margin: 3px 0; padding: 2px 5px;';
            row.textContent = ip;
            ipList.appendChild(row);
        });
        ipSection.appendChild(ipList);
        fragment.appendChild(ipSection);
    }

    // Protocol breakdown
    if (trafficData.protocols && Object.keys(trafficData.protocols).length > 0) {
        const protoSection = document.createElement('div');
        protoSection.style.cssText = 'margin-bottom: 15px;';
        const protoTitle = document.createElement('h4');
        protoTitle.textContent = 'Protocol Breakdown';
        protoSection.appendChild(protoTitle);
        const protoFlex = document.createElement('div');
        protoFlex.style.cssText = 'display: flex; flex-wrap: wrap; gap: 10px;';
        for (const [protocol, count] of Object.entries(trafficData.protocols)) {
            const col = document.createElement('div');
            col.style.cssText = 'flex: 1; min-width: 100px; padding: 8px; background: #f0f0f0; border-radius: 4px; text-align: center;';
            const strong = document.createElement('strong');
            strong.textContent = protocol + ': ';
            col.appendChild(strong);
            col.appendChild(document.createTextNode(count));
            protoFlex.appendChild(col);
        }
        protoSection.appendChild(protoFlex);
        fragment.appendChild(protoSection);
    }

    // Process information
    if (trafficData.processes && Object.keys(trafficData.processes).length > 0) {
        const procSection = document.createElement('div');
        procSection.style.cssText = 'margin-bottom: 15px;';
        const procTitle = document.createElement('h4');
        procTitle.textContent = 'Process Network Activity';
        procSection.appendChild(procTitle);

        const wrap = document.createElement('div');
        wrap.style.cssText = 'max-height: 200px; overflow-y: auto;';
        const table = document.createElement('table');
        table.style.cssText = 'width: 100%; border-collapse: collapse;';

        const thead = document.createElement('thead');
        const thr = document.createElement('tr');
        thr.style.cssText = 'background: #f0f0f0;';
        const th1 = document.createElement('th');
        th1.style.cssText = 'text-align: left; padding: 8px;';
        th1.textContent = 'Process';
        const th2 = document.createElement('th');
        th2.style.cssText = 'text-align: center; padding: 8px;';
        th2.textContent = 'Connections';
        thr.appendChild(th1);
        thr.appendChild(th2);
        thead.appendChild(thr);
        table.appendChild(thead);

        const tbody = document.createElement('tbody');
        for (const [process, data] of Object.entries(trafficData.processes)) {
            const tr = document.createElement('tr');
            tr.style.cssText = 'border-bottom: 1px solid #eee;';
            const td1 = document.createElement('td');
            td1.style.cssText = 'padding: 8px;';
            td1.textContent = process;
            const td2 = document.createElement('td');
            td2.style.cssText = 'text-align: center; padding: 8px;';
            td2.textContent = data.connections || 0;
            tr.appendChild(td1);
            tr.appendChild(td2);
            tbody.appendChild(tr);
        }
        table.appendChild(tbody);
        wrap.appendChild(table);
        procSection.appendChild(wrap);
        fragment.appendChild(procSection);
    }

    // C2 detection information
    if (c2Data && !c2Data.error && c2Data.suspicious_connections && c2Data.suspicious_connections.length > 0) {
        const c2Section = document.createElement('div');
        c2Section.style.cssText = 'margin-top: 20px; border-top: 1px solid #eee; padding-top: 15px;';
        const c2Title = document.createElement('h4');
        c2Title.style.color = '#e74c3c';
        c2Title.textContent = 'Suspicious Connection Alerts';
        c2Section.appendChild(c2Title);

        const c2Wrap = document.createElement('div');
        c2Wrap.style.cssText = 'max-height: 200px; overflow-y: auto;';

        function makeC2Line(label, value, color) {
            const div = document.createElement('div');
            const strong = document.createElement('strong');
            strong.textContent = label + ': ';
            div.appendChild(strong);
            const span = document.createElement('span');
            span.textContent = value;
            if (color) span.style.color = color;
            div.appendChild(span);
            return div;
        }

        c2Data.suspicious_connections.forEach(conn => {
            const row = document.createElement('div');
            row.style.cssText = 'margin: 8px 0; padding: 8px; background: #fff3f3; border-left: 3px solid #e74c3c; border-radius: 4px;';
            row.appendChild(makeC2Line('Process', conn.process + ' (PID: ' + (conn.pid || 0) + ')', null));
            row.appendChild(makeC2Line('Remote', conn.remote_ip + ':' + conn.remote_port, null));
            row.appendChild(makeC2Line('Reason', conn.reason, '#e74c3c'));
            if (conn.process_scan) {
                const ps = conn.process_scan;
                const findings = ps.malware_found ? ps.findings.join('; ') : 'clean';
                const color = ps.malware_found ? '#e74c3c' : null;
                row.appendChild(makeC2Line('Process scan', findings, color));
            }
            c2Wrap.appendChild(row);
        });

        c2Section.appendChild(c2Wrap);
        fragment.appendChild(c2Section);
    }

    trafficContent.appendChild(fragment);
}

// Function to fetch traffic statistics from the API
function updateTrafficStats() {
    Promise.all([
        fetch('/get_traffic_stats', {credentials: 'include'}),
        fetch('/get_c2_patterns', {credentials: 'include'})
    ])
    .then(responses => Promise.all(responses.map(r => r.json())))
    .then(([trafficData, c2Data]) => {
        updateTrafficDisplay(trafficData, c2Data);
    })
    .catch(error => {
        console.error('Error fetching traffic stats:', error);
        const trafficContent = document.getElementById('traffic_content') || document.getElementById('traffic_stats');
        if (trafficContent) {
            clearChildren(trafficContent);
            const alert = document.createElement('div');
            alert.className = 'alert alert-warning';
            alert.textContent = 'Error retrieving traffic statistics: ' + (error.message || 'Unknown error');
            trafficContent.appendChild(alert);
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
        credentials: 'include'
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
            clearChildren(container);
            const alert = document.createElement('div');
            alert.className = 'alert alert-warning';
            alert.textContent = 'Failed to start network monitoring: ' + (error.message || 'Unknown error');
            container.appendChild(alert);
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
        clearChildren(container);
        const loading = document.createElement('div');
        loading.className = 'loading';
        loading.textContent = 'Loading monitored directories...';
        container.appendChild(loading);

        fetch('/api/network/monitored_directories', {credentials: 'include'})
            .then(response => {
                if (!response.ok) {
                    throw new Error('Failed to fetch monitored directories: ' + response.status);
                }
                return response.json();
            })
            .then(data => {
                if (data.directories && Array.isArray(data.directories)) {
                    updateMonitoredDirectoriesDisplay(data);
                } else {
                    clearChildren(container);
                    const alert = document.createElement('div');
                    alert.className = 'alert alert-info';
                    alert.textContent = 'No monitored directories available.';
                    container.appendChild(alert);
                }
            })
            .catch(error => {
                console.error('Error fetching monitored directories:', error);
                clearChildren(container);
                const alert = document.createElement('div');
                alert.className = 'alert alert-warning';
                alert.textContent = 'Error loading monitored directories: ' + (error.message || 'Unknown error');
                container.appendChild(alert);
            });
    });
}

/**
 * Function to update the displayed list of monitored directories
 */
function updateMonitoredDirectoriesDisplay(data) {
    safeDomOperation('monitored_directories', function(container) {
        // Clear previous content
        clearChildren(container);

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
