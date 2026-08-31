"""
Network Monitor Integration Module
----------------------------------
This module provides functions and endpoints to integrate network monitoring functionality
with the main application. It includes functions to get monitored network directories
and display network monitoring information in the dashboard.

To use this module:
1. Import the functions in app.py
2. Register the endpoint in your Flask app
"""
import os
import logging
from datetime import datetime
from flask import jsonify, Blueprint

# Create a blueprint for network monitoring endpoints
network_bp = Blueprint('network', __name__)

def get_monitored_network_directories(network_monitor):
    """
    Get the list of directories being monitored for network activity
    
    Args:
        network_monitor: Instance of the network monitor class
        
    Returns:
        Dictionary with monitored directories information
    """
    try:
        # Get timestamp for last scan
        last_scan = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Define network monitored directories
        # These are common system directories that would be monitored for network activity
        monitored_dirs = [
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32\\drivers\\etc'),  # hosts file, DNS config
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32\\config'),  # registry files
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32\\wbem'),  # WMI
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'SysWOW64'),  # 32-bit system files
            os.path.join(os.environ.get('PROGRAMDATA', 'C:\\ProgramData'), 'Microsoft\\Windows\\Start Menu\\Programs\\Startup'),  # Startup programs
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'Prefetch'),  # Prefetch files
            os.path.join(os.environ.get('USERPROFILE', ''), 'AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'),  # User startup
            os.path.join(os.environ.get('USERPROFILE', ''), 'AppData\\Local\\Temp'),  # Temporary files
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'Temp')  # System temp
        ]
        
        # Define high-risk file extensions to monitor more carefully
        high_risk_extensions = [
            '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.wsf', '.hta', 
            '.scr', '.pif', '.reg', '.com', '.msi', '.jar', '.jnlp', '.vbe', 
            '.wsh', '.sys', '.inf'
        ]
        
        # Check if directories exist and are accessible
        directories = []
        total_files_monitored = 0
        
        for dir_path in monitored_dirs:
            exists = os.path.exists(dir_path)
            accessible = exists and os.access(dir_path, os.R_OK)
            
            # Count files if accessible (including subdirectories)
            file_count = 0
            high_risk_file_count = 0
            subdir_count = 0
            subdirectories = []
            
            if accessible:
                try:
                    # Recursively walk through directory and subdirectories
                    for root, dirs, files in os.walk(dir_path):
                        # Add found subdirectories to our list
                        for subdir in dirs:
                            subdir_full_path = os.path.join(root, subdir)
                            # Only add subdirectories that are relative to dir_path
                            if subdir_full_path.startswith(dir_path):
                                subdirectories.append(subdir_full_path)
                        
                        # Count subdirectories
                        subdir_count += len(dirs)
                        
                        # Count files and identify high-risk files
                        for file in files:
                            file_count += 1
                            _, ext = os.path.splitext(file)
                            if ext.lower() in high_risk_extensions:
                                high_risk_file_count += 1
                except Exception as e:
                    logging.warning(f"Error scanning subdirectories in {dir_path}: {str(e)}")
            
            total_files_monitored += file_count
            
            directories.append({
                'path': dir_path,
                'exists': exists,
                'accessible': accessible,
                'file_count': file_count,
                'high_risk_files': high_risk_file_count,
                'subdirectory_count': subdir_count,
                'subdirectories': subdirectories[:100] if len(subdirectories) > 100 else subdirectories  # Limit to 100 to avoid overly large responses
            })
        
        # Create the response data
        data = {
            'success': True,
            'monitoring_status': {
                'enabled': network_monitor and hasattr(network_monitor, 'is_running') and network_monitor.is_running(),
                'last_scan': last_scan,
                'total_directories': len(directories),
                'total_files_monitored': total_files_monitored,
                'directories': directories
            }
        }
        
        return data
    except Exception as e:
        logging.error(f"Error getting network monitored directories: {str(e)}")
        return {'success': False, 'error': str(e)}

# We'll use a function to set the network_monitor_instance later
_network_monitor_instance = None

def set_network_monitor_instance(network_monitor):
    """Set the network monitor instance to be used by the blueprint"""
    global _network_monitor_instance
    _network_monitor_instance = network_monitor

@network_bp.route('/monitored_directories', methods=['GET'])
def get_network_monitored_directories_endpoint():
    """Flask endpoint to get network monitored directories"""
    try:
        # Get timestamp for last scan
        from datetime import datetime
        last_scan = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Define network monitored directories - ensure this is comprehensive
        import os
        monitored_dirs = [
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32\\drivers\\etc'),  # hosts file, DNS config
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32\\config'),  # registry files
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32\\wbem'),  # WMI
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'SysWOW64'),  # 32-bit system files
            os.path.join(os.environ.get('PROGRAMDATA', 'C:\\ProgramData'), 'Microsoft\\Windows\\Start Menu\\Programs\\Startup'),  # Startup programs
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'Prefetch'),  # Prefetch files
            os.path.join(os.environ.get('USERPROFILE', ''), 'AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'),  # User startup
            os.path.join(os.environ.get('USERPROFILE', ''), 'AppData\\Local\\Temp'),  # Temporary files
            os.path.join(os.environ.get('USERPROFILE', ''), '.ssh'),  # SSH configuration
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'Temp'),  # System temp
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32\\spool\\drivers'),  # Print drivers
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32\\tasks'),  # Scheduled tasks
            os.path.join(os.environ.get('USERPROFILE', ''), 'Documents'),  # User documents
            os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads')  # User downloads
        ]
        
        # Check if directories exist and are accessible
        directories = []
        total_files_monitored = 0
        
        for dir_path in monitored_dirs:
            exists = os.path.exists(dir_path)
            accessible = exists and os.access(dir_path, os.R_OK)
            
            # Count files if accessible (including subdirectories)
            file_count = 0
            high_risk_file_count = 0
            subdir_count = 0
            
            if accessible:
                try:
                    # Walk through directory to count files more accurately
                    for root, dirs, files in os.walk(dir_path, topdown=True, followlinks=False):
                        file_count += len(files)
                        subdir_count += len(dirs)
                        # Limit depth to avoid excessive scanning
                        if root.count(os.sep) - dir_path.count(os.sep) >= 2:
                            dirs[:] = []  # Don't go deeper than 2 levels
                except Exception as e:
                    logging.warning(f"Error scanning directory {dir_path}: {str(e)}")
                    # If error, still try to count files in the top directory
                    try:
                        file_count = len([f for f in os.listdir(dir_path) if os.path.isfile(os.path.join(dir_path, f))])
                    except:
                        pass
            
            total_files_monitored += file_count
            
            directories.append({
                'path': dir_path,
                'exists': exists,
                'accessible': accessible,
                'file_count': file_count,
                'subdirectory_count': subdir_count
            })
        
        # Create the response with more comprehensive information
        response = {
            'success': True,
            'monitoring_status': {
                'enabled': _network_monitor_instance and hasattr(_network_monitor_instance, 'is_running') and _network_monitor_instance.is_running() if _network_monitor_instance else True,
                'last_scan': last_scan,
                'total_directories': len(directories),
                'total_files_monitored': total_files_monitored,
                'directories': directories
            }
        }
        
        return jsonify(response)
    except Exception as e:
        logging.error(f"Error getting network monitored directories: {str(e)}")
        # Return a valid JSON response even on error
        return jsonify({
            'success': False, 
            'error': str(e),
            'monitoring_status': {
                'enabled': False,
                'directories': [],
                'total_directories': 0,
                'total_files_monitored': 0
            }
        }), 500

def register_network_monitor_endpoints(app):
    """Register the network monitor blueprint with the Flask app"""
    app.register_blueprint(network_bp)
    
# Integration instructions
"""
To integrate this module with your main app.py, add the following code:

1. At the top of your app.py with other imports:
   from network_monitor_integration import register_network_monitor_endpoints

2. After your Flask app is initialized:
   register_network_monitor_endpoints(app)

This will register the /get_network_monitored_directories endpoint
with your Flask application.
"""

# CSS styles for network monitored directories display
network_directories_css = """
.network-monitored-directories {
    margin-top: 20px;
    padding: 10px;
    border-top: 1px solid #eee;
}

.monitoring-status {
    margin-bottom: 15px;
}

.monitoring-status .enabled {
    color: #27ae60;
    font-weight: bold;
}

.monitoring-status .disabled {
    color: #c0392b;
    font-weight: bold;
}

.directories-list {
    list-style-type: none;
    padding-left: 0;
    margin-top: 10px;
}

.directories-list li {
    padding: 8px;
    margin-bottom: 8px;
    border-left: 3px solid #eee;
    padding-left: 10px;
    background-color: #f9f9f9;
    border-radius: 4px;
}

.directory-active {
    color: #27ae60;
    font-weight: bold;
    margin-right: 5px;
}

.directory-inactive {
    color: #e74c3c;
    font-weight: bold;
    margin-right: 5px;
}

.directory-details {
    margin-top: 5px;
    padding-left: 15px;
    font-size: 0.9em;
    color: #555;
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
}

.file-count {
    color: #3498db;
}

.subdir-count {
    color: #9b59b6;
}

.high-risk-files {
    color: #e74c3c;
    font-weight: bold;
}

.subdirectories-container {
    margin-top: 8px;
    margin-bottom: 8px;
    width: 100%;
}

.toggle-subdirs {
    background-color: #f0f0f0;
    border: 1px solid #ddd;
    border-radius: 4px;
    padding: 5px 10px;
    font-size: 0.85em;
    cursor: pointer;
    margin-bottom: 5px;
    transition: background-color 0.2s;
}

.toggle-subdirs:hover {
    background-color: #e0e0e0;
}

.subdirectories-list {
    list-style-type: none;
    padding-left: 15px;
    margin-top: 5px;
    font-size: 0.85em;
    max-height: 200px;
    overflow-y: auto;
    background-color: #f9f9f9;
    border-left: 2px solid #ddd;
    padding-top: 5px;
    padding-bottom: 5px;
}

.subdirectories-list li {
    padding: 3px 5px;
    margin-bottom: 3px;
    border-bottom: 1px dotted #eee;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}
"""

# JavaScript for fetching and displaying network monitored directories
network_directories_js = """
// Function to fetch monitored network directories
function fetchMonitoredNetworkDirectories() {
    fetch('/get_network_monitored_directories')
        .then(response => response.json())
        .then(data => {
            updateMonitoredDirectoriesDisplay(data);
        })
        .catch(error => {
            console.error('Error fetching monitored network directories:', error);
        });
}

// Function to display monitored directories
function updateMonitoredDirectoriesDisplay(data) {
    const directoriesContainer = document.getElementById('monitored_directories');
    if (!directoriesContainer) {
        // Create the container if it doesn't exist
        const networkCard = document.querySelector('.card');
        if (networkCard) {
            const newSection = document.createElement('div');
            newSection.className = 'network-monitored-directories';
            newSection.innerHTML = `
                <h4>Monitored Directories</h4>
                <div id="monitored_directories"></div>
            `;
            networkCard.appendChild(newSection);
            directoriesContainer = document.getElementById('monitored_directories');
        } else {
            return;
        }
    }
    
    // Clear previous contents
    directoriesContainer.innerHTML = '';
    
    // Display monitoring status and total files monitored
    if (data && data.success) {
        const status = data.monitoring_status;
        const statusDiv = document.createElement('div');
        statusDiv.className = 'monitoring-status';
        statusDiv.innerHTML = `
            <div><strong>Status:</strong> <span class="${status.enabled ? 'enabled' : 'disabled'}">${status.enabled ? 'Enabled' : 'Disabled'}</span></div>
            <div><strong>Last Scan:</strong> ${status.last_scan}</div>
            <div><strong>Total Monitored Directories:</strong> ${status.total_directories}</div>
            <div><strong>Total Files Monitored:</strong> ${status.total_files_monitored || 0}</div>
        `;
        directoriesContainer.appendChild(statusDiv);
        
        // Display directory list
        if (status.directories && status.directories.length > 0) {
            const list = document.createElement('ul');
            list.className = 'directories-list';
            
            status.directories.forEach(dir => {
                const li = document.createElement('li');
                const statusClass = dir.exists && dir.accessible ? 'directory-active' : 'directory-inactive';
                const statusIcon = dir.exists && dir.accessible ? '✓' : '⚠️';
                
                li.innerHTML = `<span class="${statusClass}">${statusIcon}</span> ${dir.path}`;
                
                // Create detailed information div
                if (dir.exists && dir.accessible) {
                    const detailsDiv = document.createElement('div');
                    detailsDiv.className = 'directory-details';
                    detailsDiv.innerHTML = `
                        <span class="file-count">Files: ${dir.file_count || 0}</span>
                        <span class="subdir-count">Subdirectories: ${dir.subdirectory_count || 0}</span>
                        ${dir.high_risk_files > 0 ? `<span class="high-risk-files">High-risk files: ${dir.high_risk_files}</span>` : ''}
                    `;
                    li.appendChild(detailsDiv);
                }
                
                list.appendChild(li);
            });
            
            directoriesContainer.appendChild(list);
        } else {
            directoriesContainer.innerHTML += '<p>No directories currently being monitored.</p>';
        }
    } else {
        directoriesContainer.innerHTML = '<p>Error loading monitored directories.</p>';
    }
}
"""

if __name__ == "__main__":
    print("This module is meant to be imported, not run directly.")
    print("See the integration instructions in the comments.")
