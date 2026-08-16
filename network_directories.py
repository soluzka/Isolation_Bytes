import os
import logging
from datetime import datetime
from flask import jsonify

def get_network_monitored_directories(network_monitor):
    """
    Get the list of directories being monitored for network activity.
    This function can be imported and used in the main app.py file.
    
    Args:
        network_monitor: Instance of the network monitor class
        
    Returns:
        JSON response with monitored directories information
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
        
        # Check if directories exist and are accessible
        directories = []
        for dir_path in monitored_dirs:
            exists = os.path.exists(dir_path)
            accessible = exists and os.access(dir_path, os.R_OK)
            
            # Count files if accessible
            file_count = 0
            if accessible:
                try:
                    # Count files in directory
                    file_count = len([f for f in os.listdir(dir_path) if os.path.isfile(os.path.join(dir_path, f))])
                except Exception:
                    pass
            
            directories.append({
                'path': dir_path,
                'exists': exists,
                'accessible': accessible,
                'file_count': file_count
            })
        
        # Create the response
        response = {
            'success': True,
            'monitoring_status': {
                'enabled': network_monitor and hasattr(network_monitor, 'is_running') and network_monitor.is_running(),
                'last_scan': last_scan,
                'total_directories': len(directories),
                'directories': directories
            }
        }
        
        return jsonify(response)
    except Exception as e:
        logging.error(f"Error getting network monitored directories: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Add CSS styles that should be included in the template
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
    padding: 5px;
    margin-bottom: 3px;
    border-left: 3px solid #eee;
    padding-left: 10px;
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

.file-count {
    color: #7f8c8d;
    font-size: 0.9em;
}
"""
