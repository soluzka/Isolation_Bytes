"""
Network Monitored Directories Endpoint

This file contains the endpoint function for retrieving network monitored directories.
To use this in your app.py, add the following code after your other network endpoints:

@app.route('/get_network_monitored_directories', methods=['GET'])
def get_network_monitored_directories_endpoint():
    return get_network_monitored_directories_handler(network_monitor)

"""

import os
import logging
from datetime import datetime
from flask import jsonify

def get_network_monitored_directories_handler(network_monitor):
    """
    Get network monitored directories
    
    Args:
        network_monitor: The network monitor instance
        
    Returns:
        JSON response with monitored directories information
    """
    try:
        # Get timestamp for last scan
        last_scan = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Define network monitored directories
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
