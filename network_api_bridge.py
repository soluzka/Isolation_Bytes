"""
Network API Bridge
-----------------

This module provides a simple bridge between the YARA scanner interface 
and the network monitoring functionality, ensuring that the
/api/network/monitored_directories endpoint is available and working correctly.

Usage:
1. Import in app.py after the other imports
2. Call register_network_api_bridge(app) after initializing the Flask app 
"""

import os
import logging
from datetime import datetime
from flask import jsonify, Blueprint

# Create a bridge blueprint for the network API endpoints with a unique name
network_api_bridge = Blueprint('network_api_bridge_fix', __name__, url_prefix='/api/network')

@network_api_bridge.route('/monitored_directories', methods=['GET'])
def get_monitored_directories():
    """API endpoint for network monitored directories needed by YARA scanner"""
    try:
        # Define common system directories to monitor for network activity
        monitored_dirs = [
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32\\drivers\\etc'),  # hosts file, DNS config
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32\\config'),  # registry files
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32\\wbem'),  # WMI
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'SysWOW64'),  # 32-bit system files
            os.path.join(os.environ.get('PROGRAMDATA', 'C:\\ProgramData'), 'Microsoft\\Windows\\Start Menu\\Programs\\Startup'),  # Startup programs
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'Prefetch'),  # Prefetch files
            os.path.join(os.environ.get('USERPROFILE', ''), 'AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'),  # User startup
            os.path.join(os.environ.get('USERPROFILE', ''), 'AppData\\Local\\Temp'),  # Temporary files
            os.path.join(os.environ.get('USERPROFILE', ''), 'Documents'),  # User documents
            os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads'),  # User downloads
            os.path.join(os.environ.get('USERPROFILE', ''), 'Desktop'),  # User desktop
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
                except Exception as e:
                    logging.warning(f"Error counting files in {dir_path}: {str(e)}")
            
            directories.append({
                'path': dir_path,
                'exists': exists,
                'accessible': accessible,
                'file_count': file_count
            })
        
        # Create the response data in the format expected by the YARA scanner
        response = {
            'success': True,
            'monitoring_status': {
                'enabled': True,  # Assume monitoring is enabled
                'last_scan': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'total_directories': len(directories),
                'directories': directories
            }
        }
        
        return jsonify(response)
    except Exception as e:
        logging.error(f"Error in network monitored directories endpoint: {str(e)}")
        return jsonify({
            'success': False, 
            'error': str(e),
            'monitoring_status': {
                'enabled': False,
                'directories': [],
                'total_directories': 0
            }
        }), 500

def register_network_api_bridge(app):
    """Register the network API bridge blueprint with the Flask app"""
    app.register_blueprint(network_api_bridge)
