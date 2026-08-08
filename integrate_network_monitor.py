"""
Network Monitor Integration Runner

This script will integrate the network monitoring functionality into the main app.py
by adding the necessary route and functions if they don't already exist.
"""
import os
import re

def integrate_network_monitoring():
    app_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'app.py')
    
    # Read the current app.py content
    with open(app_path, 'r') as f:
        content = f.read()
    
    # Check if the endpoint is already registered
    if 'get_network_monitored_directories' not in content:
        # Integration locations
        import_pattern = re.compile(r'import\s+re\s*\n')
        network_endpoint_pattern = re.compile(r'# Network Monitoring Endpoints\s*\n')
        
        # Import the module
        if 'from network_monitor_integration import' not in content:
            new_import = 'from network_monitor_integration import register_network_monitor_endpoints\n'
            content = import_pattern.sub(f'import re\n{new_import}', content)
        
        # Add blueprint registration after Flask app initialization
        if 'register_network_monitor_endpoints(app)' not in content:
            app_init_pattern = re.compile(r'app = Flask\(__name__\)\s*\n')
            content = app_init_pattern.sub('app = Flask(__name__)\nregister_network_monitor_endpoints(app)\n', content)
        
        # Write the modified content back
        with open(app_path, 'w') as f:
            f.write(content)
        
        print("✅ Successfully integrated network monitoring endpoints into app.py")
    else:
        print("ℹ️ Network monitoring endpoints are already integrated")
    
    # Create CSS file for network monitor styles if it doesn't exist
    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
    css_path = os.path.join(static_dir, 'network_monitor.css')
    
    if not os.path.exists(static_dir):
        os.makedirs(static_dir)
    
    if not os.path.exists(css_path):
        from network_monitor_integration import network_directories_css
        
        with open(css_path, 'w', encoding='utf-8') as f:
            f.write(network_directories_css)
        
        print("Created network monitor CSS file")
    else:
        print("Network monitor CSS file already exists")
    
    # Create JavaScript file for network monitor functions if it doesn't exist
    js_path = os.path.join(static_dir, 'network_monitor.js')
    
    if not os.path.exists(js_path):
        from network_monitor_integration import network_directories_js
        
        with open(js_path, 'w', encoding='utf-8') as f:
            f.write(network_directories_js)
        
        print("Created network monitor JavaScript file")
    else:
        print("Network monitor JavaScript file already exists")
    
    print("\nNetwork monitoring integration complete!")
    print("Note: Please restart the Flask application for the changes to take effect.")

if __name__ == "__main__":
    integrate_network_monitoring()
