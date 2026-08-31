"""
Network Traffic Monitor Module
-----------------------------
This module provides functions and endpoints to implement and manage network traffic
monitoring functionality with the main application.

It's responsible for collecting, processing, and exposing network traffic statistics.
"""

import time
import logging
import threading
import psutil
import json
from collections import defaultdict
import socket
from flask import jsonify, Blueprint

# Create a blueprint for network traffic monitoring endpoints
traffic_bp = Blueprint('traffic', __name__)

# Global traffic stats storage
traffic_statistics = {}
traffic_monitoring_active = False
traffic_monitor_thread = None
c2_patterns_data = {}

def start_traffic_monitoring():
    """Start the traffic monitoring thread"""
    global traffic_monitoring_active, traffic_monitor_thread
    
    if not traffic_monitoring_active:
        traffic_monitoring_active = True
        traffic_monitor_thread = threading.Thread(target=monitor_traffic, daemon=True)
        traffic_monitor_thread.start()
        logging.info("Network traffic monitoring started")
        return True
    return False

def stop_traffic_monitoring():
    """Stop the traffic monitoring thread"""
    global traffic_monitoring_active
    
    if traffic_monitoring_active:
        traffic_monitoring_active = False
        logging.info("Network traffic monitoring stopped")
        return True
    return False

def is_traffic_monitoring_active():
    """Check if traffic monitoring is active"""
    global traffic_monitoring_active
    return traffic_monitoring_active

def monitor_traffic():
    """Monitor network traffic and collect statistics"""
    global traffic_statistics, c2_patterns_data
    
    while traffic_monitoring_active:
        try:
            # Collect traffic statistics
            traffic_stats = {
                'inbound': 0,
                'outbound': 0,
                'total_connections': 0,
                'active_ips': set(),
                'protocols': defaultdict(int),
                'ports': defaultdict(int),
                'processes': defaultdict(lambda: {'connections': 0, 'tx_bytes': 0, 'rx_bytes': 0}),
                'timestamp': time.time()
            }
            
            # Get network I/O counters for all interfaces
            net_counters = psutil.net_io_counters(pernic=True)
            for interface, counters in net_counters.items():
                if interface != 'lo':  # Skip loopback
                    traffic_stats['inbound'] += counters.bytes_recv
                    traffic_stats['outbound'] += counters.bytes_sent
            
            # Get connection information
            connections = []
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    # Get connections for this process
                    proc_connections = proc.connections()
                    if proc_connections:
                        for conn in proc_connections:
                            # Only count established connections
                            if conn.status == 'ESTABLISHED':
                                connections.append({
                                    'pid': proc.pid,
                                    'name': proc.info['name'],
                                    'laddr': conn.laddr if hasattr(conn, 'laddr') else None,
                                    'raddr': conn.raddr if hasattr(conn, 'raddr') else None,
                                    'status': conn.status,
                                    'type': conn.type
                                })
                                
                                # Update process stats
                                traffic_stats['processes'][proc.info['name']]['connections'] += 1
                                
                                # Count protocols and remote IPs
                                if conn.type == socket.SOCK_STREAM:
                                    traffic_stats['protocols']['TCP'] += 1
                                elif conn.type == socket.SOCK_DGRAM:
                                    traffic_stats['protocols']['UDP'] += 1
                                
                                # Count remote ports
                                if hasattr(conn, 'raddr') and conn.raddr:
                                    traffic_stats['active_ips'].add(conn.raddr.ip)
                                    traffic_stats['ports'][conn.raddr.port] += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                    continue
            
            traffic_stats['total_connections'] = len(connections)
            traffic_stats['active_ips'] = list(traffic_stats['active_ips'])  # Convert set to list for JSON serialization
            
            # Update global traffic statistics
            traffic_statistics = traffic_stats
            
            # Also update C2 patterns data
            c2_patterns_data = collect_c2_patterns(connections)
            
        except Exception as e:
            logging.error(f"Error monitoring traffic: {str(e)}")
        
        time.sleep(1)  # Update every second

def collect_c2_patterns(connections):
    """Collect potential command and control patterns from connections"""
    try:
        # This is a simplified implementation
        c2_data = {
            'potential_c2': [],
            'beaconing': [],
            'suspicious_connections': [],
            'timestamp': time.time()
        }
        
        # Process connections for suspicious patterns
        for conn in connections:
            if 'raddr' in conn and conn['raddr']:
                # Check for common suspicious ports
                suspicious_ports = [4444, 8080, 8443, 9001, 9002, 31337]
                if conn['raddr'].port in suspicious_ports:
                    c2_data['suspicious_connections'].append({
                        'process': conn.get('name', 'unknown'),
                        'pid': conn.get('pid', 0),
                        'remote_ip': conn['raddr'].ip,
                        'remote_port': conn['raddr'].port,
                        'reason': f"Connection to suspicious port {conn['raddr'].port}"
                    })
        
        return c2_data
    except Exception as e:
        logging.error(f"Error collecting C2 patterns: {str(e)}")
        return {
            'error': str(e),
            'potential_c2': [],
            'beaconing': [],
            'suspicious_connections': [],
            'timestamp': time.time()
        }

def get_traffic_stats():
    """Get the current traffic statistics"""
    global traffic_statistics
    
    if not traffic_statistics:
        # Return default empty structure if no data collected yet
        return {
            'inbound': 0,
            'outbound': 0,
            'total_connections': 0,
            'active_ips': [],
            'protocols': {},
            'ports': {},
            'processes': {},
            'timestamp': time.time()
        }
    
    return traffic_statistics

def get_c2_patterns():
    """Get potential command and control patterns in network traffic"""
    global c2_patterns_data
    
    if not c2_patterns_data:
        # Return default empty structure if no data collected yet
        return {
            'potential_c2': [],
            'beaconing': [],
            'suspicious_connections': [],
            'timestamp': time.time()
        }
    
    return c2_patterns_data

@traffic_bp.route('/get_traffic_stats', methods=['GET'])
def get_traffic_stats_endpoint():
    """Flask endpoint to get traffic statistics"""
    return jsonify(get_traffic_stats())

@traffic_bp.route('/get_c2_patterns', methods=['GET'])
def get_c2_patterns_endpoint():
    """Flask endpoint to get C2 patterns"""
    return jsonify(get_c2_patterns())

@traffic_bp.route('/start_traffic_monitoring', methods=['POST'])
def start_traffic_monitoring_endpoint():
    """Flask endpoint to start traffic monitoring"""
    if start_traffic_monitoring():
        return jsonify({'status': 'success', 'message': 'Network traffic monitoring started'})
    else:
        return jsonify({'status': 'warning', 'message': 'Network traffic monitoring is already running'})

@traffic_bp.route('/stop_traffic_monitoring', methods=['POST'])
def stop_traffic_monitoring_endpoint():
    """Flask endpoint to stop traffic monitoring"""
    if stop_traffic_monitoring():
        return jsonify({'status': 'success', 'message': 'Network traffic monitoring stopped'})
    else:
        return jsonify({'status': 'warning', 'message': 'Network traffic monitoring is not running'})

def register_traffic_monitor_endpoints(app):
    """Register the traffic monitor blueprint with the Flask app"""
    app.register_blueprint(traffic_bp)
    
# Start traffic monitoring automatically when the module is imported
start_traffic_monitoring()

# Integration instructions
"""
To integrate this module with your main app.py, add the following code:

1. At the top of your app.py with other imports:
   from network_traffic_monitor import register_traffic_monitor_endpoints

2. After your Flask app is initialized:
   register_traffic_monitor_endpoints(app)

This will register all the necessary traffic monitoring endpoints
with your Flask application.
"""
