from utils.paths import get_resource_path
import os
import psutil
import time
import logging
import redis
import json
import socket
import threading
from redis.exceptions import ConnectionError
from collections import defaultdict

class NetworkMonitor:
    def __init__(self, use_redis=False):
        self.running = False
        self.thread = None
        self.use_redis = use_redis
        self.redis_client = None
        self.network_info = {}
        self.logger = logging.getLogger('network_monitor')
        self.setup_logging()
        
        if self.use_redis:
            try:
                self.redis_client = redis.Redis(host='localhost', port=6379, db=0)
                self.redis_client.ping()
                self.logger.info("Successfully connected to Redis")
            except ConnectionError:
                self.logger.warning("Redis not available, using in-memory storage")
                self.use_redis = False

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('network_monitor.log'),
                logging.StreamHandler()
            ]
        )

    def start(self):
        """Start the network monitoring thread."""
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self.monitor_network, daemon=True)
            self.thread.start()
            self.logger.info("Network monitoring started")

    def stop(self):
        """Stop the network monitoring thread."""
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join()
        self.logger.info("Network monitoring stopped")

    def is_running(self):
        """Check if network monitoring is active."""
        return self.running

    def monitor_network(self):
        """Monitor network activity and store information."""
        while self.running:
            try:
                # Get network connections
                connections = []
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'username', 'cwd']):
                    try:
                        proc_connections = proc.connections()
                        if proc_connections:
                            connections.extend(proc_connections)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                # Store network information
                self.network_info = {
                    'connections': len(connections),
                    'timestamp': time.time()
                }

                # Store in Redis if available
                if self.use_redis and self.redis_client:
                    self.redis_client.set('network_info', json.dumps(self.network_info))

            except Exception as e:
                self.logger.error(f"Error monitoring network: {str(e)}")

            time.sleep(1)  # Check every second

    def get_network_info(self):
        """Get current network information."""
        if self.use_redis and self.redis_client:
            try:
                data = self.redis_client.get('network_info')
                if data:
                    return json.loads(data)
            except Exception as e:
                self.logger.error(f"Error getting network info from Redis: {str(e)}")
        return self.network_info
        
    def get_traffic_stats(self):
        """Get traffic statistics from the system."""
        try:
            # Initialize traffic stats
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
                                    'laddr': conn.laddr,
                                    'raddr': conn.raddr,
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
                                if conn.raddr:
                                    traffic_stats['active_ips'].add(conn.raddr.ip)
                                    traffic_stats['ports'][conn.raddr.port] += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            traffic_stats['total_connections'] = len(connections)
            traffic_stats['active_ips'] = list(traffic_stats['active_ips'])  # Convert set to list for JSON serialization
            
            return traffic_stats
        except Exception as e:
            self.logger.error(f"Error getting traffic stats: {str(e)}")
            return {
                'error': str(e),
                'inbound': 0,
                'outbound': 0,
                'total_connections': 0,
                'active_ips': [],
                'protocols': {},
                'ports': {},
                'processes': {},
                'timestamp': time.time()
            }
    
    def get_c2_patterns(self):
        """Get potential command and control patterns in network traffic."""
        try:
            # This is a simplified implementation
            # In a real-world scenario, this would involve advanced analysis
            c2_data = {
                'potential_c2': [],
                'beaconing': [],
                'suspicious_connections': [],
                'timestamp': time.time()
            }
            
            # Get all active connections
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    connections = proc.connections()
                    for conn in connections:
                        if conn.status == 'ESTABLISHED' and conn.raddr:
                            # Check for common suspicious ports
                            suspicious_ports = [4444, 8080, 8443, 9001, 9002, 31337]
                            if conn.raddr.port in suspicious_ports:
                                c2_data['suspicious_connections'].append({
                                    'process': proc.info['name'],
                                    'pid': proc.pid,
                                    'remote_ip': conn.raddr.ip,
                                    'remote_port': conn.raddr.port,
                                    'reason': f"Suspicious port {conn.raddr.port}"
                                })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            return c2_data
        except Exception as e:
            self.logger.error(f"Error getting C2 patterns: {str(e)}")
            return {
                'error': str(e),
                'potential_c2': [],
                'beaconing': [],
                'suspicious_connections': [],
                'timestamp': time.time()
            }
