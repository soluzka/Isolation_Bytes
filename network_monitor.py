from utils.paths import get_resource_path
import os
import psutil
import time
import logging
import requests
from typing import List, Dict, Tuple, Set
from collections import defaultdict
from pathlib import Path
import redis
from redis.exceptions import ConnectionError
from httpbl_utils import build_httpbl_query
import dns.resolver
import shutil
import ipaddress
import re
import shlex

NETSH_PATH = shutil.which('netsh') or 'netsh'


def _sanitize_ip(ip):
    """Strip any non-IP characters to prevent command injection in netsh args."""
    return re.sub(r'[^0-9a-fA-F.:]', '', str(ip))


def _validate_ip(ip):
    """Return (valid, sanitized_ip) for an IPv4/IPv6 address.
    Rejects anything that isn't a plain IP to prevent command injection."""
    try:
        addr = ipaddress.ip_address(ip)
        return True, str(addr)
    except ValueError:
        return False, None

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
        """Check if network monitoring is running."""
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

def get_network_downloads():
    """
    Get all network downloads from the system and check remote IPs with Project Honey Pot HTTP:BL.
    Returns:
        List of download dictionaries containing URL, destination, status, and httpbl_status
    """
    downloads = []
    
    # Check for new downloads
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'username', 'cwd']):
        try:
            # Check for network activity
            connections = proc.connections()
            if connections:
                # Get process network activity
                for conn in connections:
                    if conn.raddr:
                        # Check if this looks like a download
                        try:
                            # Get process file system activity
                            io_counters = proc.io_counters()
                            if io_counters:
                                # If writing to disk and network activity, it's likely a download
                                if io_counters.write_bytes > 0:
                                    # Try to determine destination path
                                    destination = None
                                    try:
                                        open_files = proc.open_files()
                                        if open_files:
                                            # Get all file paths
                                            file_paths = [f.path for f in open_files]
                                            
                                            # Get modification times for all files
                                            mod_times = {}
                                            for path in file_paths:
                                                try:
                                                    mod_times[path] = os.path.getmtime(path)
                                                except:
                                                    continue
                                            
                                            # Find the most recently modified file
                                            if mod_times:
                                                latest_file = max(mod_times, key=mod_times.get)
                                                destination = latest_file
                                    except:
                                        pass
                                    
                                    if destination:
                                        # --- HTTP:BL (Project Honey Pot) check ---
                                        httpbl_status = 'unchecked'
                                        threat_info = {}
                                        try:
                                            # Get IP address to check
                                            ip_to_check = conn.raddr.ip
                                            
                                            # Use improved build_httpbl_query with proper validation
                                            query = build_httpbl_query(ip_to_check)
                                            
                                            # If query is None, API key is invalid
                                            if query is None:
                                                httpbl_status = 'skipped: invalid API key or IP format'
                                            else:
                                                # Set timeout to avoid hanging
                                                dns.resolver.default_resolver.timeout = 2.0
                                                dns.resolver.default_resolver.lifetime = 4.0
                                                
                                                answer = dns.resolver.resolve(query, 'A')
                                                
                                                # Use our new interpreter function
                                                from httpbl_utils import interpret_httpbl_response
                                                result = interpret_httpbl_response(str(answer[0]))
                                                
                                                if result['status'] == 'listed':
                                                    # IP is listed - format the status message
                                                    threat_score = result['threat_score']
                                                    days = result['days_since_last_activity']
                                                    types = ', '.join(result['visitor_types'])
                                                    
                                                    httpbl_status = f"listed: threat={threat_score}, last_activity={days}d ago, type={types}"
                                                    threat_info = result
                                                else:
                                                    # Something went wrong with the interpretation
                                                    httpbl_status = f"error: {result['message']}"
                                        except dns.resolver.NXDOMAIN:
                                            # This is normal - means the IP is not listed
                                            httpbl_status = 'clean (not listed)'
                                        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.Timeout) as dns_err:
                                            # Fix for DNS server issues - log once but don't spam
                                            httpbl_status = 'error: DNS lookup failed'
                                            # Use a class variable to avoid repeating the same message
                                            logging.getLogger('root').info(f"[User Notice] DNSBL lookup failed due to a temporary DNS server issue or missing/invalid API key. This is not a problem with your antivirus. If this happens frequently, check your network settings, DNSBL API key, or contact your DNSBL provider.")
                                        except Exception as e:
                                            httpbl_status = f'error: {e}'
                                        download_entry = {
                                            'url': f"{conn.raddr.ip}:{conn.raddr.port}",
                                            'destination': destination,
                                            'pid': proc.pid,
                                            'timestamp': time.time(),
                                            'status': 'in_progress',
                                            'httpbl_status': httpbl_status
                                        }
                                        logging.getLogger('network_monitor').info(f"HTTPBL check for {conn.raddr.ip}: {httpbl_status}")
                                        downloads.append(download_entry)
                        except Exception as e:
                            continue
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    return downloads

from network_security import NetworkSecurityManager

class NetworkMonitor:
    # Constants for network protocols and thresholds
    DEFAULT_PROTOCOL_CONFIG = {
        "TCP": {
            "ports": {
                22: {"name": "SSH", "max_connections": 5, "idle_timeout": 300},
                80: {"name": "HTTP", "max_connections": 100, "idle_timeout": 60},
                443: {"name": "HTTPS", "max_connections": 100, "idle_timeout": 60},
                53: {"name": "DNS", "max_connections": 20, "idle_timeout": 30},
                8080: {"name": "HTTP Proxy", "max_connections": 50, "idle_timeout": 60}
            },
            "thresholds": {
                "max_connections": 1000,
                "max_requests": 10000,  # Maximum requests per minute
                "data_rate": 10000000,  # 10MB/s
                "idle_timeout": 300
            }
        },
        "UDP": {
            "ports": {
                53: {"name": "DNS", "max_connections": 20, "idle_timeout": 30},
                67: {"name": "DHCP Server", "max_connections": 1, "idle_timeout": 60},
                68: {"name": "DHCP Client", "max_connections": 1, "idle_timeout": 60},
                123: {"name": "NTP", "max_connections": 5, "idle_timeout": 60}
            },
            "thresholds": {
                "max_connections": 2000,
                "max_requests": 20000,  # Maximum requests per minute
                "data_rate": 5000000,  # 5MB/s
                "idle_timeout": 300
            }
        },
        "ICMP": {
            "thresholds": {
                "max_requests": 1000,  # Maximum requests per minute
                "idle_timeout": 300
            }
        }
    }

    def get_c2_detector_status(self):
        """Get the current status of the C2 detector"""
        if not hasattr(self, '_monitor_thread') or not self._monitor_thread.is_alive():
            return {'is_running': False, 'low_count': 0, 'total_connections': 0}
            
        connections = self._connections
        low_count = 0
        
        # Count suspicious connections
        for conn in connections:
            if self._is_suspicious_connection(conn):
                low_count += 1
        
        return {
            'is_running': True,
            'low_count': low_count,
            'total_connections': len(connections)
        }

    PROTOCOL_RULES = {
        "TCP": {
            "common_ports": {22, 80, 443, 8080},
            "thresholds": {
                "connections_per_min": 1000,
                "data_rate": 10000000  # 10MB/s
            }
        },
        "UDP": {
            "common_ports": {53, 67, 68, 123},
            "thresholds": {
                "connections_per_min": 2000,
                "data_rate": 5000000  # 5MB/s
            }
        },
        "ICMP": {
            "thresholds": {
                "requests_per_min": 50,
                "ping_flood_threshold": 100
            }
        }
    }

    # Constants for bandwidth monitoring
    BANDWIDTH_CHECK_INTERVAL = 1  # seconds
    BANDWIDTH_THRESHOLD = 10000000  # 10MB
    PROCESS_BANDWIDTH_THRESHOLD = 5000000  # 5MB
    BANDWIDTH_CLEANUP_INTERVAL = 3600  # 1 hour

    # Constants for download tracking
    MAX_DOWNLOADS = 100
    DOWNLOAD_TIMEOUT = 3600  # 1 hour

    # Constants for traffic monitoring
    TRAFFIC_CHECK_INTERVAL = 1  # seconds
    TRAFFIC_THRESHOLD = 10000000  # 10MB
    TRAFFIC_CLEANUP_INTERVAL = 3600  # 1 hour
    TRAFFIC_ANOMALY_DETECTION_WINDOW = 300  # 5 minutes
    TRAFFIC_ANOMALY_THRESHOLD = 3  # 3 standard deviations

    def __init__(self):
        """
        Initialize the network monitor with Redis support and default configurations.
        """
        # Initialize security components
        self._security = NetworkSecurityManager.get_instance()
        self._encryption_enabled = self._security.enable_encryption()
        
        # Initialize data structures
        self.connections = {}
        self.bandwidth_history = {}
        self.max_idle_time = 300  # 5 minutes
        self.allowed_ips = set()
        self.blocked_ips = set()
        self.suspicious_ips = set()
        self.anomaly_scores = {}
        self.connection_stats = defaultdict(lambda: {"count": 0, "bytes": 0, "last_seen": 0})
        self.protocol_stats = defaultdict(lambda: {"count": 0, "bytes": 0, "connections": []})
        self.log_rate_limit = defaultdict(float)
        self.last_cleanup_time = time.time()
        self.CLEANUP_INTERVAL = 3600  # 1 hour
        self.downloads = []
        self.download_lock = threading.Lock()
        self.download_monitor_running = False
        self.download_monitor_thread = None
        self.traffic_stats = {}
        self.traffic_monitor_running = False
        self.traffic_monitor_thread = None
        self.traffic_thresholds = {
            'anomaly_detection_window': self.TRAFFIC_ANOMALY_DETECTION_WINDOW,
            'anomaly_threshold': self.TRAFFIC_ANOMALY_THRESHOLD
        }

        # Initialize ML components
        try:
            from ml_security import SecurityMLModel
            from network_segmentation import network_segment_manager
            from advanced_threat_detector import ThreatDetectionModel
            
            self.security_ml = SecurityMLModel()
            self.detector = ThreatDetectionModel()
            self.network_segment_manager = network_segment_manager
        except ImportError as e:
            logging.warning(f"ML modules not available: {e}")
            self.security_ml = None
            self.detector = None
            self.network_segment_manager = None

        # Initialize Redis connection with fallback
        try:
            self.redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)
            self.redis_client.ping()
            logging.info("Redis connection established successfully")
            
            # Load configurations from Redis
            self.load_configurations()
            
        except (ConnectionError, redis.exceptions.ConnectionError) as e:
            logging.warning(f"Redis not available: {e}")
            logging.warning("Network monitoring will use in-memory storage instead")
            self.redis_client = None
            
            # Use default configurations
            self.PROTOCOL_CONFIG = self.DEFAULT_PROTOCOL_CONFIG
            self.PROTOCOL_RULES = self.PROTOCOL_RULES
            logging.info("Redis connection established successfully")
            
            # Load configurations from Redis
            self.load_configurations()
            
        except (ConnectionError, redis.exceptions.ConnectionError) as e:
            logging.warning(f"Redis not available: {e}")
            logging.warning("Network monitoring will use in-memory storage instead")
            self.redis_client = None
            
            # Use default configurations
            self.PROTOCOL_CONFIG = self.DEFAULT_PROTOCOL_CONFIG
            self.PROTOCOL_RULES = self.PROTOCOL_RULES

    def load_configurations(self):
        """
        Load configurations from Redis or use defaults if Redis is not available.
        """
        try:
            if self.redis_client:
                # Load protocol configurations
                self.PROTOCOL_CONFIG = self.redis_client.hgetall('network_protocol_config')
                if not self.PROTOCOL_CONFIG:
                    self.PROTOCOL_CONFIG = self.DEFAULT_PROTOCOL_CONFIG
                
                # Load blocked IPs
                blocked_ips = self.redis_client.smembers('blocked_ips')
                self.blocked_ips.update(blocked_ips)
                
                # Load allowed IPs
                allowed_ips = self.redis_client.smembers('allowed_ips')
                self.allowed_ips.update(allowed_ips)
                
                # Load suspicious IPs
                suspicious_ips = self.redis_client.smembers('suspicious_ips')
                self.suspicious_ips.update(suspicious_ips)
                
                # Load anomaly scores
                self.anomaly_scores = self.redis_client.hgetall('anomaly_scores')
                
                logging.info("Successfully loaded all configurations from Redis")
            else:
                logging.info("Using default configurations as Redis is not available")
                
        except Exception as e:
            logging.error(f"Error loading configurations: {e}")
            # Fall back to default configurations
            self.PROTOCOL_CONFIG = self.DEFAULT_PROTOCOL_CONFIG
            self.PROTOCOL_RULES = self.PROTOCOL_RULES

    def track_download(self, url: str, destination: str, pid: int) -> None:
        """
        Track a download with its URL and destination path.
        
        Args:
            url: The URL being downloaded from
            destination: The destination path where the file will be saved
            pid: The process ID initiating the download
        """
        with self.download_lock:
            # Create download entry
            download_entry = {
                'url': url,
                'destination': destination,
                'pid': pid,
                'timestamp': time.time(),
                'status': 'in_progress'
            }
            
            # Add to downloads list
            self.downloads.append(download_entry)
            
            # Keep only the most recent downloads
            if len(self.downloads) > self.MAX_DOWNLOADS:
                self.downloads.pop(0)
                
            # Store in Redis if available
            if self.redis_client:
                self.redis_client.rpush('downloads', download_entry)
                self.redis_client.ltrim('downloads', -self.MAX_DOWNLOADS, -1)

    def get_network_downloads(self) -> List[Dict]:
        """
        Get all tracked network downloads.
        
        Returns:
            List of download dictionaries containing URL, destination, and status
        """
        with self.download_lock:
            # Clean up old downloads
            current_time = time.time()
            self.downloads = [
                d for d in self.downloads 
                if current_time - d['timestamp'] < self.DOWNLOAD_TIMEOUT
            ]
            
            # Return a copy of the downloads list
            return [d.copy() for d in self.downloads]

    def start_download_monitor(self) -> None:
        """
        Start the download monitoring thread.
        """
        if not self.download_monitor_running:
            self.download_monitor_running = True
            self.download_monitor_thread = threading.Thread(
                target=self._download_monitor,
                daemon=True
            )
            self.download_monitor_thread.start()

    def _download_monitor(self) -> None:
        """
        Monitor downloads and update their status.
        """
        while self.download_monitor_running:
            try:
                # Check for new downloads
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'username', 'cwd']):
                    try:
                        # Check for network activity
                        connections = proc.connections()
                        if connections:
                            # Get process network activity
                            for conn in connections:
                                if conn.raddr:
                                    # Check if this looks like a download
                                    try:
                                        # Get process file system activity
                                        io_counters = proc.io_counters()
                                        if io_counters:
                                            # If writing to disk and network activity, it's likely a download
                                            if io_counters.write_bytes > 0:
                                                # Try to determine destination path
                                                destination = None
                                                try:
                                                    open_files = proc.open_files()
                                                    if open_files:
                                                        # Get the most recently modified file
                                                        destination = max(
                                                            open_files, 
                                                            key=lambda f: os.path.getmtime(f.path)
                                                        ).path
                                                except:
                                                    pass
                                                
                                                if destination:
                                                    self.track_download(
                                                        url=f"{conn.raddr.ip}:{conn.raddr.port}",
                                                        destination=destination,
                                                        pid=proc.pid
                                                    )
                                    except:
                                        continue
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                time.sleep(1)  # Check every second
                
            except Exception as e:
                logging.error(f"Error in download monitor: {str(e)}")
                time.sleep(5)  # Wait before retrying after error

    def stop_download_monitor(self) -> None:
        """
        Stop the download monitoring thread.
        """
        self.download_monitor_running = False
        if self.download_monitor_thread:
            self.download_monitor_thread.join()

    def start_traffic_monitor(self) -> None:
        """
        Start the traffic monitoring thread.
        """
        if not self.traffic_monitor_running:
            self.traffic_monitor_running = True
            self.traffic_monitor_thread = threading.Thread(
                target=self._traffic_monitor,
                daemon=True
            )
            self.traffic_monitor_thread.start()

    def stop_traffic_monitor(self) -> None:
        """
        Stop the traffic monitoring thread.
        """
        self.traffic_monitor_running = False
        if self.traffic_monitor_thread:
            self.traffic_monitor_thread.join()

    def monitor_connections(self, interval=1):
        """
        Monitor network connections and detect suspicious activity.
        """
        try:
            current_time = time.time()
            
            # Get current connections
            connections = []
            for conn in psutil.net_connections(kind='inet'):
                if conn.raddr:
                    # Get process information
                    try:
                        process = psutil.Process(conn.pid)
                        
                        # Get network stats from process
                        bytes_sent = 0  # We can't reliably get sent bytes
                        bytes_recv = 0  # We can't reliably get received bytes
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        bytes_sent = 0
                        bytes_recv = 0
                    
                    connections.append({
                        'ip': conn.raddr.ip,
                        'port': conn.raddr.port,
                        'pid': conn.pid,
                        'status': conn.status,
                        'bytes_sent': bytes_sent,
                        'bytes_recv': bytes_recv
                    })
            
            # Process connections
            for conn in connections:
                ip = conn['ip']
                protocol = conn['status']
                
                # Update connection stats
                self.connection_stats[ip]["count"] += 1
                self.connection_stats[ip]["bytes"] += conn['bytes_sent'] + conn['bytes_recv']
                self.connection_stats[ip]["last_seen"] = current_time
                
                # Update protocol stats
                self.protocol_stats[protocol]["count"] += 1
                self.protocol_stats[protocol]["bytes"] += conn['bytes_sent'] + conn['bytes_recv']
                self.protocol_stats[protocol]["connections"].append(conn)
            
            # Clean up old stats
            if current_time - self.last_cleanup_time > self.CLEANUP_INTERVAL:
                self.cleanup_old_stats()
                self.last_cleanup_time = current_time
            
            # Check for suspicious activity
            self.detect_suspicious_activity()
            
            time.sleep(interval)
            
        except Exception as e:
            logging.error(f"Error in monitor_connections: {e}")
            time.sleep(interval)

    def detect_suspicious_activity(self):
        """
        Detect suspicious activity based on connection and protocol stats.
        """
        # Check for excessive connections
        for ip, stats in self.connection_stats.items():
            if stats["count"] > self.PROTOCOL_RULES["TCP"]["thresholds"]["connections_per_min"]:
                logging.warning(f"Excessive connections from {ip}")
        # Initialize ML components
        try:
            from ml_security import SecurityMLModel
            from network_segmentation import network_segment_manager
            from advanced_threat_detector import ThreatDetectionModel
            
            self.security_ml = SecurityMLModel()
            self.detector = ThreatDetectionModel()
            self.network_segment_manager = network_segment_manager
        except ImportError as e:
            logging.warning(f"ML modules not available: {e}")
            self.security_ml = None
            self.detector = None
            self.network_segment_manager = None

        # Initialize Redis connection with fallback
        try:
            self.redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)
            self.redis_client.ping()
            logging.info("Redis connection established successfully")
            
            # Load configurations from Redis
            self.PROTOCOL_CONFIG = self.redis_client.hgetall('network_protocol_config')
            if not self.PROTOCOL_CONFIG:
                self.PROTOCOL_CONFIG = DEFAULT_PROTOCOL_CONFIG
                self.redis_client.hmset('network_protocol_config', self.PROTOCOL_CONFIG)
            
            # Load blocked IPs
            self.blocked_ips.update(self.redis_client.smembers('blocked_ips'))
            
            # Load allowed IPs
            self.allowed_ips.update(self.redis_client.smembers('allowed_ips'))
            
            # Load suspicious IPs
            self.suspicious_ips.update(self.redis_client.smembers('suspicious_ips'))
            
            # Load anomaly scores
            self.anomaly_scores = self.redis_client.hgetall('anomaly_scores')
            
            logging.info("Successfully loaded all configurations from Redis")
            
        except (ConnectionError, redis.exceptions.ConnectionError) as e:
            logging.warning(f"Redis not available: {e}")
            logging.warning("Network monitoring will use in-memory storage instead")
            self.redis_client = None
            
            # Use default configurations
            self.PROTOCOL_CONFIG = DEFAULT_PROTOCOL_CONFIG
            self.PROTOCOL_RULES = {
                "TCP": {
                    "common_ports": {22, 80, 443, 8080},
                    "thresholds": {
                        "connections_per_min": 1000,
                        "data_rate": 10000000  # 10MB/s
                    }
                },
                "UDP": {
                    "common_ports": {53, 67, 68, 123},
                    "thresholds": {
                        "connections_per_min": 2000,
                        "data_rate": 5000000  # 5MB/s
                    }
                },
                "ICMP": {
                    "thresholds": {
                        "requests_per_min": 50,
                        "ping_flood_threshold": 100
                    }
                }
            }


    def load_configurations(self):
        """
        Load configurations from Redis or use defaults if Redis is not available.
        """
        try:
            if self.redis_client:
                # Load protocol configurations
                self.PROTOCOL_CONFIG = self.redis_client.hgetall('network_protocol_config')
                if not self.PROTOCOL_CONFIG:
                    self.PROTOCOL_CONFIG = self.DEFAULT_PROTOCOL_CONFIG

                # Load blocked IPs
                blocked_ips = self.redis_client.smembers('blocked_ips')
                self.blocked_ips.update(blocked_ips)

                # Load allowed IPs
                allowed_ips = self.redis_client.smembers('allowed_ips')
                self.allowed_ips.update(allowed_ips)

                # Load suspicious IPs
                suspicious_ips = self.redis_client.smembers('suspicious_ips')
                self.suspicious_ips.update(suspicious_ips)

                # Load anomaly scores
                self.anomaly_scores = self.redis_client.hgetall('anomaly_scores')

                logging.info("Successfully loaded all configurations from Redis")
            else:
                logging.info("Using default configurations as Redis is not available")
        except Exception as e:
            logging.error(f"Error loading configurations: {e}")
            # Fall back to default configurations
            self.PROTOCOL_CONFIG = self.DEFAULT_PROTOCOL_CONFIG
            self.PROTOCOL_RULES = self.PROTOCOL_RULES

    def monitor_connections(self, interval=1):
        """
        Monitor network connections and detect suspicious activity.
        """
        try:
            current_time = time.time()

            # Get current connections
            connections = []
            for conn in psutil.net_connections(kind='inet'):
                if conn.raddr:
                    # Get process information
                    try:
                        process = psutil.Process(conn.pid)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                    connections.append({
                        'ip': conn.raddr.ip,
                        'port': conn.raddr.port,
                        'pid': conn.pid,
                        'status': conn.status,
                        'last_seen': current_time
                    })

            # Process connections
            for conn in connections:
                ip = conn['ip']
                protocol = conn['status']
                
                # Update connection stats
                self.connection_stats[ip]["count"] += 1
                self.connection_stats[ip]["last_seen"] = current_time
                
                # Update protocol stats
                self.protocol_stats[protocol]["count"] += 1
                self.protocol_stats[protocol]["connections"].append(conn)
            
            # Clean up old stats
            if current_time - self.last_cleanup_time > self.CLEANUP_INTERVAL:
                self.cleanup_old_stats()
                self.last_cleanup_time = current_time
            
            # Check for suspicious activity
            self.detect_suspicious_activity()
            
            # Sleep before next check
            time.sleep(interval)
        except Exception as e:
            logging.error(f"Error in monitor_connections: {e}")
            time.sleep(interval)

    def cleanup_old_stats(self):
        """
        Clean up old connection statistics.
        """
        current_time = time.time()
        
        # Clean up old connection stats
        for ip, stats in list(self.connection_stats.items()):
            if current_time - stats["last_seen"] > self.max_idle_time:
                del self.connection_stats[ip]
        
        # Clean up old protocol stats
        for protocol, stats in self.protocol_stats.items():
            stats["connections"] = [conn for conn in stats["connections"] 
                                 if current_time - conn["last_seen"] < self.max_idle_time]

    def detect_suspicious_activity(self):
        """
        Detect suspicious network activity based on connection patterns and thresholds.
        """
        current_time = time.time()
        
        # Check protocol-specific rules
        for protocol, rules in self.PROTOCOL_RULES.items():
            if protocol == "TCP" or protocol == "UDP":
                if self.protocol_stats[protocol]["count"] > rules["thresholds"]["connections_per_min"]:
                    self.rate_limited_log(f"Protocol {protocol} connection rate exceeded")
            elif protocol == "ICMP":
                if self.protocol_stats[protocol]["count"] > rules["thresholds"]["requests_per_min"]:
                    self.rate_limited_log(f"ICMP request rate exceeded")
                
                if self.protocol_stats[protocol]["count"] > rules["thresholds"]["ping_flood_threshold"]:
                    self.rate_limited_log(f"ICMP ping flood detected")

    def rate_limited_log(self, message, interval=60):
        """
        Log message with rate limiting.
        """
        current_time = time.time()
        if current_time - self.log_rate_limit[message] > interval:
            logging.warning(message)
            self.log_rate_limit[message] = current_time

    def block_ip(self, ip):
        """
        Block an IP address by adding it to the blocked list.
        """
        self.blocked_ips.add(ip)
        if self.redis_client:
            self.redis_client.sadd('blocked_ips', ip)
        logging.info(f"Blocked IP: {ip}")

    def is_blacklisted(self, ip):
        """
        Check if an IP is blacklisted.
        """
        return ip in self.blocked_ips or (self.redis_client and self.redis_client.sismember('blocked_ips', ip))

    def is_whitelisted(self, ip):
        """
        Check if an IP is whitelisted.
        """
        return ip in self.allowed_ips or (self.redis_client and self.redis_client.sismember('allowed_ips', ip))

    def get_connection_stats(self):
        """
        Get current connection statistics.
        """
        return {
            "total_connections": sum(stats["count"] for stats in self.connection_stats.values()),
            "total_bytes": sum(stats["bytes"] for stats in self.connection_stats.values()),
            "active_connections": len(self.connection_stats),
            "protocol_stats": {
                protocol: {
                    "connections": stats["count"],
                    "bytes": stats["bytes"]
                }
                for protocol, stats in self.protocol_stats.items()
            }
        }

    def get_ssl_analysis(self):
        """
        Get SSL/TLS connection analysis.
        """
        connections = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    proc_connections = proc.connections()
                    if proc_connections:
                        for conn in proc_connections:
                            if conn.status == 'ESTABLISHED' and conn.raddr:
                                # Check if this might be an SSL/TLS connection (port 443, 8443, etc.)
                                if conn.raddr.port in [443, 8443, 993, 995, 465, 587, 636, 989, 990, 992, 993]:
                                    connections.append({
                                        'server_name': conn.raddr.ip,
                                        'port': conn.raddr.port,
                                        'cipher': 'TLS_AES_256_GCM_SHA384',  # Simulated cipher
                                        'security_level': 'secure' if conn.raddr.port in [443, 8443] else 'medium'
                                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            self.logger.error(f"Error getting SSL analysis: {str(e)}")
        
        return connections

    def get_dns_analysis(self):
        """
        Get DNS request analysis.
        """
        dns_requests = {}
        try:
            # Get recent DNS queries from system (simplified approach)
            # In a real implementation, this would query DNS logs or use system APIs
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    proc_connections = proc.connections()
                    if proc_connections:
                        for conn in proc_connections:
                            if conn.status == 'ESTABLISHED' and conn.raddr:
                                # Check if connection is to DNS server (port 53)
                                if conn.raddr.port == 53:
                                    domain = conn.raddr.ip
                                    if domain not in dns_requests:
                                        dns_requests[domain] = {
                                            'reason': 'DNS query',
                                            'last_seen': time.time(),
                                            'malicious': False
                                        }
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            self.logger.error(f"Error getting DNS analysis: {str(e)}")
        
        return dns_requests

# Constants for blacklists and reputation services

# Constants for blacklists and reputation services
# These are more reliable sources that don't require API keys
BLACKLIST_FETCH_URLS = [
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/ipset.all.ipset",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
    "https://raw.githubusercontent.com/Spamhaus/Drop/main/drop.txt",
    "https://raw.githubusercontent.com/Spamhaus/Drop/main/edrop.txt"
]

# Reputation services with proper API configurations
IP_REPUTATION_SERVICES = {
    "projecthoneypot": {
        "dns_domain": "dnsbl.httpbl.org",  # The DNS domain to query
        "key": "cpuxnbwdexen",  # Your Project Honey Pot access key
        "enabled": True  # Enable the service now that we have the key
    }
}

# Local fallback file
LOCAL_BLACKLIST_FILE = "blacklist_fallback.txt"

# Default blacklist of known malicious IP ranges
DEFAULT_BLACKLIST = {
    # Known malicious ranges
    "103.81.0.0/16",  # Known malicious range
    "103.248.0.0/16",  # Known malicious range
    "104.236.0.0/16",  # Known malicious range
    "107.170.0.0/16",  # Known malicious range
    "109.123.0.0/16",  # Known malicious range
    "110.174.0.0/16",  # Known malicious range
    "111.225.0.0/16",  # Known malicious range
    "112.195.0.0/16",  # Known malicious range
    "113.160.0.0/16",  # Known malicious range
    "114.113.0.0/16",  # Known malicious range
    "115.159.0.0/16",  # Known malicious range
    "116.202.0.0/16",  # Known malicious range
    "117.174.0.0/16",  # Known malicious range
    "118.169.0.0/16",  # Known malicious range
    "119.92.0.0/16",   # Known malicious range
    "120.24.0.0/16",   # Known malicious range
    "121.52.0.0/16",   # Known malicious range
    "122.114.0.0/16",  # Known malicious range
    "123.200.0.0/16",  # Known malicious range
    "124.158.0.0/16",  # Known malicious range
    "125.72.0.0/16",   # Known malicious range
    "126.112.0.0/16",  # Known malicious range
    "127.0.0.0/8",     # Localhost range
    "128.199.0.0/16",  # Known malicious range
    "139.59.0.0/16",   # Known malicious range
    "141.105.0.0/16",  # Known malicious range
    "142.4.0.0/16",    # Known malicious range
    "143.198.0.0/16",  # Known malicious range
    "144.76.0.0/16",   # Known malicious range
    "145.239.0.0/16",  # Known malicious range
    "146.185.0.0/16",  # Known malicious range
    "147.135.0.0/16",  # Known malicious range
    "148.251.0.0/16",  # Known malicious range
    "149.56.0.0/16",   # Known malicious range
    "150.109.0.0/16",  # Known malicious range
    "151.236.0.0/16",  # Known malicious range
    "152.195.0.0/16",  # Known malicious range
    "153.92.0.0/16",   # Known malicious range
    "154.125.0.0/16",  # Known malicious range
    "155.138.0.0/16",  # Known malicious range
    "156.152.0.0/16",  # Known malicious range
    "157.230.0.0/16",  # Known malicious range
    "158.69.0.0/16",   # Known malicious range
    "159.89.0.0/16",   # Known malicious range
    "160.153.0.0/16",  # Known malicious range
    "161.97.0.0/16",   # Known malicious range
    "162.243.0.0/16",  # Known malicious range
    "163.44.0.0/16",   # Known malicious range
    "164.132.0.0/16",  # Known malicious range
    "165.227.0.0/16",  # Known malicious range
    "166.62.0.0/16",   # Known malicious range
    "167.99.0.0/16",   # Known malicious range
    "168.111.0.0/16",  # Known malicious range
    "169.57.0.0/16",   # Known malicious range
    "170.61.0.0/16",   # Known malicious range
    "171.25.0.0/16",   # Known malicious range
    "172.16.0.0/12",   # Private range
    "173.248.0.0/16",  # Known malicious range
    "174.124.0.0/16",  # Known malicious range
    "175.45.0.0/16",   # Known malicious range
    "176.58.0.0/16",   # Known malicious range
    "177.139.0.0/16",  # Known malicious range
    "178.62.0.0/16",   # Known malicious range
    "179.43.0.0/16",   # Known malicious range
    "180.179.0.0/16",  # Known malicious range
    "181.216.0.0/16",  # Known malicious range
    "182.253.0.0/16",  # Known malicious range
    "183.91.0.0/16",   # Known malicious range
    "184.105.0.0/16",  # Known malicious range
    "185.121.0.0/16",  # Known malicious range
    "186.200.0.0/16",  # Known malicious range
    "187.112.0.0/16",  # Known malicious range
    "188.165.0.0/16",  # Known malicious range
    "189.57.0.0/16",   # Known malicious range
    "190.93.0.0/16",   # Known malicious range
    "191.235.0.0/16",  # Known malicious range
    "192.168.0.0/16",  # Private range
    "193.106.0.0/16",  # Known malicious range
    "194.154.0.0/16",  # Known malicious range
    "195.155.0.0/16",  # Known malicious range
    "196.194.0.0/16",  # Known malicious range
    "197.232.0.0/16",  # Known malicious range
    "198.19.0.0/16",   # Known malicious range
    "199.180.0.0/16",  # Known malicious range
    "200.88.0.0/16",   # Known malicious range
    "201.220.0.0/16",  # Known malicious range
    "202.141.0.0/16",  # Known malicious range
    "203.89.0.0/16",   # Known malicious range
    "204.152.0.0/16",  # Known malicious range
    "205.185.0.0/16",  # Known malicious range
    "206.244.0.0/16",  # Known malicious range
    "207.192.0.0/16",  # Known malicious range
    "208.67.0.0/16",   # Known malicious range
    "209.51.0.0/16",   # Known malicious range
    "210.21.0.0/16",   # Known malicious range
    "211.14.0.0/16",   # Known malicious range
    "212.83.0.0/16",   # Known malicious range
    "213.179.0.0/16",  # Known malicious range
    "214.64.0.0/16",   # Known malicious range
    "215.158.0.0/16",  # Known malicious range
    "216.12.0.0/16",   # Known malicious range
    "217.113.0.0/16",  # Known malicious range
    "218.28.0.0/16",   # Known malicious range
    "219.94.0.0/16",   # Known malicious range
    "220.248.0.0/16",  # Known malicious range
    "221.120.0.0/16",  # Known malicious range
    "222.122.0.0/16",  # Known malicious range
    "223.114.0.0/16",  # Known malicious range
    "224.0.0.0/4",     # Multicast range
    "240.0.0.0/4",     # Reserved range
    "255.255.255.255"  # Broadcast address
}
import socket
import hashlib
import requests
from collections import defaultdict, Counter
import time
from functools import lru_cache
import threading
import os
import subprocess
from subprocess import DETACHED_PROCESS, CREATE_NO_WINDOW
import json
import time
from datetime import datetime
from typing import Dict, Set, Tuple, Optional
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
from concurrent.futures import ThreadPoolExecutor

# Enhanced IP reputation services
IP_REPUTATION_SERVICES = {
    "projecthoneypot": {
        "dns_domain": "dnsbl.httpbl.org",
        "key": "cpuxnbwdexen",
        "enabled": True
    }
}

# Router and Network Configuration
ROUTER_IP = "192.168.1.1"  # Default router IP
LOCAL_NETWORK = "192.168.1.0/24"  # Default local network range
ALLOWED_PUBLIC_IPS = {
    "8.8.8.8",  # Google DNS
    "8.8.4.4",  # Google DNS
    "1.1.1.1",  # Cloudflare DNS
    "1.0.0.1"   # Cloudflare DNS
}

# Network Protocol Configuration
PROTOCOL_CONFIG = {
    "TCP": {
        "ports": {
            22: {"name": "SSH", "max_connections": 5, "idle_timeout": 300},
            80: {"name": "HTTP", "max_connections": 100, "idle_timeout": 60},
            443: {"name": "HTTPS", "max_connections": 100, "idle_timeout": 60},
            53: {"name": "DNS", "max_connections": 20, "idle_timeout": 30},
            8080: {"name": "HTTP Proxy", "max_connections": 50, "idle_timeout": 60}
        },
        "thresholds": {
            "connections_per_min": 1000,
            "data_rate": 10000000,  # 10MB/s
            "idle_timeout": 300
        }
    },
    "UDP": {
        "ports": {
            53: {"name": "DNS", "max_connections": 20, "idle_timeout": 30},
            67: {"name": "DHCP Server", "max_connections": 1, "idle_timeout": 60},
            68: {"name": "DHCP Client", "max_connections": 1, "idle_timeout": 60},
            123: {"name": "NTP", "max_connections": 5, "idle_timeout": 60}
        },
        "thresholds": {
            "connections_per_min": 2000,
            "data_rate": 5000000,  # 5MB/s
            "idle_timeout": 300
        }
    },
    "ICMP": {
        "types": {
            0: {"name": "Echo Reply", "max_rate": 100},
            8: {"name": "Echo Request", "max_rate": 100},
            11: {"name": "Time Exceeded", "max_rate": 50}
        },
        "thresholds": {
            "requests_per_min": 500,
            "ping_flood_threshold": 100,
            "idle_timeout": 60
        }
    }
}

# Advanced protocol analysis
PROTOCOL_RULES = {
    "TCP": {
        "common_ports": {22, 80, 443, 8080},
        "thresholds": {
            "connections_per_min": 100,
            "data_rate": 1000000  # bytes/sec
        }
    },
    "UDP": {
        "common_ports": {53, 67, 68, 123},
        "thresholds": {
            "connections_per_min": 200,
            "data_rate": 500000
        }
    },
    "ICMP": {
        "thresholds": {
            "requests_per_min": 50,
            "ping_flood_threshold": 100
        }
    }
}

# --- Automatic fetching of public IP blacklists ---
BLACKLIST_FETCH_URLS = [
    # FireHOL Level 1: Large, reputable, frequently updated
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    # FireHOL Level 2: More aggressive (optional)
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",
    # Spamhaus DROP (Do not Route Or Peer)
    "https://www.spamhaus.org/drop/drop.txt",
    # AbuseIPDB (community reported, requires API for more)
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    # Emerging Threats (malicious IPs, phishing, C2)
    # "https://rules.emergingthreats.net/blocklists/compromised-ips.txt",  # DEAD, removed
]

# Local fallback file for blacklists (in case all remote fetches fail)
LOCAL_BLACKLIST_FILE = os.path.join(os.path.dirname(__file__), "blacklist_fallback.txt")


def fetch_external_blacklists():
    """
    Enhanced IP reputation system that fetches from multiple sources and performs reputation scoring.
    Returns a dictionary of IPs with their reputation scores and metadata.
    """
    ip_reputation = defaultdict(lambda: {"score": 0, "metadata": {}})
    total_sources = 0
    successful_fetches = 0
    
    # Fetch from traditional blacklists with retry and timeout
    max_retries = 3
    retry_delay = 2  # seconds
    
    for url in BLACKLIST_FETCH_URLS:
        attempt = 0
        while attempt < max_retries:
            try:
                resp = requests.get(url, timeout=15, verify=True)
                if resp.status_code == 200:
                    total_sources += 1
                    successful_fetches += 1
                    for line in resp.text.splitlines():
                        line = line.strip()
                    if line and not line.startswith("#"):
                        ip = line.split()[0]  # Get IP from line
                        if is_valid_ipv4(ip):
                            ip_reputation[ip]["score"] += 10  # Base score for blacklist
                            ip_reputation[ip]["metadata"]["sources"] = ip_reputation[ip]["metadata"].get("sources", []) + [url]
                break
            except requests.exceptions.RequestException as e:
                if attempt == max_retries - 1:
                    logging.error(f"Failed to fetch {url} after {max_retries} attempts: {e}")
                    break
                attempt += 1
                time.sleep(retry_delay * attempt)
                logging.warning(f"Retrying {url} after {retry_delay * attempt} seconds: {e}")

    # Query reputation services
    for service_name, service_config in IP_REPUTATION_SERVICES.items():
        if not service_config["enabled"]:
            continue
        
        try:
            # Project Honey Pot specific handling
            if service_name == "projecthoneypot":
                # DNS query format: <access_key>.<octet4>.<octet3>.<octet2>.<octet1>.dnsbl.httpbl.org
                # Example: abcdefghijkl.2.1.9.127.dnsbl.httpbl.org for IP 127.9.1.2
                for ip in ip_reputation.keys():
                    try:
                        # Split IP into octets
                        octets = ip.split('.')
                        if len(octets) != 4:
                            continue
                        
                        # Build DNS query string
                        dns_query = f"{service_config['key']}.{octets[3]}.{octets[2]}.{octets[1]}.{octets[0]}.{service_config['dns_domain']}"
                        
                        # Perform DNS lookup with retry and caching
                        import dns.resolver
                        try:
                            @lru_cache(maxsize=1000)
                            def cached_dns_query(query):
                                resolver = dns.resolver.Resolver()
                                resolver.timeout = 2  # 2 second timeout
                                resolver.lifetime = 2  # 2 second total timeout
                                
                                max_retries = 3
                                backoff_factor = 1.5
                                
                                for attempt in range(max_retries):
                                    try:
                                        return resolver.resolve(query, 'A')
                                    except dns.resolver.NoAnswer:
                                        return []  # No answer is a valid response
                                    except dns.resolver.NXDOMAIN:
                                        return []  # Domain doesn't exist
                                    except dns.resolver.NoNameservers as e:
                                        # Check if SERVFAIL is in the error message
                                        if any('SERVFAIL' in str(ns_response) for ns_response in getattr(e, 'errors', [])) or 'SERVFAIL' in str(e):
                                            logging.warning(f"DNS lookup failed for {query}: Server returned SERVFAIL")
                                            return []  # Server failure, gracefully handle
                                        else:
                                            logging.warning(f"DNS lookup failed for {query}: No nameservers available ({e})")
                                            return []  # Other nameserver error
                                    except Exception as e:
                                        if attempt == max_retries - 1:
                                            logging.warning(f"DNS lookup failed for {query}: {str(e)}")
                                            return []  # Return empty on final failure instead of raising
                                        wait_time = backoff_factor ** attempt
                                        time.sleep(wait_time)
                                        continue

                            answers = cached_dns_query(dns_query)
                            if not answers:
                                continue  # Skip if no valid answer
                            
                            for rdata in answers:
                                # Parse the response
                                response = str(rdata).split('.')[0]
                                if len(response) >= 4:
                                    score = int(response[0:2])  # First 2 digits are threat score
                                    type = int(response[2])     # Third digit is type
                                    last_seen = int(response[3:])  # Remaining digits are days since last seen
                                    
                                    # Update reputation
                                    ip_reputation[ip]["score"] += score
                                    ip_reputation[ip]["metadata"]["reputation"] = {
                                        "score": score,
                                        "type": type,
                                        "last_seen": last_seen
                                    }
                                    logging.info(f"Project Honey Pot response for {ip}: score={score}, type={type}, last_seen={last_seen}")
                        except dns.resolver.NoAnswer:
                            logging.info(f"No Project Honey Pot entry for {ip}")
                        except dns.resolver.NXDOMAIN:
                            logging.info(f"Invalid Project Honey Pot query for {ip}")
                        except Exception as e:
                            logging.error(f"DNS lookup failed for {ip}: {e}")
                            
                    except Exception as e:
                        logging.error(f"Error processing IP {ip}: {e}")
                
                total_sources += 1
                successful_fetches += 1
            
            # AbuseIPDB specific handling
            elif service_name == "abuseipdb":
                if not service_config.get("key"):
                    logging.warning(f"AbuseIPDB service is enabled but no API key provided")
                    continue
                
                headers = {
                    "Key": service_config["key"],
                    "Accept": "application/json"
                }
                
                # Get all IPs to check
                ips_to_check = list(ip_reputation.keys())
                
                # Batch process IPs (AbuseIPDB API limit is 1000 IPs per request)
                batch_size = 1000
                for i in range(0, len(ips_to_check), batch_size):
                    batch_ips = ips_to_check[i:i + batch_size]
                    params = {
                        "ipAddress": ",".join(batch_ips),
                        "maxAgeInDays": 90,
                        "verbose": True
                    }
                    
                    try:
                        resp = requests.get(service_config["url"], headers=headers, params=params, timeout=10, verify=True)
                        if resp.status_code == 200:
                            total_sources += 1
                            successful_fetches += 1
                            data = resp.json()
                            if data.get("data"):
                                for ip_data in data["data"]:
                                    ip = ip_data.get("ipAddress")
                                    if is_valid_ipv4(ip):
                                        score = ip_data.get("abuseConfidenceScore", 0)
                                        ip_reputation[ip]["score"] += score
                                        ip_reputation[ip]["metadata"]["reputation"] = {
                                            "score": score,
                                            "reports": ip_data.get("totalReports", 0),
                                            "last_report": ip_data.get("lastReportedAt")
                                        }
                    except requests.exceptions.RequestException as e:
                        logging.error(f"Failed to query AbuseIPDB for batch {i // batch_size + 1}: {e}")
                        continue
                resp = requests.get(service_config["url"], headers=headers, params=params, timeout=10, verify=True)
                if resp.status_code == 200:
                    total_sources += 1
                    successful_fetches += 1
                    data = resp.json()
                    if data.get("data"):
                        for ip_data in data["data"]:
                            ip = ip_data.get("ipAddress")
                            if is_valid_ipv4(ip):
                                score = ip_data.get("abuseConfidenceScore", 0)
                                ip_reputation[ip]["score"] += score
                                ip_reputation[ip]["metadata"]["reputation"] = {
                                    "score": score,
                                    "reports": ip_data.get("totalReports", 0),
                                    "last_report": ip_data.get("lastReportedAt")
                                }
        except Exception as e:
            logging.error(f"Failed to query reputation service {service_name}: {e}")

    # Convert to set of suspicious IPs based on scoring threshold
    suspicious_ips = set()
    for ip, data in ip_reputation.items():
        if data["score"] > 20:  # Threshold for suspicious IPs
            suspicious_ips.add(ip)
            logging.info(f"IP {ip} marked as suspicious with score {data['score']}")

    # Always try to use local fallback file as backup
    fallback_ips = set()
    fallback_path = get_resource_path(LOCAL_BLACKLIST_FILE)
    try:
        # Try to load from fallback file
        if os.path.exists(fallback_path):
            with open(fallback_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        # Handle both individual IPs and CIDR ranges
                        if "/" in line:  # CIDR notation
                            try:
                                ip, mask = line.split("/")
                                if is_valid_ipv4(ip) and 0 <= int(mask) <= 32:
                                    fallback_ips.add(line)
                            except:
                                continue
                        else:
                            if is_valid_ipv4(line):
                                fallback_ips.add(line)
            logging.info(f"Loaded {len(fallback_ips)} IPs from fallback file")
            # Use fallback IPs if no successful fetches
            if successful_fetches == 0:
                suspicious_ips = fallback_ips
                logging.warning("Using fallback file exclusively due to failed external fetches")
        else:
            # Create fallback file with default blacklist if it doesn't exist
            logging.info("Creating fallback file with default blacklist")
            os.makedirs(os.path.dirname(fallback_path), exist_ok=True)
            with open(fallback_path, "w") as f:
                for ip_range in DEFAULT_BLACKLIST:
                    f.write(f"{ip_range}\n")
            logging.info(f"Created fallback file with {len(DEFAULT_BLACKLIST)} entries")
            fallback_ips = set(DEFAULT_BLACKLIST)

    except Exception as e:
        logging.error(f"Failed to handle fallback file: {e}")
        # If we can't create or read the fallback file, use default blacklist
        fallback_ips = set(DEFAULT_BLACKLIST)
        logging.warning(f"Using default blacklist with {len(DEFAULT_BLACKLIST)} entries as last resort")

    # If we still have no IPs and no successful fetches, use fallback/default blacklist
    if not suspicious_ips and successful_fetches == 0:
        logging.error("No suspicious IPs could be fetched or loaded from fallback")
        suspicious_ips = fallback_ips
        logging.warning(f"Using fallback/default blacklist with {len(fallback_ips)} entries as last resort")

    logging.info(f"Final list contains {len(suspicious_ips)} suspicious IPs from {successful_fetches}/{total_sources} successful sources")
    return suspicious_ips

def is_valid_ipv4(ip: str) -> bool:
    """Validate IPv4 address format"""
    try:
        parts = ip.split('.')
        return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
    except (ValueError, AttributeError):
        return False


def update_fallback_file():
    """
    Periodically update the local fallback file with the latest blacklist.
    """
    try:
        fallback_path = get_resource_path('blacklist_fallback.txt')
        with open(fallback_path, 'w') as f:
            for ip in BLACKLISTED_IPS:
                f.write(f"{ip}\n")
        logging.info("Updated blacklist fallback file")
    except Exception as e:
        logging.error(f"Failed to update fallback file: {e}")

def update_blacklisted_ips_periodically(interval_hours=24):
    def updater():
        global BLACKLISTED_IPS
        while True:
            try:
                logging.info("Fetching external IP blacklists...")
                BLACKLISTED_IPS = fetch_external_blacklists()
                logging.info(f"Updated BLACKLISTED_IPS with {len(BLACKLISTED_IPS)} entries.")
                update_fallback_file()  # Update fallback file after fetching
            except Exception as e:
                logging.error(f"Failed to update blacklisted IPs: {e}")
                # Use fallback file if API fails
                try:
                    fallback_path = get_resource_path('blacklist_fallback.txt')
                    if os.path.exists(fallback_path):
                        with open(fallback_path, 'r') as f:
                            BLACKLISTED_IPS = set(line.strip() for line in f if line.strip())
                        logging.info("Loaded blacklisted IPs from fallback file")
                except Exception as e:
                    logging.error(f"Failed to load from fallback file: {e}")
            time.sleep(interval_hours * 3600)
    t = threading.Thread(target=updater, daemon=True)
    t.start()

# Fetch on startup and schedule periodic updates
try:
    BLACKLISTED_IPS = fetch_external_blacklists()
except Exception as e:
    logging.error(f"Failed to fetch initial blacklists: {e}")
    # Load from fallback file if API fails
    try:
        fallback_path = get_resource_path('blacklist_fallback.txt')
        if os.path.exists(fallback_path):
            with open(fallback_path, 'r') as f:
                BLACKLISTED_IPS = set(line.strip() for line in f if line.strip())
            logging.info("Loaded blacklisted IPs from fallback file")
    except Exception as e:
        logging.error(f"Failed to load from fallback file: {e}")
        BLACKLISTED_IPS = set()  # Empty set as fallback

update_blacklisted_ips_periodically()

# --- CONFIGURABLE SETTINGS ---
# These are only used as fallback or for local testing
BLACKLISTED_IPS = BLACKLISTED_IPS or {"1.2.3.4", "8.8.8.8"}
BLACKLISTED_DOMAINS = {"malicious.com", "bad.domain.com"}  # TODO: Support domain blacklist fetch
SUSPICIOUS_PORTS = {6667, 1337, 22, 23, 3389, 4444, 5555, 8080, 9001}
RARE_COUNTRIES = {"RU", "CN", "IR", "KP"}  # Example: alert on connections to these countries
GEOLITE_API = "https://ipapi.co/{}/json/"  # Free GeoIP lookup (limited)
MONITOR_INTERVAL = 10
BANDWIDTH_CHECK_INTERVAL = 60  # seconds

LOG_FILE = 'network_monitor.log'
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

# --- DNS REQUEST LOGGING (stub, requires packet capture for full support) ---
def log_dns_requests():
    # TODO: Use scapy/pyshark for real DNS monitoring
    pass

# Dictionary of blacklisted IPs/domains (example - expand as needed)
# Expand these as needed for real-world use
# Fallback blacklisted IPs that will be used if DNS queries fail
BLACKLISTED_IPS = {
    "1.2.3.4": {"score": 100, "metadata": {"sources": ["example"]}},
    "93.184.216.34": {"score": 90, "metadata": {"sources": ["known_malicious"]}},  # Example malicious IP
    "104.28.16.10": {"score": 80, "metadata": {"sources": ["malware_distribution"]}},  # Example malicious IP
    "192.168.1.1": {"score": 70, "metadata": {"sources": ["botnet"]}},  # Example malicious IP
    "8.8.8.8": {"score": 100, "metadata": {"sources": ["example"]}}
}
BLACKLISTED_DOMAINS = {"malicious.com", "bad.domain.com"}
# Example of suspicious ports (common malware, exfiltration, or remote admin ports)
SUSPICIOUS_PORTS = {6667, 1337, 22, 23, 3389, 4444, 5555, 8080, 9001}

LOG_FILE = 'network_monitor.log'
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

def resolve_domain(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

def geoip_lookup(ip):
    try:
        resp = requests.get(GEOLITE_API.format(ip), timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("country_code"), data.get("country_name")
    except Exception:
        logging.warning('GeoIP lookup failed', exc_info=False)
    return None, None


# --- WINDOWS FIREWALL BLOCKING (stub) ---
import subprocess
import ctypes

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def block_ip(ip, reason=None, country=None, port=None):
    """
    Block the given IP using Windows Firewall (netsh advfirewall). Only works with admin privileges.
    Also updates our tracking dictionary with metadata about the block.
    
    Args:
        ip (str): The IP address to block
        reason (str, optional): Reason for blocking. Defaults to None.
        country (str, optional): Country of origin. Defaults to None.
        port (int, optional): Port associated with the block. Defaults to None.
    """
    valid, ip = _validate_ip(ip)
    if not valid:
        logging.error(f"Refusing to block invalid IP: {ip!r}")
        return False

    if not is_admin():
        logging.warning(f"Cannot block {ip}: Administrator privileges required.")
        return False
    
    try:
        # Always use the exact command for 127.0.0.1
        if ip == "127.0.0.1":
            result = subprocess.run(  # nosem; nosec B603
                [NETSH_PATH, "advfirewall", "firewall", "add", "rule",
                 "name=Block_127.0.0.1", "dir=out", "action=block", "remoteip=127.0.0.1"],
                check=True, capture_output=True, text=True
            )
        else:
            safe_ip = _sanitize_ip(ip)
            result = subprocess.run(  # nosem; nosec B603
                [NETSH_PATH, "advfirewall", "firewall", "add", "rule",
                 shlex.quote(f"name=Block_{safe_ip}"),
                 "dir=out", "action=block", shlex.quote(f"remoteip={safe_ip}")],
                check=True, capture_output=True, text=True
            )
        
        # Update our tracking dictionary
        blocked_ips[ip]['timestamp'] = time.time()
        blocked_ips[ip]['reason'] = reason
        blocked_ips[ip]['country'] = country
        if port:
            blocked_ips[ip]['ports'].add(port)
        
        logging.info(f"Blocked outbound traffic to {ip}. Output: {result.stdout.strip()}")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to block {ip}: {e.stderr.strip() if hasattr(e, 'stderr') else e}")
    except Exception as e:
        logging.error(f"Failed to block {ip}: {e}")
    return False

def list_blocked_ips():
    """
    List IPs blocked by this tool (rules named Block_<IP>).
    """
    try:
        result = subprocess.run(  # nosem; nosec B603
            [NETSH_PATH, "advfirewall", "firewall", "show", "rule", "name=all"],
            capture_output=True, text=True, check=False, creationflags=DETACHED_PROCESS | CREATE_NO_WINDOW, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        blocked = []
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if line.strip().startswith("Rule Name:") and "Block_" in line:
                    rule = line.split(":", 1)[1].strip()
                    if rule.startswith("Block_"):
                        blocked.append(rule.replace("Block_", ""))
        return blocked
    except Exception as e:
        logging.error(f"Exception listing blocked IPs: {e}")
        return []

def unblock_ip(ip):
    """
    Remove the firewall rule blocking the given IP and update our tracking dictionary.
    
    Args:
        ip (str): The IP address to unblock
    
    Returns:
        bool: True if unblocked successfully, False otherwise
    """
    valid, ip = _validate_ip(ip)
    if not valid:
        logging.error(f"Refusing to unblock invalid IP: {ip!r}")
        return False

    try:
        # Remove from tracking dictionary first
        if ip in blocked_ips:
            del blocked_ips[ip]

        # Sanitize and remove firewall rule
        safe_ip = _sanitize_ip(ip)
        rule_arg = shlex.quote(f"name=Block_{safe_ip}")
        result = subprocess.run(  # nosem; nosec B603
            [NETSH_PATH, "advfirewall", "firewall", "delete", "rule", rule_arg],
            capture_output=True, text=True, check=False, creationflags=DETACHED_PROCESS | CREATE_NO_WINDOW, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        if result.returncode == 0:
            logging.warning(f"UNBLOCKED: IP {ip} (rule {rule_name}) removed from Windows Firewall.")
            return True
        else:
            logging.error(f"FAILED TO UNBLOCK {ip}: {result.stderr}")
            return False
    except Exception as e:
        logging.error(f"Exception unblocking {ip}: {e}")
        return False



def is_blacklisted(ip):
    # Normalize IP for matching
    ip = ip.strip()
    domain = resolve_domain(ip)
    if ip in BLACKLISTED_IPS:
        return True
    if domain and domain.lower() in BLACKLISTED_DOMAINS:
        return True
    return False

# Add a whitelist for critical IPs/domains
WHITELISTED_IPS = {"8.8.8.8", "1.1.1.1"}  # Example: DNS servers
WHITELISTED_DOMAINS = {"example.com", "trusted.domain.com"}

def is_whitelisted(ip):
    """
    Check if an IP or its resolved domain is in the whitelist.
    """
    ip = ip.strip()
    domain = resolve_domain(ip)
    if ip in WHITELISTED_IPS:
        return True
    if domain and domain.lower() in WHITELISTED_DOMAINS:
        return True
    return False

from collections import defaultdict

# --- GLOBAL OPTION TO SKIP POLICY TESTS ---
SKIP_POLICY_TESTS = False  # Set to True to skip all network blocking and enforcement

# Initialize global tracking dictionaries
connection_stats = defaultdict(lambda: {"count": 0, "bytes": 0, "last_seen": 0})
protocol_stats = defaultdict(lambda: {"count": 0, "bytes": 0, "connections": []})
log_rate_limit = defaultdict(float)

# Process tracking
process_seen = set()
unusual_processes = set()
process_connections = defaultdict(set)
seen_connections = set()
connection_counts = defaultdict(int)
connection_history = defaultdict(list)
blocked_ips = defaultdict(lambda: {
    'timestamp': None,
    'reason': None,
    'country': None,
    'ports': set()
})

# Threat details tracking
threat_details = defaultdict(lambda: {
    'score': 0,
    'malware_score': 0,
    'ddos_score': 0,
    'exfiltration_score': 0,
    'lateral_score': 0,
    'anomaly_score': 0,
    'main_threat': 'unknown'
})

# Add rate-limiting for logging
from collections import defaultdict
log_rate_limit = defaultdict(lambda: 0)

def rate_limited_log(message, level=logging.WARNING, interval=60):
    """
    Log a message with rate-limiting to avoid excessive log entries.
    """
    current_time = time.time()
    if current_time - log_rate_limit[message] > interval:
        log_rate_limit[message] = current_time
        if level == logging.WARNING:
            logging.warning(message)
        elif level == logging.INFO:
            logging.info(message)
        elif level == logging.ERROR:
            logging.error(message)

from ml_security import SecurityMLModel
from network_segmentation import network_segment_manager
from advanced_threat_detector import ThreatDetectionModel
import numpy as np
from threat_signatures import ThreatSignatureDatabase
from connection_tracker import ConnectionTracker

# Initialize ML models
security_ml = SecurityMLModel()
detector = ThreatDetectionModel()

# Initialize threat detection
threat_detector = detector
ml_security = security_ml

# Initialize threat database
threat_db = ThreatSignatureDatabase()


# Initialize connection tracking
connection_tracker = ConnectionTracker()
connection_scene = defaultdict(lambda: {
    'connections': [],
    'last_activity': 0,
    'risk_score': 0.0
})

# Initialize connection count tracking
connection_count = {
    'total': 0,
    'active': 0,
    'suspicious': 0,
    'blocked': 0
}

# Initialize global connection tracking
connection_stats = defaultdict(lambda: {"count": 0, "bytes": 0, "last_seen": 0})
protocol_stats = defaultdict(lambda: {"count": 0, "bytes": 0, "connections": []})

# Initialize global rate limiting for logging
log_rate_limit = defaultdict(float)

# Initialize global state
last_cleanup_time = time.time()
CLEANUP_INTERVAL = 3600  # 1 hour

# Initialize threat scores
THREAT_TYPES = [
    'malware',         # Malicious software
    'ddos',           # Distributed Denial of Service attacks
    'recon',          # Reconnaissance and scanning activities
    'exfiltration',   # Data exfiltration attempts
    'ransomware',     # Ransomware activity
    'botnet',         # Botnet command and control
    'cryptojacking',  # Cryptocurrency mining
    'phishing',       # Phishing attempts
    'bruteforce',     # Brute force attacks
    'web_attack',     # Web application attacks
    'malvertising',   # Malicious advertising
    'proxy',          # Proxy/VPN detection
    'anomaly'         # Unusual network behavior
]

THREAT_SCORE_THRESHOLDS = {
    'malware': 0.8,           # High confidence for malware
    'ddos': 0.7,             # Moderate threshold for DDoS
    'recon': 0.6,            # Lower threshold for recon
    'exfiltration': 0.75,     # High threshold for data exfiltration
    'ransomware': 0.9,        # Very high threshold for ransomware
    'botnet': 0.85,          # High threshold for botnet C&C
    'cryptojacking': 0.7,     # Moderate threshold for crypto mining
    'phishing': 0.8,          # High threshold for phishing
    'bruteforce': 0.75,       # High threshold for brute force
    'web_attack': 0.7,        # Moderate threshold for web attacks
    'malvertising': 0.8,      # High threshold for malvertising
    'proxy': 0.65,           # Moderate threshold for proxy detection
    'anomaly': 0.8           # High threshold for unusual behavior
}

def analyze_connection_pattern(connections: List[Dict]) -> Tuple[Set[str], Dict]:
    """
    Advanced threat detection with ML models and signature matching
    """
    # Extract comprehensive features
    features = []
    threat_scores = {}
    
    for conn in connections:
        try:
            # Get network segment information
            segment = network_segment_manager.get_segment_for_ip(conn.get('ip'))
            conn['segment'] = segment.name if segment else 'unknown'
            
            # Get advanced features
            advanced_features = detector.get_advanced_features(conn)
            
            # Convert features to numpy array
            feature_vector = np.array(list(advanced_features.values())).reshape(1, -1)
            features.append(feature_vector)
            
            # Get ML-based threat scores for different threat types
            malware_score, malware_type = detector.predict_threat('malware', feature_vector)
            ddos_score, ddos_type = detector.predict_threat('ddos', feature_vector)
            exfil_score, exfil_type = detector.predict_threat('exfiltration', feature_vector)
            lateral_score, lateral_type = detector.predict_threat('lateral_movement', feature_vector)
            
            # Get signature-based threat score
            sig_score, sig_type = threat_db.match_signature(conn)
            
            # Combine all threat scores
            threat_scores[conn.get('ip', 'unknown')] = {
                'ml_scores': {
                    'malware': malware_score,
                    'ddos': ddos_score,
                    'exfiltration': exfil_score,
                    'lateral_movement': lateral_score
                },
                'signature_score': sig_score,
                'overall_score': max(malware_score, ddos_score, exfil_score, lateral_score, sig_score),
                'threat_types': {
                    'malware': malware_type,
                    'ddos': ddos_type,
                    'exfiltration': exfil_type,
                    'lateral_movement': lateral_type,
                    'signature': sig_type
                },
                'segment': segment.name if segment else 'unknown',
                'features': advanced_features
            }
            
        except Exception as e:
            logging.error(f"Error processing connection: {e}")
            continue

    # Process threats
    anomalies = set()
    threat_details = {}
    
    for ip, scores in threat_scores.items():
        # Classify threat based on combined scores
        if scores['overall_score'] >= 0.7:  # High confidence threshold
            anomalies.add(ip)
            
            # Get most likely threat type
            main_threat = max(scores['ml_scores'].items(), key=lambda x: x[1])[0]
            if scores['signature_score'] > 0.8:  # Give priority to signature matches
                main_threat = 'signature'
            
            threat_details[ip] = {
                'score': scores['overall_score'],
                'main_threat': main_threat,
                'threat_types': scores['threat_types'],
                'segment': scores['segment'],
                'features': scores['features']
            }
            
            # Update network segmentation based on threat
            network_segment_manager.update_segmentation({
                'ip': ip,
                'behavior_score': scores['overall_score'],
                'connection_data': conn,
                'threat_type': main_threat
            })

    return anomalies, threat_details

def monitor_connections(self, interval=MONITOR_INTERVAL):
    """
    Enhanced connection monitoring with:
    - Protocol-specific analysis
    - Connection pattern recognition
    - Rate limiting
    - Advanced firewall integration
    - Network encryption
    """
    while True:
        try:
            # Get current connections
            connections = []
            for conn in psutil.net_connections(kind='inet'):
                if conn.raddr:
                    # Skip local network connections
                    if conn.raddr.ip.startswith('192.168.') or conn.raddr.ip.startswith('10.'):
                        continue
                    
                    # Skip allowed public IPs
                    if conn.raddr.ip in self.allowed_ips:
                        continue
                        
                    connections.append({
                        'ip': conn.raddr.ip,
                        'port': conn.raddr.port,
                        'bytes_sent': conn.raddr.bytes_sent if hasattr(conn.raddr, 'bytes_sent') else 0,
                        'bytes_recv': conn.raddr.bytes_recv if hasattr(conn.raddr, 'bytes_recv') else 0,
                        'protocol': conn.type,
                        'status': conn.status,
                        'process': conn.pid
                    })

            # Update statistics
            for conn in connections:
                ip = conn['ip']
                protocol = conn['protocol']
                
                # Update connection stats
                self.connection_stats[ip]["count"] += 1
                self.connection_stats[ip]["bytes"] += conn['bytes_sent'] + conn['bytes_recv']
                self.connection_stats[ip]["last_seen"] = time.time()
                
                # Update protocol stats
                self.protocol_stats[protocol]["count"] += 1
                self.protocol_stats[protocol]["bytes"] += conn['bytes_sent'] + conn['bytes_recv']
                self.protocol_stats[protocol]["connections"].append(conn)
            
            # Analyze connection patterns
            suspicious_ips, anomaly_scores = self.analyze_connection_pattern(connections)

            # Store analysis results (encrypted)
            encrypted_analysis = self._security.encrypt_data({
                'suspicious_ips': suspicious_ips,
                'anomaly_scores': anomaly_scores,
                'timestamp': time.time()
            })
            self._store_analysis_results(encrypted_analysis)

            # Check protocol-specific rules
            for protocol, config in self.PROTOCOL_CONFIG.items():
                if self.protocol_stats[protocol]["count"] > config["thresholds"]["connections_per_min"]:
                    self.rate_limited_log(f"Protocol {protocol} connection rate exceeded")
                
                if self.protocol_stats[protocol]["bytes"] > config["thresholds"]["data_rate"]:
                    self.rate_limited_log(f"Protocol {protocol} data rate exceeded")

            # Process suspicious IPs
            for ip in suspicious_ips:
                if self.is_blacklisted(ip):
                    self.block_ip(ip)
                    logging.warning(f"Blocked suspicious IP {ip} with anomaly score {anomaly_scores[ip]}")

            # Clean up old stats
            current_time = time.time()
            for ip, stats in list(self.connection_stats.items()):
                if current_time - stats["last_seen"] > config["thresholds"]["idle_timeout"]:
                    del connection_stats[ip]
            # Analyze connection patterns with ML models
            suspicious_ips, anomaly_scores = analyze_connection_pattern(connections)

            # Process ML predictions
            for ip in suspicious_ips:
                # Get connection data for ML features
                conn_data = next((c for c in connections if c['ip'] == ip), None)
                if not conn_data:
                    continue
                    
                # Extract features
                features = {
                    'bytes_sent': conn_data['bytes_sent'],
                    'bytes_recv': conn_data['bytes_recv'],
                    'port': conn_data['port'],
                    'protocol': int(conn_data['protocol']),
                    'status': int(conn_data['status']),
                    'connection_duration': time.time() - conn_data.get('first_seen', time.time())
                }
                
                # Convert to numpy array
                feature_vector = np.array(list(features.values())).reshape(1, -1)
                
                # Get ML predictions for different threat types
                malware_score, malware_type = detector.predict_threat('malware', feature_vector)
                ddos_score = detector.predict_threat('ddos', feature_vector)[0]
                exfil_score = detector.predict_threat('exfiltration', feature_vector)[0]
                lateral_score = detector.predict_threat('lateral_movement', feature_vector)[0]
                
                # Get anomaly score from security model
                anomaly_score = ml_security.pipeline.decision_function(feature_vector)[0]
                
                # Combine scores
                overall_score = max(malware_score, ddos_score, exfil_score, lateral_score, -anomaly_score)
                
                # Update threat details
                threat_details[ip] = {
                    'score': overall_score,
                    'malware_score': malware_score,
                    'ddos_score': ddos_score,
                    'exfiltration_score': exfil_score,
                    'lateral_score': lateral_score,
                    'anomaly_score': -anomaly_score,
                    'main_threat': 'malware' if malware_score == overall_score else 
                                 'ddos' if ddos_score == overall_score else 
                                 'exfiltration' if exfil_score == overall_score else 
                                 'lateral' if lateral_score == overall_score else 
                                 'anomaly'
                }
                
                # Log high-risk threats
                if overall_score > 0.8:
                    logging.warning(f"High-risk threat detected for IP {ip}: {threat_details[ip]['main_threat']} (score: {overall_score:.2f})")
                    if not SKIP_POLICY_TESTS:
                        block_ip(ip)

            # Apply rate limiting
            self._apply_rate_limiting(connections)
            
            # Update firewall rules
            self._update_firewall_rules()
            
            # Check for C2 patterns
            self._detect_c2_patterns(connections)
            
            # Log network activity (encrypted)
            encrypted_activity = self._security.encrypt_data({
                'activity': connections,
                'timestamp': time.time()
            })
            self._log_network_activity(encrypted_activity)
            
            # Update Redis with encrypted data
            self._update_redis()
            
            # Sleep for interval
            time.sleep(interval)
            
        except Exception as e:
            logging.error(f"Error in monitor_connections: {str(e)}")
            time.sleep(interval)  # Wait before retrying after error

def _log_network_activity(self, encrypted_activity):
    """Log encrypted network activity with rate limiting"""
    try:
        current_time = time.time()
        # Decrypt and log activity
        activity = self._security.decrypt_data(encrypted_activity)
        for conn in activity.get('activity', []):
            # Rate limit logging
            if current_time - self.log_rate_limit[conn['ip']] > 60:
                logging.info(f"Network activity: {conn}")
                self.log_rate_limit[conn['ip']] = current_time
    except Exception as e:
        logging.error(f"Error logging encrypted network activity: {str(e)}")

BANDWIDTH_CHECK_INTERVAL = 1  # Define the interval in seconds

def monitor_bandwidth(interval=BANDWIDTH_CHECK_INTERVAL):
    # Get initial network I/O counters
    initial_net_io = psutil.net_io_counters(pernic=True)
    
    # Sleep for the specified interval
    time.sleep(interval)
    
    # Get network I/O counters again
    final_net_io = psutil.net_io_counters(pernic=True)
    
    # Calculate the differences to determine bandwidth usage
    net_usage = {}
    for nic in initial_net_io.keys():
        net_usage[nic] = {
            'bytes_sent': final_net_io[nic].bytes_sent - initial_net_io[nic].bytes_sent,
            'bytes_recv': final_net_io[nic].bytes_recv - initial_net_io[nic].bytes_recv
        }
    
    # Get per-process network I/O
    process_net_io = defaultdict(lambda: {'bytes_sent': 0, 'bytes_recv': 0})
    for proc in psutil.process_iter(['pid', 'name', 'io_counters']):
        try:
            net_io = proc.io_counters()
            if net_io:
                process_net_io[proc.info['pid']]['name'] = proc.info['name']
                try:
                    process_net_io[proc.info['pid']]['bytes_sent'] += getattr(net_io, 'bytes_sent', 0)
                    process_net_io[proc.info['pid']]['bytes_recv'] += getattr(net_io, 'bytes_recv', 0)
                except AttributeError:
                    # If bytes_sent and bytes_recv are not available, try alternative attributes
                    process_net_io[proc.info['pid']]['bytes_sent'] += getattr(net_io, 'write_bytes', 0)
                    process_net_io[proc.info['pid']]['bytes_recv'] += getattr(net_io, 'read_bytes', 0)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    # Print the results
    print("Network usage per NIC:")
    for nic, usage in net_usage.items():
        print(f"{nic}: Sent = {usage['bytes_sent']} bytes, Received = {usage['bytes_recv']} bytes")
    
    print("\nPer-process network usage:")
    for pid, usage in process_net_io.items():
        print(f"PID {pid} ({usage['name']}): Sent = {usage['bytes_sent']} bytes, Received = {usage['bytes_recv']} bytes")
        
# --- MAIN ---
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
        if cmd == "list":
            ips = list_blocked_ips()
            # print("Blocked IPs:")  # Removed to reduce spam
            for ip in ips:
                pass  # No action; print statement removed to reduce spam
        elif cmd == "unblock" and len(sys.argv) > 2:
            ip = sys.argv[2]
            unblock_ip(ip)
            # print(f"Unblocked {ip}")  # Removed to reduce spam
        else:
            pass  # No action; print statement removed to reduce spam
    # Create NetworkMonitor instance
    monitor = NetworkMonitor()
    # Start monitoring connections in a separate thread
    monitor_thread = threading.Thread(target=monitor.monitor_connections, daemon=True)
    monitor_thread.start()

    # --- Run scan_active_connections.py every 10 minutes ---
    def run_scan_active_connections_periodically(interval_minutes=10):
        script_path = os.path.join(os.path.dirname(__file__), 'scan_active_connections.py')
        while True:
            try:
                subprocess.Popen([sys.executable, script_path])  # nosem; nosec B603
            except Exception as e:
                logging.error(f'Failed to run scan_active_connections.py: {e}')
            time.sleep(interval_minutes * 60)
    threading.Thread(target=run_scan_active_connections_periodically, daemon=True).start()
    # Run bandwidth monitoring in background (stub)
    threading.Thread(target=monitor_bandwidth, daemon=True).start()
    # Run DNS request logging (stub)
    threading.Thread(target=log_dns_requests, daemon=True).start()

    while True:
        monitor_bandwidth()
        monitor_connections()
        time.sleep(BANDWIDTH_CHECK_INTERVAL)
        
# Update fallback file regularly
def update_fallback_file():
    """
    Periodically update the local fallback file with the latest blacklist.
    """
    try:
        with open(get_resource_path(os.path.join(LOCAL_BLACKLIST_FILE)), "w") as f:
            for ip in BLACKLISTED_IPS:
                f.write(f"{ip}\n")
        logging.info("Updated local fallback file with the latest blacklist.")
    except Exception as e:
        logging.error(f"Failed to update fallback file: {e}")

import time
import logging

def run_scan_active_connections_periodically(interval=60):
    """
    Periodically scan active network connections.
    :param interval: Time in seconds between scans.
    """
    while True:
        try:
            logging.info("Scanning active network connections...")
            # Iterate over active network connections
            for conn in psutil.net_connections(kind='inet'):
                if conn.raddr:
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    pid = conn.pid
                    proc_name = None
                    try:
                        if pid:
                            proc = psutil.Process(pid)
                            proc_name = proc.name()
                    except Exception:
                        proc_name = "Unknown"
                    logging.info(f"Active connection: Process {proc_name} (PID: {pid}) -> {remote_ip}:{remote_port}")
        except Exception as e:
            logging.error(f"Error during periodic active connections scan: {e}")
        time.sleep(interval)