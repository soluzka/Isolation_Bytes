from utils.paths import get_resource_path
import os

import logging
import os
import time
import threading
import socket
import psutil
import json
from collections import defaultdict
import math
from datetime import datetime
import requests
import ipaddress
from security.network_threat_feed import NetworkThreatFeed
from security.process_security import scan_specific_process

class C2Detector:
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger("C2Detector")
        self.connection_history = defaultdict(list)
        self.domain_history = []
        self.suspicious_connections = []
        self.suspicious_processes = []
        
        # Beaconing detection thresholds
        self.beaconing_thresholds = {
            "min_samples": 5,
            "max_variance": 0.2,
            "min_interval": 10,
            "max_interval": 3600
        }
        
        # DGA detection
        self.entropy_threshold = 4.2
        
        # Known C2 ports (commonly used by malware)
        self.known_c2_ports = {
            4444,   # Metasploit default
            8080,   # Common alternate HTTP (often used by RATs)
            1080,   # SOCKS proxy (often used for C2)
            6666,   # Common backdoor port
            31337,  # Elite backdoor port
            1337,   # Common hacker port
            9001,   # Tor default ORPort
            9030,   # Tor default DirPort
            1024,   # Common first non-privileged port
            5555,   # Common Android debug port
        }
        
        # Load threat intelligence data
        self.malicious_ip_ranges = self._load_malicious_ip_ranges()
        self.malicious_ips = self._load_malicious_ips()
        self.feed = NetworkThreatFeed()
        
    def _load_malicious_ip_ranges(self):
        """Load known malicious IP ranges"""
        ranges = []
        try:
            # This would typically come from a threat intelligence feed
            # For demonstration, we'll use a small hardcoded list
            malicious_ranges = [
                "185.156.73.0/24",  # Example malicious range
                "103.101.103.0/24",  # Example malicious range
                "5.188.206.0/24",    # Example malicious range
            ]
            
            for ip_range in malicious_ranges:
                try:
                    ranges.append(ipaddress.ip_network(ip_range))
                except ValueError:
                    self.logger.warning(f"Invalid IP range format: {ip_range}")
        except Exception as e:
            self.logger.error(f"Error loading malicious IP ranges: {e}")
        
        return ranges
    
    def _load_malicious_ips(self):
        """Load known malicious individual IPs"""
        ips = set()
        try:
            # Check if we have a local malicious_ips.log file
            basedir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            malicious_ip_file = os.path.join(basedir, "malicious_ips.log")
            
            if os.path.exists(malicious_ip_file):
                with open(get_resource_path(os.path.join(malicious_ip_file)), 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            ips.add(line)
            
            # Add some known malicious IPs for demonstration
            known_bad = [
                "185.156.73.54",
                "103.101.103.78",
                "5.188.206.100",
            ]
            ips.update(known_bad)
            
        except Exception as e:
            self.logger.error(f"Error loading malicious IPs: {e}")
        
        return ips
    
    def _is_ip_in_malicious_ranges(self, ip):
        """Check if an IP is in any known malicious ranges"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for ip_range in self.malicious_ip_ranges:
                if ip_obj in ip_range:
                    return True
            return False
        except ValueError:
            return False
    
    def _analyze_beaconing(self):
        """Analyze connections for beaconing patterns with severity assessment"""
        suspicious = []
        
        # Whitelist common services
        whitelisted_ips = {
            '127.0.0.1',
            '192.168.1.1',
        }
        
        whitelisted_processes = {
            'chrome.exe',
            'firefox.exe',
            'msedge.exe',
            'outlook.exe',
            'teams.exe',
            'slack.exe',
            'zoom.exe',
            'explorer.exe',
            'svchost.exe',
        }
        
        for conn_id, timestamps in self.connection_history.items():
            parts = conn_id.split(':')
            if len(parts) < 5:
                continue

            remote_ip = parts[0]
            remote_port = int(parts[1])
            process_name = parts[3]
            pid = int(parts[4]) if parts[4].isdigit() else 0
            
            # Skip whitelisted items
            if remote_ip in whitelisted_ips or process_name in whitelisted_processes:
                continue
                
            if len(timestamps) < self.beaconing_thresholds["min_samples"]:
                continue
            
            # Calculate intervals between connections
            intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
            
            if len(intervals) < 3:
                continue
            
            # Calculate statistics
            avg_interval = sum(intervals) / len(intervals)
            variance = sum((i - avg_interval)**2 for i in intervals) / len(intervals)
            std_dev = variance ** 0.5
            
            # Check if this matches beaconing behavior
            if (self.beaconing_thresholds["min_interval"] <= avg_interval <= self.beaconing_thresholds["max_interval"] and
                (std_dev / avg_interval) <= self.beaconing_thresholds["max_variance"]):
                
                # Calculate severity score (0-100)
                severity = self._calculate_beaconing_severity(
                    remote_ip, 
                    remote_port, 
                    process_name, 
                    avg_interval, 
                    std_dev, 
                    len(timestamps)
                )
                
                # Only report if severity is above threshold
                if severity >= 40:  # Medium severity or higher
                    process_scan = scan_specific_process(pid) if pid else None
                    suspicious.append({
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "process": process_name,
                        "pid": pid,
                        "avg_interval": avg_interval,
                        "connection_count": len(timestamps),
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "severity": severity,
                        "severity_label": self._get_severity_label(severity),
                        "reasons": self._get_severity_reasons(
                            remote_ip, 
                            remote_port, 
                            process_name, 
                            avg_interval, 
                            std_dev
                        ),
                        "process_scan": process_scan
                    })
                    
                    self.logger.warning(
                        f"Potential C2 beaconing detected: {process_name} connecting to {remote_ip}:{remote_port} "
                        f"every {avg_interval:.2f} seconds ({len(timestamps)} connections) - "
                        f"Severity: {self._get_severity_label(severity)} ({severity}/100)"
                    )
        
        self.suspicious_connections = suspicious
        return suspicious
    
    def _calculate_beaconing_severity(self, ip, port, process, interval, std_dev, count):
        """
        Calculate a severity score for beaconing behavior
        Returns a score from 0-100 where:
        0-39: Low severity (likely benign)
        40-69: Medium severity (suspicious)
        70-89: High severity (likely malicious)
        90-100: Critical severity (almost certainly malicious)
        """
        score = 0
        
        # Factor 1: Known malicious IP or range (highest weight)
        if ip in self.malicious_ips or self.feed.is_malicious_ip(ip):
            score += 50
        elif self._is_ip_in_malicious_ranges(ip):
            score += 40
            
        # Factor 2: Known C2 port
        if port in self.known_c2_ports or self.feed.is_c2_port(port):
            score += 25

        # Factor 2b: Blocked geo-IP country
        if self.feed.is_blocked_country(ip):
            score += 30
            
        # Factor 3: Consistency of beaconing (lower std_dev = more consistent = more suspicious)
        consistency_ratio = std_dev / interval if interval > 0 else 1
        if consistency_ratio < 0.05:  # Extremely consistent
            score += 20
        elif consistency_ratio < 0.1:
            score += 15
        elif consistency_ratio < 0.15:
            score += 10
            
        # Factor 4: Unusual process making network connections
        unusual_processes = {
            'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe', 
            'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'certutil.exe'
        }
        if process.lower() in unusual_processes:
            score += 20
            
        # Factor 5: Beaconing interval characteristics
        if 50 <= interval <= 300:  # 50s-5min is common for C2
            score += 15
        elif interval < 50:  # Very frequent beaconing
            score += 10
            
        # Factor 6: Number of connections
        if count > 20:
            score += 10
        elif count > 10:
            score += 5
            
        # Factor 7: Non-standard port for the process
        browser_processes = {'chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe'}
        if process.lower() in browser_processes and port not in {80, 443, 8080, 8443}:
            score += 15
            
        # Cap at 100
        return min(score, 100)
    
    def _get_severity_label(self, score):
        """Convert numeric severity to text label"""
        if score >= 90:
            return "Critical"
        elif score >= 70:
            return "High"
        elif score >= 40:
            return "Medium"
        else:
            return "Low"
    
    def _get_severity_reasons(self, ip, port, process, interval, std_dev):
        """Get human-readable reasons for the severity score"""
        reasons = []
        
        if ip in self.malicious_ips or self.feed.is_malicious_ip(ip):
            reasons.append("IP address is in known malicious list or threat feed")
        elif self._is_ip_in_malicious_ranges(ip):
            reasons.append("IP address is in known malicious range")

        if self.feed.is_blocked_country(ip):
            reasons.append("Remote IP is in a user-blocked country")
            
        if port in self.known_c2_ports or self.feed.is_c2_port(port):
            reasons.append(f"Port {port} is commonly used for C2 communications")
            
        consistency_ratio = std_dev / interval if interval > 0 else 1
        if consistency_ratio < 0.1:
            reasons.append("Connection timing is highly consistent")
            
        unusual_processes = {
            'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe', 
            'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'certutil.exe'
        }
        if process.lower() in unusual_processes:
            reasons.append(f"{process} is unusual for making regular network connections")
            
        if 50 <= interval <= 300:
            reasons.append(f"Beaconing interval ({interval:.1f}s) is typical for C2 traffic")
            
        browser_processes = {'chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe'}
        if process.lower() in browser_processes and port not in {80, 443, 8080, 8443}:
            reasons.append(f"Browser process connecting to non-standard port {port}")
            
        return reasons
    
    def start_monitoring(self, duration=None):
        """Start monitoring network connections"""
        self.logger.info("Starting C2 detection monitoring")
        start_time = time.time()
        
        try:
            while duration is None or time.time() - start_time < duration:
                self._capture_connections()
                time.sleep(5)
                
                # Analyze periodically
                if time.time() % 60 < 5:
                    self._analyze_beaconing()
                    
        except KeyboardInterrupt:
            self.logger.info("C2 monitoring stopped by user")
        except Exception as e:
            self.logger.error(f"Error in C2 monitoring: {e}")
    
    def _capture_connections(self):
        """Capture current network connections"""
        try:
            connections = psutil.net_connections(kind='inet')
            current_time = time.time()
            
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    local_port = conn.laddr.port
                    pid = conn.pid
                    
                    # Get process name
                    process_name = "Unknown"
                    if pid:
                        try:
                            process_name = psutil.Process(pid).name()
                        except:
                            pass
                    
                    connection_id = f"{remote_ip}:{remote_port}:{local_port}:{process_name}:{pid or 0}"
                    self.connection_history[connection_id].append(current_time)
                    
                    # Check if this is a known domain
                    try:
                        domain = socket.gethostbyaddr(remote_ip)[0]
                        self._analyze_domain(domain)
                    except:
                        pass
        except Exception as e:
            self.logger.error(f"Error capturing connections: {e}")
    
    def _analyze_domain(self, domain):
        """Analyze a domain for DGA characteristics"""
        self.domain_history.append(domain)
        
        # Check domain entropy (randomness)
        entropy = self._calculate_entropy(domain)
        
        # Check for unusual TLDs
        unusual_tld = self._check_unusual_tld(domain)
        
        # Check for consonant clusters
        consonant_clusters = self._check_consonant_clusters(domain)
        
        # Calculate overall score
        score = 0
        if entropy > self.entropy_threshold:
            score += 0.4
        if unusual_tld:
            score += 0.3
        if consonant_clusters:
            score += 0.3
        
        if score >= 0.7:
            self.logger.warning(f"Potential DGA domain detected: {domain} (score: {score:.2f})")
            return True, score
        return False, score
    
    def _calculate_entropy(self, text):
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0
        entropy = 0
        text = text.lower()
        char_count = {}
        for char in text:
            char_count[char] = char_count.get(char, 0) + 1
        length = len(text)
        
        for count in char_count.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _check_unusual_tld(self, domain):
        """Check if domain has an unusual TLD"""
        common_tlds = {'.com', '.org', '.net', '.edu', '.gov', '.co', '.io', '.info'}
        parts = domain.lower().split('.')
        if len(parts) > 1:
            tld = '.' + parts[-1]
            return tld not in common_tlds
        return False
    
    def _check_consonant_clusters(self, domain):
        """Check for unusual consonant clusters"""
        domain = domain.lower().split('.')[0]  # Remove TLD
        consonants = 'bcdfghjklmnpqrstvwxyz'
        
        # Count consonant sequences
        max_consonant_seq = 0
        current_seq = 0
        
        for char in domain:
            if char in consonants:
                current_seq += 1
                max_consonant_seq = max(max_consonant_seq, current_seq)
            else:
                current_seq = 0
        
        return max_consonant_seq >= 4  # 4+ consonants in a row is unusual
    
    def _monitor_processes(self):
        """Monitor processes for suspicious behavior"""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username']):
                try:
                    pid = proc.info['pid']
                    process = psutil.Process(pid)
                    
                    # Skip system processes
                    if process.username() in ['NT AUTHORITY\\SYSTEM', 'root']:
                        continue
                    
                    # Check for suspicious process behavior
                    # 1. Hidden processes (rare)
                    # 2. Processes with network connections but low CPU
                    # 3. Processes with unusual file access patterns
                    
                    # This is a simplified check - real implementation would be more complex
                    cpu_percent = process.cpu_percent(interval=0.1)
                    connections = process.connections()
                    
                    if cpu_percent < 0.5 and len(connections) > 0:
                        # Process has network activity but very low CPU - potential backdoor
                        self.logger.warning(f"Suspicious process: {proc.info['name']} (PID: {pid}) - "
                                           f"Low CPU ({cpu_percent}%) with network activity")
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            self.logger.error(f"Error monitoring processes: {e}")
    
    def _analyze_process_behavior(self):
        """Analyze process behavior for C2 indicators"""
        # This would be a more complex implementation in a real system
        pass
    
    def get_report(self):
        """Get a report of all suspicious activity"""
        return {
            "suspicious_connections": self.suspicious_connections,
            "suspicious_processes": self.suspicious_processes,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }