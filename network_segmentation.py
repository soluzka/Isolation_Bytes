import os
import logging
import json
from typing import Dict, Set, List
import subprocess
import time
from dataclasses import dataclass
from enum import Enum

class ServiceType(Enum):
    WEB = "web"
    DATABASE = "database"
    FILE = "file"
    NETWORK = "network"
    ADMIN = "admin"
    UNKNOWN = "unknown"

@dataclass
class NetworkSegment:
    name: str
    ip_ranges: List[str]
    allowed_services: Set[ServiceType]
    allowed_ports: Set[int]
    priority: int = 100  # Lower number = higher priority

class NetworkSegmentManager:
    def __init__(self, config_path='network_segments.json'):
        self.config_path = config_path
        self.segments = {}
        self.initialize_segments()
        
    def initialize_segments(self):
        """Initialize network segments from config."""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    config = json.load(f)
                    for name, data in config.items():
                        self.segments[name] = NetworkSegment(
                            name=name,
                            ip_ranges=data.get('ip_ranges', []),
                            allowed_services=set(ServiceType[s] for s in data.get('services', [])),
                            allowed_ports=set(data.get('ports', [])),
                            priority=data.get('priority', 100)
                        )
            else:
                self.create_default_segments()
                self.save_segments()
        except Exception as e:
            logging.error(f"Error initializing segments: {e}")
            self.create_default_segments()
            self.save_segments()
            
    def create_default_segments(self):
        """Create default network segments."""
        self.segments = {
            'trusted': NetworkSegment(
                name='trusted',
                ip_ranges=['192.168.1.0/24'],
                allowed_services={ServiceType.WEB, ServiceType.DATABASE},
                allowed_ports={80, 443, 3306, 5432},
                priority=10
            ),
            'untrusted': NetworkSegment(
                name='untrusted',
                ip_ranges=['10.0.0.0/8'],
                allowed_services={ServiceType.WEB},
                allowed_ports={80, 443},
                priority=50
            ),
            'admin': NetworkSegment(
                name='admin',
                ip_ranges=['192.168.1.100/32'],
                allowed_services={ServiceType.ADMIN},
                allowed_ports={22, 3389},
                priority=1
            )
        }
        
        # Add a default segment for unknown IPs
        self.segments['default'] = NetworkSegment(
            name='default',
            ip_ranges=['0.0.0.0/0'],
            allowed_services={ServiceType.UNKNOWN},
            allowed_ports=set(),
            priority=100
        )
        
    def save_segments(self):
        """Save current segments to config file."""
        config = {
            name: {
                'ip_ranges': segment.ip_ranges,
                'services': [s.value for s in segment.allowed_services],
                'ports': list(segment.allowed_ports),
                'priority': segment.priority
            }
            for name, segment in self.segments.items()
        }
        with open(self.config_path, 'w') as f:
            json.dump(config, f, indent=4)
            
    def get_segment_for_ip(self, ip: str) -> NetworkSegment:
        """Get the segment for a given IP address."""
        for name, segment in sorted(self.segments.items(), key=lambda x: x[1].priority):
            for ip_range in segment.ip_ranges:
                if self.is_ip_in_range(ip, ip_range):
                    return segment
        return None
        
    def is_ip_in_range(self, ip: str, ip_range: str) -> bool:
        """Check if an IP is in a given range."""
        import ipaddress
        try:
            ip_addr = ipaddress.ip_address(ip)
            network = ipaddress.ip_network(ip_range)
            return ip_addr in network
        except ValueError:
            return False
            
    def apply_segment_rules(self, segment: NetworkSegment):
        """Apply firewall rules for a segment."""
        try:
            # Create firewall rules for allowed ports
            for port in segment.allowed_ports:
                subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    'name=f"Segment_{segment.name}_Port_{port}"',
                    'protocol=TCP',
                    'dir=in',
                    'localport=f{port}',
                    'action=allow',
                    'profile=any'
                ], check=True)
                
            # Create rules for allowed services
            for service in segment.allowed_services:
                if service == ServiceType.WEB:
                    self.apply_web_service_rules(segment)
                elif service == ServiceType.DATABASE:
                    self.apply_database_service_rules(segment)
                    
        except subprocess.CalledProcessError as e:
            logging.error(f"Error applying segment rules: {e}")
            
    def apply_web_service_rules(self, segment: NetworkSegment):
        """Apply rules specific to web services."""
        try:
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                'name=f"Segment_{segment.name}_Web_Service"',
                'protocol=TCP',
                'dir=in',
                'localport=80,443',
                'action=allow',
                'profile=any'
            ], check=True)
        except subprocess.CalledProcessError as e:
            logging.error(f"Error applying web service rules: {e}")
            
    def apply_database_service_rules(self, segment: NetworkSegment):
        """Apply rules specific to database services."""
        try:
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                'name=f"Segment_{segment.name}_Database_Service"',
                'protocol=TCP',
                'dir=in',
                'localport=3306,5432',
                'action=allow',
                'profile=any'
            ], check=True)
        except subprocess.CalledProcessError as e:
            logging.error(f"Error applying database service rules: {e}")
            
    def update_segmentation(self, connection_data: Dict):
        """Update segmentation based on connection behavior."""
        current_segment = self.get_segment_for_ip(connection_data['ip'])
        if not current_segment:
            return
            
        # Update segment rules based on behavior
        if connection_data.get('behavior_score', 0) > 0.9:
            self.apply_behavior_based_rules(current_segment, connection_data)
            
    def apply_behavior_based_rules(self, segment: NetworkSegment, connection_data: Dict):
        """Apply rules based on connection behavior."""
        try:
            # Add rate limiting for suspicious behavior
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                'name=f"Behavior_Limit_{segment.name}"',
                'protocol=TCP',
                'dir=in',
                'localport=any',
                'action=block',
                'profile=any',
                'enable=yes',
                'program=any',
                'service=any',
                'description="Rate limit based on behavior"'
            ], check=True)
            
        except subprocess.CalledProcessError as e:
            logging.error(f"Error applying behavior-based rules: {e}")

# Initialize the network segment manager
network_segment_manager = NetworkSegmentManager()
