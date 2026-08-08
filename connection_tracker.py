from typing import Dict, List, Set, Tuple
import time
from collections import defaultdict
import logging

class ConnectionTracker:
    def __init__(self):
        self.active_connections = set()
        self.suspicious_connections = set()
        self.blocked_connections = set()
        self.connection_history = defaultdict(list)
        self.last_cleanup = time.time()
        self.cleanup_interval = 3600  # 1 hour
        
    def add_connection(self, conn_info: dict):
        """Add a new connection to tracking."""
        conn_id = self._generate_connection_id(conn_info)
        self.active_connections.add(conn_id)
        self.connection_history[conn_id].append({
            'timestamp': time.time(),
            'info': conn_info
        })
        self._cleanup_old_connections()
        
    def mark_suspicious(self, conn_info: dict):
        """Mark a connection as suspicious."""
        conn_id = self._generate_connection_id(conn_info)
        self.suspicious_connections.add(conn_id)
        
    def block_connection(self, conn_info: dict):
        """Mark a connection as blocked."""
        conn_id = self._generate_connection_id(conn_info)
        self.blocked_connections.add(conn_id)
        
    def get_stats(self) -> Dict[str, int]:
        """Get current connection statistics."""
        return {
            'total': len(self.active_connections),
            'suspicious': len(self.suspicious_connections),
            'blocked': len(self.blocked_connections)
        }
        
    def _generate_connection_id(self, conn_info: dict) -> str:
        """Generate a unique ID for a connection."""
        parts = [
            conn_info.get('ip', ''),
            str(conn_info.get('port', '')),
            conn_info.get('protocol', ''),
            conn_info.get('process', '')
        ]
        return hashlib.md5(''.join(parts).encode()).hexdigest()
        
    def _cleanup_old_connections(self):
        """Clean up old connection history."""
        current_time = time.time()
        if current_time - self.last_cleanup < self.cleanup_interval:
            return
            
        # Remove connections older than 24 hours
        threshold = current_time - 86400
        for conn_id, history in list(self.connection_history.items()):
            if history[-1]['timestamp'] < threshold:
                del self.connection_history[conn_id]
                if conn_id in self.active_connections:
                    self.active_connections.remove(conn_id)
                    
        self.last_cleanup = current_time

# Initialize the connection tracker
connection_tracker = ConnectionTracker()
