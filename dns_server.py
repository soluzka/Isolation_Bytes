from dnslib import DNSRecord, DNSHeader, DNSQuestion, RR, QTYPE
from dnslib.server import DNSServer, DNSHandler, BaseResolver
import socket
import logging
import random
import os
import json
import threading
import time
from datetime import datetime
from ipaddress import ip_address, ip_network
import dns.resolver
import dns.flags
import dns.rdatatype
from typing import Dict, List, Set, Optional
from collections import defaultdict, deque

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dns_server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('home_dns_server')

class RateLimiter:
    def __init__(self, max_requests=100, time_window=60):
        self.max_requests = max_requests  # Max requests per window
        self.time_window = time_window    # Window in seconds
        self.client_requests = defaultdict(list)
        self.last_cleanup = time.time()
        self.blocked_ips = set()
        self.blocked_until = {}
    
    def cleanup(self):
        """Remove entries older than the time window"""
        now = time.time()
        # Only clean up every 10 seconds to avoid performance impact
        if now - self.last_cleanup < 10:
            return
            
        for ip in list(self.client_requests.keys()):
            # Keep only requests within the time window
            self.client_requests[ip] = [t for t in self.client_requests[ip] 
                                      if now - t < self.time_window]
            # Remove empty entries
            if not self.client_requests[ip]:
                del self.client_requests[ip]
                
        # Unblock IPs whose block time has expired
        for ip in list(self.blocked_until.keys()):
            if now > self.blocked_until[ip]:
                self.blocked_ips.remove(ip)
                del self.blocked_until[ip]
                
        self.last_cleanup = now
    
    def is_allowed(self, client_ip):
        """Check if a client is allowed to make a request"""
        self.cleanup()
        
        # If IP is in blocked list, deny request
        if client_ip in self.blocked_ips:
            return False
            
        now = time.time()
        self.client_requests[client_ip].append(now)
        
        # Block if too many requests
        if len(self.client_requests[client_ip]) > self.max_requests:
            logger.warning(f"Rate limit exceeded for {client_ip}: {len(self.client_requests[client_ip])} requests in {self.time_window}s")
            self.blocked_ips.add(client_ip)
            # Block for 5 minutes
            self.blocked_until[client_ip] = now + 300
            return False
            
        return True

class ReputationChecker:
    def __init__(self):
        self.malicious_domains_file = 'malicious_domains.json'
        self.malicious_domains = set()
        self.load_malicious_domains()
        
        # Schedule background updates every 24 hours
        update_thread = threading.Thread(target=self._periodic_update, daemon=True)
        update_thread.start()
    
    def load_malicious_domains(self):
        """Load malicious domains from file"""
        try:
            if os.path.exists(self.malicious_domains_file):
                with open(self.malicious_domains_file, 'r') as f:
                    data = json.load(f)
                    self.malicious_domains = set(data.get('domains', []))
                    logger.info(f"Loaded {len(self.malicious_domains)} malicious domains")
        except Exception as e:
            logger.error(f"Error loading malicious domains: {e}")
            # Load default domains if file can't be read
            self.malicious_domains = {
                'malicious.example.com',
                'bad.example.com',
                'malware.org',
                'phishing.net'
            }
    
    def _periodic_update(self):
        """Update malicious domains periodically"""
        while True:
            try:
                # In a real implementation, this would fetch from reputation services
                logger.info("Updating malicious domains database")
                # For demo purposes, just reload the file
                self.load_malicious_domains()
            except Exception as e:
                logger.error(f"Error updating malicious domains: {e}")
            # Sleep for 24 hours
            time.sleep(86400)
    
    def is_malicious(self, domain):
        """Check if a domain is in the malicious list"""
        # Remove trailing dot and convert to lowercase
        domain = domain.rstrip('.').lower()
        
        # Check exact match
        if domain in self.malicious_domains:
            return True
            
        # Check parent domains (e.g., if evil.example.com is queried, 
        # check if example.com is malicious)
        parts = domain.split('.')
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            if parent in self.malicious_domains:
                return True
                
        return False

class EnhancedDNSResolver(BaseResolver):
    def __init__(self, network_range="192.168.1.0/24", localhost_only=True):
        # Security configuration
        self.localhost_only = localhost_only  # Only accept localhost connections by default
        self.network_range = ip_network(network_range)
        self.allow_network = not localhost_only  # Whether to allow network connections
        
        # Cache for DNS responses
        self.cache = {}
        self.cache_ttl = 300  # 5 minutes
        self.cache_max_size = 1000
        
        # Domain mappings
        self.local_domains = {
            'local': '127.0.0.1',
            'home.local': '127.0.0.1'
        }
        
        # Security components
        self.rate_limiter = RateLimiter()
        self.reputation_checker = ReputationChecker()
        
        # Query ID tracking for anti-spoofing
        self.query_ids = deque(maxlen=1000)
        
        # Statistics
        self.stats = {
            'total_queries': 0,
            'blocked_queries': 0,
            'cached_responses': 0,
            'rate_limited': 0,
            'start_time': time.time()
        }
        
        # Start cache cleanup thread
        cache_thread = threading.Thread(target=self._cache_cleanup, daemon=True)
        cache_thread.start()
        
        logger.info(f"DNS Server initialized. Network access: {'Disabled (localhost only)' if self.localhost_only else 'Enabled for ' + str(self.network_range)}")
    
    def _cache_cleanup(self):
        """Periodically clean up expired cache entries"""
        while True:
            time.sleep(60)  # Run every minute
            try:
                now = time.time()
                expired_keys = [k for k, v in self.cache.items() if now - v['timestamp'] > v['ttl']]
                for k in expired_keys:
                    del self.cache[k]
                
                # If cache is still too large, remove oldest entries
                if len(self.cache) > self.cache_max_size:
                    sorted_cache = sorted(self.cache.items(), key=lambda x: x[1]['timestamp'])
                    to_remove = len(self.cache) - self.cache_max_size
                    for k, _ in sorted_cache[:to_remove]:
                        del self.cache[k]
            except Exception as e:
                logger.error(f"Error cleaning cache: {e}")
    
    def is_allowed_ip(self, client_ip):
        """Check if client IP is allowed to use this DNS server"""
        # Always allow localhost
        if client_ip == '127.0.0.1':
            return True
            
        # If localhost_only is enabled, only allow 127.0.0.1
        if self.localhost_only:
            return False
            
        # Otherwise check network range
        try:
            return ip_address(client_ip) in self.network_range
        except ValueError:
            return False
    
    def check_security(self, request, handler):
        """Perform security checks on the request"""
        client_ip = handler.client_address[0]
        
        # Check if client IP is allowed
        if not self.is_allowed_ip(client_ip):
            logger.warning(f"Denied DNS request from unauthorized IP: {client_ip}")
            try:
                from network_monitor import block_ip
                block_ip(client_ip, reason="Unauthorized DNS request", port=53)
            except ImportError:
                logger.warning("Network monitor module not available for firewall blocking")
            self.stats['blocked_queries'] += 1
            return False
            
        # Check rate limiting
        if not self.rate_limiter.is_allowed(client_ip):
            logger.warning(f"Rate limit exceeded for client: {client_ip}")
            self.stats['rate_limited'] += 1
            return False
            
        # Track query ID to protect against ID spoofing
        query_id = request.header.id
        if query_id in self.query_ids:
            logger.warning(f"Duplicate query ID detected: {query_id} from {client_ip}, possible spoofing attempt")
            return False
        self.query_ids.append(query_id)
        
        return True

    def resolve(self, request, handler):
        """Resolve DNS queries with enhanced security"""
        self.stats['total_queries'] += 1
        
        # Perform security checks
        if not self.check_security(request, handler):
            return None
            
        # Create reply with same header ID for tracking
        reply = request.reply()
        qname = str(request.q.qname).rstrip('.')
        qtype = request.q.qtype
        
        # Generate cache key based on query name and type
        cache_key = f"{qname}:{qtype}"
        
        # Check cache
        if cache_key in self.cache and time.time() - self.cache['timestamp'] < self.cache['ttl']:
            self.stats['cached_responses'] += 1
            cached_reply = self.cache[cache_key]['reply']
            logger.debug(f"Cache hit for {qname} (type {qtype})")
            return cached_reply
            
        # Check reputation for malicious domains
        if self.reputation_checker.is_malicious(qname):
            logger.info(f"Blocked request for malicious domain: {qname}")
            self.stats['blocked_queries'] += 1
            reply.add_answer(RR(qname, rdata='0.0.0.0'))
            return reply
            
        # Handle local domains
        if qname in self.local_domains:
            logger.debug(f"Local domain request: {qname}")
            reply.add_answer(RR(qname, rdata=self.local_domains[qname]))
            return reply
            
        # For other domains, forward to public DNS servers
        try:
            # Create a new resolver with DNSSEC validation if possible
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '1.1.1.1']  # Google and Cloudflare DNS
            resolver.timeout = 3.0  # 3 second timeout
            resolver.lifetime = 5.0  # 5 second lifetime
            
            # Attempt to get a DNSSEC-validated response when possible
            try:
                resolver.use_dnssec = True
                answer = resolver.resolve(qname, dns.rdatatype.from_text(QTYPE[qtype]))
                dns_response = answer.response
                is_secure = dns_response.flags & dns.flags.AD
                
                if is_secure:
                    logger.debug(f"DNSSEC validated response for {qname}")
            except Exception:
                # Fall back to non-DNSSEC if it fails
                resolver.use_dnssec = False
                answer = resolver.resolve(qname)
                
            # Add all records to the response
            if qtype == QTYPE.A:
                for record in answer:
                    reply.add_answer(RR(qname, rdata=record.address))
            else:
                # Default handling for other record types
                # In a production system, this would handle all DNS record types
                for record in answer:
                    reply.add_answer(RR(qname, rdata=str(record)))
                    
            # Cache the result with TTL from the response
            ttl = min(answer.ttl, self.cache_ttl)  # Use the lesser of response TTL or max cache TTL
            self.cache[cache_key] = {
                'reply': reply,
                'timestamp': time.time(),
                'ttl': ttl
            }
                
            return reply
            
        except dns.resolver.NXDOMAIN:
            # Domain doesn't exist
            logger.debug(f"NXDOMAIN for {qname}")
            return reply  # Empty reply indicates NXDOMAIN
            
        except Exception as e:
            logger.warning(f"Failed to resolve domain: {qname} ({e})")
            logger.info(f"[User Notice] DNS lookup for '{qname}' failed. This is often a temporary issue with your network or DNS server, not a problem with your antivirus software. If this happens frequently, check your network settings or DNS provider.")
            return None

    def get_stats(self):
        """Get DNS server statistics"""
        uptime = time.time() - self.stats['start_time']
        return {
            **self.stats,
            'uptime': uptime,
            'cache_size': len(self.cache),
            'queries_per_second': self.stats['total_queries'] / uptime if uptime > 0 else 0
        }

def start_dns_server(network_range="192.168.1.0/24", allow_network=False, port=53):
    """
    Start the DNS server with enhanced security features
    
    Args:
        network_range: IP range to allow if network access is enabled (e.g., "192.168.1.0/24")
        allow_network: Whether to allow access from the local network (default: False, localhost only)
        port: Port to listen on (default: 53, requires admin/root privileges)
    
    Returns:
        tuple: (server, resolver) - The DNS server and resolver instances
    """
    try:
        # Create resolver
        resolver = EnhancedDNSResolver(
            network_range=network_range,
            localhost_only=not allow_network
        )
        
        # Create DNS server
        server = DNSServer(
            resolver,
            port=port,
            address="0.0.0.0",  # Listen on all interfaces
            tcp=True              # Support both UDP and TCP
        )
        
        # Start server
        logger.info(f"Starting DNS server on port {port}...")
        logger.info(f"Network access: {'Enabled for ' + network_range if allow_network else 'Disabled (localhost only)'}")
        
        # Start in a separate thread to not block
        server_thread = threading.Thread(target=server.start, daemon=True)
        server_thread.start()
        
        return server, resolver
        
    except Exception as e:
        logger.error(f"Error starting DNS server: {str(e)}")
        raise

def stop_dns_server(server):
    """Stop the DNS server"""
    if server:
        try:
            server.stop()
            logger.info("DNS server stopped")
            return True
        except Exception as e:
            logger.error(f"Error stopping DNS server: {str(e)}")
            return False
    return False

# Simple CLI for testing
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Enhanced DNS Server')
    parser.add_argument('--network', action='store_true', help='Allow network access (not just localhost)')
    parser.add_argument('--range', default="192.168.1.0/24", help='Network range to allow (default: 192.168.1.0/24)')
    parser.add_argument('--port', type=int, default=53, help='Port to listen on (default: 53)')
    
    args = parser.parse_args()
    
    print(f"Starting DNS server on port {args.port}")
    print(f"Network access: {'Enabled for ' + args.range if args.network else 'Disabled (localhost only)'}")
    
    try:
        server, resolver = start_dns_server(args.range, args.network, args.port)
        
        # Keep the main thread running
        while True:
            time.sleep(60)
            stats = resolver.get_stats()
            print(f"DNS Server stats: {stats['total_queries']} queries, {stats['blocked_queries']} blocked")
            
    except KeyboardInterrupt:
        print("Stopping DNS server...")
        stop_dns_server(server)
        print("Server stopped")

# Export key functions
__all__ = ['start_dns_server', 'stop_dns_server']
