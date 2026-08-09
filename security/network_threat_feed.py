"""Network threat feed helper.

Provides lookups for:
- Known malicious individual IPs and IP ranges
- Known C2 / attacker ports
- Geo-IP country using the free ip-api.com endpoint
- Blocked country codes (configured by the user)

All external calls are best-effort and fail gracefully when offline.
"""

import ipaddress
import json
import logging
import os
import time
from collections import defaultdict

import requests

logger = logging.getLogger("NetworkThreatFeed")


class NetworkThreatFeed:
    def __init__(self, basedir=None):
        self.basedir = basedir or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.malicious_ips = set()
        self.malicious_ranges = []
        self.c2_ports = {
            4444, 8080, 1080, 6666, 31337, 1337,
            9001, 9030, 5555, 9999, 12345, 23456,
            1337, 31337, 9875, 10101, 1178, 1234,
        }
        self.blocked_countries = set()
        self._geo_cache = {}
        self._geo_cache_ttl = 3600  # 1 hour
        self._load_feeds()

    def _load_feeds(self):
        """Load local threat feeds and port lists."""
        # Malicious individual IPs
        ip_file = os.path.join(self.basedir, "malicious_ips.log")
        try:
            if os.path.exists(ip_file):
                with open(ip_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            try:
                                ipaddress.ip_address(line)
                                self.malicious_ips.add(line)
                            except ValueError:
                                pass
        except Exception as e:
            logger.error(f"Error loading malicious IPs: {e}")

        # Hardcoded demo malicious ranges
        demo_ranges = [
            "185.156.73.0/24",
            "103.101.103.0/24",
            "5.188.206.0/24",
            "185.220.101.0/24",
        ]
        for r in demo_ranges:
            try:
                self.malicious_ranges.append(ipaddress.ip_network(r, strict=False))
            except ValueError:
                logger.warning(f"Invalid demo range: {r}")

        # User configurable C2 ports
        ports_file = os.path.join(self.basedir, "c2_ports.json")
        try:
            if os.path.exists(ports_file):
                with open(ports_file, "r") as f:
                    data = json.load(f)
                    user_ports = data.get("ports", [])
                    if user_ports:
                        self.c2_ports = set(int(p) for p in user_ports)
        except Exception as e:
            logger.error(f"Error loading C2 ports: {e}")

        # Blocked countries
        countries_file = os.path.join(self.basedir, "blocklists", "blocked_countries.txt")
        try:
            if os.path.exists(countries_file):
                with open(countries_file, "r") as f:
                    for line in f:
                        code = line.strip().upper()
                        if code and not code.startswith("#"):
                            self.blocked_countries.add(code)
        except Exception as e:
            logger.error(f"Error loading blocked countries: {e}")

    def is_malicious_ip(self, ip):
        """Check if an IP is a known malicious address or within a malicious range."""
        if ip in self.malicious_ips:
            return True
        try:
            ip_obj = ipaddress.ip_address(ip)
            for ip_range in self.malicious_ranges:
                if ip_obj in ip_range:
                    return True
        except ValueError:
            pass
        return False

    def is_c2_port(self, port):
        """Check if a port is commonly associated with C2 / RAT traffic."""
        return port in self.c2_ports

    def country_for_ip(self, ip, timeout=2):
        """Return the ISO 3166-1 alpha-2 country code for an IP.

        Results are cached to reduce API calls. No API key is required for
        ip-api.com non-commercial use; respect their rate limits.
        """
        if not ip:
            return None

        # Check cache
        now = time.time()
        cached = self._geo_cache.get(ip)
        if cached and now - cached["ts"] < self._geo_cache_ttl:
            return cached["country"]

        try:
            resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=timeout)
            resp.raise_for_status()
            data = resp.json()
            country = data.get("countryCode") or data.get("country")
            if country:
                self._geo_cache[ip] = {"country": country, "ts": now}
            return country
        except Exception as e:
            logger.debug(f"Geo-IP lookup failed for {ip}: {e}")
            return None

    def is_blocked_country(self, ip):
        """Check if the country for an IP is in the user's blocked list."""
        if not self.blocked_countries:
            return False
        country = self.country_for_ip(ip)
        return country in self.blocked_countries

    def get_blocked_countries(self):
        return set(self.blocked_countries)
