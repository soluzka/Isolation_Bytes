from utils.paths import get_resource_path
import os

import threading
import time
import os
import json
from datetime import datetime

ALERTS_FILE = os.path.join(os.path.dirname(__file__), 'phishing_alerts.json')

_alerts_lock = threading.Lock()

def load_alerts():
    if not os.path.exists(ALERTS_FILE):
        return []
    with open(get_resource_path(os.path.join(ALERTS_FILE)), 'r', encoding='utf-8') as f:
        try:
            return json.load(f)
        except Exception:
            return []

def save_alert(alert):
    with _alerts_lock:
        alerts = load_alerts()
        if isinstance(alert, tuple) and len(alert) >= 2:  # Ensure tuple has enough elements
            alerts.insert(0, alert)
        elif isinstance(alert, dict):  # Handle dictionary alerts
            alerts.insert(0, alert)
        with open(get_resource_path(os.path.join(ALERTS_FILE)), 'w', encoding='utf-8') as f:
            json.dump(alerts, f, indent=2)

def get_recent_alerts(limit=50):
    return load_alerts()[:limit]