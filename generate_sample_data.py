import os
import json
import numpy as np
from pathlib import Path

def generate_malware_data(num_samples=100):
    """Generate sample malware detection data."""
    data = []
    for _ in range(num_samples):
        is_malicious = np.random.random() > 0.5
        data.append({
            'features': {
                'file_size': int(np.random.uniform(1000, 10000000)),
                'entropy': np.random.uniform(4.0, 8.0),
                'imports': np.random.randint(5, 100),
                'sections': np.random.randint(1, 10),
                'has_certificate': int(np.random.random() > 0.7),
                'packed': int(is_malicious and np.random.random() > 0.3),
                'writes_to_system': int(is_malicious and np.random.random() > 0.5),
                'network_connections': np.random.randint(0, 10) if is_malicious else np.random.randint(0, 2),
                'registry_changes': np.random.randint(0, 8) if is_malicious else np.random.randint(0, 2),
                'process_creations': np.random.randint(0, 5) if is_malicious else np.random.randint(0, 1)
            },
            'label': 1 if is_malicious else 0
        })
    return data

def generate_ddos_data(num_samples=100):
    """Generate sample DDoS detection data."""
    data = []
    for _ in range(num_samples):
        is_ddos = np.random.random() > 0.5
        data.append({
            'features': {
                'packet_count': int(np.random.uniform(1000, 20000) * (10 if is_ddos else 1)),
                'packet_size_var': np.random.uniform(100, 1500) * (5 if is_ddos else 1),
                'unique_ports': np.random.randint(1, 5),
                'unique_ips': np.random.randint(10, 1000) * (100 if is_ddos else 1),
                'packet_rate': np.random.uniform(50, 1000) * (10 if is_ddos else 1),
                'flow_duration': np.random.uniform(1, 60),
                'avg_packet_size': np.random.uniform(100, 1500),
                'payload_entropy': np.random.uniform(4.0, 8.0)
            },
            'label': 1 if is_ddos else 0
        })
    return data

def generate_exfiltration_data(num_samples=100):
    """Generate sample data exfiltration detection data."""
    data = []
    for _ in range(num_samples):
        is_exfil = np.random.random() > 0.5
        data_volume = np.random.uniform(1, 1000) * (100 if is_exfil else 1)
        
        data.append({
            'features': {
                'data_volume': data_volume,
                'data_entropy': np.random.uniform(6.0, 8.0) if is_exfil else np.random.uniform(2.0, 5.0),
                'unique_destinations': np.random.randint(1, 10) * (5 if is_exfil else 1),
                'transfer_speed': np.random.uniform(0.1, 100) * (10 if is_exfil else 1),
                'file_types': np.random.randint(1, 5) * (3 if is_exfil else 1),
                'time_of_day': np.random.uniform(0, 24),
                'data_compression': np.random.uniform(0.1, 1.0),
                'protocols_used': np.random.randint(1, 4)
            },
            'label': 1 if is_exfil else 0
        })
    return data

def generate_lateral_movement_data(num_samples=100):
    """Generate sample lateral movement detection data."""
    data = []
    for _ in range(num_samples):
        is_lateral = np.random.random() > 0.5
        
        data.append({
            'features': {
                'auth_attempts': np.random.randint(1, 10) * (5 if is_lateral else 1),
                'unique_systems': np.random.randint(1, 10) * (3 if is_lateral else 1),
                'failed_logins': np.random.randint(0, 5) * (4 if is_lateral else 1),
                'privilege_escalation': int(is_lateral and np.random.random() > 0.7),
                'service_creation': int(is_lateral and np.random.random() > 0.6),
                'scheduled_tasks': int(is_lateral and np.random.random() > 0.5),
                'remote_execution': int(is_lateral and np.random.random() > 0.4),
                'lateral_movement_score': np.random.uniform(0.7, 1.0) if is_lateral else np.random.uniform(0.0, 0.3)
            },
            'label': 1 if is_lateral else 0
        })
    return data

def generate_phishing_data(num_samples=100):
    """Generate sample phishing detection data."""
    data = []
    for _ in range(num_samples):
        is_phish = np.random.random() > 0.5
        
        data.append({
            'features': {
                'url_length': np.random.randint(10, 200) * (2 if is_phish else 1),
                'num_dots': np.random.randint(1, 5) * (3 if is_phish else 1),
                'has_ip': int(is_phish and np.random.random() > 0.7),
                'special_chars': np.random.randint(1, 10) * (4 if is_phish else 1),
                'redirects': int(is_phish and np.random.random() > 0.6),
                'sensitive_keywords': int(is_phish and np.random.random() > 0.5),
                'ssl_verified': int(not is_phish or np.random.random() > 0.3),
                'domain_age_days': np.random.randint(1, 3650)  # 0-10 years
            },
            'label': 1 if is_phish else 0
        })
    return data

def generate_ransomware_data(num_samples=100):
    """Generate sample ransomware detection data."""
    data = []
    for _ in range(num_samples):
        is_ransomware = np.random.random() > 0.5
        
        data.append({
            'features': {
                'file_encryption_rate': np.random.uniform(0, 100) * (100 if is_ransomware else 1),
                'file_deletion_rate': np.random.uniform(0, 50) * (10 if is_ransomware else 1),
                'registry_changes': np.random.randint(0, 20) * (5 if is_ransomware else 1),
                'network_connections': np.random.randint(0, 10) * (3 if is_ransomware else 1),
                'process_creation': np.random.randint(0, 5) * (2 if is_ransomware else 1),
                'ransom_note_detected': int(is_ransomware and np.random.random() > 0.7),
                'crypto_operations': int(is_ransomware and np.random.random() > 0.6),
                'entropy_level': np.random.uniform(0, 1) * (2 if is_ransomware else 1)
            },
            'label': 1 if is_ransomware else 0
        })
    return data

def generate_insider_threat_data(num_samples=100):
    """Generate sample insider threat detection data."""
    data = []
    for _ in range(num_samples):
        is_threat = np.random.random() > 0.5
        
        data.append({
            'features': {
                'after_hours_access': int(is_threat and np.random.random() > 0.6),
                'data_access_rate': np.random.uniform(0, 100) * (3 if is_threat else 1),
                'sensitive_files_accessed': np.random.randint(0, 20) * (5 if is_threat else 1),
                'failed_auth_attempts': np.random.randint(0, 5) * (4 if is_threat else 1),
                'external_device_use': int(is_threat and np.random.random() > 0.5),
                'unusual_downloads': int(is_threat and np.random.random() > 0.6),
                'privilege_escalation': int(is_threat and np.random.random() > 0.4),
                'access_pattern_score': np.random.uniform(0, 1) * (2 if is_threat else 1)
            },
            'label': 1 if is_threat else 0
        })
    return data

def generate_cryptojacking_data(num_samples=100):
    """Generate sample cryptojacking detection data."""
    data = []
    for _ in range(num_samples):
        is_cryptojacking = np.random.random() > 0.5
        
        data.append({
            'features': {
                'cpu_usage': np.random.uniform(0, 100) * (2 if is_cryptojacking else 1),
                'gpu_usage': np.random.uniform(0, 100) * (3 if is_cryptojacking else 1),
                'mining_pool_connections': int(is_cryptojacking and np.random.random() > 0.7),
                'crypto_mining_api_calls': np.random.randint(0, 20) * (5 if is_cryptojacking else 1),
                'power_consumption': np.random.uniform(0, 100) * (2 if is_cryptojacking else 1),
                'suspicious_processes': np.random.randint(0, 5) * (3 if is_cryptojacking else 1),
                'network_connections': np.random.randint(0, 10) * (2 if is_cryptojacking else 1),
                'mining_signature_detected': int(is_cryptojacking and np.random.random() > 0.6)
            },
            'label': 1 if is_cryptojacking else 0
        })
    return data

def generate_zero_day_data(num_samples=100):
    """Generate sample zero-day exploit detection data."""
    data = []
    for _ in range(num_samples):
        is_zero_day = np.random.random() > 0.5
        
        data.append({
            'features': {
                'unusual_process_behavior': int(is_zero_day and np.random.random() > 0.7),
                'memory_corruption': int(is_zero_day and np.random.random() > 0.6),
                'code_injection': int(is_zero_day and np.random.random() > 0.5),
                'unusual_api_calls': np.random.randint(0, 20) * (4 if is_zero_day else 1),
                'anomaly_score': np.random.uniform(0, 1) * (3 if is_zero_day else 1),
                'suspicious_network_activity': int(is_zero_day and np.random.random() > 0.6),
                'process_hollowing': int(is_zero_day and np.random.random() > 0.5),
                'behavior_anomaly': np.random.uniform(0, 1) * (2 if is_zero_day else 1)
            },
            'label': 1 if is_zero_day else 0
        })
    return data

def generate_credential_stuffing_data(num_samples=100):
    """Generate sample credential stuffing detection data."""
    data = []
    for _ in range(num_samples):
        is_cred_stuffing = np.random.random() > 0.5
        
        data.append({
            'features': {
                'login_attempts': np.random.randint(1, 100) * (10 if is_cred_stuffing else 1),
                'failed_attempts': np.random.randint(0, 100) * (5 if is_cred_stuffing else 1),
                'unique_user_agents': np.random.randint(1, 10) * (3 if is_cred_stuffing else 1),
                'ip_reputation': np.random.uniform(0, 1) * (0.3 if is_cred_stuffing else 0.8),
                'request_rate': np.random.uniform(1, 100) * (20 if is_cred_stuffing else 1),
                'account_lockouts': np.random.randint(0, 5) * (3 if is_cred_stuffing else 1),
                'password_entropy': np.random.uniform(0, 1) * (0.5 if is_cred_stuffing else 0.9),
                'known_breach_emails': int(is_cred_stuffing and np.random.random() > 0.6)
            },
            'label': 1 if is_cred_stuffing else 0
        })
    return data

def generate_sql_injection_data(num_samples=100):
    """Generate sample SQL injection detection data."""
    data = []
    for _ in range(num_samples):
        is_sqli = np.random.random() > 0.5
        
        data.append({
            'features': {
                'query_length': np.random.randint(10, 1000) * (5 if is_sqli else 1),
                'special_chars': np.random.randint(1, 50) * (10 if is_sqli else 1),
                'sql_keywords': np.random.randint(0, 10) * (5 if is_sqli else 1),
                'error_messages': int(is_sqli and np.random.random() > 0.6),
                'unusual_encoding': int(is_sqli and np.random.random() > 0.5),
                'request_size': np.random.randint(100, 10000) * (3 if is_sqli else 1),
                'parameter_manipulation': int(is_sqli and np.random.random() > 0.7),
                'query_structure_score': np.random.uniform(0, 1) * (0.8 if is_sqli else 0.2)
            },
            'label': 1 if is_sqli else 0
        })
    return data

def generate_xss_data(num_samples=100):
    """Generate sample XSS detection data."""
    data = []
    for _ in range(num_samples):
        is_xss = np.random.random() > 0.5
        
        data.append({
            'features': {
                'script_tags': int(is_xss and np.random.random() > 0.6),
                'event_handlers': int(is_xss and np.random.random() > 0.5),
                'javascript_uri': int(is_xss and np.random.random() > 0.7),
                'obfuscation': int(is_xss and np.random.random() > 0.5),
                'dom_manipulation': int(is_xss and np.random.random() > 0.6),
                'suspicious_attributes': np.random.randint(0, 10) * (3 if is_xss else 1),
                'html_entities': np.random.randint(0, 20) * (4 if is_xss else 1),
                'xss_pattern_score': np.random.uniform(0, 1) * (2 if is_xss else 0.5)
            },
            'label': 1 if is_xss else 0
        })
    return data

def generate_mitm_data(num_samples=100):
    """Generate sample MITM attack detection data."""
    data = []
    for _ in range(num_samples):
        is_mitm = np.random.random() > 0.5
        
        data.append({
            'features': {
                'certificate_mismatch': int(is_mitm and np.random.random() > 0.7),
                'ssl_stripping': int(is_mitm and np.random.random() > 0.6),
                'arp_spoofing': int(is_mitm and np.random.random() > 0.5),
                'dns_spoofing': int(is_mitm and np.random.random() > 0.6),
                'unencrypted_traffic': int(is_mitm and np.random.random() > 0.5),
                'session_hijacking': int(is_mitm and np.random.random() > 0.4),
                'protocol_anomalies': np.random.randint(0, 5) * (3 if is_mitm else 1),
                'traffic_redirection': int(is_mitm and np.random.random() > 0.5)
            },
            'label': 1 if is_mitm else 0
        })
    return data

def generate_fileless_data(num_samples=100):
    """Generate sample fileless malware detection data."""
    data = []
    for _ in range(num_samples):
        is_fileless = np.random.random() > 0.5
        
        data.append({
            'features': {
                'memory_execution': int(is_fileless and np.random.random() > 0.7),
                'powershell_usage': int(is_fileless and np.random.random() > 0.6),
                'wmi_usage': int(is_fileless and np.random.random() > 0.5),
                'registry_persistence': int(is_fileless and np.random.random() > 0.4),
                'process_hollowing': int(is_fileless and np.random.random() > 0.5),
                'reflective_dll_loading': int(is_fileless and np.random.random() > 0.6),
                'script_based_execution': int(is_fileless and np.random.random() > 0.5),
                'behavioral_anomaly': np.random.uniform(0, 1) * (2 if is_fileless else 0.5)
            },
            'label': 1 if is_fileless else 0
        })
    return data

def generate_supply_chain_data(num_samples=100):
    """Generate sample supply chain attack detection data."""
    data = []
    for _ in range(num_samples):
        is_supply_chain = np.random.random() > 0.5
        
        data.append({
            'features': {
                'unusual_dependencies': int(is_supply_chain and np.random.random() > 0.7),
                'version_anomaly': int(is_supply_chain and np.random.random() > 0.6),
                'unsigned_components': int(is_supply_chain and np.random.random() > 0.5),
                'suspicious_network_connections': np.random.randint(0, 10) * (3 if is_supply_chain else 1),
                'unusual_process_creation': int(is_supply_chain and np.random.random() > 0.6),
                'code_obfuscation': int(is_supply_chain and np.random.random() > 0.5),
                'reputation_score': np.random.uniform(0, 1) * (0.4 if is_supply_chain else 0.9),
                'behavioral_deviation': np.random.uniform(0, 1) * (2 if is_supply_chain else 0.5)
            },
            'label': 1 if is_supply_chain else 0
        })
    return data

def generate_apt_data(num_samples=100):
    """Generate sample APT detection data."""
    data = []
    for _ in range(num_samples):
        is_apt = np.random.random() > 0.5
        data.append({
            'features': {
                'persistence_mechanisms': np.random.randint(0, 5) * (3 if is_apt else 1),
                'c2_communication': int(is_apt and np.random.random() > 0.6),
                'data_staging': int(is_apt and np.random.random() > 0.7),
                'evasion_techniques': np.random.randint(0, 5) * (2 if is_apt else 1),
                'credential_access': int(is_apt and np.random.random() > 0.5),
                'lateral_movement_attempts': np.random.randint(0, 10) * (3 if is_apt else 1),
                'privilege_escalation': int(is_apt and np.random.random() > 0.6),
                'exfiltration_indicators': int(is_apt and np.random.random() > 0.7)
            },
            'label': 1 if is_apt else 0
        })
    return data

def generate_rootkit_data(num_samples=100):
    """Generate sample rootkit detection data."""
    data = []
    for _ in range(num_samples):
        is_rootkit = np.random.random() > 0.5
        data.append({
            'features': {
                'hidden_processes': int(is_rootkit and np.random.random() > 0.6),
                'kernel_modification': int(is_rootkit and np.random.random() > 0.7),
                'syscall_hooking': int(is_rootkit and np.random.random() > 0.5),
                'device_driver_manipulation': int(is_rootkit and np.random.random() > 0.6),
                'file_hiding': int(is_rootkit and np.random.random() > 0.7),
                'registry_stealth': int(is_rootkit and np.random.random() > 0.6),
                'network_hiding': int(is_rootkit and np.random.random() > 0.5),
                'anti_detection': np.random.uniform(0, 1) * (2 if is_rootkit else 0.5)
            },
            'label': 1 if is_rootkit else 0
        })
    return data

def generate_spyware_data(num_samples=100):
    """Generate sample spyware detection data."""
    data = []
    for _ in range(num_samples):
        is_spyware = np.random.random() > 0.5
        data.append({
            'features': {
                'keylogging_activity': int(is_spyware and np.random.random() > 0.6),
                'screen_capture': int(is_spyware and np.random.random() > 0.7),
                'clipboard_monitoring': int(is_spyware and np.random.random() > 0.5),
                'browser_monitoring': int(is_spyware and np.random.random() > 0.6),
                'data_exfiltration': np.random.uniform(0, 100) * (5 if is_spyware else 1),
                'process_monitoring': int(is_spyware and np.random.random() > 0.5),
                'input_capturing': int(is_spyware and np.random.random() > 0.6),
                'stealth_mechanisms': np.random.uniform(0, 1) * (2 if is_spyware else 0.5)
            },
            'label': 1 if is_spyware else 0
        })
    return data

def generate_backdoor_data(num_samples=100):
    """Generate sample backdoor detection data."""
    data = []
    for _ in range(num_samples):
        is_backdoor = np.random.random() > 0.5
        data.append({
            'features': {
                'unauthorized_ports': int(is_backdoor and np.random.random() > 0.6),
                'hidden_services': int(is_backdoor and np.random.random() > 0.7),
                'reverse_shell': int(is_backdoor and np.random.random() > 0.5),
                'persistence_mechanism': int(is_backdoor and np.random.random() > 0.6),
                'c2_communication': np.random.randint(0, 10) * (3 if is_backdoor else 1),
                'suspicious_listening': int(is_backdoor and np.random.random() > 0.5),
                'abnormal_connections': np.random.randint(0, 5) * (4 if is_backdoor else 1),
                'stealth_score': np.random.uniform(0, 1) * (2 if is_backdoor else 0.5)
            },
            'label': 1 if is_backdoor else 0
        })
    return data

def generate_shimming_data(num_samples=100):
    """Generate sample shimming attack detection data."""
    data = []
    for _ in range(num_samples):
        is_shimming = np.random.random() > 0.5
        data.append({
            'features': {
                'dll_injection_attempts': int(is_shimming and np.random.random() > 0.6),
                'registry_modifications': int(is_shimming and np.random.random() > 0.7),
                'api_hooking': int(is_shimming and np.random.random() > 0.5),
                'sdb_files_created': int(is_shimming and np.random.random() > 0.6),
                'custom_shim_databases': int(is_shimming and np.random.random() > 0.7),
                'application_compatibility': int(is_shimming and np.random.random() > 0.6),
                'process_tampering': np.random.randint(0, 5) * (3 if is_shimming else 1),
                'persistence_mechanisms': np.random.randint(0, 3) * (2 if is_shimming else 1)
            },
            'label': 1 if is_shimming else 0
        })
    return data

def generate_golden_silver_ticket_data(num_samples=100):
    """Generate sample Golden/Silver Ticket attack detection data."""
    data = []
    for _ in range(num_samples):
        is_ticket_attack = np.random.random() > 0.5
        is_golden = np.random.random() > 0.5  # Determines if Golden (True) or Silver (False) ticket
        
        data.append({
            'features': {
                'kerberos_ticket_lifetime': np.random.randint(1, 365) * (10 if is_ticket_attack else 1),
                'ticket_encryption_type': int(is_ticket_attack and np.random.random() > 0.6),
                'privileged_group_membership': int(is_ticket_attack and is_golden),
                'ticket_usage_count': np.random.randint(1, 100) * (5 if is_ticket_attack else 1),
                'service_access_pattern': np.random.uniform(0, 1) * (2 if is_ticket_attack else 1),
                'ticket_signature_valid': int(not is_ticket_attack or np.random.random() > 0.8),
                'domain_admin_access': int(is_ticket_attack and is_golden and np.random.random() > 0.7),
                'unusual_service_tickets': np.random.randint(0, 10) * (3 if is_ticket_attack else 1)
            },
            'label': 1 if is_ticket_attack else 0
        })
    return data

def generate_social_engineering_data(num_samples=100):
    """Generate sample social engineering attack detection data."""
    data = []
    for _ in range(num_samples):
        is_social_engineering = np.random.random() > 0.5
        attack_type = np.random.choice(['vishing', 'smishing', 'spear_phishing'])
        
        data.append({
            'features': {
                'urgency_indicators': int(is_social_engineering and np.random.random() > 0.6),
                'impersonation_attempt': int(is_social_engineering and np.random.random() > 0.7),
                'credential_request': int(is_social_engineering and np.random.random() > 0.5),
                'unusual_sender_pattern': int(is_social_engineering and np.random.random() > 0.6),
                'social_pressure_score': np.random.uniform(0, 1) * (2 if is_social_engineering else 0.5),
                'targeted_attack': int(is_social_engineering and np.random.random() > 0.7),
                'message_similarity': np.random.uniform(0, 1) * (0.8 if is_social_engineering else 0.2),
                'attack_sophistication': np.random.uniform(0, 1) * (2 if is_social_engineering else 0.5)
            },
            'label': 1 if is_social_engineering else 0
        })
    return data

def save_data(data, threat_type, output_dir):
    """Save generated data to JSON files."""
    output_dir = Path(output_dir) / 'labeled'
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Clear existing files for this threat type
    for f in output_dir.glob(f"{threat_type}_*.json"):
        try:
            f.unlink()
        except Exception as e:
            print(f"Warning: Could not delete {f}: {e}")
    
    # Save new data
    for i, item in enumerate(data):
        filename = output_dir / f"{threat_type}_{i}.json"
        with open(filename, 'w') as f:
            json.dump(item, f, indent=2)

def generate_process_injection_data(num_samples=100):
    """Generate sample process injection detection data."""
    data = []
    for _ in range(num_samples):
        is_injection = np.random.random() > 0.5
        data.append({
            'features': {
                'virtual_alloc_calls': np.random.randint(0, 10) * (3 if is_injection else 1),
                'write_process_memory': int(is_injection and np.random.random() > 0.6),
                'create_remote_thread': int(is_injection and np.random.random() > 0.7),
                'memory_protection_changes': np.random.randint(0, 5) * (2 if is_injection else 1),
                'parent_child_violation': int(is_injection and np.random.random() > 0.5),
                'suspicious_loaded_dlls': np.random.randint(0, 5) * (3 if is_injection else 1),
                'memory_mapped_files': int(is_injection and np.random.random() > 0.6),
                'hollowing_indicators': np.random.uniform(0, 1) * (2 if is_injection else 0.5)
            },
            'label': 1 if is_injection else 0
        })
    return data

def generate_dns_attacks_data(num_samples=100):
    """Generate sample DNS-based attack detection data."""
    data = []
    for _ in range(num_samples):
        is_dns_attack = np.random.random() > 0.5
        attack_subtype = np.random.choice(['tunneling', 'poisoning', 'amplification'])
        
        data.append({
            'features': {
                'query_entropy': np.random.uniform(0, 8) * (2 if is_dns_attack else 1),
                'query_length': np.random.randint(10, 255) * (3 if is_dns_attack else 1),
                'subdomain_depth': np.random.randint(1, 10) * (2 if is_dns_attack else 1),
                'txt_record_usage': int(is_dns_attack and np.random.random() > 0.6),
                'request_frequency': np.random.uniform(0, 100) * (5 if is_dns_attack else 1),
                'unique_query_patterns': np.random.randint(1, 20) * (3 if is_dns_attack else 1),
                'cache_violation_attempts': int(is_dns_attack and attack_subtype == 'poisoning'),
                'response_manipulation': int(is_dns_attack and np.random.random() > 0.7)
            },
            'label': 1 if is_dns_attack else 0
        })
    return data

def generate_wifi_attack_data(num_samples=100):
    """Generate sample WiFi attack detection data."""
    data = []
    for _ in range(num_samples):
        is_wifi_attack = np.random.random() > 0.5
        attack_type = np.random.choice(['evil_twin', 'deauth', 'karma'])
        
        data.append({
            'features': {
                'rogue_ap_detected': int(is_wifi_attack and attack_type == 'evil_twin'),
                'deauth_packets': np.random.randint(0, 1000) * (10 if is_wifi_attack else 1),
                'beacon_spam': int(is_wifi_attack and np.random.random() > 0.6),
                'client_probes': np.random.randint(0, 100) * (5 if is_wifi_attack else 1),
                'channel_switching': int(is_wifi_attack and np.random.random() > 0.7),
                'signal_strength_variation': np.random.uniform(0, 30) * (2 if is_wifi_attack else 1),
                'encryption_downgrade': int(is_wifi_attack and np.random.random() > 0.5),
                'suspicious_management_frames': np.random.randint(0, 50) * (4 if is_wifi_attack else 1)
            },
            'label': 1 if is_wifi_attack else 0
        })
    return data

def generate_firmware_attack_data(num_samples=100):
    """Generate sample firmware/UEFI attack detection data."""
    data = []
    for _ in range(num_samples):
        is_firmware_attack = np.random.random() > 0.5
        
        data.append({
            'features': {
                'firmware_modification': int(is_firmware_attack and np.random.random() > 0.7),
                'secure_boot_violation': int(is_firmware_attack and np.random.random() > 0.6),
                'spi_flash_writes': np.random.randint(0, 10) * (3 if is_firmware_attack else 1),
                'smm_violations': int(is_firmware_attack and np.random.random() > 0.5),
                'bootloader_integrity': int(not is_firmware_attack or np.random.random() > 0.8),
                'acpi_table_modifications': int(is_firmware_attack and np.random.random() > 0.6),
                'dxe_driver_loading': int(is_firmware_attack and np.random.random() > 0.7),
                'tpm_measurements': np.random.uniform(0, 1) * (0.5 if is_firmware_attack else 1)
            },
            'label': 1 if is_firmware_attack else 0
        })
    return data

def generate_kernel_exploit_data(num_samples=100):
    """Generate sample kernel exploit detection data."""
    data = []
    for _ in range(num_samples):
        is_kernel_exploit = np.random.random() > 0.5
        
        data.append({
            'features': {
                'syscall_hooking': int(is_kernel_exploit and np.random.random() > 0.6),
                'idt_modification': int(is_kernel_exploit and np.random.random() > 0.7),
                'kernel_memory_access': np.random.randint(0, 100) * (5 if is_kernel_exploit else 1),
                'privilege_escalation': int(is_kernel_exploit and np.random.random() > 0.5),
                'driver_loading': int(is_kernel_exploit and np.random.random() > 0.6),
                'page_table_modification': int(is_kernel_exploit and np.random.random() > 0.7),
                'interrupt_handling': np.random.randint(0, 20) * (3 if is_kernel_exploit else 1),
                'suspicious_kernel_calls': np.random.uniform(0, 1) * (2 if is_kernel_exploit else 0.5)
            },
            'label': 1 if is_kernel_exploit else 0
        })
    return data

def generate_hardware_attack_data(num_samples=100):
    """Generate sample hardware-based attack detection data."""
    data = []
    for _ in range(num_samples):
        is_hardware_attack = np.random.random() > 0.5
        attack_type = np.random.choice(['implant', 'cold_boot', 'row_hammer'])
        
        data.append({
            'features': {
                'memory_access_pattern': np.random.randint(0, 1000) * (5 if is_hardware_attack else 1),
                'power_fluctuation': np.random.uniform(0, 1) * (3 if is_hardware_attack else 1),
                'temperature_anomaly': np.random.uniform(0, 30) * (2 if is_hardware_attack else 1),
                'bus_activity': np.random.randint(0, 100) * (4 if is_hardware_attack else 1),
                'dma_operations': int(is_hardware_attack and np.random.random() > 0.6),
                'memory_errors': np.random.randint(0, 50) * (10 if attack_type == 'row_hammer' else 1),
                'firmware_integrity': int(not is_hardware_attack or np.random.random() > 0.7),
                'hardware_interrupts': np.random.randint(0, 1000) * (3 if is_hardware_attack else 1)
            },
            'label': 1 if is_hardware_attack else 0
        })
    return data

def generate_side_channel_data(num_samples=100):
    """Generate sample side-channel attack detection data."""
    data = []
    for _ in range(num_samples):
        is_side_channel = np.random.random() > 0.5
        attack_type = np.random.choice(['spectre', 'meltdown', 'timing'])
        
        data.append({
            'features': {
                'cache_misses': np.random.randint(0, 10000) * (5 if is_side_channel else 1),
                'branch_mispredictions': np.random.randint(0, 1000) * (4 if attack_type in ['spectre', 'meltdown'] else 1),
                'execution_time_variance': np.random.uniform(0, 100) * (3 if is_side_channel else 1),
                'memory_access_timing': np.random.uniform(0, 50) * (4 if is_side_channel else 1),
                'cpu_utilization_pattern': np.random.uniform(0, 100) * (2 if is_side_channel else 1),
                'speculative_execution': int(is_side_channel and attack_type in ['spectre', 'meltdown']),
                'cache_flush_operations': np.random.randint(0, 500) * (3 if is_side_channel else 1),
                'power_consumption_pattern': np.random.uniform(0, 1) * (2 if is_side_channel else 1)
            },
            'label': 1 if is_side_channel else 0
        })
    return data

def generate_exploit_data(num_samples=100):
    """Generate sample known exploit detection data."""
    data = []
    for _ in range(num_samples):
        is_exploit = np.random.random() > 0.5
        exploit_type = np.random.choice(['bluekeep', 'eternalblue', 'zerologon', 'log4shell'])
        
        data.append({
            'features': {
                'vulnerable_service_running': int(is_exploit and np.random.random() > 0.6),
                'exploit_pattern_match': int(is_exploit and np.random.random() > 0.7),
                'payload_signature': int(is_exploit and np.random.random() > 0.5),
                'network_scan_detected': int(is_exploit and np.random.random() > 0.6),
                'suspicious_connections': np.random.randint(0, 50) * (4 if is_exploit else 1),
                'system_calls_pattern': np.random.randint(0, 100) * (3 if is_exploit else 1),
                'privilege_elevation': int(is_exploit and np.random.random() > 0.7),
                'vulnerability_score': np.random.uniform(0, 1) * (3 if is_exploit else 0.5)
            },
            'label': 1 if is_exploit else 0
        })
    return data

def generate_fault_injection_data(num_samples=100):
    """Generate sample fault injection attack detection data."""
    data = []
    for _ in range(num_samples):
        is_fault_injection = np.random.random() > 0.5
        attack_type = np.random.choice(['voltage', 'electromagnetic', 'optical'])
        
        data.append({
            'features': {
                'power_glitch_detected': int(is_fault_injection and attack_type == 'voltage'),
                'em_interference': int(is_fault_injection and attack_type == 'electromagnetic'),
                'light_sensor_anomaly': int(is_fault_injection and attack_type == 'optical'),
                'execution_errors': np.random.randint(0, 100) * (5 if is_fault_injection else 1),
                'clock_instability': np.random.uniform(0, 1) * (3 if is_fault_injection else 1),
                'computation_failures': np.random.randint(0, 50) * (4 if is_fault_injection else 1),
                'sensor_readings_anomaly': np.random.uniform(0, 1) * (2 if is_fault_injection else 1),
                'hardware_error_rate': np.random.uniform(0, 1) * (3 if is_fault_injection else 1)
            },
            'label': 1 if is_fault_injection else 0
        })
    return data

def generate_authentication_attack_data(num_samples=100):
    """Generate sample authentication attack detection data."""
    data = []
    for _ in range(num_samples):
        is_auth_attack = np.random.random() > 0.5
        attack_type = np.random.choice(['pass_the_ticket', 'kerberoasting', 'dcsync'])
        
        data.append({
            'features': {
                'ticket_manipulation': int(is_auth_attack and attack_type == 'pass_the_ticket'),
                'service_ticket_requests': np.random.randint(0, 100) * (5 if attack_type == 'kerberoasting' else 1),
                'directory_replication': int(is_auth_attack and attack_type == 'dcsync'),
                'privileged_account_usage': int(is_auth_attack and np.random.random() > 0.6),
                'authentication_errors': np.random.randint(0, 50) * (3 if is_auth_attack else 1),
                'ticket_encryption_downgrade': int(is_auth_attack and np.random.random() > 0.7),
                'replication_requests': np.random.randint(0, 20) * (4 if is_auth_attack else 1),
                'credential_extraction_attempt': int(is_auth_attack and np.random.random() > 0.5)
            },
            'label': 1 if is_auth_attack else 0
        })
    return data

def generate_supply_chain_attack_data(num_samples=100):
    """Generate sample supply chain attack detection data."""
    data = []
    for _ in range(num_samples):
        is_supply_chain = np.random.random() > 0.5
        attack_type = np.random.choice(['poisoned_torrent', 'source_backdoor', 'dependency_confusion'])
        
        data.append({
            'features': {
                'package_integrity': int(not is_supply_chain or np.random.random() > 0.7),
                'version_anomaly': int(is_supply_chain and attack_type == 'dependency_confusion'),
                'signature_mismatch': int(is_supply_chain and np.random.random() > 0.6),
                'unusual_dependencies': int(is_supply_chain and np.random.random() > 0.5),
                'code_changes_volume': np.random.randint(0, 1000) * (3 if is_supply_chain else 1),
                'network_callbacks': np.random.randint(0, 50) * (4 if is_supply_chain else 1),
                'build_process_tampering': int(is_supply_chain and np.random.random() > 0.7),
                'repository_anomalies': int(is_supply_chain and np.random.random() > 0.6)
            },
            'label': 1 if is_supply_chain else 0
        })
    return data

def generate_advanced_memory_attack_data(num_samples=100):
    """Generate sample advanced memory attack detection data."""
    data = []
    for _ in range(num_samples):
        is_attack = np.random.random() > 0.5
        attack_type = np.random.choice(['buffer_overflow', 'use_after_free', 'double_free', 'heap_spray'])
        
        data.append({
            'features': {
                'memory_corruption': int(is_attack and np.random.random() > 0.6),
                'heap_manipulation': np.random.randint(0, 100) * (5 if is_attack else 1),
                'stack_manipulation': np.random.randint(0, 100) * (4 if is_attack else 1),
                'invalid_pointers': int(is_attack and attack_type in ['use_after_free', 'double_free']),
                'memory_allocation_pattern': np.random.randint(0, 1000) * (3 if attack_type == 'heap_spray' else 1),
                'execution_flow_anomaly': int(is_attack and np.random.random() > 0.7),
                'crash_likelihood': np.random.uniform(0, 1) * (3 if is_attack else 0.5),
                'exploit_guard_triggers': int(is_attack and np.random.random() > 0.6)
            },
            'label': 1 if is_attack else 0
        })
    return data

def generate_advanced_web_attack_data(num_samples=100):
    """Generate sample advanced web attack detection data."""
    data = []
    for _ in range(num_samples):
        is_attack = np.random.random() > 0.5
        attack_type = np.random.choice(['clickjacking', 'cache_poisoning', 'request_smuggling'])
        
        data.append({
            'features': {
                'frame_manipulation': int(is_attack and attack_type == 'clickjacking'),
                'cache_inconsistency': int(is_attack and attack_type == 'cache_poisoning'),
                'http_desync': int(is_attack and attack_type == 'request_smuggling'),
                'header_manipulation': np.random.randint(0, 50) * (4 if is_attack else 1),
                'response_tampering': int(is_attack and np.random.random() > 0.6),
                'request_anomalies': np.random.randint(0, 100) * (3 if is_attack else 1),
                'security_header_bypass': int(is_attack and np.random.random() > 0.7),
                'attack_sophistication': np.random.uniform(0, 1) * (2 if is_attack else 0.5)
            },
            'label': 1 if is_attack else 0
        })
    return data

def generate_code_reuse_attack_data(num_samples=100):
    """Generate sample code reuse attack detection data."""
    data = []
    for _ in range(num_samples):
        is_attack = np.random.random() > 0.5
        attack_type = np.random.choice(['rop', 'jop', 'blind_rop', 'srop', 'stack_pivot'])
        
        data.append({
            'features': {
                'gadget_chain_detected': int(is_attack and np.random.random() > 0.6),
                'stack_manipulation': int(is_attack and np.random.random() > 0.7),
                'return_address_override': int(is_attack and attack_type == 'rop'),
                'jump_table_abuse': int(is_attack and attack_type == 'jop'),
                'sigreturn_frame': int(is_attack and attack_type == 'srop'),
                'stack_pivot_attempt': int(is_attack and attack_type == 'stack_pivot'),
                'control_flow_integrity': np.random.uniform(0, 1) * (0.3 if is_attack else 0.9),
                'gadget_execution_pattern': np.random.randint(0, 100) * (5 if is_attack else 1)
            },
            'label': 1 if is_attack else 0
        })
    return data

def generate_virtualization_attack_data(num_samples=100):
    """Generate sample virtualization-based attack detection data."""
    data = []
    for _ in range(num_samples):
        is_attack = np.random.random() > 0.5
        attack_type = np.random.choice(['sandbox_escape', 'vm_escape', 'container_escape', 'hypervisor'])
        
        data.append({
            'features': {
                'isolation_breach': int(is_attack and np.random.random() > 0.6),
                'privilege_escalation': int(is_attack and np.random.random() > 0.7),
                'hypervisor_interaction': np.random.randint(0, 100) * (5 if attack_type == 'hypervisor' else 1),
                'resource_access_violation': int(is_attack and np.random.random() > 0.5),
                'container_breakout': int(is_attack and attack_type == 'container_escape'),
                'vm_boundary_violation': int(is_attack and attack_type == 'vm_escape'),
                'sandbox_integrity': np.random.uniform(0, 1) * (0.3 if is_attack else 0.9),
                'suspicious_syscalls': np.random.randint(0, 1000) * (4 if is_attack else 1)
            },
            'label': 1 if is_attack else 0
        })
    return data

def generate_hardware_security_attack_data(num_samples=100):
    """Generate sample hardware security feature attack detection data."""
    data = []
    for _ in range(num_samples):
        is_attack = np.random.random() > 0.5
        attack_type = np.random.choice(['microcode', 'bios', 'ime', 'me', 'psp', 'sgx', 'tpm', 'secure_boot'])
        
        data.append({
            'features': {
                'firmware_integrity': int(not is_attack or np.random.random() > 0.8),
                'secure_boot_state': int(not is_attack or np.random.random() > 0.7),
                'tpm_measurements': np.random.uniform(0, 1) * (0.3 if attack_type == 'tpm' else 1),
                'microcode_version': int(not is_attack or np.random.random() > 0.6),
                'sgx_enclave_violation': int(is_attack and attack_type == 'sgx'),
                'me_state_anomaly': int(is_attack and attack_type in ['ime', 'me']),
                'psp_integrity': int(not is_attack or attack_type != 'psp'),
                'privileged_operation': np.random.randint(0, 100) * (5 if is_attack else 1)
            },
            'label': 1 if is_attack else 0
        })
    return data

def generate_air_gap_attack_data(num_samples=100):
    """Generate sample air gap attack detection data."""
    data = []
    for _ in range(num_samples):
        is_attack = np.random.random() > 0.5
        attack_type = np.random.choice(['acoustic', 'electromagnetic', 'thermal', 'optical'])
        
        data.append({
            'features': {
                'covert_channel_detected': int(is_attack and np.random.random() > 0.6),
                'unusual_emissions': int(is_attack and np.random.random() > 0.7),
                'signal_strength': np.random.uniform(0, 100) * (5 if is_attack else 1),
                'transmission_frequency': np.random.uniform(0, 1000) * (3 if is_attack else 1),
                'data_modulation': int(is_attack and np.random.random() > 0.5),
                'sensor_readings': np.random.randint(0, 1000) * (4 if is_attack else 1),
                'channel_bandwidth': np.random.uniform(0, 50) * (3 if is_attack else 1),
                'ambient_noise': np.random.uniform(0, 1) * (2 if attack_type in ['acoustic', 'electromagnetic'] else 1)
            },
            'label': 1 if is_attack else 0
        })
    return data

def generate_shack_attack_data(num_samples=100):
    """Generate sample software-defined hardware attack detection data."""
    data = []
    for _ in range(num_samples):
        is_attack = np.random.random() > 0.5
        attack_type = np.random.choice(['frequency_manipulation', 'voltage_glitch', 'timing_violation'])
        
        data.append({
            'features': {
                'clock_manipulation': int(is_attack and attack_type == 'frequency_manipulation'),
                'voltage_fluctuation': np.random.uniform(0, 2) * (3 if is_attack else 1),
                'timing_violations': np.random.randint(0, 100) * (5 if is_attack else 1),
                'power_consumption': np.random.uniform(0, 100) * (2 if is_attack else 1),
                'hardware_errors': np.random.randint(0, 50) * (4 if is_attack else 1),
                'performance_degradation': np.random.uniform(0, 1) * (3 if is_attack else 1),
                'temperature_anomaly': np.random.uniform(0, 30) * (2 if is_attack else 1),
                'fault_injection': int(is_attack and np.random.random() > 0.6)
            },
            'label': 1 if is_attack else 0
        })
    return data

def main():
    data_dir = Path("data")
    num_samples = 200  # Number of samples per threat type
    
    # Updated threat generators dictionary
    threat_generators = {
        'malware': generate_malware_data,
        'ddos': generate_ddos_data,
        'exfiltration': generate_exfiltration_data,
        'lateral_movement': generate_lateral_movement_data,
        'phishing': generate_phishing_data,
        'ransomware': generate_ransomware_data,
        'insider_threat': generate_insider_threat_data,
        'cryptojacking': generate_cryptojacking_data,
        'zero_day': generate_zero_day_data,
        'credential_stuffing': generate_credential_stuffing_data,
        'sql_injection': generate_sql_injection_data,
        'xss': generate_xss_data,
        'mitm': generate_mitm_data,
        'fileless': generate_fileless_data,
        'supply_chain': generate_supply_chain_data,
        'apt': generate_apt_data,
        'rootkit': generate_rootkit_data,
        'bootkit': generate_rootkit_data,  # Similar to rootkit
        'spyware': generate_spyware_data,  # Use dedicated spyware generator
        'adware': generate_malware_data,   # Can reuse malware generator
        'backdoor': generate_backdoor_data, # Use dedicated backdoor generator
        'trojan': generate_malware_data,   # Can reuse malware generator
        'worm': generate_malware_data,     # Can reuse malware generator
        'keylogger': generate_spyware_data,
        'botnet': generate_ddos_data,      # Can reuse DDoS generator
        'logic_bomb': generate_malware_data,
        'formjacking': generate_xss_data,  # Similar to XSS
        'crypto_mining': generate_cryptojacking_data,
        'dns_tunneling': generate_exfiltration_data,
        'living_off_land': generate_fileless_data,
        'password_spraying': generate_credential_stuffing_data,
        'watering_hole': generate_supply_chain_data,
        'drive_by_download': generate_malware_data,
        'vishing': generate_phishing_data,
        'smishing': generate_phishing_data,
        'spear_phishing': generate_phishing_data,
        'reverse_shell': generate_backdoor_data,
        'memory_scraping': generate_fileless_data,
        'process_injection': generate_fileless_data,
        'dll_injection': generate_fileless_data,
        'shimming': generate_shimming_data,
        'pass_hash': generate_credential_stuffing_data,
        'golden_ticket': generate_golden_silver_ticket_data,
        'silver_ticket': generate_golden_silver_ticket_data,
        'domain_fronting': generate_exfiltration_data,
        'dns_cache_poisoning': generate_mitm_data,
        'arp_spoofing': generate_mitm_data,
        'session_hijacking': generate_mitm_data,
        'process_injection': generate_process_injection_data,
        'dll_injection': generate_process_injection_data,  # Similar to process injection
        'dns_tunneling': generate_dns_attacks_data,
        'dns_cache_poisoning': generate_dns_attacks_data,
        'wifi_attack': generate_wifi_attack_data,
        'firmware_attack': generate_firmware_attack_data,
        'kernel_exploit': generate_kernel_exploit_data,
        'evil_twin': generate_wifi_attack_data,
        'deauth_attack': generate_wifi_attack_data,
        'karma_attack': generate_wifi_attack_data,
        'uefi_rootkit': generate_firmware_attack_data,
        'bootkit_advanced': generate_firmware_attack_data,
        'kernel_rootkit': generate_kernel_exploit_data,
        'driver_manipulation': generate_kernel_exploit_data,
        
        # Add new advanced threat types
        # Add advanced web attacks
        'clickjacking': generate_advanced_web_attack_data,
        'ui_redress': generate_advanced_web_attack_data,
        'tabnabbing': generate_advanced_web_attack_data,
        'cookie_theft': generate_advanced_web_attack_data,
        'session_fixation': generate_advanced_web_attack_data,
        'http_response_splitting': generate_advanced_web_attack_data,
        'cache_poisoning': generate_advanced_web_attack_data,
        'web_cache_deception': generate_advanced_web_attack_data,
        'host_header_attack': generate_advanced_web_attack_data,
        'request_smuggling': generate_advanced_web_attack_data,
        'deserialization_attack': generate_advanced_web_attack_data,
        'protocol_downgrade': generate_advanced_web_attack_data,
        
        # Add injection attacks
        'xml_injection': generate_advanced_web_attack_data,
        'css_injection': generate_advanced_web_attack_data,
        'csv_injection': generate_advanced_web_attack_data,
        'ldap_injection': generate_advanced_web_attack_data,
        'xpath_injection': generate_advanced_web_attack_data,
        'command_injection': generate_advanced_web_attack_data,
        
        # Add memory corruption attacks
        'buffer_overflow': generate_advanced_memory_attack_data,
        'integer_overflow': generate_advanced_memory_attack_data,
        'format_string': generate_advanced_memory_attack_data,
        'null_pointer_deref': generate_advanced_memory_attack_data,
        'use_after_free': generate_advanced_memory_attack_data,
        'double_free': generate_advanced_memory_attack_data,
        'heap_spray': generate_advanced_memory_attack_data,
        
        # Add code reuse and ROP attacks
        'return_oriented_programming': generate_code_reuse_attack_data,
        'jump_oriented_programming': generate_code_reuse_attack_data,
        'sigreturn_programming': generate_code_reuse_attack_data,
        'blind_rop': generate_code_reuse_attack_data,
        'data_oriented_programming': generate_code_reuse_attack_data,
        'control_flow_hijack': generate_code_reuse_attack_data,
        'stack_clash': generate_code_reuse_attack_data,
        'stack_pivot': generate_code_reuse_attack_data,
        'return_to_libc': generate_code_reuse_attack_data,
        
        # Add isolation and virtualization attacks  
        'sandbox_escape': generate_virtualization_attack_data,
        'vm_escape': generate_virtualization_attack_data,
        'container_escape': generate_virtualization_attack_data,
        'hypervisor_attack': generate_virtualization_attack_data,
        'smt_attack': generate_virtualization_attack_data,
        
        # Add hardware security attacks
        'microcode_attack': generate_hardware_security_attack_data,
        'bios_attack': generate_hardware_security_attack_data,
        'ime_attack': generate_hardware_security_attack_data,
        'me_attack': generate_hardware_security_attack_data,
        'psp_attack': generate_hardware_security_attack_data,
        'sgx_attack': generate_hardware_security_attack_data,
        'tpm_attack': generate_hardware_security_attack_data,
        'secure_boot_attack': generate_hardware_security_attack_data,
        
        # Add timing and physical attacks
        'air_gap_attack': generate_air_gap_attack_data,
        'shack_attack': generate_air_gap_attack_data,
        'rowhammer_attack': generate_hardware_attack_data,
        'clkscrew': generate_hardware_attack_data,
        'parametric_attack': generate_hardware_attack_data,
        'template_attack': generate_side_channel_data,
        'micro_probing': generate_hardware_attack_data,
    }
    
    # Ensure data directory exists
    data_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate and save sample data for each threat type
    stats = {}
    for threat_type, generator in threat_generators.items():
        try:
            print(f"Generating {threat_type.replace('_', ' ')} data...")
            data = generator(num_samples)
            save_data(data, threat_type, data_dir)
            stats[threat_type] = len(data)
        except Exception as e:
            print(f"Error generating {threat_type} data: {e}")
            stats[threat_type] = 0
    
    # Print summary
    print(f"\nSample data generated in {data_dir.absolute()}/labeled/")
    for threat_type, count in stats.items():
        print(f"- {threat_type.replace('_', ' ').title()}: {count} samples")

if __name__ == "__main__":
    main()
