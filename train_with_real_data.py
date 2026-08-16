import json
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
import joblib
import logging
from typing import Tuple, Dict, Any
from pathlib import Path

from advanced_threat_detector import ThreatDetectionModel

# Set up logging
logging.basicConfig(level=logging.INFO)

class RealDataTrainer:
    def __init__(self, data_dir='data', model_dir='models'):
        self.data_dir = Path(data_dir)
        self.model_dir = Path(model_dir)
        self.detector = ThreatDetectionModel(model_dir=model_dir)
        
    def load_labeled_data(self, threat_type: str) -> Tuple[np.ndarray, np.ndarray]:
        """Load labeled data for a specific threat type."""
        try:
            data_dir = self.data_dir / 'labeled'
            data_files = list(data_dir.glob(f"{threat_type}_*.json"))
            
            if not data_files:
                logging.warning(f"No labeled data found for {threat_type}")
                return None, None
            
            features = []
            labels = []
            
            for file_path in data_files:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    features.append(list(data['features'].values()))
                    labels.append(data['label'])
            
            return np.array(features), np.array(labels)
            
        except Exception as e:
            logging.error(f"Error loading labeled data: {e}")
            return None, None
            
    def create_models(self, threat_type: str):
        """Create multiple models for a given threat type."""
        from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
        from sklearn.svm import SVC
        from xgboost import XGBClassifier
        
        models = {}
        
        # Random Forest
        models[f"{threat_type}_rf"] = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced'
        )
        
        # Gradient Boosting
        models[f"{threat_type}_gb"] = GradientBoostingClassifier(
            n_estimators=100,
            learning_rate=0.1,
            max_depth=5,
            random_state=42
        )
        
        # Support Vector Machine
        models[f"{threat_type}_svm"] = Pipeline([
            ('scaler', StandardScaler()),
            ('svc', SVC(
                C=1.0,
                kernel='rbf',
                gamma='scale',
                probability=True,
                class_weight='balanced',
                random_state=42
            ))
        ])
        
        # XGBoost
        models[f"{threat_type}_xgb"] = XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            objective='binary:logistic',
            use_label_encoder=False,
            eval_metric='logloss',
            random_state=42
        )
        
        return models
    
    def train_model(self, threat_type: str):
        """Train multiple models for a given threat type."""
        try:
            X, y = self.load_labeled_data(threat_type)
            if X is None or y is None:
                logging.error(f"No data available for {threat_type}")
                return False
            
            # Create model directory if it doesn't exist
            (self.model_dir / threat_type).mkdir(parents=True, exist_ok=True)
            
            # Create multiple models
            models = self.create_models(threat_type)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            best_score = 0
            best_model = None
            best_model_name = ""
            
            # Train and evaluate each model
            for model_name, model in models.items():
                try:
                    logging.info(f"Training {model_name}...")
                    
                    # Train the model
                    model.fit(X_train, y_train)
                    
                    # Evaluate
                    y_pred = model.predict(X_test)
                    report = classification_report(y_test, y_pred, zero_division=0, output_dict=True)
                    
                    # Calculate weighted F1 score
                    f1_score = report['weighted avg']['f1-score']
                    logging.info(f"{model_name} F1-score: {f1_score:.4f}")
                    
                    # Save the model if it's the best so far
                    if f1_score > best_score:
                        best_score = f1_score
                        best_model = model
                        best_model_name = model_name
                    
                    # Save all models
                    model_path = self.model_dir / f"{threat_type}" / f"{model_name}.pkl"
                    joblib.dump(model, model_path)
                    
                except Exception as e:
                    logging.error(f"Error training {model_name}: {e}", exc_info=True)
            
            if best_model is not None:
                # Save the best model as the main model
                best_model_path = self.model_dir / f"{threat_type}_model.pkl"
                joblib.dump({
                    'model': best_model,
                    'model_name': best_model_name,
                    'f1_score': best_score
                }, best_model_path)
                
                logging.info(f"Best model for {threat_type}: {best_model_name} with F1-score: {best_score:.4f}")
                return True
            
            return False
            
        except Exception as e:
            logging.error(f"Error training {threat_type} models: {e}", exc_info=True)
            return False
            
    def discover_threat_types(self):
        """Discover all threat types present in data/labeled."""
        data_dir = self.data_dir / 'labeled'
        types = set()
        for p in data_dir.glob('*.json'):
            stem = p.stem
            if '_extra_' in stem:
                continue
            if '_' not in stem:
                continue
            t = stem.rsplit('_', 1)[0]
            types.add(t)
        return sorted(types)

    def train_all_models(self):
        """Train all threat detection models with real data."""
        threat_types = [
            'malware', 'ddos', 'exfiltration', 'lateral_movement', 'phishing',
            'ransomware', 'insider_threat', 'cryptojacking', 'zero_day',
            'credential_stuffing', 'sql_injection', 'xss', 'mitm', 'fileless',
            'supply_chain', 'apt', 'rootkit', 'bootkit', 'spyware', 'adware',
            'backdoor', 'trojan', 'worm', 'keylogger', 'botnet', 'logic_bomb',
            'formjacking', 'crypto_mining', 'dns_tunneling', 'living_off_land',
            'password_spraying', 'watering_hole', 'drive_by_download', 'vishing',
            'smishing', 'social_engineering', 'spear_phishing', 'reverse_shell',
            'memory_scraping', 'process_injection', 'dll_injection', 'shimming',
            'pass_hash', 'golden_ticket', 'silver_ticket', 'domain_fronting',
            'dns_cache_poisoning', 'arp_spoofing', 'session_hijacking',
            'wifi_attack', 'firmware_attack', 'kernel_exploit', 'evil_twin',
            'deauth_attack', 'karma_attack', 'uefi_rootkit', 'bootkit_advanced',
            'kernel_rootkit', 'driver_manipulation',
            # Add new threat types
            'hardware_implant', 'cold_boot_attack', 'row_hammer',
            'side_channel_attack', 'spectre', 'meltdown', 'bluekeep',
            'eternalblue', 'heartbleed', 'zerologon', 'printnightmare',
            'log4shell', 'proxylogon', 'proxyshell', 'follina',
            'dirty_pipe', 'dirty_cow', 'thunderspy', 'plundervolt',
            'microarchitectural_attack', 'voltage_fault_injection',
            'electromagnetic_fault_injection', 'optical_fault_injection',
            'acoustic_attack', 'power_analysis_attack', 'timing_attack',
            'race_condition', 'replay_attack', 'pass_the_ticket',
            'kerberoasting', 'dcshadow', 'dcsync', 'ntds_dumping',
            'forced_authentication', 'usb_rubber_ducky', 'badusb',
            'rubber_ducky_attack', 'poisoned_torrent', 'source_code_backdoor',
            'library_poisoning', 'dependency_confusion',
            # Add new advanced threat types
            'air_gap_attack', 'shack_attack', 'rowhammer_attack', 
            'clkscrew', 'parametric_attack', 'template_attack',
            'micro_probing', 'protocol_downgrade', 'clickjacking',
            'ui_redress', 'tabnabbing', 'cookie_theft',
            'session_fixation', 'http_response_splitting',
            'cache_poisoning', 'web_cache_deception',
            'host_header_attack', 'request_smuggling',
            'deserialization_attack', 'xml_injection',
            'css_injection', 'csv_injection',
            'ldap_injection', 'xpath_injection',
            'command_injection', 'buffer_overflow',
            'integer_overflow', 'format_string',
            'null_pointer_deref', 'use_after_free',
            'double_free', 'heap_spray',
            'return_oriented_programming', 'jump_oriented_programming',
            'sigreturn_programming', 'blind_rop',
            'data_oriented_programming', 'control_flow_hijack',
            'stack_clash', 'stack_pivot',
            'return_to_libc', 'sandbox_escape',
            'vm_escape', 'container_escape',
            'hypervisor_attack', 'smt_attack',
            'microcode_attack', 'bios_attack',
            'ime_attack', 'me_attack',
            'psp_attack', 'sgx_attack',
            'tpm_attack', 'secure_boot_attack'
        ]
        
        for threat_type in threat_types:
            try:
                logging.info(f"Training {threat_type} model with real data...")
                success = self.train_model(threat_type)
                if success:
                    logging.info(f"Successfully trained {threat_type} model")
                else:
                    logging.error(f"Failed to train {threat_type} model")
                    
            except Exception as e:
                logging.error(f"Error in training process: {e}")

if __name__ == "__main__":
    # Initialize trainer
    trainer = RealDataTrainer()
    
    # Train all models with real data
    trainer.train_all_models()
    
    # Verify models were saved
    for threat_type in trainer.discover_threat_types():
        model_path = trainer.model_dir / f"{threat_type}_model.pkl"
        if model_path.exists():
            logging.info(f"Model saved: {model_path}")
        else:
            logging.error(f"Model not saved: {model_path}")
