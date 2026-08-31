"""Training system for the local findings assistant.

Lets the user:
- Give feedback on answers (good/bad) so the assistant learns what works
- Correct false positives so the assistant remembers which files are safe
- Add custom knowledge entries that the assistant references in future answers
- Auto-generate YARA rules from learned threat patterns
- Train the ML model from findings and false positive feedback
- Build a learning history that improves responses over time

All data is stored locally in JSON files — no external AI service needed.
"""
import datetime
import hashlib
import json
import os
import re
from pathlib import Path


class AssistantTrainer:
    """Stores and retrieves training data for the local assistant.

    Also generates YARA rules and trains the ML model from learned data.
    """

    def __init__(self, base_dir=None):
        self.base_dir = Path(base_dir or os.path.dirname(os.path.dirname(__file__)))
        self._data_dir = Path(os.environ.get('ANTIVIRUS_RUNTIME_DIR', str(self.base_dir))) / 'data'
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._yara_rules_dir = self.base_dir / 'security' / 'yara_rules'
        self._yara_rules_dir.mkdir(parents=True, exist_ok=True)
        self._ml_model = None
        # SQLite database for persistent learning
        try:
            from security.assistant_database import AssistantDatabase
            self._db = AssistantDatabase(self.base_dir)
        except Exception:
            self._db = None
        self._seed_base_knowledge()

    def _seed_base_knowledge(self):
        """On first startup, seed the knowledge base with base security info."""
        try:
            existing = self.get_knowledge()
            existing_topics = {k.get('topic', '').lower() for k in existing}
            from security.assistant_base_knowledge import BASE_KNOWLEDGE
            new_entries = 0
            for topic, content in BASE_KNOWLEDGE:
                if topic.lower() not in existing_topics:
                    self.add_knowledge(topic, content)
                    new_entries += 1
            if new_entries > 0:
                self._record_auto_learn('base_knowledge_seeded', {'count': new_entries})
        except Exception:
            pass

    def _get_ml_model(self):
        """Lazily load the ML security model."""
        if self._ml_model is not None:
            return self._ml_model
        try:
            import sys
            sys.path.insert(0, str(self.base_dir))
            from ml_security import SecurityMLModel
            self._ml_model = SecurityMLModel(
                model_path=str(self.base_dir / 'models' / 'malware_model.pkl'),
                pca_path=str(self.base_dir / 'models' / 'malware_pca.pkl'),
                scaler_path=str(self.base_dir / 'models' / 'malware_scaler.pkl'),
            )
            return self._ml_model
        except Exception:
            return None

    @property
    def _training_path(self):
        return self._data_dir / 'assistant_training.json'

    @property
    def _feedback_path(self):
        return self._data_dir / 'assistant_feedback.json'

    @property
    def _false_positive_path(self):
        return self._data_dir / 'assistant_false_positives.json'

    @property
    def _knowledge_path(self):
        return self._data_dir / 'assistant_knowledge.json'

    def _load(self, path, default):
        try:
            return json.loads(Path(path).read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError):
            return default

    def _save(self, path, data):
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix('.json.tmp')
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
        os.replace(tmp, target)

    # --- Feedback on answers ---
    def record_feedback(self, question, answer, rating, comment=''):
        """Record whether an answer was good (1) or bad (-1)."""
        feedback = self._load(self._feedback_path, [])
        entry = {
            'timestamp': datetime.datetime.now().isoformat(timespec='seconds'),
            'question': question[:500],
            'answer': answer[:2000],
            'rating': rating,
            'comment': comment[:500],
        }
        feedback.append(entry)
        feedback = feedback[-500:]
        self._save(self._feedback_path, feedback)
        if self._db:
            self._db.record_feedback(question, answer, rating, comment)
        # Auto-learn from feedback
        self._auto_learn_from_feedback(entry)
        return entry

    def get_feedback_stats(self):
        """Return stats about what answers were good vs bad."""
        feedback = self._load(self._feedback_path, [])
        if not feedback:
            return {'total': 0, 'good': 0, 'bad': 0, 'good_rate': 0}
        good = sum(1 for f in feedback if f.get('rating', 0) > 0)
        bad = sum(1 for f in feedback if f.get('rating', 0) < 0)
        total = len(feedback)
        return {
            'total': total,
            'good': good,
            'bad': bad,
            'good_rate': round(good / total * 100, 1) if total else 0,
        }

    def get_bad_patterns(self):
        """Return question patterns that got bad feedback, so we can avoid them."""
        feedback = self._load(self._feedback_path, [])
        bad = [f for f in feedback if f.get('rating', 0) < 0]
        # Extract keywords from bad questions
        keywords = set()
        for f in bad:
            words = re.findall(r'\b\w{4,}\b', f.get('question', '').lower())
            keywords.update(words[:5])
        return list(keywords)[:50]

    # --- False positive tracking ---
    def mark_false_positive(self, file_path, hash_val='', reason=''):
        """Mark a file as a known false positive so the assistant won't flag it."""
        fps = self._load(self._false_positive_path, [])
        fps = [f for f in fps if f.get('path') != file_path]
        entry = {
            'timestamp': datetime.datetime.now().isoformat(timespec='seconds'),
            'path': file_path,
            'hash': hash_val,
            'reason': reason,
        }
        fps.append(entry)
        fps = fps[-1000:]
        self._save(self._false_positive_path, fps)
        if self._db:
            self._db.mark_false_positive(file_path, hash_val, reason)
        # Train ML model that this is a safe file
        self.train_ml_from_findings([{'path': file_path, 'hash': hash_val, 'risk_score': 0, 'false_positive': True}], is_threat=False)
        return entry

    def unmark_false_positive(self, file_path):
        """Remove a false positive marking."""
        fps = self._load(self._false_positive_path, [])
        fps = [f for f in fps if f.get('path') != file_path]
        self._save(self._false_positive_path, fps)

    def get_false_positives(self):
        """Return all known false positives."""
        return self._load(self._false_positive_path, [])

    def is_false_positive(self, file_path='', hash_val=''):
        """Check if a file or hash is a known false positive."""
        fps = self._load(self._false_positive_path, [])
        for fp in fps:
            if file_path and fp.get('path') == file_path:
                return True
            if hash_val and fp.get('hash') == hash_val:
                return True
        return False

    def filter_findings(self, findings):
        """Remove false positives from a findings list."""
        fps = self._load(self._false_positive_path, [])
        fp_paths = {f.get('path', '').lower() for f in fps if f.get('path')}
        fp_hashes = {f.get('hash', '').lower() for f in fps if f.get('hash')}
        result = []
        for f in findings:
            path = str(f.get('path', f.get('file', ''))).lower()
            h = str(f.get('hash', '')).lower()
            if path in fp_paths or h in fp_hashes:
                f = dict(f)
                f['false_positive'] = True
                f['severity'] = 'safe'
                f['risk_score'] = 0
            result.append(f)
        return result

    # --- Knowledge base ---
    def add_knowledge(self, topic, content):
        """Add a knowledge entry the assistant can reference."""
        knowledge = self._load(self._knowledge_path, [])
        knowledge = [k for k in knowledge if k.get('topic', '').lower() != topic.lower()]
        entry = {
            'timestamp': datetime.datetime.now().isoformat(timespec='seconds'),
            'topic': topic,
            'content': content,
        }
        knowledge.append(entry)
        knowledge = knowledge[-500:]
        self._save(self._knowledge_path, knowledge)
        if self._db:
            self._db.add_knowledge(topic, content, source='manual')
        return entry

    def remove_knowledge(self, topic):
        """Remove a knowledge entry."""
        knowledge = self._load(self._knowledge_path, [])
        knowledge = [k for k in knowledge if k.get('topic', '').lower() != topic.lower()]
        self._save(self._knowledge_path, knowledge)

    def get_knowledge(self):
        """Return all knowledge entries."""
        return self._load(self._knowledge_path, [])

    def search_knowledge(self, question):
        """Find knowledge entries relevant to a question."""
        knowledge = self._load(self._knowledge_path, [])
        if not knowledge:
            return []
        q_lower = question.lower()
        scored = []
        for k in knowledge:
            topic = k.get('topic', '').lower()
            content = k.get('content', '').lower()
            score = 0
            for word in q_lower.split():
                if len(word) < 3:
                    continue
                if word in topic:
                    score += 3
                if word in content:
                    score += 1
            if score > 0:
                scored.append((score, k))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [k for _, k in scored[:5]]

    # --- Training summary ---
    def get_training_summary(self):
        """Return a summary of all training data."""
        yara_count = len(list(self._yara_rules_dir.glob('learned_*.yar'))) if self._yara_rules_dir.exists() else 0
        summary = {
            'feedback': self.get_feedback_stats(),
            'false_positives': len(self.get_false_positives()),
            'knowledge_entries': len(self.get_knowledge()),
            'yara_rules_generated': yara_count,
            'ml_trained': self._load(self._data_dir / 'ml_training_count.json', {'count': 0}).get('count', 0),
        }
        # Add database stats if available
        if self._db:
            db_summary = self._db.get_summary()
            summary['database'] = db_summary
            # Use DB counts if higher (more accurate)
            summary['findings_total'] = db_summary['findings']['total']
            summary['confirmed_threats'] = db_summary['findings']['confirmed_threats']
            summary['malware_signatures'] = db_summary['malware_signatures']
            summary['ml_samples'] = db_summary['ml_samples']
            summary['learning_events'] = db_summary['learning_events']['total_events']
            summary['agent_reports'] = db_summary['agent_reports']['total_reports']
        return summary

    # --- YARA rule generation from learned threats ---
    def generate_yara_rule(self, threat_name, strings, condition='any of them', severity='medium'):
        """Generate a YARA rule file from learned threat patterns.

        Args:
            threat_name: Name for the rule (alphanumeric + underscore)
            strings: List of hex strings, text strings, or byte patterns to match
            condition: YARA condition (default 'any of them')
            severity: Rule severity metadata
        Returns:
            Path to the generated .yar file
        """
        # Sanitize rule name
        rule_name = re.sub(r'[^a-zA-Z0-9_]', '_', threat_name)
        rule_name = f'learned_{rule_name}'

        # Build YARA strings section
        string_lines = []
        for i, s in enumerate(strings):
            s = str(s).strip()
            if not s:
                continue
            # Hex string (starts with 0x or contains {)
            if s.startswith('0x') or re.match(r'^[0-9a-fA-F\s]{6,}$', s):
                hex_val = s.replace('0x', '').replace(' ', '').replace('{', '').replace('}', '')
                string_lines.append(f'    $hex{i} = {{ {hex_val} }}')
            # Regex-like pattern
            elif '/' in s and len(s) > 4:
                string_lines.append(f'    $str{i} = "{s}" nocase')
            # Plain text string
            else:
                escaped = s.replace('"', '\\"').replace('\\', '\\\\')
                string_lines.append(f'    $str{i} = "{escaped}" nocase')

        if not string_lines:
            return None

        # Always require a PE file header check to prevent false positives on
        # text files, scripts, documentation, and other non-executable content.
        # If the caller's condition already includes uint16(0) or $mz, don't
        # add it again.
        pe_check = 'uint16(0) == 0x5A4D'
        if pe_check not in condition and 'uint16(0)' not in condition and '$mz' not in condition:
            full_condition = f'({condition}) and {pe_check}'
        else:
            full_condition = condition

        # Build the rule
        rule_text = f'''/*
    Auto-generated by Assistant Trainer
    Threat: {threat_name}
    Severity: {severity}
    Generated: {datetime.datetime.now().isoformat(timespec='seconds')}
*/

rule {rule_name} : {severity}
{{
    strings:
{chr(10).join(string_lines)}

    condition:
        {full_condition}
}}
'''

        rule_path = self._yara_rules_dir / f'{rule_name}.yar'
        rule_path.write_text(rule_text, encoding='utf-8')
        if self._db:
            self._db.record_yara_rule(rule_name, threat_name, severity, strings, rule_text, str(rule_path), auto_generated=True)
        return str(rule_path)

    def learn_threat(self, threat_name, patterns, severity='medium', description=''):
        """Learn a new threat pattern — generates a YARA rule AND adds knowledge.

        Args:
            threat_name: Name of the threat
            patterns: List of strings/hex patterns/behaviors to detect
            severity: Threat severity (low, medium, high, critical)
            description: Human-readable description
        Returns:
            Dict with results
        """
        results = {'yara_rule': None, 'knowledge': None}

        # Generate YARA rule
        try:
            rule_path = self.generate_yara_rule(threat_name, patterns, severity=severity)
            results['yara_rule'] = rule_path
        except Exception as e:
            results['yara_error'] = str(e)

        # Add to knowledge base
        try:
            content = description or f"Threat pattern: {', '.join(patterns[:5])}. Severity: {severity}."
            self.add_knowledge(f'threat:{threat_name}', content)
            results['knowledge'] = True
        except Exception as e:
            results['knowledge_error'] = str(e)

        return results

    def get_learned_yara_rules(self):
        """Return list of learned YARA rule files."""
        if not self._yara_rules_dir.exists():
            return []
        return [f.name for f in self._yara_rules_dir.glob('learned_*.yar')]

    def delete_learned_yara_rule(self, rule_name):
        """Delete a learned YARA rule."""
        safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', rule_name)
        rule_path = self._yara_rules_dir / f'learned_{safe_name}.yar'
        if rule_path.exists():
            rule_path.unlink()
            return True
        return False

    # --- ML model training ---
    def train_ml_from_findings(self, findings, is_threat=True):
        """Train the ML model from findings data.

        Args:
            findings: List of finding dicts with features (file size, entropy, etc.)
            is_threat: Whether these are threats (True) or safe files (False)
        Returns:
            True if training succeeded
        """
        ml = self._get_ml_model()
        if ml is None:
            return False

        try:
            import numpy as np
            # Extract features from findings
            feature_vectors = []
            for f in findings:
                if not isinstance(f, dict):
                    continue
                # Build feature vector from available data
                features = [
                    len(str(f.get('path', ''))),           # path length
                    f.get('risk_score', 50),               # risk score
                    f.get('file_size', 0),                 # file size
                    len(str(f.get('hash', ''))),           # hash length
                    1 if f.get('severity', '').lower() in ('critical', 'high') else 0,  # high severity
                    1 if f.get('threat_type', '') != 'unknown' else 0,  # classified threat
                    1 if f.get('false_positive') else 0,   # marked as FP
                ]
                feature_vectors.append(features)

            if not feature_vectors:
                return False

            X = np.array(feature_vectors)
            ml.retrain_model(X)
            # Track training count
            count_data = self._load(self._data_dir / 'ml_training_count.json', {'count': 0})
            count_data['count'] = count_data.get('count', 0) + len(feature_vectors)
            self._save(self._data_dir / 'ml_training_count.json', count_data)
            return True
        except Exception:
            return False

    def train_ml_from_feedback(self):
        """Retrain the ML model using accumulated feedback and false positives.

        Positive feedback + non-false-positive findings = threat samples.
        False positives = safe samples.
        Returns True if training succeeded.
        """
        ml = self._get_ml_model()
        if ml is None:
            return False

        try:
            import numpy as np
            fps = self.get_false_positives()

            # Safe samples (false positives)
            safe_vectors = []
            for fp in fps:
                safe_vectors.append([
                    len(fp.get('path', '')),
                    0,  # risk score = 0 (safe)
                    0,  # file size unknown
                    len(fp.get('hash', '')),
                    0,  # not high severity
                    0,  # not a classified threat
                    1,  # is false positive
                ])

            # Threat samples (from feedback where rating was positive on threat answers)
            feedback = self._load(self._feedback_path, [])
            threat_vectors = []
            for fb in feedback:
                if fb.get('rating', 0) > 0 and 'threat' in fb.get('question', '').lower():
                    threat_vectors.append([100, 75, 50000, 32, 1, 1, 0])

            if not safe_vectors and not threat_vectors:
                return False

            all_vectors = safe_vectors + threat_vectors
            X = np.array(all_vectors)
            ml.retrain_model(X)

            count_data = self._load(self._data_dir / 'ml_training_count.json', {'count': 0})
            count_data['count'] = count_data.get('count', 0) + len(all_vectors)
            self._save(self._data_dir / 'ml_training_count.json', count_data)
            return True
        except Exception:
            return False

    # --- AUTO-LEARNING ENGINE ---
    # Learns from every interaction automatically — no explicit training needed.

    @property
    def _auto_learn_path(self):
        return self._data_dir / 'assistant_auto_learn.json'

    def _record_auto_learn(self, event_type, data):
        """Record an auto-learning event."""
        events_log = self._load(self._auto_learn_path, [])
        entry = {
            'timestamp': datetime.datetime.now().isoformat(timespec='seconds'),
            'type': event_type,
            'data': data,
        }
        events_log.append(entry)
        events_log = events_log[-1000:]
        self._save(self._auto_learn_path, events_log)
        if self._db:
            self._db.record_event(event_type, data)

    def auto_learn_from_interaction(self, question, answer, analysis):
        """Automatically learn from every question/answer interaction.

        This runs after every answer the assistant gives. It:
        - Detects when users ask about specific files being safe → auto false positive
        - Detects threat-related questions → strengthens threat knowledge
        - Learns common question patterns for better responses
        - Auto-generates YARA rules from threat patterns in findings
        - Auto-trains ML from findings data
        - Self-reflects on its own answer quality
        """
        q = (question or '').lower().strip()
        learned = []

        # 1. Auto-detect false positive suggestions
        fp_match = re.search(r'(?:is\s+)?([a-z]:\\[^\s]+|/[^\s]+\.\w+)\s+(?:safe|a false positive|legitimate|not malware|ok)', q)
        if fp_match:
            path = fp_match.group(1)
            if not self.is_false_positive(path):
                self._record_auto_learn('false_positive_candidate', {'path': path, 'question': q})
                learned.append(f"Flagged {path} as a potential false positive candidate")

        # 2. Auto-learn threat patterns from findings
        findings = analysis.get('priority_findings') or []
        for f in findings[:5]:
            if not isinstance(f, dict):
                continue
            threat_type = f.get('threat_type', '')
            path = f.get('path', '')
            reason = f.get('reason', '')
            if threat_type and threat_type != 'unknown' and reason:
                rule_name = f'learned_auto_{threat_type}'
                rule_path = self._yara_rules_dir / f'{rule_name}.yar'
                if not rule_path.exists():
                    patterns = self._extract_patterns_from_finding(f)
                    if patterns:
                        try:
                            self.generate_yara_rule(f'auto_{threat_type}', patterns, severity=f.get('severity', 'medium'))
                            self._record_auto_learn('auto_yara_generated', {
                                'threat_type': threat_type,
                                'path': path,
                                'patterns': patterns,
                            })
                            learned.append(f"Auto-generated YARA rule for {threat_type}")
                        except Exception:
                            pass

        # 2b. Auto-improve existing YARA rules with new patterns from findings
        if findings:
            improvements = self.auto_improve_from_findings(findings)
            for imp in improvements:
                learned.append(imp)

        # 3. Auto-train ML from findings if we have enough data
        if findings:
            try:
                self.train_ml_from_findings(findings, is_threat=True)
                self._record_auto_learn('auto_ml_trained', {'sample_count': len(findings)})
                learned.append(f"Trained ML model on {len(findings)} finding(s)")
            except Exception:
                pass

        # 4. Learn question patterns for better responses
        self._record_auto_learn('interaction', {
            'question': question[:200],
            'question_type': self._classify_question(q),
            'had_findings': len(findings) > 0,
            'agent_count': analysis.get('agent_count', 0),
        })

        # 5. Auto-learn knowledge from threat descriptions in findings
        for f in findings[:3]:
            if isinstance(f, dict) and f.get('threat_type') and f.get('threat_type') != 'unknown':
                topic = f"threat:{f['threat_type']}"
                existing = self._load(self._knowledge_path, [])
                if not any(k.get('topic', '').lower() == topic.lower() for k in existing):
                    desc = f.get('reason', f.get('description', ''))
                    if desc:
                        self.add_knowledge(topic, f"Auto-learned: {desc}. Detected on {f.get('path','?')}.")
                        learned.append(f"Learned about {f['threat_type']}")

        # 6. SELF-LEARNING — analyze own answer and learn from it
        self._self_reflect(question, answer, analysis, learned)

        return learned

    def _self_reflect(self, question, answer, analysis, learned):
        """Self-reflection: the assistant analyzes its own answer and learns from it.

        - Detects if it mentioned threat types → reinforces that knowledge
        - Detects if it gave remediation advice → stores it for future use
        - Detects if it referenced specific files/paths → builds path intelligence
        - Detects confidence level → adjusts future response style
        - Extracts new knowledge from its own reasoning
        """
        if not answer:
            return

        answer_lower = answer.lower()

        # Self-learn: extract threat types mentioned in the answer
        threat_keywords = {
            'ransomware': 'ransomware', 'trojan': 'trojan', 'rootkit': 'rootkit',
            'keylogger': 'keylogger', 'spyware': 'spyware', 'backdoor': 'backdoor',
            'cryptominer': 'cryptominer', 'miner': 'cryptominer', 'adware': 'adware',
            'worm': 'worm', 'c2': 'c2_beacon', 'beacon': 'c2_beacon',
        }
        mentioned_threats = set()
        for keyword, threat_type in threat_keywords.items():
            if keyword in answer_lower:
                mentioned_threats.add(threat_type)

        for tt in mentioned_threats:
            topic = f"self_learned:{tt}"
            existing = self._load(self._knowledge_path, [])
            if not any(k.get('topic', '').lower() == topic.lower() for k in existing):
                # Build knowledge from what the assistant said about this threat
                sentences = [s.strip() for s in answer.split('.') if tt in s.lower() or keyword in s.lower()]
                if sentences:
                    self.add_knowledge(topic, f"Self-learned: {' '.join(sentences[:2])}")
                    learned.append(f"Self-learned about {tt} from my own answer")

        # Self-learn: extract file paths mentioned
        paths = re.findall(r'[a-zA-Z]:\\[^\s]+\.\w{2,5}|/[^\s]+\.\w{2,5}', answer)
        for path in paths[:5]:
            path_lower = path.lower()
            # If the assistant mentioned a path in context of a threat, record it
            if any(kw in answer_lower for kw in ('threat', 'malware', 'suspicious', 'infected', 'flagged')):
                self._record_auto_learn('self_identified_threat_path', {'path': path_lower})

        # Self-learn: detect remediation advice and store it
        if any(kw in answer_lower for kw in ('quarantine', 'remove', 'delete', 'clean', 'fix', 'patch', 'isolate')):
            remediation_sentences = [s.strip() for s in answer.split('\n') if any(kw in s.lower() for kw in ('quarantine', 'remove', 'delete', 'clean', 'fix', 'patch', 'isolate', 'step'))]
            if remediation_sentences:
                existing = self._load(self._knowledge_path, [])
                if not any(k.get('topic', '').lower() == 'self_learned:remediation' for k in existing):
                    self.add_knowledge('self_learned:remediation', f"Self-learned remediation: {' '.join(remediation_sentences[:3])}")
                    learned.append("Saved my own remediation advice for future reference")

        # Self-learn: confidence assessment
        confidence_markers = {
            'high': ['definitely', 'certainly', 'confirmed', 'i know', 'i\'m sure', 'clearly'],
            'low': ['might', 'maybe', 'possibly', 'not sure', 'uncertain', 'could be', 'i think'],
            'medium': ['likely', 'probably', 'appears to', 'seems to', 'i\'d say'],
        }
        confidence = 'medium'
        for level, markers in confidence_markers.items():
            if any(m in answer_lower for m in markers):
                confidence = level
                break

        self._record_auto_learn('self_assessment', {
            'question_type': self._classify_question(question.lower()),
            'confidence': confidence,
            'answer_length': len(answer),
            'mentioned_threats': list(mentioned_threats),
            'mentioned_paths': len(paths),
        })

        # Self-improve: if confidence is low, note what info was missing
        if confidence == 'low':
            missing = []
            if not analysis.get('agents'):
                missing.append('agent_data')
            if not analysis.get('priority_findings'):
                missing.append('findings')
            if not analysis.get('scan_history_available'):
                missing.append('scan_history')
            if missing:
                self._record_auto_learn('low_confidence_gap', {
                    'missing_data': missing,
                    'question_type': self._classify_question(question.lower()),
                })

    def _extract_patterns_from_finding(self, finding):
        """Extract detectable patterns from a finding for YARA rule generation."""
        patterns = []
        reason = str(finding.get('reason', ''))
        path = str(finding.get('path', ''))
        threat_type = str(finding.get('threat_type', ''))
        h = str(finding.get('hash', ''))

        # Extract meaningful strings from the reason
        if reason:
            # Pull out quoted strings, rule names, or key phrases
            quoted = re.findall(r"'([^']+)'|\"([^\"]+)\"", reason)
            for q in quoted:
                val = q[0] or q[1]
                if val and len(val) > 3:
                    patterns.append(val)
            # Extract rule match names like "YARA rule matched: xyz"
            rule_match = re.search(r'matched:\s*(\S+)', reason)
            if rule_match:
                patterns.append(rule_match.group(1))
            # Use the threat type as a pattern
            if threat_type and threat_type != 'unknown':
                patterns.append(threat_type)

        # Use file extension as a weak signal — only for executable types
        if path:
            ext = os.path.splitext(path)[1].lower().lstrip('.')
            if ext and ext in ('exe', 'dll', 'sys', 'drv', 'ocx'):
                patterns.append(f'.{ext}')

        # Deduplicate and limit
        seen = set()
        unique = []
        for p in patterns:
            if p.lower() not in seen and len(p) > 2:
                seen.add(p.lower())
                unique.append(p)
        return unique[:6]

    def _classify_question(self, q):
        """Classify a question type for learning patterns."""
        if any(w in q for w in ('report', 'incident', 'summary')):
            return 'report'
        if any(w in q for w in ('threat', 'suspicious', 'malware', 'attack')):
            return 'threats'
        if any(w in q for w in ('agent', 'device', 'host')):
            return 'agents'
        if any(w in q for w in ('ioc', 'hash', 'ip', 'domain')):
            return 'iocs'
        if any(w in q for w in ('fix', 'remediat', 'remove', 'clean')):
            return 'remediation'
        if any(w in q for w in ('false positive', 'safe', 'legitimate')):
            return 'false_positive'
        if any(w in q for w in ('behavior', 'thinking', 'doing')):
            return 'behavior'
        if any(w in q for w in ('hi', 'hello', 'hey')):
            return 'greeting'
        if any(w in q for w in ('train', 'learn', 'teach')):
            return 'training'
        return 'other'

    def _auto_learn_from_feedback(self, entry):
        """Auto-learn from feedback entries."""
        if entry.get('rating', 0) < 0:
            # Bad answer — record what went wrong
            self._record_auto_learn('bad_answer', {
                'question': entry.get('question', '')[:200],
                'answer': entry.get('answer', '')[:200],
            })
        elif entry.get('rating', 0) > 0:
            # Good answer — reinforce
            self._record_auto_learn('good_answer', {
                'question': entry.get('question', '')[:200],
            })

    def get_auto_learn_stats(self):
        """Return stats about auto-learning."""
        events = self._load(self._auto_learn_path, [])
        if not events:
            return {'total_events': 0, 'auto_yara_rules': 0, 'auto_ml_trains': 0, 'false_positive_candidates': 0}
        return {
            'total_events': len(events),
            'auto_yara_rules': sum(1 for e in events if e.get('type') == 'auto_yara_generated'),
            'auto_ml_trains': sum(1 for e in events if e.get('type') == 'auto_ml_trained'),
            'false_positive_candidates': sum(1 for e in events if e.get('type') == 'false_positive_candidate'),
            'good_answers': sum(1 for e in events if e.get('type') == 'good_answer'),
            'bad_answers': sum(1 for e in events if e.get('type') == 'bad_answer'),
        }

    def auto_improve(self):
        """Run periodic auto-improvement — call this on a timer or on startup.

        - Retrains ML from all accumulated data
        - Cleans up stale false positive candidates
        - Promotes high-confidence false positive candidates to real false positives
        """
        improvements = []

        # Promote false positive candidates that appear 3+ times
        events = self._load(self._auto_learn_path, [])
        fp_candidates = [e for e in events if e.get('type') == 'false_positive_candidate']
        fp_counts = {}
        for e in fp_candidates:
            path = e.get('data', {}).get('path', '')
            if path:
                fp_counts[path] = fp_counts.get(path, 0) + 1

        for path, count in fp_counts.items():
            if count >= 3 and not self.is_false_positive(path):
                self.mark_false_positive(path, reason=f'Auto-promoted after {count} mentions')
                improvements.append(f"Auto-marked {path} as false positive (mentioned {count} times)")

        # Retrain ML from all feedback
        if self.train_ml_from_feedback():
            improvements.append("Retrained ML model from accumulated feedback")

        return improvements

    # --- SCORE MANAGEMENT ---
    # Auto-adjust risk scores based on learning history, feedback, and false positives.

    @property
    def _score_adjustments_path(self):
        return self._data_dir / 'assistant_score_adjustments.json'

    def adjust_finding_score(self, finding):
        """Adjust a finding's risk score based on learned data.

        - If the file is a known false positive → score 0
        - If the threat type has been seen many times → boost score
        - If the user gave bad feedback on similar findings → lower score
        - If the user gave good feedback on similar findings → boost score
        - If the ML model predicts it's anomalous → boost score

        Returns the adjusted finding with updated risk_score.
        """
        if not isinstance(finding, dict):
            return finding

        path = str(finding.get('path', '')).lower()
        h = str(finding.get('hash', '')).lower()
        threat_type = str(finding.get('threat_type', 'unknown')).lower()
        original_score = finding.get('risk_score', 50)

        # 1. Known false positive → score 0
        if self.is_false_positive(path, h):
            finding['risk_score'] = 0
            finding['severity'] = 'safe'
            finding['false_positive'] = True
            finding['score_adjusted'] = 'false_positive'
            return finding

        adjustments = self._load(self._score_adjustments_path, {})

        # 2. Threat type frequency — if we've seen this threat type a lot, boost it
        threat_key = f'threat:{threat_type}'
        threat_count = int(adjustments.get(threat_key, {}).get('count', 0))
        if threat_count >= 3:
            boost = min(threat_count * 2, 20)
            original_score = min(original_score + boost, 100)
            finding['score_adjusted'] = f'threat_boost:+{boost}'

        # 3. Path-based adjustments — if this exact path was flagged before and confirmed
        path_key = f'path:{path}'
        path_adj = adjustments.get(path_key, {})
        if path_adj.get('confirmed_threat'):
            original_score = min(original_score + 15, 100)
            finding['score_adjusted'] = 'confirmed_threat_boost:+15'

        # 4. ML model prediction
        ml = self._get_ml_model()
        if ml is not None:
            try:
                import numpy as np
                features = np.array([[
                    len(path),
                    original_score,
                    finding.get('file_size', 0),
                    len(h),
                    1 if finding.get('severity', '').lower() in ('critical', 'high') else 0,
                    1 if threat_type != 'unknown' else 0,
                    0,
                ]])
                pred, score = ml.predict(features)
                if pred is not None and len(pred) > 0:
                    # IsolationForest: -1 = anomaly (threat), 1 = normal
                    if pred[0] == -1:
                        original_score = min(original_score + 10, 100)
                        finding['ml_anomaly'] = True
                        finding['score_adjusted'] = (finding.get('score_adjusted', '') + ' ml_boost:+10').strip()
                    else:
                        original_score = max(original_score - 5, 0)
                        finding['ml_anomaly'] = False
            except Exception:
                pass

        finding['risk_score'] = original_score
        # Update severity based on adjusted score
        if original_score >= 90:
            finding['severity'] = 'critical'
        elif original_score >= 70:
            finding['severity'] = 'high'
        elif original_score >= 40:
            finding['severity'] = 'medium'
        elif original_score > 0:
            finding['severity'] = 'low'

        return finding

    def record_score_adjustment(self, finding, confirmed_threat=False):
        """Record that a finding was confirmed as a real threat or not.

        This feeds back into future score adjustments.
        """
        adjustments = self._load(self._score_adjustments_path, {})
        path = str(finding.get('path', '')).lower()
        threat_type = str(finding.get('threat_type', 'unknown')).lower()

        # Increment threat type count
        threat_key = f'threat:{threat_type}'
        if threat_key not in adjustments:
            adjustments[threat_key] = {'count': 0}
        adjustments[threat_key]['count'] += 1

        # Mark path as confirmed threat
        if confirmed_threat and path:
            path_key = f'path:{path}'
            adjustments[path_key] = {'confirmed_threat': True, 'count': adjustments.get(path_key, {}).get('count', 0) + 1}

        self._save(self._score_adjustments_path, adjustments)

        # Write to database
        if self._db:
            self._db.record_score_adjustment(threat_key, 'threat', confirmed_threat)
            if confirmed_threat and path:
                self._db.record_score_adjustment(f'path:{path}', 'path', True)
            # Record the finding in the database
            self._db.record_finding(finding)
            # Record as a malware signature if it has a hash
            h = str(finding.get('hash', ''))
            if h:
                self._db.record_signature(
                    name=threat_type,
                    hash_val=h,
                    threat_type=threat_type,
                    severity=finding.get('severity', 'medium'),
                    description=finding.get('reason', ''),
                )

    def get_score_stats(self):
        """Return stats about score adjustments."""
        adjustments = self._load(self._score_adjustments_path, {})
        threat_types = {k: v for k, v in adjustments.items() if k.startswith('threat:')}
        confirmed_paths = {k: v for k, v in adjustments.items() if k.startswith('path:')}
        return {
            'threat_type_counts': {k.replace('threat:', ''): v.get('count', 0) for k, v in threat_types.items()},
            'confirmed_threats': len([v for v in confirmed_paths.values() if v.get('confirmed_threat')]),
        }

    # --- MALWARE SCANNING ---
    # Actually scan files using YARA rules and ML model.

    def scan_file(self, filepath):
        """Scan a single file for malware using YARA rules + ML.

        Returns a dict with:
        - 'path': the file path
        - 'threats': list of YARA matches
        - 'risk_score': 0-100
        - 'severity': low/medium/high/critical
        - 'threat_type': classified type
        - 'ml_anomaly': whether ML flagged it
        - 'yara_rules_matched': list of rule names
        """
        result = {
            'path': filepath,
            'threats': [],
            'risk_score': 0,
            'severity': 'safe',
            'threat_type': 'unknown',
            'ml_anomaly': False,
            'yara_rules_matched': [],
            'scanned_at': datetime.datetime.now().isoformat(timespec='seconds'),
        }

        if not os.path.isfile(filepath):
            result['error'] = 'File not found'
            return result

        # Skip non-executable/media files that can't be malware
        ext = os.path.splitext(filepath)[1].lower()
        if ext in {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.mp3', '.mp4',
                   '.avi', '.mkv', '.mov', '.wmv', '.flv', '.wav', '.flac', '.ico',
                   '.txt', '.md', '.json', '.xml', '.csv'}:
            result['severity'] = 'safe'
            return result

        # 1. YARA scan
        try:
            import sys
            sys.path.insert(0, str(self.base_dir))
            from security.yara_scanner import scan_file_with_yara
            matches = scan_file_with_yara(filepath)
            if matches:
                result['yara_rules_matched'] = [m.rule for m in matches]
                result['threats'] = [{'rule': m.rule, 'tags': list(m.tags) if m.tags else []} for m in matches]
                # Base score from number and type of matches
                base_score = min(30 + len(matches) * 15, 90)
                # Check if any learned rules matched
                learned_matches = [m for m in matches if m.rule.startswith('learned_')]
                if learned_matches:
                    base_score = min(base_score + 15, 100)
                    result['threat_type'] = learned_matches[0].rule.replace('learned_auto_', '').replace('learned_', '')
                # Classify threat type from rule names
                if result['threat_type'] == 'unknown':
                    for m in matches:
                        rule_lower = m.rule.lower()
                        if 'ransomware' in rule_lower or 'ransom' in rule_lower:
                            result['threat_type'] = 'ransomware'
                            base_score = max(base_score, 90)
                            break
                        elif 'trojan' in rule_lower or 'backdoor' in rule_lower:
                            result['threat_type'] = 'trojan'
                            base_score = max(base_score, 75)
                            break
                        elif 'rootkit' in rule_lower:
                            result['threat_type'] = 'rootkit'
                            base_score = max(base_score, 85)
                            break
                        elif 'keylog' in rule_lower:
                            result['threat_type'] = 'keylogger'
                            base_score = max(base_score, 80)
                            break
                        elif 'miner' in rule_lower or 'crypto' in rule_lower:
                            result['threat_type'] = 'cryptominer'
                            base_score = max(base_score, 60)
                            break
                        elif 'spyware' in rule_lower:
                            result['threat_type'] = 'spyware'
                            base_score = max(base_score, 65)
                            break
                result['risk_score'] = base_score
        except Exception as e:
            result['yara_error'] = str(e)

        # 2. ML anomaly detection
        ml = self._get_ml_model()
        if ml is not None:
            try:
                import numpy as np
                file_size = os.path.getsize(filepath)
                features = np.array([[
                    len(filepath),
                    result['risk_score'],
                    file_size,
                    32,  # assume hash length
                    1 if result['risk_score'] >= 70 else 0,
                    1 if result['threat_type'] != 'unknown' else 0,
                    0,
                ]])
                pred, score = ml.predict(features)
                if pred is not None and len(pred) > 0:
                    if pred[0] == -1:
                        result['ml_anomaly'] = True
                        result['risk_score'] = min(result['risk_score'] + 15, 100)
                    elif result['risk_score'] == 0:
                        # ML says anomalous but YARA didn't catch it
                        result['risk_score'] = max(result['risk_score'], 25)
            except Exception:
                pass

        # 3. Apply learned score adjustments
        result = self.adjust_finding_score(result)

        # 4. Set severity from final score
        score = result['risk_score']
        if score >= 90:
            result['severity'] = 'critical'
        elif score >= 70:
            result['severity'] = 'high'
        elif score >= 40:
            result['severity'] = 'medium'
        elif score > 0:
            result['severity'] = 'low'
        else:
            result['severity'] = 'safe'

        return result

    def scan_directory(self, dirpath, max_files=500):
        """Scan a directory for malware. Returns list of findings.

        Args:
            dirpath: Directory to scan
            max_files: Maximum number of files to scan (safety limit)
        Returns:
            List of finding dicts with risk scores
        """
        findings = []
        if not os.path.isdir(dirpath):
            return findings

        scanned = 0
        for root, dirs, files in os.walk(dirpath):
            for filename in files:
                if scanned >= max_files:
                    break
                filepath = os.path.join(root, filename)
                try:
                    result = self.scan_file(filepath)
                    if result.get('risk_score', 0) > 0:
                        findings.append(result)
                        # Auto-learn from this finding
                        self.record_score_adjustment(result, confirmed_threat=result['risk_score'] >= 70)
                    scanned += 1
                except Exception:
                    continue
            if scanned >= max_files:
                break

        # Sort by risk score descending
        findings.sort(key=lambda x: x.get('risk_score', 0), reverse=True)
        return findings

    def auto_scan_agent_findings(self, findings):
        """Process agent-reported findings: adjust scores, auto-learn, scan hashes.

        Called automatically when an agent sends a report.
        Returns the processed findings with adjusted scores.
        """
        processed = []
        for f in findings:
            if not isinstance(f, dict):
                continue
            # Adjust score based on learned data
            f = self.adjust_finding_score(f)
            # Record for score learning
            if f.get('risk_score', 0) > 0:
                self.record_score_adjustment(f, confirmed_threat=f.get('risk_score', 0) >= 70)
            processed.append(f)
        return processed

    # --- CODE GENERATION & SELF-IMPROVEMENT ---
    # The assistant can write and update its own YARA rules, ML features,
    # and scanner logic based on what it learns.

    @property
    def _improvements_path(self):
        return self._data_dir / 'assistant_code_improvements.json'

    @property
    def _custom_rules_path(self):
        return self._yara_rules_dir / 'ai_improved_rules.yar'

    @property
    def _custom_features_path(self):
        return self.base_dir / 'security' / 'ai_learned_features.py'

    def _load_improvements(self):
        return self._load(self._improvements_path, {'yara_updates': [], 'ml_features': [], 'scanner_rules': [], 'total_improvements': 0})

    def _save_improvements(self, data):
        self._save(self._improvements_path, data)

    def improve_yara_rule(self, threat_type, new_patterns, severity='high'):
        """Update or create an improved YARA rule with new patterns learned.

        If a rule for this threat type already exists, merge the new patterns
        into it. Otherwise create a new one.
        """
        rule_name = f'ai_improved_{threat_type}'
        rule_path = self._yara_rules_dir / f'{rule_name}.yar'

        # Load existing patterns from the rule file
        existing_patterns = []
        if rule_path.exists():
            existing_text = rule_path.read_text(encoding='utf-8')
            # Extract existing string patterns
            import re as _re
            for m in _re.finditer(r'\$str\d+\s*=\s*"([^"]+)"', existing_text):
                existing_patterns.append(m.group(1))
            for m in _re.finditer(r'\$hex\d+\s*=\s*\{\s*([0-9a-fA-F]+)\s*\}', existing_text):
                existing_patterns.append(m.group(1))
            # Backup the existing rule before updating
            backup_path = rule_path.with_suffix('.yar.bak')
            backup_path.write_text(existing_text, encoding='utf-8')

        # Merge patterns — add new ones that aren't already there
        all_patterns = list(existing_patterns)
        for p in new_patterns:
            p_str = str(p).strip()
            if p_str and p_str.lower() not in [p.lower() for p in all_patterns]:
                all_patterns.append(p_str)

        if not all_patterns:
            return None

        # Build the improved rule
        string_lines = []
        for i, p in enumerate(all_patterns[:20]):  # Max 20 patterns per rule
            p = str(p).strip()
            if re.match(r'^[0-9a-fA-F\s]{6,}$', p):
                string_lines.append(f'    $hex{i} = {{ {p} }}')
            else:
                escaped = p.replace('"', '\\"').replace('\\', '\\\\')
                string_lines.append(f'    $str{i} = "{escaped}" nocase')

        # Smart condition: require at least 2 matches for high confidence
        if len(all_patterns) >= 3:
            base_condition = '2 of them'
        else:
            base_condition = 'any of them'

        # Always require a PE file header check to prevent false positives on
        # text files, scripts, documentation, and other non-executable content.
        condition = f'({base_condition}) and uint16(0) == 0x5A4D'

        rule_text = f'''/*
    AI-Improved YARA Rule
    Threat: {threat_type}
    Severity: {severity}
    Patterns learned: {len(all_patterns)}
    Last improved: {datetime.datetime.now().isoformat(timespec='seconds')}
*/

rule {rule_name} : {severity}
{{
    strings:
{chr(10).join(string_lines)}

    condition:
        {condition}
}}
'''

        rule_path.write_text(rule_text, encoding='utf-8')

        # Record in database
        if self._db:
            self._db.record_yara_rule(rule_name, threat_type, severity, all_patterns,
                                      rule_text, str(rule_path), auto_generated=True)

        # Record the improvement
        improvements = self._load_improvements()
        improvements['yara_updates'].append({
            'timestamp': datetime.datetime.now().isoformat(timespec='seconds'),
            'threat_type': threat_type,
            'rule_name': rule_name,
            'patterns_added': len(all_patterns) - len(existing_patterns),
            'total_patterns': len(all_patterns),
            'rule_path': str(rule_path),
        })
        improvements['yara_updates'] = improvements['yara_updates'][-200:]
        improvements['total_improvements'] = improvements.get('total_improvements', 0) + 1
        self._save_improvements(improvements)

        self._record_auto_learn('yara_rule_improved', {
            'threat_type': threat_type,
            'rule_name': rule_name,
            'patterns_added': len(all_patterns) - len(existing_patterns),
            'total_patterns': len(all_patterns),
        })

        return {
            'rule_name': rule_name,
            'rule_path': str(rule_path),
            'patterns_total': len(all_patterns),
            'patterns_added': len(all_patterns) - len(existing_patterns),
            'rule_text': rule_text,
        }

    def write_ml_features(self, feature_name, feature_logic):
        """Write a new ML feature extraction function to the learned features file.

        Args:
            feature_name: Name of the feature function (e.g., 'entropy_score')
            feature_logic: Python code string for the function body
        Returns:
            Path to the features file
        """
        features_path = self._custom_features_path

        # Build the features module
        header = '''"""AI-learned ML features — auto-generated by the assistant.

These features are extracted from files and findings to improve
the ML model's ability to detect malware.
"""
import os
import math
import hashlib

'''

        # Read existing content if file exists
        existing_funcs = []
        if features_path.exists():
            existing_text = features_path.read_text(encoding='utf-8')
            # Extract existing function names
            import re as _re
            for m in _re.finditer(r'def\s+(\w+)\s*\(', existing_text):
                existing_funcs.append(m.group(1))

        # Don't duplicate functions
        if feature_name in existing_funcs:
            # Replace the existing function
            pattern = rf'def\s+{feature_name}\s*\([^)]*\):.*?(?=\ndef\s|\Z)'
            existing_text = _re.sub(pattern, f'def {feature_name}(finding):\n{feature_logic}\n\n', existing_text, flags=_re.DOTALL)
            features_path.write_text(existing_text, encoding='utf-8')
        else:
            # Append new function
            with open(features_path, 'a', encoding='utf-8') as f:
                if features_path.exists() and features_path.stat().st_size > 0:
                    f.write('\n\n')
                else:
                    f.write(header)
                f.write(f'def {feature_name}(finding):\n{feature_logic}\n')

        # Record the improvement
        improvements = self._load_improvements()
        improvements['ml_features'].append({
            'timestamp': datetime.datetime.now().isoformat(timespec='seconds'),
            'feature_name': feature_name,
            'file_path': str(features_path),
        })
        improvements['ml_features'] = improvements['ml_features'][-100:]
        improvements['total_improvements'] = improvements.get('total_improvements', 0) + 1
        self._save_improvements(improvements)

        self._record_auto_learn('ml_feature_written', {
            'feature_name': feature_name,
            'file_path': str(features_path),
        })

        return str(features_path)

    def auto_improve_from_findings(self, findings):
        """Automatically improve YARA rules and ML from new findings.

        Called when new findings come in. For each finding:
        - Extract new patterns and add them to YARA rules
        - Generate ML features based on the finding's characteristics
        - Record malware signatures for future lookup
        """
        improvements = []

        for f in findings:
            if not isinstance(f, dict):
                continue

            threat_type = f.get('threat_type', 'unknown')
            if threat_type == 'unknown':
                continue

            # Extract patterns from the finding
            patterns = self._extract_patterns_from_finding(f)
            if patterns:
                # Improve the YARA rule with these patterns
                result = self.improve_yara_rule(threat_type, patterns, severity=f.get('severity', 'medium'))
                if result and result.get('patterns_added', 0) > 0:
                    improvements.append(f"YARA rule for {threat_type}: added {result['patterns_added']} new pattern(s)")

            # Record as a malware signature in the database
            if self._db and f.get('hash'):
                self._db.record_signature(
                    name=threat_type,
                    hash_val=f.get('hash', ''),
                    threat_type=threat_type,
                    severity=f.get('severity', 'medium'),
                    patterns=patterns,
                    description=f.get('reason', ''),
                )

            # Auto-generate ML features based on finding characteristics
            path = str(f.get('path', ''))
            ext = os.path.splitext(path)[1].lower().lstrip('.')
            # Only generate features for executable file types to avoid
            # false positives on text/config/documentation files
            if ext and ext in ('exe', 'dll', 'sys', 'drv', 'ocx'):
                feature_name = f'ext_{ext}_risk'
                feature_logic = f'    """Auto-generated: risk feature for .{ext} files."""\n    path = str(finding.get("path", ""))\n    return 1 if path.lower().endswith(".{ext}") else 0'
                # Only write if this is a new extension
                existing_improvements = self._load_improvements()
                existing_features = [f['feature_name'] for f in existing_improvements.get('ml_features', [])]
                if feature_name not in existing_features:
                    try:
                        self.write_ml_features(feature_name, feature_logic)
                        improvements.append(f"ML feature for .{ext} files added")
                    except Exception:
                        pass

        return improvements

    def get_improvement_stats(self):
        """Return stats about code improvements made by the assistant."""
        improvements = self._load_improvements()
        return {
            'total_improvements': improvements.get('total_improvements', 0),
            'yara_rules_updated': len(improvements.get('yara_updates', [])),
            'ml_features_added': len(improvements.get('ml_features', [])),
            'scanner_rules_added': len(improvements.get('scanner_rules', [])),
        }

    def get_ai_improved_rules(self):
        """Return list of AI-improved YARA rule files."""
        if not self._yara_rules_dir.exists():
            return []
        return [f.name for f in self._yara_rules_dir.glob('ai_improved_*.yar')]

    def get_learned_features(self):
        """Return list of learned ML feature function names."""
        if not self._custom_features_path.exists():
            return []
        text = self._custom_features_path.read_text(encoding='utf-8')
        import re as _re
        return _re.findall(r'def\s+(\w+)\s*\(', text)
