"""SQLite database for the assistant's learning system.

Stores all training data, findings, threats, false positives, knowledge,
feedback, agent reports, and learning events in a persistent database.

This replaces the JSON file storage with a proper database that can:
- Query learned data efficiently
- Track learning history over time
- Store malware signatures and YARA rules
- Record agent reports and findings
- Track false positive corrections
- Store knowledge entries
- Log every learning event
"""
import datetime
import json
import os
import sqlite3
import hashlib
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS knowledge (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    topic TEXT UNIQUE NOT NULL,
    content TEXT NOT NULL,
    source TEXT DEFAULT 'manual',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS false_positives (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL,
    hash TEXT DEFAULT '',
    reason TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE(path)
);

CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    question TEXT NOT NULL,
    answer TEXT NOT NULL,
    rating INTEGER NOT NULL,
    comment TEXT DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT DEFAULT '',
    path TEXT NOT NULL,
    hash TEXT DEFAULT '',
    threat_type TEXT DEFAULT 'unknown',
    severity TEXT DEFAULT 'low',
    risk_score INTEGER DEFAULT 0,
    reason TEXT DEFAULT '',
    source TEXT DEFAULT '',
    detected_at TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    false_positive INTEGER DEFAULT 0,
    confirmed INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS agent_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    hostname TEXT DEFAULT '',
    report_type TEXT DEFAULT 'scan',
    findings_count INTEGER DEFAULT 0,
    files_scanned INTEGER DEFAULT 0,
    threats_blocked INTEGER DEFAULT 0,
    raw_data TEXT DEFAULT '',
    received_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS yara_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name TEXT UNIQUE NOT NULL,
    threat_type TEXT DEFAULT '',
    severity TEXT DEFAULT 'medium',
    patterns TEXT DEFAULT '[]',
    rule_text TEXT NOT NULL,
    file_path TEXT NOT NULL,
    auto_generated INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    active INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS ml_training_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    features TEXT NOT NULL,
    label INTEGER DEFAULT 0,
    source TEXT DEFAULT 'auto',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS learning_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    event_data TEXT DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS score_adjustments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    adjustment_type TEXT DEFAULT 'threat',
    count INTEGER DEFAULT 0,
    confirmed_threat INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS malware_signatures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    hash TEXT DEFAULT '',
    threat_type TEXT DEFAULT '',
    severity TEXT DEFAULT 'medium',
    patterns TEXT DEFAULT '[]',
    description TEXT DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    hit_count INTEGER DEFAULT 1,
    UNIQUE(name, hash)
);

CREATE INDEX IF NOT EXISTS idx_findings_path ON findings(path);
CREATE INDEX IF NOT EXISTS idx_findings_hash ON findings(hash);
CREATE INDEX IF NOT EXISTS idx_findings_threat_type ON findings(threat_type);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_agent_reports_device ON agent_reports(device_id);
CREATE INDEX IF NOT EXISTS idx_learning_events_type ON learning_events(event_type);
CREATE INDEX IF NOT EXISTS idx_knowledge_topic ON knowledge(topic);
CREATE INDEX IF NOT EXISTS idx_false_positives_path ON false_positives(path);
"""


class AssistantDatabase:
    """SQLite database for persistent assistant learning."""

    def __init__(self, base_dir=None):
        self.base_dir = Path(base_dir or os.path.dirname(os.path.dirname(__file__)))
        self._data_dir = Path(os.environ.get('ANTIVIRUS_RUNTIME_DIR', str(self.base_dir))) / 'data'
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._db_path = self._data_dir / 'assistant_learning.db'
        self._init_db()

    def _init_db(self):
        """Initialize the database schema."""
        with self._connect() as conn:
            conn.executescript(SCHEMA)
            conn.commit()

    def _connect(self):
        """Create a database connection."""
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _now(self):
        return datetime.datetime.now().isoformat(timespec='seconds')

    # --- Knowledge ---
    def add_knowledge(self, topic, content, source='manual'):
        """Add or update a knowledge entry."""
        with self._connect() as conn:
            conn.execute(
                'INSERT INTO knowledge (topic, content, source, created_at, updated_at) '
                'VALUES (?, ?, ?, ?, ?) '
                'ON CONFLICT(topic) DO UPDATE SET content=excluded.content, updated_at=excluded.updated_at',
                (topic, content, source, self._now(), self._now())
            )
            conn.commit()

    def remove_knowledge(self, topic):
        """Remove a knowledge entry."""
        with self._connect() as conn:
            conn.execute('DELETE FROM knowledge WHERE topic = ?', (topic,))
            conn.commit()

    def get_knowledge(self):
        """Return all knowledge entries."""
        with self._connect() as conn:
            rows = conn.execute('SELECT * FROM knowledge ORDER BY updated_at DESC').fetchall()
            return [{'topic': r['topic'], 'content': r['content'], 'source': r['source'],
                     'created_at': r['created_at']} for r in rows]

    def search_knowledge(self, question, limit=5):
        """Search knowledge entries by keyword relevance."""
        words = [w for w in question.lower().split() if len(w) >= 3]
        if not words:
            return []
        with self._connect() as conn:
            results = []
            rows = conn.execute('SELECT * FROM knowledge').fetchall()
            for r in rows:
                topic = r['topic'].lower()
                content = r['content'].lower()
                score = sum(3 if w in topic else 1 for w in words if w in topic or w in content)
                if score > 0:
                    results.append((score, r))
            results.sort(key=lambda x: x[0], reverse=True)
            return [{'topic': r['topic'], 'content': r['content']} for _, r in results[:limit]]

    # --- False Positives ---
    def mark_false_positive(self, path, hash_val='', reason=''):
        """Mark a file as a known false positive."""
        with self._connect() as conn:
            conn.execute(
                'INSERT INTO false_positives (path, hash, reason, created_at) '
                'VALUES (?, ?, ?, ?) '
                'ON CONFLICT(path) DO UPDATE SET hash=excluded.hash, reason=excluded.reason',
                (path.lower(), hash_val.lower(), reason, self._now())
            )
            conn.commit()

    def unmark_false_positive(self, path):
        """Remove a false positive marking."""
        with self._connect() as conn:
            conn.execute('DELETE FROM false_positives WHERE path = ?', (path.lower(),))
            conn.commit()

    def get_false_positives(self):
        """Return all known false positives."""
        with self._connect() as conn:
            rows = conn.execute('SELECT * FROM false_positives ORDER BY created_at DESC').fetchall()
            return [{'path': r['path'], 'hash': r['hash'], 'reason': r['reason'],
                     'created_at': r['created_at']} for r in rows]

    def is_false_positive(self, path='', hash_val=''):
        """Check if a file or hash is a known false positive."""
        with self._connect() as conn:
            if path:
                r = conn.execute('SELECT 1 FROM false_positives WHERE path = ?', (path.lower(),)).fetchone()
                if r:
                    return True
            if hash_val:
                r = conn.execute('SELECT 1 FROM false_positives WHERE hash = ?', (hash_val.lower(),)).fetchone()
                if r:
                    return True
        return False

    # --- Feedback ---
    def record_feedback(self, question, answer, rating, comment=''):
        """Record feedback on an assistant answer."""
        with self._connect() as conn:
            conn.execute(
                'INSERT INTO feedback (question, answer, rating, comment, created_at) VALUES (?, ?, ?, ?, ?)',
                (question[:500], answer[:2000], rating, comment[:500], self._now())
            )
            conn.commit()

    def get_feedback_stats(self):
        """Return feedback statistics."""
        with self._connect() as conn:
            total = conn.execute('SELECT COUNT(*) as c FROM feedback').fetchone()['c']
            good = conn.execute('SELECT COUNT(*) as c FROM feedback WHERE rating > 0').fetchone()['c']
            bad = conn.execute('SELECT COUNT(*) as c FROM feedback WHERE rating < 0').fetchone()['c']
        return {
            'total': total, 'good': good, 'bad': bad,
            'good_rate': round(good / total * 100, 1) if total else 0,
        }

    def get_recent_feedback(self, limit=20):
        """Return recent feedback entries."""
        with self._connect() as conn:
            rows = conn.execute('SELECT * FROM feedback ORDER BY created_at DESC LIMIT ?', (limit,)).fetchall()
            return [dict(r) for r in rows]

    # --- Findings ---
    def record_finding(self, finding):
        """Record a malware finding in the database."""
        if not isinstance(finding, dict):
            return
        path = str(finding.get('path', ''))
        h = str(finding.get('hash', ''))
        if not path:
            return
        with self._connect() as conn:
            conn.execute(
                'INSERT INTO findings (device_id, path, hash, threat_type, severity, risk_score, '
                'reason, source, detected_at, recorded_at, false_positive, confirmed) '
                'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (
                    finding.get('device_id', ''),
                    path.lower(),
                    h.lower(),
                    finding.get('threat_type', 'unknown'),
                    finding.get('severity', 'low'),
                    finding.get('risk_score', 0),
                    finding.get('reason', ''),
                    finding.get('source', ''),
                    finding.get('detected_at', self._now()),
                    self._now(),
                    1 if finding.get('false_positive') else 0,
                    1 if finding.get('confirmed') else 0,
                )
            )
            conn.commit()

    def get_findings(self, limit=100, threat_type=None, min_score=0):
        """Query findings from the database.

        Uses a fixed query with optional parameter binding — the query
        structure is determined by a boolean flag, not by interpolating
        user input, so there is no SQL injection surface.
        """
        with self._connect() as conn:
            if threat_type:
                rows = conn.execute(
                    'SELECT * FROM findings WHERE risk_score >= ? '
                    'AND threat_type = ? '
                    'ORDER BY risk_score DESC, recorded_at DESC LIMIT ?',
                    [min_score, threat_type, limit]
                ).fetchall()
            else:
                rows = conn.execute(
                    'SELECT * FROM findings WHERE risk_score >= ? '
                    'ORDER BY risk_score DESC, recorded_at DESC LIMIT ?',
                    [min_score, limit]
                ).fetchall()
            return [dict(r) for r in rows]

    def get_finding_stats(self):
        """Return statistics about recorded findings."""
        with self._connect() as conn:
            total = conn.execute('SELECT COUNT(*) as c FROM findings').fetchone()['c']
            by_type = conn.execute(
                'SELECT threat_type, COUNT(*) as c FROM findings GROUP BY threat_type ORDER BY c DESC'
            ).fetchall()
            by_severity = conn.execute(
                'SELECT severity, COUNT(*) as c FROM findings GROUP BY severity ORDER BY c DESC'
            ).fetchall()
            confirmed = conn.execute('SELECT COUNT(*) as c FROM findings WHERE confirmed = 1').fetchone()['c']
            fps = conn.execute('SELECT COUNT(*) as c FROM findings WHERE false_positive = 1').fetchone()['c']
        return {
            'total': total,
            'confirmed_threats': confirmed,
            'false_positives': fps,
            'by_threat_type': {r['threat_type']: r['c'] for r in by_type},
            'by_severity': {r['severity']: r['c'] for r in by_severity},
        }

    # --- Agent Reports ---
    def record_agent_report(self, device_id, hostname='', report_type='scan',
                            findings_count=0, files_scanned=0, threats_blocked=0, raw_data=''):
        """Record an agent report in the database."""
        with self._connect() as conn:
            conn.execute(
                'INSERT INTO agent_reports (device_id, hostname, report_type, findings_count, '
                'files_scanned, threats_blocked, raw_data, received_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                (device_id, hostname, report_type, findings_count, files_scanned,
                 threats_blocked, raw_data[:5000], self._now())
            )
            conn.commit()

    def get_agent_report_stats(self):
        """Return statistics about agent reports."""
        with self._connect() as conn:
            total = conn.execute('SELECT COUNT(*) as c FROM agent_reports').fetchone()['c']
            devices = conn.execute(
                'SELECT device_id, COUNT(*) as c FROM agent_reports GROUP BY device_id'
            ).fetchall()
            total_findings = conn.execute(
                'SELECT COALESCE(SUM(findings_count), 0) as s FROM agent_reports'
            ).fetchone()['s']
            total_scanned = conn.execute(
                'SELECT COALESCE(SUM(files_scanned), 0) as s FROM agent_reports'
            ).fetchone()['s']
        return {
            'total_reports': total,
            'total_findings': total_findings,
            'total_files_scanned': total_scanned,
            'devices_reporting': len(devices),
        }

    # --- YARA Rules ---
    def record_yara_rule(self, rule_name, threat_type='', severity='medium',
                         patterns=None, rule_text='', file_path='', auto_generated=False):
        """Record a generated YARA rule."""
        patterns_json = json.dumps(patterns or [])
        with self._connect() as conn:
            conn.execute(
                'INSERT INTO yara_rules (rule_name, threat_type, severity, patterns, rule_text, '
                'file_path, auto_generated, created_at, active) '
                'VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1) '
                'ON CONFLICT(rule_name) DO UPDATE SET rule_text=excluded.rule_text, '
                'patterns=excluded.patterns, active=1',
                (rule_name, threat_type, severity, patterns_json, rule_text,
                 file_path, 1 if auto_generated else 0, self._now())
            )
            conn.commit()

    def get_yara_rules(self, active_only=True):
        """Return all YARA rules."""
        with self._connect() as conn:
            query = 'SELECT * FROM yara_rules'
            if active_only:
                query += ' WHERE active = 1'
            query += ' ORDER BY created_at DESC'
            rows = conn.execute(query).fetchall()
            return [dict(r) for r in rows]

    def deactivate_yara_rule(self, rule_name):
        """Deactivate a YARA rule."""
        with self._connect() as conn:
            conn.execute('UPDATE yara_rules SET active = 0 WHERE rule_name = ?', (rule_name,))
            conn.commit()

    # --- ML Training Samples ---
    def record_ml_sample(self, features, label=0, source='auto'):
        """Record an ML training sample."""
        features_json = json.dumps(features if isinstance(features, list) else list(features))
        with self._connect() as conn:
            conn.execute(
                'INSERT INTO ml_training_samples (features, label, source, created_at) VALUES (?, ?, ?, ?)',
                (features_json, label, source, self._now())
            )
            conn.commit()

    def get_ml_sample_count(self):
        """Return the total number of ML training samples."""
        with self._connect() as conn:
            return conn.execute('SELECT COUNT(*) as c FROM ml_training_samples').fetchone()['c']

    def get_ml_samples(self, limit=1000):
        """Return ML training samples for model training."""
        import json as _json
        with self._connect() as conn:
            rows = conn.execute(
                'SELECT features, label FROM ml_training_samples ORDER BY created_at DESC LIMIT ?',
                (limit,)
            ).fetchall()
            return [(_json.loads(r['features']), r['label']) for r in rows]

    # --- Learning Events ---
    def record_event(self, event_type, event_data=None):
        """Record a learning event."""
        data_json = json.dumps(event_data or {}, ensure_ascii=False)
        with self._connect() as conn:
            conn.execute(
                'INSERT INTO learning_events (event_type, event_data, created_at) VALUES (?, ?, ?)',
                (event_type, data_json, self._now())
            )
            conn.commit()

    def get_event_stats(self):
        """Return statistics about learning events."""
        with self._connect() as conn:
            total = conn.execute('SELECT COUNT(*) as c FROM learning_events').fetchone()['c']
            by_type = conn.execute(
                'SELECT event_type, COUNT(*) as c FROM learning_events GROUP BY event_type ORDER BY c DESC'
            ).fetchall()
        return {
            'total_events': total,
            'by_type': {r['event_type']: r['c'] for r in by_type},
        }

    def get_recent_events(self, limit=50):
        """Return recent learning events."""
        with self._connect() as conn:
            rows = conn.execute(
                'SELECT * FROM learning_events ORDER BY created_at DESC LIMIT ?',
                (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    # --- Score Adjustments ---
    def record_score_adjustment(self, key, adjustment_type='threat', confirmed_threat=False):
        """Record or update a score adjustment."""
        with self._connect() as conn:
            existing = conn.execute(
                'SELECT id, count FROM score_adjustments WHERE key = ?', (key,)
            ).fetchone()
            if existing:
                conn.execute(
                    'UPDATE score_adjustments SET count = count + 1, confirmed_threat = ?, updated_at = ? WHERE key = ?',
                    (1 if confirmed_threat else 0, self._now(), key)
                )
            else:
                conn.execute(
                    'INSERT INTO score_adjustments (key, adjustment_type, count, confirmed_threat, created_at, updated_at) '
                    'VALUES (?, ?, 1, ?, ?, ?)',
                    (key, adjustment_type, 1 if confirmed_threat else 0, self._now(), self._now())
                )
            conn.commit()

    def get_score_adjustments(self):
        """Return all score adjustments."""
        with self._connect() as conn:
            rows = conn.execute('SELECT * FROM score_adjustments ORDER BY count DESC').fetchall()
            return [dict(r) for r in rows]

    # --- Malware Signatures ---
    def record_signature(self, name, hash_val='', threat_type='', severity='medium',
                         patterns=None, description=''):
        """Record or update a malware signature."""
        patterns_json = json.dumps(patterns or [])
        with self._connect() as conn:
            existing = conn.execute(
                'SELECT id, hit_count FROM malware_signatures WHERE name = ? AND hash = ?',
                (name, hash_val.lower())
            ).fetchone()
            if existing:
                conn.execute(
                    'UPDATE malware_signatures SET hit_count = hit_count + 1, last_seen = ? WHERE id = ?',
                    (self._now(), existing['id'])
                )
            else:
                conn.execute(
                    'INSERT INTO malware_signatures (name, hash, threat_type, severity, patterns, '
                    'description, first_seen, last_seen, hit_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)',
                    (name, hash_val.lower(), threat_type, severity, patterns_json,
                     description, self._now(), self._now())
                )
            conn.commit()

    def get_signatures(self, limit=100):
        """Return malware signatures ordered by hit count."""
        with self._connect() as conn:
            rows = conn.execute(
                'SELECT * FROM malware_signatures ORDER BY hit_count DESC, last_seen DESC LIMIT ?',
                (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    def lookup_signature(self, hash_val=''):
        """Look up a signature by hash."""
        with self._connect() as conn:
            r = conn.execute(
                'SELECT * FROM malware_signatures WHERE hash = ?', (hash_val.lower(),)
            ).fetchone()
            return dict(r) if r else None

    # --- Summary ---
    def get_summary(self):
        """Return a complete summary of all learning data."""
        return {
            'knowledge_entries': len(self.get_knowledge()),
            'false_positives': len(self.get_false_positives()),
            'feedback': self.get_feedback_stats(),
            'findings': self.get_finding_stats(),
            'agent_reports': self.get_agent_report_stats(),
            'yara_rules': len(self.get_yara_rules()),
            'ml_samples': self.get_ml_sample_count(),
            'learning_events': self.get_event_stats(),
            'score_adjustments': len(self.get_score_adjustments()),
            'malware_signatures': len(self.get_signatures()),
        }
