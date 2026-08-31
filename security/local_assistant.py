"""Local findings assistant with bounded, evidence-based analysis."""
import datetime
import ipaddress
import json
import os
import re
from collections import Counter
from pathlib import Path

from security.assistant_trainer import AssistantTrainer


_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,128}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class LocalFindingsAssistant:
    def __init__(self, base_dir=None):
        self.base_dir = Path(base_dir or os.path.dirname(os.path.dirname(__file__)))
        self._model = None
        self._model_error = None
        self._trainer = AssistantTrainer(self.base_dir)

    @property
    def _history_path(self):
        runtime = Path(os.environ.get('ANTIVIRUS_RUNTIME_DIR', str(self.base_dir)))
        return runtime / 'data' / 'assistant_scan_history.json'

    def load_history(self):
        try:
            data = json.loads(self._history_path.read_text(encoding='utf-8'))
            return data[-50:] if isinstance(data, list) else []
        except (OSError, json.JSONDecodeError):
            return []

    def record_scan(self, context):
        context = context if isinstance(context, dict) else {}
        record = {
            'timestamp': context.get('timestamp') or datetime.datetime.now().isoformat(timespec='seconds'),
            'findings': self._findings(context),
            'service_status': context.get('service_status') or {},
            'quarantine': context.get('quarantine') or [],
        }
        history = self.load_history()
        history.append(record)
        target = self._history_path
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix('.json.tmp')
        temporary.write_text(json.dumps(history[-50:], ensure_ascii=False), encoding='utf-8')
        os.replace(temporary, target)
        return record

    def _model_path(self):
        candidates = [
            self.base_dir / 'models' / 'assistant.gguf',
            self.base_dir / 'models' / 'local_assistant.gguf',
            self.base_dir / '_internal' / 'models' / 'assistant.gguf',
        ]
        return next((path for path in candidates if path.is_file()), None)

    def _load_model(self):
        # The GGUF model (1.6 GB) is too heavy for the cloud server process
        # and causes crashes/timeouts. Use the fast findings mode instead,
        # which generates instant structured reports from the evidence.
        if self._model_error is None:
            self._model_error = 'Local GGUF model disabled in cloud mode; using findings mode for fast, reliable reports.'
        return None

    @staticmethod
    def _findings(context):
        findings = context.get('findings') or context.get('results') or []
        if isinstance(findings, dict):
            findings = list(findings.values())
        return [item if isinstance(item, dict) else {'value': str(item)} for item in findings[:100]]

    @staticmethod
    def _extract_iocs(findings):
        hashes, ips, domains = set(), set(), set()
        for item in findings:
            text = json.dumps(item, ensure_ascii=False)
            hashes.update(value.lower() for value in _HASH_RE.findall(text))
            for value in _IP_RE.findall(text):
                try:
                    if ipaddress.ip_address(value).is_global:
                        ips.add(value)
                except ValueError:
                    pass
            domains.update(value.lower() for value in _DOMAIN_RE.findall(text))
        return {'hashes': sorted(hashes)[:100], 'ips': sorted(ips)[:100], 'domains': sorted(domains)[:100]}

    @staticmethod
    def _priority(item):
        text = json.dumps(item, ensure_ascii=False).lower()
        severity = str(item.get('severity', '')).lower()
        score = 0
        for word, points in (('critical', 5), ('ransomware', 5), ('persistence', 4), ('malware', 4), ('high', 3), ('suspicious', 2), ('medium', 2), ('low', 1)):
            if word in severity or word in text:
                score = max(score, points)
        return score

    def _analysis(self, context):
        context = context if isinstance(context, dict) else {}
        findings = self._findings(context)
        # Filter out known false positives from training
        findings = self._trainer.filter_findings(findings)
        ranked = sorted(findings, key=self._priority, reverse=True)
        categories = Counter(str(item.get('source') or item.get('category') or 'unknown') for item in findings)
        paths = [item.get('path') for item in findings if item.get('path')]
        history = context.get('scan_history') or []
        quarantined = context.get('quarantine') or context.get('quarantined_files') or []
        agents = context.get('agents') or []
        events = context.get('events') or []
        # Merge agent reports and events into findings if no explicit findings
        if not findings and agents:
            for agent in agents:
                report = agent.get('last_report') or {}
                if report:
                    agent_findings = report.get('findings') or report.get('results') or []
                    if isinstance(agent_findings, list):
                        for f in agent_findings:
                            if isinstance(f, dict):
                                f.setdefault('source', f"agent:{agent.get('hostname', agent.get('device_id','unknown'))}")
                                findings.append(f)
            ranked = sorted(findings, key=self._priority, reverse=True)
            categories = Counter(str(item.get('source') or item.get('category') or 'unknown') for item in findings)
            paths = [item.get('path') for item in findings if item.get('path')]
        return {
            'finding_count': len(findings),
            'priority_findings': ranked[:20],
            'categories': dict(categories),
            'unique_paths': sorted(set(paths))[:100],
            'iocs': self._extract_iocs(findings),
            'scan_history_available': bool(history),
            'scan_history_count': len(history) if isinstance(history, list) else 0,
            'quarantine_count': len(quarantined) if isinstance(quarantined, list) else 0,
            'agents': agents,
            'agent_count': len(agents),
            'events': events[-50:] if isinstance(events, list) else [],
            'event_count': len(events) if isinstance(events, list) else 0,
        }

    @staticmethod
    def _report(analysis):
        iocs = analysis['iocs']
        lines = [
            f"Incident summary: {analysis['finding_count']} finding(s).",
            f"Categories: {', '.join(f'{k}={v}' for k, v in analysis['categories'].items()) or 'none'}.",
            f"Quarantine records supplied: {analysis['quarantine_count']}.",
            f"Scan history supplied: {analysis['scan_history_count']} record(s).",
            f"IOCs: {len(iocs['hashes'])} hash(es), {len(iocs['ips'])} IP(s), {len(iocs['domains'])} domain(s).",
        ]
        agents = analysis.get('agents') or []
        if agents:
            lines.append(f"Connected agents: {len(agents)}.")
            for a in agents[:5]:
                host = a.get('hostname') or a.get('device_id', 'unknown')
                status = a.get('status', 'unknown')
                report = a.get('last_report') or {}
                rfindings = report.get('findings') or report.get('results') or []
                fc = len(rfindings) if isinstance(rfindings, list) else 0
                os_name = a.get('os', '')
                cpu = a.get('cpu_usage', '')
                mem = a.get('mem_usage', '')
                sys_info = f" [{os_name}]" if os_name else ""
                load = f" CPU:{cpu}% MEM:{mem}%" if cpu or mem else ""
                lines.append(f"  - {host} ({status}){sys_info}: {fc} finding(s){load}.")
        events = analysis.get('events') or []
        if events:
            lines.append(f"Recent events: {len(events)}.")
        if analysis['priority_findings']:
            lines.append('Highest-priority findings:')
            for item in analysis['priority_findings'][:10]:
                src = item.get('source', '')
                ttype = item.get('threat_type', '')
                risk = item.get('risk_score', '')
                risk_str = f" risk:{risk}" if risk else ""
                type_str = f" [{ttype}]" if ttype else ""
                lines.append(f"- {item.get('path', item.get('value', 'unknown'))}: {item.get('reason', item.get('severity', 'unclassified'))}{type_str}{risk_str}" + (f" [{src}]" if src else ""))
        else:
            lines.append('No findings were supplied; no threat conclusion can be made.')
        return '\n'.join(lines)

    @staticmethod
    def _narrate_agent(agent, events):
        """Generate a human-like narration of what an agent is doing/thinking."""
        import random
        random.seed(hash(agent.get('device_id', '')) % 1000)
        host = agent.get('hostname') or agent.get('device_id', 'unknown')
        status = agent.get('status', 'unknown')
        last = agent.get('last_seen', 'unknown')
        os_name = agent.get('os', '')
        cpu = agent.get('cpu_usage', '')
        mem = agent.get('mem_usage', '')
        files_scanned = agent.get('files_scanned', 0)
        threats_blocked = agent.get('threats_blocked', 0)
        report = agent.get('last_report') or {}
        rfindings = report.get('findings') or report.get('results') or []
        fc = len(rfindings) if isinstance(rfindings, list) else 0

        # Agent events for this device
        my_events = [e for e in events if isinstance(e, dict) and e.get('device_id') == agent.get('device_id')]

        thoughts = []

        if status == 'online':
            greetings = [
                f"Hey, {host} here. I'm online and keeping watch.",
                f"{host} checking in. Everything looks stable on my end.",
                f"This is {host}. I'm up and running, scanning like usual.",
                f"{host} reporting live. I'm actively monitoring the system.",
            ]
            thoughts.append(random.choice(greetings))
            if os_name:
                thoughts.append(f"I'm running on {os_name}.")
            if cpu or mem:
                thoughts.append(f"Current load — CPU: {cpu}%, Memory: {mem}%.")
            if files_scanned:
                thoughts.append(f"I've scanned {files_scanned} file(s) so far.")
            if threats_blocked:
                thoughts.append(f"Blocked {threats_blocked} threat(s) since I started.")
        else:
            thoughts.append(f"This is {host}. I haven't checked in recently — last seen {last}. Something might have interrupted me.")

        if fc > 0:
            # Use enriched threat types and risk scores
            threat_types = []
            high_risk = []
            for f in rfindings:
                if isinstance(f, dict):
                    tt = f.get('threat_type', '')
                    if tt and tt != 'unknown':
                        threat_types.append(tt)
                    rs = f.get('risk_score', 0)
                    if isinstance(rs, (int, float)) and rs >= 75:
                        high_risk.append(f)
            if high_risk:
                names = ', '.join(set(f.get('threat_type', 'threat') for f in high_risk[:5]))
                thoughts.append(f"I found {fc} issue(s) in my last scan — {len(high_risk)} of them are high risk ({names}). You should probably look at those right away.")
            elif any('high' in str(f.get('severity', f.get('reason', ''))).lower() for f in rfindings if isinstance(f, dict)):
                thoughts.append(f"My last scan turned up {fc} finding(s). A few of them are suspicious — I'm keeping a close eye on them. Not panicking yet, but I wouldn't ignore them either.")
            else:
                thoughts.append(f"I picked up {fc} finding(s) in my last scan. Nothing too alarming — mostly low-priority stuff. I've logged them for the record.")
            # Mention specific threat types if found
            if threat_types:
                unique_types = list(set(threat_types))[:5]
                thoughts.append(f"Threat types I saw: {', '.join(unique_types)}.")
        else:
            calm = [
                "No threats on my end. Clean scan, clean system. I'll keep watching.",
                "Nothing suspicious to report. The system looks healthy from where I'm sitting.",
                "All clear here. I'm just quietly monitoring in the background.",
                "No findings yet. I'm patrolling and everything's quiet.",
            ]
            thoughts.append(random.choice(calm))

        if my_events:
            recent = my_events[-3:]
            for ev in recent:
                etype = ev.get('type', 'event')
                summary = ev.get('summary') or ev.get('message') or ''
                if not summary:
                    summary = json.dumps(ev)[:120]
                if 'scan' in str(etype).lower():
                    thoughts.append(f"I ran a scan a moment ago — {summary}.")
                elif 'quarantine' in str(etype).lower():
                    thoughts.append(f"I quarantined something: {summary}. It's contained, don't worry.")
                elif 'block' in str(etype).lower():
                    thoughts.append(f"I blocked a suspicious connection: {summary}. That one looked sketchy.")
                elif 'alert' in str(etype).lower():
                    thoughts.append(f"I triggered an alert: {summary}. Thought you should know.")
                else:
                    thoughts.append(f"Something happened on my end: {summary}.")

        return f"[{host}] " + ' '.join(thoughts)

    @staticmethod
    def _converse(question, analysis, trainer=None, _skip_knowledge=False):
        """Conversational response engine — answers naturally like a real person."""
        import random
        random.seed(hash(question) % 10000)

        q = question.lower().strip()
        agents = analysis.get('agents') or []
        events = analysis.get('events') or []
        findings = analysis.get('priority_findings') or []
        iocs = analysis.get('iocs') or {}
        history = analysis.get('scan_history_available', False)
        history_count = analysis.get('scan_history_count', 0)
        quarantined = analysis.get('quarantine_count', 0)

        # --- Greetings & identity ---
        if any(q == w or q.startswith(w) for w in ('hi', 'hey', 'hello', 'yo', 'sup', 'howdy')):
            names = [
                "Hey! I'm your security assistant. I can see your agents, scan results, threats, and system activity. What do you want to know?",
                "Hello! I'm here and watching the system. Ask me about threats, agents, IOCs, or what's happening right now.",
                "Hi there. I've got eyes on everything — agents, scans, findings, the works. What's on your mind?",
            ]
            return random.choice(names)

        if any(w in q for w in ('who are you', 'what are you', 'your name', 'about you')):
            return "I'm the local findings assistant. I live inside your antivirus server and watch everything that's happening — connected agents, scan results, threats, quarantined files, suspicious behavior. I don't need the internet, I don't send your data anywhere, and I can answer questions about what's going on right now. What do you want to dig into?"

        if any(w in q for w in ('how are you', 'how do you feel', 'you ok', 'you good')):
            states = [
                "I'm running fine. The server's up, I'm processing data, and I'm ready to help you figure out what's happening on your network.",
                "Doing good! Everything's operational on my end. The real question is how your systems are doing — want me to check?",
                "All good here. I'm quietly watching everything in the background. What can I help you with?",
            ]
            return random.choice(states)

        if any(w in q for w in ('thank', 'thanks', 'cheers', 'appreciate')):
            return "Anytime. That's what I'm here for. Let me know if anything else comes up."

        # --- What's happening / status overview ---
        if any(w in q for w in ("what's happening", 'whats happening', 'status', 'overview', 'situation', 'going on', 'update')):
            parts = []
            if agents:
                online = sum(1 for a in agents if a.get('status') == 'online')
                parts.append(f"You've got {len(agents)} agent(s) connected, {online} of them online right now.")
            else:
                parts.append("No agents are connected at the moment.")
            if findings:
                parts.append(f"There are {analysis['finding_count']} finding(s) total — I can break those down if you want.")
            else:
                parts.append("No findings have been reported yet — things look clean.")
            if events:
                parts.append(f"I've recorded {len(events)} recent event(s) from agent activity.")
            if quarantined:
                parts.append(f"{quarantined} file(s) are in quarantine.")
            parts.append("What specifically do you want to dig into?")
            return ' '.join(parts)

        # --- Agent thoughts / behavior ---
        if any(w in q for w in ('behavior', 'behaviour', 'thought', 'thinking', 'mind', 'doing right now', 'what are they', 'talk to', 'say')):
            if not agents:
                return "Nobody's home right now. No agents are connected. Once they come online and start sending heartbeats and reports, I'll be able to tell you exactly what each one is thinking and doing — in real time."
            lines = ["Here's what your agents are saying right now:\n"]
            for a in agents[:8]:
                lines.append(LocalFindingsAssistant._narrate_agent(a, events))
                lines.append('')
            return '\n'.join(lines).strip()

        # --- Agent list ---
        if any(w in q for w in ('agent', 'device', 'connect', 'online', 'host', 'who is', 'who are', 'machine')):
            if not agents:
                return "No agents are connected. They'll appear here as soon as they register and start sending heartbeats. If you're expecting agents, they might still be starting up."
            lines = [f"I see {len(agents)} agent(s) connected:\n"]
            for a in agents[:10]:
                host = a.get('hostname') or a.get('device_id', 'unknown')
                status = a.get('status', 'unknown')
                last = a.get('last_seen', 'unknown')
                report = a.get('last_report') or {}
                rfindings = report.get('findings') or report.get('results') or []
                fc = len(rfindings) if isinstance(rfindings, list) else 0
                if status == 'online':
                    lines.append(f"  - {host} is online and active. Last checked in at {last}. Reported {fc} finding(s).")
                else:
                    lines.append(f"  - {host} appears to be offline. Last seen {last}. Might need attention.")
            lines.append("\nWant me to tell you what they're thinking? Just ask about their behavior.")
            return '\n'.join(lines)

        # --- Remediation / fix (check before threats so "how do I fix" works) ---
        if any(w in q for w in ('fix', 'remediat', 'next step', 'what should i do', 'how do i', 'how to', 'clean', 'remove', 'delete threat')):
            if not findings:
                return "There's nothing to fix right now — no threats have been detected. If something comes up, I'll walk you through the steps to contain and remove it."
            parts = ["Here's what I'd recommend:\n"]
            parts.append("1. Look at the highest-priority findings first — those are the ones most likely to be real threats.")
            parts.append("2. For each one, check the file path, the publisher, and whether it's something you recognize.")
            parts.append("3. If it's genuinely suspicious, quarantine it through the dashboard.")
            parts.append("4. If you're not sure, check the hash reputation and compare with prior scan history.")
            parts.append("5. Preserve evidence before removing anything — you might need it later.")
            parts.append("\nI can pull the IOCs or generate a full report if that helps. Just ask.")
            return '\n'.join(parts)

        # --- Training: mark false positive (before threats so "mark" isn't caught) ---
        if q.startswith('mark ') and ('false positive' in q or 'safe' in q):
            path_match = re.search(r'mark\s+(.+?)\s+as\s+(?:false positive|safe)', q)
            if path_match:
                path = path_match.group(1).strip()
                if trainer:
                    trainer.mark_false_positive(path)
                    return f"Got it. I've marked '{path}' as a false positive. I won't flag it as a threat in future scans. If you change your mind, just say 'forget {path}'."
                return "I'd mark that as a false positive, but my training system isn't available right now."
            return "I couldn't tell which file you want me to mark as safe. Try saying 'mark C:/path/to/file.exe as false positive'."

        # --- Training: forget false positive ---
        if q.startswith('forget '):
            path_match = re.search(r'forget\s+(.+)', q)
            if path_match:
                path = path_match.group(1).strip()
                if trainer:
                    trainer.unmark_false_positive(path)
                    return f"Done. I've removed '{path}' from my false positive list. It'll be scanned normally again."
                return "I'd remove that from my false positive list, but my training system isn't available right now."

        # --- Training: remember knowledge (before threats so "ransomware" in text isn't caught) ---
        if q.startswith('remember that '):
            content_match = re.search(r'remember that\s+(.+)', q)
            if content_match:
                text = content_match.group(1).strip()
                if ' is ' in text:
                    parts_text = text.split(' is ', 1)
                    topic = parts_text[0].strip()
                    content = parts_text[1].strip()
                else:
                    topic = text[:50]
                    content = text
                if trainer:
                    trainer.add_knowledge(topic, content)
                    return f"Got it. I'll remember that {topic} is {content}. I'll use this knowledge when answering future questions about {topic}."
                return "I'd remember that, but my training system isn't available right now."

        # --- Learn a threat pattern (generates YARA rule + trains ML) ---
        if q.startswith('learn threat ') or q.startswith('detect '):
            # "learn threat ransomware with patterns encrypt_files, bitcoin_payment, file_extension_lock"
            import re as _re
            m = _re.search(r'(?:learn threat|detect)\s+(\S+)(?:\s+with\s+patterns?\s+(.+))?', q)
            if m:
                threat_name = m.group(1).strip()
                patterns_str = m.group(2) or ''
                patterns = [p.strip().strip('"\'') for p in patterns_str.split(',') if p.strip()]
                if not patterns:
                    # Try to extract patterns from the question differently
                    patterns = [threat_name]
                if trainer:
                    result = trainer.learn_threat(threat_name, patterns, severity='high')
                    parts = [f"I've learned the threat '{threat_name}'. Here's what I did:"]
                    if result.get('yara_rule'):
                        parts.append(f"  - Generated YARA rule: {result['yara_rule']}")
                    if result.get('knowledge'):
                        parts.append(f"  - Saved to my knowledge base for future reference.")
                    parts.append(f"  - Patterns I'll watch for: {', '.join(patterns[:5])}")
                    parts.append("\nThis threat will now be detected in future YARA scans. You can also ask me about it anytime.")
                    return '\n'.join(parts)
                return "I'd learn that threat, but my training system isn't available right now."

        # --- Show learned YARA rules ---
        if any(w in q for w in ('learned rules', 'yara rules', 'generated rules', 'show rules')):
            if trainer:
                rules = trainer.get_learned_yara_rules()
                ai_rules = trainer.get_ai_improved_rules()
                if not rules and not ai_rules:
                    return "I haven't generated any YARA rules yet. You can teach me threats by saying 'learn threat <name> with patterns <pattern1, pattern2, ...>' and I'll generate YARA rules that detect them in future scans. I also auto-generate rules from any findings agents report."
                lines = []
                if rules:
                    lines.append(f"Auto-generated YARA rules ({len(rules)}):")
                    for r in rules:
                        lines.append(f"  - {r}")
                if ai_rules:
                    lines.append(f"\nAI-improved YARA rules ({len(ai_rules)}):")
                    for r in ai_rules:
                        lines.append(f"  - {r}")
                lines.append("\nThese rules are active and will be used in all future YARA scans.")
                return '\n'.join(lines)
            return "My training system isn't available right now."

        # --- Improve YARA rules from findings ---
        if any(w in q for w in ('improve rules', 'update rules', 'improve yara', 'update yara', 'better rules')):
            if trainer:
                findings = analysis.get('priority_findings') or []
                if findings:
                    improvements = trainer.auto_improve_from_findings(findings)
                    if improvements:
                        lines = ["I've improved my detection rules. Here's what I updated:\n"]
                        for imp in improvements:
                            lines.append(f"  - {imp}")
                        lines.append("\nThese improvements are now active in the YARA scanner.")
                        return '\n'.join(lines)
                # Check if we already have improvements
                stats = trainer.get_improvement_stats()
                if stats['total_improvements'] > 0:
                    return f"I've already made {stats['total_improvements']} improvement(s) to my code — {stats['yara_rules_updated']} YARA rule update(s) and {stats['ml_features_added']} ML feature addition(s). The rules are already up to date with the latest patterns I've learned. Say 'show improvements' to see the details."
                return "There are no findings to learn from right now. Once agents report threats, I'll automatically improve the YARA rules with new patterns I discover. You can also say 'learn threat <name> with patterns <p1, p2>' to teach me manually."

        # --- Show code improvements ---
        if any(w in q for w in ('code improvements', 'what have you improved', 'show improvements', 'self improved')):
            if trainer:
                stats = trainer.get_improvement_stats()
                features = trainer.get_learned_features()
                ai_rules = trainer.get_ai_improved_rules()
                lines = ["Here's what I've improved in my own code:\n"]
                lines.append(f"Total improvements made: {stats['total_improvements']}")
                lines.append(f"YARA rules updated: {stats['yara_rules_updated']}")
                lines.append(f"ML features added: {stats['ml_features_added']}")
                if ai_rules:
                    lines.append(f"\nAI-improved YARA rules ({len(ai_rules)}):")
                    for r in ai_rules:
                        lines.append(f"  - {r}")
                if features:
                    lines.append(f"\nLearned ML features ({len(features)}):")
                    for f in features:
                        lines.append(f"  - {f}")
                return '\n'.join(lines)
            return "My training system isn't available right now."

        # --- Retrain ML from feedback ---
        if any(w in q for w in ('retrain', 'retrain model', 'update ml', 'train model', 'train ml')):
            if trainer:
                ok = trainer.train_ml_from_feedback()
                if ok:
                    return "Done. I've retrained the ML model using all accumulated feedback and false positive data. The model is now smarter — it'll be better at distinguishing real threats from safe files."
                return "I couldn't retrain the ML model right now. Make sure I have some feedback or false positive data to learn from first."
            return "My training system isn't available right now."

        # --- Scan a file for malware ---
        if q.startswith('scan ') or q.startswith('check file ') or q.startswith('is this file safe'):
            import re as _re
            path_match = _re.search(r'(?:scan|check file|is this file safe)\s+([a-zA-Z]:\\[^\s]+|/[^\s]+\.\w{2,5})', q)
            if path_match and trainer:
                filepath = path_match.group(1)
                result = trainer.scan_file(filepath)
                if result.get('error'):
                    return f"I couldn't scan that file: {result['error']}"
                score = result.get('risk_score', 0)
                sev = result.get('severity', 'unknown')
                matches = result.get('yara_rules_matched', [])
                threat_type = result.get('threat_type', 'unknown')
                ml_anom = result.get('ml_anomaly', False)
                lines = [f"I scanned {filepath}. Here's what I found:\n"]
                lines.append(f"Risk score: {score}/100 — Severity: {sev}")
                if threat_type != 'unknown':
                    lines.append(f"Threat type: {threat_type}")
                if matches:
                    lines.append(f"YARA rules matched: {', '.join(matches)}")
                else:
                    lines.append("No YARA rules matched.")
                if ml_anom:
                    lines.append("ML model flagged this as anomalous.")
                if score == 0:
                    lines.append("\nThis file looks clean. No threats detected.")
                elif score >= 70:
                    lines.append(f"\nThis file is likely malicious. I'd recommend quarantining it immediately.")
                elif score >= 40:
                    lines.append(f"\nThis file is suspicious. I'd investigate further before running it.")
                else:
                    lines.append(f"\nThis file has some minor indicators but probably isn't dangerous.")
                return '\n'.join(lines)
            return "Tell me which file to scan — say 'scan C:/path/to/file.exe'."

        # --- Check knowledge base first (before threat matching) ---
        if not _skip_knowledge:
            relevant = trainer.search_knowledge(question) if trainer else []
            if relevant and not any(w in q for w in ('train', 'teach', 'remember', 'mark', 'forget', 'threat', 'suspicious', 'agent', 'behavior')):
                knowledge_text = "\n".join(f"  - {k.get('topic','?')}: {k.get('content','')}" for k in relevant[:3])
                base_answer = LocalFindingsAssistant._converse(question, analysis, trainer, _skip_knowledge=True)
                return f"{base_answer}\n\nFrom my training, I also know:\n{knowledge_text}"

        # --- Threats / suspicious activity ---
        if any(w in q for w in ('suspicious', 'threat', 'attack', 'danger', 'malware', 'virus', 'ransomware', 'infected', 'compromis')):
            if not findings and not events:
                return "Everything looks clean. No threats, no suspicious activity, no anomalies. Your agents are watching and nothing has triggered any alarms. If something comes up, I'll know about it."
            parts = ["Here's what's on my radar:\n"]
            if findings:
                parts.append("Top threats:")
                for item in findings[:10]:
                    src = item.get('source', 'unknown')
                    parts.append(f"  - {item.get('path','?')}: {item.get('reason', item.get('severity','unknown'))} (caught by {src})")
                parts.append('')
            if events:
                parts.append(f"Recent suspicious activity ({len(events)} events):")
                for ev in events[-10:]:
                    if isinstance(ev, dict):
                        parts.append(f"  - {ev.get('type','event')} from {ev.get('device_id','?')}: {ev.get('summary', ev.get('message', json.dumps(ev)[:120]))}")
            parts.append("\nWant me to pull the IOCs from these, or suggest next steps?")
            return '\n'.join(parts)

        # --- IOCs ---
        if any(w in q for w in ('ioc', 'indicator', 'hash', 'domain', 'ip address', 'ip ')):
            h = len(iocs.get('hashes', []))
            ips = len(iocs.get('ips', []))
            doms = len(iocs.get('domains', []))
            if h + ips + doms == 0:
                return "I don't have any IOCs right now. Once agents start reporting findings with file hashes, IP addresses, or domains, I'll extract and list them for you."
            parts = [f"I've extracted {h} hash(es), {ips} IP(s), and {doms} domain(s) from the current findings:\n"]
            if iocs.get('hashes'):
                parts.append("Hashes: " + ', '.join(iocs['hashes'][:10]))
            if iocs.get('ips'):
                parts.append("IPs: " + ', '.join(iocs['ips'][:10]))
            if iocs.get('domains'):
                parts.append("Domains: " + ', '.join(iocs['domains'][:10]))
            return '\n'.join(parts)

        # --- Incident report ---
        if any(w in q for w in ('report', 'incident', 'summary', 'summarize', 'brief')):
            return LocalFindingsAssistant._report(analysis)

        # --- False positive ---
        if any(w in q for w in ('false positive', 'legitimate', 'safe file', 'not malware', 'mistake')):
            return "It's hard to be 100% sure something is a false positive just from a scan result. Here's what I'd check: Who published the file? Is the path normal for that software? Does the hash show up as clean on reputation services? How specific was the YARA rule that flagged it? Have we seen this file before in scan history without issues? If all of those check out, it's probably safe to allow. If anything looks off, keep it quarantined."

        # --- Scan history / comparison ---
        if any(w in q for w in ('compare', 'change', 'yesterday', 'previous', 'history', 'before', 'last scan')):
            if not history:
                return "I don't have any scan history to compare against yet. Once multiple scans have been recorded, I can tell you what changed between them — new findings, resolved threats, that kind of thing."
            return f"I've got {history_count} historical scan record(s) to work with. I can compare the current findings against previous scans to see what's new, what's gone, and what's getting worse. What specifically do you want to compare?"

        # --- Quarantine ---
        if any(w in q for w in ('quarantine', 'isolated', 'contained', 'locked')):
            if quarantined:
                return f"There are {quarantined} file(s) in quarantine right now. They're contained and can't execute. If you want to review or restore any of them, you can do that through the dashboard. Want me to check if any of them might be false positives?"
            return "Nothing's in quarantine right now. The system is clean. If threats get detected, they'll be isolated automatically and I'll let you know."

        # --- How does something work / capabilities ---
        if any(w in q for w in ('how does', 'how do', 'what can you', 'help me', 'capabilit', 'feature')):
            return ("I can answer questions about what's happening across your antivirus system. "
                    "Here's what I can tell you about:\n\n"
                    "- Connected agents and what they're doing\n"
                    "- Threats and suspicious activity\n"
                    "- IOCs (hashes, IPs, domains) from findings\n"
                    "- Incident reports and summaries\n"
                    "- Scan history and changes over time\n"
                    "- Quarantined files\n"
                    "- Remediation steps\n"
                    "- False positive analysis\n\n"
                    "Just ask me naturally — like you're talking to a person. What do you want to know?")

        # --- Training commands ---
        if any(w in q for w in ('train', 'learning', 'teach you', 'teach me', 'feedback', 'trained')):
            stats = trainer.get_training_summary() if trainer else {'feedback': {'total': 0, 'good': 0, 'bad': 0, 'good_rate': 0}, 'false_positives': 0, 'knowledge_entries': 0, 'yara_rules_generated': 0, 'ml_trained': 0}
            fb = stats['feedback']
            lines = [
                "Here's everything I've learned so far:\n",
                f"- Feedback: {fb['total']} response(s) rated — {fb['good']} good, {fb['bad']} bad ({fb['good_rate']}% good rate).",
                f"- False positives learned: {stats['false_positives']} file(s) I now know are safe.",
                f"- Knowledge entries: {stats['knowledge_entries']} topic(s) I can reference.",
                f"- YARA rules generated: {stats['yara_rules_generated']} rule(s) actively scanning for learned threats.",
                f"- ML training samples: {stats['ml_trained']} sample(s) used to train the anomaly detection model.\n",
                "You can train me by:",
                "  - 'remember that <topic> is <info>' — I'll use that knowledge in future answers.",
                "  - 'learn threat <name> with patterns <p1, p2, ...>' — I'll generate a YARA rule AND save knowledge.",
                "  - 'mark <path> as false positive' — I'll stop flagging it AND train the ML model it's safe.",
                "  - 'retrain model' — I'll retrain the ML model from all accumulated feedback.",
                "  - 'show rules' — See all YARA rules I've generated.",
                "  - 'what have you learned' — See my full training summary.",
            ]
            return '\n'.join(lines)

        if any(w in q for w in ('what have you learned', 'training summary', 'what do you know')):
            stats = trainer.get_training_summary() if trainer else {'feedback': {'total': 0, 'good': 0, 'bad': 0, 'good_rate': 0}, 'false_positives': 0, 'knowledge_entries': 0, 'yara_rules_generated': 0, 'ml_trained': 0}
            auto_stats = trainer.get_auto_learn_stats() if trainer else {}
            db_stats = stats.get('database', {}) if trainer else {}
            fb = stats['feedback']
            lines = [f"Here's my full training summary:\n"]
            lines.append(f"I've received {fb['total']} feedback rating(s) — {fb['good']} positive, {fb['bad']} negative. My good response rate is {fb['good_rate']}%.")
            lines.append(f"I know about {stats['false_positives']} false positive(s) — files I won't flag as threats anymore.")
            lines.append(f"I have {stats['knowledge_entries']} knowledge entr(y/ies) stored that I can reference when answering questions.")
            lines.append(f"I've generated {stats['yara_rules_generated']} YARA rule(s) that actively scan for threats I've learned.")
            lines.append(f"The ML model has been trained on {stats['ml_trained']} sample(s) for anomaly detection.")
            if db_stats:
                lines.append(f"\nDatabase learning stats:")
                lines.append(f"  - Findings recorded: {db_stats['findings']['total']}")
                lines.append(f"  - Confirmed threats: {db_stats['findings']['confirmed_threats']}")
                lines.append(f"  - Malware signatures: {db_stats['malware_signatures']}")
                lines.append(f"  - ML training samples: {db_stats['ml_samples']}")
                lines.append(f"  - Learning events: {db_stats['learning_events']['total_events']}")
                lines.append(f"  - Agent reports: {db_stats['agent_reports']['total_reports']}")
                lines.append(f"  - Score adjustments: {db_stats['score_adjustments']}")
                ft = db_stats['findings'].get('by_threat_type', {})
                if ft:
                    lines.append(f"\nThreat types I've seen:")
                    for tt, count in list(ft.items())[:10]:
                        lines.append(f"  - {tt}: {count} time(s)")
            if auto_stats:
                lines.append(f"\nSelf-learning stats:")
                lines.append(f"  - Auto-learning events: {auto_stats.get('total_events', 0)}")
                lines.append(f"  - YARA rules auto-generated: {auto_stats.get('auto_yara_rules', 0)}")
                lines.append(f"  - ML auto-training sessions: {auto_stats.get('auto_ml_trains', 0)}")
                lines.append(f"  - Good answers I gave: {auto_stats.get('good_answers', 0)}")
                lines.append(f"  - Bad answers (to improve): {auto_stats.get('bad_answers', 0)}")
                lines.append(f"  - False positive candidates: {auto_stats.get('false_positive_candidates', 0)}")
            if trainer:
                fps = trainer.get_false_positives()
                if fps:
                    lines.append("\nKnown false positives:")
                    for fp in fps[:10]:
                        lines.append(f"  - {fp.get('path','?')}")
                knowledge = trainer.get_knowledge()
                if knowledge:
                    lines.append(f"\nKnowledge topics ({len(knowledge)} total):")
                    for k in knowledge[:15]:
                        lines.append(f"  - {k.get('topic','?')}")
                    if len(knowledge) > 15:
                        lines.append(f"  ... and {len(knowledge) - 15} more")
                rules = trainer.get_learned_yara_rules()
                if rules:
                    lines.append("\nGenerated YARA rules:")
                    for r in rules:
                        lines.append(f"  - {r}")
            return '\n'.join(lines)

        # --- Yes/no / follow-up ---
        if q in ('yes', 'yeah', 'yep', 'sure', 'ok', 'okay', 'go ahead', 'do it'):
            return "Alright — tell me what you'd like me to look into. Agents, threats, IOCs, a report? I'm ready when you are."

        if q in ('no', 'nope', 'nah', 'not really'):
            return "No problem. I'm here whenever you need me."

        # --- Default: intelligent conversational response ---
        # Try to relate the question to available data
        parts = []
        parts.append(f"That's a good question. Let me think about what I know right now.\n")
        if agents:
            parts.append(f"I can see {len(agents)} agent(s) connected. ")
            if findings:
                parts.append(f"There are {analysis['finding_count']} finding(s) total, with {len(findings)} ranked as high priority. ")
            else:
                parts.append("They haven't reported any findings yet — things look quiet. ")
        else:
            parts.append("No agents are connected right now, so I don't have live data to work with. ")
        if events:
            parts.append(f"I've also recorded {len(events)} recent event(s) from agent activity. ")
        if quarantined:
            parts.append(f"There are {quarantined} file(s) in quarantine. ")
        parts.append("\n\nCould you ask me more specifically? For example, you could ask about threats, agents, IOCs, or ask for an incident report. I'll give you the most useful answer I can based on what I'm seeing.")
        return ''.join(parts)

    @staticmethod
    def _fallback_answer(question, analysis, trainer=None):
        return LocalFindingsAssistant._converse(question, analysis, trainer)

    def answer(self, question, context=None):
        question = (question or '').strip()
        if not question:
            return {'answer': "Hey! I'm your security assistant. Ask me anything — what's happening, what the agents are doing, any threats, IOCs, or if you want an incident report. I'm listening.", 'mode': 'findings'}
        context = context if isinstance(context, dict) else {}
        context.setdefault('scan_history', self.load_history())
        analysis = self._analysis(context)
        model = self._load_model()
        if model is not None:
            evidence = json.dumps(analysis, ensure_ascii=False)[:60000]
            prompt = (
                'You are a local antivirus investigation assistant. Use only the supplied JSON evidence. '
                'Do not invent detections, claim certainty, execute actions, or give unsupported conclusions. '
                'Explain YARA reasons, prioritize risk, correlate paths and IOCs, compare only supplied history, '
                'and give safe remediation guidance. State when evidence is missing.\n\n'
                f'Evidence:\n{evidence}\n\nQuestion: {question}'
            )
            result = model.create_chat_completion(messages=[
                {'role': 'system', 'content': 'Answer safely and concisely using local evidence only.'},
                {'role': 'user', 'content': prompt},
            ], max_tokens=500, temperature=0.2)
            answer_text = result['choices'][0]['message']['content'].strip()
            # Auto-learn from this interaction
            self._auto_learn(question, answer_text, analysis)
            return {'answer': answer_text, 'mode': 'llama.cpp', 'analysis': analysis}
        answer_text = self._fallback_answer(question, analysis, self._trainer)
        # Auto-learn from this interaction
        self._auto_learn(question, answer_text, analysis)
        return {'answer': answer_text, 'mode': 'findings', 'analysis': analysis, 'model_error': self._model_error}

    def _auto_learn(self, question, answer, analysis):
        """Auto-learn from every interaction — improves YARA, ML, and knowledge."""
        try:
            if self._trainer:
                self._trainer.auto_learn_from_interaction(question, answer, analysis)
        except Exception:
            pass  # Never let auto-learning break the answer
