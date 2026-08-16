"""Local findings assistant with bounded, evidence-based analysis."""
import datetime
import ipaddress
import json
import os
import re
from collections import Counter
from pathlib import Path


_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,128}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class LocalFindingsAssistant:
    def __init__(self, base_dir=None):
        self.base_dir = Path(base_dir or os.path.dirname(os.path.dirname(__file__)))
        self._model = None
        self._model_error = None

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
        if self._model is not None or self._model_error:
            return self._model
        model_path = self._model_path()
        if model_path is None:
            self._model_error = 'No local GGUF model is installed; using findings mode.'
            return None
        try:
            from llama_cpp import Llama
            self._model = Llama(model_path=str(model_path), n_ctx=4096, verbose=False)
        except Exception as error:
            self._model_error = f'Local model unavailable; using findings mode: {error}'
        return self._model

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
        ranked = sorted(findings, key=self._priority, reverse=True)
        categories = Counter(str(item.get('source') or item.get('category') or 'unknown') for item in findings)
        paths = [item.get('path') for item in findings if item.get('path')]
        history = context.get('scan_history') or []
        quarantined = context.get('quarantine') or context.get('quarantined_files') or []
        service = context.get('service_status') or {}
        return {
            'finding_count': len(findings),
            'priority_findings': ranked[:20],
            'categories': dict(categories),
            'unique_paths': sorted(set(paths))[:100],
            'iocs': self._extract_iocs(findings),
            'scan_history_available': bool(history),
            'scan_history_count': len(history) if isinstance(history, list) else 0,
            'quarantine_count': len(quarantined) if isinstance(quarantined, list) else 0,
            'administrator_service': service,
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
        if analysis['priority_findings']:
            lines.append('Highest-priority findings:')
            for item in analysis['priority_findings'][:10]:
                lines.append(f"- {item.get('path', item.get('value', 'unknown'))}: {item.get('reason', item.get('severity', 'unclassified'))}")
        else:
            lines.append('No findings were supplied; no threat conclusion can be made.')
        return '\n'.join(lines)

    @staticmethod
    def _fallback_answer(question, analysis):
        lower = question.lower()
        if any(word in lower for word in ('report', 'incident', 'summary')):
            return LocalFindingsAssistant._report(analysis)
        if any(word in lower for word in ('ioc', 'indicator', 'hash', 'domain', 'ip')):
            iocs = analysis['iocs']
            return json.dumps(iocs, indent=2)
        if any(word in lower for word in ('admin', 'service', 'elevat')):
            status = analysis['administrator_service']
            return 'Administrator service status: ' + (json.dumps(status) if status else 'not supplied.')
        if any(word in lower for word in ('compare', 'change', 'yesterday', 'previous')):
            return ('Scan history was not supplied, so no comparison can be made.' if not analysis['scan_history_available'] else f"{analysis['scan_history_count']} historical scan record(s) were supplied for comparison.")
        if any(word in lower for word in ('fix', 'remediat', 'next step', 'safe')):
            return 'Review the highest-priority findings, verify the file and publisher, preserve evidence, and use the dashboard confirmation flow for remediation. No action was performed.'
        if any(word in lower for word in ('false positive', 'legitimate', 'safe file')):
            return 'False-positive confidence cannot be established from the supplied context alone. Check publisher, path, hash reputation, rule specificity, and prior scan history.'
        return LocalFindingsAssistant._report(analysis)

    def answer(self, question, context=None):
        question = (question or '').strip()
        if not question:
            return {'answer': 'Ask about findings, scan history, IOCs, remediation, rules, or service status.', 'mode': 'findings'}
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
            return {'answer': result['choices'][0]['message']['content'].strip(), 'mode': 'llama.cpp', 'analysis': analysis}
        return {'answer': self._fallback_answer(question, analysis), 'mode': 'findings', 'analysis': analysis, 'model_error': self._model_error}
