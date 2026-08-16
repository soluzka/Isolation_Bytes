"""Local findings assistant with an optional llama.cpp backend."""
import json
import os
from pathlib import Path


class LocalFindingsAssistant:
    def __init__(self, base_dir=None):
        self.base_dir = Path(base_dir or os.path.dirname(os.path.dirname(__file__)))
        self._model = None
        self._model_error = None

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
    def _findings_summary(context):
        if not isinstance(context, dict):
            return 'No scan context was provided.'
        findings = context.get('findings') or context.get('results') or []
        if isinstance(findings, dict):
            findings = list(findings.values())
        if not findings:
            return 'No current findings are available.'
        lines = []
        for item in findings[:20]:
            if isinstance(item, dict):
                lines.append(json.dumps({
                    key: item.get(key) for key in ('path', 'reason', 'source', 'severity')
                    if item.get(key) is not None
                }, ensure_ascii=False))
            else:
                lines.append(str(item))
        return '\n'.join(lines)

    def answer(self, question, context=None):
        question = (question or '').strip()
        if not question:
            return {'answer': 'Ask about a scan, detection, process, or network finding.', 'mode': 'findings'}
        summary = self._findings_summary(context)
        model = self._load_model()
        if model is not None:
            prompt = (
                'You are a local antivirus findings assistant. Use only the supplied '
                'context. Do not invent detections or claim certainty. Explain clearly.\n\n'
                f'Findings:\n{summary}\n\nQuestion: {question}'
            )
            result = model.create_chat_completion(messages=[
                {'role': 'system', 'content': 'Answer safely and concisely using local findings only.'},
                {'role': 'user', 'content': prompt},
            ], max_tokens=350, temperature=0.2)
            return {'answer': result['choices'][0]['message']['content'].strip(), 'mode': 'llama.cpp'}

        lower = question.lower()
        if 'why' in lower or 'explain' in lower:
            answer = f'Here is the local findings context:\n{summary}'
        elif 'admin' in lower or 'elevat' in lower:
            answer = 'Administrator privileges are required for some network, quarantine, and protected-file operations.'
        else:
            answer = f'Local findings mode has no language model installed. Current context:\n{summary}'
        return {'answer': answer, 'mode': 'findings'}
