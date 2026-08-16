"""Download the optional local GGUF assistant model.

The model is downloaded only when this script is run explicitly. It is not
committed to Git or bundled automatically because it is still a large file.
"""
import os
from pathlib import Path
from urllib.request import Request, urlopen


MODEL_URL = 'https://huggingface.co/unsloth/Qwen3-4B-GGUF/resolve/main/Qwen3-4B-Q2_K.gguf?download=true'
MODEL_PATH = Path(__file__).resolve().parents[1] / 'models' / 'assistant.gguf'


def main():
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    temp_path = MODEL_PATH.with_suffix('.gguf.download')
    request = Request(MODEL_URL, headers={'User-Agent': 'antivirus-server-local-model-setup'})
    print(f'Downloading local assistant model to {MODEL_PATH}...')
    try:
        with urlopen(request, timeout=60) as response, temp_path.open('wb') as output:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                output.write(chunk)
        os.replace(temp_path, MODEL_PATH)
    finally:
        temp_path.unlink(missing_ok=True)
    print('Downloaded Qwen3-4B Q2_K GGUF model.')
    print('Install llama-cpp-python separately before enabling model inference.')


if __name__ == '__main__':
    main()
