"""Download the optional local GGUF assistant model.

The model is downloaded only when this script is run explicitly. It is not
committed to Git or bundled automatically because it is several gigabytes.
"""
from pathlib import Path
from urllib.request import Request, urlopen


MODEL_URL = 'https://huggingface.co/Qwen/Qwen3-8B-GGUF/resolve/main/Qwen3-8B-Q4_K_M.gguf?download=true'
MODEL_PATH = Path(__file__).resolve().parents[1] / 'models' / 'assistant.gguf'


def main():
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    request = Request(MODEL_URL, headers={'User-Agent': 'antivirus-server-local-model-setup'})
    print(f'Downloading local assistant model to {MODEL_PATH}...')
    with urlopen(request, timeout=60) as response, MODEL_PATH.open('wb') as output:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            output.write(chunk)
    print('Downloaded Qwen3-8B Q4_K_M GGUF model.')
    print('Install llama-cpp-python separately before enabling model inference.')


if __name__ == '__main__':
    main()
