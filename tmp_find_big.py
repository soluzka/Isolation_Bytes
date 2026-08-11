import subprocess
out = subprocess.check_output(['git', 'rev-list', '--objects', 'HEAD'], text=True, errors='replace')
big = []
for line in out.splitlines():
    parts = line.split(maxsplit=1)
    if not parts:
        continue
    sha = parts[0]
    name = parts[1] if len(parts) > 1 else ''
    try:
        if subprocess.check_output(['git', 'cat-file', '-t', sha], text=True).strip() != 'blob':
            continue
        sz = int(subprocess.check_output(['git', 'cat-file', '-s', sha]).strip())
        if sz > 100*1024*1024:
            big.append((sha, sz, name))
    except Exception:
        continue
print(f'Found {len(big)} blobs > 100 MB in HEAD')
for sha, sz, name in big:
    print(f'{sha[:12]} {sz / (1024*1024):.1f} MB {name}')
