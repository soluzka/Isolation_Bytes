"""
ssdeep_runner.py

Compute ssdeep for target files, compare against ssdeep values embedded in YARA rule meta,
and run YARA rules for exact matches. Prints combined results.

Usage:
  python ssdeep_runner.py --rules yara_rules.yar --target sample.exe
  python ssdeep_runner.py --rules yara_rules.yar --dir samples/ --threshold 60

Dependencies:
  pip install yara-python ssdeep
  (Optional) pip install pefile if you want to compute imphash locally

Notes:
 - YARA cannot compute ssdeep during evaluation. This script uses metadata in rules
   (meta: ssdeep = "...") and compares them to file ssdeep using the ssdeep library.
 - Put ssdeep strings into rules' meta before running, or use this script to compare
   against known hashes.
"""

import argparse
import os
import re
import sys

# ssdeep import: prefer 'ssdeep' package, fall back to 'pyssdeep' if available
try:
    import ssdeep
    _ssdeep_has_hash = hasattr(ssdeep, 'hash')
    _ssdeep_has_compare = hasattr(ssdeep, 'compare')
except Exception:
    try:
        import pyssdeep as ssdeep
        _ssdeep_has_hash = hasattr(ssdeep, 'fuzzy_hash_filename') or hasattr(ssdeep, 'fuzzy_hash_buf')
        _ssdeep_has_compare = hasattr(ssdeep, 'compare') or hasattr(ssdeep, 'fuzzy_compare')
    except Exception:
        ssdeep = None
        _ssdeep_has_hash = False
        _ssdeep_has_compare = False

try:
    import yara
except Exception:
    yara = None


def parse_rules_meta_ssdeep(rule_path):
    """Parse the rules file and extract ssdeep/imphash meta entries per rule.
    Returns dict: { rule_name: { 'ssdeep': '...', 'imphash': '...' } }
    """
    data = open(rule_path, 'r', encoding='utf-8', errors='ignore').read()
    # Find top-level rule blocks. This is a simple heuristic that works for
    # typical YARA files: 'rule <name> { ... }'
    rule_pattern = re.compile(r'rule\s+([A-Za-z0-9_\-]+)\s*\{([\s\S]*?)\n\}', re.MULTILINE)
    meta_pattern = re.compile(r'meta\s*:\s*([\s\S]*?)(?:\n\s*(?:strings|condition)\s*:)', re.IGNORECASE)
    kv_pattern = re.compile(r"([A-Za-z0-9_\-]+)\s*=\s*\"(.*?)\"", re.DOTALL)

    results = {}
    for m in rule_pattern.finditer(data):
        rule_name = m.group(1)
        body = m.group(2)
        ss = None
        imp = None
        # find meta block within body
        mm = meta_pattern.search(body)
        if mm:
            meta_block = mm.group(1)
            for kv in kv_pattern.finditer(meta_block):
                k = kv.group(1).strip()
                v = kv.group(2).strip()
                if k.lower() == 'ssdeep':
                    ss = v
                elif k.lower() == 'imphash':
                    imp = v
        if ss or imp:
            results[rule_name] = {'ssdeep': ss, 'imphash': imp}
    return results


def compute_file_ssdeep(path):
    if ssdeep is None or not _ssdeep_has_hash:
        raise RuntimeError('ssdeep library not installed. pip install ssdeep or pyssdeep')
    # prefer available API
    if hasattr(ssdeep, 'hash'):
        with open(path, 'rb') as f:
            data = f.read()
        return ssdeep.hash(data)
    if hasattr(ssdeep, 'fuzzy_hash_filename'):
        return ssdeep.fuzzy_hash_filename(path)
    if hasattr(ssdeep, 'fuzzy_hash_buf'):
        with open(path, 'rb') as f:
            data = f.read()
        return ssdeep.fuzzy_hash_buf(data)
    raise RuntimeError('No known ssdeep API available in module')


def compile_ruleset(rule_path):
    """Try to compile a ruleset. If compiling the combined file fails (duplicate
    identifiers), attempt to compile each .yar/.yara file found in the same directory
    and return a dict of compiled rule objects.
    Returns either a single compiled object or a dict { filename: compiled_obj } or None.
    """
    if yara is None:
        return None
    try:
        return yara.compile(filepath=rule_path)
    except Exception as e:
        print('yara.compile failed:', e)
        # try compiling each file in the containing directory
        base_dir = rule_path if os.path.isdir(rule_path) else os.path.dirname(rule_path)
        compiled = {}
        for root, _, files in os.walk(base_dir):
            for f in files:
                if f.lower().endswith(('.yar', '.yara')):
                    fp = os.path.join(root, f)
                    try:
                        compiled[f] = yara.compile(filepath=fp)
                    except Exception:
                        # skip files that don't compile standalone
                        continue
        if compiled:
            print(f'Compiled {len(compiled)} individual rule files as a fallback')
            return compiled
        return None


def match_yara(rules_obj, path):
    """Match a file against either a single compiled rules object or a dict of
    compiled rule objects. Returns a list of rule names that matched.
    """
    if rules_obj is None:
        return []

    results = set()
    if isinstance(rules_obj, dict):
        for name, obj in rules_obj.items():
            try:
                matches = obj.match(path)
                results.update(m.rule for m in matches)
            except Exception:
                try:
                    with open(path, 'rb') as fh:
                        data = fh.read()
                    matches = obj.match(data=data)
                    results.update(m.rule for m in matches)
                except Exception:
                    print('YARA match failed for data buffer', file=sys.stderr)
        return list(results)

    # single compiled object
    try:
        matches = rules_obj.match(path)
        return [m.rule for m in matches]
    except Exception:
        try:
            with open(path, 'rb') as fh:
                data = fh.read()
            matches = rules_obj.match(data=data)
            return [m.rule for m in matches]
        except Exception:
            return []


def main():
    p = argparse.ArgumentParser(description='YARA + ssdeep fuzzy runner')
    p.add_argument('--rules', required=True, help='YARA rules file path')
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument('--target', help='Single file to scan')
    g.add_argument('--dir', help='Directory of files to scan (recursively)')
    p.add_argument('--threshold', type=int, default=60, help='ssdeep match threshold (0-100)')
    p.add_argument('--yara-timeout', type=int, default=10, help='YARA match timeout (seconds)')
    args = p.parse_args()

    if not os.path.exists(args.rules):
        print('Rules file not found:', args.rules)
        sys.exit(2)

    meta_map = parse_rules_meta_ssdeep(args.rules)
    print(f'Parsed {len(meta_map)} rules containing ssdeep/imphash meta entries')

    rules_obj = compile_ruleset(args.rules)
    if rules_obj is None and yara is None:
        print('yara-python not installed; will only perform ssdeep comparisons if possible')

    targets = []
    if args.target:
        if os.path.isfile(args.target):
            targets = [args.target]
        else:
            print('Target file not found:', args.target)
            sys.exit(2)
    else:
        for root, _, files in os.walk(args.dir):
            for fn in files:
                targets.append(os.path.join(root, fn))

    if not targets:
        print('No target files found')
        sys.exit(0)

    for t in targets:
        print('\n== File: {} =='.format(t))
        try:
            file_ss = compute_file_ssdeep(t) if ssdeep is not None else None
        except Exception as e:
            print('ssdeep compute failed:', e)
            file_ss = None

        yara_matches = match_yara(rules_obj, t) if rules_obj is not None else []
        if yara_matches:
            print('YARA direct matches:', ', '.join(yara_matches))

        fuzzy_hits = []
        if file_ss is not None and meta_map:
            for rname, metas in meta_map.items():
                rs = metas.get('ssdeep')
                if not rs:
                    continue
                try:
                    score = ssdeep.compare(file_ss, rs)
                    if score >= args.threshold:
                        fuzzy_hits.append((rname, score))
                except Exception:
                    print('ssdeep comparison failed for rule', rname, file=sys.stderr)

        if fuzzy_hits:
            fuzzy_hits.sort(key=lambda x: -x[1])
            print('Fuzzy matches (ssdeep >= {}):'.format(args.threshold))
            for name, score in fuzzy_hits:
                print(f'  {name}: {score}')
        else:
            if file_ss is None:
                print('ssdeep not available; install the ssdeep package to enable fuzzy matching')
            else:
                print('No fuzzy matches (threshold {})'.format(args.threshold))

        # Suggest combined result
        combined = set(yara_matches) | {n for n, _ in fuzzy_hits}
        if combined:
            print('Combined matches/suspicions:', ', '.join(sorted(combined)))
        else:
            print('No matches detected')


if __name__ == '__main__':
    main()
