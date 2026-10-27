"""Bounded local Vale lint artifact. Does not approve or publish documents."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import threading

VERSION = '3.25.1'
MAX_INPUT = 262144
MAX_OUTPUT = 1048576
TIMEOUT = 10
HERE = Path(__file__).resolve().parent

class Rejected(Exception):
    pass

def digest(data):
    return hashlib.sha256(data).hexdigest()

def regular(path):
    path = Path(path)
    if not path.is_absolute() or any(p.is_symlink() for p in [path, *path.parents]):
        raise Rejected('unsafe_path')
    if not path.is_file():
        raise Rejected('missing_regular_file')
    return path

def bounded(argv, cwd, env, timeout=TIMEOUT):
    """Continuously drain pipes with a shared hard byte cap; never echo diagnostics."""
    proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
    chunks = [bytearray(), bytearray()]
    lock = threading.Lock()
    overflow = threading.Event()
    def drain(stream, index):
        while True:
            block = stream.read(4096)
            if not block:
                break
            with lock:
                if sum(map(len, chunks)) + len(block) > MAX_OUTPUT:
                    overflow.set()
                    proc.kill()
                    break
                chunks[index].extend(block)
        stream.close()
    threads = [threading.Thread(target=drain, args=(pipe, i), daemon=True)
               for i, pipe in enumerate((proc.stdout, proc.stderr))]
    for thread in threads:
        thread.start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        raise Rejected('timeout')
    finally:
        for thread in threads:
            thread.join(timeout=1)
    if any(thread.is_alive() for thread in threads):
        raise Rejected('pipe_timeout')
    if overflow.is_set():
        raise Rejected('output_limit')
    return proc.returncode, bytes(chunks[0]), bytes(chunks[1])

def lint(binary, expected_sha256, input_root, relative):
    result = {'schema_version': 1, 'status': 'failed', 'outbound_state': 'HOLD',
              'approval_required': True, 'publication_authorized': False, 'findings': []}
    try:
        if not re.fullmatch('[a-f0-9]{64}', expected_sha256):
            raise Rejected('invalid_executable_digest')
        binary = regular(binary)
        if binary.stat().st_size > 67108864 or digest(binary.read_bytes()) != expected_sha256:
            raise Rejected('executable_digest_mismatch')
        root = Path(input_root)
        if not root.is_absolute() or not root.is_dir() or any(p.is_symlink() for p in [root, *root.parents]):
            raise Rejected('unsafe_input_root')
        rel = Path(relative)
        if rel.is_absolute() or len(rel.parts) != 1 or rel.name.startswith('-') or rel.suffix != '.txt':
            raise Rejected('unsafe_document_path')
        document = regular(root / rel)
        if document.stat().st_size > MAX_INPUT:
            raise Rejected('input_limit')
        content = document.read_bytes()
        if len(content) > MAX_INPUT:
            raise Rejected('input_limit')
        text = content.decode('utf-8', errors='strict')
        # Reject complete off/on keywords (including punctuation boundaries), not
        # ordinary words such as offers/only; keep rule assignments and NUL denied.
        if '\x00' in text or re.search(r'(?i)vale\s+(?:(?:off|on)\b|[\w.]+\s*=)', text):
            raise Rejected('document_directive')
        config = regular(HERE / '.vale.ini').read_bytes()
        rule = regular(HERE / 'styles' / 'Local' / 'Guard.yml').read_bytes()
        pins = json.loads(regular(HERE / 'config-pins.json').read_text(encoding='utf-8-sig'))
        if digest(config) != pins['config_sha256'] or digest(rule) != pins['rule_sha256']:
            raise Rejected('configuration_digest_mismatch')
        with tempfile.TemporaryDirectory(prefix='cp080-') as tmp:
            work = Path(tmp)
            (work / 'styles' / 'Local').mkdir(parents=True)
            (work / '.vale.ini').write_bytes(config)
            (work / 'styles' / 'Local' / 'Guard.yml').write_bytes(rule)
            (work / 'document.txt').write_bytes(content)
            (work / 'home').mkdir()
            env = {'HOME': str(work / 'home'), 'XDG_CONFIG_HOME': str(work / 'home'),
                   'TMPDIR': str(work), 'TMP': str(work), 'TEMP': str(work), 'LANG': 'C.UTF-8'}
            code, out, err = bounded([str(binary), '--version'], tmp, env)
            if code != 0 or err or not re.fullmatch(rb'vale version 3\.25\.1\s*', out):
                raise Rejected('unsupported_version')
            code, out, err = bounded([str(binary), '--no-global', '--config=' + str(work / '.vale.ini'),
                                      '--output=JSON', str(work / 'document.txt')], tmp, env)
            if code not in (0, 1) or err:
                raise Rejected('vale_execution_error')
            parsed = json.loads(out)
            if not isinstance(parsed, dict) or set(parsed) - {str(work / 'document.txt'), 'document.txt'}:
                raise Rejected('unexpected_report')
            findings = []
            for alerts in parsed.values():
                if not isinstance(alerts, list) or len(alerts) > 4096:
                    raise Rejected('unexpected_report')
                for alert in alerts:
                    if (alert.get('Check') != 'Local.Guard' or alert.get('Severity') != 'warning'
                            or type(alert.get('Line')) is not int or alert['Line'] < 1):
                        raise Rejected('unexpected_alert')
                    findings.append({'rule': 'Local.Guard', 'severity': 'warning', 'line': alert['Line']})
            # This package has only a warning rule: exit 1 is inconsistent.
            if code != 0:
                raise Rejected('unexpected_exit')
            result.update(status='lint_findings' if findings else 'lint_clean', findings=findings,
                          input_sha256=digest(content), config_sha256=digest(config),
                          rule_sha256=digest(rule), executable_sha256=expected_sha256, version=VERSION)
    except Rejected as exc:
        result['error_code'] = str(exc)
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        result['error_code'] = 'invalid_input_or_report'
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--executable-sha256', required=True)
    parser.add_argument('--input-root', required=True)
    parser.add_argument('document')
    args = parser.parse_args()
    result = lint(args.binary, args.executable_sha256, args.input_root, args.document)
    print(json.dumps(result, sort_keys=True))
    return 2 if result['status'] == 'failed' else 0

if __name__ == '__main__':
    raise SystemExit(main())
