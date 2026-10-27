#!/usr/bin/env bash
# Bounded acquisition precedes network-isolated qualification; no installation.
set -euo pipefail
umask 077
[[ $(uname -s) == Linux && $(uname -m) == x86_64 && $(id -u) != 0 ]] || { echo 'CP080 requires nonroot Linux x86_64' >&2; exit 1; }
for command in python3 curl bwrap timeout prlimit sha256sum tar; do
  command -v "$command" >/dev/null || { echo "CP080 missing required capability: $command" >&2; exit 1; }
done
python3 - <<'CP080_PY'
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tarfile
import tempfile
import threading

ARCHIVE = '4bf5c5176b682b1da0830f471584d3494f1c2e27ee3029e1ad6f6661d4962182'
CHECKSUMS = 'dd2b8190fa4766098a4eb3f864700e34cabc3c6a8148b12fe0bfdd615a811c87'
BINARY = '9ea28f2c9e6f06a76ad187116d46a9568fc15d310808480e4e60ec0f7568390c'
LICENSE = '29a16197c8d01cafcacbd9c1774b66b28d7c0f15a6aceed88e4e8068ea398470'
README = 'd0068972a25b6987a18bb6186783d560002495c22e12944ec332334865393b36'
LIMIT = 67108864
OUTPUT_LIMIT = 1048576
COMPONENT = Path('deploy/components/vale').absolute()
SAFE_ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def snapshot():
    require(not any(p.is_symlink() for p in [COMPONENT, *COMPONENT.parents]), 'symlink component ancestry')
    items = list(COMPONENT.rglob('*'))
    require(not any(p.is_symlink() for p in items), 'component contains symlink')
    files = [p for p in items if p.is_file()]
    require(len(files) == 11, 'expected exactly 11 immutable component files')
    require(all(p.is_file() or p.is_dir() for p in items), 'nonregular component entry')
    return {p.relative_to(COMPONENT).as_posix(): sha(p) for p in files}

def bounded(argv, seconds, cwd=None):
    # timeout contains the whole foreground process group; bwrap dies with parent.
    proc = subprocess.Popen(['/usr/bin/timeout', '--kill-after=5', str(seconds), *argv],
                            cwd=cwd, env=SAFE_ENV, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    chunks = [bytearray(), bytearray()]
    lock = threading.Lock()
    exceeded = threading.Event()
    def drain(pipe, index):
        while True:
            block = pipe.read(4096)
            if not block:
                break
            with lock:
                if sum(map(len, chunks)) + len(block) > OUTPUT_LIMIT:
                    exceeded.set()
                    # TERM timeout itself: timeout forwards TERM to managed group.
                    proc.terminate()
                    break
                chunks[index].extend(block)
        pipe.close()
    threads = [threading.Thread(target=drain, args=(p, i), daemon=True)
               for i, p in enumerate((proc.stdout, proc.stderr))]
    for thread in threads:
        thread.start()
    try:
        code = proc.wait(timeout=seconds + 10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        raise RuntimeError('outer execution deadline exceeded')
    for thread in threads:
        thread.join(timeout=2)
    require(not any(t.is_alive() for t in threads), 'process pipe teardown incomplete')
    require(not exceeded.is_set(), 'bounded process output exceeded 1MiB')
    return code, bytes(chunks[0]), bytes(chunks[1])

# Executed only inside the read-only, no-network, private-tmp sandbox.
SANDBOX = r'''
import errno, hashlib, io, json, os, pathlib, re, socket, subprocess, sys, tempfile, unittest

def check(value, message):
    if not value:
        raise RuntimeError(message)

mode, outer_net = sys.argv[1:3]
check(os.getuid() != 0, 'sandbox UID must be nonroot')
check(os.readlink('/proc/self/ns/net') != outer_net, 'network namespace not isolated')
check(set(os.listdir('/sys/class/net')) <= {'lo'} if os.path.exists('/sys/class/net') else
      set(line.split(':')[0].strip() for line in pathlib.Path('/proc/net/dev').read_text().splitlines()[2:]) <= {'lo'},
      'sandbox has non-loopback network interface')
for family, target in [(socket.AF_INET, ('192.0.2.1', 9)),
                       (socket.AF_INET6, ('2001:db8::1', 9))]:
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            sock.connect(target)
        raise RuntimeError('sandbox unexpectedly has network')
    except OSError as exc:
        check(exc.errno in (errno.ENETUNREACH, errno.EADDRNOTAVAIL, errno.EAFNOSUPPORT),
              'unexpected network probe failure')
st = os.statvfs('/tmp')
check(0 < st.f_blocks * st.f_frsize <= 67108864, 'private tmp exceeds 64MiB quota')
if mode == 'setup':
    # Never touches host tmp: /tmp is this sandbox newly created size-limited tmpfs.
    with tempfile.TemporaryDirectory(prefix='quota-', dir='/tmp') as probe:
        check(os.stat(probe).st_uid == os.getuid(), 'quota probe not private-owned')
        written = 0
        saw_enospc = False
        try:
            for index in range(9):
                with open(probe + '/' + str(index), 'wb', buffering=0) as stream:
                    for _ in range(8):
                        block = b'x' * 1048576
                        count = stream.write(block)
                        written += count
                        check(written <= 68157440, 'quota probe byte budget exceeded')
            raise RuntimeError('quota probe failed to reach ENOSPC')
        except OSError as exc:
            check(exc.errno == errno.ENOSPC, 'quota probe failed for reason other than ENOSPC')
            saw_enospc = True
        check(saw_enospc, 'quota ENOSPC evidence missing')
    check(os.statvfs('/tmp').f_bavail > 0, 'quota probe cleanup failed')
    print('SETUP: nonroot, distinct netns, no route, tmp<=64MiB, private ENOSPC probe cleaned')
elif mode in ('normal', 'optimized'):
    # Capture complete unittest result object and complete bounded text summary.
    class BoundedText(io.StringIO):
        def write(self, text):
            check(self.tell() + len(text) <= 524288, 'test report exceeds limit')
            return super().write(text)
    stream = BoundedText()
    suite = unittest.defaultTestLoader.discover('/component/tests', pattern='test_*.py')
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    report = stream.getvalue()
    print(report, end='')
    check(result.testsRun == 12 and not result.errors and not result.failures and not result.skipped,
          'require exactly 12 tests and zero failures/errors/skips')
    check(re.search(r'Ran 12 tests in [0-9.]+s\s+OK\s*$', report), 'complete unittest summary missing')
    print(json.dumps({'mode':mode,'tests':result.testsRun,'failures':len(result.failures),
                      'errors':len(result.errors),'skips':len(result.skipped)}))
elif mode == 'observer':
    # Direct known pinned Vale, independent from permissive assertNotEqual tests.
    binary = '/artifact/vale'
    env = {'HOME':'/tmp','XDG_CONFIG_HOME':'/tmp','TMPDIR':'/tmp'}
    def observe(argv, cwd=None):
        # Regular files + inherited hard RLIMIT_FSIZE bound output before allocation.
        with tempfile.TemporaryDirectory(dir='/tmp') as capture:
            out_path, err_path = pathlib.Path(capture)/'out', pathlib.Path(capture)/'err'
            with out_path.open('wb') as out, err_path.open('wb') as err:
                proc = subprocess.run(['/usr/bin/prlimit','--fsize=65536',*argv],
                    cwd=cwd, stdout=out, stderr=err, timeout=10, env=env)
            check(out_path.stat().st_size + err_path.stat().st_size <= 65536,
                  'observer combined output exceeded 64KiB')
            return subprocess.CompletedProcess(argv, proc.returncode,
                out_path.read_bytes(), err_path.read_bytes())
    version = observe([binary,'--version'])
    check(version.returncode == 0 and version.stdout.strip() == b'vale version 3.25.1'
          and not version.stderr, 'pinned version probe failed')
    help_result = observe([binary,'--help'])
    check(help_result.returncode == 0 and all(flag in help_result.stdout + help_result.stderr
          for flag in [b'--no-global',b'--config',b'--output',b'--version']), 'required pinned CLI flags absent')
    with tempfile.TemporaryDirectory(dir='/tmp') as tmp:
        p = pathlib.Path(tmp)
        (p/'styles'/'Local').mkdir(parents=True)
        (p/'document.txt').write_text('CP080_FORBIDDEN_PHRASE', encoding='utf-8')
        cases = [
            ('missing-style', 'StylesPath = styles\n[*.txt]\nBasedOnStyles = Missing\n', '', ('Missing',)),
            ('invalid-extends', 'StylesPath = styles\n[*.txt]\nBasedOnStyles = Local\n',
             'extends: nonexistent\nmessage: invalid\n',
             ("'extends' key must be one of [capitalization conditional consistency existence occurrence repetition substitution readability spelling sequence metric script].",)),
        ]
        for name, config, rule, expected in cases:
            (p/'.vale.ini').write_text(config, encoding='utf-8')
            (p/'styles'/'Local'/'Guard.yml').write_text(rule, encoding='utf-8')
            response = observe([binary,'--no-global','--config='+str(p/'.vale.ini'),
                '--output=JSON',str(p/'document.txt')], cwd=tmp)
            # Synthetic fixtures only. Emit bounded actual evidence BEFORE strict
            # predicates; never infer the hidden failure cause or retry it.
            evidence = {
                'event': 'CP080_SYNTHETIC_CONFIG_OBSERVER', 'case': name,
                'returncode': response.returncode,
                'stdout_bytes': len(response.stdout), 'stderr_bytes': len(response.stderr),
                'stdout_sha256': hashlib.sha256(response.stdout).hexdigest(),
                'stderr_sha256': hashlib.sha256(response.stderr).hexdigest(),
                'stdout_preview': response.stdout[:512].decode('utf-8', errors='replace'),
                'stderr_preview': response.stderr[:512].decode('utf-8', errors='replace'),
                'preview_raw_byte_cap_each': 512,
                'stdout_truncated': len(response.stdout) > 512,
                'stderr_truncated': len(response.stderr) > 512,
                'config_sha256': hashlib.sha256((p/'.vale.ini').read_bytes()).hexdigest(),
                'rule_sha256': hashlib.sha256((p/'styles'/'Local'/'Guard.yml').read_bytes()).hexdigest(),
                'fixture_document_sha256': hashlib.sha256((p/'document.txt').read_bytes()).hexdigest(),
                'expected_diagnostic': 'E201', 'expected_terms': expected,
                'observed_version': version.stdout.strip().decode('ascii', errors='replace'),
                'verified_executable_sha256': '9ea28f2c9e6f06a76ad187116d46a9568fc15d310808480e4e60ec0f7568390c',
                'target': {'system': os.uname().sysname, 'machine': os.uname().machine},
                'context': {'cwd': 'private synthetic fixture directory',
                            'config': 'explicit fixture .vale.ini',
                            'flags': ['--no-global', '--output=JSON'],
                            'configured_virtual_AS_perprocess_bytes': 2147483648,
                            'observer_perfile_output_limit_bytes': 65536,
                            'observer_combined_output_limit_bytes': 65536,
                            'timeout_seconds': 10},
            }
            evidence_json = json.dumps(evidence, sort_keys=True, ensure_ascii=True)
            check(len(evidence_json.encode('ascii')) <= 8192, 'observer evidence exceeds 8KiB')
            print(evidence_json, flush=True)
            diagnostic = (response.stdout + response.stderr).decode('utf-8', errors='replace')
            check(len(diagnostic) <= 65536, 'observer diagnostic oversized')
            if name == 'invalid-extends':
                # Pinned 3.25.1 reports allowed extends keys, not the invalid token.
                # Require the complete observed structured stderr error, not a
                # generic nonzero exit or an E201 substring in runtime diagnostics.
                def unique_error_fields(pairs):
                    check(len(pairs) == len(dict(pairs)), 'duplicate structured error fields')
                    return dict(pairs)
                check(response.returncode == 2 and response.stdout == b'',
                      'invalid-extends must have pinned exit 2 and empty stdout')
                error = json.loads(response.stderr.decode('utf-8', errors='strict'),
                                   object_pairs_hook=unique_error_fields)
                check(type(error) is dict and set(error) == {'Line', 'Path', 'Text', 'Code', 'Span'},
                      'invalid-extends structured error shape mismatch')
                check(type(error['Line']) is int and error['Line'] == 1
                      and type(error['Span']) is int and error['Span'] == 10
                      and type(error['Code']) is str and error['Code'] == 'E201'
                      and type(error['Path']) is str
                      and error['Path'] == str(p/'styles'/'Local'/'Guard.yml')
                      and type(error['Text']) is str and error['Text'] == expected[0],
                      'invalid-extends must match pinned E201 Line/Span/Path/extends-key text')
            else:
                check(response.returncode != 0 and 'E201' in diagnostic
                      and all(term in diagnostic for term in expected), name + ' must specifically fail E201')
            check(not re.search(r'(?i)out of memory|cannot allocate|bad_alloc|fatal error|runtime:', diagnostic),
                  name + ' allocation/runtime failure is not expected config evidence')
            print(name + ': E201 expected configuration error confirmed')
    print('OBSERVER: actual Vale version/help and both expected E201 failures confirmed')
else:
    raise RuntimeError('unknown fixed CI mode')
'''

before = snapshot()
outer_net = os.readlink('/proc/self/ns/net')
with tempfile.TemporaryDirectory(prefix='cp080-ci-', dir=os.environ.get('RUNNER_TEMP')) as tmp:
    tmp = Path(tmp)
    os.chmod(tmp, 0o700)
    archive, sums, binary = tmp/'vale.tar.gz', tmp/'checksums.txt', tmp/'vale'
    base = 'https://github.com/vale-cli/vale/releases/download/v3.25.1/'
    for url, destination in [(base+'vale_3.25.1_Linux_64-bit.tar.gz', archive),
                             (base+'vale_3.25.1_checksums.txt', sums)]:
        code, out, err = bounded(['/usr/bin/curl','-q','--fail','--silent','--show-error','--location',
            '--proto','=https','--proto-redir','=https','--connect-timeout','10','--max-time','60',
            '--max-filesize',str(LIMIT),'--output',str(destination),url], 65)
        require(code == 0, 'fixed HTTPS acquisition failed: ' + err.decode('utf-8',errors='replace')[:2048])
        require(destination.stat().st_size <= LIMIT, 'download exceeded byte cap')
    require(sha(sums) == CHECKSUMS and sha(archive) == ARCHIVE, 'official asset SHA256 mismatch')
    entries = [line.split() for line in sums.read_text().splitlines()]
    selected = [line for line in entries if len(line)==2 and line[1]=='vale_3.25.1_Linux_64-bit.tar.gz']
    require(selected == [[ARCHIVE,'vale_3.25.1_Linux_64-bit.tar.gz']], 'selected checksum line mismatch')
    with tarfile.open(archive, 'r:gz') as tar:
        members = tar.getmembers()
        require(len(members)==3 and {m.name for m in members}=={'LICENSE','README.md','vale'}, 'unexpected tar inventory')
        require(all(m.isfile() and m.name in {'LICENSE','README.md','vale'} and 0 <= m.size <= LIMIT
                    for m in members) and sum(m.size for m in members)<=2*LIMIT, 'unsafe tar member/type/size')
        for member in members:
            source = tar.extractfile(member)
            require(source is not None, 'missing regular archive member')
            with source, (tmp/member.name).open('wb') as target:
                shutil.copyfileobj(source,target,1048576)
            require((tmp/member.name).stat().st_size==member.size, 'archive extracted size mismatch')
    require(sha(binary)==BINARY and sha(tmp/'LICENSE')==LICENSE and sha(tmp/'README.md')==README,
            'extracted binary/notice/readme SHA256 mismatch')
    require(sha(COMPONENT/'LICENSE.upstream.txt')==LICENSE, 'candidate upstream notice mismatch')
    binary.chmod(0o500)
    print('Acquisition verified; not adoption or runtime qualification')
    for mode, seconds in [('setup',20),('observer',90),('normal',90),('optimized',90)]:
        argv = ['/usr/bin/prlimit','--as=2147483648','--cpu=90','--nofile=128','--fsize=16777216',
                '/usr/bin/bwrap','--unshare-all','--die-with-parent','--new-session','--cap-drop','ALL',
                '--ro-bind','/usr','/usr','--ro-bind','/lib','/lib']
        if Path('/lib64').exists():
            argv += ['--ro-bind','/lib64','/lib64']
        argv += ['--dir','/component','--ro-bind',str(COMPONENT),'/component',
                 '--dir','/artifact','--ro-bind',str(binary),'/artifact/vale',
                 '--proc','/proc','--dev','/dev','--size','67108864','--tmpfs','/tmp',
                 '--clearenv','--setenv','PATH','/usr/bin','--setenv','HOME','/tmp',
                 '--setenv','TMPDIR','/tmp','--setenv','PYTHONDONTWRITEBYTECODE','1',
                 '--setenv','MALLOC_ARENA_MAX','1','--setenv','CP080_VALE_BINARY','/artifact/vale',
                 '--setenv','CP080_VALE_SHA256',BINARY,'--chdir','/component','/usr/bin/python3','-B']
        if mode=='optimized':
            argv += ['-O']
        argv += ['-c',SANDBOX,mode,outer_net]
        code, out, err = bounded(argv,seconds)
        print(out.decode('utf-8',errors='replace'),end='')
        if err:
            print(err.decode('utf-8',errors='replace'),end='')
        require(code==0, 'CP080 strict sandbox '+mode+' failed (no fallback), exit '+str(code))
        require(snapshot()==before and sha(binary)==BINARY,'component or binary mutated')
print('CP080 CI checks passed; 12 normal + 12 optimized, zero failures/errors/skips.')
print('Includes actual Vale, mocks and Python process probes; not 12 actual Vale integration cases.')
print('Native adoption, SBOM/scans/recovery, aggregate physical RAM/PIDs/inodes, 576/G02/production remain held.')
CP080_PY
