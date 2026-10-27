#!/usr/bin/env python3
"""Disposable, serial synthetic FS screen; never a lifecycle qualification."""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import tempfile
import time

BASE = '40a35c3ee44b6e2e63eb3ebd1e8f44035ea9bfaf'
BRANCH = 'refs/heads/perf/issue-89-fs-hash-screen'
TEST = 'TestFixtureLocalHashScreen'
ACTIVE = set()
DEADLINE = 0
STAGE = 'source-check'
FAILURE = None


def require(value):
    if not value:
        raise RuntimeError('closed FS hash screen refusal')


def stop_join(process):
    saved = {n: signal.signal(n, signal.SIG_IGN) for n in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
    try:
        try: os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError: pass
        try: process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            process.wait(timeout=2)
        try: os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        require(process.poll() is not None)
    finally:
        for n, handler in saved.items(): signal.signal(n, handler)


def capture(command, environment, seconds, limit=2*1024*1024):
    output = [bytearray(), bytearray()]
    selector, process, reason = selectors.DefaultSelector(), None, None
    started = time.monotonic()
    try:
        process = subprocess.Popen(command, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        ACTIVE.add(process)
        selector.register(process.stdout, selectors.EVENT_READ, 0)
        selector.register(process.stderr, selectors.EVENT_READ, 1)
        while selector.get_map() or process.poll() is None:
            if time.monotonic() >= DEADLINE or time.monotonic() - started >= seconds:
                reason = 'timeout'; break
            if not selector.get_map(): time.sleep(0.05)
            for key, _ in selector.select(0.1) if selector.get_map() else []:
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj); continue
                target = output[key.data]
                if len(target) + len(chunk) > limit:
                    reason = 'output-limit'; break
                target.extend(chunk)
            if reason: break
    finally:
        try:
            if process is not None:
                stop_join(process); ACTIVE.remove(process)
        finally:
            selector.close()
            if process is not None:
                process.stdout.close(); process.stderr.close()
    return process.returncode, reason, output


def checked(command, environment, seconds, limit=2*1024*1024):
    global FAILURE
    code, reason, output = capture(command, environment, seconds, limit)
    if code != 0 or reason is not None:
        positions = []
        public = ('internal/privatefs/confirm_comparing.go', 'internal/privatefs/confirm_comparing_test.go', 'internal/installengine/fixture_local_hash_screen_test.go')
        for stream in output:
            text = bytes(stream).decode('utf8', 'replace')
            for filename, line, column in re.findall(r'(?m)^((?:internal/(?:privatefs|installengine)/)?[a-z0-9_]+\.go):([0-9]{1,7})(?::([0-9]{1,7}))?:', text):
                full = next((p for p in public if p == filename or p.rsplit('/', 1)[1] == filename), None)
                if full and len(positions) < 16:
                    positions.append({'file': full, 'line': int(line), 'column': int(column or 0)})
        FAILURE = {'exitCode': code, 'reason': reason or 'exit-failure', 'positions': positions}
    require(code == 0 and reason is None)
    return output


def sample(body, variant):
    text = bytes(body).decode('utf8', 'strict')
    require(not any(s in text for s in ('--- SKIP:', '--- FAIL:', 'panic:', 'fatal error:', 'WARNING: DATA RACE', 'no tests to run')) and re.search(r'^FAIL\b', text, re.M) is None)
    require(re.findall(r'^=== RUN\s+(\S+)$', text, re.M) == [TEST, TEST+'/retained', TEST+'/fallback'])
    passes = re.findall(r'^\s*--- PASS: (\S+) \([0-9.]+s\)$', text, re.M)
    require(len(passes) == 3 and set(passes) == {TEST, TEST+'/retained', TEST+'/fallback'})
    require(text.splitlines().count('PASS') == 1)
    pattern = (r'FS_HASH_SCREEN variant=(base|candidate) mode=(retained|fallback) iterations=256 '
               r'wall-ns=([0-9]+) user-cpu-ns=([0-9]+) system-cpu-ns=([0-9]+) '
               r'alloc-bytes=([0-9]+) mallocs=([0-9]+) wal-bytes=([0-9]+) companion-bytes=([0-9]+) '
               r'custody=true no-http=true no-effects=true')
    found = re.findall(pattern, text)
    require(len(found) == 2 and [r[1] for r in found] == ['retained', 'fallback'])
    rows = []
    for row in found:
        require(row[0] == variant)
        numbers = list(map(int, row[2:]))
        require(all(0 <= n <= 9007199254740991 for n in numbers) and numbers[0] > 0)
        require(0 < numbers[-2] <= 1024*1024 and 0 < numbers[-1] <= 32*1024*1024)
        rows.append(dict(zip(('wallNs', 'userCPUNs', 'systemCPUNs', 'allocBytes', 'mallocs', 'walBytes', 'companionBytes'), numbers), mode=row[1], variant=variant, iterations=256))
    return rows


def useful(rows):
    require(len(rows) == 8)
    for mode in ('retained', 'fallback'):
        selected = [r for r in rows if r['mode'] == mode]
        base = [r for r in selected if r['variant'] == 'base']
        candidate = [r for r in selected if r['variant'] == 'candidate']
        require(len(base) == len(candidate) == 2)
        require(len({(r['walBytes'], r['companionBytes']) for r in selected}) == 1)
        faster = min(r['wallNs'] for r in base)
        if mode == 'retained' and any(r['wallNs']*100 > faster*90 for r in candidate): return False
        if mode == 'fallback' and any(r['wallNs']*100 > faster*110 for r in candidate): return False
        if any(r['allocBytes']*100 > min(b['allocBytes'] for b in base)*110 for r in candidate): return False
    return True


def interrupt(_number, _frame):
    raise KeyboardInterrupt


def main():
    global DEADLINE, STAGE
    DEADLINE = time.monotonic() + 1200
    for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP): signal.signal(number, interrupt)
    environment = dict(os.environ)
    require(environment.get('GITHUB_REF') == BRANCH and environment.get('GITHUB_RUN_ATTEMPT') == '1')
    source = environment.get('GITHUB_SHA', '')
    require(re.fullmatch('[a-f0-9]{40}', source) is not None)
    require(bytes(checked(['git', 'rev-parse', 'HEAD'], environment, 5, 4096)[0]).strip().decode() == source)
    require(bytes(checked(['git', 'show', '-s', '--format=%P', 'HEAD'], environment, 5, 4096)[0]).strip().decode() == BASE)
    names = bytes(checked(['git', 'diff', '--name-status', 'HEAD^', 'HEAD'], environment, 5, 16384)[0]).decode().splitlines()
    require(set(names) == {'M\t.github/workflows/installer-performance.yml', 'A\thack/fs-hash-screen/screen.py', 'A\tinternal/privatefs/confirm_comparing.go', 'A\tinternal/privatefs/confirm_comparing_test.go', 'A\tinternal/installengine/fixture_local_hash_screen_test.go'})
    require(not checked(['git', 'status', '--porcelain'], environment, 5, 4096)[0])
    environment.update(GOMAXPROCS='2', GOMEMLIMIT='512MiB', GOTOOLCHAIN='local', CI='false', ARCADECTL_FS_HASH_SCREEN='1')
    temporary = Path(environment['RUNNER_TEMP']).resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix='arcadectl-fs-hash.', dir=temporary))
    try:
        require(stat.S_IMODE(root.stat().st_mode) == 0o700)
        replacements = {}
        for filename, old, new in (
            ('fixture_wire.go', 'ConfirmDurable(f.name, identity)', 'ConfirmDurableComparing(f.name, identity, body)'),
            ('fixture_worlds.go', 'ConfirmDurable(f.name, identity)', 'ConfirmDurableComparing(f.name, identity, body)'),
            ('fixture_worlds.go', 'ConfirmEvidenceDurable(name, identity)', 'ConfirmEvidenceDurableComparing(name, identity, body)'),
            ('fixture_decode.go', 'ConfirmEvidenceDurable(name, *f.worldIdentity)', 'ConfirmEvidenceDurableComparing(name, *f.worldIdentity, body)'),
        ):
            path = Path('internal/installengine') / filename
            target = root / filename
            body = target.read_text() if target.exists() else path.read_text()
            require(body.count(old) == 1)
            target.write_text(body.replace(old, new))
            replacements[str(path.resolve())] = str(target)
        overlay = root / 'overlay.json'
        overlay.write_text(json.dumps({'Replace': replacements}))
        go = ['go', 'test', '-mod=readonly', '-p=1']
        STAGE = 'privatefs-controls'
        control = checked(go + ['-v', '-count=1', '-timeout=2m', './internal/privatefs'], environment, 180)
        control_text = bytes(control[0]).decode('utf8', 'strict')
        for test in ('TestConfirmComparingFreshReaderOracle', 'TestConfirmComparingOriginalRefusalOracle', 'TestConfirmComparingOwnedOperandAndExceptionalCleanup', 'TestConfirmComparingOperandBoundsAndFirstReadPrecedence'):
            require(control_text.splitlines().count('=== RUN   '+test) == 1)
            require(len(re.findall(r'^--- PASS: '+test+r' \([0-9.]+s\)$', control_text, re.M)) == 1)
        require(control_text.splitlines().count('PASS') == 1 and len(re.findall(r'^ok\s+github\.com/gobha-me/arcadectl/internal/privatefs\s+[0-9.]+s\s*$', control_text, re.M)) == 1)
        require(not any(s in control_text for s in ('--- SKIP:', '--- FAIL:', 'panic:', 'fatal error:', 'WARNING: DATA RACE', 'no tests to run')))
        for variant in ('base', 'candidate'):
            STAGE = 'compile-'+variant
            options = ['-overlay='+str(overlay)] if variant == 'candidate' else []
            checked(go + options + ['-c', '-o', str(root/variant), './internal/installengine'], environment, 360)
        rows = []
        for variant in ('base', 'candidate', 'candidate', 'base'):
            STAGE = 'measure-'+variant
            run_env = dict(environment, ARCADECTL_FS_HASH_SCREEN_VARIANT=variant)
            output = checked([str(root/variant), '-test.v', '-test.timeout=2m', '-test.run=^'+TEST+'$'], run_env, 125)
            rows.extend(sample(output[0], variant))
        STAGE = 'source-closure'
        require(not checked(['git', 'status', '--porcelain'], environment, 5, 4096)[0])
        result = {'format':'arcadectl-fs-hash-screen-v1', 'source':source, 'base':BASE, 'rows':rows, 'privatefsControlsPassed':True, 'complete':True, 'usefulScreen':useful(rows), 'nativeLatencyClaim':False, 'permanentAdoption':False}
    finally:
        previous_stage = STAGE
        STAGE = 'cleanup'
        require(not ACTIVE)
        shutil.rmtree(root)
        STAGE = previous_stage
    STAGE = 'complete'
    print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        print(json.dumps({'format':'arcadectl-fs-hash-screen-v1', 'complete':False, 'stage':STAGE, 'failure':FAILURE, 'nativeLatencyClaim':False, 'permanentAdoption':False}, sort_keys=True), flush=True)
        raise SystemExit(1)
