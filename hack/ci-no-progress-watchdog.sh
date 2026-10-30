#!/usr/bin/env bash
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0
# STOPGAP for CI only; the command and its proof selection remain unchanged.
set -euo pipefail
exec python3 - "$@" <<'PYCODE'
import math
import os
import selectors
import signal
import subprocess
import sys
import time

if len(sys.argv) < 4:
    sys.exit("usage: ci-no-progress-watchdog.sh MINUTES LABEL COMMAND [ARG ...]")
minutes = float(sys.argv[1])
if not math.isfinite(minutes) or minutes <= 0:
    sys.exit("watchdog minutes must be positive and finite")
label = sys.argv[2]
process = None


def terminate_tree():
    if process is None:
        return
    # The command owns a new session/group. Signal descendants even if their
    # parent has already exited; do not leave an orphan holding the log pipe.
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            break
        if sig == signal.SIGTERM:
            time.sleep(5)
    process.wait()


def interrupted(signum, _frame):
    raise SystemExit(128 + signum)


signal.signal(signal.SIGTERM, interrupted)
signal.signal(signal.SIGINT, interrupted)
try:
    process = subprocess.Popen(sys.argv[3:], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               start_new_session=True)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    last_progress = time.monotonic()
    while True:
        remaining = minutes * 60 - (time.monotonic() - last_progress)
        if remaining <= 0:
            print(f"\n::error::no log progress for {minutes:g} min in {label} "
                  "(watchdog stopgap, see https://github.com/gobha-me/arcadectl/issues/139)",
                  flush=True)
            sys.exit(124)
        if selector.select(min(remaining, 1)):
            chunk = os.read(process.stdout.fileno(), 65536)
            if chunk:
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()
                last_progress = time.monotonic()
            else:
                selector.unregister(process.stdout)
                # A process may close stdout/stderr and still hang. Keep its
                # last-byte deadline active until the command actually exits.
        if process.poll() is not None and not selector.get_map():
            status = process.wait()
            sys.exit(status if status >= 0 else 128 - status)
finally:
    # Also runs on runner cancellation, reader failure, and normal exit.
    terminate_tree()
PYCODE
