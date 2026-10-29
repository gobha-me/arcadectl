#!/usr/bin/env python3
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0
"""Package an exact-source build; this performs no signing or publication."""
import gzip
import hashlib
import io
import json
import os
import pathlib
import platform
import re
import sys
import tarfile
import zlib


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def package(work, output, sha, epoch, toolchain):
    if not re.fullmatch(r'[0-9a-f]{40}', sha) or not 0 < epoch <= 253402300799:
        raise ValueError('source identity')
    records, contents = [], {}
    for arch in ('amd64', 'arm64'):
        binary = (work / 'build' / f'arcadectl-{arch}').read_bytes()
        modules = json.loads((work / 'build' / f'modules-{arch}.json').read_text())
        if modules.get('GoVersion') != toolchain or modules.get('Path') != 'github.com/gobha-me/arcadectl/cmd/arcadectl':
            raise ValueError('binary identity')
        settings = {entry['Key']: entry['Value'] for entry in modules.get('Settings', [])}
        if settings.get('GOOS') != 'linux' or settings.get('GOARCH') != arch or settings.get('CGO_ENABLED') != '0':
            raise ValueError('binary platform')
        # The command path was checked above; the module inventory describes deps.
        modules.pop('Path', None)
        modules.pop('Main', None)  # Main is the exact source claim below, not a module release.
        modules['sourceSha'] = sha
        modules['schemaVersion'] = 'arcadectl.go-build-inventory/v1'
        inventory_name = f'arcadectl-linux-{arch}.modules.json'
        contents[inventory_name] = encode(modules)
        stream = io.BytesIO()
        with gzip.GzipFile(fileobj=stream, mode='wb', filename='', mtime=0, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as archive:
                entries = {'arcadectl': binary, 'LICENSE': (work / 'source' / 'LICENSE').read_bytes(), 'NOTICE': (work / 'source' / 'NOTICE').read_bytes()}
                for name, data in sorted(entries.items()):
                    entry = tarfile.TarInfo(name)
                    entry.size, entry.mtime = len(data), epoch
                    entry.mode = 0o755 if name == 'arcadectl' else 0o644
                    entry.uid = entry.gid = 0
                    entry.uname = entry.gname = ''
                    archive.addfile(entry, io.BytesIO(data))
        archive_name = f'arcadectl-linux-{arch}.tar.gz'
        contents[archive_name] = stream.getvalue()
        records.append({'os': 'linux', 'arch': arch, 'file': archive_name,
                        'sha256': hashlib.sha256(contents[archive_name]).hexdigest(),
                        'size': len(contents[archive_name]), 'moduleInventory': inventory_name,
                        'certification': 'not-evaluated'})
    manifest = {'schemaVersion': 'arcadectl.cli-artifacts/v1', 'sourceSha': sha, 'sourceEpoch': epoch,
                'goVersion': toolchain, 'pythonVersion': platform.python_version(), 'zlibVersion': zlib.ZLIB_RUNTIME_VERSION,
                'signed': False, 'certified': False, 'artifacts': records}
    contents['manifest.json'] = encode(manifest)
    contents['SHA256SUMS'] = ''.join(f'{hashlib.sha256(data).hexdigest()}  {name}\n' for name, data in sorted(contents.items())).encode()
    # Atomic directory creation refuses an existing output, including symlinks.
    # No manifest is present until all builds and all packaging have succeeded.
    output.mkdir(mode=0o700)
    for name in sorted(contents, key=lambda name: (name == 'manifest.json', name)):
        descriptor = os.open(output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as destination:
            destination.write(contents[name])


if __name__ == '__main__':
    try:
        if len(sys.argv) != 6:
            raise ValueError('arguments')
        package(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3], int(sys.argv[4]), sys.argv[5])
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError):
        raise SystemExit('artifact packaging refused; no release approval is implied')
