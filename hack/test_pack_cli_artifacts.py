# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0
import hashlib
import importlib.util
import json
import pathlib
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('pack_cli', pathlib.Path(__file__).with_name('pack-cli-artifacts.py'))
pack_cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pack_cli)


class ArtifactPackagingTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.work = self.root / 'work'
        (self.work / 'source').mkdir(parents=True)
        (self.work / 'build').mkdir()
        for name in ('LICENSE', 'NOTICE'):
            (self.work / 'source' / name).write_bytes(name.encode())
        self.metadata = {}
        for arch in ('amd64', 'arm64'):
            (self.work / 'build' / f'arcadectl-{arch}').write_bytes(f'fixture-{arch}'.encode())
            self.metadata[arch] = {'GoVersion': 'go1.26.10', 'Path': 'github.com/gobha-me/arcadectl/cmd/arcadectl',
                                   'Main': {'Path': 'github.com/gobha-me/arcadectl', 'Version': '(devel)'},
                                   'Deps': [{'Path': 'example.invalid/dependency', 'Version': 'v1.0.0', 'Sum': 'h1:fixture'}],
                                   'Settings': [{'Key': k, 'Value': v} for k, v in {'GOOS': 'linux', 'GOARCH': arch, 'CGO_ENABLED': '0'}.items()]}
        self.write_metadata()

    def write_metadata(self):
        for arch, metadata in self.metadata.items():
            (self.work / 'build' / f'modules-{arch}.json').write_text(json.dumps(metadata))

    def build(self, name='output', sha='a' * 40, epoch=1793300400):
        output = self.root / name
        pack_cli.package(self.work, output, sha, epoch, 'go1.26.10')
        return output

    def test_repeat_bytes_checksums_and_honest_manifest(self):
        one, two = self.build('one'), self.build('two')
        self.assertEqual({p.name: p.read_bytes() for p in one.iterdir()}, {p.name: p.read_bytes() for p in two.iterdir()})
        for line in (one / 'SHA256SUMS').read_text().splitlines():
            digest, name = line.split('  ')
            self.assertEqual(hashlib.sha256((one / name).read_bytes()).hexdigest(), digest)
        manifest = json.loads((one / 'manifest.json').read_text())
        self.assertFalse(manifest['signed'])
        self.assertFalse(manifest['certified'])
        self.assertEqual(manifest['sourceSha'], 'a' * 40)
        self.assertEqual(len(manifest['artifacts']), 2)
        for record in manifest['artifacts']:
            self.assertEqual(record['certification'], 'not-evaluated')
            self.assertEqual(hashlib.sha256((one / record['file']).read_bytes()).hexdigest(), record['sha256'])

    def test_archive_has_only_fixed_safe_entries_and_metadata(self):
        output = self.build()
        for arch in ('amd64', 'arm64'):
            path = output / f'arcadectl-linux-{arch}.tar.gz'
            self.assertEqual(path.read_bytes()[4:8], b'\0' * 4)  # gzip mtime
            with tarfile.open(path) as archive:
                self.assertEqual(archive.getnames(), ['LICENSE', 'NOTICE', 'arcadectl'])
                for member in archive.getmembers():
                    self.assertTrue(member.isfile())
                    self.assertEqual((member.uid, member.gid, member.uname, member.gname, member.mtime), (0, 0, '', '', 1793300400))
                    self.assertEqual(member.mode, 0o755 if member.name == 'arcadectl' else 0o644)
                self.assertEqual(archive.extractfile('arcadectl').read(), f'fixture-{arch}'.encode())
            inventory = json.loads((output / f'arcadectl-linux-{arch}.modules.json').read_text())
            self.assertEqual(inventory['sourceSha'], 'a' * 40)
            self.assertEqual(inventory['Deps'][0]['Sum'], 'h1:fixture')
            self.assertNotIn(str(self.root), json.dumps(inventory))

    def test_wrong_binary_identity_or_platform_creates_nothing(self):
        for key, value in [('GoVersion', 'go1.26.0'), ('Path', 'another/command')]:
            previous = self.metadata['arm64'][key]
            self.metadata['arm64'][key] = value
            self.write_metadata()
            with self.assertRaises(ValueError):
                self.build()
            self.assertFalse((self.root / 'output').exists())
            self.metadata['arm64'][key] = previous
        self.metadata['arm64']['Settings'][1]['Value'] = 'amd64'
        self.write_metadata()
        with self.assertRaises(ValueError):
            self.build()
        self.assertFalse((self.root / 'output').exists())

    def test_invalid_source_creates_nothing(self):
        for sha, epoch in [('SECRET-CANARY', 1), ('a' * 40, 0), ('a' * 40, 253402300800)]:
            with self.assertRaises(ValueError):
                self.build(sha=sha, epoch=epoch)
            self.assertFalse((self.root / 'output').exists())

    def test_existing_directory_and_symlink_are_never_overwritten(self):
        protected = self.root / 'protected'
        protected.mkdir()
        (protected / 'sentinel').write_text('unchanged')
        with self.assertRaises(FileExistsError):
            self.build('protected')
        (self.root / 'output').symlink_to(protected, target_is_directory=True)
        with self.assertRaises(FileExistsError):
            self.build()
        self.assertEqual([p.name for p in protected.iterdir()], ['sentinel'])


if __name__ == '__main__':
    unittest.main()
