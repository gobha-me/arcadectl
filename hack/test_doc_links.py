# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name('check-doc-links.py')
SPEC = importlib.util.spec_from_file_location('doc_links', SCRIPT)
LINKS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LINKS)


class DocumentationLinkTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
        return path

    def test_paths_anchors_duplicates_and_supported_links(self):
        self.write('README.md', '# Home\n[guide](docs/guide.md#hello-api)\n[folder](docs/)\n')
        self.write('docs/README.md', '# Docs\n')
        self.write('docs/guide.md', '''# Hello, `API`!
## Hello, API!
## Über Größe
Setext section
==============
<a id="stable"></a>
[same](#hello-api)
[duplicate](#hello-api-1)
[unicode](#%C3%BCber-gr%C3%B6%C3%9Fe)
[setext](#setext-section)
[explicit](#stable)
[parent](../README.md#home)
[query](../README.md?view=1#home)
[nested](nested(a).md)
[escaped](nested\\(a\\).md)
[space](<space document.md>)
![image](icon.svg)
<a href="../README.md#home">home</a>
<img src="icon.svg">
[reference]: ../README.md#home "title"
[home][reference]
''')
        self.write('docs/nested(a).md', '# Nested\n')
        self.write('docs/space document.md', '# Space\n')
        self.write('docs/icon.svg', '<svg/>')
        self.assertEqual(LINKS.check(self.root), [])

    def test_missing_file_anchor_image_and_reference_are_failures(self):
        self.write('README.md', '''# Home
[missing](absent.md)
[anchor](#absent)
![image](absent.svg)
[reference]: absent-reference.md
''')
        self.assertEqual(LINKS.check(self.root), [
            ('README.md', 2, 'missing local destination'),
            ('README.md', 3, 'missing Markdown anchor'),
            ('README.md', 4, 'missing local destination'),
            ('README.md', 5, 'missing local destination'),
        ])
        self.write('absent.md', '# Exists\n')
        self.write('absent.svg', '<svg/>')
        self.write('absent-reference.md', '# Exists\n')
        self.assertEqual(LINKS.check(self.root), [('README.md', 3, 'missing Markdown anchor')])

    def test_examples_comments_and_external_urls_are_not_fetched(self):
        self.write('README.md', '''# Home
`[code](absent.md)`
``[code with ` in it](absent.md)``
```markdown
[fenced](absent.md)
# Not a heading
```
~~~
[tilde](absent.md)
~~~
    [indented](absent.md)
<!-- [comment](absent.md)
[comment continuation](absent.md) -->
[https](https://example.invalid/absent.md)
[mail](mailto:nobody@example.invalid)
[protocol-relative](//example.invalid/absent.md)
''')
        self.assertEqual(LINKS.check(self.root), [])

    def test_code_block_cannot_create_a_setext_anchor(self):
        self.write('README.md', '''Paragraph
```
example
```
---
[wrong](#paragraph)
''')
        self.assertEqual(LINKS.check(self.root), [('README.md', 6, 'missing Markdown anchor')])

    def test_repository_escapes_and_symlinks_are_refused(self):
        self.write('README.md', '[outside](../PRIVATE-DOC-CANARY.md)\n[root](/README.md)\n')
        self.assertEqual(LINKS.check(self.root), [
            ('README.md', 1, 'destination escapes repository'),
            ('README.md', 2, 'invalid repository-relative destination'),
        ])
        with tempfile.TemporaryDirectory() as outside:
            secret = Path(outside) / 'PRIVATE-DOC-CANARY.md'
            secret.write_text('PRIVATE-DOC-CANARY', encoding='utf-8')
            (self.root / 'linked.md').symlink_to(secret)
            self.write('README.md', '[outside](linked.md)\n')
            issues = LINKS.check(self.root)
            self.assertIn(('linked.md', 1, 'unsafe document path'), issues)
            self.assertIn(('README.md', 1, 'destination escapes repository'), issues)

    def test_cli_exit_status_reports_locations_without_destinations(self):
        self.write('README.md', '[broken](PRIVATE-DOC-CANARY.md)\n')
        result = subprocess.run([sys.executable, '-B', str(SCRIPT), '--root', str(self.root)], text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertIn("'README.md':1: missing local destination", result.stderr)
        self.assertNotIn('PRIVATE-DOC-CANARY', result.stdout + result.stderr)
        self.write('PRIVATE-DOC-CANARY.md', '# Exists\n')
        result = subprocess.run([sys.executable, '-B', str(SCRIPT), '--root', str(self.root)], text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0)
        self.assertIn('documentation links passed', result.stdout)

    def test_empty_tree_does_not_silently_pass(self):
        self.assertEqual(LINKS.check(self.root), [('.', 1, 'no Markdown documents found')])


if __name__ == '__main__':
    unittest.main()
