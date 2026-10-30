#!/usr/bin/env python3
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0
"""Check repository-local Markdown destinations without making network requests."""

import argparse
import html
from pathlib import Path
import re
import sys
import unicodedata
from urllib.parse import unquote, urlsplit


INLINE = re.compile(r"(?<!\\)\[[^\]\n]*\]\(")
REFERENCE = re.compile(r'^ {0,3}\[[^\]]+\]:\s*(?:<([^>]+)>|(\S+))')
HEADING = re.compile(r'^ {0,3}#{1,6}\s+(.+?)\s*#*\s*$')
HTML_ID = re.compile(r'<[^>]+\b(?:id|name)=["\']([^"\']+)["\']', re.I)
HTML_LINK = re.compile(r'<[^>]+\b(?:href|src)=["\']([^"\']+)["\']', re.I)


def visible_lines(text):
    """Ignore fenced/indented examples and comments; preserve source line numbers."""
    fence, width, comment = '', 0, False
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip(' ')
        marker = re.match(r'(`{3,}|~{3,})', stripped) if len(line) - len(stripped) <= 3 else None
        if fence:
            if marker and marker[0][0] == fence and len(marker[0]) >= width and not stripped[len(marker[0]):].strip():
                fence = ''
            yield number, ''
            continue
        if marker:
            fence, width = marker[0][0], len(marker[0])
            yield number, ''
            continue
        if line.startswith('    ') or line.startswith('\t'):
            yield number, ''
            continue
        result = ''
        while line:
            if comment:
                end = line.find('-->')
                if end < 0:
                    line = ''
                else:
                    comment, line = False, line[end + 3:]
            else:
                start = line.find('<!--')
                if start < 0:
                    result += line
                    line = ''
                else:
                    result += line[:start]
                    comment, line = True, line[start + 4:]
        yield number, result


def destination(line, start):
    """Read a destination with balanced parentheses or angle-bracket quoting."""
    rest = line[start:].lstrip()
    if rest.startswith('<'):
        end = rest.find('>')
        return rest[1:end] if end >= 0 else None
    depth, result, escaped = 0, '', False
    for char in rest:
        if escaped:
            result += char
            escaped = False
        elif char == '\\':
            escaped = True
        elif char == '(':
            depth += 1
            result += char
        elif char == ')':
            if depth == 0:
                return result
            depth -= 1
            result += char
        elif char.isspace() and depth == 0:
            return result
        else:
            result += char
    return None


def slug(text):
    text = re.sub(r'<[^>]*>', '', html.unescape(text)).lower().replace('`', '')
    text = re.sub(r'\[([^\]]+)\]\([^)]*\)', r'\1', text)
    return ''.join('-' if char.isspace() else char for char in text
                   if char.isspace() or char in '-_' or unicodedata.category(char)[0] in 'LN')


def parse_document(text):
    links, anchors, used = [], set(), set()
    previous = ''
    for number, line in visible_lines(text):
        anchors.update(HTML_ID.findall(line))
        heading = HEADING.match(line)
        heading_text = heading[1] if heading else None
        if heading_text is None and re.fullmatch(r' {0,3}(?:=+|-+)\s*', line) and previous.strip():
            heading_text = previous.strip()
        if heading_text is not None:
            base, suffix = slug(heading_text), 0
            anchor = base
            while anchor in used:
                suffix += 1
                anchor = f'{base}-{suffix}'
            used.add(anchor)
            anchors.add(anchor)
        previous = line
        # Inline code examples are not links. Matching delimiter widths keep
        # literal backticks inside a code span from ending it prematurely.
        prose = re.sub(r'(`+)(.*?)\1(?!`)', '', line)
        definition = REFERENCE.match(prose)
        if definition:
            links.append((number, definition[1] or definition[2]))
        for match in INLINE.finditer(prose):
            target = destination(prose, match.end())
            if target is not None:
                links.append((number, target))
        links.extend((number, target) for target in HTML_LINK.findall(prose))
    return links, anchors


def check(root):
    root = Path(root).resolve()
    documents, issues = {}, []
    for path in sorted(root.rglob('*.md')):
        if any(part in {'.git', 'node_modules', 'vendor'} for part in path.relative_to(root).parts):
            continue
        relative = path.relative_to(root).as_posix()
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            issues.append((relative, 1, 'unsafe document path'))
            continue
        try:
            documents[path.resolve()] = parse_document(path.read_text(encoding='utf-8'))
        except (OSError, UnicodeError):
            issues.append((relative, 1, 'unreadable Markdown document'))
    if not documents:
        return [('.', 1, 'no Markdown documents found')]
    for document, (links, _) in documents.items():
        for line, raw in links:
            try:
                target = urlsplit(html.unescape(raw))
            except ValueError:
                issues.append((document.relative_to(root).as_posix(), line, 'invalid link destination'))
                continue
            if target.scheme or target.netloc:
                continue  # External links are deliberately never fetched.
            relative = document.relative_to(root).as_posix()
            decoded = unquote(target.path)
            if '\x00' in decoded or decoded.startswith('/'):
                issues.append((relative, line, 'invalid repository-relative destination'))
                continue
            candidate = (document.parent / decoded).resolve() if decoded else document
            if not candidate.is_relative_to(root):
                issues.append((relative, line, 'destination escapes repository'))
                continue
            if not candidate.exists():
                issues.append((relative, line, 'missing local destination'))
                continue
            if candidate.is_dir() and target.fragment:
                candidate /= 'README.md'
            if target.fragment and candidate.suffix.lower() == '.md':
                parsed = documents.get(candidate)
                if parsed is None or unquote(target.fragment) not in parsed[1]:
                    issues.append((relative, line, 'missing Markdown anchor'))
    return issues


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    issues = check(args.root)
    for path, line, reason in issues:
        # Report location/category only, never arbitrary destination text.
        print(f'{path!r}:{line}: {reason}', file=sys.stderr)
    if issues:
        return 1
    print('Repository-local documentation links passed.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
