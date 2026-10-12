#!/usr/bin/env python3
"""Apply a preflighted candidate, or publish its exact Git blobs for review.

This script never updates a branch. Publishing blobs is not a test result.
"""
import base64
import json
import os
from pathlib import Path
import sqlite3
import sys
import urllib.request

FILES = ['src/connectors/mod.rs', 'src/connectors/remote_mirror.rs', 'tests/remote_mirror_layouts.rs', 'tests/fixtures/remote-mirror-cursor.vscdb']
LAYOUTS = {
    'factory': '&[&[".factory", "sessions"]]',
    'gemini': '&[&[".gemini", "tmp"]]',
    'vibe': '&[&[".vibe", "logs", "session"]]',
    'prime_agent': '&[&[".prime", "agent", "sessions"]]',
    'cursor': '&[&["Cursor", "User"], &["Cursor", "User", "globalStorage"], &["Cursor", "User", "workspaceStorage"]]',
}
FILES += [f'src/connectors/{name}.rs' for name in LAYOUTS]


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f'Expected one source anchor, found {text.count(old)}: {old!r}')
    return text.replace(old, new, 1)


if len(sys.argv) > 1 and sys.argv[1] == 'publish':
    if os.environ['GITHUB_REPOSITORY'] != 'Dicklesworthstone/franken_agent_detection':
        raise ValueError('Unexpected repository')
    for filename in FILES:
        data = {'encoding': 'base64', 'content': base64.b64encode(Path(filename).read_bytes()).decode()}
        request = urllib.request.Request(
            'https://api.github.com/repos/Dicklesworthstone/franken_agent_detection/git/blobs',
            data=json.dumps(data).encode(), method='POST',
            headers={'Authorization': 'Bearer ' + os.environ['GH_TOKEN'], 'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=60) as response:
            blob = json.load(response)
        print(json.dumps({'path': filename, 'mode': '100644', 'type': 'blob', 'sha': blob['sha']}), flush=True)
    sys.exit(0)

# Resolve every anchor and output before modifying any source file.
changes = {}
for name, layouts in LAYOUTS.items():
    path = Path(f'src/connectors/{name}.rs')
    text = path.read_text()
    marker = '    fn source_roots(ctx: &ScanContext) -> Vec<ScanRoot> {'
    if text.count(marker) != 1 or 'super::remote_mirror::roots' in text:
        raise ValueError(f'{name}: source_roots changed or candidate already applied')
    start = text.index(marker)
    anchor = '        roots.sort_by(|a, b| a.path.cmp(&b.path));'
    position = text.index(anchor, start)
    if position - start >= 6000:
        raise ValueError(f'{name}: unexpected source_roots extent')
    text = text[:position] + f'        roots.extend(super::remote_mirror::roots(ctx, {layouts}));\n' + text[position:]
    if name == 'cursor':
        old = '        let workspace_storage = base.join("workspaceStorage");'
        if old not in text:
            raise ValueError('Cursor workspace enumeration changed')
        text = text.replace(old, '        let workspace_storage = if base.file_name().is_some_and(|name| name == "workspaceStorage") {\n            base.to_path_buf()\n        } else {\n            base.join("workspaceStorage")\n        };', 1)
        old = '        dbs.sort();\n        dbs'
        if old not in text:
            raise ValueError('Cursor database sorting changed')
        text = text.replace(old, '        dbs.sort();\n        dbs.dedup();\n        dbs', 1)
    changes[path] = text

path = Path('src/connectors/mod.rs')
changes[path] = replace_once(path.read_text(), 'pub mod scan;', 'mod remote_mirror;\npub mod scan;')
helper = Path('.github/patches/remote_mirror.rs').read_text()
helper = replace_once(helper, '                wrappers.insert(ancestor.to_path_buf());\n                break;', '                wrappers.insert(ancestor.to_path_buf());')
helper = helper.replace("WalkDir's existing", "`WalkDir`'s existing")
changes[Path('src/connectors/remote_mirror.rs')] = helper

# A whole-provider payload already has a native local layout. It must remain
# readable locally; only the new wrapper inference is restricted to SSH roots.
tests = Path('.github/patches/remote_mirror_layouts.rs').read_text()
tests = replace_once(tests, '    let ctx = ScanContext::with_roots(tmp.path().join("cass-state"), vec![ScanRoot::local(wrapper)], None);\n    assert!(connector.scan(&ctx).unwrap().is_empty(), "do not broaden local wrapper detection");\n', '')
changes[Path('tests/remote_mirror_layouts.rs')] = tests
fixture = Path('tests/fixtures/remote-mirror-cursor.vscdb')
if fixture.exists():
    raise ValueError('Fixture already exists; refusing to overwrite')
for path in changes:
    if not path.exists() and path.parent != Path('tests') and path.parent != Path('src/connectors'):
        raise ValueError(f'Unexpected new source path: {path}')
for path, text in changes.items():
    path.write_text(text)
fixture.parent.mkdir(parents=True, exist_ok=True)
with sqlite3.connect(fixture) as db:
    db.execute('CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value TEXT)')
    payload = {'composerId': 'cursor-mirror', 'name': 'Mirror regression', 'createdAt': 1767225601000, 'lastUpdatedAt': 1767225602000, 'conversation': [{'type': 1, 'text': 'mirror user'}, {'type': 2, 'text': 'mirror assistant'}]}
    db.execute('INSERT INTO cursorDiskKV VALUES (?, ?)', ('composerData:cursor-mirror', json.dumps(payload)))
print('Applied preflighted remote mirror candidate; no branch was modified.')
