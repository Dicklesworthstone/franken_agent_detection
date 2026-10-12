#!/usr/bin/env python3
"""Apply a fail-closed candidate patch, or publish its exact tested Git blobs."""
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

if len(sys.argv) > 1 and sys.argv[1] == 'publish':
    assert os.environ['GITHUB_REPOSITORY'] == 'Dicklesworthstone/franken_agent_detection'
    for filename in FILES:
        data = {'encoding': 'base64', 'content': base64.b64encode(Path(filename).read_bytes()).decode()}
        request = urllib.request.Request(
            'https://api.github.com/repos/Dicklesworthstone/franken_agent_detection/git/blobs',
            data=json.dumps(data).encode(), method='POST',
            headers={'Authorization': 'Bearer ' + os.environ['GH_TOKEN'], 'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json'})
        with urllib.request.urlopen(request) as response:
            blob = json.load(response)
        print(json.dumps({'path': filename, 'mode': '100644', 'type': 'blob', 'sha': blob['sha']}), flush=True)
    sys.exit(0)

for name, layouts in LAYOUTS.items():
    path = Path(f'src/connectors/{name}.rs')
    text = path.read_text()
    marker = '    fn source_roots(ctx: &ScanContext) -> Vec<ScanRoot> {'
    assert text.count(marker) == 1, (name, 'source_roots anchor changed')
    start = text.index(marker)
    anchor = '        roots.sort_by(|a, b| a.path.cmp(&b.path));'
    position = text.index(anchor, start)
    assert position - start < 6000 and 'super::remote_mirror::roots' not in text
    text = text[:position] + f'        roots.extend(super::remote_mirror::roots(ctx, {layouts}));\n' + text[position:]
    if name == 'cursor':
        old = '        let workspace_storage = base.join("workspaceStorage");'
        assert old in text
        text = text.replace(old, '        let workspace_storage = if base.file_name().is_some_and(|name| name == "workspaceStorage") {\n            base.to_path_buf()\n        } else {\n            base.join("workspaceStorage")\n        };', 1)
        text = text.replace('        dbs.sort();\n        dbs', '        dbs.sort();\n        dbs.dedup();\n        dbs', 1)
    path.write_text(text)

path = Path('src/connectors/mod.rs')
text = path.read_text()
assert text.count('pub mod scan;') == 1
path.write_text(text.replace('pub mod scan;', 'mod remote_mirror;\npub mod scan;'))
Path('src/connectors/remote_mirror.rs').write_text(Path('.github/patches/remote_mirror.rs').read_text())
Path('tests/remote_mirror_layouts.rs').write_text(Path('.github/patches/remote_mirror_layouts.rs').read_text())
fixture = Path('tests/fixtures/remote-mirror-cursor.vscdb')
assert not fixture.exists()
fixture.parent.mkdir(parents=True, exist_ok=True)
with sqlite3.connect(fixture) as db:
    db.execute('CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value TEXT)')
    payload = {'composerId': 'cursor-mirror', 'name': 'Mirror regression', 'createdAt': 1767225601000, 'lastUpdatedAt': 1767225602000, 'conversation': [{'type': 1, 'text': 'mirror user'}, {'type': 2, 'text': 'mirror assistant'}]}
    db.execute('INSERT INTO cursorDiskKV VALUES (?, ?)', ('composerData:cursor-mirror', json.dumps(payload)))
print('Applied remote mirror candidate to five connectors; no branch was modified.')
