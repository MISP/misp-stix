#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Sync the MISP Extensions from the OASIS Common Object Repository.

The Common Object Repository (oasis-open/cti-stix-common-objects) is the
canonical home of the MISP Extensions: misp-stix keeps a copy, and the copy
only changes through this script. From one commit of the repository, it
copies:
- the suite directory, extension-definition-specifications/misp-5ec/ (schemas,
  examples and documentation), byte for byte into
  data/misp-extensions/extension-definition-specifications/misp-5ec/, removing
  every local file the repository does not have;
- the four extension definitions, each one out of the bundle holding it under
  objects/extension-definition/, into misp_stix_converter/data/misp_extensions/
  with their values unchanged.

The commit is recorded in data/misp-extensions/source.json. The MISP Project
identity packaged next to the definitions is left alone.

Run by hand, never at install time. Standard library only.
"""

import argparse
import hashlib
import json
import re
import sys
from base64 import b64encode
from http.client import HTTPException, HTTPSConnection
from pathlib import Path, PurePosixPath
from urllib.parse import quote, unquote, urlsplit
from urllib.request import getproxies, proxy_bypass

REPO_ROOT = Path(__file__).resolve().parent.parent
REPOSITORY = 'oasis-open/cti-stix-common-objects'
SUITE = 'extension-definition-specifications/misp-5ec'
DEFINITIONS = 'objects/extension-definition'
API_URL = f'https://api.github.com/repos/{REPOSITORY}'
RAW_URL = f'https://raw.githubusercontent.com/{REPOSITORY}'

DATA = REPO_ROOT / 'data' / 'misp-extensions'
MIRROR = DATA / SUITE
SOURCE_FILE = DATA / 'source.json'
PACKAGED = REPO_ROOT / 'misp_stix_converter' / 'data' / 'misp_extensions'

# A schema file of the suite is named after the definition it describes
SCHEMA_FILE_NAME = re.compile(
    r'^(extension-definition--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-'
    r'[0-9a-f]{4}-[0-9a-f]{12})\.json$'
)


def _connection(host: str) -> HTTPSConnection:
    proxy = getproxies().get('https')
    if proxy is None or proxy_bypass(host):
        return HTTPSConnection(host, timeout=60)
    proxy = urlsplit(proxy)
    connection = HTTPSConnection(proxy.hostname, proxy.port or 80, timeout=60)
    headers = {}
    if proxy.username is not None:
        credentials = f'{unquote(proxy.username)}:{unquote(proxy.password or "")}'
        headers['Proxy-Authorization'] = (
            f"Basic {b64encode(credentials.encode('utf-8')).decode('ascii')}"
        )
    connection.set_tunnel(host, headers=headers)
    return connection


def _get(url: str, accept: str = '*/*') -> bytes:
    # Not urllib: it sends `Connection: close`, and some proxies cut the end of
    # a response when the server closes the connection behind it. Here the
    # server keeps it open, the response is read to its end, and the
    # connection is closed on this side
    parts = urlsplit(url)
    connection = _connection(parts.hostname)
    try:
        connection.request(
            'GET', f'{parts.path}?{parts.query}' if parts.query else parts.path,
            headers={'Accept': accept, 'User-Agent': 'misp-stix-sync'}
        )
        response = connection.getresponse()
        content = response.read()
    except (HTTPException, OSError) as error:
        sys.exit(f'Error: {url}: {error!r}')
    finally:
        connection.close()
    if response.status != 200:
        sys.exit(f'Error: {url}: {response.status} {response.reason}')
    return content


def _api(path: str):
    return json.loads(_get(f'{API_URL}/{path}', 'application/vnd.github+json'))


def _fetch(commit: str, path: str) -> bytes:
    return _get(f'{RAW_URL}/{commit}/{quote(path)}')


def _resolve_commit(ref: str) -> tuple[str, str]:
    # The bare sha, then the commit alone: the full commit view lists every
    # file the commit changes
    sha = _get(
        f"{API_URL}/commits/{quote(ref, safe='')}", 'application/vnd.github.sha'
    ).decode('ascii')
    return sha, _api(f'git/commits/{sha}')['committer']['date']


def _list_suite(commit: str, directory: str = SUITE) -> dict[str, str]:
    """Every file of the suite at the commit, by its path in the suite.

    :return: the git blob sha of each file
    """
    files = {}
    for entry in _api(f'contents/{quote(directory)}?ref={commit}'):
        if entry['type'] == 'dir':
            files.update(_list_suite(commit, entry['path']))
            continue
        if entry['type'] != 'file':
            sys.exit(f"Error: {entry['path']} is a {entry['type']}, not a file")
        relative = PurePosixPath(entry['path']).relative_to(SUITE)
        if '..' in relative.parts:
            sys.exit(f"Error: {entry['path']} points outside {SUITE}")
        files[relative.as_posix()] = entry['sha']
    return files


def _blob_sha(content: bytes) -> str:
    return hashlib.sha1(b'blob %d\0' % len(content) + content).hexdigest()


def _fetch_suite(commit: str) -> dict[str, bytes]:
    suite = {}
    for path, sha in sorted(_list_suite(commit).items()):
        content = _fetch(commit, f'{SUITE}/{path}')
        if _blob_sha(content) != sha:
            sys.exit(f'Error: {SUITE}/{path} does not match its blob at {commit}')
        suite[path] = content
    return suite


def _fixed_ids() -> list[str]:
    # The definitions the Export embeds, each one in the file named after its
    # fixed id: the test suite checks those names against the ids both
    # conversion directions know
    return sorted(
        path.stem for path in PACKAGED.glob('extension-definition--*.json')
    )


def _suite_ids(suite: dict[str, bytes]) -> list[str]:
    return sorted(
        match.group(1) for match in (
            SCHEMA_FILE_NAME.match(PurePosixPath(path).name)
            for path in suite
        ) if match is not None
    )


def _fetch_definition(commit: str, identifier: str) -> dict:
    path = f'{DEFINITIONS}/{identifier}.json'
    bundle = json.loads(_fetch(commit, path))
    objects = bundle.get('objects', []) if bundle.get('type') == 'bundle' else []
    if len(objects) != 1 or objects[0].get('id') != identifier:
        sys.exit(f'Error: {path} is not a bundle holding only {identifier}')
    return objects[0]


def _definition_text(definition: dict) -> bytes:
    # The format of the packaged files
    return (json.dumps(definition, indent=4) + '\n').encode('utf-8')


def _local_suite() -> dict[str, Path]:
    return {
        path.relative_to(MIRROR).as_posix(): path
        for path in MIRROR.rglob('*') if path.is_file()
    }


def _suite_changes(suite: dict[str, bytes]) -> tuple[list, list]:
    """What a sync writes and removes in the mirrored suite.

    :return: the (status, path) of each file to write, with status `added` or
        `changed`, and the path of each local file to remove
    """
    local = _local_suite()
    writes = [
        ('changed' if path in local else 'added', path)
        for path, content in suite.items()
        if path not in local or local[path].read_bytes() != content
    ]
    removals = sorted(path for path in local if path not in suite)
    return writes, removals


def _definition_changes(definitions: dict[str, dict]) -> dict[str, list]:
    """The values of each packaged definition a sync changes.

    :return: the (property, packaged value, new value) of each change, by id
    """
    changes = {}
    for identifier, definition in definitions.items():
        path = PACKAGED / f'{identifier}.json'
        if path.read_bytes() == _definition_text(definition):
            continue
        packaged = json.loads(path.read_text(encoding='utf-8'))
        changes[identifier] = [
            (key, packaged.get(key), definition.get(key))
            for key in dict.fromkeys((*packaged, *definition))
            if packaged.get(key) != definition.get(key)
        ]
    return changes


def _report(writes: list, removals: list, changes: dict[str, list],
            definitions: dict[str, dict]):
    if writes or removals:
        print(f'Suite, {MIRROR.relative_to(REPO_ROOT)}:')
        for status, path in writes:
            print(f'  {status:8} {path}')
        for path in removals:
            print(f'  {"removed":8} {path}')
    if changes:
        print(f'Definitions, {PACKAGED.relative_to(REPO_ROOT)}:')
        for identifier, values in changes.items():
            print(f"  {identifier} ({definitions[identifier].get('name')})")
            for key, packaged, new in values:
                print(f'    {key}: {packaged!r} -> {new!r}')


def _prune_empty_directories():
    directories = sorted(
        (path for path in MIRROR.rglob('*') if path.is_dir()),
        key=lambda path: len(path.parts), reverse=True
    )
    for directory in directories:
        if not any(directory.iterdir()):
            directory.rmdir()


def _sync(suite: dict[str, bytes], writes: list, removals: list,
          definitions: dict[str, dict], changes: dict[str, list],
          commit: str, date: str):
    for _, path in writes:
        target = MIRROR / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(suite[path])
    for path in removals:
        (MIRROR / path).unlink()
    _prune_empty_directories()
    for identifier in changes:
        (PACKAGED / f'{identifier}.json').write_bytes(
            _definition_text(definitions[identifier])
        )
    source = {
        'repository': f'https://github.com/{REPOSITORY}',
        'commit': commit, 'date': date
    }
    SOURCE_FILE.write_text(json.dumps(source, indent=4) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(
        description=(
            'Sync the MISP Extensions (suite and definitions) from the OASIS '
            'Common Object Repository.'
        )
    )
    parser.add_argument(
        '--commit', default='main', metavar='COMMIT',
        help='The commit to sync from (default: the head of main)'
    )
    parser.add_argument(
        '--check', action='store_true',
        help='Write nothing; exit 1 if a sync would change the copy.'
    )
    args = parser.parse_args()

    commit, date = _resolve_commit(args.commit)
    print(f'{REPOSITORY} at {commit} ({date})')

    suite = _fetch_suite(commit)
    fixed_ids = _fixed_ids()
    suite_ids = _suite_ids(suite)
    if suite_ids != fixed_ids:
        sys.exit(
            f'Error: the suite names the definitions {suite_ids}, not the '
            f'fixed ids {fixed_ids}: adding or removing a definition needs a '
            'code change first'
        )
    definitions = {
        identifier: _fetch_definition(commit, identifier)
        for identifier in fixed_ids
    }

    writes, removals = _suite_changes(suite)
    changes = _definition_changes(definitions)
    _report(writes, removals, changes, definitions)

    if args.check:
        if writes or removals or changes:
            print('The copy differs: run tools/update_misp_extensions.py')
            sys.exit(1)
        print('The copy is up to date.')
        return

    _sync(suite, writes, removals, definitions, changes, commit, date)
    if not (writes or removals or changes):
        print('The copy was up to date.')
    print(f'Recorded the commit in {SOURCE_FILE.relative_to(REPO_ROOT)}')


if __name__ == '__main__':
    main()
