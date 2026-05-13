#!/usr/bin/env python3
"""
Build misp_stix_converter/data/cti_uuid_catalog.json from the data/cti submodule.

Run this script after each ATT&CK/CAPEC release to refresh the catalog:
    python tools/build_cti_uuid_catalog.py

The catalog maps cluster names and external IDs to their canonical STIX UUIDs.
It is used by the use_cti_uuids export option to reference existing MITRE
objects by their stable UUID rather than emitting a full custom SDO.
"""

import json
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CTI_PATH = REPO_ROOT / 'data' / 'cti'
OUTPUT_PATH = REPO_ROOT / 'misp_stix_converter' / 'data' / 'cti_uuid_catalog.json'

KEPT_TYPES = {
    'attack-pattern', 'campaign', 'course-of-action', 'intrusion-set',
    'malware', 'threat-actor', 'tool', 'vulnerability',
}

SOURCE_NAMES = {
    'ATTACK', 'NIST Mobile Threat Catalogue', 'WASC', 'capec', 'cve', 'cwe',
    'mitre-attack', 'mitre-ics-attack', 'mitre-mobile-attack',
    'mitre-pre-attack', 'reference_from_CAPEC',
}

BUNDLE_PATHS = [
    CTI_PATH / 'enterprise-attack' / 'enterprise-attack.json',
    CTI_PATH / 'ics-attack' / 'ics-attack.json',
    CTI_PATH / 'mobile-attack' / 'mobile-attack.json',
    CTI_PATH / 'pre-attack' / 'pre-attack.json',
    CTI_PATH / 'capec' / '2.1' / 'stix-capec.json',
]


def main():
    # name → type → set of UUIDs seen (may vary across domains)
    name_candidates: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    # ext_id → type → UUID (first seen wins; ext_ids are unique by definition)
    by_ext_id: dict[str, dict[str, str]] = {}

    for bundle_path in BUNDLE_PATHS:
        if not bundle_path.exists():
            print(f'WARNING: {bundle_path} not found — skipping')
            continue
        with open(bundle_path, 'rt', encoding='utf-8') as f:
            bundle = json.load(f)
        for obj in bundle.get('objects', []):
            obj_type = obj.get('type')
            if obj_type not in KEPT_TYPES:
                continue
            name = obj.get('name')
            obj_id = obj.get('id', '')
            if not name or not obj_id:
                continue

            name_candidates[name][obj_type].add(obj_id)

            for ref in obj.get('external_references', []):
                if ref.get('source_name') not in SOURCE_NAMES:
                    continue
                ext_id = ref.get('external_id')
                if not ext_id:
                    continue
                if ext_id not in by_ext_id:
                    by_ext_id[ext_id] = {}
                if obj_type not in by_ext_id[ext_id]:
                    by_ext_id[ext_id][obj_type] = obj_id
                break

        print(f'Processed {bundle_path.name}')

    # by_name: only include entries with exactly one UUID per type (unambiguous)
    by_name: dict[str, dict[str, str]] = {}
    ambiguous = 0
    for name, type_map in name_candidates.items():
        entry: dict[str, str] = {}
        for obj_type, uuids in type_map.items():
            if len(uuids) == 1:
                entry[obj_type] = next(iter(uuids))
            else:
                ambiguous += 1
        if entry:
            by_name[name] = entry

    catalog = {'by_name': by_name, 'by_ext_id': by_ext_id}

    with open(OUTPUT_PATH, 'wt', encoding='utf-8') as f:
        json.dump(catalog, f, indent=4)

    size_kb = OUTPUT_PATH.stat().st_size / 1024
    print(f'\nby_name entries: {len(by_name)} ({ambiguous} names skipped as ambiguous)')
    print(f'by_ext_id entries: {len(by_ext_id)}')
    print(f'Wrote {OUTPUT_PATH} ({size_kb:.1f} KB)')


if __name__ == '__main__':
    main()
