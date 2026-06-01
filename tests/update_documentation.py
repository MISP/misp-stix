#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import re
from pathlib import Path
from uuid import UUID, uuid5

from misp_stix_converter.abstract import _UUIDv4

_ROOT_PATH = Path(__file__).parents[1].resolve()
_UUID_RE = re.compile(
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    re.IGNORECASE
)


def _canonicalise(mapping, feature):
    """Substitute pymisp's random uuid4 fallback on each Import-direction
    ObjectReference with a deterministic uuid5 derived from object_uuid +
    referenced_uuid + relationship_type, so doc-mapping diffs only reflect
    semantic changes. Parent MISPObject uuids and MISPAttribute uuids are
    set deterministically at the converter side already (see the
    ``_create_misp_object(..., object_id=...)`` factory and the
    ``add_attribute(..., uuid=_create_v5_uuid(...))`` convention), so they
    no longer need normalisation here. ObjectReference uuids stay random
    at the converter side by design — pymisp generates them inside
    ``MISPObjectReference.__init__`` with no clean injection point — and
    are the sole reason this layer still exists."""
    if feature != 'import' or not isinstance(mapping, dict):
        return
    for entry in mapping.values():
        _canonicalise_entry(entry)


def _canonicalise_entry(entry):
    if not isinstance(entry, dict):
        return
    if 'MISP' in entry or 'STIX' in entry:
        _canonicalise_pair(entry)
    else:
        for sub in entry.values():
            _canonicalise_entry(sub)


def _canonicalise_pair(pair):
    misp_side = pair.get('MISP')
    if misp_side is None:
        return
    preserved = _scrape_uuids(pair.get('STIX'))
    uuid_map = {}
    for misp_object in (misp_side if isinstance(misp_side, list) else [misp_side]):
        _resolve_reference_uuids(misp_object, preserved, uuid_map)
    if uuid_map:
        _rewrite_misp_uuids(misp_side, uuid_map)


def _scrape_uuids(stix_side):
    """Collect every UUID-shaped substring appearing anywhere on the STIX
    side. These are the UUIDs the converter preserved or derived from STIX
    input, so the MISP side may legitimately reuse them."""
    if stix_side is None:
        return frozenset()
    return frozenset(_UUID_RE.findall(json.dumps(stix_side)))


def _resolve_reference_uuids(misp_object, preserved, uuid_map):
    """Compute a stable uuid5 for each ObjectReference whose own uuid is a
    pymisp v4 fallback. The recipe uses the (already-deterministic)
    object_uuid / referenced_uuid stored on the reference itself, so no
    cross-reference lookup is needed."""
    if not isinstance(misp_object, dict):
        return
    for reference in misp_object.get('ObjectReference', []) or []:
        ref_uuid = reference.get('uuid')
        if (
            isinstance(ref_uuid, str) and _UUID_RE.fullmatch(ref_uuid)
            and _is_pymisp_fallback(ref_uuid, preserved)
        ):
            uuid_map[ref_uuid] = str(
                uuid5(
                    _UUIDv4,
                    f"{reference.get('object_uuid')}"
                    f" - {reference.get('referenced_uuid')}"
                    f" - {reference.get('relationship_type', '')}"
                )
            )


def _is_pymisp_fallback(uuid_value, preserved):
    if uuid_value in preserved:
        return False
    try:
        return UUID(uuid_value).version == 4
    except ValueError:
        return False


def _rewrite_misp_uuids(node, uuid_map):
    """Apply the {old -> canonical} substitutions on every ObjectReference
    uuid encountered in the MISP-side tree."""
    if isinstance(node, dict):
        for key, value in node.items():
            if (
                key == 'uuid' and isinstance(value, str)
                and value in uuid_map
            ):
                node[key] = uuid_map[value]
            else:
                _rewrite_misp_uuids(value, uuid_map)
    elif isinstance(node, list):
        for item in node:
            _rewrite_misp_uuids(item, uuid_map)


_OBJECT_FEATURES = ('indicator', 'observed-data')
_PATTERNING_TYPES = (
    'crs',
    'nova',
    'sigma',
    'snort',
    'suricata',
    'wazuh',
    'yara',
)
_SUMMARY_MAPPING = {
    'email-addr': 'Email Address',
    'ipv4-addr': 'IPv4/IPv6 Address',
    'ipv6-addr': 'IPv4/IPv6 Address',
    'mac-addr': 'Mac Address',
    'url': 'URL'
}


class DocumentationUpdater:
    def __init__(self, filename, feature):
        documentation_path = _ROOT_PATH / 'documentation' / 'mapping'
        self.__mapping_path = documentation_path / f'{filename}.json'
        with open(self.__mapping_path, 'rt', encoding='utf-8') as f:
            self._documentation = json.load(f)
        _canonicalise(self._documentation, feature)
        self.__summary_path = documentation_path / f'{filename}_summary.json'
        try:
            with open(self.__summary_path, 'rt', encoding='utf-8') as f:
                self._summary = json.load(f)
        except (FileNotFoundError, json.decoder.JSONDecodeError):
            self._summary = {}
        self._summary_changed = False
        self.__feature = feature

    @property
    def feature(self):
        return self.__feature

    @property
    def mapping_path(self):
        return self.__mapping_path

    @property
    def mapping_to_check(self):
        return self.__mapping_to_check

    @property
    def summary_mapping(self):
        return self.__summary_mapping

    @property
    def summary_path(self):
        return self.__summary_path

    def check_export_mapping(self):
        if self._documentation != self.mapping_to_check:
            for name, mapping in self.mapping_to_check.items():
                if name not in self._documentation:
                    self._documentation[name] = mapping
                else:
                    if mapping['MISP'] != self._documentation[name]['MISP']:
                        self._documentation[name]['MISP'] = mapping['MISP']
                    if mapping['STIX'] != self._documentation[name]['STIX']:
                        self._documentation[name]['STIX'] = mapping['STIX']
                self._check_stix_export_summary(name, mapping['STIX'])
            self._write_documentation()
        else:
            for name, mapping in self.mapping_to_check.items():
                self._check_stix_export_summary(name, mapping['STIX'])
        if self._summary_changed:
            self._write_summary()

    def check_import_mapping(self, feature):
        if self._documentation != self.mapping_to_check:
            for name, mappings in self.mapping_to_check.items():
                if name not in self._documentation:
                    self._documentation[name] = mappings
                else:
                    for object_type, mapping in mappings.items():
                        for standard in ('MISP', 'STIX'):
                            if self._documentation[name].get(object_type) is None:
                                self._documentation[name][object_type] = {}
                            if mapping[standard] != self._documentation[name].get(object_type, {}).get(standard):
                                self._documentation[name][object_type][standard] = mapping[standard]
                self._check_stix_import_summary(name, mappings, feature)
            self._write_documentation()
        else:
            for name, mappings in self.mapping_to_check.items():
                self._check_stix_import_summary(name, mappings, feature)
        if self._summary_changed:
            self._write_summary()

    def _check_stix_export_summary(self, name, mapping):
        summary = (
            self.summary_mapping[name] if name in self.summary_mapping else
            self._define_export_summary(mapping)
        )
        if name not in self._summary or self._summary[name] != summary:
            self._summary[name] = summary
            self._summary_changed = True

    def _check_stix_import_summary(self, name, mappings, feature):
        summary = (
            self.summary_mapping[name] if name in self.summary_mapping
            else getattr(self, f"_define_{feature}_import_summary")(mappings)
        )
        if name not in self._summary or self._summary[name] != summary:
            self._summary[name] = summary
            self._summary_changed = True

    def _declare_mapping(self, mapping):
        _canonicalise(mapping, self.feature)
        self.__mapping_to_check = mapping

    def _declare_summary(self, summary):
        self.__summary_mapping = summary

    def _define_export_summary(self, stix_mapping):
        if isinstance(stix_mapping, dict):
            return f"**{stix_mapping['type'].capitalize()}**"
        object_types = {
            stix_object['type'] for stix_object in stix_mapping
            if stix_object['type'] != 'relationship'
        }
        if all(object_type in object_types for object_type in _OBJECT_FEATURES):
            return self._observable_types(
                *(
                    object_type for object_type in object_types
                    if object_type not in _OBJECT_FEATURES
                )
            )
        return ' / '.join(
            f'**{object_type.capitalize()}**' for object_type in object_types
        )

    def _define_import_summary(self, stix_mapping):
        _skip_types = frozenset(('indicator', 'observed-data', 'relationship'))
        types = []
        for stix_type, mapping in stix_mapping.items():
            stix_object = mapping['STIX']
            if stix_type == 'Indicator':
                types.append(self._pattern_types(stix_object['pattern']))
            elif stix_type == 'Observed Data':
                if isinstance(stix_object, dict):
                    observables = stix_object['objects'].values()
                elif 'objects' in stix_object[0]:
                    observables = stix_object[0]['objects'].values()
                else:
                    observables = [o for o in stix_object[1:] if o['type'] not in _skip_types]
                observable_types = (observable['type'] for observable in observables)
                types.append(f"{self._observable_types(*observable_types)} (observable)")
            else:
                types.append(f'**{stix_type}**')
        return ' / '.join(types)

    def _define_stix20_import_summary(self, stix_mapping):
        if all(feature in stix_mapping for feature in _OBJECT_FEATURES):
            return self._observable_types(stix_mapping['Observed Data']['STIX']['objects'].values())
        if len(stix_mapping.keys()) == 1 and 'Indicator' in stix_mapping:
            indicator_type = self._pattern_types(stix_mapping['Indicator']['STIX']['pattern'])
            return f"{indicator_type} / Custom Object"
        return self._define_import_summary(stix_mapping)

    def _define_stix21_import_summary(self, stix_mapping):
        if all(feature in stix_mapping for feature in _OBJECT_FEATURES):
            return self._observable_types(stix_mapping['Observed Data']['STIX'][1:])
        if len(stix_mapping.keys()) == 1 and 'Indicator' in stix_mapping:
            indicator = stix_mapping['Indicator']['STIX']
            if indicator['pattern_type'] in _PATTERNING_TYPES:
                return '**Indicator**'
            return f"{self._pattern_types(indicator['pattern'])} / Custom Object"
        return self._define_import_summary(stix_mapping)

    @staticmethod
    def _observable_type(observable_type):
        if observable_type in _SUMMARY_MAPPING:
            return _SUMMARY_MAPPING[observable_type]
        return observable_type.replace('-', ' ').title()

    def _observable_types(self, *observable_types):
        types = ' & '.join(
            sorted(
                set(
                    ' '.join(observable_type.split('-')).title()
                    for observable_type in observable_types
                )
            )
        )
        objects = 'Objects' if len(observable_types) > 1 else 'Object'
        return f"{types} {objects} and IoCs described in Indicator (pattern)"

    def _order_mapping(self, name):
        return {key: attribute for key, attribute in sorted(getattr(self, name).items())}

    def _pattern_types(self, pattern):
        types = set()
        for part in pattern[1:-1].split(' AND '):
            types.add(self._observable_type(part.lstrip('(').split(':')[0]))
        return f"{' & '.join(sorted(types))} {'Objects' if len(types) > 1 else 'Object'} (pattern)"

    def _replace_data(self, name, misp_mapping, stix_mapping):
        data = misp_mapping['data']
        short_data = f"{data[:23]}[...]{data[-23:]}"
        misp_mapping['data'] = short_data
        getattr(self, self.data_replacement[name].format(self.feature))(stix_mapping, data, short_data)

    @staticmethod
    def _replace_export_file_data(mapping, data, short_data):
        for stix_object in mapping:
            if stix_object['type'] == 'indicator':
                stix_object['pattern'] = stix_object['pattern'].replace(data, short_data)
                continue
            if stix_object['type'] == 'observed-data' and 'objects' in stix_object:
                for index, observable in stix_object['objects'].items():
                    if observable['type'] == 'artifact':
                        stix_object['objects'][index]['payload_bin'] = short_data
                        continue
                continue
            if stix_object['type'] == 'artifact':
                stix_object['payload_bin'] = short_data

    @staticmethod
    def _replace_import_file_data(mapping, data, short_data):
        if isinstance(mapping, list):
            for observable in mapping[1:]:
                if observable['type'] == 'artifact':
                    observable['payload_bin'] = short_data
                    break
        else:
            if mapping['type'] == 'indicator':
                mapping['pattern'] = mapping['pattern'].replace(data, short_data)
            elif mapping['type'] == 'artifact':
                mapping['payload_bin'] = short_data
            else:
                for index, observable in mapping['objects'].items():
                    if observable['type'] == 'artifact':
                        mapping['objects'][index]['payload_bin'] = short_data

    def _write_documentation(self):
        with open(self.mapping_path, 'wt', encoding='utf-8') as f:
            f.write(
                json.dumps(
                    dict(self._order_mapping('_documentation')),
                    indent=4, ensure_ascii=False
                )
            )

    def _write_summary(self):
        with open(self.summary_path, 'wt', encoding='utf-8') as f:
            f.write(
                json.dumps(
                    dict(self._order_mapping('_summary')),
                    indent=4, ensure_ascii=False
                )
            )


class AttributesDocumentationUpdater(DocumentationUpdater):
    __data_replacement = {
        'malware-sample': '_replace_{}_file_data'
    }

    def __init__(self, filename, attributes_mapping, feature):
        super().__init__(filename, feature)
        self._load_attributes_mapping(attributes_mapping)

    @property
    def data_replacement(cls):
        return cls.__data_replacement

    def _check_data(self, attribute_type, mapping):
        if 'data' in mapping['MISP']:
            data = mapping['MISP']['data']
        else:
            data = None
        if data is not None and len(data) > 51:
            self._replace_data(attribute_type, mapping['MISP'], mapping['STIX'])

    def _load_attributes_mapping(self, attributes_mapping):
        self._declare_summary(attributes_mapping.pop('summary', {}))
        if self.feature == 'export':
            for attribute_type, mapping in attributes_mapping.items():
                self._check_data(attribute_type, mapping)
        else:
            for attribute_type, mappings in attributes_mapping.items():
                for mapping in mappings.values():
                    self._check_data(attribute_type, mapping)
        self._declare_mapping(attributes_mapping)


class GalaxiesDocumentationUpdater(DocumentationUpdater):
    def __init__(self, filename, galaxies_mapping, feature):
        super().__init__(filename, feature)
        self._load_galaxies_mapping(galaxies_mapping)

    def _load_galaxies_mapping(self, galaxies_mapping):
        self._declare_summary(galaxies_mapping.pop('summary', {}))
        self._declare_mapping(galaxies_mapping)

    def check_import_galaxy_mapping(self):
        if self._documentation != self.mapping_to_check:
            for name, mapping in self.mapping_to_check.items():
                if name not in self._documentation:
                    self._documentation[name] = mapping
                else:
                    for key in ('MISP', 'STIX'):
                        if mapping[key] != self._documentation[name].get(key):
                            self._documentation[name][key] = mapping[key]
                self._check_stix_import_galaxy_summary(name, mapping)
            self._write_documentation()
        else:
            for name, mapping in self.mapping_to_check.items():
                self._check_stix_import_galaxy_summary(name, mapping)
        if self._summary_changed:
            self._write_summary()

    def _check_stix_import_galaxy_summary(self, name, mapping):
        summary = (
            self.summary_mapping[name] if name in self.summary_mapping
            else self._define_import_galaxy_summary(mapping)
        )
        if name not in self._summary or self._summary[name] != summary:
            self._summary[name] = summary
            self._summary_changed = True

    @staticmethod
    def _define_import_galaxy_summary(mapping):
        clusters = mapping.get('MISP', {}).get('GalaxyCluster', [{}])
        if clusters:
            galaxy_type = clusters[0].get('type', '')
            galaxy_name = mapping.get('MISP', {}).get('name', '')
            if galaxy_name and galaxy_type:
                return f'{galaxy_name} ({galaxy_type})'
        stix_type = mapping.get('STIX', {}).get('type', 'unknown')
        return f'**{stix_type.replace("-", " ").title()}**'


class ObjectsDocumentationUpdater(DocumentationUpdater):
    __data_replacement = {
        'annotation': '_replace_{}_annotation_data',
        'artifact': '_replace_{}_file_data',
        'facebook-account': '_replace_{}_account_data',
        'file': '_replace_{}_file_data',
        'github-user': '_replace_{}_account_data',
        'image': '_replace_{}_file_data',
        'legal-entity': '_replace_{}_identity_data',
        'lnk': '_replace_{}_file_data',
        'news-agency': '_replace_{}_identity_data',
        'parler-account': '_replace_{}_account_data',
        'reddit-account': '_replace_{}_account_data',
        'twitter-account': '_replace_{}_account_data',
        'user-account': '_replace_{}_account_data'
    }

    def __init__(self, filename, objects_mapping, feature):
        super().__init__(filename, feature)
        self._load_objects_mapping(objects_mapping)

    @property
    def data_replacement(cls):
        return cls.__data_replacement

    def _check_data(self, name, mapping):
        if isinstance(mapping['MISP'], list):
            for misp_object in mapping['MISP']:
                for attribute in misp_object['Attribute']:
                    if 'data' in attribute and len(attribute['data']) > 51:
                        self._replace_data(name, attribute, mapping['STIX'])
        else:
            for attribute in mapping['MISP']['Attribute']:
                if 'data' in attribute and len(attribute['data']) > 51:
                    self._replace_data(name, attribute, mapping['STIX'])

    def _load_objects_mapping(self, objects_mapping):
        self._declare_summary(objects_mapping.pop('summary', {}))
        if self.feature == 'export':
            for name, mapping in objects_mapping.items():
                self._check_data(name, mapping)
        else:
            for name, mappings in objects_mapping.items():
                for mapping in mappings.values():
                    self._check_data(name, mapping)
        self._declare_mapping(objects_mapping)

    def _replace_export_account_data(self, mapping, data, short_data):
        for stix_object in mapping:
            if stix_object['type'] == 'indicator':
                stix_object['pattern'] = stix_object['pattern'].replace(data, short_data)
                continue
            if stix_object['type'] == 'observed-data':
                if 'objects' in stix_object:
                    for observable in stix_object['objects'].values():
                        self._replace_custom_field(observable, short_data)
                continue
            if stix_object['type'] != 'relationship':
                self._replace_custom_field(stix_object, short_data)

    def _replace_import_account_data(self, mapping, data, short_data):
        if isinstance(mapping, list):
            for observable in mapping[1:]:
                self._replace_custom_field(observable, short_data)
        else:
            if mapping['type'] == 'indicator':
                mapping['pattern'] = mapping['pattern'].replace(data, short_data)
            else:
                for observable in mapping['objects'].values():
                    self._replace_custom_field(observable, short_data)

    @staticmethod
    def _replace_custom_field(mapping, short_data):
        for feature, value in mapping.items():
            if feature.startswith('x_misp_') and isinstance(value, dict):
                value['data'] = short_data
                break

    def _replace_export_identity_data(self, mapping, _, short_data):
        self._replace_custom_field(mapping, short_data)

    def _replace_import_identity_data(self, mapping, _, short_data):
        self._replace_custom_field(mapping, short_data)

    def _replace_export_annotation_data(self, mapping, _, short_data):
        for stix_object in mapping:
            if stix_object['type'] != 'note':
                continue
            self._replace_custom_field(stix_object, short_data)

    def _replace_import_annotation_data(self, mapping, _, short_data):
        self._replace_custom_field(mapping, short_data)
