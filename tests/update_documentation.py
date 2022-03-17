#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
from pathlib import Path

_ROOT_PATH = Path(__file__).parents[1].resolve()
_OBJECT_FEATURES = ('Indicator', 'Observed Data')
_PATTERNING_TYPES = (
    'sigma',
    'snort',
    'suricata',
    'yara'
)
_SUMMARY_MAPPING = {
    'email-addr': 'Email Address',
    'ipv4-addr': 'IPv4/IPv6 Address',
    'ipv6-addr': 'IPv4/IPv6 Address',
    'mac-addr': 'Mac Address',
    'url': 'URL'
}


class DocumentationUpdater:
    def __init__(self, filename):
        documentation_path = _ROOT_PATH / 'documentation' / 'mapping'
        self.__mapping_path = documentation_path / f'{filename}.json'
        with open(self.__mapping_path, 'rt', encoding='utf-8') as f:
            self._documentation = json.loads(f.read())
        self.__summary_path = documentation_path / f'{filename}_summary.json'
        try:
            with open(self.__summary_path, 'rt', encoding='utf-8') as f:
                self._summary = json.loads(f.read())
        except (FileNotFoundError, json.decoder.JSONDecodeError):
            self._summary = {}

    @property
    def mapping_path(self):
        return self.__mapping_path

    @property
    def summary_path(self):
        return self.__summary_path

    def check_stix20_mapping(self, mapping_to_check):
        summary_mapping = mapping_to_check.pop('summary', {})
        if self._documentation != mapping_to_check:
            for attribute_type, mapping in mapping_to_check.items():
                self._check_mapping(attribute_type, mapping)
                summary = summary_mapping[attribute_type] if attribute_type in summary_mapping else self._define_stix20_summary(mapping['STIX'])
                if attribute_type not in self._summary or self._summary != summary:
                    self._summary[attribute_type] = summary
            self._write_mappings()
        else:
            summary_changed = False
            for attribute_type, mapping in mapping_to_check.items():
                summary = summary_mapping[attribute_type] if attribute_type in summary_mapping else self._define_stix20_summary(mapping['STIX'])
                if attribute_type not in self._summary or self._summary != summary:
                    summary_changed = True
                    self._summary[attribute_type] = summary
            if summary_changed:
                self._write_summary_mapping()

    def check_stix21_mapping(self, mapping_to_check):
        summary_mapping = mapping_to_check.pop('summary', {})
        if self._documentation != mapping_to_check:
            for attribute_type, mapping in mapping_to_check.items():
                self._check_mapping(attribute_type, mapping)
                summary = summary_mapping[attribute_type] if attribute_type in summary_mapping else self._define_stix21_summary(mapping['STIX'])
                if attribute_type not in self._summary or self._summary != summary:
                    self._summary[attribute_type] = summary
            self._write_mappings()
        else:
            summary_changed = False
            for attribute_type, mapping in mapping_to_check.items():
                summary = summary_mapping[attribute_type] if attribute_type in summary_mapping else self._define_stix21_summary(mapping['STIX'])
                if attribute_type not in self._summary or self._summary != summary:
                    summary_changed = True
                    self._summary[attribute_type] = summary
            if summary_changed:
                self._write_summary_mapping()

    def _check_mapping(self, attribute_type, mapping):
        if attribute_type not in self._documentation:
            self._documentation[attribute_type] = mapping
        else:
            if mapping['MISP'] != self._documentation[attribute_type]['MISP']:
                self._documentation[attribute_type]['MISP'] = mapping['MISP']
            for stix_type, stix_object in mapping['STIX'].items():
                stixobject = self._documentation[attribute_type]['STIX'].get(stix_type, {})
                if stix_object != stixobject:
                    self._documentation[attribute_type]['STIX'][stix_type] = stix_object

    def _define_stix20_summary(self, stix_mapping):
        if all(feature in stix_mapping for feature in _OBJECT_FEATURES):
            return self._observable_types(stix_mapping['Observed Data']['objects'].values())
        if len(stix_mapping.keys()) == 1 and 'Indicator' in stix_mapping:
            indicator_type = self._pattern_types(stix_mapping['Indicator']['pattern'])
            return f"{indicator_type} / Custom Object"
        return self._define_summary(stix_mapping)

    def _define_stix21_summary(self, stix_mapping):
        if all(feature in stix_mapping for feature in _OBJECT_FEATURES):
            return self._observable_types(stix_mapping['Observed Data'][1:])
        if len(stix_mapping.keys()) == 1 and 'Indicator' in stix_mapping:
            indicator = stix_mapping['Indicator']
            if indicator['pattern_type'] in _PATTERNING_TYPES:
                return '**Indicator**'
            return f"{self._pattern_types(indicator['pattern'])} / Custom Object"
        return self._define_summary(stix_mapping)

    def _define_summary(self, stix_mapping):
        types = []
        for stix_type, stix_object in stix_mapping.items():
            if stix_type == 'Indicator':
                types.append(self._pattern_types(stix_object['pattern']))
            elif stix_type == 'Observed Data':
                types.append(f"{self._observable_types(stix_object[1:])} (observable)")
            else:
                types.append(f'**{stix_type}**')
        return ' / '.join(types)

    @staticmethod
    def _observable_type(observable_type):
        if observable_type in _SUMMARY_MAPPING:
            return _SUMMARY_MAPPING[observable_type]
        return observable_type.replace('-', ' ').title()

    def _observable_types(self, observables):
        types = {self._observable_type(observable['type']) for observable in observables}
        return f"{' & '.join(sorted(types))} {'Objects' if len(observables) > 1 else 'Object'}"

    def _order_mapping(self, name):
        return {key: attribute for key, attribute in sorted(getattr(self, name).items())}

    def _pattern_types(self, pattern):
        types = set()
        for part in pattern[1:-1].split(' AND '):
            types.add(self._observable_type(part.split(':')[0]))
        return f"{' & '.join(types)} {'Objects' if len(types) > 1 else 'Object'} (pattern)"

    def _write_mappings(self):
        with open(self.mapping_path, 'wt', encoding='utf-8') as f:
            f.write(json.dumps(self._order_mapping('_documentation'), indent=4))
        self._write_summary_mapping()

    def _write_summary_mapping(self):
        with open(self.summary_path, 'wt', encoding='utf-8') as f:
            f.write(json.dumps(self._order_mapping('_summary'), indent=4))