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
        self._summary_changed = False

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

    def check_mapping(self, feature):
        if self._documentation != self.mapping_to_check:
            for name, mapping in self.mapping_to_check.items():
                self._check_mapping(name, mapping)
                self._check_stix_summary(name, mapping['STIX'], feature)
            self._write_documentation()
        else:
            for name, mapping in self.mapping_to_check.items():
                self._check_stix_summary(name, mapping['STIX'], feature)
        if self._summary_changed:
            self._write_summary()

    def _check_mapping(self, name, mapping):
        if name not in self._documentation:
            self._documentation[name] = mapping
        else:
            if mapping['MISP'] != self._documentation[name]['MISP']:
                self._documentation[name]['MISP'] = mapping['MISP']
            for stix_type, stix_object in mapping['STIX'].items():
                stixobject = self._documentation[name]['STIX'].get(stix_type, {})
                if stix_object != stixobject:
                    self._documentation[name]['STIX'][stix_type] = stix_object

    def _check_stix_summary(self, name, mapping, feature):
        summary = self.summary_mapping[name] if name in self.summary_mapping else getattr(self, f"_define_{feature}_summary")(mapping)
        if name not in self._summary or self._summary[name] != summary:
            self._summary[name] = summary
            self._summary_changed = True

    def _declare_mapping(self, mapping):
        self.__mapping_to_check = mapping

    def _declare_summary(self, summary):
        self.__summary_mapping = summary

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

    def _replace_data(self, attribute, name, stix_mapping):
        data = attribute['data']
        short_data = f"{data[:23]}[...]{data[-23:]}"
        attribute['data'] = short_data
        getattr(self, self.data_replacement[name])(stix_mapping, data, short_data)

    @staticmethod
    def _replace_file_data(mapping, data, short_data):
        mapping['Indicator']['pattern'] = mapping['Indicator']['pattern'].replace(data, short_data)
        if isinstance(mapping['Observed Data'], list):
            for observable in mapping['Observed Data'][1:]:
                if observable['type'] == 'artifact':
                    observable['payload_bin'] = observable['payload_bin'].replace(data, short_data)
                    break
        else:
            for index, observable in mapping['Observed Data']['objects'].items():
                if observable['type'] == 'artifact':
                    mapping['Observed Data']['objects'][index]['payload_bin'] = observable['payload_bin'].replace(data, short_data)
                    break

    def _write_documentation(self):
        with open(self.mapping_path, 'wt', encoding='utf-8') as f:
            f.write(json.dumps(self._order_mapping('_documentation'), indent=4))

    def _write_summary(self):
        with open(self.summary_path, 'wt', encoding='utf-8') as f:
            f.write(json.dumps(self._order_mapping('_summary'), indent=4))


class AttributesDocumentationUpdater(DocumentationUpdater):
    __data_replacement = {
        'malware-sample': '_replace_file_data'
    }

    def __init__(self, filename, attributes_mapping):
        super().__init__(filename)
        self._load_attributes_mapping(attributes_mapping)

    @property
    def data_replacement(cls):
        return cls.__data_replacement

    def _load_attributes_mapping(self, attributes_mapping):
        self._declare_summary(attributes_mapping.pop('summary', {}))
        for attribute_type, mapping in attributes_mapping.items():
            if 'data' in mapping['MISP'] and len(mapping['MISP']['data']) > 51:
                self._replace_data(mapping['MISP'], attribute_type, mapping['STIX'])
        self._declare_mapping(attributes_mapping)


class ObjectsDocumentationUpdater(DocumentationUpdater):
    __data_replacement = {
        'annotation': '_replace_annotation_data',
        'facebook-account': '_replace_account_data',
        'file': '_replace_file_data',
        'github-user': '_replace_account_data',
        'image': '_replace_file_data',
        'legal-entity': '_replace_identity_data',
        'lnk': '_replace_file_data',
        'news-agency': '_replace_identity_data',
        'parler-account': '_replace_account_data',
        'reddit-account': '_replace_account_data',
        'twitter-account': '_replace_account_data',
        'user-account': '_replace_account_data'
    }

    def __init__(self, filename, objects_mapping):
        super().__init__(filename)
        self._load_objects_mapping(objects_mapping)

    @property
    def data_replacement(cls):
        return cls.__data_replacement

    def _load_objects_mapping(self, objects_mapping):
        self._declare_summary(objects_mapping.pop('summary', {}))
        for name, mapping in objects_mapping.items():
            if isinstance(mapping['MISP'], list):
                for misp_object in mapping['MISP']:
                    for attribute in misp_object['Attribute']:
                        if 'data' in attribute and len(attribute['data']) > 51:
                            self._replace_data(attribute, name, mapping['STIX'])
            else:
                for attribute in mapping['MISP']['Attribute']:
                    if 'data' in attribute and len(attribute['data']) > 51:
                        self._replace_data(attribute, name, mapping['STIX'])
        self._declare_mapping(objects_mapping)

    def _replace_account_data(self, mapping, data, short_data):
        mapping['Indicator']['pattern'] = mapping['Indicator']['pattern'].replace(data, short_data)
        if isinstance(mapping['Observed Data'], list):
            for observable in mapping['Observed Data'][1:]:
                self._replace_custom_field(observable, data, short_data)
        else:
            for observable in mapping['Observed Data']['objects'].values():
                self._replace_custom_field(observable, data, short_data)

    @staticmethod
    def _replace_custom_field(mapping, data, short_data):
        for feature, value in mapping.items():
            if feature.startswith('x_misp_') and isinstance(value, dict):
                value['data'] = value['data'].replace(data, short_data)
                break

    def _replace_identity_data(self, mapping, data, short_data):
        self._replace_custom_field(mapping['Identity'], data, short_data)

    def _replace_annotation_data(self, mapping, data, short_data):
        self._replace_custom_field(mapping['Note'], data, short_data)
