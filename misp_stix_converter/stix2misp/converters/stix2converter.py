#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ..exceptions import UndefinedSTIXObjectError
from abc import ABCMeta
from collections import defaultdict
from datetime import datetime
from pymisp import AbstractMISP, MISPGalaxyCluster, MISPObject
from stix2.v20.sdo import (
    AttackPattern as AttackPattern_v20, Malware as Malware_v20,
    ObservedData as ObservedData_v20)
from stix2.v21.sdo import (
    AttackPattern as AttackPattern_v21, Malware as Malware_v21,
    ObservedData as ObservedData_v21)
from typing import Iterator, Optional, Tuple, TYPE_CHECKING, Union

if TYPE_CHECKING:
    from ..external_stix2_to_misp import ExternalSTIX2toMISPParser
    from ..internal_stix2_to_misp import InternalSTIX2toMISPParser

_MISP_OBJECTS_PATH = AbstractMISP().misp_objects_path

_GALAXY_OBJECTS_TYPING = Union[
    AttackPattern_v20, AttackPattern_v21,
    Malware_v20, Malware_v21
]
_MAIN_PARSER_TYPING = Union[
    'ExternalSTIX2toMISPParser', 'InternalSTIX2toMISPParser'
]
_SDO_TYPING = Union[
    AttackPattern_v20, AttackPattern_v21,
    Malware_v20, Malware_v21,
    ObservedData_v20, ObservedData_v21
]


class STIX2Converter(metaclass=ABCMeta):
    def _set_main_parser(self, main: _MAIN_PARSER_TYPING):
        self.__main_parser = main

    @property
    def event_uuid(self) -> str:
        return self.main_parser.misp_event.uuid

    @property
    def main_parser(self) -> _MAIN_PARSER_TYPING:
        return self.__main_parser

    ############################################################################
    #                  MISP DATA STRUCTURES CREATION METHODS.                  #
    ############################################################################

    def _create_attribute_dict(self, stix_object: _SDO_TYPING) -> dict:
        attribute = self._parse_timeline(stix_object)
        attribute.update(
            self.main_parser._sanitise_attribute_uuid(
                stix_object.id, comment=stix_object.get('description')
            )
        )
        return attribute

    def _create_misp_object(
            self, name: str,
            stix_object: Optional[_SDO_TYPING] = None) -> MISPObject:
        misp_object = MISPObject(
            name, force_timestamps=True,
            misp_objects_path_custom=_MISP_OBJECTS_PATH
        )
        if stix_object is not None:
            self.main_parser._sanitise_object_uuid(
                misp_object, stix_object['id']
            )
            misp_object.from_dict(**self._parse_timeline(stix_object))
        return misp_object

    ############################################################################
    #                     STIX OBJECTS CONVERSION METHODS.                     #
    ############################################################################

    def _generic_parser(
            self, stix_object, feature: Optional[str] = None) -> Iterator[dict]:
        if feature is None:
            feature = stix_object.type.replace('-', '_')
        mapping = getattr(self._mapping, f'{feature}_object_mapping')
        for field, attribute in mapping().items():
            if hasattr(stix_object, field):
                yield from self._populate_object_attributes(
                    attribute, getattr(stix_object, field), stix_object.id
                )

    def _populate_object_attribute(self, mapping: dict, object_id: str,
                                   value: Union[dict, str]) -> dict:
        reference = f"{object_id} - {mapping['object_relation']}"
        if isinstance(value, dict):
            attribute_value = value['value']
            return {
                **value, **mapping,
                'uuid': self.main_parser._create_v5_uuid(
                    f'{reference} - {attribute_value}'
                )
            }
        return {
            'value': value, **mapping,
            'uuid': self.main_parser._create_v5_uuid(
                f'{reference} - {value}'
            )
        }

    def _populate_object_attributes(
            self, mapping: dict, values: Union[list, str],
            object_id: str) -> Iterator[dict]:
        reference = f"{object_id} - {mapping['object_relation']}"
        if isinstance(values, list):
            for value in values:
                yield {
                    'value': value, **mapping,
                    'uuid': self.main_parser._create_v5_uuid(
                        f'{reference} - {value}'
                    )
                }
        else:
            yield {
                'value': values, **mapping,
                'uuid': self.main_parser._create_v5_uuid(
                    f'{reference} - {values}'
                )
            }

    def _populate_object_attributes_with_data(
            self, mapping: dict, values: Union[dict, list, str],
            object_id: str) -> Iterator[dict]:
        if isinstance(values, list):
            for value in values:
                yield self._populate_object_attribute(mapping, object_id, value)
        else:
            yield self._populate_object_attribute(mapping, object_id, values)

    ############################################################################
    #                             UTILITY METHODS.                             #
    ############################################################################

    @staticmethod
    def _handle_kill_chain_phases(kill_chain_phases: list) -> list:
        kill_chains = []
        for kill_chain in kill_chain_phases:
            kill_chains.append(
                f'{kill_chain.kill_chain_name}:{kill_chain.phase_name}'
            )
        return kill_chains

    @staticmethod
    def _handle_labels(meta: dict, labels: list):
        meta_labels = [
            label for label in labels if not label.startswith('misp:galaxy-')
        ]
        if meta_labels:
            meta['labels'] = meta_labels

    @staticmethod
    def _parse_AS_value(number: Union[int, str]) -> str:
        if isinstance(number, int) or not number.startswith('AS'):
            return f'AS{number}'
        return number

    def _parse_timeline(self, stix_object: _SDO_TYPING) -> dict:
        misp_object = {
            'timestamp': stix_object.modified
        }
        object_type = stix_object.type
        if self._mapping.timeline_mapping(object_type) is not None:
            first, last = self._mapping.timeline_mapping(object_type)
            if not self._skip_first_seen_last_seen(stix_object):
                if hasattr(stix_object, first) and getattr(stix_object, first):
                    misp_object['first_seen'] = getattr(stix_object, first)
                if hasattr(stix_object, last) and getattr(stix_object, last):
                    misp_object['last_seen'] = getattr(stix_object, last)
        return misp_object

    @staticmethod
    def _skip_first_seen_last_seen(sdo: _SDO_TYPING) -> bool:
        if sdo.type != 'indicator':
            return sdo.modified == sdo.first_observed == sdo.last_observed
        if sdo.valid_from != sdo.modified:
            return False
        if not hasattr(sdo, 'valid_until'):
            return True
        return sdo.valid_until == sdo.modified

    @staticmethod
    def _timestamp_from_date(date: datetime) -> int:
        return int(date.timestamp())
        # I keep it just in case
        # try:
        #     return int(date.timestamp())
        # except AttributeError:
        #     return int(
        #         time.mktime(
        #             time.strptime(date.split('+')[0], "%Y-%m-%dT%H:%M:%S.%fZ")
        #         )
        #     )


class ExternalSTIX2Converter(STIX2Converter, metaclass=ABCMeta):

    def parse(self, stix_object_ref: str):
        stix_object = self.main_parser._get_stix_object(stix_object_ref)
        self._parse_galaxy(stix_object)

    ############################################################################
    #                         GALAXIES PARSING METHODS                         #
    ############################################################################

    def _check_existing_galaxy_name(self, stix_object_name: str) -> Union[list, None]:
        if stix_object_name in self.main_parser.synonyms_mapping:
            return self.main_parser.synonyms_mapping[stix_object_name]
        for name, tag_names in self.main_parser.synonyms_mapping.items():
            if stix_object_name in name:
                return tag_names

    def _create_cluster_args(
            self, stix_object: _GALAXY_OBJECTS_TYPING, galaxy_type: str,
            description: Optional[str] = None,
            cluster_value: Optional[str] = None) -> dict:
        value = cluster_value or getattr(stix_object, 'name', stix_object.id)
        cluster_args = {
            'value': value, **self.main_parser.cluster_distribution,
            'uuid': self.main_parser._create_v5_uuid(
                f'{self.main_parser._extract_uuid(stix_object.id)} -'
                f' {self.main_parser.organisation_uuid}'
            ),
            'source': (
                self.main_parser._handle_creator(stix_object.created_by_ref)
                if hasattr(stix_object, 'created_by_ref') else 'misp-stix'
            )
        }
        if galaxy_type is None:
            version = getattr(stix_object, 'spec_version', '2.0')
            mapping = self._mapping.galaxy_name_mapping(stix_object.type)
            name = f"STIX {version} {mapping['name']}"
            cluster_args.update(
                {
                    'version': ''.join(version.split('.')),
                    'collection_uuid': self.main_parser._create_v5_uuid(name)
                }
            )
            galaxy_type = f'stix-{version}-{stix_object.type}'
        cluster_args['type'] = galaxy_type
        if description is not None:
            cluster_args['description'] = description
            return cluster_args
        if hasattr(stix_object, 'description'):
            cluster_args['description'] = stix_object.description
            return cluster_args
        cluster_args['description'] = value.capitalize()
        return cluster_args

    def _create_galaxy_args(self, stix_object: _GALAXY_OBJECTS_TYPING,
                            galaxy_type: Optional[str] = None):
        if galaxy_type is None:
            galaxy_type = stix_object.type
        mapping = self._mapping.galaxy_name_mapping(galaxy_type)
        name = mapping['name']
        galaxy_args = {
            'description': mapping['description'], 'namespace': 'stix',
            **self.main_parser.cluster_distribution
        }
        if galaxy_type not in ('country', 'region', 'sector'):
            version = getattr(stix_object, 'spec_version', '2.0')
            name = f"STIX {version} {name}"
            galaxy_args.update(
                {
                    'uuid': self.main_parser._create_v5_uuid(name),
                    'version': ''.join(version.split('.')),
                    'icon': mapping['icon']
                }
            )
            galaxy_type = f'stix-{version}-{galaxy_type}'
        galaxy_args.update({'type': galaxy_type, 'name': name})
        self.main_parser._galaxies[galaxy_type] = galaxy_args

    def _handle_meta_fields(self, stix_object: _GALAXY_OBJECTS_TYPING) -> dict:
        mapping = f"{stix_object.type.replace('-', '_')}_meta_mapping"
        meta = {
            field: stix_object[field].strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            for field in ('created', 'modified')
            if stix_object.get(field) is not None
        }
        if hasattr(self._mapping, mapping):
            for feature, field in getattr(self._mapping, mapping)().items():
                if hasattr(stix_object, feature):
                    meta[field] = getattr(stix_object, feature)
        return meta

    def _parse_galaxy(self, stix_object: _GALAXY_OBJECTS_TYPING,
                      object_type: Optional[str] = None):
        clusters = self.main_parser._clusters
        if stix_object.id in clusters:
            clusters[stix_object.id]['used'][self.event_uuid] = False
        else:
            feature = f'_parse_galaxy_{self.main_parser.galaxy_feature}'
            clusters[stix_object.id] = getattr(self, feature)(
                stix_object, object_type
            )

    def _parse_galaxy_as_container(self, stix_object: _GALAXY_OBJECTS_TYPING,
                                   object_type: Union[str, None]) -> dict:
        galaxy_type = object_type or stix_object.type
        if galaxy_type not in self.main_parser._galaxies:
            self._create_galaxy_args(stix_object, galaxy_type)
        return {
            'cluster': self._create_cluster(
                stix_object, galaxy_type=object_type
            ),
            'used': {self.event_uuid: False}
        }

    def _parse_galaxy_as_tag_names(self, stix_object: _GALAXY_OBJECTS_TYPING,
                                   object_type: Union[str, None]) -> dict:
        name = stix_object.name
        tag_names = self._check_existing_galaxy_name(name)
        if tag_names is None:
            tag_names = [
                f'misp-galaxy:{object_type or stix_object.type}="{name}"'
            ]
        return {
            'tag_names': tag_names,
            'used': {self.event_uuid: False}
        }

    ############################################################################
    #                             UTILITY METHODS.                             #
    ############################################################################

    @staticmethod
    def _handle_external_references(external_references: list) -> dict:
        meta = defaultdict(list)
        for reference in external_references:
            if reference.get('url'):
                meta['refs'].append(reference['url'])
            if reference.get('external_id'):
                meta['external_id'].append(reference['external_id'])
        if 'external_id' in meta and len(meta['external_id']) == 1:
            meta['external_id'] = meta.pop('external_id')[0]
        return meta

    def _handle_import_case(self, stix_object: _SDO_TYPING, attributes: list,
                            name: str, *force_object: Tuple[str]):
        if self._handle_object_forcing(attributes, force_object):
            self._handle_object_case(stix_object, attributes, name)
        else:
            self.main_parser._add_misp_attribute(
                dict(
                    self._create_attribute_dict(stix_object), **attributes[0]
                ),
                stix_object
            )

    @staticmethod
    def _handle_object_forcing(attributes: list, force_object: tuple) -> bool:
        if len(attributes) > 1:
            return True
        return attributes[0]['object_relation'] in force_object

    def _handle_object_case(self, stix_object: _SDO_TYPING, attributes: list,
                            name: str) -> MISPObject:
        misp_object = self._create_misp_object(name, stix_object)
        for attribute in attributes:
            misp_object.add_attribute(**attribute)
        return self.main_parser._add_misp_object(misp_object, stix_object)


class InternalSTIX2Converter(STIX2Converter, metaclass=ABCMeta):

    def _create_attribute_dict(self, stix_object: _SDO_TYPING) -> dict:
        attribute = {}
        tags = []
        for label in stix_object.labels:
            if label.startswith('misp:'):
                feature, value = label.split('=')
                attribute[feature.split(':')[-1]] = value.strip('"')
            else:
                tags.append({'name': label})
        if tags:
            attribute['Tag'] = tags
        attribute.update(super()._create_attribute_dict(stix_object))
        return attribute

    ############################################################################
    #                         GALAXIES PARSING METHODS                         #
    ############################################################################

    def _create_cluster_args(
            self, stix_object: _GALAXY_OBJECTS_TYPING, galaxy_type: str,
            description: Optional[str] = None,
            cluster_value: Optional[str] = None) -> dict:
        value = cluster_value or stix_object.name
        cluster_args = {
            'uuid': self.main_parser._sanitise_uuid(stix_object.id),
            'value': value, 'type': galaxy_type
        }
        if description is not None:
            cluster_args['description'] = description
            return cluster_args
        if hasattr(stix_object, 'description'):
            cluster_args['description'] = stix_object.description
            return cluster_args
        cluster_args['description'] = value.capitalize()
        return cluster_args

    def _create_galaxy_args(self, galaxy_type: str, galaxy_name: str):
        self.main_parser._galaxies[galaxy_type] = (
            self.main_parser.galaxy_definitions[galaxy_type]
            if galaxy_type in self.main_parser.galaxy_definitions
            else {'type': galaxy_type, 'name': galaxy_name}
        )

    def _extract_custom_fields(self, stix_object: _GALAXY_OBJECTS_TYPING):
        for key, value in stix_object.items():
            if key.startswith('x_misp_'):
                separator = (
                    '-' if key in self._mapping.dash_meta_fields() else '_'
                )
                yield separator.join(key.split('_')[2:]), value

    @staticmethod
    def _handle_cluster_value(cluster_args: dict, external_id: str):
        cluster_value = cluster_args['value']
        if external_id not in cluster_value:
            cluster_args['value'] = f'{cluster_value} - {external_id}'

    @staticmethod
    def _handle_cluster_value_with_synonyms(cluster_args: dict, meta: dict):
        cluster_value = cluster_args['value']
        external_id = meta['external_id']
        if external_id not in cluster_value:
            cluster_args['value'] = f'{cluster_value} - {external_id}'
            if meta.get('synonyms') is None:
                meta['synonyms'] = [cluster_value]
            elif cluster_value not in meta['synonyms']:
                meta['synonyms'].append(cluster_value)

    def _handle_meta_fields(self, stix_object: _GALAXY_OBJECTS_TYPING) -> dict:
        mapping = f"{stix_object.type.replace('-', '_')}_meta_mapping"
        if hasattr(self._mapping, mapping):
            meta = {}
            for feature, field in getattr(self._mapping, mapping)().items():
                if hasattr(stix_object, feature):
                    meta[field] = getattr(stix_object, feature)
            meta.update(dict(self._extract_custom_fields(stix_object)))
            return meta
        return dict(self._extract_custom_fields(stix_object))

    def _parse_galaxy(self, stix_object: _GALAXY_OBJECTS_TYPING):
        clusters = self.main_parser._clusters
        if stix_object.id in clusters:
            clusters[stix_object.id]['used'][self.event_uuid] = False
        else:
            feature = f'_parse_galaxy_{self.main_parser.galaxy_feature}'
            clusters[stix_object.id] = getattr(self, feature)(stix_object)

    def _parse_galaxy_as_container(
            self, stix_object: _GALAXY_OBJECTS_TYPING) -> dict:
        galaxy_type, galaxy_name = self._extract_galaxy_labels(
            stix_object.labels
        )
        cluster = self._parse_galaxy_cluster(stix_object, galaxy_type)
        if galaxy_type not in self.main_parser._galaxies:
            self._create_galaxy_args(galaxy_type, galaxy_name)
        return {
            'cluster': cluster,
            'used': {self.event_uuid: False}
        }

    def _parse_galaxy_as_tag_names(
            self, stix_object: _GALAXY_OBJECTS_TYPING) -> dict:
        galaxy_type = stix_object.labels[1].split('=')[1].strip('"')
        return {
            'tag_names': [
                f'misp-galaxy:{galaxy_type}="{stix_object.name}"'
            ],
            'used': {self.event_uuid: False}
        }

    def _parse_galaxy_cluster(
            self, stix_object: _GALAXY_OBJECTS_TYPING, galaxy_type: str,
            description: Optional[str] = None) -> Tuple[MISPGalaxyCluster, str]:
        if getattr(stix_object, 'description', '').count(' | ') == 1:
            _, description = stix_object.description.split(' | ')
        return self._create_cluster(
            stix_object, description=description, galaxy_type=galaxy_type
        )

    ############################################################################
    #                             UTILITY METHODS.                             #
    ############################################################################

    @staticmethod
    def _extract_galaxy_labels(labels: list) -> dict:
        for label in labels[:2]:
            if 'galaxy-type' in label:
                galaxy_type = label.split('=')[1].strip('"')
            elif 'galaxy-name' in label:
                galaxy_name = label.split('=')[1].strip('"')
        return galaxy_type, galaxy_name

    @staticmethod
    def _handle_external_references(external_references: list) -> dict:
        meta = defaultdict(list)
        for reference in external_references:
            if reference.get('url'):
                meta['refs'].append(reference['url'])
            feature = (
                'aliases' if reference.get('source_name') == 'cve'
                else 'external_id'
            )
            if reference.get('external_id'):
                meta[feature].append(reference['external_id'])
        if 'external_id' in meta and len(meta['external_id']) == 1:
            meta['external_id'] = meta.pop('external_id')[0]
        return meta

    def _handle_mapping_from_labels(self, labels: list, object_id: str) -> str:
        parsed_labels = {
            key: value.strip('"') for key, value
            in (label.split('=') for label in labels if '=' in label)
        }
        if 'misp:galaxy-type' in parsed_labels:
            return f'_parse_galaxy'
        if 'misp:name' in parsed_labels:
            to_call = self._mapping.objects_mapping(parsed_labels['misp:name'])
            if to_call is not None:
                return to_call
        elif 'misp:type' in parsed_labels:
            to_call = self._mapping.attributes_mapping(
                parsed_labels['misp:type']
            )
            if to_call is not None:
                return to_call
        raise UndefinedSTIXObjectError(object_id)
