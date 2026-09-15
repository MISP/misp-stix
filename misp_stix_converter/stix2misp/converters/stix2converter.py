#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ._galaxy_definitions import GALAXY_DEFINITIONS
from ..exceptions import UndefinedSTIXObjectError
from abc import ABCMeta
from collections import defaultdict
from datetime import datetime
from pymisp import AbstractMISP, MISPGalaxyCluster, MISPObject
from stix2.v20.sdo import (
    AttackPattern as AttackPattern_v20, CourseOfAction as CourseOfAction_v20,
    IntrusionSet as IntrusionSet_v20, Malware as Malware_v20,
    ObservedData as ObservedData_v20, ThreatActor as ThreatActor_v20,
    Tool as Tool_v20, Vulnerability as Vulnerability_v20)
from stix2.v21.sdo import (
    AttackPattern as AttackPattern_v21, CourseOfAction as CourseOfAction_v21,
    IntrusionSet as IntrusionSet_v21, Malware as Malware_v21,
    ObservedData as ObservedData_v21, ThreatActor as ThreatActor_v21,
    Tool as Tool_v21, Vulnerability as Vulnerability_v21)
from typing import Iterator, Optional, Tuple, TYPE_CHECKING, Union

if TYPE_CHECKING:
    from ..external_stix2_to_misp import ExternalSTIX2toMISPParser
    from ..internal_stix2_to_misp import InternalSTIX2toMISPParser

_MISP_OBJECTS_PATH = AbstractMISP().misp_objects_path
_DATETIME_REGEX = '%Y-%m-%dT%H:%M:%S'

# `dict` is part of the incoming typings: a STIX 2.0 Bundle keeps the object
# types 2.0 does not know (Location, Malware Analysis) as plain dictionaries,
# so every helper here reads through the Mapping interface both forms offer.
_GALAXY_OBJECTS_TYPING = Union[
    AttackPattern_v20, AttackPattern_v21,
    CourseOfAction_v20, CourseOfAction_v21,
    IntrusionSet_v20, IntrusionSet_v21,
    Malware_v20, Malware_v21,
    ThreatActor_v20, ThreatActor_v21,
    Tool_v20, Tool_v21,
    Vulnerability_v20, Vulnerability_v21, dict
]
_MAIN_PARSER_TYPING = Union[
    'ExternalSTIX2toMISPParser', 'InternalSTIX2toMISPParser'
]
_SDO_TYPING = Union[
    AttackPattern_v20, AttackPattern_v21,
    Malware_v20, Malware_v21,
    ObservedData_v20, ObservedData_v21, dict
]


class STIX2Converter(metaclass=ABCMeta):
    __network_assets = {'src': 'source', 'dst': 'destination'}

    @property
    def network_assets(self) -> dict:
        return self.__network_assets

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
                stix_object['id'], comment=stix_object.get('description')
            )
        )
        return attribute

    def _create_misp_object(
            self, name: str,
            stix_object: Optional[_SDO_TYPING] = None,
            object_id: Optional[str] = None) -> MISPObject:
        misp_object = MISPObject(
            name, force_timestamps=True,
            misp_objects_path_custom=_MISP_OBJECTS_PATH
        )
        if stix_object is not None:
            if object_id is None:
                self.main_parser._sanitise_object_uuid(
                    misp_object, stix_object['id']
                )
            else:
                misp_object.uuid = self.main_parser._create_v5_uuid(object_id)
            misp_object.from_dict(**self._parse_timeline(stix_object))
        return misp_object

    ############################################################################
    #                     STIX OBJECTS CONVERSION METHODS.                     #
    ############################################################################

    def _generic_parser(
            self, stix_object, feature: Optional[str] = None) -> Iterator[dict]:
        if feature is None:
            feature = stix_object['type'].replace('-', '_')
        mapping = getattr(self._mapping, f'{feature}_object_mapping')
        for field, attribute in mapping().items():
            if field in stix_object:
                yield from self._populate_object_attributes(
                    attribute, stix_object[field], stix_object['id']
                )

    def _populate_object_attribute(
            self, value: str, mapping: dict, attribute: dict) -> dict:
        return {'value': value, **mapping, **attribute}

    def _populate_object_attribute_with_data(
            self, value: dict | str, mapping: dict, **attribute: dict) -> dict:
        if isinstance(value, dict):
            return {**value, **mapping, **attribute}
        return self._populate_object_attribute(value, mapping, attribute)

    def _populate_object_attributes(
            self, mapping: dict, values: Union[list, str],
            object_id: str) -> Iterator[dict]:
        if isinstance(values, list):
            for value in values:
                uuid = self.main_parser._create_v5_uuid(
                    f"{object_id} - {mapping['object_relation']} - {value}"
                )
                yield self._populate_object_attribute(
                    value, mapping, {'uuid': uuid}
                )
        else:
            uuid = self.main_parser._create_v5_uuid(
                f"{object_id} - {mapping['object_relation']} - {values}"
            )
            yield self._populate_object_attribute(
                values, mapping, {'uuid': uuid}
            )

    ############################################################################
    #                             UTILITY METHODS.                             #
    ############################################################################

    @staticmethod
    def _handle_kill_chain_phases(kill_chain_phases: list) -> list:
        kill_chains = []
        for kill_chain in kill_chain_phases:
            kill_chains.append(
                f"{kill_chain['kill_chain_name']}:{kill_chain['phase_name']}"
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
    def _handle_misp_object_references(
            misp_object: MISPObject, *object_ids: tuple,
            relationship_type: str = 'contains'):
        for object_id in object_ids:
            if not any(reference.referenced_uuid == object_id and
                   reference.relationship_type == relationship_type
                   for reference in misp_object.references):
                misp_object.add_reference(object_id, relationship_type)

    @staticmethod
    def _parse_AS_value(number: Union[int, str]) -> str:
        if isinstance(number, int) or not number.startswith('AS'):
            return f'AS{number}'
        return number

    def _parse_timeline(self, stix_object: _SDO_TYPING) -> dict:
        # A dict-form object keeps the timestamp string the document carried,
        # and the MISP side only takes a `datetime`
        misp_object = {
            'timestamp': self.main_parser._stix_date(stix_object['modified'])
        }
        object_type = stix_object['type']
        if self._mapping.timeline_mapping(object_type) is not None:
            first, last = self._mapping.timeline_mapping(object_type)
            if not self._skip_first_seen_last_seen(stix_object):
                if stix_object.get(first):
                    misp_object['first_seen'] = stix_object[first]
                if stix_object.get(last):
                    misp_object['last_seen'] = stix_object[last]
        return misp_object

    @staticmethod
    def _skip_first_seen_last_seen(sdo: _SDO_TYPING) -> bool:
        modified = sdo['modified']
        if sdo['type'] != 'indicator':
            return modified == sdo['first_observed'] == sdo['last_observed']
        if sdo['valid_from'] != modified:
            return False
        if 'valid_until' not in sdo:
            return True
        return sdo['valid_until'] == modified

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

    def _create_cluster_args(
            self, stix_object: _GALAXY_OBJECTS_TYPING, galaxy_type: str,
            description: Optional[str] = None,
            cluster_value: Optional[str] = None) -> dict:
        object_id = stix_object['id']
        value = cluster_value or stix_object.get('name', object_id)
        cluster_uuid = self.main_parser._create_v5_uuid(
            f'{self.main_parser._extract_uuid(object_id)} -'
            f' {self.main_parser.organisation_uuid}'
        )
        self.main_parser._check_record_uuid_collision(
            'galaxy cluster', cluster_uuid, object_id
        )
        cluster_args = {
            'value': value, **self.main_parser.cluster_distribution,
            'uuid': cluster_uuid,
            'source': (
                self.main_parser._handle_creator(stix_object['created_by_ref'])
                if 'created_by_ref' in stix_object else 'misp-stix'
            )
        }
        if galaxy_type is None:
            version = stix_object.get('spec_version', '2.0')
            mapping = self._mapping.galaxy_name_mapping(stix_object['type'])
            name = f"STIX {version} {mapping['name']}"
            cluster_args.update(
                {
                    'version': ''.join(version.split('.')),
                    'collection_uuid': self.main_parser._create_v5_uuid(name)
                }
            )
            galaxy_type = f"stix-{version}-{stix_object['type']}"
        cluster_args['type'] = galaxy_type
        if description is not None:
            cluster_args['description'] = description
            return cluster_args
        if 'description' in stix_object:
            cluster_args['description'] = stix_object['description']
            return cluster_args
        cluster_args['description'] = value.capitalize()
        return cluster_args

    def _create_galaxy_args(self, stix_object: _GALAXY_OBJECTS_TYPING,
                            galaxy_type: Optional[str] = None):
        if galaxy_type is None:
            galaxy_type = stix_object['type']
        mapping = self._mapping.galaxy_name_mapping(galaxy_type)
        name = mapping['name']
        galaxy_args = {
            'description': mapping['description'], 'namespace': 'stix',
            **self.main_parser.cluster_distribution
        }
        if galaxy_type not in ('country', 'region', 'sector'):
            version = stix_object.get('spec_version', '2.0')
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

    def _handle_datetime_meta_fields(
            self, stix_object: _GALAXY_OBJECTS_TYPING):
        for field in ('created', 'modified', 'first_seen', 'last_seen'):
            if stix_object.get(field) is not None:
                dt_value = self.main_parser._stix_date(stix_object[field])
                yield field, dt_value.strftime(
                    f'{_DATETIME_REGEX}.%fZ' if dt_value.microsecond != 0
                    else f'{_DATETIME_REGEX}Z'
                )

    def _handle_meta_fields(self, stix_object: _GALAXY_OBJECTS_TYPING) -> dict:
        mapping = f"{stix_object['type'].replace('-', '_')}_meta_mapping"
        meta = dict(self._handle_datetime_meta_fields(stix_object))
        if hasattr(self._mapping, mapping):
            for feature, field in getattr(self._mapping, mapping)().items():
                if feature in stix_object:
                    meta[field] = stix_object[feature]
        return meta

    def _parse_galaxy(self, stix_object: _GALAXY_OBJECTS_TYPING,
                      object_type: Optional[str] = None):
        clusters = self.main_parser._clusters
        object_id = stix_object['id']
        if object_id in clusters:
            clusters[object_id]['used'][self.event_uuid] = False
        else:
            feature = f'_parse_galaxy_{self.main_parser.galaxy_feature}'
            clusters[object_id] = getattr(self, feature)(
                stix_object, object_type
            )

    def _parse_galaxy_as_container(self, stix_object: _GALAXY_OBJECTS_TYPING,
                                   object_type: Union[str, None]) -> dict:
        galaxy_type = object_type or stix_object['type']
        if galaxy_type not in self.main_parser._galaxies:
            self._create_galaxy_args(stix_object, galaxy_type)
        galaxy_cluster = self._create_cluster(
            stix_object, galaxy_type=object_type
        )
        if 'object_marking_refs' in stix_object:
            for marking_ref in stix_object['object_marking_refs']:
                if marking_ref not in self.main_parser._clusters:
                    continue
                cluster = self.main_parser._clusters[marking_ref]
                if cluster['used'].get(self.event_uuid) is None:
                    cluster['used'][self.event_uuid] = False
                for misp_cluster in cluster['cluster']:
                    galaxy_cluster.add_cluster_relation(
                        misp_cluster.uuid, 'marked-with'
                    )
        return {
            'cluster': galaxy_cluster,
            'used': {self.event_uuid: False}
        }

    def _parse_galaxy_as_tag_names(self, stix_object: _GALAXY_OBJECTS_TYPING,
                                   object_type: Union[str, None]) -> dict:
        tag_name = self.main_parser._build_tag(
            'misp-galaxy', object_type or stix_object['type'],
            stix_object.get('name', stix_object['id'])
        )
        return {
            'tag_names': [tag_name] if tag_name is not None else [],
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


class InternalSTIX2Converter(STIX2Converter, metaclass=ABCMeta):

    def _create_attribute_dict(self, stix_object: _SDO_TYPING) -> dict:
        attribute = super()._create_attribute_dict(stix_object)
        for field, value in self._parse_labels(stix_object).items():
            if field.startswith('misp:'):
                attribute[field.split(':')[-1]] = value
        return attribute

    ############################################################################
    #                         GALAXIES PARSING METHODS                         #
    ############################################################################

    def _create_cluster_args(
            self, stix_object: _GALAXY_OBJECTS_TYPING, galaxy_type: str,
            description: Optional[str] = None,
            cluster_value: Optional[str] = None) -> dict:
        object_id = stix_object['id']
        value = cluster_value or stix_object.get('name', object_id)
        cluster_args = {
            'uuid': self.main_parser._sanitise_cluster_uuid(object_id),
            'value': value, 'type': galaxy_type
        }
        if description is not None:
            cluster_args['description'] = description
            return cluster_args
        if 'description' in stix_object:
            cluster_args['description'] = stix_object['description']
            return cluster_args
        cluster_args['description'] = value.capitalize()
        return cluster_args

    def _create_galaxy_args(self, galaxy_type: str, galaxy_name: str):
        self.main_parser._galaxies[galaxy_type] = (
            GALAXY_DEFINITIONS[galaxy_type]
            if galaxy_type in GALAXY_DEFINITIONS
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
        mapping = f"{stix_object['type'].replace('-', '_')}_meta_mapping"
        if hasattr(self._mapping, mapping):
            meta = {}
            for feature, field in getattr(self._mapping, mapping)().items():
                if feature in stix_object:
                    meta[field] = stix_object[feature]
            meta.update(dict(self._extract_custom_fields(stix_object)))
            return meta
        return dict(self._extract_custom_fields(stix_object))

    def _parse_galaxy(self, stix_object: _GALAXY_OBJECTS_TYPING):
        clusters = self.main_parser._clusters
        object_id = stix_object['id']
        if object_id in clusters:
            clusters[object_id]['used'][self.event_uuid] = False
        else:
            feature = f'_parse_galaxy_{self.main_parser.galaxy_feature}'
            clusters[object_id] = getattr(self, feature)(stix_object)

    def _parse_galaxy_as_container(
            self, stix_object: _GALAXY_OBJECTS_TYPING) -> dict:
        galaxy_type, galaxy_name = self._extract_galaxy_labels(stix_object)
        cluster = self._parse_galaxy_cluster(stix_object, galaxy_type)
        if galaxy_name is None:
            self.main_parser._add_warning(
                'Missing MISP galaxy name label on the object with id '
                f"{stix_object['id']}"
            )
            galaxy_name = galaxy_type
        if galaxy_type not in self.main_parser._galaxies:
            self._create_galaxy_args(galaxy_type, galaxy_name)
        return {
            'cluster': cluster,
            'used': {self.event_uuid: False}
        }

    def _parse_galaxy_as_tag_names(
            self, stix_object: _GALAXY_OBJECTS_TYPING) -> dict:
        galaxy_type, _ = self._extract_galaxy_labels(stix_object)
        tag_name = self.main_parser._build_tag(
            'misp-galaxy', galaxy_type,
            stix_object.get('name', stix_object['id'])
        )
        return {
            'tag_names': [tag_name] if tag_name is not None else [],
            'used': {self.event_uuid: False}
        }

    def _parse_galaxy_cluster(
            self, stix_object: _GALAXY_OBJECTS_TYPING, galaxy_type: str,
            description: Optional[str] = None) -> Tuple[MISPGalaxyCluster, str]:
        if stix_object.get('description', '').count(' | ') == 1:
            _, description = stix_object['description'].split(' | ')
        return self._create_cluster(
            stix_object, description=description, galaxy_type=galaxy_type
        )

    ############################################################################
    #                             UTILITY METHODS.                             #
    ############################################################################

    def _extract_galaxy_labels(
            self, stix_object: _GALAXY_OBJECTS_TYPING
            ) -> Tuple[str, Optional[str]]:
        labels = self._parse_labels(stix_object)
        galaxy_type = labels.get('misp:galaxy-type')
        if not galaxy_type:
            raise UndefinedSTIXObjectError(stix_object['id'])
        return galaxy_type, labels.get('misp:galaxy-name') or None

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

    def _handle_mapping_from_labels(self, stix_object: _SDO_TYPING) -> str:
        parsed_labels = self._parse_labels(stix_object)
        if 'misp:galaxy-type' in parsed_labels:
            return '_parse_galaxy'
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
        raise UndefinedSTIXObjectError(stix_object['id'])

    @staticmethod
    def _parse_labels(stix_object: _SDO_TYPING) -> dict:
        """Index the `field=value` labels the Internal path dispatches on.

        Labels are content: an object may carry none, and any of them may be
        missing the `=` the field/value split needs. They are read through the
        Mapping interface a typed object and a Dict-Form Object both offer,
        never with attribute access: this is what every per-type converter
        dispatches on, and a dispatch reading no field takes no branch and
        drops the object saying nothing.
        """
        parsed_labels = {}
        for label in stix_object.get('labels', ()):
            field, separator, value = label.partition('=')
            if separator:
                parsed_labels[field] = value.strip('"')
        return parsed_labels
