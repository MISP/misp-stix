#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ..exceptions import (UndefinedSTIXObjectError, UnknownParsingFunctionError)
from ..external_stix2_mapping import ExternalSTIX2toMISPMapping
from ..external_stix2_to_misp import ExternalSTIX2toMISPParser
from ..internal_stix2_mapping import InternalSTIX2toMISPMapping
from ..internal_stix2_to_misp import InternalSTIX2toMISPParser
from abc import ABCMeta
from collections import defaultdict
from pymisp import AbstractMISP, MISPGalaxy, MISPGalaxyCluster, MISPObject
from stix2.v20.sdo import (
    AttackPattern as AttackPattern_v20, Malware as Malware_v20)
from stix2.v21.sdo import (
    AttackPattern as AttackPattern_v21, Malware as Malware_v21)
from typing import Optional, Tuple, Union

_MISP_OBJECTS_PATH = AbstractMISP().misp_objects_path

_GALAXY_OBJECTS_TYPING = Union[
    AttackPattern_v20, AttackPattern_v21,
    Malware_v20, Malware_v21
]
_MAIN_PARSER_TYPING = Union[
    ExternalSTIX2toMISPParser, InternalSTIX2toMISPParser
]
_SDO_TYPING = Union[
    AttackPattern_v20, AttackPattern_v21
]


class STIX2Parser(metaclass=ABCMeta):
    def __init__(self, main: _MAIN_PARSER_TYPING):
        self.__main_parser = main
    
    @property
    def main_parser(self) -> _MAIN_PARSER_TYPING:
        return self.__main_parser

    ############################################################################
    #                       MISP OBJBECT PARSING METHODS                       #
    ############################################################################

    def _create_misp_object(
            self, name: str,
            stix_object: Optional[_SDO_TYPING] = None) -> MISPObject:
        misp_object = MISPObject(
            name,
            misp_objects_path_custom=_MISP_OBJECTS_PATH,
            force_timestamps=True
        )
        if stix_object is not None:
            self._sanitise_object_uuid(misp_object, stix_object['id'])
            misp_object.from_dict(**self._parse_timeline(stix_object))
        return misp_object

    ############################################################################
    #                         GALAXIES PARSING METHODS                         #
    ############################################################################

    @staticmethod
    def _create_misp_galaxy_cluster(cluster_args: dict) -> MISPGalaxyCluster:
        cluster = MISPGalaxyCluster()
        cluster.from_dict(**cluster_args)
        return cluster
    
    def _parse_galaxy(self, stix_object: _GALAXY_OBJECTS_TYPING):
        clusters = self.main_parser._clusters
        if stix_object.id in clusters:
            misp_event_uuid = self.main_parser.misp_event.uuid
            clusters[stix_object.id]['used'][misp_event_uuid] = False
        else:
            feature = f'_parse_galaxy_{self.main_parser.galaxy_feature}'
            clusters[stix_object.id] = getattr(self, feature)(stix_object)

    ############################################################################
    #                             UTILITY METHODS                             #
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
    

class ExternalParser(STIX2Parser, metaclass=ABCMeta):
    def __init__(self):
        self._mapping = ExternalSTIX2toMISPMapping

    def parse(self, stix_object_ref: str):
        stix_object = self.main_parser._get_stix_object(stix_object_ref)
        self._parse_galaxy(stix_object)

    ############################################################################
    #                         GALAXIES PARSING METHODS                         #
    ############################################################################

    def _create_galaxy_args(self, stix_object: _GALAXY_OBJECTS_TYPING,
                            galaxy_type: Optional[str] = None):
        misp_galaxy = MISPGalaxy()
        if galaxy_type is None:
            galaxy_type = stix_object.type
        mapping = self._mapping.galaxy_name_mapping(galaxy_type)
        name = mapping['name']
        galaxy_args = {
            'description': mapping['description'], 'namespace': 'stix'
        }
        if galaxy_type not in ('country', 'region', 'sector'):
            version = getattr(stix_object, 'spec_version', '2.0')
            name = f"STIX {version} {name}"
            galaxy_args.update(
                {
                    'uuid': self._create_v5_uuid(name),
                    'version': ''.join(version.split('.')),
                    'icon': mapping['icon']
                }
            )
            galaxy_type = f'stix-{version}-{galaxy_type}'
        misp_galaxy.from_dict(
            **{
                'type': galaxy_type, 'name': name, **galaxy_args
            }
        )
        self._galaxies[galaxy_type] = misp_galaxy

    def _parse_galaxy_as_container(self, stix_object: _GALAXY_OBJECTS_TYPING,
                                   object_type: Optional[str] = None) -> dict:
        if object_type is None:
            object_type = stix_object.type
        if object_type not in self.main_parser._galaxies:
            self._create_galaxy_args(
                stix_object, object_type
            )
        return {
            'cluster': self._create_cluster(stix_object),
            'used': {self.main_parser.misp_event.uuid: False}
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


class InternalParser(STIX2Parser, metaclass=ABCMeta):
    def __init__(self):
        self._mapping = InternalSTIX2toMISPMapping

    ############################################################################
    #                         GALAXIES PARSING METHODS                         #
    ############################################################################

    def _create_galaxy_args(
            self, description: str, galaxy_type: str, galaxy_name: str):
        misp_galaxy = MISPGalaxy()
        misp_galaxy.from_dict(
            **{
                'type': galaxy_type,
                'name': galaxy_name,
                'description': description
            }
        )
        self.main_parser._galaxies[galaxy_type] = misp_galaxy

    def _parse_galaxy_as_container(
            self, stix_object: _GALAXY_OBJECTS_TYPING) -> dict:
        galaxy_type, galaxy_name = self._extract_galaxy_labels(
            stix_object.labels
        )
        cluster, galaxy_description = self._parse_galaxy_cluster(
            stix_object, galaxy_type
        )
        if galaxy_type not in self.main_parser._galaxies:
            self._create_galaxy_args(
                galaxy_description, galaxy_type, galaxy_name
            )
        return {
            'cluster': cluster,
            'used': {self.main_parser.misp_event.uuid: False}
        }

    def _parse_galaxy_cluster(
            self, stix_object: _GALAXY_OBJECTS_TYPING,
            galaxy_type: str) -> Tuple[MISPGalaxyCluster, str]:
        if ' | ' in stix_object.description:
            galaxy_desc, cluster_desc = stix_object.description.split(' | ')
            cluster = self._create_cluster(
                stix_object, description=cluster_desc, galaxy_type=galaxy_type
            )
            return cluster, galaxy_desc
        cluster = self._create_cluster(stix_object, galaxy_type=galaxy_type)
        return cluster, stix_object.description
        
    
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
            feature = 'aliases' if reference.get('source_name') == 'cve' else 'external_id'
            if reference.get('external_id'):
                meta[feature].append(reference['external_id'])
        if 'external_id' in meta and len(meta['external_id']) == 1:
            meta['external_id'] = meta.pop('external_id')[0]
        return meta

    def _handle_object_mapping(self, labels: list, object_id: str) -> str:
        parsed_labels = {
            key: value.strip('"') for key, value
            in (label.split('=') for label in labels)
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