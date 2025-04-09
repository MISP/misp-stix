#!/usr/bin/env python3

import json
import sys
import traceback
from .exceptions import UnavailableGalaxyResourcesError
from abc import ABCMeta
from collections import defaultdict
from datetime import datetime
from mixbox.namespaces import NamespaceNotFoundError
from pathlib import Path
from pymisp import MISPEvent, MISPObject
from pymisp.abstract import resources_path
from stix.core import STIXPackage
from stix2.exceptions import InvalidValueError
from stix2.parsing import dict_to_stix2, parse as stix2_parser, ParseError
from stix2.v20.bundle import Bundle as Bundle_v20
from stix2.v21.bundle import Bundle as Bundle_v21
from typing import Optional, Union
from uuid import UUID, uuid5

_DATA_PATH = Path(__file__).parents[1].resolve() / 'data'

MISP_org_uuid = '55f6ea65-aa10-4c5a-bf01-4f84950d210f'

_DEFAULT_DISTRIBUTION = 0

_VALID_DISTRIBUTIONS = (0, 1, 2, 3, 4)
_RFC_VERSIONS = (1, 3, 4, 5)
_UUIDv4 = UUID('76beed5f-7251-457e-8c2a-b45f7b589d3d')


def _get_stix2_content_version(stix2_content: dict):
    for stix_object in stix2_content['objects']:
        if stix_object.get('spec_version'):
            return '2.1'
    return '2.0'


def _handle_stix2_loading_error(stix2_content: dict):
    version = _get_stix2_content_version(stix2_content)
    if isinstance(stix2_content, dict):
        if version == '2.1' and stix2_content.get('spec_version') == '2.0':
            del stix2_content['spec_version']
            return dict_to_stix2(
                stix2_content, allow_custom=True, interoperability=True
            )
        if version == '2.0' and stix2_content.get('spec_version') == '2.1':
            stix2_content['spec_version'] = '2.0'
            return dict_to_stix2(
                stix2_content, allow_custom=True, interoperability=True
            )
        bundle = Bundle_v21 if version == '2.1' else Bundle_v20
        if 'objects' in stix2_content:
            stix2_content = stix2_content['objects']
    return bundle(*stix2_content, allow_custom=True, interoperability=True)


def _load_stix1_package(filename, tries=0):
    try:
        return STIXPackage.from_xml(filename)
    except NamespaceNotFoundError:
        if tries > 0:
            sys.exit('Cannot handle STIX namespace')
        _update_namespaces()
        return _load_stix1_package(filename, tries + 1)
    except NotImplementedError:
        sys.exit('Missing python library: stix_edh')
    except Exception:
        try:
            import maec
            return STIXPackage.from_xml(filename)
        except ImportError:
            sys.exit('Missing python library: maec')
        except Exception as error:
            sys.exit(f'Error while loading STIX1 package: {error.__str__()}')


def _load_stix2_content(filename):
    with open(filename, 'rt', encoding='utf-8') as f:
        stix2_content = f.read()
    try:
        return stix2_parser(
            stix2_content, allow_custom=True, interoperability=True
        )
    except (InvalidValueError, ParseError):
        return _handle_stix2_loading_error(json.loads(stix2_content))


def _load_json_file(path):
    with open(path, 'rb') as f:
        return json.load(f)


def _update_namespaces():
    from mixbox.namespaces import Namespace, register_namespace
    # LIST OF ADDITIONAL NAMESPACES
    # can add additional ones whenever it is needed
    ADDITIONAL_NAMESPACES = [
        Namespace('http://us-cert.gov/ciscp', 'CISCP',
                  'http://www.us-cert.gov/sites/default/files/STIX_Namespace/ciscp_vocab_v1.1.1.xsd'),
        Namespace('http://taxii.mitre.org/messages/taxii_xml_binding-1.1', 'TAXII',
                  'http://docs.oasis-open.org/cti/taxii/v1.1.1/cs01/schemas/TAXII-XMLMessageBinding-Schema.xsd')
    ]
    for namespace in ADDITIONAL_NAMESPACES:
        register_namespace(namespace)


class ExternalSTIXtoMISPParser(metaclass=ABCMeta):
    def _set_cluster_distribution(
            self, distribution: int, sharing_group_id: Union[int, None]):
        cl_dis = {'distribution': self._sanitise_distribution(distribution)}
        if distribution == 4:
            if sharing_group_id is not None:
                cl_dis['sharing_group_id'] = self._sanitise_sharing_group_id(
                    sharing_group_id
                )
            else:
                cl_dis['distribution'] = 0
                self._cluster_distribution_and_sharing_group_id_error()
        self.__cluster_distribution = cl_dis

    def _set_organisation_uuid(self, organisation_uuid: Union[str, None]):
        self.__organisation_uuid = organisation_uuid or MISP_org_uuid

    @property
    def cluster_distribution(self) -> dict:
        return self.__cluster_distribution

    @property
    def organisation_uuid(self) -> str:
        return self.__organisation_uuid


class STIXtoMISPParser(metaclass=ABCMeta):
    def __init__(self):
        self._identifier: str
        self.__distribution: int
        self.__galaxies_as_tags: bool
        self.__galaxy_feature: str
        self.__producer: Union[str, None]
        self.__relationship_types: dict
        self.__sharing_group_id: Union[int, None]
        self.__title: Union[str, None]

        self.__errors: defaultdict = defaultdict(set)
        self.__warnings: defaultdict = defaultdict(set)
        self.__replacement_uuids: dict = {}

    def _populate_misp_event(self):
        self.misp_events.append(self.misp_event)

    def _sanitise_distribution(self, distribution: int) -> int:
        try:
            sanitised = int(distribution)
        except (TypeError, ValueError) as error:
            self._distribution_error(error)
            return 0
        if sanitised in _VALID_DISTRIBUTIONS:
            return sanitised
        self._distribution_value_error(sanitised)
        return 0

    def _sanitise_sharing_group_id(
            self, sharing_group_id: Union[int, None]) -> Union[int, None]:
        if sharing_group_id is None:
            return None
        try:
            return int(sharing_group_id)
        except (TypeError, ValueError) as error:
            self._sharing_group_id_error(error)
            return None

    def _set_misp_event(self, misp_event: MISPEvent):
        self.__misp_event = misp_event

    def _set_misp_events(self):
        self.__misp_events = []

    def _set_parameters(self, distribution: int = _DEFAULT_DISTRIBUTION,
                        sharing_group_id: Optional[int] = None,
                        force_contextual_data: Optional[bool] = False,
                        galaxies_as_tags: Optional[bool] = False,
                        single_event: Optional[bool] = False,
                        producer: Optional[str] = None,
                        title: Optional[str] = None):
        self.__distribution = self._sanitise_distribution(distribution)
        self.__sharing_group_id = self._sanitise_sharing_group_id(
            sharing_group_id
        )
        if self.sharing_group_id is None and self.distribution == 4:
            self.__distribution = 0
            self._distribution_and_sharing_group_id_error()
        self.__force_contextual_data = force_contextual_data
        self.__galaxies_as_tags = galaxies_as_tags
        self.__galaxy_feature = (
            'as_tag_names' if self.galaxies_as_tags else 'as_container'
        )
        self.__single_event = single_event
        self.__producer = producer
        self.__title = title

    def _set_single_event(self, single_event: bool):
        self.__single_event = single_event

    ############################################################################
    #                                PROPERTIES                                #
    ############################################################################

    @property
    def distribution(self) -> int:
        return self.__distribution

    @property
    def event_title(self) -> Union[str, None]:
        return self.__title

    @property
    def errors(self) -> dict:
        return self.__errors

    @property
    def force_contextual_data(self) -> bool:
        return self.__force_contextual_data

    @property
    def galaxies_as_tags(self) -> bool:
        return self.__galaxies_as_tags

    @property
    def galaxy_definitions(self) -> Path:
        try:
            return self.__galaxy_definitions
        except AttributeError:
            self.__get_galaxy_definitions()
            return self.__galaxy_definitions

    @property
    def galaxy_feature(self) -> str:
        return self.__galaxy_feature

    @property
    def misp_event(self) -> MISPEvent:
        return self.__misp_event

    @property
    def misp_events(self) -> Union[list, MISPEvent]:
        return getattr(
            self, '_STIXtoMISPParser__misp_events', self.__misp_event
        )

    @property
    def producer(self) -> Union[str, None]:
        return self.__producer

    @property
    def relationship_types(self) -> dict:
        try:
            return self.__relationship_types
        except AttributeError:
            self.__get_relationship_types()
            return self.__relationship_types

    @property
    def replacement_uuids(self) -> dict:
        return self.__replacement_uuids

    @property
    def sharing_group_id(self) -> Union[int, None]:
        return self.__sharing_group_id

    @property
    def single_event(self) -> bool:
        return self.__single_event

    @property
    def synonyms_mapping(self) -> dict:
        try:
            return self.__synonyms_mapping
        except AttributeError:
            self.__get_synonyms_mapping()
            return self.__synonyms_mapping

    @property
    def warnings(self) -> defaultdict:
        return self.__warnings

    ############################################################################
    #                   ERRORS AND WARNINGS HANDLING METHODS                   #
    ############################################################################

    def _add_error(self, error: str):
        self.__errors[self._identifier].add(error)

    def _add_warning(self, warning: str):
        self.__warnings[self._identifier].add(warning)

    def _cluster_distribution_and_sharing_group_id_error(self):
        self.__errors['init'].add(
            'Invalid Cluster Sharing Group ID - '
            'cannot be None when distribution is 4'
        )

    def _distribution_and_sharing_group_id_error(self):
        self.__errors['init'].add(
            'Invalid Sharing Group ID - cannot be None when distribution is 4'
        )

    def _distribution_and_sharing_group_id_error(self):
        self.__errors['init'].add(
            'Invalid Sharing Group ID - cannot be None when distribution is 4'
        )

    def _distribution_error(self, exception: Exception):
        self.__errors['init'].add(
            f'Wrong distribution format: {exception}'
        )

    def _distribution_value_error(self, distribution: int):
        self.__errors['init'].add(
            f'Invalid distribution value: {distribution}'
        )

    @staticmethod
    def _parse_traceback(exception: Exception) -> str:
        tb = ''.join(traceback.format_tb(exception.__traceback__))
        return f'{tb}{exception.__str__()}'

    def _sharing_group_id_error(self, exception: Exception):
        self.__errors['init'].add(
            f'Wrong sharing group id format: {exception}'
        )

    ############################################################################
    #            MISP OBJECT RELATIONSHIPS MAPPING CREATION METHODS            #
    ############################################################################

    def __get_relationship_types(self):
        relationships_path = resources_path / 'misp-objects' / 'relationships'
        relationships = _load_json_file(relationships_path / 'definition.json')
        self.__relationship_types = {
            relationship['name']: relationship['opposite'] for relationship
            in relationships['values'] if 'opposite' in relationship
        }

    ############################################################################
    #          SYNONYMS TO GALAXY TAG NAMES MAPPING HANDLING METHODS.          #
    ############################################################################

    def __check_fingerprint(self):
        latest_fingerprint = self.__get_misp_galaxy_fingerprint()
        if latest_fingerprint is not None:
            fingerprint_path = _DATA_PATH / 'synonymsToTagNames.fingerprint'
            with open(fingerprint_path, 'wt', encoding='utf-8') as f:
                f.write(latest_fingerprint)

    def __galaxies_up_to_date(self) -> bool:
        fingerprint_path = _DATA_PATH / 'synonymsToTagNames.fingerprint'
        if not fingerprint_path.exists():
            return False
        latest_fingerprint = self.__get_misp_galaxy_fingerprint()
        if latest_fingerprint is None:
            return False
        with open(fingerprint_path, 'rt', encoding='utf-8') as f:
            fingerprint = f.read()
        return fingerprint == latest_fingerprint

    def __get_galaxy_definitions(self):
        definitions_path = _DATA_PATH / 'galaxyDefinitions.json'
        if not definitions_path.exists() or not self.__galaxies_up_to_date():
            data_path = _DATA_PATH / 'misp-galaxy' / 'galaxies'
            if not data_path.exists():
                raise UnavailableGalaxyResourcesError(data_path)
            definitions = {}
            for filename in data_path.glob('*.json'):
                galaxy_definition = _load_json_file(filename)
                definitions[galaxy_definition['type']] = galaxy_definition
            with open(definitions_path, 'wt', encoding='utf-8') as f:
                f.write(json.dumps(definitions))
            self.__check_fingerprint()
        self.__galaxy_definitions = _load_json_file(definitions_path)

    @staticmethod
    def __get_misp_galaxy_fingerprint() -> Optional[str]:
        galaxy_git = _DATA_PATH / 'misp-galaxy' / '.git'

        if galaxy_git.is_file():
            with open(galaxy_git, 'rt') as f:
                git_file_content = f.read()
                if git_file_content.startswith('gitdir:'):
                    galaxy_git = (
                        _DATA_PATH / 'misp-galaxy' /
                        git_file_content.split(':')[1].strip()
                    )
                else:
                    return None

        head_file = galaxy_git / 'HEAD'
        if head_file.is_file():
            with open(head_file, 'rt') as f:
                return f.read().strip()

        return None

    def __get_synonyms_mapping(self):
        synonyms_path = _DATA_PATH / 'synonymsToTagNames.json'
        if not synonyms_path.exists() or not self.__galaxies_up_to_date():
            data_path = _DATA_PATH / 'misp-galaxy' / 'clusters'
            if not data_path.exists():
                raise UnavailableGalaxyResourcesError(data_path)
            synonyms_mapping = defaultdict(list)
            for filename in data_path.glob('*.json'):
                cluster_definition = _load_json_file(filename)
                cluster_type = f"misp-galaxy:{cluster_definition['type']}"
                for cluster in cluster_definition['values']:
                    value = cluster['value']
                    tag_name = f'{cluster_type}="{value}"'
                    synonyms_mapping[value].append(tag_name)
                    if cluster.get('meta', {}).get('synonyms') is not None:
                        for synonym in cluster['meta']['synonyms']:
                            synonyms_mapping[synonym].append(tag_name)
            with open(synonyms_path, 'wt', encoding='utf-8') as f:
                f.write(json.dumps(synonyms_mapping))
            self.__check_fingerprint()
        self.__synonyms_mapping = _load_json_file(synonyms_path)

    ############################################################################
    #                     UUID SANITATION HANDLING METHODS                     #
    ############################################################################

    def _check_uuid(self, object_id: str):
        object_uuid = self._extract_uuid(object_id)
        replacement = (
            UUID(object_uuid).version not in _RFC_VERSIONS and
            object_uuid not in self.replacement_uuids
        )
        if replacement:
            self.replacement_uuids[object_uuid] = self._create_v5_uuid(
                object_uuid
            )

    @staticmethod
    def _create_v5_uuid(value: str) -> UUID:
        return uuid5(_UUIDv4, value)

    def _sanitise_attribute_uuid(
            self, object_id: str, comment: Optional[str] = None) -> dict:
        attribute_uuid = self._extract_uuid(object_id)
        attribute_comment = f'Original UUID was: {attribute_uuid}'
        if attribute_uuid in self.replacement_uuids:
            return {
                'uuid': self.replacement_uuids[attribute_uuid],
                'comment': (
                    attribute_comment if comment is None
                    else f'{comment} - {attribute_comment}'
                )
            }
        if UUID(attribute_uuid).version not in _RFC_VERSIONS:
            sanitised_uuid = self._create_v5_uuid(attribute_uuid)
            self.replacement_uuids[attribute_uuid] = sanitised_uuid
            return {
                'uuid': sanitised_uuid,
                'comment': (
                    attribute_comment if comment is None
                    else f'{comment} - {attribute_comment}'
                )
            }
        attribute = {'uuid': attribute_uuid}
        if comment is not None:
            attribute['comment'] = comment
        return attribute

    def _sanitise_object_uuid(
            self, misp_object: Union[MISPEvent, MISPObject], object_id: str):
        object_uuid = self._extract_uuid(object_id)
        if object_uuid in self.replacement_uuids:
            comment = f'Original UUID was: {object_uuid}'
            misp_object.comment = (
                f'{misp_object.comment} - {comment}'
                if hasattr(misp_object, 'comment') else comment
            )
            object_uuid = self.replacement_uuids[object_uuid]
        misp_object.uuid = object_uuid

    def _sanitise_uuid(self, object_id: str) -> str:
        object_uuid = self._extract_uuid(object_id)
        if UUID(object_uuid).version not in _RFC_VERSIONS:
            if object_uuid in self.replacement_uuids:
                return self.replacement_uuids[object_uuid]
            sanitised_uuid = self._create_v5_uuid(object_uuid)
            self.replacement_uuids[object_uuid] = sanitised_uuid
            return sanitised_uuid
        return object_uuid

    ############################################################################
    #                             UTILITY METHODS.                             #
    ############################################################################

    @staticmethod
    def _timestamp_from_date(date: datetime) -> int:
        return int(date.timestamp())
