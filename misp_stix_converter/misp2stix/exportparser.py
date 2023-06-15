# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import traceback
from .stix1_mapping import MISPtoSTIX1Mapping
from .stix20_mapping import MISPtoSTIX20Mapping
from .stix21_mapping import MISPtoSTIX21Mapping
from abc import ABCMeta
from collections import defaultdict
from datetime import datetime, timezone
from pymisp import MISPAttribute, MISPObject
from typing import Optional, Union


class MISPtoSTIXParser(metaclass=ABCMeta):
    __composite_separators = ('|', '_')
    __published_fields = ('published', 'publish_timestamp')
    __PE_RELATIONSHIP_TYPES = ('includes', 'included-in')

    def __init__(self):
        super().__init__()
        self.__errors: defaultdict = defaultdict(list)
        self.__warnings: defaultdict = defaultdict(set)
        self._identifier: str
        self._mapping: Union[
            MISPtoSTIX1Mapping, MISPtoSTIX20Mapping, MISPtoSTIX21Mapping
        ]
        self._misp_event: dict

    @property
    def composite_separators(cls) -> tuple:
        return cls.__composite_separators

    @property
    def errors(self) -> dict:
        return self.__errors

    @property
    def warnings(self) -> dict:
        return {identifier: list(warnings) for identifier, warnings in self.__warnings.items()}

    ################################################################################
    #                           COMMON PARSING FUNCTIONS                           #
    ################################################################################

    @staticmethod
    def _extract_multiple_object_attributes(attributes: list, force_single: Optional[tuple] = None) -> dict:
        attributes_dict = defaultdict(list)
        if force_single is not None:
            for attribute in attributes:
                relation = attribute['object_relation']
                if relation in force_single:
                    attributes_dict[relation] = attribute['value']
                else:
                    attributes_dict[relation].append(attribute['value'])
            return attributes_dict
        for attribute in attributes:
            attributes_dict[attribute['object_relation']].append(attribute['value'])
        return attributes_dict

    @staticmethod
    def _extract_multiple_object_attributes_with_data(attributes: list, force_single: tuple = (), with_data: tuple = ()) -> dict:
        attributes_dict = defaultdict(list)
        for attribute in attributes:
            relation = attribute['object_relation']
            value = attribute['value']
            if relation in with_data and attribute.get('data'):
                value = (value, attribute['data'])
            if relation in force_single:
                attributes_dict[relation] = value
            else:
                attributes_dict[relation].append(value)
        return attributes_dict

    @staticmethod
    def _extract_multiple_object_attributes_with_uuid(attributes: list, with_uuid: Optional[tuple] = None) -> dict:
        attributes_dict = defaultdict(list)
        if with_uuid is not None:
            for attribute in attributes:
                relation = attribute['object_relation']
                value = (attribute['value'], attribute['uuid']) if relation in with_uuid else attribute['value']
                attributes_dict[relation].append(value)
            return attributes_dict
        for attribute in attributes:
            attributes_dict[attribute['object_relation']].append(
                (
                    attribute['value'],
                    attribute['uuid']
                )
            )
        return attributes_dict

    @staticmethod
    def _extract_object_attributes(attributes: list) -> dict:
        return {attribute['object_relation']: attribute['value'] for attribute in attributes}

    @staticmethod
    def _extract_object_attributes_with_uuid(attributes: list, with_uuid: Optional[tuple] = None) -> dict:
        if with_uuid is not None:
            attributes_dict = {}
            for attribute in attributes:
                relation = attribute['object_relation']
                attributes_dict[relation] = (attribute['value'], attribute['uuid']) if relation in with_uuid else attribute['value']
            return attributes_dict
        return {attribute['object_relation']: (attribute['value'], attribute['uuid']) for attribute in attributes}

    def _extract_object_attribute_tags_and_galaxies(self, misp_object: dict) -> tuple:
        tags: set = set()
        galaxies: dict = {}
        for attribute in misp_object['Attribute']:
            if attribute.get('Galaxy'):
                for galaxy in attribute['Galaxy']:
                    galaxy_type = galaxy['type']
                    if galaxy_type in galaxies:
                        self._merge_galaxy_clusters(galaxies[galaxy_type], galaxy)
                    else:
                        galaxies[galaxy_type] = galaxy
            if attribute.get('Tag'):
                tags.update(tag['name'] for tag in attribute['Tag'])
        return tags, galaxies

    def _handle_event_tags_and_galaxies(self) -> tuple:
        if self._misp_event.get('Galaxy'):
            tag_names: list = []
            for galaxy in self._misp_event['Galaxy']:
                galaxy_type = galaxy['type']
                to_call = self._mapping.galaxy_types_mapping(galaxy_type)
                if to_call is not None:
                    getattr(self, to_call.format('event'))(galaxy)
                    tag_names.extend(self._quick_fetch_tag_names(galaxy))
                else:
                    self._handle_undefined_event_galaxy(galaxy)
            return tuple(tag['name'] for tag in self._misp_event.get('Tag', []) if tag['name'] not in tag_names)
        return tuple(tag['name'] for tag in self._misp_event.get('Tag', []))

    def _parse_event_galaxies(self, galaxies: list):
        for galaxy in galaxies:
            galaxy_type = galaxy['type']
            to_call = self._mapping.galaxy_types_mapping(galaxy_type)
            if to_call is not None:
                getattr(self, to_call.format('parent'))(galaxy)
            else:
                self._handle_undefined_parent_galaxy(galaxy)

    ################################################################################
    #                           COMMON UTILITY FUNCTIONS                           #
    ################################################################################

    @staticmethod
    def _datetime_from_str(timestamp: Union[datetime, str]) -> datetime:
        if isinstance(timestamp, datetime):
            return timestamp
        regex = '%Y-%m-%dT%H:%M:%S'
        if '.' in timestamp:
            regex = f'{regex}.%f'
        if timestamp.endswith('Z') or '+' in timestamp:
            regex = f'{regex}%z'
        return datetime.strptime(timestamp, regex)

    @staticmethod
    def _datetime_from_timestamp(timestamp: Union[datetime, str]) -> datetime:
        if isinstance(timestamp, datetime):
            return timestamp
        return datetime.fromtimestamp(int(timestamp), timezone.utc)

    @staticmethod
    def _fetch_ids_flag(attributes: list) -> bool:
        for attribute in attributes:
            if attribute.get('to_ids', False):
                return True
        return False

    def _is_published(self) -> bool:
        return all(self._misp_event.get(feature) for feature in self.__published_fields)

    def _is_reference_included(self, reference: dict, name: str) -> bool:
        if reference['relationship_type'] not in self.__PE_RELATIONSHIP_TYPES:
            return False
        return 'Object' in reference and reference['Object'].get('name') == name

    @staticmethod
    def _merge_galaxy_clusters(galaxies: dict, galaxy: dict):
        for cluster in galaxy['GalaxyCluster']:
            for galaxy_cluster in galaxies['GalaxyCluster']:
                if cluster['uuid'] == galaxy_cluster['uuid']:
                    break
            else:
                galaxies['GalaxyCluster'].append(cluster)

    @staticmethod
    def _quick_fetch_tag_names(galaxy: dict) -> tuple:
        return tuple(f'misp-galaxy:{galaxy["type"]}="{cluster["value"]}"' for cluster in galaxy["GalaxyCluster"])

    @staticmethod
    def _select_single_feature(attributes: dict, feature: str) -> Union[str, tuple]:
        if isinstance(attributes[feature], list):
            if len(attributes[feature]) == 1:
                return attributes.pop(feature)[0]
            return attributes[feature].pop(0)
        return attributes.pop(feature)


    ################################################################################
    #                     ERRORS & WARNINGS HANDLING FUNCTIONS                     #
    ################################################################################

    def _attribute_error(self, attribute: Union[MISPAttribute, dict], exception: Exception):
        features = f"{attribute['type']} attribute: {attribute['value']} (uuid: {attribute['uuid']})"
        tb = self._parse_traceback(exception)
        message = f"Error with the {features}:\n{tb}."
        self.__errors[self._identifier].append(message)
        self._parse_custom_attribute(attribute)

    def _attribute_galaxy_not_mapped_warning(self, galaxy_type: str, attribute_type: str):
        message = f"{galaxy_type} galaxy in {attribute_type} attribute not mapped."
        self.__warnings[self._identifier].add(message)

    def _attribute_not_mapped_warning(self, attribute_type: str):
        message = f"MISP Attribute type {attribute_type} not mapped."
        self.__warnings[self._identifier].add(message)

    def _composite_attribute_value_warning(self, attribute_type: str, value: str):
        message = f"The {attribute_type} MISP Attribute should have a composite value: {value}."
        self.__warnings[self._identifier].add(message)

    def _invalid_attribute_hash_value_error(self, attribute: Union[MISPAttribute, dict]):
        features = f"Error with the {attribute['type']} value: {attribute['value']}"
        message = f"{features} is not a valid {attribute['type']} hash."
        self.__errors[self._identifier].append(message)

    def _invalid_object_hash_value_error(self, hash_type: str, misp_object: Union[MISPObject, dict]):
        features = f"{misp_object['name']} object (uuid: {misp_object['uuid']})"
        message = f"Error with the {features}: Invalid {hash_type} value."
        self.__errors[self._identifier].append(message)

    def _event_galaxy_not_mapped_warning(self, galaxy_type: str):
        message = f'{galaxy_type} galaxy in event not mapped.'
        self.__warnings[self._identifier].add(message)

    def _missing_orgc_error(self):
        self.__errors[self._identifier].append(f'Missing Orgc field.')

    def _missing_orgc_field_error(self, orgc: dict):
        missing = (field for field in ('name', 'uuid') if field not in orgc)
        self.__errors[self._identifier].append(
            f"Error with the Orgc field missing its {' and '.join(missing)}"
            f"{'values' if len(missing) > 1 else 'value'}. Please make sure"
            f" both the name and uuid values are provided."
        )

    def _object_error(self, misp_object: dict, exception: Exception):
        features = f"{misp_object['name']} object (uuid: {misp_object['uuid']})"
        tb = self._parse_traceback(exception)
        message = f"Error with the {features}:\n{tb}."
        self.__errors[self._identifier].append(message)
        self._parse_custom_object(misp_object)

    def _object_galaxy_not_mapped_warning(self, galaxy_type: str, object_name: str):
        message = f"{galaxy_type} galaxy in {object_name} object not mapped."
        self.__warnings[self._identifier].add(message)

    def _object_galaxy_incompatible_warning(self, galaxy_type: str, object_name: str):
        message = f"{galaxy_type} galaxy not compatible with the {object_name}"
        self.__warnings[self._identifier].add(f"{message} STIX 1 conver")

    def _object_not_mapped_warning(self, object_name: str):
        message = f"MISP Object name {object_name} not mapped."
        self.__warnings[self._identifier].add(message)

    def _parent_galaxy_not_mapping_warning(self, galaxy_type: str):
        message = f'{galaxy_type} galaxy from event level not mapped.'
        self.__warnings[self._identifier].add(message)

    @staticmethod
    def _parse_traceback(exception: Exception) -> str:
        tb = ''.join(traceback.format_tb(exception.__traceback__))
        return f'{tb}{exception.__str__()}'

    def _pe_reference_warning(self, file_uuid: str):
        message = f"Unable to find the pe object related to the file object {file_uuid}."
        self.__warnings[self._identifier].add(message)

    def _referenced_object_name_warning(self, object_name: str, referenced_uuid: str):
        message = f"Reference to a non existing {object_name} object with uuid: {referenced_uuid}."
        self.__warnings[self._identifier].add(message)

    def _required_fields_missing_warning(self, object_type: str, object_name: str):
        message = f"Missing minimum requirement to build a {object_type} object from a {object_name} MISP Object."
        self.__warnings[self._identifier].add(message)

    def _unclear_pe_references_warning(self, file_uuid: str, pe_uuids: list):
        message = f"The file object {file_uuid} has more than one reference to pe objects: {', '.join(pe_uuids)}"
        self.__warnings[self._identifier].add(message)
