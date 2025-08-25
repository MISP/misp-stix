# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import json
import traceback
from .stix1_mapping import MISPtoSTIX1Mapping
from .stix20_mapping import MISPtoSTIX20Mapping
from .stix21_mapping import MISPtoSTIX21Mapping
from abc import ABCMeta
from collections import defaultdict
from datetime import datetime, timezone
from io import BufferedIOBase, TextIOBase
from pathlib import Path
from pymisp import MISPAttribute, MISPObject
from typing import IO, Optional, Union


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
        return {
            identifier: list(warnings)
            for identifier, warnings in self.__warnings.items()
        }

    def parse_json_file(self, filename: Path | str):
        with open(filename, 'rt', encoding='utf-8') as f:
            json_content = json.loads(f.read())
        self._parse_json_content(json_content)

    def parse_json_content(self, json_content: IO | str | bytes | dict | list):
        if isinstance(json_content, (BufferedIOBase, TextIOBase)):
            json_content = json_content.read()
        if isinstance(json_content, (str, bytes)):
            json_content = json.loads(json_content)
        self._parse_json_content(json_content)

    ############################################################################
    #                         COMMON PARSING FUNCTIONS                         #
    ############################################################################

    @staticmethod
    def _extract_multiple_object_attributes(
            attributes: list, force_single: Optional[tuple] = None) -> dict:
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
            attributes_dict[attribute['object_relation']].append(
                attribute['value']
            )
        return attributes_dict

    @staticmethod
    def _extract_multiple_object_attributes_with_data(
            attributes: list, force_single: tuple = (),
            with_data: tuple = ()) -> dict:
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
    def _extract_multiple_object_attributes_with_uuid(
            attributes: list, with_uuid: Optional[tuple] = None) -> dict:
        attributes_dict = defaultdict(list)
        if with_uuid is not None:
            for attribute in attributes:
                relation = attribute['object_relation']
                value = (
                    (attribute['value'], attribute['uuid'])
                    if relation in with_uuid else attribute['value']
                )
                attributes_dict[relation].append(value)
            return attributes_dict
        for attribute in attributes:
            attributes_dict[attribute['object_relation']].append(
                (attribute['value'], attribute['uuid'])
            )
        return attributes_dict

    @staticmethod
    def _extract_object_attributes(attributes: list) -> dict:
        return {
            attribute['object_relation']: attribute['value']
            for attribute in attributes
        }

    @staticmethod
    def _extract_object_attributes_with_uuid(
            attributes: list, with_uuid: Optional[tuple] = None) -> dict:
        if with_uuid is not None:
            attributes_dict = {}
            for attribute in attributes:
                relation = attribute['object_relation']
                attributes_dict[relation] = (
                    (attribute['value'], attribute['uuid'])
                    if relation in with_uuid else attribute['value']
                )
            return attributes_dict
        return {
            attr['object_relation']: (attr['value'], attr['uuid'])
            for attr in attributes
        }

    def _extract_object_attribute_tags_and_galaxies(
            self, misp_object: dict) -> tuple:
        tags: set = set()
        galaxies: dict = {}
        for attribute in misp_object['Attribute']:
            if attribute.get('Galaxy'):
                for galaxy in attribute['Galaxy']:
                    galaxy_type = galaxy['type']
                    if galaxy_type in galaxies:
                        self._merge_galaxy_clusters(
                            galaxies[galaxy_type], galaxy
                        )
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
            return tuple(
                tag['name'] for tag in self._misp_event.get('Tag', [])
                if tag['name'] not in tag_names
            )
        return tuple(tag['name'] for tag in self._misp_event.get('Tag', []))

    def _parse_event_galaxies(self, galaxies: list):
        for galaxy in galaxies:
            galaxy_type = galaxy['type']
            to_call = self._mapping.galaxy_types_mapping(galaxy_type)
            if to_call is not None:
                getattr(self, to_call.format('parent'))(galaxy)
            else:
                self._handle_undefined_parent_galaxy(galaxy)

    ############################################################################
    #                         COMMON UTILITY FUNCTIONS                         #
    ############################################################################

    @staticmethod
    def _datetime_from_str(timestamp: Union[datetime, str]) -> datetime:
        if isinstance(timestamp, datetime):
            return timestamp
        regex = f"%Y-%m-%d{'T' if 'T' in timestamp else ' '}%H:%M:%S"
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
        return all(
            self._misp_event.get(feature) for feature in self.__published_fields
        )

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
        return tuple(
            f'misp-galaxy:{galaxy["type"]}="{cluster["value"]}"'
            for cluster in galaxy["GalaxyCluster"]
        )

    @staticmethod
    def _select_single_feature(
            attributes: dict, feature: str) -> Union[str, tuple]:
        if isinstance(attributes[feature], list):
            if len(attributes[feature]) == 1:
                return attributes.pop(feature)[0]
            return attributes[feature].pop(0)
        return attributes.pop(feature)


    ############################################################################
    #                   ERRORS & WARNINGS HANDLING FUNCTIONS                   #
    ############################################################################

    def _attribute_error(self, attribute: Union[MISPAttribute, dict],
                         exception: Exception):
        features = (
            f"{attribute['type']} attribute: {attribute['value']} "
            f"(uuid: {attribute['uuid']})"
        )
        tb = self._parse_traceback(exception)
        message = f"Error with the {features}:\n{tb}."
        self.__errors[self._identifier].append(message)
        self._parse_custom_attribute(attribute)

    def _attribute_galaxy_not_mapped_warning(
            self, galaxy_type: str, attribute_type: str):
        self.__warnings[self._identifier].add(
            f"{galaxy_type} galaxy in {attribute_type} attribute not mapped."
        )

    def _attribute_not_mapped_warning(self, attribute_type: str):
        self.__warnings[self._identifier].add(
            f'MISP Attribute type {attribute_type} not mapped.'
        )

    def _composite_attribute_value_warning(
            self, attribute_type: str, value: str):
        self.__warnings[self._identifier].add(
            f'The {attribute_type} MISP Attribute '
            f'should have a composite value: {value}.'
        )

    def _country_code_warning(self, country: str):
        self.__warnings[self._identifier].add(
            f'Location `country` warning for "{country}": '
            'this value should be a valid ISO 3166-1 ALPHA-2 Code.'
        )

    def _invalid_attribute_hash_value_error(
            self, attribute: Union[MISPAttribute, dict]):
        self.__errors[self._identifier].append(
            f"Error with the {attribute['type']} value: "
            f"{attribute['value']} is not a valid {attribute['type']} hash."
        )

    def _invalid_object_hash_value_error(
            self, hash_type: str, misp_object: Union[MISPObject, dict]):
        self.__errors[self._identifier].append(
            f"Error with the {misp_object['name']} object "
            f"(uuid: {misp_object['uuid']}): Invalid {hash_type} value."
        )

    def _event_galaxy_not_mapped_warning(self, galaxy_type: str):
        self.__warnings[self._identifier].add(
            f'{galaxy_type} galaxy in event not mapped.'
        )

    def _missing_orgc_error(self):
        self.__errors[self._identifier].append(f'Missing Orgc field.')

    def _missing_orgc_field_error(self, orgc: dict):
        missing = (field for field in ('name', 'uuid') if field not in orgc)
        self.__errors[self._identifier].append(
            f"Error with the Orgc field missing its {' and '.join(missing)}"
            f"{'values' if len(missing) > 1 else 'value'}. Please make sure"
            ' both the name and uuid values are provided.'
        )

    def _object_error(self, misp_object: dict, exception: Exception):
        features = f"{misp_object['name']} object (uuid: {misp_object['uuid']})"
        tb = self._parse_traceback(exception)
        message = f"Error with the {features}:\n{tb}."
        self.__errors[self._identifier].append(message)
        self._parse_custom_object(misp_object)

    def _object_galaxy_not_mapped_warning(self, galaxy_type: str, name: str):
        self.__warnings[self._identifier].add(
            f"{galaxy_type} galaxy in {name} object not mapped."
        )

    def _object_galaxy_incompatible_warning(self, galaxy_type: str, name: str):
        self.__warnings[self._identifier].add(
            f'{galaxy_type} galaxy not compatible with '
            f'the {name} STIX 1 object.'
        )

    def _object_not_mapped_warning(self, object_name: str):
        self.__warnings[self._identifier].add(
            f'MISP Object name {object_name} not mapped.'
        )

    def _parent_galaxy_not_mapping_warning(self, galaxy_type: str):
        self.__warnings[self._identifier].add(
            f'{galaxy_type} galaxy from event level not mapped.'
        )

    @staticmethod
    def _parse_traceback(exception: Exception) -> str:
        tb = ''.join(traceback.format_tb(exception.__traceback__))
        return f'{tb}{exception.__str__()}'

    def _pe_reference_warning(self, file_uuid: str):
        self.__warnings[self._identifier].add(
            'Unable to find the pe object related to '
            f'the file object {file_uuid}.'
        )

    def _referenced_object_name_warning(
            self, object_name: str, referenced_uuid: str):
        self.__warnings[self._identifier].add(
            f'Reference to a non existing {object_name} '
            f'object with uuid: {referenced_uuid}.'
        )

    def _required_fields_missing_warning(
            self, object_type: str, object_name: str):
        self.__warnings[self._identifier].add(
            f'Missing minimum requirement to build a {object_type} '
            f'object from a {object_name} MISP Object.'
        )

    def _unclear_pe_references_warning(self, file_uuid: str, pe_uuids: list):
        self.__warnings[self._identifier].add(
            f'The file object {file_uuid} has more than one reference '
            f"to pe objects: {', '.join(pe_uuids)}"
        )
