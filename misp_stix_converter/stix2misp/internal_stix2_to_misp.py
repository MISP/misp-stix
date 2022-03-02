#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from .exceptions import (AttributeFromPatternParsingError, UndefinedSTIXObjectError,
    UnknownAttributeTypeError, UnknownObjectNameError, UnknownParsingFunctionError)
from .internal_stix2_mapping import InternalSTIX2Mapping
from .stix2_to_misp import STIX2toMISPParser, _MISP_OBJECT_TYPING
from pymisp import MISPAttribute, MISPEvent, MISPObject
from stix2.v20.sdo import (CustomObject as CustomObject_v20, Indicator as Indicator_v20,
    ObservedData as ObservedData_v20, Vulnerability as Vulnerability_v20)
from stix2.v21.sdo import (CustomObject as CustomObject_v21, Indicator as Indicator_v21,
    Location, Note, ObservedData as ObservedData_v21, Vulnerability as Vulnerability_v21)
from typing import Optional, Tuple, Union

_attribute_additional_fields = (
    'category',
    'comment',
    'data',
    'to_ids',
    'uuid'
)
_INDICATOR_TYPING = Union[
    Indicator_v20,
    Indicator_v21
]
_MISP_FEATURES_TYPING = Union[
    MISPAttribute,
    MISPEvent,
    MISPObject
]


class InternalSTIX2toMISPParser(STIX2toMISPParser):
    def __init__(self, single_event: Optional[bool]=False, synonyms_path: Optional[str]=None):
        super().__init__(single_event, synonyms_path)
        self._mapping = InternalSTIX2Mapping()

    ################################################################################
    #                     MAIN STIX OBJECTS PARSING FUNCTIONS.                     #
    ################################################################################

    def _handle_observable_mapping(self, labels: list, object_id: str) -> str:
        try:
            is_object, name = self._parse_labels(labels)
        except TypeError:
            raise UndefinedSTIXObjectError(object_id)
        if is_object:
            try:
                feature = self._mapping.objects_mapping[name]
            except KeyError:
                raise UnknownObjectNameError(name)
            return feature
        try:
            feature = self._mapping.attributes_mapping[name]
        except KeyError:
            raise UnknownAttributeTypeError(name)
        return feature

    def _parse_custom_attribute(self, custom_ref: str):
        custom_attribute = self._get_stix_object(custom_ref)
        attribute = {
            "type": custom_attribute.x_misp_type,
            "value": self._sanitize_value(custom_attribute.x_misp_value),
            "timestamp": self._timestamp_from_date(custom_attribute.modified),
            "uuid": custom_attribute.id.split('--')[1]
        }
        for field in _attribute_additional_fields:
            if hasattr(custom_attribute, f'x_misp_{field}'):
                attribute[field] = getattr(custom_attribute, f'x_misp_{field}')
        self._add_misp_attribute(attribute)

    def _parse_custom_object(self, custom_ref: str):
        custom_object = self._get_stix_object(custom_ref)
        name = custom_object.x_misp_name
        misp_object = MISPObject(name)
        misp_object.category = custom_object.x_misp_meta_category
        misp_object.uuid = custom_object.id.split('--')[1]
        misp_object.timestamp = self._timestamp_from_date(custom_object.modified)
        if hasattr(custom_object, 'x_misp_comment'):
            misp_object.comment = custom_object.x_misp_comment
        for attribute in custom_object.x_misp_attributes:
            misp_object.add_attribute(**attribute)
        self._add_misp_object(misp_object)

    def _parse_indicator(self, indicator_ref: str):
        indicator = self._get_stix_object(indicator_ref)
        feature = self._handle_observable_mapping(indicator.labels, indicator.id)
        try:
            parser = getattr(self, f"{feature}_pattern")
        except AttributeError:
            raise UnknownParsingFunctionError(f"{feature}_pattern")
        try:
            parser(indicator)
        except AttributeFromPatternParsingError as error:
            self._attribute_from_pattern_parsing_error(error)
        except Exception as exception:
            self._indicator_error(indicator.id, exception)

    def _parse_location(self, location_ref: str):
        location = self._get_stix_object(location_ref)
        misp_object = self._parse_location_object(location)
        for label in location.labels:
            if label.startwith('misp:'):
                continue
            misp_object.add_tag(label)
        self._add_misp_object(misp_object)

    def _parse_observed_data_v20(self, observed_data: ObservedData_v20):
        feature = self._handle_observable_mapping(observed_data.labels, observed_data.id)
        try:
            parser = getattr(self, f"{feature}_observable_v20")
        except AttributeError:
            raise UnknownParsingFunctionError(f"{feature}_observable_v20")
        try:
            parser(observed_data)
        except Exception as exception:
            self._observed_data_error(observed_data.id, exception)

    def _parse_observed_data_v21(self, observed_data: ObservedData_v21):
        feature = self._handle_observable_mapping(observed_data.labels, observed_data.id)
        try:
            parser = getattr(self, f"{feature}_observable_v21")
        except AttributeError as error:
            raise UnknownParsingFunctionError(f"{feature}_observable_v21")
        try:
            parser(observed_data)
        except Exception as exception:
            self._observed_data_error(observed_data.id, exception)

    def _parse_vulnerability(self, vulnerability_ref: str):
        vulnerability = self._get_stix_object(vulnerability_ref)
        feature = self._handle_observable_mapping(vulnerability.labels, vulnerability.id)
        try:
            parser = getattr(self, feature)
        except AttributeError:
            raise UnknownParsingFunctionError(feature)
        try:
            parser(vulnerability)
        except Exception as exception:
            self._vulnerability_error(vulnerability.id, exception)

    ################################################################################
    #                 STIX Domain Objects (SDOs) PARSING FUNCTIONS                 #
    ################################################################################

    def _parse_vulnerability_attribute(self, vulnerability: Union[Vulnerability_v20, Vulnerability_v21]):
        attribute = self._create_attribute_dict(vulnerability)
        attribute['value'] = vulnerability.name
        self._add_misp_attribute(attribute)

    def _parse_vulnerability_object(self, vulnerability: Union[Vulnerability_v20, Vulnerability_v21]):
        misp_object = self._create_misp_object('vulnerability', vulnerability)
        for reference in vulnerability.external_references:
            if reference['source_name'] in ('cve', 'vulnerability'):
                external_id = reference['external_id']
                attribute = {'value': external_id}
                attribute.update(self._mapping.vulnerability_attribute)
                misp_object.add_attribute(**attribute)
                if external_id != vulnerability.name:
                    attribute = {'value': vulnerability.name}
                    attribute.update(self._mapping.summary_attribute)
                    misp_object.add_attribute(**attribute)
            elif reference['source_name'] == 'url':
                attribute = {'value': reference['url']}
                attribute.update(self._mapping.references_attribute)
                misp_object.add_attribute(**attribute)
        if hasattr(vulnerability, 'description'):
            attribute = {'value': vulnerability.description}
            attribute.update(self._mapping.description_attribute)
            misp_object.add_attribute(**attribute)
        self._add_misp_object(misp_object)

    ################################################################################
    #                     OBSERVABLE OBJECTS PARSING FUNCTIONS                     #
    ################################################################################

    def _attribute_from_filename_hash_observable_v20(self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        observable = observed_data.objects['0']
        hash_value = list(observable.hashes.values())[0]
        attribute['value'] = f'{observable.name}|{hash_value}'
        self._add_misp_attribute(attribute)

    def _attribute_from_filename_hash_observable_v21(self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._observable[observed_data.object_refs[0]]
        hash_value = list(observable.hashes.values())[0]
        attribute['value'] = f'{observable.name}|{hash_value}'
        self._add_misp_attribute(attribute)

    def _attribute_from_hash_observable_v20(self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        attribute['value'] = list(observed_data.objects['0'].hashes.values())[0]
        self._add_misp_attribute(attribute)

    def _attribute_from_hash_observable_v21(self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._observable[observed_data.object_refs[0]]
        attribute['value'] = list(observable.hashes.values())[0]
        self._add_misp_attribute(attribute)

    ################################################################################
    #                          PATTERNS PARSING FUNCTIONS                          #
    ################################################################################

    def _attribute_from_filename_hash_pattern(self, indicator: _INDICATOR_TYPING):
        attribute = self._create_attribute_dict(indicator)
        for pattern in indicator.pattern[1:-1].split(' AND '):
            if 'file:name = ' in pattern:
                filename = self._extract_attribute_value_from_pattern(pattern)
            elif 'file:hashes.' in pattern:
                hash_value = self._extract_attribute_value_from_pattern(pattern)
        try:
            attribute['value'] = f"{filename}|{hash_value}"
        except NameError:
            raise AttributeFromPatternParsingError(indicator.id)
        self._add_misp_attribute(attribute)

    def _attribute_from_hash_pattern(self, indicator: _INDICATOR_TYPING):
        attribute = self._create_attribute_dict(indicator)
        attribute['value'] = self._extract_attribute_value_from_pattern(indicator.pattern[1:-1])
        self._add_misp_attribute(attribute)

    def _attribute_from_patterning_language(self, indicator: Indicator_v21):
        attribute = self._create_attribute_dict(indicator)
        attribute['value'] = indicator.pattern
        self._add_misp_attribute(attribute)

    ################################################################################
    #                   MISP DATA STRUCTURES CREATION FUNCTIONS.                   #
    ################################################################################

    def _create_attribute_dict(self, stix_object: _MISP_OBJECT_TYPING) -> dict:
        attribute = self._attribute_from_labels(stix_object.labels)
        attribute['uuid'] = stix_object.id.split('--')[-1]
        attribute.update(self._parse_timeline(stix_object))
        if hasattr(stix_object, 'description') and stix_object.description:
            attribute['comment'] = stix_object.description
        if hasattr(stix_object, 'object_marking_refs'):
            self._update_marking_refs(attribute['uuid'])
        return attribute

    ################################################################################
    #                              UTILITY FUNCTIONS.                              #
    ################################################################################

    @staticmethod
    def _attribute_from_labels(labels: list) -> dict:
        attribute = {}
        tags = []
        for label in labels:
            if label.startswith('misp:'):
                feature, value = label.split('=')
                attribute[feature.split(':')[-1]] = value.strip('"')
            else:
                tags.append({'name': label})
        if tags:
            attribute['Tag'] = tags
        return attribute

    @staticmethod
    def _extract_attribute_value_from_pattern(pattern: str) -> str:
        return pattern.split(' = ')[1][1:-1]

    def _fetch_tags_from_labels(self, misp_feature: _MISP_FEATURES_TYPING, labels: list):
        for label in (label for label in labels if label != 'Threat-Report'):
            misp_feature.add_tag(label)

    @staticmethod
    def _parse_labels(labels: list) -> Tuple[bool, str]:
        for label in labels:
            if 'misp:name="' in label or 'misp:type="' in label:
                feature, value = label.split('=')
                return feature == 'misp:name', value.strip('"')
