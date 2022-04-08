#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from .exceptions import (AttributeFromPatternParsingError, UndefinedSTIXObjectError,
    UnknownAttributeTypeError, UnknownObjectNameError, UnknownParsingFunctionError)
from .internal_stix2_mapping import InternalSTIX2Mapping
from .stix2_to_misp import STIX2toMISPParser, _MISP_OBJECT_TYPING
from pymisp import MISPAttribute, MISPEvent, MISPObject
from stix2.v20.sdo import (AttackPattern as AttackPattern_v20,
    CourseOfAction as CourseOfAction_v20, CustomObject as CustomObject_v20,
    Identity as Identity_v20, Indicator as Indicator_v20, Malware as Malware_v20,
    ObservedData as ObservedData_v20, Tool as Tool_v20,
    Vulnerability as Vulnerability_v20)
from stix2.v21.sdo import (AttackPattern as AttackPattern_v21,
    CourseOfAction as CourseOfAction_v21, CustomObject as CustomObject_v21,
    Identity as Identity_v21, Indicator as Indicator_v21, Malware as Malware_v21,
    Note, ObservedData as ObservedData_v21, Tool as Tool_v21,
    Vulnerability as Vulnerability_v21)
from typing import Optional, Union

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
    #                        STIX OBJECTS LOADING FUNCTIONS                        #
    ################################################################################

    def _load_custom_attribute(self, custom_attribute: Union[CustomObject_v20, CustomObject_v21]):
        try:
            self._custom_attribute[custom_attribute.id] = custom_attribute
        except AttributeError:
            self._custom_attribute = {custom_attribute.id: custom_attribute}

    def _load_custom_object(self, custom_object: Union[CustomObject_v20, CustomObject_v21]):
        try:
            self._custom_object[custom_object.id] = custom_object
        except AttributeError:
            self._custom_object = {custom_object.id: custom_object}

    def _load_indicator(self, indicator: Union[Indicator_v20, Indicator_v21]):
        try:
            self._indicator[indicator.id] = indicator
        except AttributeError:
            self._indicator = {indicator.id: indicator}

    def _load_note(self, note: Note):
        try:
            self._note[note.id] = note
        except AttributeError:
            self._note = {note.id: note}

    def _load_observed_data(self, observed_data: Union[ObservedData_v20, ObservedData_v21]):
        try:
            self._observed_data[observed_data.id] = observed_data
        except AttributeError:
            self._observed_data = {observed_data.id: observed_data}

    ################################################################################
    #                     MAIN STIX OBJECTS PARSING FUNCTIONS.                     #
    ################################################################################

    def _handle_object_mapping(self, labels: list, object_id: str) -> str:
        parsed_labels = {key: value.strip('"') for key, value in (label.split('=') for label in labels)}
        if any(label.startswith('misp-galaxy:') for label in parsed_labels):
            for label in parsed_labels:
                if label.startswith('misp-galaxy:'):
                    return self._mapping.galaxies_mapping[label.split(':')[1]]
        elif 'misp:name' in parsed_labels:
            return self._mapping.objects_mapping[parsed_labels['misp:name']]
        elif 'misp:type' in parsed_labels:
            return self._mapping.attributes_mapping[parsed_labels['misp:type']]
        raise UndefinedSTIXObjectError(object_id)

    def _parse_attack_pattern(self, attack_pattern_ref: str):
        attack_pattern = self._get_stix_object(attack_pattern_ref)
        feature = self._handle_object_mapping(attack_pattern.labels, attack_pattern.id)
        try:
            parser = getattr(self, feature)
        except AttributeError:
            raise UnknownParsingFunctionError(feature)
        try:
            parser(attack_pattern)
        except Exception as exception:
            self._attack_pattern_error(attack_pattern.id, exception)

    def _parse_campaign(self, campaign_ref: str):
        campaign = self._get_stix_object(campaign_ref)
        attribute = self._create_attribute_dict(campaign)
        attribute['value'] = campaign.name
        self._add_misp_attribute(attribute)

    def _parse_course_of_action(self, course_of_action_ref: str):
        course_of_action = self._get_stix_object(course_of_action_ref)
        feature = self._handle_object_mapping(course_of_action.labels, course_of_action.id)
        try:
            parser = getattr(self, feature)
        except AttributeError:
            raise UnknownParsingFunctionError(feature)
        try:
            parser(course_of_action)
        except Exception as exception:
            self._course_of_action_error(course_of_action.id, exception)

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

    def _parse_identity(self, identity_ref: str):
        identity = self._get_stix_object(identity_ref)
        feature = self._handle_object_mapping(identity.labels, identity.id)
        try:
            parser = getattr(self, feature)
        except AttributeError:
            raise UnknownParsingFunctionError(feature)
        try:
            parser(identity)
        except Exception as exception:
            self._identity_error(identity.id, exception)

    def _parse_indicator(self, indicator_ref: str):
        indicator = self._get_stix_object(indicator_ref)
        feature = self._handle_object_mapping(indicator.labels, indicator.id)
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
            if label.startswith('misp:'):
                continue
            misp_object.add_tag(label)
        self._add_misp_object(misp_object)

    def _parse_malware(self, malware_ref: str):
        malware = self._get_stix_object(malware_ref)
        feature = self._handle_object_mapping(malware.labels, malware.id)
        try:
            parser = getattr(self, feature)
        except AttributeError:
            raise UnknownParsingFunctionError(feature)
        try:
            parser(malware)
        except Exception as exception:
            self._malware_error(malware.id, exception)

    def _parse_observed_data_v20(self, observed_data: ObservedData_v20):
        feature = self._handle_object_mapping(observed_data.labels, observed_data.id)
        try:
            parser = getattr(self, f"{feature}_observable_v20")
        except AttributeError:
            raise UnknownParsingFunctionError(f"{feature}_observable_v20")
        try:
            parser(observed_data)
        except Exception as exception:
            self._observed_data_error(observed_data.id, exception)

    def _parse_observed_data_v21(self, observed_data: ObservedData_v21):
        feature = self._handle_object_mapping(observed_data.labels, observed_data.id)
        try:
            parser = getattr(self, f"{feature}_observable_v21")
        except AttributeError as error:
            raise UnknownParsingFunctionError(f"{feature}_observable_v21")
        try:
            parser(observed_data)
        except Exception as exception:
            self._observed_data_error(observed_data.id, exception)

    def _parse_tool(self, tool_ref: str):
        tool = self._get_stix_object(tool_ref)
        feature = self._handle_object_mapping(tool.labels, tool.id)
        try:
            parser = getattr(self, feature)
        except AttributeError:
            raise UnknownParsingFunctionError(feature)
        try:
            parser(tool)
        except Exception as exception:
            self._tool_error(tool.id, exception)

    def _parse_vulnerability(self, vulnerability_ref: str):
        vulnerability = self._get_stix_object(vulnerability_ref)
        feature = self._handle_object_mapping(vulnerability.labels, vulnerability.id)
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

    def _parse_attack_pattern_object(self, attack_pattern: Union[AttackPattern_v20, AttackPattern_v21]):
        misp_object = self._create_misp_object('attack-pattern', attack_pattern)
        for key, mapping in self._mapping.attack_pattern_object_mapping.items():
            if hasattr(attack_pattern, key):
                self._populate_object_attributes(
                    misp_object,
                    mapping,
                    getattr(attack_pattern, key)
                )
        if hasattr(attack_pattern, 'external_references'):
            for reference in attack_pattern.external_references:
                misp_object.add_attribute(**self._parse_attack_pattern_reference(reference))
        self._add_misp_object(misp_object)

    def _parse_attack_pattern_reference(self, reference: dict) -> dict:
        if reference['source_name'] == 'capec':
            return {
                'type': 'text',
                'object_relation': 'id',
                'value': reference['external_id'].split('-')[1]
            }
        return {
            'type': 'link',
            'object_relation': 'references',
            'value': reference['url']
        }

    def _parse_course_of_action_object(self, course_of_action: Union[CourseOfAction_v20, CourseOfAction_v21]):
        misp_object = self._create_misp_object('course-of-action', course_of_action)
        for key, mapping in self._mapping.course_of_action_object_mapping.items():
            if hasattr(course_of_action, key):
                self._populate_object_attributes(
                    misp_object,
                    mapping,
                    getattr(course_of_action, key)
                )
        self._add_misp_object(misp_object)

    def _parse_employee_object(self, identity: Union[Identity_v20, Identity_v21]):
        misp_object = self._create_misp_object('employee', identity)
        for key, mapping in self._mapping.employee_object_mapping.items():
            if hasattr(identity, key):
                self._populate_object_attributes(
                    misp_object,
                    mapping,
                    getattr(identity, key)
                )
        if hasattr(identity, 'contact_information'):
            object_relation, value = identity.contact_information.split(': ')
            attribute = {
                'type': 'target-email',
                'object_relation': object_relation,
                'value': value
            }
            misp_object.add_attribute(**attribute)
        self._add_misp_object(misp_object)

    def _parse_identity_object(self, identity: Union[Identity_v20, Identity_v21], name: str) -> MISPObject:
        misp_object = self._create_misp_object(name, identity)
        feature = name.replace('-', '_')
        for key, mapping in getattr(self._mapping, f'{feature}_object_mapping').items():
            if hasattr(identity, key):
                self._populate_object_attributes(
                    misp_object,
                    mapping,
                    getattr(identity, key)
                )
        if hasattr(identity, 'contact_information'):
            mapping = getattr(self._mapping, f'{feature}_contact_information_mapping')
            for contact_info in identity.contact_information.split(' / '):
                object_relation, value = contact_info.split(': ')
                attribute = {
                    'object_relation': object_relation,
                    'value': value
                }
                attribute.update(mapping[object_relation])
                misp_object.add_attribute(**attribute)
        return misp_object

    def _parse_legal_entity_object(self, identity: Union[Identity_v20, Identity_v21]):
        misp_object = self._parse_identity_object(identity, 'legal-entity')
        if hasattr(identity, 'x_misp_logo'):
            attribute = {'type': 'attachment', 'object_relation': 'logo'}
            if isinstance(identity.x_misp_logo, dict):
                attribute.update(identity.x_misp_logo)
            else:
                attribute['value'] = identity.x_misp_logo
            misp_object.add_attribute(**attribute)
        self._add_misp_object(misp_object)

    def _parse_news_agency_object(self, identity: Union[Identity_v20, Identity_v21]):
        misp_object = self._parse_identity_object(identity, 'news-agency')
        if hasattr(identity, 'x_misp_attachment'):
            attribute = {'type': 'attachment', 'object_relation': 'attachment'}
            if isinstance(identity.x_misp_attachment, dict):
                attribute.update(identity.x_misp_attachment)
            else:
                attribute['value'] = identity.x_misp_attachment
            misp_object.add_attribute(**attribute)
        self._add_misp_object(misp_object)

    def _parse_organization_object(self, identity: Union[Identity_v20, Identity_v21]):
        misp_object = self._parse_identity_object(identity, 'organization')
        self._add_misp_object(misp_object)

    def _parse_script_object(self, stix_object: Union[Malware_v20, Malware_v21, Tool_v20, Tool_v21]):
        misp_object = self._create_misp_object('script', stix_object)
        feature = f'script_from_{stix_object.type}_object_mapping'
        for key, mapping in getattr(self._mapping, feature).items():
            if hasattr(stix_object, key):
                self._populate_object_attributes(
                    misp_object,
                    mapping,
                    getattr(stix_object, key)
                )
        if hasattr(stix_object, 'x_misp_script_as_attachment'):
            attribute = {'type': 'attachment', 'object_relation': 'script-as-attachment'}
            if isinstance(stix_object.x_misp_script_as_attachment, dict):
                attribute.update(stix_object.x_misp_script_as_attachment)
            else:
                attribute['value'] = stix_object.x_misp_script_as_attachment
            misp_object.add_attribute(**attribute)
        self._add_misp_object(misp_object)

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
        for key, mapping in self._mapping.vulnerability_object_mapping.items():
            if hasattr(vulnerability, key):
                self._populate_object_attributes(
                    misp_object,
                    mapping,
                    getattr(vulnerability, key)
                )
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

    def _attribute_from_patterning_language_pattern(self, indicator: Indicator_v21):
        attribute = self._create_attribute_dict(indicator)
        attribute['value'] = indicator.pattern
        self._add_misp_attribute(attribute)

    def _object_from_patterning_language_pattern(self, indicator: Indicator_v21):
        name = 'suricata' if indicator.pattern_type == 'snort' else indicator.pattern_type
        misp_object = self._create_misp_object(name, indicator)
        for key, mapping in getattr(self._mapping, f'{name}_object_mapping').items():
            if hasattr(indicator, key):
                self._populate_object_attributes(
                    misp_object,
                    mapping,
                    getattr(indicator, key)
                )
        if hasattr(indicator, 'external_references') and name == 'suricata':
            for reference in indicator.external_references:
                attribute = {
                    'type': 'link',
                    'object_relation': 'ref',
                    'value': reference.url
                }
                if hasattr(reference, 'description'):
                    attribute['comment'] = reference.description
                misp_object.add_attribute(**attribute)
        self._add_misp_object(misp_object)

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
    def _populate_object_attributes(misp_object: MISPObject, mapping: dict, values: Union[list, str]):
        if isinstance(values, list):
            for value in values:
                attribute = {'value': value}
                attribute.update(mapping)
                misp_object.add_attribute(**attribute)
        else:
            attribute = {'value': values}
            attribute.update(mapping)
            misp_object.add_attribute(**attribute)