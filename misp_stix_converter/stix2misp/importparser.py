# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import traceback
from collections import defaultdict
from pymisp import MISPObject
from stix2.v20.sdo import Indicator as Indicator_v20
from stix2.v21.sdo import Indicator as Indicator_v21
from typing import Optional, Union
from uuid import UUID, uuid5

_INDICATOR_TYPING = Union[
    Indicator_v20,
    Indicator_v21
]

_RFC_VERSIONS = (1, 3, 4, 5)
_UUIDv4 = UUID('76beed5f-7251-457e-8c2a-b45f7b589d3d')


class STIXtoMISPParser:
    def __init__(self):
        self._identifier: str
        self._galaxies: dict = {}
        self._clusters: dict = {}
        self.__replacement_uuids: dict = {}
        self.__errors: defaultdict = defaultdict(set)
        self.__warnings: defaultdict = defaultdict(set)

    @property
    def errors(self) -> dict:
        return self.__errors

    @property
    def replacement_uuids(self) -> dict:
        return self.__replacement_uuids

    @property
    def warnings(self) -> defaultdict:
        return self.__warnings

    ################################################################################
    #                    ERRORS AND WARNINGS HANDLING FUNCTIONS                    #
    ################################################################################

    def _attack_pattern_error(self, attack_pattern_id: str, exception: Exception):
        tb = self._parse_traceback(exception)
        message = f"Error with the Attack Pattern object with id {attack_pattern_id}: {tb}"
        self.__errors[self._identifier].add(message)

    def _attribute_from_pattern_parsing_error(self, indicator_id: str):
        message = f"Error while parsing pattern from indicator with id {indicator_id}"
        self.__errors[self._identifier].add(message)

    def _course_of_action_error(self, course_of_action_id: str, exception: Exception):
        tb = self._parse_traceback(exception)
        message = f"Error with the Course of Action object with id {course_of_action_id}: {tb}"
        self.__errors[self._identifier].add(message)

    def _critical_error(self, exception: Exception):
        message = f'The Following exception was raised: {exception}'
        self.__errors[self._identifier].add(message)

    def _identity_error(self, identity_id: str, exception: Exception):
        tb = self._parse_traceback(exception)
        message = f"Error with the Identity object with id {identity_id}: {tb}"
        self.__errors[self._identifier].add(message)

    def _indicator_error(self, indicator_id: str, exception: Exception):
        tb = self._parse_traceback(exception)
        message = f"Error with the Indicator object with id {indicator_id}: {tb}"
        self.__errors[self._identifier].add(message)

    def _intrusion_set_error(self, intrusion_set_id: str, exception: Exception):
        tb = self._parse_traceback(exception)
        message = f"Error with the Intrusion Set object with id {intrusion_set_id}: {tb}"
        self.__errors[self._identifier].add(message)

    def _location_error(self, location_id: str, exception: Exception):
        tb = self._parse_traceback(exception)
        message = f"Error with the Location object with id {location_id}: {tb}"
        self.__errors[self._identifier].add(message)

    def _malware_error(self, malware_id: str, exception: Exception):
        tb = self._parse_traceback(exception)
        message = f"Error with the Malware object with id {malware_id}: {tb}"
        self.__errors[self._identifier].add(message)

    def _no_converted_content_from_pattern_warning(self, indicator: _INDICATOR_TYPING):
        message = f"Indicator's (id: {indicator.id}) pattern: {indicator.pattern}"
        self.__warnings[self._identifier].add(
            f"No content to extract from the following {message}"
        )

    def _object_ref_loading_error(self, object_ref: str):
        message = f"Error loading the STIX object with id {object_ref}"
        self.__errors[self._identifier].add(message)

    def _object_type_loading_error(self, object_type: str):
        message = f"Error loading the STIX object of type {object_type}"
        self.__errors[self._identifier].add(message)

    def _observed_data_error(self, observed_data_id: str, exception: Exception):
        tb = self._parse_traceback(exception)
        message = f"Error with the Observed Data object with id {observed_data_id}: {tb}"
        self.__errors[self._identifier].add(message)

    @staticmethod
    def _parse_traceback(exception: Exception) -> str:
        tb = ''.join(traceback.format_tb(exception.__traceback__))
        return f'{tb}{exception.__str__()}'

    def _threat_actor_error(self, threat_actor_id: str, exception: Exception):
        tb = self._parse_traceback(exception)
        message = f"Error with the Threat Actor object with id {threat_actor_id}: {tb}"
        self.__errors[self._identifier].add(message)

    def _tool_error(self, tool_id: str, exception: Exception):
        tb = self._parse_traceback(exception)
        message = f"Error with the Tool object with id {tool_id}: {tb}"
        self.__errors[self._identifier].add(message)

    def _unable_to_load_stix_object_type_error(self, object_type: str):
        message = f"Unable to load STIX object type: {object_type}"
        self.__errors[self._identifier].add(message)

    def _undefined_object_error(self, object_id: str):
        message = f"Unable to define the object identified with the id: {object_id}"
        self.__errors[self._identifier].add(message)

    def _unknown_attribute_type_warning(self, attribute_type: str):
        message = f"MISP attribute type not mapped: {attribute_type}"
        self.__warnings[self._identifier].add(message)

    def _unknown_marking_ref_warning(self, marking_ref: str):
        message = f"Unknown marking ref: {marking_ref}"
        self.__warnings[self._identifier].add(message)

    def _unknown_object_name_warning(self, name: str):
        message = f"MISP object name not mapped: {name}"
        self.__warnings[self._identifier].add(message)

    def _unknown_parsing_function_error(self, feature: str):
        message = f"Unknown STIX parsing function name: {feature}"
        self.__errors[self._identifier].add(message)

    def _unknown_pattern_mapping_warning(self, indicator_id: str, observable_types: Union[list, str]):
        if not isinstance(observable_types, list):
            observable_types = observable_types.split('_')
        types = f"containing the following types: {', '.join(observable_types)}"
        message = f"Unable to map pattern from the indicator with id {indicator_id}, {types}"
        self.__warnings[self._identifier].add(message)

    def _unknown_pattern_type_error(self, indicator_id: str, pattern_type: str):
        message = f"Unknown pattern type in indicator with id {indicator_id}: {pattern_type}"
        self.__errors[self._identifier].add(message)

    def _unknown_stix_object_type_error(self, object_type: str):
        message = f"Unknown STIX object type: {object_type}"
        self.__errors[self._identifier].add(message)

    def _unmapped_pattern_warning(self, indicator_id: str, feature: str):
        message = f"Unmapped pattern part in indicator with id {indicator_id}: {feature}"
        self.__warnings[self._identifier].add(message)

    def _vulnerability_error(self, vulnerability_id: str, exception: Exception):
        tb = self._parse_traceback(exception)
        message = f"Error with the Vulnerability object with id {vulnerability_id}: {tb}"
        self.__errors[self._identifier].add(message)

    ################################################################################
    #                      UUID SANITATION HANDLING FUNCTIONS                      #
    ################################################################################

    def _check_uuid(self, object_id: str):
        object_uuid = self._extract_uuid(object_id)
        if UUID(object_uuid).version not in _RFC_VERSIONS and object_uuid not in self.replacement_uuids:
            self.replacement_uuids[object_uuid] = uuid5(_UUIDv4, object_uuid)

    def _sanitise_attribute_uuid(self, object_id: str, comment: Optional[str] = None) -> dict:
        attribute_uuid = self._extract_uuid(object_id)
        if attribute_uuid in self.replacement_uuids:
            attribute_comment = f'Original UUID was: {attribute_uuid}'
            return {
                'uuid': self.replacement_uuids[attribute_uuid],
                'comment': f'{comment} - {attribute_comment}' if comment else attribute_comment
            }
        if UUID(attribute_uuid).version not in _RFC_VERSIONS:
            attribute_comment = f'Original UUID was: {attribute_uuid}'
            sanitised_uuid = uuid5(_UUIDv4, attribute_uuid)
            self.replacement_uuids[attribute_uuid] = sanitised_uuid
            return {
                'uuid': sanitised_uuid,
                'comment': f'{comment} - {attribute_comment}' if comment else attribute_comment
            }
        return {'uuid': attribute_uuid}

    def _sanitise_object_uuid(self, misp_object: MISPObject, object_uuid: str):
        comment = f'Original UUID was: {object_uuid}'
        misp_object.comment = f'{misp_object.comment} - {comment}' if hasattr(misp_object, 'comment') else comment
        misp_object.uuid = self.replacement_uuids[object_uuid]

    def _sanitise_uuid(self, object_id: str) -> str:
        object_uuid = self._extract_uuid(object_id)
        if UUID(object_uuid).version not in _RFC_VERSIONS:
            if object_uuid in self.replacement_uuids:
                return self.replacement_uuids[object_uuid]
            sanitised_uuid = uuid5(_UUIDv4, object_uuid)
            self.replacement_uuids[object_uuid] = sanitised_uuid
            return sanitised_uuid
        return object_uuid