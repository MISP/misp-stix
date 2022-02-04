#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from .exceptions import (UndefinedSTIXObjectError, UnknownAttributeTypeError,
    UnknownObjectNameError)
from .internal_stix2_mapping import InternalSTIX2Mapping
from .stix2_to_misp import STIX2toMISPParser
from pymisp import MISPAttribute, MISPObject
from stix2.v20.sdo import (CustomObject as CustomObject_v20, Indicator as Indicator_v20,
    ObservedData as ObservedData_v20)
from stix2.v21.sdo import (CustomObject as CustomObject_v21, Indicator as Indicator_v21,
    Location, Note, ObservedData as ObservedData_v21)
from typing import Tuple, Union

_attribute_additional_fields = (
    'category',
    'comment',
    'data',
    'to_ids',
    'uuid'
)
_MISP_OBJECT_TYPING = Union[
    Indicator_v20,
    Indicator_v21,
    ObservedData_v20,
    ObservedData_v21
]


class InternalSTIX2toMISPParser(STIX2toMISPParser):
    def __init__(self):
        super().__init__()
        self._mapping = InternalSTIX2Mapping()

    ################################################################################
    #                     MAIN STIX OBJECTS PARSING FUNCTIONS.                     #
    ################################################################################

    def _handle_observed_data(self, labels: list, observed_data_id: str) -> str:
        try:
            is_object, name = self._parse_labels(labels)
        except TypeError:
            raise UndefinedSTIXObjectError(observed_data_id)
        if is_object:
            try:
                feature = self._mapping.observable_objects_mapping[name]
            except KeyError:
                raise UnknownObjectNameError(name)
            return feature, name
        try:
            feature = self._mapping.observable_attributes_mapping[name]
        except KeyError:
            raise UnknownAttributeTypeError(name)
        return feature

    def _parse_custom_attribute(self, custom_attribute: Union[CustomObject_v20, CustomObject_v21]):
        attribute = {
            "type": custom_attribute.x_misp_type,
            "value": self._sanitize_value(custom_attribute.x_misp_value),
            "timestamp": self._get_timestamp_from_date(custom_attribute.modified),
            "uuid": custom_attribute.id.split('--')[1]
        }
        for field in _attribute_additional_fields:
            if hasattr(custom_attribute, f'x_misp_{field}'):
                attribute[field] = getattr(custom_attribute, f'x_misp_{field}')
        self._add_attribute(attribute)

    def _parse_custom_object(self, custom_object: Union[CustomObject_v20, CustomObject_v21]):
        name = custom_object.x_misp_name
        misp_object = MISPObject(name)
        misp_object.category = custom_object.x_misp_meta_category
        misp_object.uuid = custom_object.id.split('--')[1]
        misp_object.timestamp = self._get_timestamp_from_date(custom_object.modified)
        if hasattr(custom_object, 'x_misp_comment'):
            misp_object.comment = custom_object.x_misp_comment
        for attribute in custom_object.x_misp_attributes:
            misp_object.add_attribute(**attribute)
        self._add_object(misp_object)

    def _parse_observed_data_v20(self, observed_data: ObservedData_v20):
        feature = self._handle_observed_data(observed_data.labels, observed_data.id)
        try:
            getattr(self, f"{feature}_v20")(observed_data)
        except Exception as exception:
            self._observed_data_error(observed_data.id, exception)

    def _parse_observed_data_v21(self, observed_data: ObservedData_v21):
        feature = self._handle_observed_data(observed_data.labels, observed_data.id)
        try:
            getattr(self, f"{feature}_v21")(observed_data)
        except Exception as exception:
            self._observed_data_error(observed_data.id, exception)

    ################################################################################
    #                     OBSERVABLE OBJECTS PARSING FUNCTIONS                     #
    ################################################################################

    def _parse_filename_hash_observable_attribute_v20(self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        observable = observed_data.objects['0']
        hash_value = list(observable.hashes.values())[0]
        attribute['value'] = f'{observable.name}|{hash_value}'
        self._add_attribute(attribute)

    def _parse_filename_hash_observable_attribute_v21(self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._observable[observed_data.object_refs[0]]
        hash_value = list(observable.hashes.values())[0]
        attribute['value'] = f'{observable.name}|{hash_value}'
        self._add_attribute(attribute)

    def _parse_hash_observable_attribute_v20(self, observed_data: ObservedData_v20):
        attribute = self._attribute_from_labels(observed_data.labels)
        attribute['value'] = list(observed_data.objects['0'].hashes.values())[0]
        self._add_attribute(attribute)

    def _parse_hash_observable_attribute_v21(self, observed_data: ObservedData_v21):
        attribute = self._attribute_from_labels(observed_data.labels)
        observable = self._observable[observed_data.object_refs[0]]
        attribute['value'] = list(observable.hashes.values())[0]
        self._add_attribute(attribute)

    ################################################################################
    #                              UTILITY FUNCTIONS.                              #
    ################################################################################

    @staticmethod
    def _attribute_from_labels(labels: list) -> dict:
        attribute = {}
        tags = []
        for label in labels:
            if labels.startswith('misp:'):
                feature, value = label.split('=')
                attribute[feature.split(':')[-1]] = value.strip('"')
            else:
                tags.append({'name': label})
        if tags:
            attribute['Tag'] = tags
        return attribute

    def _create_attribute_dict(self, stix_object: _MISP_OBJECT_TYPING) -> dict:
        attribute = self._attribute_from_labels(sitx_object.labels)
        attribute['uuid'] = stix_object.id.split('--')[-1]
        attribute.update(self._parse_timeline(stix_object))
        if hasattr(stix_object, 'object_marking_refs'):
            self._update_marking_refs(attribute['uuid'])
        return attribute

    def _create_misp_object(self, name: str, stix_object: _MISP_OBJECT_TYPING) -> MISPObject:
        misp_object = MISPObject(name)
        misp_object.uuid = stix_object.id.split('--')[-1]
        misp_object.update(self._parse_timeline(stix_object))
        return misp_object

    @staticmethod
    def _parse_labels(labels: list) -> Tuple[bool, str]:
        for label in labels:
            if 'misp:name="' in label or 'misp:type="' in label:
                feature, value = label.split('=')
                return feature == 'misp:name', value.strip('"')
