#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
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
    ##                    MAIN STIX OBJECTS PARSING FUNCTIONS.                    ##
    ################################################################################

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

    ################################################################################
    ##                             UTILITY FUNCTIONS.                             ##
    ################################################################################

    def _create_misp_object(self, stix_object: _MISP_OBJECT_TYPING) -> MISPObject:
        name = stix_object.labels[0].split('=')[-1].strip('"')
        misp_object = MISPObject(name)
        misp_object.uuid = stix_object.id.split('--')[-1]
        misp_object.update(self._parse_timeline(stix_object))
        return misp_object

    @staticmethod
    def _is_object(labels: list) -> bool:
        return any('misp:name="' in label for label in labels[:2])
