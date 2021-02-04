#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from . import stix2_mapping
from .exportparser import MISPtoSTIXParser
from collections import defaultdict
from stix2.v20.bundle import Bundle as Bundle_v20
from stix2.v21.bundle import Bundle as Bundle_v21
from stix2.v20.sro import Relationship
# from stix2.v20.sdo import AttackPattern, CourseOfAction, CustomObject, IntrusionSet, Malware, ObservedData, Report, ThreatActor, Tool, Vulnerability
from typing import Union
from uuid import uuid4

_label_fields = ('type', 'category', 'to_ids')
_misp_time_fields = ('first_seen', 'last_seen')
_stix_time_fields = {
    'indicator': ('valid_from', 'valid_until'),
    'observed-data': ('first_observed', 'last_observed')
}


class MISPtoSTIX2Parser(MISPtoSTIXParser):
    def __init__(self):
        super().__init__()
        self._custom_objects = {}
        self._galaxies = []
        self._ids = {}
        self._markings = {}
        self._orgs = []

    def parse_misp_event(self, misp_event: dict, ids=[], include_bundle=True):
        if 'Event' in misp_event:
            misp_event = misp_event['Event']
        self._misp_event = misp_event
        self._ids = ids
        self._include_bundle = include_bundle
        self._objects = []
        self._object_refs = []
        self._links = []
        self._relationships = defaultdict(list)
        index = self._set_identity()
        if self._misp_event.get('Attribute'):
            self._resolve_attributes()
        if self._misp_event.get('Object'):
            self._resolve_objects()
        report = self._generate_event_report()
        self._objects.insert(index, report)

    @property
    def stix_objects(self) -> Union[Bundle_v20, Bundle_v21, list]:
        if self._include_bundle:
            return self._create_bundle()
        return self._objects

    ################################################################################
    #                            MAIN PARSING FUNCTIONS                            #
    ################################################################################

    def _append_SDO(self, stix_object):
        self._objects.append(stix_object)
        self._object_refs.append(stix_object.id)

    def _generate_event_report(self):
        report_args = {
            'name': self._misp_event['info'],
            'modified': self._datetime_from_timestamp(self._misp_event['timestamp']),
            'labels': [
                'Threat-Report',
                'misp:tool="MISP-STIX-Converter"'
            ],
            'created_by_ref': self._identity_id,
            'interoperability': True
        }
        markings = self._handle_event_tags_and_galaxies()
        if markings:
            report_args['object_marking_refs'] = self._handle_markings(markings)
        if self._markings:
            for marking in self._marking.values():
                self._append_SDO(marking)
        report_args['object_refs'] = self._object_refs
        if self._is_published():
            published = self._datetime_from_timestamp(self._misp_event['publish_timestamp'])
            report_args.update(
                {
                    'id': f"report--{self._misp_event['uuid']}",
                    'type': 'report',
                    'published': published
                }
            )
            return self._create_report(report_args)
        return self._handle_unpublished_report(report_args)

    def _handle_markings(self, markings: tuple) -> list:
        marking_ids = []
        for marking in markings:
            if marking in self._markings:
                marking_ids.append(self._markings[marking]['id'])
                continue
            marking_id = self._create_marking(marking)
            if marking_id is not None:
                marking_ids.append(marking_id)
        return marking_ids

    ################################################################################
    #                         ATTRIBUTES PARSING FUNCTIONS                         #
    ################################################################################

    def _resolve_attributes(self):
        for attribute in self._misp_event['Attribute']:
            attribute_type = attribute['type']
            try:
                if attribute_type in stix2_mapping.attribute_types_mapping:
                    getattr(self, stix2_mapping.attribute_types_mapping[attribute_type])(attribute)
                else:
                    self._parse_custom_attribute(attribute)
                    self._warnings.add(f'MISP Attribute type {attribute_type} not mapped.')
            except Exception:
                self._errors.append(f"Error with the {attribute_type} attribute: {attribute['value']}.")

    def _handle_attribute_indicator(self, attribute: dict, pattern: str):
        indicator_id = f"indicator--{attribute['uuid']}"
        indicator_args = {
            'id': indicator_id,
            'type': 'indicator',
            'labels': self._create_labels(attribute),
            'kill_chain_phases': self._create_killchain(attribute['category']),
            'created_by_ref': self._identity_id,
            'pattern': pattern,
            'interoperability': True
        }
        if attribute.get('comment'):
            indicator_args['description'] = attribute['comment']
        markings = self._handle_attribute_tags_and_galaxies(attribute, indicator_id)
        if marking:
            indicator_args['object_marking_refs'] = self._handle_markings(markings)
        indicator = self._create_indicator(indicator_args)
        self._append_SDO(indicator)

    @staticmethod
    def _parse_AS_value(value: str) -> str:
        if value.startswith('AS'):
            return int(value[2:])
        return int(value)

    def _parse_autonomous_system_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            self._parse_autonomous_system_attribute_pattern(attribute)
        else:
            self._parse_autonomous_system_attribute_observable(attribute)

    def _parse_autonomous_system_attribute_pattern(self, attribute: dict):
        value = self._parse_AS_value(attribute['value'])
        pattern = f"[autonomous-system:number = '{value}']"
        self._handle_attribute_indicator(attribute, pattern)

    ################################################################################
    #                        MISP OBJECTS PARSING FUNCTIONS                        #
    ################################################################################

    def _resolve_objects(self):
        for misp_object in self._misp_event['Object']:
            object_name = misp_object['name']

    ################################################################################
    #                          GALAXIES PARSING FUNCTIONS                          #
    ################################################################################

    ################################################################################
    #                    STIX OBJECTS CREATION HELPER FUNCTIONS                    #
    ################################################################################

    @staticmethod
    def _create_labels(attribute: dict) -> list:
        return [f'misp:{feature}="{attribute[feature]}"' for feature in _label_fields if attribute.get(feature)]

    @staticmethod
    def _create_marking_definition_args(marking: str) -> dict:
        definition_type, definition = marking.split(':')
        marking_definition = {
            'type': 'marking-definition',
            'id': f'marking-definition--{uuid4()}',
            'definition_type': definition_type,
            'definition': {
                definition_type: definition
            }
        }
        return marking_definition

    def _create_observable_args(self, attribute: dict) -> dict:
        observable_id = f"observed-data--{attribute['uuid']}"
        observable_args = {
            'id': observable_id,
            'type': 'observed-data',
            'labels': self._create_labels(attribute),
            'number_observed': 1,
            'created_by_ref': self._identity_id,
            'interoperability': True
        }
        observable_args.update(self._handle_time_fields(attribute, 'observed-data'))
        markings = self._handle_attribute_tags_and_galaxies(attribute, observable_id)
        if markings:
            observable_args['object_marking_refs'] = self._handle_markings(markings)
        return observable_args

    def _set_identity(self) -> int:
        orgc = self._misp_event['Orgc']
        orgc_uuid = orgc['uuid']
        self._identity_id = f'identity--{orgc_uuid}'
        if orgc_uuid not in self._orgs and self._identity_id not in self._ids:
            self._orgs.append(orgc_uuid)
            identity = self._create_identity_object(orgc['name'])
            self._objects.append(identity)
            return 1
        return 0

    ################################################################################
    #                              UTILITY FUNCTIONS.                              #
    ################################################################################

    @staticmethod
    def _datetime_from_str(timestamp):
        return datetime.strptime(timestamp.split('+')[0], '%Y-%m-%dT%H:%M:%S.%f')

    def _handle_time_fields(self, attribute: dict, stix_type: str) -> dict:
        timestamp = self._datetime_from_timestamp(attribute['timestamp'])
        to_return = {
            'created': timestamp,
            'modified': timestamp
        }
        stix_fields = _stix_time_fields[stix_type]
        for misp_field, stix_field in zip(_misp_time_fields, stix_fields):
            to_return[stix_field] = self._datetime_from_str(attribute[misp_field]) if attribute.get(misp_field) else timestamp
        return to_return

    @staticmethod
    def _handle_value_for_pattern(attribute_value: str) -> str:
        return attribute_value.replace("'", '##APOSTROPHE##').replace('"', '##QUOTE##')
