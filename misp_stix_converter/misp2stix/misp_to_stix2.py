#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from . import stix2_mapping
from .exportparser import MISPtoSTIXParser
from collections import defaultdict
from datetime import datetime
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
    def bundle(self) -> Union[Bundle_v20, Bundle_v21]:
        return self._create_bundle()

    @property
    def stix_objects(self) -> list:
        return self._objects

    @staticmethod
    def _update_mapping_v21():
        stix2_mapping.attribute_types_mapping.update(
            {
                'email-message-id': '_parse_email_message_id_attribute'
            }
        )

    ################################################################################
    #                            MAIN PARSING FUNCTIONS                            #
    ################################################################################

    def _append_SDO(self, stix_object):
        self._objects.append(stix_object)
        self._object_refs.append(stix_object.id)

    def _generate_event_report(self):
        timestamp = self._datetime_from_timestamp(self._misp_event['timestamp'])
        report_args = {
            'name': self._misp_event['info'],
            'created': timestamp,
            'modified': timestamp,
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
        indicator_args.update(self._handle_indicator_time_fields(attribute))
        if attribute.get('comment'):
            indicator_args['description'] = attribute['comment']
        markings = self._handle_attribute_tags_and_galaxies(attribute, indicator_id)
        if markings:
            indicator_args['object_marking_refs'] = self._handle_markings(markings)
        indicator = self._create_indicator(indicator_args)
        self._append_SDO(indicator)

    @staticmethod
    def _parse_AS_value(value: str) -> str:
        if value.startswith('AS'):
            return int(value[2:])
        return int(value)

    def _parse_attachment_attribute(self, attribute: dict):
        if attribute.get('data'):
            if attribute.get('to_ids', False):
                file_pattern = self._create_filename_pattern(attribute['value'])
                data_pattern = self._create_content_ref_pattern(attribute['data'])
                pattern = f"[{file_pattern} AND {data_pattern}]"
                self._handle_attribute_indicator(attribute, pattern)
            else:
                self._parse_attachment_attribute_observable(attribute)
        else:
            self._parse_filename_attribute(attribute)

    def _parse_autonomous_system_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            value = self._parse_AS_value(attribute['value'])
            pattern = f"[autonomous-system:number = '{value}']"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            self._parse_autonomous_system_attribute_observable(attribute)

    def _parse_custom_attribute(self, attribute: dict):
        prefix = f"x-misp-object-{attribute['type'].replace('|', '-').replace(' ', '-').lower()}"
        custom_id = f"{prefix}--{attribute['uuid']}"
        timestamp = self._datetime_from_timestamp(attribute['timestamp'])
        custom_args = {
            'id': custom_id,
            'x_misp_category': attribute['category'],
            'created': timestamp,
            'modified': timestamp,
            'labels': self._create_labels(attribute),
            'x_misp_value': attribute['value'],
            'created_by_ref': self._identity_id
        }
        if attribute.get('comment'):
            custom_args['x_misp_comment'] = attribute['comment']
        markings = self._handle_attribute_tags_and_galaxies(attribute, custom_id)
        if markings:
            custom_args['object_marking_refs'] = self._handle_markings(markings)
        custom_object = self._create_custom_object(prefix, custom_args)
        self._append_SDO(custom_object)

    def _parse_domain_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            pattern = f"[{self._create_domain_pattern(attribute['value'])}]"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            self._parse_domain_attribute_observable(attribute)

    def _parse_domain_ip_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            domain, ip = attribute['value'].split('|')
            domain_pattern = self._create_domain_pattern(domain)
            resolving_ref = self._create_domain_resolving_pattern(ip)
            pattern = f"[{domain_pattern} AND {resolving_ref}]"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            self._parse_domain_ip_attribute_observable(attribute)

    def _parse_email_attachment_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            pattern = f"[email-message:body_multipart[*].body_raw_ref.name = '{attribute['value']}']"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            self._parse_email_attachment_attribute_observable(attribute)

    def _parse_email_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            pattern = f"[email-addr:value = '{attribute['value']}']"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            self._parse_email_attribute_observable(attribute)

    def _parse_email_body_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            pattern = f"[email-message:body = '{attribute['value']}']"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            self._parse_email_body_attribute_observable(attribute)

    def _parse_email_destination_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            pattern = f"[email-message:to_refs[*].value = '{attribute['value']}']"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            self._parse_email_destination_attribute_observable(attribute)

    def _parse_email_header_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            pattern = f"[email-message:received_lines = '{attribute['value']}']"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            self._parse_email_header_attribute_observable(attribute)

    def _parse_email_reply_to_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            pattern = f"[email-message:additional_header_fields.reply_to = '{attribute['value']}']"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            self._parse_email_reply_to_attribute_observable(attribute)

    def _parse_email_source_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            pattern = f"[email-message:from_ref.value = '{attribute['value']}']"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            self._parse_email_source_attribute_observable(attribute)

    def _parse_email_subject_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            pattern = f"[email-message:subject = '{attribute['value']}']"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            self._parse_email_subject_attribute_observable(attribute)

    def _parse_email_x_mailer_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            pattern = f"[email-message:additional_header_fields.x_mailer = '{attribute['value']}']"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            self._parse_email_x_mailer_attribute_observable(attribute)

    def _parse_filename_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            pattern = f"[{self._create_filename_pattern(attribute['value'])}]"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            self._parse_filename_attribute_observable(attribute)

    def _parse_hash_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            pattern = f"[{self._create_hash_pattern(attribute['type'], attribute['value'])}]"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            self._parse_hash_attribute_observable(attribute)

    def _parse_hash_composite_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            hash_type = attribute['type'].split('|')[1]
            filename, hash_value = attribute['value'].split('|')
            filename_pattern = self._create_filename_pattern(filename)
            hash_pattern = self._create_hash_pattern(hash_type, hash_value)
            pattern = f"[{filename_pattern} AND {hash_pattern}]"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            self._parse_hash_composite_attribute_observable(attribute)

    def _parse_hostname_port_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            hostname, port = attribute['value'].split('|')
            hostname_pattern = self._create_domain_pattern(hostname)
            port_pattern = self._create_port_pattern(port)
            pattern = f"[{hostname_pattern} AND {port_pattern}]"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            self._parse_hostname_port_attribute_observable(attribute)

    def _parse_mac_address_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            pattern = f"[mac-addr:value = '{attribute['value']}']"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            self._parse_mac_address_attribute_observable(attribute)

    def _parse_mutex_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            pattern = f"[mutex:name = '{attribute['value']}']"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            self._parse_mutex_attribute_observable(attribute)

    def _parse_regkey_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            key = attribute['value']
            if '\\\\' not in key:
                key = key.replace('\\', '\\\\')
            pattern = f"[{self._create_regkey_pattern(key)}]"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            self._parse_regkey_attribute_observable(attribute)

    def _parse_regkey_value_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            key, value = attribute['value'].split('|')
            if '\\\\' not in key:
                key = key.replace('\\', '\\\\')
            key_pattern = self._create_regkey_pattern(key)
            pattern = f"[{key_pattern} AND windows-registry-key:values.data = '{value.strip()}']"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            self._parse_regkey_value_attribute_observable(attribute)


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
    def _create_killchain(category):
        kill_chain = [
            {
                'kill_chain_name': 'misp-category',
                'phase_name': category
            }
        ]
        return kill_chain

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
        observable_args.update(self._handle_observable_time_fields(attribute))
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
    #                         PATTERNS CREATION FUNCTIONS.                         #
    ################################################################################

    @staticmethod
    def _create_content_ref_pattern(value: str) -> str:
        return f"file:content_ref.payload_bin = '{value}'"

    @staticmethod
    def _create_domain_pattern(value: str) -> str:
        return f"domain-name:value = '{value}'"

    @staticmethod
    def _create_domain_resolving_pattern(value: str) -> str:
        return f"domain-name:resolves_to_refs[*].value = '{value}'"

    @staticmethod
    def _create_filename_pattern(value: str) -> str:
        return f"file:name = '{value}'"

    def _create_hash_pattern(self, hash_type: str, value: str) -> str:
        return f"file:hashes.{self._define_hash_type(hash_type)} = '{value}'"

    @staticmethod
    def _create_port_pattern(value: str) -> str:
        return f"network-traffic:dst_port = '{value}'"

    @staticmethod
    def _create_regkey_pattern(value: str) -> str:
        return f"windows-registry-key:key = '{value.strip()}'"

    ################################################################################
    #                              UTILITY FUNCTIONS.                              #
    ################################################################################

    @staticmethod
    def _datetime_from_str(timestamp: str) -> datetime:
        return datetime.strptime(timestamp.split('+')[0], '%Y-%m-%dT%H:%M:%S.%f')

    @staticmethod
    def _define_hash_type(hash_type: str) -> str:
        if '/' in hash_type:
            return f"SHA{hash_type.split('/')[1]}"
        return hash_type.replace('-', '').upper()

    def _handle_indicator_time_fields(self, attribute: dict) -> dict:
        timestamp = self._datetime_from_timestamp(attribute['timestamp'])
        to_return = {
            'created': timestamp,
            'modified': timestamp
        }
        if not any(attribute.get(feature) for feature in _misp_time_fields):
            to_return['valid_from'] = timestamp
            return to_return
        stix_fields = _stix_time_fields['indicator']
        for misp_field, stix_field in zip(_misp_time_fields, stix_fields):
            to_return[stix_field] = self._datetime_from_str(attribute[misp_field]) if attribute.get(misp_field) else timestamp
        return to_return

    def _handle_observable_time_fields(self, attribute: dict) -> dict:
        timestamp = self._datetime_from_timestamp(attribute['timestamp'])
        to_return = {
            'created': timestamp,
            'modified': timestamp
        }
        stix_fields = _stix_time_fields['observed-data']
        for misp_field, stix_field in zip(_misp_time_fields, stix_fields):
            to_return[stix_field] = self._datetime_from_str(attribute[misp_field]) if attribute.get(misp_field) else timestamp
        return to_return

    @staticmethod
    def _handle_value_for_pattern(attribute_value: str) -> str:
        return attribute_value.replace("'", '##APOSTROPHE##').replace('"', '##QUOTE##')
