#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from . import stix2_mapping
from .exportparser import MISPtoSTIXParser
from collections import defaultdict
from datetime import datetime
from stix2.properties import ListProperty, StringProperty
from stix2.v20.bundle import Bundle as Bundle_v20
from stix2.v21.bundle import Bundle as Bundle_v21
from typing import Optional, Union
from uuid import uuid4

_label_fields = ('type', 'category', 'to_ids')
_misp_time_fields = ('first_seen', 'last_seen')
_object_attributes_additional_fields = ('category', 'comment', 'to_ids', 'uuid')
_object_attributes_fields = ('type', 'object_relation', 'value')
_stix_time_fields = {
    'indicator': ('valid_from', 'valid_until'),
    'observed-data': ('first_observed', 'last_observed')
}


class MISPtoSTIX2Parser(MISPtoSTIXParser):
    def __init__(self):
        super().__init__()
        self._custom_objects = {}
        self._galaxies = []
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
            self._objects_to_parse = defaultdict(dict)
            self._resolve_objects()
            if self._objects_to_parse:
                self._resolve_objects_to_parse()
        report = self._generate_event_report()
        self._objects.insert(index, report)

    @property
    def bundle(self) -> Union[Bundle_v20, Bundle_v21]:
        return self._create_bundle()

    @property
    def stix_objects(self) -> list:
        return self._objects

    @staticmethod
    def _update_mapping_v20():
        stix2_mapping.network_socket_mapping['extension'].update(
            {
                'domain-family': 'protocol_family'
            }
        )
        stix2_mapping.process_object_mapping['features'].update(
            {
                'args': 'arguments',
                'name': 'name'
            }
        )
        stix2_mapping.process_object_mapping['parent'].update(
            {
                'parent-process-name': 'name'
            }
        )

    @staticmethod
    def _update_mapping_v21():
        stix2_mapping.attribute_types_mapping.update(
            {
                'email-message-id': '_parse_email_message_id_attribute'
            }
        )
        stix2_mapping.email_object_mapping.update(
            {
                'message-id': 'message_id'
            }
        )
        stix2_mapping.user_account_object_mapping['features'].update(
            {
                'password': 'credential'
            }
        )
        stix2_mapping.user_account_object_mapping['timeline'].update(
            {
                'password_last_changed': 'credential_last_changed'
            }
        )
        stix2_mapping.objects_mapping.update(
            {
                'geolocation': '_parse_geolocation_object'
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
        markings = self._handle_event_tags_and_galaxies('stix2_galaxy_mapping')
        if markings:
            self._handle_markings(report_args, markings)
        if self._relationships:
            for source_id, relationships in self._relationships.items():
                for relationship in relationships:
                    target_id, relationship_type, timestamp = relationship
                    relationship_args = {
                        'source_ref': source_id,
                        'target_ref': target_id,
                        'relationship_type': relationship_type,
                        'created': timestamp,
                        'modified': timestamp
                    }
                    self._append_SDO(self._create_relationship(relationship_args))
        if self._markings:
            for marking in self._markings.values():
                self._objects.append(marking)
        if self._is_published():
            report_id = f"report--{self._misp_event['uuid']}"
            if not self._object_refs:
                self._handle_empty_object_refs(report_id, timestamp)
            published = self._datetime_from_timestamp(self._misp_event['publish_timestamp'])
            report_args.update(
                {
                    'id': report_id,
                    'type': 'report',
                    'published': published,
                    'object_refs': self._object_refs
                }
            )
            return self._create_report(report_args)
        return self._handle_unpublished_report(report_args)

    def _handle_markings(self, object_args: dict, markings: tuple):
        marking_ids = []
        for marking in markings:
            if marking in self._markings:
                marking_ids.append(self._markings[marking]['id'])
                continue
            if marking.startswith('tlp:'):
                marking_id = self._get_marking(marking)
                if marking_id is not None:
                    marking_ids.append(marking_id)
                    continue
            object_args['labels'].append(marking)
        if marking_ids:
            object_args['object_marking_refs'] = marking_ids

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
        markings = self._handle_attribute_tags_and_galaxies(
            attribute,
            indicator_id,
            indicator_args['modified']
        )
        if markings:
            self._handle_markings(indicator_args, markings)
        self._append_SDO(self._create_indicator(indicator_args))

    def _handle_attribute_observable(self, attribute: dict, observable: Union[dict, list]):
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
        markings = self._handle_attribute_tags_and_galaxies(
            attribute,
            observable_id,
            observable_args['modified']
        )
        if markings:
            self._handle_markings(observable_args, markings)
        self._create_observed_data(observable_args, observable)

    def _handle_attribute_tags_and_galaxies(self, attribute: dict, object_id: str, timestamp: datetime) -> tuple:
        if attribute.get('Galaxy'):
            tag_names = []
            for galaxy in attribute['Galaxy']:
                galaxy_type = galaxy['type']
                if galaxy_type in stix2_mapping.galaxy_types_mapping:
                    to_call = stix2_mapping.galaxy_types_mapping[galaxy_type]
                    getattr(self, to_call.format('attribute'))(galaxy, object_id, timestamp)
                    tag_names.extend(self._quick_fetch_tag_names(galaxy))
                else:
                    self._warnings.add(f"{galaxy_type} galaxy in {attribute['type']} attribute not mapped.")
            return tuple(tag['name'] for tag in attribute.get('Tag', []) if tag['name'] not in tag_names)
        return tuple(tag['name'] for tag in attribute.get('Tag', []))

    @staticmethod
    def _parse_AS_value(value: str) -> int:
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
            pattern = f"[{self._create_AS_pattern(attribute['value'])}]"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            self._parse_autonomous_system_attribute_observable(attribute)

    def _parse_campaign_name_attribute(self, attribute: dict):
        campaign_id = f"campaign--{attribute['uuid']}"
        timestamp = self._datetime_from_timestamp(attribute['timestamp'])
        campaign_args = {
            'id': campaign_id,
            'type': 'campaign',
            'name': attribute['value'],
            'created_by_ref': self._identity_id,
            'labels': self._create_labels(attribute),
            'interoperability': True,
            'created': timestamp,
            'modified': timestamp
        }
        markings = self._handle_attribute_tags_and_galaxies(
            attribute,
            campaign_id,
            timestamp
        )
        if markings:
            self._handle_markings(campaign_args, markings)
        self._append_SDO(self._create_campaign(campaign_args))

    def _parse_custom_attribute(self, attribute: dict):
        custom_id = f"x-misp-attribute--{attribute['uuid']}"
        timestamp = self._datetime_from_timestamp(attribute['timestamp'])
        custom_args = {
            'id': custom_id,
            'created': timestamp,
            'modified': timestamp,
            'labels': self._create_labels(attribute),
            'created_by_ref': self._identity_id,
            'x_misp_value': attribute['value'],
            'x_misp_type': attribute['type'],
            'x_misp_category': attribute['category'],
            'interoperability': True
        }
        if attribute.get('comment'):
            custom_args['x_misp_comment'] = attribute['comment']
        markings = self._handle_attribute_tags_and_galaxies(
            attribute,
            custom_id,
            timestamp
        )
        if markings:
            self._handle_markings(custom_args, markings)
        self._append_SDO(self._create_custom_attribute(custom_args))

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

    def _parse_hash_composite_attribute(self, attribute: dict, hash_type: Optional[str] = None):
        if attribute.get('to_ids', False):
            if hash_type is None:
                hash_type = attribute['type'].split('|')[1]
            pattern = self._create_filename_hash_pattern(hash_type, attribute['value'])
            self._handle_attribute_indicator(attribute, f"[{pattern}]")
        else:
            self._parse_hash_composite_attribute_observable(attribute, hash_type=hash_type)

    def _parse_hostname_port_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            hostname, port = attribute['value'].split('|')
            hostname_pattern = self._create_domain_pattern(hostname)
            port_pattern = self._create_port_pattern(port)
            pattern = f"[{hostname_pattern} AND {port_pattern}]"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            self._parse_hostname_port_attribute_observable(attribute)

    def _parse_http_method_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            pattern = f"[network-traffic:extensions.'http-request-ext'.request_method = '{attribute['value']}']"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            self._parse_custom_attribute(attribute)

    def _parse_ip_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            ip_type = attribute['type'].split('-')[1]
            pattern = f"[{self._create_ip_pattern(ip_type, attribute['value'])}]"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            self._parse_ip_attribute_observable(attribute)

    def _parse_ip_port_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            ip_type = attribute['type'].split('|')[0].split('-')[1]
            ip_value, port_value = attribute['value'].split('|')
            ip_pattern = self._create_ip_pattern(ip_type, ip_value)
            port_pattern = self._create_port_pattern(port_value, ip_type=ip_type)
            pattern = f"[{ip_pattern} AND {port_pattern}]"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            self._parse_ip_port_attribute_observable(attribute)

    def _parse_mac_address_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            pattern = f"[mac-addr:value = '{attribute['value']}']"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            self._parse_mac_address_attribute_observable(attribute)

    def _parse_malware_sample_attribute(self, attribute: dict):
        if attribute.get('data'):
            if attribute.get('to_ids', False):
                file_pattern = self._create_filename_hash_pattern('md5', attribute['value'])
                data_pattern = self._create_content_ref_pattern(attribute['data'])
                pattern = f"[{file_pattern} AND {data_pattern}]"
                self._handle_attribute_indicator(attribute, pattern)
            else:
                self._parse_malware_sample_attribute_observable(attribute)
        else:
            self._parse_hash_composite_attribute(attribute, hash_type='md5')

    def _parse_mutex_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            pattern = f"[mutex:name = '{attribute['value']}']"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            self._parse_mutex_attribute_observable(attribute)

    def _parse_port_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            pattern = f"[network-traffic:dst_port = '{attribute['value']}']"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            self._parse_custom_attribute(attribute)

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

    def _parse_size_in_bytes_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            pattern = f"[file:size = '{attribute['value']}']"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            self._parse_custom_attribute(attribute)

    def _parse_url_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            pattern = f"[url:value = '{attribute['value']}']"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            self._parse_url_attribute_observable(attribute)

    def _parse_user_agent_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            pattern = f"[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = '{attribute['value']}']"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            self._parse_custom_attribute(attribute)

    def _parse_vulnerability_attribute(self, attribute: dict):
        vulnerability_id = f"vulnerability--{attribute['uuid']}"
        timestamp = self._datetime_from_timestamp(attribute['timestamp'])
        vulnerability_args = {
            'id': vulnerability_id,
            'type': 'vulnerability',
            'name': attribute['value'],
            'external_references': [self._get_vulnerability_references(attribute['value'])],
            'created_by_ref': self._identity_id,
            'labels': self._create_labels(attribute),
            'interoperability': True,
            'created': timestamp,
            'modified': timestamp
        }
        markings = self._handle_attribute_tags_and_galaxies(
            attribute,
            vulnerability_id,
            timestamp
        )
        if markings:
            self._handle_markings(vulnerability_args, markings)
        self._append_SDO(self._create_vulnerability(vulnerability_args))

    def _parse_x509_fingerprint_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            hash_type = attribute['type'].split('-')[-1].upper()
            pattern = f"[x509-certificate:hashes.{hash_type} = '{attribute['value']}']"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            self._parse_x509_fingerprint_attribute_observable(attribute)

    ################################################################################
    #                        MISP OBJECTS PARSING FUNCTIONS                        #
    ################################################################################

    def _resolve_objects(self):
        for misp_object in self._misp_event['Object']:
            object_name = misp_object['name']
            if object_name in stix2_mapping.objects_mapping:
                getattr(self, stix2_mapping.objects_mapping[object_name])(misp_object)
            else:
                self._parse_custom_object(misp_object)
                self._warnings.add(f'MISP Object name {object_name} not mapped.')

    def _resolve_objects_to_parse(self):
        for file_uuid, misp_object in self._objects_to_parse['file'].items():
            file_ids, file_object = misp_object
            pe_uuid = self._fetch_included_reference_uuids(file_object['ObjectReference'], 'pe')
            if len(pe_uuid) != 1:
                self._raise_file_and_pe_references_warning(file_uuid, pe_uuid)
                if file_ids:
                    pattern = self._parse_file_object_pattern(file_object['Attribute'])
                    self._handle_object_indicator(file_object, pattern)
                else:
                    self._parse_file_object_observable(file_object)
                continue
            pe_uuid = pe_uuid[0]
            pe_ids, pe_object = self._objects_to_parse['pe'][pe_uuid]
            ids_list = [file_ids, pe_ids]
            args = [pe_uuid]
            if pe_object.get('ObjectReference'):
                section_uuids = self._fetch_included_reference_uuids(
                    pe_object['ObjectReference'],
                    'pe-section'
                )
                if section_uuids:
                    for section_uuid in section_uuids:
                        section_ids, _ = self._objects_to_parse['pe-section'][section_uuid]
                        ids_list.append(section_ids)
                    args.append(section_uuids)
            if True in ids_list:
                pattern = self._parse_file_object_pattern(file_object['Attribute'])
                pattern.extend(self._parse_pe_extensions_pattern(*args))
                self._handle_object_indicator(file_object, pattern)
            else:
                file_args, observable = self._parse_file_observable_object(file_object['Attribute'])
                file_args['extensions'] = self._parse_pe_extensions_observable(*args)
                self._handle_file_observable_objects(file_args, observable)
                self._handle_object_observable(file_object, observable)

    def _handle_object_indicator(self, misp_object: dict, pattern: list):
        indicator_id = f"indicator--{misp_object['uuid']}"
        indicator_args = {
            'id': indicator_id,
            'type': 'indicator',
            'labels': self._create_object_labels(misp_object, to_ids=True),
            'kill_chain_phases': self._create_killchain(misp_object['meta-category']),
            'created_by_ref': self._identity_id,
            'pattern': f'[{" AND ".join(pattern)}]',
            'allow_custom': True,
            'interoperability': True
        }
        indicator_args.update(self._handle_indicator_time_fields(misp_object))
        if misp_object.get('comment'):
            indicator_args['description'] = misp_object['comment']
        markings = self._handle_object_tags_and_galaxies(
            misp_object,
            indicator_id,
            indicator_args['modified']
        )
        if markings:
            self._handle_markings(indicator_args, markings)
        self._append_SDO(self._create_indicator(indicator_args))

    def _handle_object_observable(self, misp_object: dict, observable: Union[dict, list]):
        observable_id = f"observed-data--{misp_object['uuid']}"
        observable_args = {
            'id': observable_id,
            'type': 'observed-data',
            'labels': self._create_object_labels(misp_object, to_ids=False),
            'number_observed': 1,
            'created_by_ref': self._identity_id,
            'allow_custom': True,
            'interoperability': True
        }
        observable_args.update(self._handle_observable_time_fields(misp_object))
        markings = self._handle_object_tags_and_galaxies(
            misp_object,
            observable_id,
            observable_args['modified']
        )
        if markings:
            self._handle_markings(observable_args, markings)
        self._create_observed_data(observable_args, observable)

    def _handle_object_tags_and_galaxies(self, misp_object: dict, object_id: str, timestamp: datetime) -> tuple:
        tags, galaxies = self._extract_object_attribute_tags_and_galaxies(
            misp_object,
            'stix2_galaxy_mapping'
        )
        if galaxies:
            tag_names = set()
            for galaxy_type, galaxy in galaxies.items():
                if galaxy_type in stix2_mapping.galaxy_types_mapping:
                    to_call = stix2_mapping.galaxy_types_mapping[galaxy_type]
                    getattr(self, to_call.format('attribute'))(galaxy, object_id, timestamp)
                    tag_names.extend(self._quick_fetch_tag_names(galaxy))
                else:
                    self._warnings.add(f"{galaxy_type} galaxy in {misp_object['name']} object not mapped.")
            return tuple(tag for tag in tags if tag not in tag_names)
        return tuple(tags)

    @staticmethod
    def _handle_observable_multiple_properties(attributes: dict) -> dict:
        properties = {'allow_custom': True}
        for key, values in attributes.items():
            feature = f"x_misp_{key.replace('-', '_')}"
            properties[feature] = values[0] if isinstance(values, list) and len(values) == 1 else values
        return properties

    @staticmethod
    def _handle_observable_properties(attributes: dict) -> dict:
        properties = {'allow_custom': True}
        for key, value in attributes.items():
            properties[f"x_misp_{key.replace('-', '_')}"] = value
        return properties

    @staticmethod
    def _handle_pattern_multiple_properties(attributes: dict, prefix: str, separator: Optional[str]=':') -> list:
        pattern = []
        for key, values in attributes.items():
            key = key.replace('-', '_')
            if not isinstance(values, list):
                pattern.append(f"{prefix}{separator}x_misp_{key} = '{values}'")
                continue
            for value in values:
                pattern.append(f"{prefix}{separator}x_misp_{key} = '{value}'")
        return pattern

    @staticmethod
    def _handle_pattern_properties(attributes: dict, prefix: str, separator: Optional[str]=':') -> list:
        pattern = []
        for key, value in attributes.items():
            pattern.append(f"{prefix}{separator}x_misp_{key.replace('-', '_')} = '{value}'")
        return pattern

    def _parse_account_object(self, misp_object: dict):
        account_type = misp_object['name'].split('-')[0]
        if self._fetch_ids_flag(misp_object['Attribute']):
            prefix = 'user-account'
            attributes = self._extract_multiple_object_attributes(
                misp_object['Attribute'],
                force_single=getattr(stix2_mapping, f"{account_type}_account_single_fields")
            )
            pattern = [f"{prefix}:account_type = '{account_type}'"]
            for key, feature in getattr(stix2_mapping, f"{account_type}_account_object_mapping").items():
                if attributes.get(key):
                    pattern.append(f"{prefix}:{feature} = '{attributes.pop(key)}'")
            if attributes:
                pattern.extend(self._handle_pattern_multiple_properties(attributes, prefix))
            self._handle_object_indicator(misp_object, pattern)
        else:
            self._parse_account_object_observable(misp_object, account_type)

    def _parse_asn_object(self, misp_object: dict):
        if self._fetch_ids_flag(misp_object['Attribute']):
            prefix = 'autonomous-system'
            attributes = self._extract_multiple_object_attributes(
                misp_object['Attribute'],
                force_single=stix2_mapping.as_single_fields
            )
            pattern = [self._create_AS_pattern(attributes.pop('asn'))]
            if attributes.get('description'):
                pattern.append(f"{prefix}:name = '{attributes.pop('description')}'")
            if attributes:
                pattern.extend(self._handle_pattern_multiple_properties(attributes, prefix))
            self._handle_object_indicator(misp_object, pattern)
        else:
            self._parse_asn_object_observable(misp_object)

    def _parse_attack_pattern_object(self, misp_object: dict):
        attributes = self._extract_multiple_object_attributes(
            misp_object['Attribute'],
            force_single=stix2_mapping.attack_pattern_single_fields
        )
        prefix = 'attack-pattern'
        attack_pattern_id = f"{prefix}--{misp_object['uuid']}"
        timestamp = self._datetime_from_timestamp(misp_object['timestamp'])
        attack_pattern_args = defaultdict(list)
        for key, feature in stix2_mapping.attack_pattern_object_mapping.items():
            if attributes.get(key):
                attack_pattern_args[feature] = attributes.pop(key)
        for feature in ('id', 'references'):
            if attributes.get(feature):
                for value in attributes.pop(feature):
                    reference = self._parse_attack_pattern_reference(
                        feature,
                        value
                    )
                    attack_pattern_args['external_references'].append(reference)
        if attributes:
            attack_pattern_args.update(self._handle_observable_multiple_properties(attributes))
        attack_pattern_args. update(
            {
                'id': attack_pattern_id,
                'type': prefix,
                'created_by_ref': self._identity_id,
                'labels': self._create_object_labels(misp_object),
                'kill_chain_phases': self._create_killchain(misp_object['meta-category']),
                'created': timestamp,
                'modified': timestamp,
                'interoperability': True
            }
        )
        markings = self._handle_object_tags_and_galaxies(
            misp_object,
            attack_pattern_id,
            timestamp
        )
        if markings:
            self._handle_markings(attack_pattern_args, markings)
        self._append_SDO(self._create_attack_pattern_from_object(attack_pattern_args))

    @staticmethod
    def _parse_attack_pattern_reference(feature: str, value: str) -> dict:
        source_name, key = stix2_mapping.attack_pattern_reference_mapping[feature]
        if feature == 'id':
            if 'CAPEC' not in value:
                value = f"CAPEC-{value}"
        else:
            if 'mitre' not in value:
                source_name = 'external_url'
        return {'source_name': source_name, key: value}

    def _parse_course_of_action_object(self, misp_object: dict):
        attributes = self._extract_object_attributes(misp_object['Attribute'])
        prefix = 'course-of-action'
        course_of_action_id = f"{prefix}--{misp_object['uuid']}"
        timestamp = self._datetime_from_timestamp(misp_object['timestamp'])
        course_of_action_args = {
            'id': course_of_action_id,
            'type': prefix,
            'created_by_ref': self._identity_id,
            'labels': self._create_object_labels(misp_object),
            'created': timestamp,
            'modified': timestamp,
            'interoperability': True
        }
        for feature in stix2_mapping.course_of_action_object_mapping:
            if attributes.get(feature):
                course_of_action_args[feature] = attributes.pop(feature)
        if attributes:
            course_of_action_args.update(self._handle_observable_properties(attributes))
        markings = self._handle_object_tags_and_galaxies(
            misp_object,
            course_of_action_id,
            timestamp
        )
        if markings:
            self._handle_markings(course_of_action_args, markings)
        self._append_SDO(self._create_course_of_action(course_of_action_args))

    def _parse_credential_object(self, misp_object: dict):
        if self._fetch_ids_flag(misp_object['Attribute']):
            prefix = 'user-account'
            attributes = self._extract_multiple_object_attributes(
                misp_object['Attribute'],
                force_single=stix2_mapping.credential_single_fields
            )
            pattern = []
            if attributes.get('username'):
                pattern.append(f"{prefix}:user_id = '{attributes.pop('username')}'")
            if attributes.get('password'):
                for password in attributes.pop('password'):
                    pattern.append(f"{prefix}:credential = '{password}'")
            if attributes:
                pattern.extend(self._handle_pattern_multiple_properties(attributes, prefix))
            self._handle_object_indicator(misp_object, pattern)
        else:
            self._parse_credential_object_observable(misp_object)

    def _parse_custom_object(self, misp_object: dict):
        custom_id = f"x-misp-object--{misp_object['uuid']}"
        timestamp = self._datetime_from_timestamp(misp_object['timestamp'])
        custom_args = {
            'id': custom_id,
            'created': timestamp,
            'modified': timestamp,
            'labels': self._create_object_labels(misp_object),
            'created_by_ref': self._identity_id,
            'x_misp_name': misp_object['name'],
            'x_misp_meta_category': misp_object['meta-category'],
            'x_misp_attributes': [
                self._parse_custom_object_attribute(attribute) for attribute in misp_object['Attribute']
            ],
            'interoperability': True
        }
        if misp_object.get('comment'):
            custom_args['x_misp_comment'] = misp_object['comment']
        markings = self._handle_object_tags_and_galaxies(
            misp_object,
            custom_id,
            timestamp
        )
        if markings:
            self._handle_markings(custom_args, markings)
        self._append_SDO(self._create_custom_object(custom_args))

    @staticmethod
    def _parse_custom_object_attribute(attribute: dict) -> dict:
        custom_attribute = {key: attribute[key] for key in _object_attributes_fields}
        for field in _object_attributes_additional_fields:
            if attribute.get(field):
                custom_attribute[field] = attribute[field]
        return custom_attribute

    def _parse_domain_ip_object(self, misp_object: dict):
        if self._fetch_ids_flag(misp_object['Attribute']):
            prefix = 'domain-name'
            attributes = self._extract_multiple_object_attributes(misp_object['Attribute'])
            pattern = []
            for key, feature in stix2_mapping.domain_ip_object_mapping.items():
                if attributes.get(key):
                    for value in attributes.pop(key):
                        pattern.append(f"{prefix}:{feature} = '{value}'")
            if attributes:
                pattern.extend(self._handle_pattern_multiple_properties(attributes, prefix))
            self._handle_object_indicator(misp_object, pattern)
        else:
            self._parse_domain_ip_object_observable(misp_object)

    def _parse_email_object(self, misp_object: dict):
        if self._fetch_ids_flag(misp_object['Attribute']):
            prefix = 'email-message'
            attributes = self._extract_multiple_object_attributes_with_data(
                misp_object['Attribute'],
                with_data=stix2_mapping.email_data_fields
            )
            pattern = []
            for key, feature in stix2_mapping.email_object_mapping.items():
                if attributes.get(key):
                    for value in attributes.pop(key):
                        pattern.append(f"{prefix}:{feature} = '{value}'")
            if attributes:
                n = 0
                for key in stix2_mapping.email_data_fields:
                    if attributes.get(key):
                        for value in attributes.pop(key):
                            feature = f'body_multipart[{n}].body_raw_ref'
                            if isinstance(value, tuple):
                                value, data = value
                                pattern.append(f"{prefix}:{feature}.payload_bin = '{value}'")
                            pattern.append(f"{prefix}:{feature}.name = '{value}'")
                            n += 1
                pattern.extend(self._handle_pattern_multiple_properties(attributes, prefix))
            self._handle_object_indicator(misp_object, pattern)
        else:
            self._parse_email_object_observable(misp_object)

    def _parse_file_object(self, misp_object: dict):
        to_ids = self._fetch_ids_flag(misp_object['Attribute'])
        if misp_object.get('ObjectReference'):
            for reference in misp_object['ObjectReference']:
                if self._is_reference_included(reference, 'pe'):
                    self._objects_to_parse['file'][misp_object['uuid']] = to_ids, misp_object
                    return
        if to_ids:
            pattern = self._parse_file_object_pattern(misp_object['Attribute'])
            self._handle_object_indicator(misp_object, pattern)
        else:
            self._parse_file_object_observable(misp_object)

    def _parse_file_object_pattern(self, attributes: list) -> list:
        prefix = 'file'
        attributes = self._extract_multiple_object_attributes_with_data(
            attributes,
            force_single=stix2_mapping.file_single_fields,
            with_data=stix2_mapping.file_data_fields
        )
        pattern = []
        for hash_type in stix2_mapping._hash_attribute_types:
            if attributes.get(hash_type):
                pattern.append(
                    self._create_hash_pattern(
                        hash_type,
                        attributes.pop(hash_type)
                    )
                )
        for key, feature in stix2_mapping.file_object_mapping.items():
            if attributes.get(key):
                for value in attributes.pop(key):
                    pattern.append(f"{prefix}:{feature} = '{value}'")
        if attributes.get('path'):
            value = attributes.pop('path')
            pattern.append(f"{prefix}:parent_directory_ref.path = '{value}'")
        if attributes.get('malware-sample'):
            value = attributes.pop('malware-sample')
            malware_sample = []
            if isinstance(value, tuple):
                value, data = value
                malware_sample.append(self._create_content_ref_pattern(data))
            filename, md5 = value.split('|')
            malware_sample.append(
                self._create_content_ref_pattern(
                    filename,
                    'x_misp_filename'
                )
            )
            malware_sample.append(
                self._create_content_ref_pattern(
                    md5,
                    'hashes.MD5'
                )
            )
            pattern.append(f"({' AND '.join(malware_sample)})")
        if attributes.get('attachment'):
            value = attributes.pop('attachment')
            if isinstance(value, tuple):
                value, data = value
                filename_pattern = self._create_content_ref_pattern(value, 'x_misp_filename')
                data_pattern = self._create_content_ref_pattern(data)
                pattern.append(f'({data_pattern} AND {filename_pattern})')
            else:
                pattern.append(self._create_content_ref_pattern(value, 'x_misp_filename'))
        if attributes:
            pattern.extend(self._handle_pattern_multiple_properties(attributes, prefix))
        return pattern

    def _parse_ip_port_object(self, misp_object: dict):
        if self._fetch_ids_flag(misp_object['Attribute']):
            prefix = 'network-traffic'
            attributes = self._extract_multiple_object_attributes(misp_object['Attribute'])
            patterns = []
            for key, pattern in stix2_mapping.ip_port_object_mapping['ip_features'].items():
                if attributes.get(key):
                    for ip_value in attributes.pop(key):
                        identifier = pattern.format(self._define_address_type(ip_value))
                        patterns.append(f"({prefix}:{identifier} = '{ip_value}')")
            for key, pattern in stix2_mapping.ip_port_object_mapping['domain_features'].items():
                if attributes.get(key):
                    for domain_value in attributes.pop(key):
                        patterns.append(f"({prefix}:{pattern} = '{domain_value}')")
            for key, feature in stix2_mapping.ip_port_object_mapping['features'].items():
                if attributes.get(key):
                    for value in attributes.pop(key):
                        patterns.append(f"{prefix}:{feature} = '{value}'")
            if attributes:
                patterns.extend(self._handle_pattern_multiple_properties(attributes, prefix))
            self._handle_object_indicator(misp_object, patterns)
        else:
            self._parse_ip_port_object_observable(misp_object)

    def _parse_mutex_object(self, misp_object: dict):
        if self._fetch_ids_flag(misp_object['Attribute']):
            prefix = 'mutex'
            attributes = self._extract_object_attributes(misp_object['Attribute'])
            pattern = []
            if attributes.get('name'):
                pattern.append(f"{prefix}:name = '{attributes.pop('name')}'")
            if attributes:
                pattern.extend(self._handle_pattern_properties(attributes, prefix))
            self._handle_object_indicator(misp_object, pattern)
        else:
            self._parse_mutex_object_observable(misp_object)

    def _parse_network_connection_object(self, misp_object: dict):
        if self._fetch_ids_flag(misp_object['Attribute']):
            prefix = 'network-traffic'
            attributes = self._extract_object_attributes(misp_object['Attribute'])
            pattern = self._parse_network_references_pattern(attributes)
            for key, feature in stix2_mapping.network_connection_mapping['features'].items():
                if attributes.get(key):
                    pattern.append(f"{prefix}:{feature} = '{attributes.pop(key)}'")
            index = 0
            for key in stix2_mapping.network_connection_mapping['protocols']:
                if attributes.get(key):
                    pattern.append(f"{prefix}:protocols[{index}] = '{attributes.pop(key)}'")
                    index += 1
            if attributes:
                pattern.extend(self._handle_pattern_properties(attributes, prefix))
            self._handle_object_indicator(misp_object, pattern)
        else:
            self._parse_network_connection_object_observable(misp_object)

    def _parse_network_references_pattern(self, attributes: dict) -> list:
        pattern = []
        for key in ('src', 'dst'):
            feature = f'network-traffic:{key}_ref'
            if attributes.get(f'ip-{key}'):
                value = attributes.pop(f'ip-{key}')
                ip_type = self._define_address_type(value)
                pattern.append(f"({feature}.type = '{ip_type}' AND {feature}.value = '{value}')")
            if attributes.get(f'hostname-{key}'):
                value = attributes.pop(f'hostname-{key}')
                pattern.append(f"({feature}.type = 'domain-name' AND {feature}.value = '{value}')")
        return pattern

    def _parse_network_socket_object_pattern(self, attributes: dict) -> list:
        prefix = 'network-traffic'
        pattern = self._parse_network_references_pattern(attributes)
        for key, feature in stix2_mapping.network_socket_mapping['features'].items():
            if attributes.get(key):
                pattern.append(f"{prefix}:{feature} = '{attributes.pop(key)}'")
        if attributes.get('protocol'):
            pattern.append(f"{prefix}:protocols[0] = '{attributes.pop('protocol')}'")
        prefix = f"{prefix}:extensions.'socket-ext'"
        for key, feature in stix2_mapping.network_socket_mapping['extension'].items():
            if attributes.get(key):
                pattern.append(f"{prefix}.{feature} = '{attributes.pop(key)}'")
        if attributes.get('state'):
            for state in attributes.pop('state'):
                if state in stix2_mapping.network_socket_state_fields:
                    pattern.append(f"{prefix}.is_{state} = true")
                else:
                    attributes['state'].append(state)
        if attributes:
            pattern.extend(
                self._handle_pattern_multiple_properties(attributes, 'network-traffic')
            )
        return pattern

    def _parse_pe_extensions_observable(self, pe_uuid: str, uuids: Optional[list]=None) -> dict:
        attributes = self._extract_multiple_object_attributes(
            self._objects_to_parse['pe'][pe_uuid][1]['Attribute'],
            force_single=stix2_mapping.pe_object_single_fields
        )
        extension = defaultdict(list)
        for key, feature in stix2_mapping.pe_object_mapping['features'].items():
            if attributes.get(key):
                extension[feature] = attributes.pop(key)
        optional_header = {}
        for key, feature in stix2_mapping.pe_object_mapping['header'].items():
            if attributes.get(key):
                optional_header[feature] = attributes.pop(key)
        if optional_header:
            extension['optional_header'] = optional_header
        if attributes:
            extension.update(self._handle_observable_multiple_properties(attributes))
        if uuids is not None:
            for section_uuid in uuids:
                section = defaultdict(dict)
                attributes = self._extract_object_attributes(
                    self._objects_to_parse['pe-section'][section_uuid][1]['Attribute']
                )
                for key, feature in stix2_mapping.pe_section_mapping.items():
                    if attributes.get(key):
                        section[feature] = attributes.pop(key)
                for hash_type in stix2_mapping.file_hash_main_types:
                    if attributes.get(hash_type):
                        value = self._select_single_feature(attributes, hash_type)
                        section['hashes'][self._define_hash_type(hash_type)] = value
                if attributes:
                    section.update(self._handle_observable_properties(attributes))
                extension['sections'].append(self._create_windowsPESection(section))
        return {'windows-pebinary-ext': extension}

    def _parse_pe_extensions_pattern(self, pe_uuid: str, uuids: Optional[list]=None) -> list:
        prefix = "file:extensions.'windows-pebinary-ext'"
        attributes = self._extract_multiple_object_attributes(
            self._objects_to_parse['pe'][pe_uuid][1]['Attribute'],
            force_single=stix2_mapping.pe_object_single_fields
        )
        pattern = []
        for key, feature in stix2_mapping.pe_object_mapping['features'].items():
            if attributes.get(key):
                pattern.append(f"{prefix}.{feature} = '{attributes.pop(key)}'")
        for key, feature in stix2_mapping.pe_object_mapping['header'].items():
            if attributes.get(key):
                pattern.append(f"{prefix}.optional_header.{feature} = '{attributes.pop(key)}'")
        if attributes:
            pattern.extend(
                self._handle_pattern_multiple_properties(
                    attributes,
                    prefix,
                    separator='.'
                )
            )
        if uuids is not None:
            for section_uuid in uuids:
                section_prefix = f"{prefix}.sections[{uuids.index(section_uuid)}]"
                attributes = self._extract_object_attributes(
                    self._objects_to_parse['pe-section'][section_uuid][1]['Attribute']
                )
                for key, feature in stix2_mapping.pe_section_mapping.items():
                    if attributes.get(key):
                        pattern.append(f"{section_prefix}.{feature} = '{attributes.pop(key)}'")
                for hash_type in stix2_mapping._hash_attribute_types:
                    if attributes.get(hash_type):
                        pattern.append(
                            self._create_hash_pattern(
                                hash_type,
                                attributes.pop(hash_type),
                                prefix=f'{section_prefix}.hashes'
                            )
                        )
                if attributes:
                    pattern.extend(
                        self._handle_pattern_properties(
                            attributes,
                            section_prefix,
                            separator='.'
                        )
                    )
        return pattern

    def _parse_process_object_pattern(self, attributes: dict) -> list:
        prefix = 'process'
        pattern = []
        for key, feature in stix2_mapping.process_object_mapping['features'].items():
            if attributes.get(key):
                pattern.append(f"{prefix}:{feature} = '{attributes.pop(key)}'")
        if attributes.get('image'):
            pattern.append(f"{prefix}:image_ref.name = '{attributes.pop('image')}'")
        for key, feature in stix2_mapping.process_object_mapping['parent'].items():
            if attributes.get(key):
                pattern.append(f"{prefix}:parent_ref.{feature} = '{attributes.pop(key)}'")
        if attributes.get('parent-image'):
            pattern.append(f"{prefix}:parent_ref.image_ref.name = '{attributes.pop('parent-image')}'")
        if attributes.get('child-pid'):
            index = 0
            for child_pid in attributes.pop('child-pid'):
                pattern.append(f"{prefix}:child_refs[{index}].pid = '{child_pid}'")
                index += 1
        if attributes:
            pattern.extend(self._handle_pattern_multiple_properties(attributes, prefix))
        return pattern

    def _parse_registry_key_object(self, misp_object: dict):
        if self._fetch_ids_flag(misp_object['Attribute']):
            prefix = 'windows-registry-key'
            attributes = self._extract_object_attributes(misp_object['Attribute'])
            pattern = []
            for key, feature in stix2_mapping.registry_key_mapping['features'].items():
                if attributes.get(key):
                    value = attributes.pop(key).replace('\\', '\\\\')
                    pattern.append(f"{prefix}:{feature} = '{value}'")
            values_prefix = f"{prefix}:values[0]"
            for key, feature in stix2_mapping.registry_key_mapping['values'].items():
                if attributes.get(key):
                    pattern.append(f"{values_prefix}.{feature} = '{attributes.pop(key)}'")
            if attributes:
                pattern.extend(self._handle_pattern_properties(attributes, prefix))
            self._handle_object_indicator(misp_object, pattern)
        else:
            self._parse_registry_key_object_observable(misp_object)

    def _parse_url_object(self, misp_object: dict):
        if self._fetch_ids_flag(misp_object['Attribute']):
            prefix = 'url'
            attributes = self._extract_object_attributes(misp_object['Attribute'])
            pattern = []
            if attributes.get('url'):
                pattern.append(f"{prefix}:value = '{attributes.pop('url')}'")
            if attributes:
                pattern.extend(self._handle_pattern_properties(attributes, prefix))
            self._handle_object_indicator(misp_object, pattern)
        else:
            self._parse_url_object_observable(misp_object)

    def _parse_user_account_object(self, misp_object: dict):
        if self._fetch_ids_flag(misp_object['Attribute']):
            prefix = 'user-account'
            attributes = self._extract_multiple_object_attributes(
                misp_object['Attribute'],
                force_single=stix2_mapping.user_account_single_fields
            )
            pattern = []
            for data_type in ('features', 'timeline'):
                for key, feature in stix2_mapping.user_account_object_mapping[data_type].items():
                    if attributes.get(key):
                        pattern.append(f"{prefix}:{feature} = '{attributes.pop(key)}'")
            extension_prefix = f"{prefix}:extensions.'unix-account-ext'"
            for key, feature in stix2_mapping.user_account_object_mapping['extension'].items():
                if attributes.get(key):
                    values = attributes.pop(key)
                    if isinstance(values, list):
                        for value in values:
                            pattern.append(f"{extension_prefix}.{feature} = '{value}'")
                    else:
                        pattern.append(f"{extension_prefix}.{feature} = '{values}'")
            if attributes:
                pattern.extend(self._handle_pattern_multiple_properties(attributes, prefix))
            self._handle_object_indicator(misp_object, pattern)
        else:
            self._parse_user_account_object_observable(misp_object)

    def _parse_vulnerability_object(self, misp_object: dict):
        vulnerability_id = f"vulnerability--{misp_object['uuid']}"
        vulnerability_args = defaultdict(list)
        vulnerability_args.update(
            {
                'id': vulnerability_id,
                'type': 'vulnerability',
                'labels': self._create_object_labels(misp_object),
                'created_by_ref': self._identity_id,
                'interoperability': True
            }
        )
        vulnerability_args.update(self._handle_indicator_time_fields(misp_object))
        markings = self._handle_object_tags_and_galaxies(
            misp_object,
            vulnerability_id,
            vulnerability_args['modified']
        )
        if markings:
            self._handle_markings(indicator_args, markings)
        attributes = self._extract_multiple_object_attributes(misp_object['Attribute'])
        if attributes.get('id'):
            vulnerability_args['name'] = attributes['id'][0]
            for vuln in attributes.pop('id'):
                reference = {
                    'source_name': 'cve' if vuln.startswith('CVE') else 'vulnerability',
                    'external_id': vuln
                }
                vulnerability_args['external_references'].append(reference)
        for feature in ('description', 'summary'):
            if attributes.get(feature):
                vulnerability_args['description'] = self._select_single_feature(
                    attributes,
                    feature
                )
                break
        if attributes.get('references'):
            for reference in attributes.pop('references'):
                vulnerability_args['external_references'].append(
                    {
                        'source_name': 'url',
                        'url': reference
                    }
                )
        if attributes:
            vulnerability_args.update(self._handle_observable_multiple_properties(attributes))
        self._append_SDO(self._create_vulnerability(vulnerability_args))

    def _parse_x509_object(self, misp_object: dict):
        if self._fetch_ids_flag(misp_object['Attribute']):
            prefix = 'x509-certificate'
            attributes = self._extract_multiple_object_attributes(
                misp_object['Attribute'],
                force_single=stix2_mapping.x509_single_fields
            )
            pattern = []
            if attributes.get('self_signed'):
                self_signed = 'true' if bool(int(attributes.pop('self_signed'))) else 'false'
                pattern.append(f"{prefix}:is_self_signed = '{self_signed}'")
            for feature in stix2_mapping.x509_hash_fields:
                if attributes.get(feature):
                    hash_type = self._define_hash_type(feature.split('-')[-1])
                    pattern.append(f"{prefix}:hashes.{hash_type} = '{attributes.pop(feature)}'")
            for data_type in ('features', 'timeline'):
                for key, feature in stix2_mapping.x509_object_mapping[data_type].items():
                    if attributes.get(key):
                        pattern.append(f"{prefix}:{feature} = '{attributes.pop(key)}'")
            extension = []
            for key, feature in stix2_mapping.x509_object_mapping['extension'].items():
                if attributes.get(key):
                    for value in attributes.pop(key):
                        extension.append(f"{feature}:{value}")
            if extension:
                name = ','.join(extension)
                pattern.append(f"{prefix}:x509_v3_extensions.subject_alternative_name = '{name}'")
            if attributes:
                pattern.extend(self._handle_pattern_properties(attributes, prefix))
            self._handle_object_indicator(misp_object, pattern)
        else:
            self._parse_x509_object_observable(misp_object)

    def _populate_objects_to_parse(self, misp_object: dict):
        to_ids = self._fetch_ids_flag(misp_object['Attribute'])
        self._objects_to_parse[misp_object['name']][misp_object['uuid']] = to_ids, misp_object

    ################################################################################
    #                          GALAXIES PARSING FUNCTIONS                          #
    ################################################################################

    def _handle_attribute_galaxy_relationships(self, object_id: str, object_refs: list, timestamp: datetime):
        self._parse_relationships(object_id, object_refs, timestamp)
        self._handle_object_refs(object_refs)

    @staticmethod
    def _handle_external_ids(values: list, prefix: str) -> list:
        external_ids = []
        for value in values:
            if value.startswith(prefix):
                external_id = {
                    'source_name': prefix.lower(),
                    'external_id': value
                }
                external_ids.append(external_id)
        return external_ids

    def _handle_object_refs(self, object_refs: list):
        for object_ref in object_refs:
            if object_ref not in self._object_refs:
                self._object_refs.append(object_ref)

    def _parse_attack_pattern_attribute_galaxy(self, galaxy: dict, object_id: str, timestamp: datetime):
        object_refs = self._parse_attack_pattern_galaxy(galaxy, timestamp)
        self._handle_attribute_galaxy_relationships(object_id, object_refs, timestamp)

    def _parse_attack_pattern_event_galaxy(self, galaxy: dict):
        timestamp = self._datetime_from_timestamp(self._misp_event['timestamp'])
        object_refs = self._parse_attack_pattern_galaxy(galaxy, timestamp)
        self._handle_object_refs(object_refs)

    def _parse_attack_pattern_galaxy(self, galaxy: dict, timestamp: datetime) -> list:
        object_refs = []
        for cluster in galaxy['GalaxyCluster']:
            attack_pattern_id = f"attack-pattern--{cluster['uuid']}"
            if attack_pattern_id in self._ids or attack_pattern_id in self._galaxies:
                object_refs.append(attack_pattern_id)
                continue
            attack_pattern_args = self._create_galaxy_args(
                cluster,
                galaxy['description'],
                galaxy['name'],
                attack_pattern_id,
                timestamp
            )
            if cluster.get('meta', {}).get('external_id'):
                external_ids = self._handle_external_ids(
                    cluster['meta']['external_id'],
                    'CAPEC'
                )
                if external_ids:
                    attack_pattern_args['external_references'] = external_ids
            self._objects.append(
                self._create_attack_pattern_from_galaxy(
                    attack_pattern_args,
                    cluster
                )
            )
            object_refs.append(attack_pattern_id)
            self._galaxies.append(attack_pattern_id)
        return object_refs

    def _parse_course_of_action_attribute_galaxy(self, galaxy: dict, object_id: str, timestamp: datetime):
        object_refs = self._parse_course_of_action_galaxy(galaxy, timestamp)
        self._handle_attribute_galaxy_relationships(object_id, object_refs, timestamp)

    def _parse_course_of_action_event_galaxy(self, galaxy: dict):
        timestamp = self._datetime_from_timestamp(self._misp_event['timestamp'])
        object_refs = self._parse_course_of_action_galaxy(galaxy, timestamp)
        self._handle_object_refs(object_refs)

    def _parse_course_of_action_galaxy(self, galaxy: dict, timestamp: datetime) -> list:
        object_refs = []
        for cluster in galaxy['GalaxyCluster']:
            course_of_action_id = f"course-of-action--{cluster['uuid']}"
            if course_of_action_id in self._ids or course_of_action_id in self._galaxies:
                object_refs.append(course_of_action_id)
                continue
            course_of_action_args = self._create_galaxy_args(
                cluster,
                galaxy['description'],
                galaxy['name'],
                course_of_action_id,
                timestamp
            )
            course_of_action = self._create_course_of_action(course_of_action_args)
            self._objects.append(course_of_action)
            object_refs.append(course_of_action_id)
            self._galaxies.append(course_of_action_id)
        return object_refs

    def _parse_malware_attribute_galaxy(self, galaxy: dict, object_id: str, timestamp: datetime):
        object_refs = self._parse_malware_galaxy(galaxy, timestamp)
        self._handle_attribute_galaxy_relationships(object_id, object_refs, timestamp)

    def _parse_malware_event_galaxy(self, galaxy: dict):
        timestamp = self._datetime_from_timestamp(self._misp_event['timestamp'])
        object_refs = self._parse_malware_galaxy(galaxy, timestamp)
        self._handle_object_refs(object_refs)

    def _parse_malware_galaxy(self, galaxy: dict, timestamp: datetime) -> list:
        object_refs = []
        for cluster in galaxy['GalaxyCluster']:
            malware_id = f"malware--{cluster['uuid']}"
            if malware_id in self._ids or malware_id in self._galaxies:
                object_refs.append(malware_id)
                continue
            malware_args = self._create_galaxy_args(
                cluster,
                galaxy['description'],
                galaxy['name'],
                malware_id,
                timestamp
            )
            malware = self._create_malware(malware_args, cluster)
            self._objects.append(malware)
            object_refs.append(malware_id)
            self._galaxies.append(malware_id)
        return object_refs

    def _parse_threat_actor_attribute_galaxy(self, galaxy: dict, object_id: str, timestamp: datetime):
        object_refs = self._parse_threat_actor_galaxy(galaxy, timestamp)
        self._handle_attribute_galaxy_relationships(object_id, object_refs, timestamp)

    def _parse_threat_actor_event_galaxy(self, galaxy: dict):
        timestamp = self._datetime_from_timestamp(self._misp_event['timestamp'])
        object_refs = self._parse_threat_actor_galaxy(galaxy, timestamp)
        self._handle_object_refs(object_refs)

    def _parse_threat_actor_galaxy(self, galaxy: dict, timestamp: datetime) -> list:
        object_refs = []
        for cluster in galaxy['GalaxyCluster']:
            threat_actor_id = f"threat-actor--{cluster['uuid']}"
            if threat_actor_id in self._ids or threat_actor_id in self._galaxies:
                object_refs.append(threat_actor_id)
                continue
            threat_actor_args = self._create_galaxy_args(
                cluster,
                galaxy['description'],
                galaxy['name'],
                threat_actor_id,
                timestamp
            )
            if cluster.get('meta', {}).get('synonyms'):
                threat_actor_args['aliases'] = cluster['meta']['synonyms']
            threat_actor = self._create_threat_actor(threat_actor_args)
            self._objects.append(threat_actor)
            object_refs.append(threat_actor_id)
            self._galaxies.append(threat_actor_id)
        return object_refs

    def _parse_tool_attribute_galaxy(self, galaxy: dict, object_id: str, timestamp: datetime):
        object_refs = self._parse_tool_galaxy(galaxy, timestamp)
        self._handle_attribute_galaxy_relationships(object_id, object_refs, timestamp)

    def _parse_tool_event_galaxy(self, galaxy: dict):
        timestamp = self._datetime_from_timestamp(self._misp_event['timestamp'])
        object_refs = self._parse_tool_galaxy(galaxy, timestamp)
        self._handle_object_refs(object_refs)

    def _parse_tool_galaxy(self, galaxy: dict, timestamp: datetime) -> list:
        object_refs = []
        for cluster in galaxy['GalaxyCluster']:
            tool_id = f"tool--{cluster['uuid']}"
            if tool_id in self._ids or tool_id in self._galaxies:
                object_refs.append(tool_id)
                continue
            tool_args = self._create_galaxy_args(
                cluster,
                galaxy['description'],
                galaxy['name'],
                tool_id,
                timestamp
            )
            tool = self._create_tool(tool_args, cluster)
            self._objects.append(tool)
            object_refs.append(tool_id)
            self._galaxies.append(tool_id)
        return object_refs

    def _parse_vulnerability_attribute_galaxy(self, galaxy: dict, object_id: str, timestamp: datetime):
        object_refs = self._parse_vulnerability_galaxy(galaxy, timestamp)
        self._handle_attribute_galaxy_relationships(object_id, object_refs, timestamp)

    def _parse_vulnerability_event_galaxy(self, galaxy: dict):
        timestamp = self._datetime_from_timestamp(self._misp_event['timestamp'])
        object_refs = self._parse_vulnerability_galaxy(galaxy, timestamp)
        self._handle_object_refs(object_refs)

    def _parse_vulnerability_galaxy(self, galaxy: dict, timestamp: datetime) -> list:
        object_refs = []
        for cluster in galaxy['GalaxyCluster']:
            vulnerability_id = f"vulnerability--{cluster['uuid']}"
            if vulnerability_id in self._ids or vulnerability_id in self._galaxies:
                object_refs.append(vulnerability_id)
                continue
            vulnerability_args = self._create_galaxy_args(
                cluster,
                galaxy['description'],
                galaxy['name'],
                vulnerability_id,
                timestamp
            )
            if cluster.get('meta', {}).get('aliases'):
                external_ids = self._handle_external_ids(
                    cluster['meta']['aliases'],
                    'CVE'
                )
                if external_ids:
                    vulnerability_args['external_references'] = external_ids
            vulnerability = self._create_vulnerability(vulnerability_args)
            self._objects.append(vulnerability)
            object_refs.append(vulnerability_id)
            self._galaxies.append(vulnerability_id)
        return object_refs

    ################################################################################
    #                    STIX OBJECTS CREATION HELPER FUNCTIONS                    #
    ################################################################################

    def _create_galaxy_args(self, cluster: dict, description: str, name: str, object_id: str, timestamp: datetime) -> dict:
        galaxy_args = {
            'id': object_id,
            'type': object_id.split('--')[0],
            'created': timestamp,
            'modified': timestamp,
            'name': cluster['value'],
            'description': f"{description} | {cluster['description']}",
            'labels': self._create_galaxy_labels(name, cluster),
            'interoperability': True
        }
        return galaxy_args

    @staticmethod
    def _create_galaxy_labels(galaxy_name: str, cluster: dict) -> list:
        labels = [f'misp:name="{galaxy_name}"']
        if cluster.get('tag_name'):
            labels.append(cluster['tag_name'])
        return labels

    @staticmethod
    def _create_killchain(category: str) -> list:
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
    def _create_object_labels(misp_object: dict, to_ids: Optional[bool] = None) -> list:
        labels = [
            f'misp:category="{misp_object["meta-category"]}"',
            f'misp:name="{misp_object["name"]}"'
        ]
        if to_ids is not None:
            labels.append(f'misp:to_ids="{to_ids}"')
        return labels

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
    #                     OBSERVABLE OBJECT PARSING FUNCTIONS.                     #
    ################################################################################

    def _parse_account_args(self, attributes: list, account_type: str) -> dict:
        attributes = self._extract_multiple_object_attributes(
            attributes,
            force_single=getattr(stix2_mapping, f"{account_type}_account_single_fields")
        )
        account_args = {'account_type': account_type}
        for key, feature in getattr(stix2_mapping, f"{account_type}_account_object_mapping").items():
            if attributes.get(key):
                account_args[feature] = attributes.pop(key)
        if attributes:
            account_args.update(self._handle_observable_multiple_properties(attributes))
        return account_args

    def _parse_AS_args(self, attributes: list) -> dict:
        attributes = self._extract_multiple_object_attributes(
            attributes,
            force_single=stix2_mapping.as_single_fields
        )
        as_args = {'number': self._parse_AS_value(attributes.pop('asn'))}
        if attributes.get('description'):
            as_args['name'] = attributes.pop('description')
        if attributes:
            as_args.update(self._handle_observable_multiple_properties(attributes))
        return as_args

    def _parse_credential_args(self, attributes: list) -> dict:
        attributes = self._extract_multiple_object_attributes(
            attributes,
            force_single=stix2_mapping.credential_single_fields
        )
        credential_args = {}
        if attributes.get('username'):
            credential_args['user_id'] = attributes.pop('username')
        if attributes.get('password'):
            credential_args['credential'] = self._select_single_feature(
                attributes,
                'password'
            )
        if attributes:
            credential_args.update(self._handle_observable_multiple_properties(attributes))
        return credential_args

    def _parse_domain_args(self, attributes: dict) -> dict:
        domain_args = {}
        for feature in ('domain', 'hostname'):
            if attributes.get(feature):
                domain_args['value'] = self._select_single_feature(
                    attributes,
                    feature
                )
                break
        if attributes:
            domain_args.update(self._handle_observable_multiple_properties(attributes))
        return domain_args

    def _parse_email_args(self, attributes: dict) -> dict:
        email_args = {}
        if any(key in attributes for key in stix2_mapping.email_header_fields.keys()):
            header_fields = {}
            for key, feature in stix2_mapping.email_header_fields.items():
                if attributes.get(key):
                    header_fields[feature] = self._select_single_feature(attributes, key)
            email_args['additional_header_fields'] = header_fields
        for feature in ('send-date', 'subject'):
            if attributes.get(feature):
                email_args[stix2_mapping.email_object_mapping[feature]] = self._select_single_feature(
                    attributes,
                    feature
                )
        if attributes:
            email_args.update(self._handle_observable_multiple_properties(attributes))
        return email_args

    def _parse_file_args(self, attributes: dict) -> dict:
        file_args = defaultdict(dict)
        for hash_type in stix2_mapping.file_hash_main_types:
            if attributes.get(hash_type):
                value = self._select_single_feature(attributes, hash_type)
                file_args['hashes'][self._define_hash_type(hash_type)] = value
        for hash_type in stix2_mapping.file_hash_types:
            if attributes.get(hash_type):
                feature = self._define_hash_type(hash_type)
                value = self._select_single_feature(attributes, hash_type)
                if feature not in file_args['hashes']:
                    file_args['hashes'][feature] = value
                else:
                    attributes[hash_type] = [value]
        for key, feature in stix2_mapping.file_object_mapping.items():
            if attributes.get(key):
                value = self._select_single_feature(attributes, key)
                file_args[feature] = value
        if attributes:
            file_args.update(self._handle_observable_multiple_properties(attributes))
        return file_args

    def _parse_ip_port_args(self, attributes: dict) -> dict:
        args = {}
        for key, feature in stix2_mapping.ip_port_object_mapping['features'].items():
            if attributes.get(key):
                args[feature] = self._select_single_feature(attributes, key)
        if attributes:
            args.update(self._handle_observable_multiple_properties(attributes))
        return args

    def _parse_mutex_args(self, attributes: dict) -> dict:
        attributes = self._extract_object_attributes(attributes)
        mutex_args = {}
        if attributes.get('name'):
            mutex_args['name'] = attributes.pop('name')
        if attributes:
            mutex_args.update(self._handle_observable_properties(attributes))
        return mutex_args

    def _parse_network_connection_args(self, attributes: dict) -> dict:
        network_traffic_args = {}
        for key, feature in stix2_mapping.network_connection_mapping['features'].items():
            if attributes.get(key):
                network_traffic_args[feature] = attributes.pop(key)
        protocols = []
        for key in stix2_mapping.network_connection_mapping['protocols']:
            if attributes.get(key):
                protocols.append(attributes.pop(key))
        if not protocols:
            protocols.append('TCP')
        network_traffic_args['protocols'] = protocols
        if attributes:
            network_traffic_args.update(self._handle_observable_properties(attributes))
        return network_traffic_args

    def _parse_network_socket_args(self, attributes: dict) -> dict:
        network_traffic_args = defaultdict(dict)
        for key, feature in stix2_mapping.network_socket_mapping['features'].items():
            if attributes.get(key):
                network_traffic_args[feature] = attributes.pop(key)
        network_traffic_args['protocols'] = [attributes.pop('protocol')] if attributes.get('protocol') else ['tcp']
        if attributes.get('address-family') in stix2_mapping.address_family_enum_list:
            socket_ext = {}
            for key, field in stix2_mapping.network_socket_mapping['extension'].items():
                if attributes.get(key):
                    value = attributes.pop(key)
                    feature = key.replace('-', '_')
                    if value in getattr(stix2_mapping, f"{feature}_enum_list"):
                        socket_ext[field] = value
                    else:
                        network_traffic_args[f'x_misp_{feature}'] = value
            if attributes.get('state'):
                for state in attributes.pop('state'):
                    if state in stix2_mapping.network_socket_state_fields:
                        socket_ext[f'is_{state}'] = True
                    else:
                        attributes['state'].append(state)
            network_traffic_args['extensions']['socket-ext'] = socket_ext
        if attributes:
            network_traffic_args.update(self._handle_observable_multiple_properties(attributes))
        return network_traffic_args

    def _parse_process_args(self, attributes: dict, level: str) -> dict:
        process_args = {}
        for key, feature in stix2_mapping.process_object_mapping[level].items():
            if attributes.get(key):
                process_args[feature] = attributes.pop(key)
        if attributes:
            process_args.update(self._handle_observable_multiple_properties(attributes))
        return process_args

    def _parse_registry_key_args(self, attributes: dict) -> dict:
        attributes = self._extract_object_attributes(attributes)
        if attributes.get('last-modified') and not attributes['last-modified'].endswith('Z'):
            attributes['last-modified'] = f"{attributes.pop('last-modified')}Z"
        registry_key_args = {}
        for key, feature in stix2_mapping.registry_key_mapping['features'].items():
            if attributes.get(key):
                registry_key_args[feature] = attributes.pop(key)
        values_args = {}
        for key, feature in stix2_mapping.registry_key_mapping['values'].items():
            if attributes.get(key):
                values_args[feature] = attributes.pop(key)
        if values_args:
            registry_key_args['values'] = [values_args]
        if attributes:
            registry_key_args.update(self._handle_observable_properties(attributes))
        return registry_key_args

    def _parse_url_args(self, attributes: dict) -> dict:
        attributes = self._extract_object_attributes(attributes)
        url_args = {}
        if attributes.get('url'):
            url_args['value'] = attributes.pop('url')
        if attributes:
            url_args.update(self._handle_observable_properties(attributes))
        return url_args

    def _parse_user_account_args(self, attributes: dict) -> dict:
        attributes = self._extract_multiple_object_attributes(
            attributes,
            force_single=stix2_mapping.user_account_single_fields
        )
        user_account_args = {}
        for key, feature in stix2_mapping.user_account_object_mapping['features'].items():
            if attributes.get(key):
                user_account_args[feature] = attributes.pop(key)
        for key, feature in stix2_mapping.user_account_object_mapping['timeline'].items():
            if attributes.get(key):
                user_account_args[feature] = datetime.strptime(attributes.pop(key), '%Y-%m-%dT%H:%M:%S')
        extension = {}
        for key, feature in stix2_mapping.user_account_object_mapping['extension'].items():
            if attributes.get(key):
                extension[feature] = attributes.pop(key)
        if extension:
            user_account_args['extensions'] = {'unix-account-ext': extension}
        if attributes:
            user_account_args.update(self._handle_observable_multiple_properties(attributes))
        return user_account_args

    def _parse_x509_args(self, attributes: dict) -> dict:
        attributes = self._extract_multiple_object_attributes(
            attributes,
            force_single=stix2_mapping.x509_single_fields
        )
        x509_args = defaultdict(dict)
        if attributes.get('self_signed'):
            x509_args['is_self_signed'] = bool(int(attributes.pop('self_signed')))
        for feature in stix2_mapping.x509_hash_fields:
            if attributes.get(feature):
                hash_type = self._define_hash_type(feature.split('-')[-1])
                x509_args['hashes'][hash_type] = attributes.pop(feature)
        for key, feature in stix2_mapping.x509_object_mapping['features'].items():
            if attributes.get(key):
                x509_args[feature] = attributes.pop(key)
        for key, feature in stix2_mapping.x509_object_mapping['timeline'].items():
            if attributes.get(key):
                x509_args[feature] = datetime.strptime(attributes.pop(key), '%Y-%m-%dT%H:%M:%S')
        extension = []
        for key, feature in stix2_mapping.x509_object_mapping['extension'].items():
            if attributes.get(key):
                for value in attributes.pop(key):
                    extension.append(f"{feature}:{value}")
        if extension:
            name = ','.join(extension)
            x509_args['x509_v3_extensions']['subject_alternative_name'] = name
        if attributes:
            x509_args.update(self._handle_observable_properties(attributes))
        return x509_args

    ################################################################################
    #                         PATTERNS CREATION FUNCTIONS.                         #
    ################################################################################

    def _create_AS_pattern(self, value: str) -> str:
        return f"autonomous-system:number = '{self._parse_AS_value(value)}'"

    @staticmethod
    def _create_content_ref_pattern(value: str, feature: str = 'payload_bin') -> str:
        return f"file:content_ref.{feature} = '{value}'"

    @staticmethod
    def _create_domain_pattern(value: str) -> str:
        return f"domain-name:value = '{value}'"

    @staticmethod
    def _create_domain_resolving_pattern(value: str) -> str:
        return f"domain-name:resolves_to_refs[*].value = '{value}'"

    def _create_filename_hash_pattern(self, hash_type: str, attribute_value: str) -> str:
        filename, hash_value = attribute_value.split('|')
        filename_pattern = self._create_filename_pattern(filename)
        hash_pattern = self._create_hash_pattern(hash_type, hash_value)
        return f"{filename_pattern} AND {hash_pattern}"

    @staticmethod
    def _create_filename_pattern(value: str) -> str:
        return f"file:name = '{value}'"

    def _create_hash_pattern(self, hash_type: str, value: str, prefix: Optional[str]='file:hashes') -> str:
        return f"{prefix}.{self._define_hash_type(hash_type)} = '{value}'"

    def _create_ip_pattern(self, ip_type: str, value: str) -> str:
        address_type = self._define_address_type(value)
        network_type = f"network-traffic:{ip_type}_ref.type = '{address_type}'"
        network_value = f"network-traffic:{ip_type}_ref.value = '{value}'"
        return f"{network_type} AND {network_value}"

    @staticmethod
    def _create_port_pattern(value: str, ip_type: str = 'dst') -> str:
        return f"network-traffic:{ip_type}_port = '{value}'"

    @staticmethod
    def _create_regkey_pattern(value: str) -> str:
        return f"windows-registry-key:key = '{value.strip()}'"

    ################################################################################
    #                              UTILITY FUNCTIONS.                              #
    ################################################################################

    @staticmethod
    def _clean_custom_properties(custom_args: dict):
        stix_labels = ListProperty(StringProperty)
        stix_labels.clean(custom_args['labels'])
        if custom_args.get('markings'):
            stix_markings = ListProperty(StringProperty)
            stix_markings.clean(custom_args['markings'])

    @staticmethod
    def _datetime_from_str(timestamp: str) -> datetime:
        return datetime.strptime(timestamp.split('+')[0], '%Y-%m-%dT%H:%M:%S.%f')

    @staticmethod
    def _define_address_type(address):
        if ':' in address:
            return 'ipv6-addr'
        return 'ipv4-addr'

    @staticmethod
    def _define_hash_type(hash_type: str) -> str:
        if '/' in hash_type:
            return f"SHA{hash_type.split('/')[1]}"
        return hash_type.replace('-', '').upper()

    @staticmethod
    def _fetch_ids_flag(attributes: list) -> bool:
        for attribute in attributes:
            if attribute.get('to_ids'):
                return True
        return False

    def _fetch_included_reference_uuids(self, references: list, name: str) -> list:
        uuids = []
        for reference in references:
            if self._is_reference_included(reference, name):
                referenced_uuid = reference['referenced_uuid']
                if referenced_uuid not in self._objects_to_parse[name]:
                    self._warnings.add(f'Referenced {name} object {referenced_uuid} not correctly handled with objects to parse.')
                    continue
                uuids.append(referenced_uuid)
        return uuids

    @staticmethod
    def _get_vulnerability_references(vulnerability: str) -> dict:
        return {
            'source_name': 'cve',
            'external_id': vulnerability
        }

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

    def _parse_relationships(self, source_id: str, target_ids: list, timestamp: datetime) -> list:
        source_type = source_id.split('--')[0]
        if source_type not in stix2_mapping.relationship_specs:
            self._relationships[source_id].extend((target_id, 'has', timestamp) for target_id in target_ids)
        else:
            for target_id in target_ids:
                target_type = target_id.split('--')[0]
                if target_type in stix2_mapping.relationship_specs[source_type]:
                    relationship_type = stix2_mapping.relationship_specs[source_type][target_type]
                    self._relationships[source_id].append(
                        (
                            target_id,
                            relationship_type,
                            timestamp
                        )
                    )
                    continue
                self._relationships[source_id].append(
                    (
                        target_id,
                        'has',
                        timestamp
                    )
                )

    @staticmethod
    def _is_reference_included(reference: dict, name: str) -> bool:
        return reference['relationship_type'] in ('includes', 'included-in') and reference['Object']['name'] == name

    def _raise_file_and_pe_references_warning(self, file_uuid: str, pe_uuid: list):
        if len(pe_uuid) == 0:
            self._warnings.add(f'Unable to parse the pe object related to the file object {file_uuid}.')
        else:
            self._warnings.add(f'The file object {file_uuid} has more than one reference to pe_objects: {", ".join(pe_uuid)}')
