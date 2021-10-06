#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import re
from .exportparser import MISPtoSTIXParser
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from stix2.properties import ListProperty, StringProperty
from stix2.v20.bundle import Bundle as Bundle_v20
from stix2.v21.bundle import Bundle as Bundle_v21
from typing import Generator, Optional, Tuple, Union
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
    def __init__(self, interoperability: bool):
        super().__init__()
        self.__ids = {}
        self.__interoperability = interoperability
        self._results_handling_function = '_append_SDO'
        self._id_parsing_function = {
            'attribute': '_define_stix_object_id',
            'object': '_define_stix_object_id'
        }

    def parse_json_content(self, filename: str):
        with open(filename, 'rt', encoding='utf-8') as f:
            json_content = json.loads(f.read())
        if json_content.get('response'):
            json_content = json_content['response']
            if isinstance(json_content, list):
                self._events_parsing_init()
                for event in json_content:
                    self._parse_misp_event(event)
                    self.__index = len(self.__objects)
            else:
                self.parse_misp_attributes(json_content)
        else:
            self.parse_misp_event(json_content)

    def parse_misp_attributes(self, attributes: dict):
        if 'Attribute' in attributes:
            attributes = attributes['Attribute']
        self._results_handling_function = '_append_SDO_without_refs'
        if hasattr(self, '_identifier') and self._identifier != 'attributes collection':
            self.__ids = {}
        self._identifier = 'attributes collection'
        self.__objects = []
        self.__relationships = []
        self.__identity_id = self._mapping.misp_identity_args['id']
        if self.__identity_id not in self.__ids:
            identity = self._create_identity(self._mapping.misp_identity_args)
            self.__objects.append(identity)
            self.__ids[self.__identity_id] = self.__identity_id
        for attribute in attributes:
            self._resolve_attribute(attribute)
        if self.__relationships:
            self._handle_relationships()

    def parse_misp_event(self, misp_event: dict):
        self._events_parsing_init()
        self._parse_misp_event(misp_event)

    def _parse_misp_event(self, misp_event: dict):
        if 'Event' in misp_event:
            misp_event = misp_event['Event']
        self._misp_event = misp_event
        self._identifier = self._misp_event['uuid']
        self._markings = {}
        self.__object_refs = []
        self.__relationships = []
        self._set_identity()
        self._parse_event_data()
        report = self._generate_event_report()
        self.__objects.insert(self.__index, report)

    def _define_stix_object_id(self, feature: str, misp_object: dict) -> str:
        return f"{feature}--{misp_object['uuid']}"

    def _events_parsing_init(self):
        self.__index = 0
        self.__objects = []
        if hasattr(self, '_identifier') and self._identifier == 'attributes collection':
            self.__ids = {}
        if not hasattr(self._mapping, 'objects_mapping'):
            self._mapping.declare_objects_mapping()

    @property
    def bundle(self) -> Union[Bundle_v20, Bundle_v21]:
        return self._create_bundle()

    @property
    def identity_id(self) -> str:
        return self.__identity_id

    @property
    def object_refs(self) -> list:
        return self.__object_refs

    def populate_unique_ids(self, unique_ids: dict):
        self.__ids.update(unique_ids)

    @property
    def stix_objects(self) -> list:
        return self.__objects

    @property
    def unique_ids(self) -> list:
        return self.__ids

    ################################################################################
    #                            MAIN PARSING FUNCTIONS                            #
    ################################################################################

    def _append_SDO(self, stix_object):
        self.__objects.append(stix_object)
        self.__object_refs.append(stix_object.id)

    def _append_SDO_without_refs(self, stix_object):
        self.__objects.append(stix_object)

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
            'created_by_ref': self.__identity_id,
            'interoperability': True
        }
        markings = self._handle_event_tags_and_galaxies()
        if markings:
            self._handle_markings(report_args, markings)
        if self.__relationships:
            self._handle_relationships()
        if self._markings:
            for marking in self._markings.values():
                self.__objects.append(marking)
        if self._is_published():
            report_id = f"report--{self._misp_event['uuid']}"
            if not self.__object_refs:
                self._handle_empty_object_refs(report_id, timestamp)
            published = self._datetime_from_timestamp(self._misp_event['publish_timestamp'])
            report_args.update(
                {
                    'id': report_id,
                    'type': 'report',
                    'published': published,
                    'object_refs': self.__object_refs,
                    'allow_custom': True
                }
            )
            return self._create_report(report_args)
        return self._handle_unpublished_report(report_args)

    def _generate_galaxies_catalog(self):
        current_path = Path(os.path.dirname(os.path.realpath(__file__)))
        cti_path = current_path.parent.parent / 'cti'
        self._galaxies_catalog = defaultdict(lambda: defaultdict(list))
        self._identities = {}
        for filename in cti_path.glob('*/*.json'):
            with open(filename, 'rt', encoding='utf-8') as f:
                bundle = json.loads(f.read())
            for stix_object in bundle['objects']:
                if stix_object['type'] == 'identity':
                    object_id = stix_object['id']
                    if object_id not in self.__ids or object_id not in self._identities:
                        self._identities[object_id] = stix_object
                    continue
                if not stix_object.get('name'):
                    continue
                name = stix_object['name']
                object_type = stix_object['type']
                object_id = stix_object['id']
                if object_id not in self._get_object_ids(name, object_type):
                    self._galaxies_catalog[name][object_type].append(stix_object)
                if stix_object.get('external_references'):
                    for reference in stix_object['external_references']:
                        if reference['source_name'] in self._mapping.source_names:
                            external_id = reference['external_id']
                            if object_id not in self._get_object_ids(external_id, object_type):
                                self._galaxies_catalog[external_id][object_type].append(stix_object)
                            break

    def _get_object_ids(self, name: str, object_type: str) -> Generator[None, None, str]:
        return (stix_object['id'] for stix_object in self._galaxies_catalog[name][object_type])

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

    def _handle_relationships(self):
        for relationship in self.__relationships:
            if relationship.get('undefined_target_ref'):
                target_ref = self._find_target_uuid(relationship.pop('undefined_target_ref'))
                if target_ref is None:
                    continue
                relationship['target_ref'] = target_ref
            self._append_SDO(self._create_relationship(relationship))

    def _handle_sightings(self, sightings: list, reference_id: str):
        sightings = self._parse_sightings(sightings)
        if 'sighting' in sightings:
            sighting_args = defaultdict(int)
            sighters_refs = set()
            for sighting in sightings['sighting']:
                sighting_args['count'] += 1
                date_sighting = int(sighting.get('date_sighting', 0))
                if date_sighting < sighting_args.get('first_seen', float('inf')):
                    sighting_args['first_seen'] = date_sighting
                if date_sighting > sighting_args.get('last_seen', 0):
                    sighting_args['last_seen'] = date_sighting
                if sighting.get('Organisation'):
                    sighters_refs.add((sighting['Organisation']['uuid'], sighting['Organisation']['name']))
            sighting_args.update(
                {
                    'first_seen': self._datetime_from_timestamp(sighting_args.pop('first_seen')),
                    'last_seen': self._datetime_from_timestamp(sighting_args.pop('last_seen')),
                    'sighting_of_ref': reference_id,
                    'type': 'sighting',
                    'where_sighted_refs': [self._handle_sighting_identity(*sighter_ref) for sighter_ref in sighters_refs]
                }
            )
            getattr(self, self._results_handling_function)(self._create_sighting(sighting_args))
        if 'opinion' in sightings:
            self._handle_opinion_object(sightings['opinion'], reference_id)

    def _handle_sighting_identity(self, uuid: str, name: str) -> str:
        identity_id = f'identity--{uuid}'
        if identity_id not in self.__ids:
            identity_args = {
                'id': identity_id,
                'name': name,
                'identity_class': 'organization'
            }
            identity = self._create_identity(identity_args)
            self.__objects.insert(self.__index, identity)
            self.__index += 1
            self.__ids[identity_id] = identity_id
        return identity_id

    @staticmethod
    def _parse_sightings(sightings: list) -> dict:
        parsed_sightings = defaultdict(list)
        for sighting in sightings:
            sighting_type = sighting.get('type')
            if sighting_type == '0':
                parsed_sightings['sighting'].append(sighting)
                continue
            if sighting_type == '1':
                if sighting.get('Organisation'):
                    parsed_sightings['opinion'].append(sighting['Organisation']['name'])
        if 'opinion' in parsed_sightings:
            parsed_sightings['opinion'] = set(parsed_sightings.pop('opinion'))
        return parsed_sightings

    ################################################################################
    #                         ATTRIBUTES PARSING FUNCTIONS                         #
    ################################################################################

    def _resolve_attribute(self, attribute: dict):
        attribute_type = attribute['type']
        try:
            if attribute_type in self._mapping.attribute_types_mapping:
                getattr(self, self._mapping.attribute_types_mapping[attribute_type])(attribute)
            else:
                self._parse_custom_attribute(attribute)
                self._attribute_not_mapped_warning(attribute_type)
        except Exception:
            self._attribute_error(attribute)

    def _handle_attribute_indicator(self, attribute: dict, pattern: str):
        indicator_id = getattr(self, self._id_parsing_function['attribute'])('indicator', attribute)
        indicator_args = {
            'id': indicator_id,
            'type': 'indicator',
            'labels': self._create_labels(attribute),
            'kill_chain_phases': self._create_killchain(attribute['category']),
            'created_by_ref': self.__identity_id,
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
        getattr(self, self._results_handling_function)(self._create_indicator(indicator_args))
        if attribute.get('Sighting'):
            self._handle_sightings(attribute['Sighting'], indicator_id)

    def _handle_attribute_observable(self, attribute: dict, observable: Union[dict, list]):
        observable_id = getattr(self, self._id_parsing_function['attribute'])('observed-data', attribute)
        observable_args = {
            'id': observable_id,
            'type': 'observed-data',
            'labels': self._create_labels(attribute),
            'number_observed': 1,
            'created_by_ref': self.__identity_id,
            'allow_custom': True,
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
        if attribute.get('Sighting'):
            self._handle_sightings(attribute['Sighting'], observable_id)

    def _handle_attribute_tags_and_galaxies(self, attribute: dict, object_id: str, timestamp: datetime) -> tuple:
        if attribute.get('Galaxy'):
            tag_names = []
            for galaxy in attribute['Galaxy']:
                galaxy_type = galaxy['type']
                if galaxy_type in self._mapping.galaxy_types_mapping:
                    to_call = self._mapping.galaxy_types_mapping[galaxy_type]
                    getattr(self, to_call.format('attribute'))(galaxy, object_id, timestamp)
                    tag_names.extend(self._quick_fetch_tag_names(galaxy))
                else:
                    self._attribute_galaxy_not_mapped_warning(galaxy_type, attribute['type'])
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
        campaign_id = getattr(self, self._id_parsing_function['attribute'])('campaign', attribute)
        timestamp = self._datetime_from_timestamp(attribute['timestamp'])
        campaign_args = {
            'id': campaign_id,
            'type': 'campaign',
            'name': attribute['value'],
            'created_by_ref': self.__identity_id,
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
        getattr(self, self._results_handling_function)(self._create_campaign(campaign_args))
        if attribute.get('Sighting'):
            self._handle_sightings(attribute['Sighting'], campaign_id)

    def _parse_custom_attribute(self, attribute: dict):
        custom_id = getattr(self, self._id_parsing_function['attribute'])('x-misp-attribute', attribute)
        timestamp = self._datetime_from_timestamp(attribute['timestamp'])
        custom_args = {
            'id': custom_id,
            'created': timestamp,
            'modified': timestamp,
            'labels': self._create_labels(attribute),
            'created_by_ref': self.__identity_id,
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
        getattr(self, self._results_handling_function)(self._create_custom_attribute(custom_args))
        if attribute.get('SIghting'):
            self._handle_sightings(attribute['sighting'], custom_id)

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
            key = self._sanitize_registry_key_value(attribute['value'])
            pattern = f"[{self._create_regkey_pattern(key)}]"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            self._parse_regkey_attribute_observable(attribute)

    def _parse_regkey_value_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            key, value = self._sanitize_registry_key_value(attribute['value']).split('|')
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
        vulnerability_id = getattr(self, self._id_parsing_function['attribute'])('vulnerability', attribute)
        timestamp = self._datetime_from_timestamp(attribute['timestamp'])
        vulnerability_args = {
            'id': vulnerability_id,
            'type': 'vulnerability',
            'name': attribute['value'],
            'external_references': [self._get_vulnerability_references(attribute['value'])],
            'created_by_ref': self.__identity_id,
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
        getattr(self, self._results_handling_function)(self._create_vulnerability(vulnerability_args))
        if attribute.get('Sighting'):
            self._handle_sightings(attribute['sighting'], vulnerability_id)

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
            try:
                object_name = misp_object['name']
                if object_name in self._mapping.objects_mapping:
                    getattr(self, self._mapping.objects_mapping[object_name])(misp_object)
                else:
                    self._parse_custom_object(misp_object)
                    self._object_not_mapped_warning(object_name)
            except Exception:
                self._object_error(misp_object)

    def _resolve_objects_to_parse(self):
        if self._objects_to_parse.get('file'):
            for file_uuid, misp_object in self._objects_to_parse['file'].items():
                file_ids, file_object = misp_object
                pe_uuid = self._fetch_included_reference_uuids(file_object['ObjectReference'], 'pe')
                pe_found = len(pe_uuid)
                if pe_found != 1:
                    if pe_found == 0:
                        self._pe_reference_warning(file_uuid)
                    else:
                        self._unclear_pe_references_warning(file_uuid, pe_uuid)
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
                    ids_list.extend(
                        self._handle_pe_object_reference(
                            pe_object['ObjectReference'],
                            args
                        )
                    )
                if True in ids_list:
                    pattern = self._parse_file_object_pattern(file_object['Attribute'])
                    pattern.extend(self._parse_pe_extensions_pattern(*args))
                    self._handle_object_indicator(file_object, pattern)
                else:
                    file_args, observable = self._parse_file_observable_object(file_object['Attribute'])
                    extension_args, custom = self._parse_pe_extensions_observable(*args)
                    file_args['extensions'] = {
                        'windows-pebinary-ext': extension_args
                    }
                    if 'allow_custom' not in file_args and custom:
                        file_args['allow_custom'] = custom
                    self._handle_file_observable_objects(file_args, observable)
                    self._handle_object_observable(file_object, observable)
        if self._objects_to_parse.get('pe'):
            for pe_uuid, misp_object in self._objects_to_parse['pe'].items():
                try:
                    pe_ids, pe_object = misp_object
                except TypeError:
                    continue
                args = [pe_uuid]
                ids_list = [pe_ids]
                if pe_object.get('ObjectReference'):
                    ids_list.extend(
                        self._handle_pe_object_reference(
                            pe_object['ObjectReference'],
                            args
                        )
                    )
                if True in ids_list:
                    pattern = self._parse_pe_extensions_pattern(*args)
                    self._handle_object_indicator(pe_object, pattern)
                else:
                    extension_args, custom = self._parse_pe_extensions_observable(*args)
                    file_args = {
                        'extensions': {
                            'windows-pebinary-ext': extension_args
                        }
                    }
                    if custom:
                        file_args['allow_custom'] = custom
                    for feature in ('original', 'internal'):
                        if extension_args.get(f'x_misp_{feature}_filename'):
                            file_args['name'] = extension_args[f'x_misp_{feature}_filename']
                            break
                    else:
                        file_args['name'] = ''
                    observable = self._handle_file_observable_object(file_args)
                    self._handle_object_observable(pe_object, observable)

    def _handle_object_indicator(self, misp_object: dict, pattern: list):
        indicator_id = getattr(self, self._id_parsing_function['object'])('indicator', misp_object)
        indicator_args = {
            'id': indicator_id,
            'type': 'indicator',
            'labels': self._create_object_labels(misp_object, to_ids=True),
            'kill_chain_phases': self._create_killchain(misp_object['meta-category']),
            'created_by_ref': self.__identity_id,
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
        if misp_object.get('ObjectReference'):
            self._parse_object_relationships(
                misp_object['ObjectReference'],
                indicator_id,
                indicator_args['modified']
            )
        self._append_SDO(self._create_indicator(indicator_args))

    def _handle_object_observable(self, misp_object: dict, observable: Union[dict, list]):
        observable_id = getattr(self, self._id_parsing_function['object'])('observed-data', misp_object)
        observable_args = {
            'id': observable_id,
            'type': 'observed-data',
            'labels': self._create_object_labels(misp_object, to_ids=False),
            'number_observed': 1,
            'created_by_ref': self.__identity_id,
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
        if misp_object.get('ObjectReference'):
            self._parse_object_relationships(
                misp_object['ObjectReference'],
                observable_id,
                observable_args['modified']
            )
        self._create_observed_data(observable_args, observable)

    def _handle_object_tags_and_galaxies(self, misp_object: dict, object_id: str, timestamp: datetime) -> tuple:
        tags, galaxies = self._extract_object_attribute_tags_and_galaxies(misp_object)
        if galaxies:
            tag_names = set()
            for galaxy_type, galaxy in galaxies.items():
                if galaxy_type in self._mapping.galaxy_types_mapping:
                    to_call = self._mapping.galaxy_types_mapping[galaxy_type]
                    getattr(self, to_call.format('attribute'))(galaxy, object_id, timestamp)
                    tag_names.update(self._quick_fetch_tag_names(galaxy))
                else:
                    self._object_galaxy_not_mapped_warning(galaxy_type, misp_object['name'])
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

    def _handle_parent_process_properties(self, attributes: dict) -> dict:
        parent_attributes = {'_'.join(key.split('-')[1:]): values for key, values in attributes.items()}
        return self._handle_observable_multiple_properties(parent_attributes)

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

    def _handle_pe_object_reference(self, references: dict, args: list) -> list:
        ids_list = []
        section_uuids = self._fetch_included_reference_uuids(
            references,
            'pe-section'
        )
        if section_uuids:
            for section_uuid in section_uuids:
                section_ids, _ = self._objects_to_parse['pe-section'][section_uuid]
                ids_list.append(section_ids)
            args.append(section_uuids)
        return ids_list

    def _parse_account_object(self, misp_object: dict):
        account_type = misp_object['name'].split('-')[0]
        if self._fetch_ids_flag(misp_object['Attribute']):
            prefix = 'user-account'
            attributes = self._extract_multiple_object_attributes(
                misp_object['Attribute'],
                force_single=getattr(self._mapping, f"{account_type}_account_single_fields")
            )
            pattern = [f"{prefix}:account_type = '{account_type}'"]
            for key, feature in getattr(self._mapping, f"{account_type}_account_object_mapping").items():
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
                force_single=self._mapping.as_single_fields
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
            force_single=self._mapping.attack_pattern_single_fields
        )
        prefix = 'attack-pattern'
        attack_pattern_id = getattr(self, self._id_parsing_function['object'])(prefix, misp_object)
        timestamp = self._datetime_from_timestamp(misp_object['timestamp'])
        attack_pattern_args = defaultdict(list)
        for key, feature in self._mapping.attack_pattern_object_mapping.items():
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
                'created_by_ref': self.__identity_id,
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
        if misp_object.get('ObjectReference'):
            self._parse_object_relationships(
                misp_object['ObjectReference'],
                attack_pattern_id,
                timestamp
            )
        self._append_SDO(self._create_attack_pattern(attack_pattern_args))

    def _parse_attack_pattern_reference(self, feature: str, value: str) -> dict:
        source_name, key = self._mapping.attack_pattern_reference_mapping[feature]
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
        course_of_action_id = getattr(self, self._id_parsing_function['object'])(prefix, misp_object)
        timestamp = self._datetime_from_timestamp(misp_object['timestamp'])
        course_of_action_args = {
            'id': course_of_action_id,
            'type': prefix,
            'created_by_ref': self.__identity_id,
            'labels': self._create_object_labels(misp_object),
            'created': timestamp,
            'modified': timestamp,
            'interoperability': True
        }
        for feature in self._mapping.course_of_action_object_mapping:
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
        if misp_object.get('ObjectReference'):
            self._parse_object_relationships(
                misp_object['ObjectReference'],
                course_of_action_id,
                timestamp
            )
        self._append_SDO(self._create_course_of_action(course_of_action_args))

    def _parse_credential_object(self, misp_object: dict):
        if self._fetch_ids_flag(misp_object['Attribute']):
            attributes = self._extract_multiple_object_attributes(
                misp_object['Attribute'],
                force_single=self._mapping.credential_single_fields
            )
            pattern = self._create_credential_pattern(attributes)
            if attributes:
                pattern.extend(
                    self._handle_pattern_multiple_properties(
                        attributes,
                        'user-account'
                    )
                )
            self._handle_object_indicator(misp_object, pattern)
        else:
            self._parse_credential_object_observable(misp_object)

    @staticmethod
    def _parse_custom_attachment(attachment: Union[str, tuple]) -> dict:
        if isinstance(attachment, tuple):
            attachment = {
                'value': attachment[0],
                'data': attachment[1]
            }
        return {
            'allow_custom': True,
            'x_misp_attachment': attachment
        }

    def _parse_custom_object(self, misp_object: dict):
        custom_id = getattr(self, self._id_parsing_function['object'])('x-misp-object', misp_object)
        timestamp = self._datetime_from_timestamp(misp_object['timestamp'])
        custom_args = {
            'id': custom_id,
            'created': timestamp,
            'modified': timestamp,
            'labels': self._create_object_labels(misp_object),
            'created_by_ref': self.__identity_id,
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
        if misp_object.get('ObjectReference'):
            self._parse_object_relationships(
                misp_object['ObjectReference'],
                custom_id,
                timestamp
            )
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
            for key, feature in self._mapping.domain_ip_object_mapping.items():
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
                with_data=self._mapping.email_data_fields
            )
            pattern = []
            for key, feature in self._mapping.email_object_mapping.items():
                if attributes.get(key):
                    for value in attributes.pop(key):
                        pattern.append(f"{prefix}:{feature} = '{value}'")
            if attributes:
                n = 0
                for key in self._mapping.email_data_fields:
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

    def _parse_file_object_observable(self, misp_object: dict):
        file_args, observable_objects = self._parse_file_observable_object(misp_object['Attribute'])
        self._handle_file_observable_objects(file_args, observable_objects)
        self._handle_object_observable(misp_object, observable_objects)

    def _parse_file_object_pattern(self, attributes: list) -> list:
        prefix = 'file'
        attributes = self._extract_multiple_object_attributes_with_data(
            attributes,
            force_single=self._mapping.file_single_fields,
            with_data=self._mapping.file_data_fields
        )
        pattern = []
        for hash_type in self._mapping.hash_attribute_types:
            if attributes.get(hash_type):
                pattern.append(
                    self._create_hash_pattern(
                        hash_type,
                        attributes.pop(hash_type)
                    )
                )
        for key, feature in self._mapping.file_object_mapping.items():
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
            for key, pattern in self._mapping.ip_port_object_mapping['ip_features'].items():
                if attributes.get(key):
                    for ip_value in attributes.pop(key):
                        identifier = pattern.format(self._define_address_type(ip_value))
                        patterns.append(f"({prefix}:{identifier} = '{ip_value}')")
            for key, pattern in self._mapping.ip_port_object_mapping['domain_features'].items():
                if attributes.get(key):
                    for domain_value in attributes.pop(key):
                        patterns.append(f"({prefix}:{pattern} = '{domain_value}')")
            for key, feature in self._mapping.ip_port_object_mapping['features'].items():
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
            for key, feature in self._mapping.network_connection_mapping['features'].items():
                if attributes.get(key):
                    pattern.append(f"{prefix}:{feature} = '{attributes.pop(key)}'")
            index = 0
            for key in self._mapping.network_connection_mapping['protocols']:
                if attributes.get(key):
                    pattern.append(f"{prefix}:protocols[{index}] = '{attributes.pop(key).lower()}'")
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
        for key, feature in self._mapping.network_socket_mapping['features'].items():
            if attributes.get(key):
                pattern.append(f"{prefix}:{feature} = '{attributes.pop(key)}'")
        if attributes.get('protocol'):
            pattern.append(f"{prefix}:protocols[0] = '{attributes.pop('protocol').lower()}'")
        prefix = f"{prefix}:extensions.'socket-ext'"
        for key, feature in self._mapping.network_socket_mapping['extension'].items():
            if attributes.get(key):
                pattern.append(f"{prefix}.{feature} = '{attributes.pop(key)}'")
        if attributes.get('state'):
            for state in attributes.pop('state'):
                if state in self._mapping.network_socket_state_fields:
                    pattern.append(f"{prefix}.is_{state} = true")
                else:
                    attributes['state'].append(state)
        if attributes:
            pattern.extend(
                self._handle_pattern_multiple_properties(attributes, 'network-traffic')
            )
        return pattern

    def _parse_pe_extensions_observable(self, pe_uuid: str, uuids: Optional[list]=None) -> dict:
        custom = False
        attributes = self._extract_multiple_object_attributes(
            self._select_pe_object(pe_uuid)['Attribute'],
            force_single=self._mapping.pe_object_single_fields
        )
        extension = defaultdict(list)
        for key, feature in self._mapping.pe_object_mapping['features'].items():
            if attributes.get(key):
                extension[feature] = attributes.pop(key)
        optional_header = {}
        for key, feature in self._mapping.pe_object_mapping['header'].items():
            if attributes.get(key):
                optional_header[feature] = attributes.pop(key)
        if optional_header:
            extension['optional_header'] = optional_header
        if attributes:
            custom = True
            extension.update(self._handle_observable_multiple_properties(attributes))
        if uuids is not None:
            for section_uuid in uuids:
                section = defaultdict(dict)
                attributes = self._extract_object_attributes(
                    self._objects_to_parse['pe-section'][section_uuid][1]['Attribute']
                )
                for key, feature in self._mapping.pe_section_mapping.items():
                    if attributes.get(key):
                        section[feature] = attributes.pop(key)
                for hash_type in self._mapping.file_hash_main_types:
                    if attributes.get(hash_type):
                        value = self._select_single_feature(attributes, hash_type)
                        section['hashes'][self._define_hash_type(hash_type)] = value
                if attributes:
                    custom = True
                    section.update(self._handle_observable_properties(attributes))
                extension['sections'].append(self._create_windowsPESection(section))
        return self._create_PE_extension(extension), custom

    def _parse_pe_extensions_pattern(self, pe_uuid: str, uuids: Optional[list]=None) -> list:
        prefix = "file:extensions.'windows-pebinary-ext'"
        attributes = self._extract_multiple_object_attributes(
            self._select_pe_object(pe_uuid)['Attribute'],
            force_single=self._mapping.pe_object_single_fields
        )
        pattern = []
        for key, feature in self._mapping.pe_object_mapping['features'].items():
            if attributes.get(key):
                pattern.append(f"{prefix}.{feature} = '{attributes.pop(key)}'")
        for key, feature in self._mapping.pe_object_mapping['header'].items():
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
                for key, feature in self._mapping.pe_section_mapping.items():
                    if attributes.get(key):
                        pattern.append(f"{section_prefix}.{feature} = '{attributes.pop(key)}'")
                for hash_type in self._mapping.hash_attribute_types:
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
        for key, feature in self._mapping.process_object_mapping['features'].items():
            if attributes.get(key):
                pattern.append(f"{prefix}:{feature} = '{attributes.pop(key)}'")
        if attributes.get('image'):
            pattern.append(self._create_process_image_pattern(attributes.pop('image')))
        parent_attributes = self._extract_parent_process_attributes(attributes)
        for key, feature in self._mapping.process_object_mapping['parent'].items():
            if parent_attributes.get(key):
                pattern.append(f"{prefix}:parent_ref.{feature} = '{parent_attributes.pop(key)}'")
        if parent_attributes:
            parent_attributes = {'_'.join(key.split('-')[1:]): values for key, values in parent_attributes.items()}
            pattern.extend(self._handle_pattern_multiple_properties(parent_attributes, prefix, separator=':parent_ref.'))
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
            for key, feature in self._mapping.registry_key_mapping['features'].items():
                if attributes.get(key):
                    value = self._sanitize_registry_key_value(attributes.pop(key))
                    pattern.append(f"{prefix}:{feature} = '{value}'")
            values_prefix = f"{prefix}:values[0]"
            for key, feature in self._mapping.registry_key_mapping['values'].items():
                if attributes.get(key):
                    value = self._sanitize_registry_key_value(attributes.pop(key))
                    pattern.append(f"{values_prefix}.{feature} = '{value}'")
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
                force_single=self._mapping.user_account_single_fields
            )
            pattern = []
            for data_type in ('features', 'timeline'):
                for key, feature in self._mapping.user_account_object_mapping[data_type].items():
                    if attributes.get(key):
                        pattern.append(f"{prefix}:{feature} = '{attributes.pop(key)}'")
            extension_prefix = f"{prefix}:extensions.'unix-account-ext'"
            for key, feature in self._mapping.user_account_object_mapping['extension'].items():
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
        vulnerability_id = getattr(self, self._id_parsing_function['object'])('vulnerability', misp_object)
        vulnerability_args = defaultdict(list)
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
        vulnerability_args.update(
            self._handle_vulnerability_time_fields(
                attributes,
                misp_object['timestamp']
            )
        )
        if attributes:
            vulnerability_args.update(self._handle_observable_multiple_properties(attributes))
        vulnerability_args.update(
            {
                'id': vulnerability_id,
                'type': 'vulnerability',
                'labels': self._create_object_labels(misp_object),
                'created_by_ref': self.__identity_id,
                'interoperability': True
            }
        )
        markings = self._handle_object_tags_and_galaxies(
            misp_object,
            vulnerability_id,
            vulnerability_args['modified']
        )
        if markings:
            self._handle_markings(indicator_args, markings)
        if misp_object.get('ObjectReference'):
            self._parse_object_relationships(
                misp_object['ObjectReference'],
                vulnerability_id,
                vulnerability_args['modified']
            )
        self._append_SDO(self._create_vulnerability(vulnerability_args))

    def _parse_x509_object(self, misp_object: dict):
        if self._fetch_ids_flag(misp_object['Attribute']):
            prefix = 'x509-certificate'
            attributes = self._extract_multiple_object_attributes(
                misp_object['Attribute'],
                force_single=self._mapping.x509_single_fields
            )
            pattern = []
            if attributes.get('self_signed'):
                self_signed = 'true' if bool(int(attributes.pop('self_signed'))) else 'false'
                pattern.append(f"{prefix}:is_self_signed = '{self_signed}'")
            for feature in self._mapping.x509_hash_fields:
                if attributes.get(feature):
                    hash_type = self._define_hash_type(feature.split('-')[-1])
                    pattern.append(f"{prefix}:hashes.{hash_type} = '{attributes.pop(feature)}'")
            for data_type in ('features', 'timeline'):
                for key, feature in self._mapping.x509_object_mapping[data_type].items():
                    if attributes.get(key):
                        pattern.append(f"{prefix}:{feature} = '{attributes.pop(key)}'")
            extension = []
            for key, feature in self._mapping.x509_object_mapping['extension'].items():
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

    def _check_external_references(self, references: list, values: list, feature: str) -> bool:
        for reference in references:
            if reference['source_name'] in self._mapping.source_names and reference[feature] in values:
                return True
        return False

    def _check_galaxy_matching(self, cluster: dict, *args: Tuple[str, str]) -> Union[str, None]:
        if self._check_galaxy_name(*args):
            return self._fetch_galaxy_matching_by_name(cluster, *args)
        if cluster.get('meta'):
            meta = cluster['meta']
            feature = 'external_id'
            if meta.get(feature) and self._check_galaxy_references(meta[feature], feature, *args):
                return self._fetch_galaxy_matching_by_reference(meta[feature], feature, *args)
            if meta.get('refs') and self._check_galaxy_references(meta['refs'], 'url', *args):
                return self._fetch_galaxy_matching_by_reference(meta['refs'], 'url', *args)

    def _check_galaxy_name(self, name: str, object_type: str) -> bool:
        names = 0
        for stix_object in self._galaxies_catalog[name][object_type]:
            if stix_object['name'] == name:
                names += 1
        return names == 1

    def _check_galaxy_references(self, values: str, feature: str, name: str, object_type: str) -> bool:
        numbers = 0
        for stix_object in self._galaxies_catalog[name][object_type]:
            if stix_object['name'] != name or not stix_object.get('external_references'):
                continue
            if self._check_external_references(stix_object['external_references'], values, feature):
                numbers += 1
        return numbers == 1

    def _define_source_name(self, value: str) -> str:
        for prefix, source_name in self._mapping.external_id_to_source_name.items():
            if value.startswith(f'{prefix}-'):
                return source_name
        if '-' in value:
            return 'NIST Mobile Threat Catalogue'
        if value.isnumeric():
            return 'WASC'
        return 'mitre-attack'

    def _fetch_galaxy_matching_by_name(self, cluster: dict, name: str, object_type: str) -> Union[str, None]:
        for stix_object in self._galaxies_catalog[name][object_type]:
            if stix_object['name'] == name:
                self._handle_galaxy_matching(object_type, stix_object)
                return stix_object['id']

    def _fetch_galaxy_matching_by_reference(self, values: list, feature: str, name: str, object_type: str) -> Union[str, None]:
        for stix_object in self._galaxies_catalog[name][object_type]:
            if stix_object['name'] != name or not stix_object.get('external_references'):
                continue
            if self._check_external_references(stix_object['external_references'], values, feature):
                self._handle_galaxy_matching(object_type, stix_object)
                return stix_object['id']

    def _handle_attribute_galaxy_relationships(self, source_id: str, target_ids: list, timestamp: datetime):
        source_type = source_id.split('--')[0]
        if source_type not in self._mapping.relationship_specs:
            for target_id in target_ids:
                self._parse_galaxy_relationship(source_id, target_id, 'has', timestamp)
        else:
            for target_id in target_ids:
                target_type = target_id.split('--')[0]
                if target_type in self._mapping.relationship_specs[source_type]:
                    self._parse_galaxy_relationship(
                        source_id,
                        target_id,
                        self._mapping.relationship_specs[source_type][target_type],
                        timestamp
                    )
                    continue
                self._parse_galaxy_relationship(source_id, target_id, 'has', timestamp)
        self._handle_object_refs(target_ids)

    def _handle_external_references(self, values: list) -> list:
        references = []
        for value in values:
            external_id = {
                'source_name': self._define_source_name(value),
                'external_id': value
            }
            references.append(external_id)
        return references

    def _handle_galaxy_matching(self, object_type: str, stix_object: dict):
        identity_id = stix_object['created_by_ref']
        if identity_id not in self.__ids:
            identity = self._create_identity(self._identities[identity_id])
            self.__objects.insert(0, identity)
            self.__index += 1
            self.__ids[identity_id] = identity_id
        stix_object['allow_custom'] = True
        self.__objects.append(getattr(self, f"_create_{object_type.replace('-', '_')}")(stix_object))

    def _handle_object_refs(self, object_refs: list):
        for object_ref in object_refs:
            if object_ref not in self.__object_refs:
                self.__object_refs.append(object_ref)

    def _is_galaxy_parsed(self, object_refs: list, cluster: dict) -> bool:
        object_id = cluster['uuid']
        if object_id in self.__ids:
            object_refs.append(self.__ids[object_id])
            return True
        if self.__interoperability:
            object_type = self._mapping.cluster_to_stix_object[cluster['type']]
            value = cluster['value']
            try:
                in_catalog = value in self._galaxies_catalog
            except AttributeError:
                self._generate_galaxies_catalog()
                in_catalog = value in self._galaxies_catalog
            if in_catalog:
                if object_type in self._galaxies_catalog[value]:
                    args = (value, object_type)
                    stix_object_id = self._check_galaxy_matching(cluster, *args)
                    if stix_object_id is not None:
                        object_refs.append(stix_object_id)
                        self.__ids[object_id] = stix_object_id
                        return True
                return False
            if ' - ' in value:
                for part in value.split(' - '):
                    if part in self._galaxies_catalog and object_type in self._galaxies_catalog[part]:
                        args = (part, object_type)
                        stix_object_id = self._check_galaxy_matching(cluster, *args)
                        if stix_object_id is not None:
                            object_refs.append(stix_object_id)
                            self.__ids[object_id] = stix_object_id
                            return True
        return False

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
            if self._is_galaxy_parsed(object_refs, cluster):
                continue
            attack_pattern_id = f"attack-pattern--{cluster['uuid']}"
            attack_pattern_args = self._create_galaxy_args(
                cluster,
                galaxy['description'],
                galaxy['name'],
                attack_pattern_id,
                timestamp
            )
            if cluster.get('meta', {}).get('external_id'):
                references = self._handle_external_references(cluster['meta']['external_id'])
                attack_pattern_args['external_references'] = references
            self.__objects.append(
                self._create_attack_pattern_from_galaxy(
                    attack_pattern_args,
                    cluster
                )
            )
            object_refs.append(attack_pattern_id)
            self.__ids[cluster['uuid']] = attack_pattern_id
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
            if self._is_galaxy_parsed(object_refs, cluster):
                continue
            course_of_action_id = f"course-of-action--{cluster['uuid']}"
            course_of_action_args = self._create_galaxy_args(
                cluster,
                galaxy['description'],
                galaxy['name'],
                course_of_action_id,
                timestamp
            )
            if cluster.get('meta', {}).get('external_id'):
                references = self._handle_external_references(cluster['meta']['external_id'])
                course_of_action_args['external_references'] = references
            course_of_action = self._create_course_of_action(course_of_action_args)
            self.__objects.append(course_of_action)
            object_refs.append(course_of_action_id)
            self.__ids[cluster['uuid']] = course_of_action_id
        return object_refs

    def _parse_intrusion_set_attribute_galaxy(self, galaxy: dict, object_id: str, timestamp: datetime):
        object_refs = self._parse_intrusion_set_galaxy(galaxy, timestamp)
        self._handle_attribute_galaxy_relationships(object_id, object_refs, timestamp)

    def _parse_intrusion_set_event_galaxy(self, galaxy: dict):
        timestamp = self._datetime_from_timestamp(self._misp_event['timestamp'])
        object_refs = self._parse_intrusion_set_galaxy(galaxy, timestamp)
        self._handle_object_refs(object_refs)

    def _parse_intrusion_set_galaxy(self, galaxy: dict, timestamp: datetime) -> list:
        object_refs = []
        for cluster in galaxy['GalaxyCluster']:
            if self._is_galaxy_parsed(object_refs, cluster):
                continue
            intrusion_set_id = f"intrusion-set--{cluster['uuid']}"
            intrusion_set_args = self._create_galaxy_args(
                cluster,
                galaxy['description'],
                galaxy['name'],
                intrusion_set_id,
                timestamp
            )
            if cluster.get('meta', {}).get('external_id'):
                references = self._handle_external_references(cluster['meta']['external_id'])
                intrusion_set_args['external_references'] = references
            if cluster.get('meta', {}).get('synonyms'):
                intrusion_set_args['aliases'] = cluster['meta']['synonyms']
            intrusion_set = self._create_intrusion_set(intrusion_set_args)
            self.__objects.append(intrusion_set)
            object_refs.append(intrusion_set_id)
            self.__ids[cluster['uuid']] = intrusion_set_id
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
            if self._is_galaxy_parsed(object_refs, cluster):
                continue
            malware_id = f"malware--{cluster['uuid']}"
            malware_args = self._create_galaxy_args(
                cluster,
                galaxy['description'],
                galaxy['name'],
                malware_id,
                timestamp
            )
            if cluster.get('meta', {}).get('external_id'):
                references = self._handle_external_references(cluster['meta']['external_id'])
                malware_args['external_references'] = references
            malware = self._create_malware(malware_args, cluster=cluster)
            self.__objects.append(malware)
            object_refs.append(malware_id)
            self.__ids[cluster['uuid']] = malware_id
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
            if self._is_galaxy_parsed(object_refs, cluster):
                continue
            threat_actor_id = f"threat-actor--{cluster['uuid']}"
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
            self.__objects.append(threat_actor)
            object_refs.append(threat_actor_id)
            self.__ids[cluster['uuid']] = threat_actor_id
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
            if self._is_galaxy_parsed(object_refs, cluster):
                continue
            tool_id = f"tool--{cluster['uuid']}"
            tool_args = self._create_galaxy_args(
                cluster,
                galaxy['description'],
                galaxy['name'],
                tool_id,
                timestamp
            )
            if cluster.get('meta', {}).get('external_id'):
                references = self._handle_external_references(cluster['meta']['external_id'])
                tool_args['external_references'] = references
            tool = self._create_tool(tool_args, cluster=cluster)
            self.__objects.append(tool)
            object_refs.append(tool_id)
            self.__ids[cluster['uuid']] = tool_id
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
            if self._is_galaxy_parsed(object_refs, cluster):
                continue
            vulnerability_id = f"vulnerability--{cluster['uuid']}"
            vulnerability_args = self._create_galaxy_args(
                cluster,
                galaxy['description'],
                galaxy['name'],
                vulnerability_id,
                timestamp
            )
            if cluster.get('meta', {}).get('aliases'):
                references = self._handle_external_references(cluster['meta']['aliases'])
                vulnerability_args['external_references'] = references
            vulnerability = self._create_vulnerability(vulnerability_args)
            self.__objects.append(vulnerability)
            object_refs.append(vulnerability_id)
            self.__ids[cluster['uuid']] = vulnerability_id
        return object_refs

    ################################################################################
    #                    STIX OBJECTS CREATION HELPER FUNCTIONS                    #
    ################################################################################

    @staticmethod
    def _create_attachment_args(value: str, data: str) -> dict:
        return {
            'allow_custom': True,
            'payload_bin': data,
            'x_misp_filename': value
        }

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
    def _create_malware_sample_args(value: str, data: str) -> dict:
        filename, md5 = value.split('|')
        return {
            'allow_custom': True,
            'hashes': {
                'MD5': md5
            },
            'payload_bin': data,
            'x_misp_filename': filename
        }

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
        orgc_id = orgc['uuid']
        self.__identity_id = f"identity--{orgc_id}"
        if orgc_id not in self.__ids:
            self.__ids[orgc_id] = self.__identity_id
            identity = self._create_identity_object(orgc['name'])
            self.__objects.append(identity)
            self.__index += 1

    ################################################################################
    #                     OBSERVABLE OBJECT PARSING FUNCTIONS.                     #
    ################################################################################

    def _parse_account_args(self, attributes: list, account_type: str) -> dict:
        attributes = self._extract_multiple_object_attributes(
            attributes,
            force_single=getattr(self._mapping, f"{account_type}_account_single_fields")
        )
        account_args = {'account_type': account_type}
        for key, feature in getattr(self._mapping, f"{account_type}_account_object_mapping").items():
            if attributes.get(key):
                account_args[feature] = attributes.pop(key)
        if attributes:
            account_args.update(self._handle_observable_multiple_properties(attributes))
        return account_args

    def _parse_AS_args(self, attributes: list) -> dict:
        attributes = self._extract_multiple_object_attributes(
            attributes,
            force_single=self._mapping.as_single_fields
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
            force_single=self._mapping.credential_single_fields
        )
        credential_args = {}
        for key, feature in self._mapping.credential_object_mapping.items():
            if attributes.get(key):
                credential_args[feature] = self._select_single_feature(attributes, key)
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
            domain_args.update(self._handle_observable_properties(attributes))
        return domain_args

    def _parse_email_args(self, attributes: dict) -> dict:
        email_args = {}
        if any(key in attributes for key in self._mapping.email_header_fields.keys()):
            header_fields = {}
            for key, feature in self._mapping.email_header_fields.items():
                if attributes.get(key):
                    header_fields[feature] = self._select_single_feature(attributes, key)
            email_args['additional_header_fields'] = header_fields
        for feature in ('mesage-id', 'send-date', 'subject'):
            if attributes.get(feature):
                email_args[self._mapping.email_object_mapping[feature]] = self._select_single_feature(
                    attributes,
                    feature
                )
        if attributes:
            email_args.update(self._handle_observable_multiple_properties(attributes))
        return email_args

    def _parse_file_args(self, attributes: dict) -> dict:
        file_args = defaultdict(dict)
        for hash_type in self._mapping.file_hash_main_types:
            if attributes.get(hash_type):
                value = self._select_single_feature(attributes, hash_type)
                file_args['hashes'][self._define_hash_type(hash_type)] = value
        for hash_type in self._mapping.file_hash_types:
            if attributes.get(hash_type):
                feature = self._define_hash_type(hash_type)
                value = self._select_single_feature(attributes, hash_type)
                if feature not in file_args['hashes']:
                    file_args['hashes'][feature] = value
                else:
                    attributes[hash_type] = [value]
        for key, feature in self._mapping.file_object_mapping.items():
            if attributes.get(key):
                value = self._select_single_feature(attributes, key)
                file_args[feature] = value
        if attributes:
            file_args.update(self._handle_observable_multiple_properties(attributes))
        return file_args

    def _parse_ip_port_args(self, attributes: dict) -> dict:
        args = {}
        for key, feature in self._mapping.ip_port_object_mapping['features'].items():
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
        for key, feature in self._mapping.network_connection_mapping['features'].items():
            if attributes.get(key):
                network_traffic_args[feature] = attributes.pop(key)
        protocols = []
        for key in self._mapping.network_connection_mapping['protocols']:
            if attributes.get(key):
                protocols.append(attributes.pop(key).lower())
        if not protocols:
            protocols.append('tcp')
        network_traffic_args['protocols'] = protocols
        if attributes:
            network_traffic_args.update(self._handle_observable_properties(attributes))
        return network_traffic_args

    def _parse_network_socket_args(self, attributes: dict) -> dict:
        network_traffic_args = defaultdict(dict)
        for key, feature in self._mapping.network_socket_mapping['features'].items():
            if attributes.get(key):
                network_traffic_args[feature] = attributes.pop(key)
        network_traffic_args['protocols'] = [attributes.pop('protocol').lower()] if attributes.get('protocol') else ['tcp']
        if attributes.get('address-family') in self._mapping.address_family_enum_list:
            socket_ext = {}
            for key, field in self._mapping.network_socket_mapping['extension'].items():
                if attributes.get(key):
                    value = attributes.pop(key)
                    feature = key.replace('-', '_')
                    if value in getattr(self._mapping, f"{feature}_enum_list"):
                        socket_ext[field] = value
                    else:
                        network_traffic_args[f'x_misp_{feature}'] = value
            if attributes.get('state'):
                for state in attributes.pop('state'):
                    if state in self._mapping.network_socket_state_fields:
                        socket_ext[f'is_{state}'] = True
                    else:
                        attributes['state'].append(state)
            network_traffic_args['extensions']['socket-ext'] = socket_ext
        if attributes:
            network_traffic_args.update(self._handle_observable_multiple_properties(attributes))
        return network_traffic_args

    def _parse_process_args(self, attributes: dict, level: str) -> dict:
        process_args = {}
        for key, feature in self._mapping.process_object_mapping[level].items():
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
        for key, feature in self._mapping.registry_key_mapping['features'].items():
            if attributes.get(key):
                registry_key_args[feature] = attributes.pop(key)
        values_args = {}
        for key, feature in self._mapping.registry_key_mapping['values'].items():
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
            force_single=self._mapping.user_account_single_fields
        )
        user_account_args = {}
        for key, feature in self._mapping.user_account_object_mapping['features'].items():
            if attributes.get(key):
                user_account_args[feature] = attributes.pop(key)
        for key, feature in self._mapping.user_account_object_mapping['timeline'].items():
            if attributes.get(key):
                user_account_args[feature] = datetime.strptime(attributes.pop(key), '%Y-%m-%dT%H:%M:%S')
        extension = {}
        for key, feature in self._mapping.user_account_object_mapping['extension'].items():
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
            force_single=self._mapping.x509_single_fields
        )
        x509_args = defaultdict(dict)
        if attributes.get('self_signed'):
            x509_args['is_self_signed'] = bool(int(attributes.pop('self_signed')))
        for feature in self._mapping.x509_hash_fields:
            if attributes.get(feature):
                hash_type = self._define_hash_type(feature.split('-')[-1])
                x509_args['hashes'][hash_type] = attributes.pop(feature)
        for key, feature in self._mapping.x509_object_mapping['features'].items():
            if attributes.get(key):
                x509_args[feature] = attributes.pop(key)
        for key, feature in self._mapping.x509_object_mapping['timeline'].items():
            if attributes.get(key):
                x509_args[feature] = datetime.strptime(attributes.pop(key), '%Y-%m-%dT%H:%M:%S')
        extension = []
        for key, feature in self._mapping.x509_object_mapping['extension'].items():
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
        stix_labels.clean(custom_args['labels'], True)
        if custom_args.get('markings'):
            stix_markings = ListProperty(StringProperty)
            stix_markings.clean(custom_args['markings'])

    @staticmethod
    def _datetime_from_str(timestamp: str) -> datetime:
        regex = '%Y-%m-%dT%H:%M:%S'
        if '.' in timestamp:
            regex = f'{regex}.%f'
        return datetime.strptime(timestamp.split('+')[0], regex)

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
    def _extract_parent_process_attributes(attributes: dict) -> dict:
        parent_fields = tuple(key for key in attributes.keys() if key.startswith('parent-'))
        return {key: attributes.pop(key) for key in parent_fields}

    def _fetch_included_reference_uuids(self, references: list, name: str) -> list:
        uuids = []
        for reference in references:
            if self._is_reference_included(reference, name):
                referenced_uuid = reference['referenced_uuid']
                if referenced_uuid not in self._objects_to_parse[name]:
                    self._referenced_object_name_warning(name, referenced_uuid)
                    continue
                uuids.append(referenced_uuid)
        return uuids

    def _find_target_uuid(self, reference: str) -> Union[str, None]:
        for object_ref in self.__object_refs:
            if reference in object_ref:
                return object_ref

    @staticmethod
    def _get_matching_email_display_name(display_names: list, address: str) -> Optional[int]:
        # Trying first to get a perfect match in case of a very standard first name last name case
        for index in range(len(display_names)):
            display_name = display_names[index].lower().split(' ')
            if all(name in address for name in display_name):
                return index
        # Trying to get a potential match otherwise
        values = re.sub('[_.@-]', ' ', address.lower()).split(' ')
        for index in range(len(display_names)):
            display_name = display_names[index].lower()
            if any(value in display_name for value in values):
                return index
            initials = ''.join(name[0] for name in display_name.split(' '))
            if len(initials) > 1 and initials in address:
                return index
        # If no match, then the remaining unmatched display names are just going to be exported as custom property

    @staticmethod
    def _get_vulnerability_references(vulnerability: str) -> dict:
        return {
            'source_name': 'cve',
            'external_id': vulnerability
        }

    def _handle_indicator_time_fields(self, attribute: dict) -> dict:
        timestamp = self._datetime_from_timestamp(attribute['timestamp'])
        time_fields = {'created': timestamp, 'modified': timestamp}
        if not any(attribute.get(feature) for feature in _misp_time_fields):
            time_fields['valid_from'] = timestamp
            return time_fields
        stix_fields = _stix_time_fields['indicator']
        for misp_field, stix_field in zip(_misp_time_fields, stix_fields):
            time_fields[stix_field] = self._datetime_from_str(attribute[misp_field]) if attribute.get(misp_field) else timestamp
        return time_fields

    def _handle_observable_time_fields(self, attribute: dict) -> dict:
        timestamp = self._datetime_from_timestamp(attribute['timestamp'])
        time_fields = {'created': timestamp, 'modified': timestamp}
        stix_fields = _stix_time_fields['observed-data']
        for misp_field, stix_field in zip(_misp_time_fields, stix_fields):
            time_fields[stix_field] = self._datetime_from_str(attribute[misp_field]) if attribute.get(misp_field) else timestamp
        return time_fields

    def _handle_vulnerability_time_fields(self, attributes: dict, object_timestamp: str) -> dict:
        timestamp = self._datetime_from_timestamp(object_timestamp)
        time_fields = {'created': 2, 'modified': 1}
        use_case = 0
        for time_field, index in time_fields.items():
            if attributes.get(time_field):
                use_case += index
                value = self._select_single_feature(attributes, time_field)
                time_fields[time_field] = self._datetime_from_str(value)
                continue
            time_fields[time_field] = timestamp
        if time_fields['created'] > time_fields['modified']:
            if use_case == 1:
                time_fields['created'] = time_fields['modified']
            else:
                time_fields['modified'] = time_fields['created']
        return time_fields

    @staticmethod
    def _handle_value_for_pattern(attribute_value: str) -> str:
        return attribute_value.replace("'", '##APOSTROPHE##').replace('"', '##QUOTE##')

    def _parse_galaxy_relationship(self, source_id: str, target_id: str, relationship_type: str, timestamp: datetime):
        self.__relationships.append(
            {
                'source_ref': source_id,
                'target_ref': target_id,
                'relationship_type': relationship_type,
                'created': timestamp,
                'modified': timestamp,
                'allow_custom': True
            }
        )

    def _parse_object_relationships(self, references: list, source_id: str, timestamp: datetime):
        for reference in references:
            referenced_uuid = reference['referenced_uuid']
            if any(referenced_uuid in objects for objects in self._objects_to_parse.values()):
                continue
            relationship = {
                'source_ref': source_id,
                'undefined_target_ref': referenced_uuid,
                'relationship_type': reference['relationship_type'],
                'allow_custom': True
            }
            if reference.get('timestamp'):
                reference_timestamp = self._datetime_from_timestamp(reference['timestamp'])
                relationship.update(
                    {
                        'created': reference_timestamp,
                        'modified': reference_timestamp
                    }
                )
            else:
                relationship.update(
                    {
                        'created': timestamp,
                        'modified': timestamp
                    }
                )
            self.__relationships.append(relationship)

    @staticmethod
    def _sanitize_registry_key_value(value: str) -> str:
        sanitized = value.strip().replace('\\', '\\\\')
        if '%' not in sanitized or '\\\\%' in sanitized:
            return sanitized
        if '\\%' in sanitized:
            return sanitized.replace('\\%', '\\\\%')
        return sanitized.replace('%', '\\\\%')

    def _select_pe_object(self, pe_uuid: str) -> dict:
        to_ids, pe_object = self._objects_to_parse['pe'][pe_uuid]
        self._objects_to_parse['pe'][pe_uuid] = to_ids
        return pe_object
