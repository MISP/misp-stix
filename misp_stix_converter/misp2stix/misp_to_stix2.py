#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from . import stix2_mapping
from .exportparser import MISPtoSTIXParser
from collections import defaultdict
from datetime import datetime
from stix2.v20.bundle import Bundle as Bundle_v20
from stix2.v21.bundle import Bundle as Bundle_v21
from typing import Optional, Union
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
        markings = self._handle_event_tags_and_galaxies('stix2_galaxy_mapping')
        if markings:
            report_args['object_marking_refs'] = self._handle_markings(markings)
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
                    relationship = self._create_relationship(relationship_args)
                    self._append_SDO(relationship)
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
        markings = self._handle_attribute_tags_and_galaxies(
            attribute,
            indicator_id,
            indicator_args['modified']
        )
        if markings:
            indicator_args['object_marking_refs'] = self._handle_markings(markings)
        indicator = self._create_indicator(indicator_args)
        self._append_SDO(indicator)

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
            campaign_args['object_marking_refs'] = self._handle_markings(markings)
        campaign = self._create_campaign(campaign_args)
        self._append_SDO(campaign)

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
            'x_misp_category': attribute['category']
        }
        if attribute.get('comment'):
            custom_args['x_misp_comment'] = attribute['comment']
        markings = self._handle_attribute_tags_and_galaxies(
            attribute,
            custom_id,
            timestamp
        )
        if markings:
            custom_args['object_marking_refs'] = self._handle_markings(markings)
        custom_object = self._create_custom_object(custom_args)
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
            vulnerability_args['object_marking_refs'] = self._handle_markings(markings)
        vulnerability = self._create_vulnerability(vulnerability_args)
        self._append_SDO(vulnerability)

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

    ################################################################################
    #                          GALAXIES PARSING FUNCTIONS                          #
    ################################################################################

    def _handle_attribute_galaxy_relationships(self, object_id: str, object_refs: list, timestamp: datetime):
        self._parse_relationships(object_id, object_refs, timestamp)
        for object_ref in object_refs:
            if object_ref not in self._object_refs:
                self._object_refs.append(object_ref)

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
            attack_pattern = self._create_attack_pattern(attack_pattern_args, cluster)
            self._objects.append(attack_pattern)
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
                threat_actors_args['aliases'] = cluster['meta']['synonyms']
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
        markings = self._handle_attribute_tags_and_galaxies(
            attribute,
            observable_id,
            observable_args['modified']
        )
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

    def _create_filename_hash_pattern(self, hash_type: str, attribute_value: str) -> str:
        filename, hash_value = attribute_value.split('|')
        filename_pattern = self._create_filename_pattern(filename)
        hash_pattern = self._create_hash_pattern(hash_type, hash_value)
        return f"{filename_pattern} AND {hash_pattern}"

    @staticmethod
    def _create_filename_pattern(value: str) -> str:
        return f"file:name = '{value}'"

    def _create_hash_pattern(self, hash_type: str, value: str) -> str:
        return f"file:hashes.{self._define_hash_type(hash_type)} = '{value}'"

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
