#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .misp_to_stix2 import MISPtoSTIX2Parser
from .stix2_mapping import CustomAttribute_v21, tlp_markings_v21
from copy import deepcopy
from datetime import datetime
from stix2.exceptions import TLPMarkingDefinitionError
from stix2.properties import DictionaryProperty, ListProperty, StringProperty, TimestampProperty
from stix2.v21.bundle import Bundle
from stix2.v21.observables import (Artifact, AutonomousSystem, DomainName, EmailAddress,
                                   EmailMessage, EmailMIMEComponent, File, IPv4Address,
                                   IPv6Address, MACAddress, Mutex, NetworkTraffic,
                                   URL, UserAccount, WindowsRegistryKey,
                                   WindowsRegistryValueType, X509Certificate)
from stix2.v21.sdo import (AttackPattern, Campaign, CourseOfAction, Grouping, Identity,
                           Indicator, Malware, Note, ObservedData, Report, ThreatActor,
                           Tool, Vulnerability)
from stix2.v21.sro import Relationship
from typing import Optional, Union

_OBSERVABLE_OBJECT_TYPES = Union[
    AutonomousSystem
]


class MISPtoSTIX21Parser(MISPtoSTIX2Parser):
    def __init__(self):
        super().__init__()
        self._version = '2.1'
        self._update_mapping_v21()

    def _handle_empty_object_refs(self, object_id: str, timestamp: datetime):
        note_args = {
            'id': f"note--{self._misp_event['uuid']}",
            'created': timestamp,
            'modified': timestamp,
            'created_by_ref': self._identity_id,
            'content': 'This MISP Event is empty and contains no attribute, object, galaxy or tag.',
            'object_refs': [object_id]
        }
        self._append_SDO(Note(**note_args))

    def _handle_unpublished_report(self, report_args: dict) -> Grouping:
        grouping_id = f"grouping--{self._misp_event['uuid']}"
        if not self._object_refs:
            self._handle_empty_object_refs(grouping_id, report_args['modified'])
        report_args.update(
            {
                'id': grouping_id,
                'type': 'grouping',
                'context': 'suspicious-activity',
                'object_refs': self._object_refs
            }
        )
        return Grouping(**report_args)

    ################################################################################
    #                         ATTRIBUTES PARSING FUNCTIONS                         #
    ################################################################################

    def _parse_attachment_attribute_observable(self, attribute: dict):
        artifact_id = f"artifact--{attribute['uuid']}"
        objects = [
            File(
                id=f"file--{attribute['uuid']}",
                name=attribute['value'],
                content_ref=artifact_id
            ),
            Artifact(
                id=artifact_id,
                payload_bin=attribute['data']
            )
        ]
        self._handle_attribute_observable(attribute, objects)

    def _parse_autonomous_system_attribute_observable(self, attribute: dict):
        AS_object = AutonomousSystem(
            id=f"autonomous-system--{attribute['uuid']}",
            number=self._parse_AS_value(attribute['value'])
        )
        self._handle_attribute_observable(attribute, [AS_object])

    def _parse_domain_attribute_observable(self, attribute: dict):
        domain_object = DomainName(
            id=f"domain-name--{attribute['uuid']}",
            value=attribute['value']
        )
        self._handle_attribute_observable(attribute, [domain_object])

    def _parse_domain_ip_attribute_observable(self, attribute: dict):
        domain, ip = attribute['value'].split('|')
        address_type = self._get_address_type(ip)
        address_id = f"{address_type._type}--{attribute['uuid']}"
        objects = [
            DomainName(
                id=f"domain-name--{attribute['uuid']}",
                value=domain,
                resolves_to_refs=[address_id]
            ),
            address_type(
                id=address_id,
                value=ip
            )
        ]
        self._handle_attribute_observable(attribute, objects)

    def _parse_email_attachment_attribute_observable(self, attribute: dict):
        file_id = f"file--{attribute['uuid']}"
        objects = [
            EmailMessage(
                id=f"email-message--{attribute['uuid']}",
                is_multipart=True,
                body_multipart=[
                    EmailMIMEComponent(
                        content_disposition=f"attachment; filename='{attribute['value']}'",
                        body_raw_ref=file_id
                    )
                ]
            ),
            File(
                id=file_id,
                name=attribute['value']
            )
        ]
        self._handle_attribute_observable(attribute, objects)

    def _parse_email_attribute_observable(self, attribute: dict):
        address_object = EmailAddress(
            id=f"email-addr--{attribute['uuid']}",
            value=attribute['value']
        )
        self._handle_attribute_observable(attribute, [address_object])

    def _parse_email_body_attribute_observable(self, attribute: dict):
        message_object = EmailMessage(
            id=f"email-message--{attribute['uuid']}",
            is_multipart=False,
            body=attribute['value']
        )
        self._handle_attribute_observable(attribute, [message_object])

    def _parse_email_destination_attribute_observable(self, attribute: dict):
        address_id = f"email-addr--{attribute['uuid']}"
        objects = [
            EmailMessage(
                id=f"email-message--{attribute['uuid']}",
                is_multipart=False,
                to_refs=[address_id]
            ),
            EmailAddress(
                id=address_id,
                value=attribute['value']
            )
        ]
        self._handle_attribute_observable(attribute, objects)

    def _parse_email_header_attribute_observable(self, attribute: dict):
        message_object = EmailMessage(
            id=f"email-message--{attribute['uuid']}",
            is_multipart=False,
            received_lines=[attribute['value']]
        )
        self._handle_attribute_observable(attribute, [message_object])

    def _parse_email_message_id_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            pattern = f"[email-message:message_id = '{attribute['value']}']"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            message_object = EmailMessage(
                id=f"email-message--{attribute['uuid']}",
                is_multipart=False,
                message_id=attribute['value']
            )
            self._handle_attribute_observable(attribute, [message_object])

    def _parse_email_reply_to_attribute_observable(self, attribute: dict):
        message_object = EmailMessage(
            id=f"email-message--{attribute['uuid']}",
            is_multipart=False,
            additional_header_fields={
                "Reply-To": [
                    attribute['value']
                ]
            }
        )
        self._handle_attribute_observable(attribute, [message_object])

    def _parse_email_source_attribute_observable(self, attribute: dict):
        address_id = f"email-addr--{attribute['uuid']}"
        objects = [
            EmailMessage(
                id=f"email-message--{attribute['uuid']}",
                is_multipart=False,
                from_ref=address_id
            ),
            EmailAddress(
                id=address_id,
                value=attribute['value']
            )
        ]
        self._handle_attribute_observable(attribute, objects)

    def _parse_email_subject_attribute_observable(self, attribute: dict):
        message_object = EmailMessage(
            id=f"email-message--{attribute['uuid']}",
            is_multipart=False,
            subject=attribute['value']
        )
        self._handle_attribute_observable(attribute, [message_object])

    def _parse_email_x_mailer_attribute_observable(self, attribute: dict):
        message_object = EmailMessage(
            id=f"email-message--{attribute['uuid']}",
            is_multipart=False,
            additional_header_fields={
                "X-Mailer": attribute['value']
            }
        )
        self._handle_attribute_observable(attribute, [message_object])

    def _parse_filename_attribute_observable(self, attribute: dict):
        file_object = File(
            id=f"file--{attribute['uuid']}",
            name=attribute['value']
        )
        self._handle_attribute_observable(attribute, [file_object])

    def _parse_hash_attribute_observable(self, attribute: dict):
        file_object = File(
            id=f"file--{attribute['uuid']}",
            hashes={
                self._define_hash_type(attribute['type']): attribute['value']
            }
        )
        self._handle_attribute_observable(attribute, [file_object])

    def _parse_hash_composite_attribute_observable(self, attribute: dict, hash_type: Optional[str] = None):
        if hash_type is None:
            hash_type = attribute['type'].split('|')[1]
        filename, hash_value = attribute['value'].split('|')
        file_object = File(
            id=f"file--{attribute['uuid']}",
            name=filename,
            hashes={
                self._define_hash_type(hash_type): hash_value
            }
        )
        self._handle_attribute_observable(attribute, [file_object])

    def _parse_hostname_port_attribute_observable(self, attribute: dict):
        hostname, port = attribute['value'].split('|')
        domain_id = f"domain-name--{attribute['uuid']}"
        objects = [
            DomainName(
                id=domain_id,
                value=hostname
            ),
            NetworkTraffic(
                id=f"network-traffic--{attribute['uuid']}",
                dst_port=port,
                dst_ref=domain_id,
                protocols=['tcp']
            )
        ]
        self._handle_attribute_observable(attribute, objects)

    def _parse_ip_attribute_observable(self, attribute: dict):
        address_type = self._get_address_type(attribute['value'])
        address_id = f"{address_type._type}--{attribute['uuid']}"
        ip_type = attribute['type'].split('-')[1]
        network_traffic_args = {
            'id': f"network-traffic--{attribute['uuid']}",
            f'{ip_type}_ref': address_id,
            'protocols': ['tcp']
        }
        objects = [
            NetworkTraffic(**network_traffic_args),
            address_type(
                id=address_id,
                value=attribute['value']
            )
        ]
        self._handle_attribute_observable(attribute, objects)

    def _parse_ip_port_attribute_observable(self, attribute: dict):
        ip_value, port_value = attribute['value'].split('|')
        address_type = self._get_address_type(ip_value)
        address_id = f"{address_type._type}--{attribute['uuid']}"
        ip_type = attribute['type'].split('|')[0].split('-')[1]
        network_traffic_args = {
            'id': f"network-traffic--{attribute['uuid']}",
            f'{ip_type}_ref': address_id,
            f'{ip_type}_port': port_value,
            'protocols': ['tcp']
        }
        objects = [
            NetworkTraffic(**network_traffic_args),
            address_type(
                id=address_id,
                value=ip_value
            )
        ]
        self._handle_attribute_observable(attribute, objects)

    def _parse_mac_address_attribute_observable(self, attribute: dict):
        mac_address_object = MACAddress(
            id=f"mac-addr--{attribute['uuid']}",
            value=attribute['value']
        )
        self._handle_attribute_observable(attribute, [mac_address_object])

    def _parse_malware_sample_attribute_observable(self, attribute: dict):
        artifact_id = f"artifact--{attribute['uuid']}"
        filename, hash_value = attribute['value'].split('|')
        objects = [
            File(
                id=f"file--{attribute['uuid']}",
                name=filename,
                hashes={
                    'MD5': hash_value
                },
                content_ref=artifact_id
            ),
            Artifact(
                id=artifact_id,
                payload_bin=attribute['data']
            )
        ]
        self._handle_attribute_observable(attribute, objects)

    def _parse_mutex_attribute_observable(self, attribute: dict):
        mutex_object = Mutex(
            id=f"mutex--{attribute['uuid']}",
            name=attribute['value']
        )
        self._handle_attribute_observable(attribute, [mutex_object])

    def _parse_regkey_attribute_observable(self, attribute: dict):
        regkey_object = WindowsRegistryKey(
            id=f"windows-registry-key--{attribute['uuid']}",
            key=attribute['value'].strip()
        )
        self._handle_attribute_observable(attribute, [regkey_object])

    def _parse_regkey_value_attribute_observable(self, attribute: dict):
        key, value = attribute['value'].split('|')
        regkey_object = WindowsRegistryKey(
            id=f"windows-registry-key--{attribute['uuid']}",
            key=key.strip(),
            values=[
                WindowsRegistryValueType(
                    data=value.strip()
                )
            ]
        )
        self._handle_attribute_observable(attribute, [regkey_object])

    def _parse_url_attribute_observable(self, attribute: dict):
        url_object = URL(
            id=f"url--{attribute['uuid']}",
            value=attribute['value']
        )
        self._handle_attribute_observable(attribute, [url_object])

    def _parse_x509_fingerprint_attribute_observable(self, attribute: dict):
        hash_type = attribute['type'].split('-')[-1]
        x509_object = X509Certificate(
            id=f"x509-certificate--{attribute['uuid']}",
            hashes={
                self._define_hash_type(hash_type): attribute['value']
            }
        )
        self._handle_attribute_observable(attribute, [x509_object])

    ################################################################################
    #                        MISP OBJECTS PARSING FUNCTIONS                        #
    ################################################################################

    def _parse_asn_object_observable(self, misp_object: dict):
        as_args = self._create_AS_args(misp_object['Attribute'])
        AS_object = AutonomousSystem(**as_args)
        self._handle_object_observable(misp_object, [AS_object])

    def _parse_credential_object_observable(self, misp_object: dict):
        credential_args = self._create_credential_args(misp_object['Attribute'])
        user_object = UserAccount(**credential_args)
        self._handle_object_observable(misp_object, [user_object])

    ################################################################################
    #                    STIX OBJECTS CREATION HELPER FUNCTIONS                    #
    ################################################################################

    def _create_attack_pattern_from_galaxy(self, args: dict, cluster: dict) -> AttackPattern:
        args['kill_chain_phases'] = self._create_killchain(cluster['type'])
        if cluster.get('meta', {}).get('synonyms'):
            args['aliases'] = cluster['meta']['synonyms']
        return AttackPattern(**args)

    @staticmethod
    def _create_attack_pattern_from_object(attack_pattern_args: dict) -> AttackPattern:
        return AttackPattern(**attack_pattern_args)

    def _create_bundle(self) -> Bundle:
        return Bundle(self._objects, allow_custom=True)

    @staticmethod
    def _create_campaign(campaign_args: dict) -> Campaign:
        return Campaign(**campaign_args)

    @staticmethod
    def _create_course_of_action(course_of_action_args: dict) -> CourseOfAction:
        return CourseOfAction(**course_of_action_args)

    @staticmethod
    def _create_custom_object(custom_args: dict) -> CustomAttribute_v21:
        stix_labels = ListProperty(StringProperty)
        stix_labels.clean(custom_args['labels'])
        stix_markings = ListProperty(StringProperty)
        if custom_args.get('markings'):
            stix_markings.clean(custom_args['markings'])
        return CustomAttribute_v21(**custom_args)

    def _create_identity_object(self, orgname: str) -> Identity:
        timestamp = self._datetime_from_timestamp(self._misp_event['timestamp'])
        identity_args = {
            'type': 'identity',
            'id': self._identity_id,
            'created': timestamp,
            'modified': timestamp,
            'name': orgname,
            'identity_class': 'organization',
            'interoperability': True
        }
        return Identity(**identity_args)

    @staticmethod
    def _create_grouping(grouping_args: dict) -> Grouping:
        return Grouping(**grouping_args)

    @staticmethod
    def _create_indicator(indicator_args: dict) -> Indicator:
        indicator_args.update(
            {
                "spec_version": "2.1",
                "pattern_type": "stix",
                "pattern_version": "2.1",
            }
        )
        return Indicator(**indicator_args)

    def _create_malware(self, malware_args: dict, cluster: dict) -> Malware:
        malware_args.update(
            {
                'kill_chain_phases': self._create_killchain(cluster['type']),
                'is_family': True
            }
        )
        if cluster.get('meta', {}).get('synonyms'):
            malware_args['aliases'] = cluster['meta']['synonyms']
        return Malware(**malware_args)

    def _create_observed_data(self, args: dict, observables: list):
        args['object_refs'] = [observable.id for observable in observables]
        self._append_SDO(ObservedData(**args))
        for observable in observables:
            self._append_SDO(observable)

    @staticmethod
    def _create_relationship(relationship_args: dict) -> Relationship:
        return Relationship(**relationship_args)

    @staticmethod
    def _create_report(report_args: dict) -> Report:
        return Report(**report_args)

    @staticmethod
    def _create_threat_actor(threat_actor_args: dict) -> ThreatActor:
        return ThreatActor(**threat_actor_args)

    def _create_tool(self, tool_args: dict, cluster: dict) -> Tool:
        tool_args['kill_chain_phases'] = self._create_killchain(cluster['type'])
        if cluster.get('meta', {}).get('synonyms'):
            tool_args['aliases'] = cluster['meta']['synonyms']
        return Tool(**tool_args)

    @staticmethod
    def _create_vulnerability(vulnerability_args: dict) -> Vulnerability:
        return Vulnerability(**vulnerability_args)

    ################################################################################
    #                              UTILITY FUNCTIONS.                              #
    ################################################################################

    @staticmethod
    def _get_address_type(address: str) -> Union[IPv4Address, IPv6Address]:
        if ':' in address:
            return IPv6Address
        return IPv4Address

    def _get_marking(self, marking: str) -> Union[str, None]:
        try:
            marking_definition = deepcopy(tlp_markings_v21[marking])
            self._markings[marking] = marking_definition
            return marking_definition.id
        except KeyError:
            self._warning.append(f"Unknwon TLP tag: {marking}")
        return
