#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .misp_to_stix2 import MISPtoSTIX2Parser
from .stix2_mapping import (CustomAttribute_v20, CustomNote, email_data_fields,
                            email_header_fields, email_object_mapping, file_data_fields,
                            file_single_fields, ip_port_single_fields,
                            network_socket_v20_single_fields, network_traffic_uuid_fields,
                            process_v20_single_fields, tlp_markings_v20)
from collections import defaultdict
from copy import deepcopy
from datetime import datetime
from stix2.properties import ListProperty, StringProperty
from stix2.v20.bundle import Bundle
from stix2.v20.observables import (Artifact, AutonomousSystem, Directory, DomainName,
                                   EmailAddress, EmailMessage, EmailMIMEComponent,
                                   File, IPv4Address, IPv6Address, MACAddress, Mutex,
                                   NetworkTraffic, Process, URL, UserAccount,
                                   WindowsRegistryKey, WindowsRegistryValueType,
                                   X509Certificate)
from stix2.v20.sdo import (AttackPattern, Campaign, CourseOfAction, Identity,
                           Indicator, Malware, ObservedData, Report, ThreatActor,
                           Tool, Vulnerability)
from stix2.v20.sro import Relationship
from typing import Optional, Union


class MISPtoSTIX20Parser(MISPtoSTIX2Parser):
    def __init__(self):
        super().__init__()
        self._version = '2.0'
        self._update_mapping_v20()

    def _handle_empty_object_refs(self, object_id: str, timestamp: datetime):
        object_type = 'x-misp-event-note'
        custom_args = {
            'id': f"{object_type}--{self._misp_event['uuid']}",
            'created': timestamp,
            'modified': timestamp,
            'created_by_ref': self._identity_id,
            'x_misp_event_note': 'This MISP Event is empty and contains no attribute, object, galaxy or tag.',
            'object_ref': object_id,
            'interoperability': True
        }
        self._append_SDO(CustomNote(**custom_args))

    def _handle_unpublished_report(self, report_args: dict) -> Report:
        report_id = f"report--{self._misp_event['uuid']}"
        if not self._object_refs:
            self._handle_empty_object_refs(report_id, report_args['modified'])
        report_args.update(
            {
                'id': report_id,
                'type': 'report',
                'published': report_args['modified'],
                'object_refs': self._object_refs
            }
        )
        return Report(**report_args)

    ################################################################################
    #                         ATTRIBUTES PARSING FUNCTIONS                         #
    ################################################################################

    def _parse_attachment_attribute_observable(self, attribute: dict):
        observable_object = {
            '0': File(
                name=attribute['value'],
                _valid_refs={'1': 'artifact'},
                content_ref='1'
            ),
            '1': self._create_artifact(attribute['data'])
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_autonomous_system_attribute_observable(self, attribute: dict):
        observable_object = {
            '0': AutonomousSystem(number=self._parse_AS_value(attribute['value']))
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_domain_attribute_observable(self, attribute: dict):
        observable_object = {
            '0': DomainName(value=attribute['value'])
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_domain_ip_attribute_observable(self, attribute: dict):
        domain, ip = attribute['value'].split('|')
        address_object = self._get_address_type(ip)(value=ip)
        observable_object = {
            '0': DomainName(
                value=domain,
                _valid_refs={'1': address_object._type},
                resolves_to_refs=['1']
            ),
            '1': address_object
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_email_attachment_attribute_observable(self, attribute: dict):
        observable_object = {
            '0': EmailMessage(
                is_multipart=True,
                body_multipart=[
                    EmailMIMEComponent(
                        content_disposition=f"attachment; filename='{attribute['value']}'",
                        body_raw_ref='1'
                    )
                ]
            ),
            '1': self._create_file(attribute['value'])
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_email_attribute_observable(self, attribute: dict):
        observable_object = {
            '0': self._create_email_address(attribute['value'])
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_email_body_attribute_observable(self, attribute: dict):
        observable_object = {
            '0': EmailMessage(
                is_multipart=False,
                body=attribute['value']
            )
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_email_destination_attribute_observable(self, attribute: dict):
        observable_object = {
            '0': EmailMessage(
                is_multipart=False,
                _valid_refs={'1': 'email-addr'},
                to_refs=['1']
            ),
            '1': self._create_email_address(attribute['value'])
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_email_header_attribute_observable(self, attribute: dict):
        observable_object = {
            '0': EmailMessage(
                is_multipart=False,
                received_lines=[attribute['value']]
            )
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_email_reply_to_attribute_observable(self, attribute: dict):
        observable_object = {
            '0': EmailMessage(
                is_multipart=False,
                additional_header_fields={
                    "Reply-To": [
                        attribute['value']
                    ]
                }
            )
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_email_source_attribute_observable(self, attribute: dict):
        observable_object = {
            '0': EmailMessage(
                is_multipart=False,
                _valid_refs={'1': 'email-addr'},
                from_ref='1'
            ),
            '1': self._create_email_address(attribute['value'])
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_email_subject_attribute_observable(self, attribute: dict):
        observable_object = {
            '0': EmailMessage(
                is_multipart=False,
                subject=attribute['value']
            )
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_email_x_mailer_attribute_observable(self, attribute: dict):
        observable_object = {
            '0': EmailMessage(
                is_multipart=False,
                additional_header_fields={
                    "X-Mailer": attribute['value']
                }
            )
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_filename_attribute_observable(self, attribute: dict):
        observable_object = {
            '0': self._create_file(attribute['value'])
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_hash_attribute_observable(self, attribute: dict):
        observable_object = {
            '0': File(
                hashes={
                    self._define_hash_type(attribute['type']): attribute['value']
                }
            )
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_hash_composite_attribute_observable(self, attribute: dict, hash_type: Optional[str] = None):
        if hash_type is None:
            hash_type = attribute['type'].split('|')[1]
        filename, hash_value = attribute['value'].split('|')
        observable_object = {
            '0': File(
                name=filename,
                hashes={
                    self._define_hash_type(hash_type): hash_value
                }
            )
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_hostname_port_attribute_observable(self, attribute: dict):
        hostname, port = attribute['value'].split('|')
        observable_object = {
            '0': DomainName(
                value=hostname
            ),
            '1': NetworkTraffic(
                dst_port=port,
                _valid_refs={'0': 'domain-name'},
                dst_ref='0',
                protocols=['tcp']
            )
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_ip_attribute_observable(self, attribute: dict):
        address_object = self._get_address_type(attribute['value'])(value=attribute['value'])
        ip_type = attribute['type'].split('-')[1]
        network_traffic_args = {
            '_valid_refs': {'1': address_object._type},
            f'{ip_type}_ref': '1',
            'protocols': ['tcp']
        }
        observable_object = {
            '0': NetworkTraffic(**network_traffic_args),
            '1': address_object
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_ip_port_attribute_observable(self, attribute: dict):
        ip_value, port_value = attribute['value'].split('|')
        address_object = self._get_address_type(ip_value)(value=ip_value)
        ip_type = attribute['type'].split('|')[0].split('-')[1]
        network_traffic_args = {
            '_valid_refs': {'1': address_object._type},
            f'{ip_type}_ref': '1',
            f'{ip_type}_port': port_value,
            'protocols': ['tcp']
        }
        observable_object = {
            '0': NetworkTraffic(**network_traffic_args),
            '1': address_object
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_mac_address_attribute_observable(self, attribute: dict):
        observable_object = {
            '0': MACAddress(value=attribute['value'])
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_malware_sample_attribute_observable(self, attribute: dict):
        filename, hash_value = attribute['value'].split('|')
        observable_object = {
            '0': File(
                name=filename,
                hashes={
                    'MD5': hash_value
                },
                _valid_refs={'1': 'artifact'},
                content_ref='1'
            ),
            '1': self._create_artifact(attribute['data'])
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_mutex_attribute_observable(self, attribute: dict):
        observable_object = {
            '0': Mutex(name=attribute['value'])
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_regkey_attribute_observable(self, attribute: dict):
        observable_object = {
            '0': WindowsRegistryKey(
                key=attribute['value'].strip()
            )
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_regkey_value_attribute_observable(self, attribute: dict):
        key, value = attribute['value'].split('|')
        observable_object = {
            '0': WindowsRegistryKey(
                key=key.strip(),
                values=[
                    WindowsRegistryValueType(
                        name='',
                        data=value.strip()
                    )
                ]
            )
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_url_attribute_observable(self, attribute: dict):
        observable_object = {
            '0': URL(
                value=attribute['value']
            )
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_x509_fingerprint_attribute_observable(self, attribute: dict):
        hash_type = attribute['type'].split('-')[-1]
        observable_object = {
            '0': X509Certificate(
                hashes={
                    self._define_hash_type(hash_type): attribute['value']
                }
            )
        }
        self._handle_attribute_observable(attribute, observable_object)

    ################################################################################
    #                        MISP OBJECTS PARSING FUNCTIONS                        #
    ################################################################################

    def _parse_asn_object_observable(self, misp_object: dict):
        as_args = self._create_AS_args(misp_object['Attribute'])
        observable_object = {
            '0': AutonomousSystem(**as_args)
        }
        self._handle_object_observable(misp_object, observable_object)

    def _parse_credential_object_observable(self, misp_object: dict):
        credential_args = self._create_credential_args(misp_object['Attribute'])
        observable_object = {
            '0': UserAccount(**credential_args)
        }
        self._handle_object_observable(misp_object, observable_object)

    def _parse_domain_ip_object_observable(self, misp_object: dict):
        attributes = self._extract_multiple_object_attributes(misp_object['Attribute'])
        if not any(feature in attributes for feature in ('domain', 'hostname')):
            self._parse_custom_object(misp_object)
            self._warnings.add('Missing minimum requirement to build a DomainName object from a domain-ip MISP Object.')
            return
        observable_object = {}
        domain_args = {}
        if attributes.get('ip'):
            index = 1
            valid_refs = {}
            for ip_value in attributes.pop('ip'):
                str_index = str(index)
                address_object = self._get_address_type(ip_value)(value=ip_value)
                observable_object[str_index] = address_object
                valid_refs[str_index] = address_object._type
                index += 1
            domain_args['_valid_refs'] = valid_refs
            domain_args['resolves_to_refs'] = list(valid_refs.keys())
        if attributes:
            domain_args.update(self._parse_domain_args(attributes))
        observable_object['0'] = DomainName(**domain_args)
        self._handle_object_observable(misp_object, observable_object)

    def _parse_email_object_observable(self, misp_object: dict):
        attributes = self._extract_multiple_object_attributes_with_data(
            misp_object['Attribute'],
            with_data=email_data_fields
        )
        observable_object = {}
        email_message_args = defaultdict(dict)
        email_message_args['is_multipart'] = False
        index = 1
        if attributes.get('from'):
            str_index = str(index)
            self._parse_email_object_reference(
                self._select_single_feature(attributes, 'from'),
                email_message_args,
                observable_object,
                str_index
            )
            email_message_args['from_ref'] = str_index
            index += 1
        for feature in ('to', 'cc'):
            if attributes.get(feature):
                references = []
                for value in attributes.pop(feature):
                    str_index = str(index)
                    self._parse_email_object_reference(
                        value,
                        email_message_args,
                        observable_object,
                        str_index
                    )
                    references.append(str_index)
                    index += 1
                email_message_args[f'{feature}_refs'] = references
        if any(key in attributes for key in email_data_fields):
            body_multipart = []
            for feature in email_data_fields:
                if attributes.get(feature):
                    for value in attributes.pop(feature):
                        str_index = str(index)
                        if isinstance(value, tuple):
                            value, data = value
                            observable_objects[str_index] = self._create_artifact(
                                data,
                                filename=value
                            )
                        else:
                            observable_object[str_index] = self._create_file(value)
                        body = {
                            'content_disposition': f"{feature}; filename='{value}'",
                            'body_raw_ref': str_index
                        }
                        body_multipart.append(body)
                        index += 1
            email_message_args.update(
                {
                    'body_multipart': body_multipart,
                    'is_multipart': True
                }
            )
        if attributes:
            email_message_args.update(self._parse_email_args(attributes))
        observable_object['0'] = EmailMessage(**email_message_args)
        self._handle_object_observable(misp_object, observable_object)

    def _parse_email_object_reference(self, address: str, email_args: dict, observable: dict, index: str):
        email_address = self._create_email_address(address)
        observable[index] = email_address
        email_args['_valid_refs'][index] = email_address._type

    def _parse_file_object_observable(self, misp_object: dict):
        attributes = self._extract_multiple_object_attributes_with_data(
            misp_object['Attribute'],
            force_single=file_single_fields,
            with_data=file_data_fields
        )
        observable_object = {}
        file_args = defaultdict(dict)
        index = 1
        if attributes.get('path'):
            str_index = str(index)
            observable_object[str_index] = Directory(path=attributes.pop('path'))
            file_args['parent_directory_ref'] = str_index
            file_args['_valid_refs'][str_index] = 'directory'
            index += 1
        if attributes.get('malware-sample'):
            value = attributes.pop('malware-sample')
            args = {'allow_custom': True}
            if isinstance(value, tuple):
                value, data = value
                args['payload_bin'] = data
            filename, md5 = value.split('|')
            args.update(
                {
                    'hashes': {'MD5': md5},
                    'x_misp_filename': filename
                }
            )
            str_index = str(index)
            observable_object[str_index] = Artifact(**args)
            file_args['content_ref'] = str_index
            file_args['_valid_refs'][str_index] = 'artifact'
            index += 1
        if attributes.get('attachment'):
            value = attributes.pop('attachment')
            args = {'allow_custom': True}
            if isinstance(value, tuple):
                value, data = value
                args['payload_bin'] = data
            args['x_misp_filename'] = value
            observable_object[str(index)] = Artifact(**args)
        if attributes:
            file_args.update(self._parse_file_args(attributes))
        observable_object['0'] = File(**file_args)
        self._handle_object_observable(misp_object, observable_object)

    def _parse_ip_port_object_observable(self, misp_object: dict):
        attributes = self._extract_multiple_object_attributes(
            misp_object['Attribute'],
            force_single=ip_port_single_fields
        )
        protocols = {'tcp'}
        observable_object = {}
        network_traffic_args = defaultdict(dict)
        index = 1
        for feature in ('ip-src', 'ip-dst', 'ip'):
            if attributes.get(feature):
                str_index = str(index)
                ip_value = self._select_single_feature(attributes, feature)
                address_object = self._get_address_type(ip_value)(value=ip_value)
                observable_object[str_index] = address_object
                network_traffic_args['_valid_refs'][str_index] = address_object._type
                protocols.add(address_object._type.split('-')[0])
                ref_type = 'src_ref' if feature == 'ip-src' else 'dst_ref'
                network_traffic_args[ref_type] = str_index
                if ref_type == 'dst_ref':
                    break
                index += 1
        network_traffic_args['protocols'] = protocols
        if attributes:
            network_traffic_args.update(self._parse_ip_port_args(attributes))
        observable_object['0'] = NetworkTraffic(**network_traffic_args)
        self._handle_object_observable(misp_object, observable_object)

    def _parse_network_connection_object_observable(self, misp_object: dict):
        attributes = self._extract_object_attributes(misp_object['Attribute'])
        network_traffic_args, observable_object = self._parse_network_references(attributes)
        if attributes:
            network_traffic_args.update(self._parse_network_connection_args(attributes))
        observable_object['0'] = NetworkTraffic(**network_traffic_args)
        self._handle_object_observable(misp_object, observable_object)

    def _parse_network_references(self, attributes: dict) -> tuple:
        index = 1
        network_traffic_args = defaultdict(dict)
        observable_object = {}
        for feature in ('src', 'dst'):
            if attributes.get(f'ip-{feature}'):
                str_index = str(index)
                ip_value = attributes.pop(f'ip-{feature}')
                address_object = self._get_address_type(ip_value)(value=ip_value)
                observable_object[str_index] = address_object
                network_traffic_args['_valid_refs'][str_index] = address_object._type
                network_traffic_args[f'{feature}_ref'] = str_index
                index += 1
                continue
            if attributes.get(f'hostname-{feature}'):
                str_index = str(index)
                observable_object[str_index] = DomainName(value=attributes.pop(f'hostname-{feature}'))
                network_traffic_args['_valid_refs'][str_index] = 'domain-name'
                network_traffic[f'{feature}_ref'] = str_index
                index += 1
        return network_traffic_args, observable_object

    def _parse_network_socket_object(self, misp_object: dict):
        attributes = self._extract_multiple_object_attributes(
            misp_object['Attribute'],
            force_single=network_socket_v20_single_fields
        )
        if self._fetch_ids_flag(misp_object['Attribute']):
            pattern = self._parse_network_socket_object_pattern(attributes)
            self._handle_object_indicator(misp_object, pattern)
        else:
            network_traffic_args, observable_object = self._parse_network_references(attributes)
            if attributes:
                network_traffic_args.update(self._parse_network_socket_args(attributes))
            observable_object['0'] = NetworkTraffic(**network_traffic_args)
            self._handle_object_observable(misp_object, observable_object)

    def _parse_process_object(self, misp_object: dict):
        attributes = self._extract_multiple_object_attributes(
            misp_object['Attribute'],
            force_single=process_v20_single_fields
        )
        if self._fetch_ids_flag(misp_object['Attribute']):
            pattern = self._parse_process_object_pattern(attributes)
            self._handle_object_indicator(misp_object, pattern)
        else:
            observable_object = {}
            parent_fields = tuple(key for key in attributes.keys() if key.startswith('parent-'))
            parent_attributes = {key: attributes.pop(key) for key in parent_fields}
            process_args = defaultdict(dict)
            index = 1
            if parent_attributes:
                str_index = str(index)
                parent_args = {}
                if parent_attributes.get('parent-image'):
                    index += 1
                    str_index2 = str(index)
                    observable_object[str_index2] = File(name=parent_attributes.pop('parent-image'))
                    parent_args['image_ref'] = str_index2
                parent_args.update(self._parse_process_args(parent_attributes, 'parent'))
                observable_object[str_index] = Process(**parent_args)
                process_args['parent_ref'] = str_index
                process_args['_valid_refs'][str_index] = 'process'
                index += 1
            if attributes.get('child-pid'):
                child_refs = []
                for child_pid in attributes.pop('child-pid'):
                    str_index = str(index)
                    observable_object[str_index] = Process(pid=child_pid)
                    child_refs.append(str_index)
                    process_args['_valid_refs'][str_index] = 'process'
                    index += 1
                process_args['child_refs'] = child_refs
            if attributes.get('image'):
                str_index = str(index)
                observable_object[str_index] = File(name=attributes.pop('image'))
                process_args['image_ref'] = str_index
            process_args.update(self._parse_process_args(attributes, 'features'))
            observable_object['0'] = Process(**process_args)
            self._handle_object_observable(misp_object, observable_object)

    def _parse_registry_key_object_observable(self, misp_object: dict):
        registry_key_args = self._parse_registry_key_args(misp_object['Attribute'])
        observable_object = {'0': WindowsRegistryKey(**registry_key_args)}
        self._handle_object_observable(misp_object, observable_object)

    def _parse_url_object_observable(self, misp_object: dict):
        url_args = self._parse_url_args(misp_object['Attribute'])
        observable_object = {'0': URL(**url_args)}
        self._handle_object_observable(misp_object, observable_object)

    def _parse_user_account_object_observable(self, misp_object: dict):
        user_account_args = self._parse_user_account_args(misp_object['Attribute'])
        observable_object = {'0': UserAccount(**user_account_args)}
        self._handle_object_observable(misp_object, observable_object)

    def _parse_x509_object_observable(self, misp_object: dict):
        x509_args = self._parse_x509_args(misp_object['Attribute'])
        observable_object = {'0': X509Certificate(**x509_args)}
        self._handle_object_observable(misp_object, observable_object)

    ################################################################################
    #                    STIX OBJECTS CREATION HELPER FUNCTIONS                    #
    ################################################################################

    @staticmethod
    def _create_artifact(content: str, filename: Optional[str] = None) -> Artifact:
        args = {'payload_bin': content}
        if filename is not None:
            args['x_misp_filename'] = filename
        return Artifact(**args)

    def _create_attack_pattern_from_galaxy(self, args: dict, cluster: dict) -> AttackPattern:
        args['kill_chain_phases'] = self._create_killchain(cluster['type'])
        return AttackPattern(**args)

    @staticmethod
    def _create_attack_pattern_from_object(attack_pattern_args: dict) -> AttackPattern:
        return AttackPattern(**attack_pattern_args)

    def _create_bundle(self) -> Bundle:
        return Bundle(self._objects)

    @staticmethod
    def _create_campaign(campaign_args: dict) -> Campaign:
        return Campaign(**campaign_args)

    @staticmethod
    def _create_course_of_action(course_of_action_args: dict) -> CourseOfAction:
        return CourseOfAction(**course_of_action_args)

    @staticmethod
    def _create_custom_object(custom_args: dict) -> CustomAttribute_v20:
        stix_labels = ListProperty(StringProperty)
        stix_labels.clean(custom_args['labels'])
        stix_markings = ListProperty(StringProperty)
        if custom_args.get('markings'):
            stix_markings.clean(custom_args['markings'])
        return CustomAttribute_v20(**custom_args)

    @staticmethod
    def _create_email_address(email_address: str) -> EmailAddress:
        return EmailAddress(value=email_address)

    @staticmethod
    def _create_file(name: str) -> File:
        return File(name=name)

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
    def _create_indicator(indicator_args: dict) -> Indicator:
        return Indicator(**indicator_args)

    def _create_malware(self, malware_args: dict, cluster: dict) -> Malware:
        malware_args['kill_chain_phases'] = self._create_killchain(cluster['type'])
        return Malware(**malware_args)

    def _create_observed_data(self, args: dict, observable: dict):
        args['objects'] = observable
        self._append_SDO(ObservedData(**args))

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
            marking_definition = deepcopy(tlp_markings_v20[marking])
            self._markings[marking] = marking_definition
            return marking_definition.id
        except KeyError:
            self._warning.append(f"Unknwon TLP tag: {marking}")
        return
