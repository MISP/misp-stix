#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .misp_to_stix2 import MISPtoSTIX2Parser
from .stix2_mapping import (CustomAttribute_v21, domain_ip_uuid_fields, email_data_fields,
                            email_uuid_fields, file_data_fields, file_uuid_fields,
                            tlp_markings_v21, ip_port_single_fields, ip_port_uuid_fields,
                            network_socket_v21_single_fields, network_traffic_uuid_fields,
                            process_uuid_fields, process_v21_single_fields)
from collections import defaultdict
from copy import deepcopy
from datetime import datetime
from stix2.properties import ListProperty, StringProperty
from stix2.v21.bundle import Bundle
from stix2.v21.observables import (Artifact, AutonomousSystem, Directory, DomainName,
                                   EmailAddress, EmailMessage, EmailMIMEComponent,
                                   File, IPv4Address, IPv6Address, MACAddress, Mutex,
                                   NetworkTraffic, Process, URL, UserAccount,
                                   WindowsPESection, WindowsRegistryKey,
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
            self._create_file(file_id, attribute['value'])
        ]
        self._handle_attribute_observable(attribute, objects)

    def _parse_email_attribute_observable(self, attribute: dict):
        address_object = self._create_email_address(
            f"email-addr--{attribute['uuid']}",
            attribute['value']
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
            self._create_email_address(
                address_id,
                attribute['value']
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
            self._create_email_address(
                address_id,
                attribute['value']
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
        file_object = self._create_file(f"file--{attribute['uuid']}", attribute['value'])
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

    @staticmethod
    def _extract_multiple_object_attributes_with_uuid_and_data(attributes: list, with_uuid: tuple = (), with_data: tuple = ()) -> dict:
        attributes_dict = defaultdict(list)
        for attribute in attributes:
            relation = attribute['object_relation']
            if relation not in with_uuid and relation not in with_data:
                attributes_dict[relation].append(attribute['value'])
                continue
            value = [attribute['value'], attribute['uuid']]
            if relation in with_data and attribute.get('data'):
                value.append(attribute['data'])
            attributes_dict[relation].append(value)
        return attributes_dict

    @staticmethod
    def _extract_object_attributes_with_multiple_and_uuid(attributes: list, force_single: tuple = (), with_uuid: tuple = ()) -> dict:
        attributes_dict = defaultdict(list)
        for attribute in attributes:
            relation = attribute['object_relation']
            value = (attribute['value'], attribute['uuid']) if relation in with_uuid else attribute['value']
            if relation in force_single:
                attributes_dict[relation] = value
            else:
                attributes_dict[relation].append(value)
        return attributes_dict

    def _handle_file_observable_objects(self, args: dict, objects: list):
        objects.insert(0, self._create_file_object(args))

    def _parse_asn_object_observable(self, misp_object: dict):
        as_args = self._create_AS_args(misp_object['Attribute'])
        AS_object = AutonomousSystem(**as_args)
        self._handle_object_observable(misp_object, [AS_object])

    def _parse_credential_object_observable(self, misp_object: dict):
        credential_args = self._create_credential_args(misp_object['Attribute'])
        user_object = UserAccount(**credential_args)
        self._handle_object_observable(misp_object, [user_object])

    def _parse_domain_ip_object_observable(self, misp_object: dict):
        attributes = self._extract_multiple_object_attributes_with_uuid(
            misp_object['Attribute'],
            with_uuid=domain_ip_uuid_fields
        )
        if not any(feature in attributes for feature in ('domain', 'hostname')):
            self._parse_custom_object(misp_object)
            self._warnings.add('Missing minimum requirement to build a DomainName object from a domain-ip MISP Object.')
            return
        domain_args = {}
        objects = []
        if attributes.get('ip'):
            for ip_value, uuid in attributes.pop('ip'):
                address_type = self._get_address_type(ip_value)
                address_id = f'{address_type._type}--{uuid}'
                objects.append(address_type(id=address_id, value=ip_value))
            domain_args['resolves_to_refs'] = [stix_object.id for stix_object in objects]
        if attributes:
            domain_args.update(self._parse_domain_args(attributes))
        objects.insert(0, DomainName(**domain_args))
        self._handle_object_observable(misp_object, objects)

    def _parse_email_object_observable(self, misp_object: dict):
        attributes = self._extract_multiple_object_attributes_with_uuid_and_data(
            misp_object['Attribute'],
            with_uuid=email_uuid_fields,
            with_data=email_data_fields
        )
        objects = []
        email_message_args = defaultdict(dict)
        email_message_args['is_multipart'] = True
        if attributes.get('from'):
            value, uuid = self._select_single_feature(attributes, 'from')
            address_id = f'email-addr--{uuid}'
            email_address = self._create_email_address(address_id, value)
            objects.append(email_address)
            email_message_args['from_ref'] = address_id
        for feature in ('to', 'cc'):
            if attributes.get(feature):
                references = []
                for value, uuid in attributes.pop(feature):
                    address_id = f'email-addr--{uuid}'
                    email_address = self._create_email_address(
                        address_id,
                        value
                    )
                    objects.append(email_address)
                    references.append(address_id)
                email_message_args[f'{feature}_refs'] = references
        if any(key in attributes for key in email_data_fields):
            body_multipart = []
            for feature in email_data_fields:
                if attributes.get(feature):
                    for attribute in attributes.pop(feature):
                        if len(attribute) == 3:
                            value, uuid, data = attribute
                            object_id = f'artifact--{uuid}'
                            objects.append(
                                self._create_artifact(object_id, data, filename=value)
                            )
                        else:
                            value, uuid = attribute
                            object_id = f'file--{uuid}'
                            objects.append(self._create_file(object_id, value))
                        body_multipart.append(
                            {
                                'content_disposition': f"{feature}; filename='{value}'",
                                'body_raw_ref': object_id
                            }
                        )
            if body_multipart:
                email_message_args.update(
                    {
                        'body_multipart': body_multipart,
                        'is_multipart': True
                    }
                )
        if attributes:
            email_message_args.update(self._parse_email_args(attributes))
        objects.insert(0, EmailMessage(**email_message_args))
        self._handle_object_observable(misp_object, objects)

    def _parse_file_object_observable(self, misp_object: dict):
        file_args, objects = self._parse_file_observable_object(misp_object['Attribute'])
        self._handle_file_observable_objects(file_args, objects)
        self._handle_object_observable(misp_object, objects)

    def _parse_file_observable_object(self, attributes: list) -> tuple:
        attributes = self._extract_multiple_object_attributes_with_uuid_and_data(
            attributes,
            with_uuid=file_uuid_fields,
            with_data=file_data_fields
        )
        objects = []
        file_args = defaultdict(dict)
        if attributes.get('path'):
            value, uuid = self._select_single_feature(attributes, 'path')
            directory_id = f'directory--{uuid}'
            objects.append(Directory(id=directory_id, path=value))
            file_args['parent_directory_ref'] = directory_id
        if attributes.get('malware-sample'):
            value = self._select_single_feature(attributes, 'malware-sample')
            args = {'allow_custom': True}
            if len(value) == 3:
                value, uuid, data = value
                args['payload_bin'] = data
            else:
                value, uuid = value
            filename, md5 = value.split('|')
            artifact_id = f'artifact--{uuid}'
            args.update(
                {
                    'id': artifact_id,
                    'hashes': {'MD5': md5},
                    'x_misp_filename': filename
                }
            )
            objects.append(Artifact(**args))
            file_args['content_ref'] = artifact_id
        if attributes.get('attachment'):
            value = self._select_single_feature(attributes, 'attachment')
            args = {'allow_custom': True}
            if len(value) == 3:
                filename, uuid, data = value
                args['payload_bin'] = data
            else:
                filename, uuid = value
            args.update(
                {
                    'id': f'artifact--{uuid}',
                    'x_misp_filename': filename
                }
            )
            objects.append(Artifact(**args))
        if attributes:
            file_args.update(self._parse_file_args(attributes))
        return file_args, objects

    def _parse_ip_port_object_observable(self, misp_object: dict):
        attributes = self._extract_object_attributes_with_multiple_and_uuid(
            misp_object['Attribute'],
            force_single=ip_port_single_fields,
            with_uuid=ip_port_uuid_fields
        )
        protocols = {'tcp'}
        network_traffic_args = {}
        objects = []
        for feature in ('ip-src', 'ip-dst', 'ip'):
            if attributes.get(feature):
                ref_type = 'src_ref' if feature == 'ip-src' else 'dst_ref'
                if ref_type not in network_traffic_args:
                    ip_value, uuid = self._select_single_feature(attributes, feature)
                    if attributes.get(feature):
                        attributes[feature] = [value[0] for value in attributes.pop(feature)]
                    address_type = self._get_address_type(ip_value)
                    address_id = f'{address_type._type}--{uuid}'
                    objects.append(address_type(id=address_id, value=ip_value))
                    network_traffic_args[ref_type] = address_id
                    protocols.add(address_type._type.split('-')[0])
                else:
                    attributes[feature] = [value[0] for value in attributes.pop(feature)]
        network_traffic_args['protocols'] = protocols
        if attributes:
            network_traffic_args.update(self._parse_ip_port_args(attributes))
        objects.insert(0, NetworkTraffic(**network_traffic_args))
        self._handle_object_observable(misp_object, objects)

    def _parse_network_connection_object_observable(self, misp_object: dict):
        attributes = self._extract_object_attributes_with_uuid(
            misp_object['Attribute'],
            with_uuid=network_traffic_uuid_fields
        )
        network_traffic_args, objects = self._parse_network_references(attributes)
        if attributes:
            network_traffic_args.update(self._parse_network_connection_args(attributes))
        objects.insert(0, NetworkTraffic(**network_traffic_args))
        self._handle_object_observable(misp_object, objects)

    def _parse_network_references(self, attributes: dict) -> tuple:
        network_traffic_args = {}
        objects = []
        for feature in ('src', 'dst'):
            hostname = f'hostname-{feature}'
            if attributes.get(f'ip-{feature}'):
                value, uuid = attributes.pop(f'ip-{feature}')
                address_type = self._get_address_type(value)
                address_id = f'{address_type._type}--{uuid}'
                objects.append(address_type(id=address_id, value=value))
                network_traffic_args[f'{feature}_ref'] = address_id
                if attributes.get(hostname):
                    attributes[hostname] = attributes.pop(hostname)[0]
                continue
            if attributes.get(hostname):
                value, uuid = attributes.pop(hostname)
                domain_id = f'domain-name--{uuid}'
                objects.append(DomainName(id=domain_id, value=value))
                network_traffic_args[f'{feature}_ref'] = domain_id
        return network_traffic_args, objects

    def _parse_network_socket_object(self, misp_object: dict):
        if self._fetch_ids_flag(misp_object['Attribute']):
            attributes = self._extract_multiple_object_attributes(
                misp_object['Attribute'],
                force_single=network_socket_v21_single_fields
            )
            pattern = self._parse_network_socket_object_pattern(attributes)
            self._handle_object_indicator(misp_object, pattern)
        else:
            attributes = self._extract_object_attributes_with_multiple_and_uuid(
                misp_object['Attribute'],
                force_single=network_socket_v21_single_fields,
                with_uuid=network_traffic_uuid_fields
            )
            network_traffic_args, objects = self._parse_network_references(attributes)
            if attributes:
                network_traffic_args.update(self._parse_network_socket_args(attributes))
            objects.insert(0, NetworkTraffic(**network_traffic_args))
            self._handle_object_observable(misp_object, objects)

    def _parse_process_object(self, misp_object: dict):
        if self._fetch_ids_flag(misp_object['Attribute']):
            attributes = self._extract_multiple_object_attributes(
                misp_object['Attribute'],
                force_single=process_v21_single_fields
            )
            pattern = self._parse_process_object_pattern(attributes)
            self._handle_object_indicator(misp_object, pattern)
        else:
            attributes = self._extract_object_attributes_with_multiple_and_uuid(
                misp_object['Attribute'],
                force_single=process_v21_single_fields,
                with_uuid=process_uuid_fields
            )
            objects = []
            parent_fields = tuple(key for key in attributes.keys() if key.startswith('parent-'))
            parent_attributes = {key: attributes.pop(key) for key in parent_fields}
            process_args = defaultdict(list)
            if parent_attributes:
                parent_args = {}
                for key in process_uuid_fields:
                    if parent_attributes.get(key):
                        parent_args['id'] = f"process--{parent_attributes[key][1]}"
                        for key in process_uuid_fields:
                            if parent_attributes.get(key):
                                parent_attributes[key] = parent_attributes.pop(key)[0]
                        break
                if parent_attributes.get('parent-image'):
                    filename, uuid = attributes.pop('parent-image')
                    image_uuid = f'file--{uuid}'
                    objects.append(File(id=image_uuid, name=filename))
                    parent_args['image_ref'] = image_uuid
                parent_args.update(self._parse_process_args(parent_attributes, 'parent'))
                process = Process(**parent_args)
                objects.append(process)
                process_args['parent_ref'] = process.id
            if attributes.get('child-pid'):
                for value, uuid in attributes.pop('child-pid'):
                    process_id = f"process--{uuid}"
                    objects.append(Process(id=process_id, pid=value))
                    process_args['child_refs'].append(process_id)
            if attributes.get('image'):
                filename, uuid = attributes.pop('image')
                image_uuid = f'file--{uuid}'
                objects.append(File(id=image_uuid, name=filename))
                process_args['image_ref'] = image_uuid
            process_args.update(self._parse_process_args(attributes, 'features'))
            objects.insert(0, Process(**process_args))
            self._handle_object_observable(misp_object, objects)

    def _parse_registry_key_object_observable(self, misp_object: dict):
        registry_key_args = self._parse_registry_key_args(misp_object['Attribute'])
        registry_key = WindowsRegistryKey(**registry_key_args)
        self._handle_object_observable(misp_object, [registry_key])

    def _parse_url_object_observable(self, misp_object: dict):
        url_args = self._parse_url_args(misp_object['Attribute'])
        self._handle_object_observable(misp_object, [URL(**url_args)])

    def _parse_user_account_object_observable(self, misp_object: dict):
        user_account_args = self._parse_user_account_args(misp_object['Attribute'])
        user_account = UserAccount(**user_account_args)
        self._handle_object_observable(misp_object, [user_account])

    def _parse_x509_object_observable(self, misp_object: dict):
        x509_args = self._parse_x509_args(misp_object['Attribute'])
        x509_certificate = X509Certificate(**x509_args)
        self._handle_object_observable(misp_object, [x509_certificate])

    ################################################################################
    #                    STIX OBJECTS CREATION HELPER FUNCTIONS                    #
    ################################################################################

    def _create_artifact(self, artifact_id: str, content: str, filename: Optional[str] = None) -> Artifact:
        args = {'id': artifact_id, 'payload_bin': content}
        if filename is not None:
            args['x_misp_filename'] = filename
        return Artifact(**args)

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

    @staticmethod
    def _create_email_address(address_id: str, email_address: str) -> EmailAddress:
        return EmailAddress(id=address_id, value=email_address)

    @staticmethod
    def _create_file(file_id: str, filename: str) -> File:
        return File(id=file_id, name=filename)

    @staticmethod
    def _create_file_object(file_args: dict) -> File:
        return File(**file_args)

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

    @staticmethod
    def _create_windowsPESection(section_args: dict) -> WindowsPESection:
        return WindowsPESection(**section_args)

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
