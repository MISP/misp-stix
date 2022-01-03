#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from .misp_to_stix2 import MISPtoSTIX2Parser
from .stix21_mapping import Stix21Mapping
from collections import defaultdict
from datetime import datetime
from stix2.properties import (DictionaryProperty, IDProperty, ListProperty,
                              ObjectReferenceProperty, ReferenceProperty,
                              StringProperty, TimestampProperty)
from stix2.v21.bundle import Bundle
from stix2.v21.observables import (Artifact, AutonomousSystem, Directory, DomainName,
    EmailAddress, EmailMessage, EmailMIMEComponent, File, IPv4Address, IPv6Address,
    MACAddress, Mutex, NetworkTraffic, Process, URL, UserAccount, WindowsPEBinaryExt,
    WindowsPESection, WindowsRegistryKey, WindowsRegistryValueType, X509Certificate)
from stix2.v21.sdo import (AttackPattern, Campaign, CourseOfAction, CustomObject,
    Grouping, Identity, Indicator, IntrusionSet, Location, Malware, Note,
    ObservedData, Opinion, Report, ThreatActor, Tool, Vulnerability)
from stix2.v21.sro import Relationship, Sighting
from stix2.v21.vocab import HASHING_ALGORITHM
from typing import Optional, Union

_OBSERVABLE_OBJECT_TYPES = Union[
    AutonomousSystem
]


@CustomObject(
    'x-misp-attribute',
    [
        ('id', IDProperty('x-misp-attribute', spec_version='2.1')),
        ('labels', ListProperty(StringProperty, required=True)),
        ('created', TimestampProperty(required=True, precision='millisecond')),
        ('modified', TimestampProperty(required=True, precision='millisecond')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('x_misp_type', StringProperty(required=True)),
        ('x_misp_value', StringProperty(required=True)),
        ('x_misp_comment', StringProperty()),
        ('x_misp_category', StringProperty())
    ]
)
class CustomAttribute():
    pass


@CustomObject(
    'x-misp-object',
    [
        ('id', IDProperty('x-misp-object', spec_version='2.1')),
        ('labels', ListProperty(StringProperty, required=True)),
        ('created', TimestampProperty(required=True, precision='millisecond')),
        ('modified', TimestampProperty(required=True, precision='millisecond')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('x_misp_name', StringProperty(required=True)),
        ('x_misp_attributes', ListProperty(DictionaryProperty())),
        ('x_misp_comment', StringProperty()),
        ('x_misp_meta_category', StringProperty())
    ]
)
class CustomMispObject():
    pass


class MISPtoSTIX21Parser(MISPtoSTIX2Parser):
    def __init__(self, interoperability=False):
        super().__init__(interoperability)
        self._version = '2.1'
        self._mapping = Stix21Mapping()

    def _parse_event_data(self):
        if self._misp_event.get('EventReport'):
            self._id_parsing_function = {
                'attribute': '_define_stix_object_id_from_attribute',
                'object': '_define_stix_object_id_from_object'
            }
            self._event_report_matching = {}
            self._handle_attributes_and_objects()
            regex = r'@[!]?\[%s\]\([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\)'
            for event_report in self._misp_event['EventReport']:
                timestamp = self._datetime_from_timestamp(event_report['timestamp'])
                note_args = {
                    'id': f"note--{event_report['uuid']}",
                    'created': timestamp,
                    'modified': timestamp,
                    'created_by_ref': self.identity_id,
                    'content': event_report['content'],
                    'abstract': event_report['name']
                }
                references = {reference.split('(')[1][:-1] for feature in ('attribute', 'object') for reference in re.findall(regex % feature, event_report['content'])}
                note_args['object_refs'] = list({self._event_report_matching[reference] for reference in references if reference in self._event_report_matching})
                self._append_SDO(Note(**note_args))
        else:
            self._handle_attributes_and_objects()

    def _define_stix_object_id_from_attribute(self, feature: str, attribute: dict) -> str:
        attribute_uuid = attribute['uuid']
        stix_id = f'{feature}--{attribute_uuid}'
        self._event_report_matching[attribute_uuid] = stix_id
        return stix_id

    def _define_stix_object_id_from_object(self, feature: str, misp_object: dict) -> str:
        object_uuid = misp_object['uuid']
        stix_id = f'{feature}--{object_uuid}'
        self._event_report_matching[object_uuid] = stix_id
        for attribute in misp_object['Attribute']:
            self._event_report_matching[attribute['uuid']] = stix_id
        return stix_id

    def _handle_attributes_and_objects(self):
        if self._misp_event.get('Attribute'):
            for attribute in self._misp_event['Attribute']:
                self._resolve_attribute(attribute)
        if self._misp_event.get('Object'):
            self._objects_to_parse = defaultdict(dict)
            self._resolve_objects()
            if self._objects_to_parse:
                self._resolve_objects_to_parse()

    def _handle_empty_object_refs(self, object_id: str, timestamp: datetime):
        note_args = {
            'id': f"note--{self._misp_event['uuid']}",
            'created': timestamp,
            'modified': timestamp,
            'created_by_ref': self.identity_id,
            'content': 'This MISP Event is empty and contains no attribute, object, galaxy or tag.',
            'object_refs': [object_id]
        }
        self._append_SDO(Note(**note_args))

    def _handle_opinion_object(self, authors: set, reference_id: str):
        opinion_args = {
            'authors': list(authors),
            'explanation': 'False positive Sighting',
            'opinion': 'strongly-disagree',
            'type': 'opinion',
            'object_refs': [reference_id]
        }
        getattr(self, self._results_handling_function)(Opinion(**opinion_args))

    def _handle_unpublished_report(self, report_args: dict) -> Grouping:
        grouping_id = f"grouping--{self._misp_event['uuid']}"
        if not self.object_refs:
            self._handle_empty_object_refs(grouping_id, report_args['modified'])
        report_args.update(
            {
                'id': grouping_id,
                'type': 'grouping',
                'context': 'suspicious-activity',
                'object_refs': self.object_refs,
                'allow_custom': True
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
            value = self._handle_value_for_pattern(attribute['value'])
            pattern = f"[email-message:message_id = '{value}']"
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
                "Reply-To": attribute['value']
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
        hash_type = self._define_hash_type(attribute['type'])
        file_args = {
            'id': f"file--{attribute['uuid']}",
            'hashes': {
                hash_type: attribute['value']
            }
        }
        if hash_type not in HASHING_ALGORITHM:
            file_args['allow_custom'] = True
        file_object = File(**file_args)
        self._handle_attribute_observable(attribute, [file_object])

    def _parse_hash_composite_attribute_observable(self, attribute: dict, hash_type: Optional[str] = None):
        if hash_type is None:
            hash_type = attribute['type'].split('|')[1]
        hash_type = self._define_hash_type(hash_type)
        filename, hash_value = attribute['value'].split('|')
        file_args = {
            'id': f"file--{attribute['uuid']}",
            'name': filename,
            'hashes': {
                hash_type: hash_value
            }
        }
        if hash_type not in HASHING_ALGORITHM:
            file_args['allow_custom'] = True
        file_object = File(**file_args)
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
            value=attribute['value'].lower()
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

    def _parse_patterning_language_attribute(self, attribute: dict):
        indicator_args = {
            'pattern_type': attribute['type']
        }
        self._handle_attribute_indicator(attribute, f"[{attribute['value']}]", indicator_args=indicator_args)

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
            value = [attribute['value']]
            if relation in with_data and attribute.get('data'):
                value.append(attribute['data'])
            value.append(attribute['uuid'])
            attributes_dict[relation].append(tuple(value))
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

    def _handle_file_observable_object(self, args: dict) -> list:
        return [self._create_file_object(args)]

    def _handle_file_observable_objects(self, args: dict, objects: list):
        objects.insert(0, self._create_file_object(args))

    def _parse_account_object_observable(self, misp_object: dict, account_type: str):
        account_args = self._parse_account_args(misp_object['Attribute'], account_type)
        account_object = UserAccount(**account_args)
        self._handle_object_observable(misp_object, [account_object])

    def _parse_asn_object_observable(self, misp_object: dict):
        as_args = self._parse_AS_args(misp_object['Attribute'])
        AS_object = AutonomousSystem(**as_args)
        self._handle_object_observable(misp_object, [AS_object])

    def _parse_credential_object_observable(self, misp_object: dict):
        credential_args = self._parse_credential_args(misp_object['Attribute'])
        user_object = UserAccount(**credential_args)
        self._handle_object_observable(misp_object, [user_object])

    def _parse_domain_ip_object_custom(self, attributes: dict) -> list:
        observable_objects, resolves_to_refs = self._parse_domainip_ip_attributes(attributes)
        domain_args = {
            'resolves_to_refs': resolves_to_refs
        }
        domain_args.update(self._parse_domain_args(attributes))
        observable_objects.insert(0, DomainName(**domain_args))
        return observable_objects

    def _parse_domain_ip_object_observable(self, misp_object: dict):
        attributes = self._extract_object_attributes_with_multiple_and_uuid(
            misp_object['Attribute'],
            force_single=self._mapping.domain_ip_single_fields,
            with_uuid=self._mapping.domain_ip_uuid_fields
        )
        if not any(feature in attributes for feature in ('domain', 'hostname')):
            self._parse_custom_object(misp_object)
            self._required_fields_missing_warning('DomainName', 'domain-ip')
            return
        function = '_parse_domain_ip_object_standard'
        if any(attribute not in self._mapping.domain_ip_uuid_fields for attribute in attributes):
            function = '_parse_domain_ip_object_custom'
            if attributes.get('hostname'):
                attributes['hostname'] = attributes.pop('hostname')[0]
            if attributes.get('domain'):
                attributes['domain'] = [domain[0] for domain in attributes.pop('domain')]
        observable_objects = getattr(self, function)(attributes)
        self._handle_object_observable(misp_object, observable_objects)

    def _parse_domain_ip_object_standard(self, attributes: dict) -> list:
        observable_objects, resolves_to_refs = self._parse_domainip_ip_attributes(attributes)
        if attributes.get('hostname'):
            value, uuid = attributes.pop('hostname')
            domain_args = {
                'id': f'domain-name--{uuid}',
                'value': value,
                'resolves_to_refs': resolves_to_refs
            }
            observable_objects.append(DomainName(**domain_args))
        if attributes.get('domain'):
            for domain in attributes.get('domain'):
                value, uuid = domain
                domain_args = {
                    'id': f'domain-name--{uuid}',
                    'value': value,
                    'resolves_to_refs': resolves_to_refs
                }
                observable_objects.append(DomainName(**domain_args))
        return observable_objects

    def _parse_domainip_ip_attributes(self, attributes: dict) -> tuple:
        observable_objects = []
        resolves_to_refs = []
        if attributes.get('ip'):
            for ip_value, uuid in attributes.pop('ip'):
                address_type = self._get_address_type(ip_value)
                address_id = f'{address_type._type}--{uuid}'
                observable_objects.append(address_type(id=address_id, value=ip_value))
                resolves_to_refs.append(address_id)
        return observable_objects, resolves_to_refs

    def _parse_email_object_observable(self, misp_object: dict):
        attributes = self._extract_multiple_object_attributes_with_uuid_and_data(
            misp_object['Attribute'],
            with_uuid=self._mapping.email_uuid_fields,
            with_data=self._mapping.email_data_fields
        )
        objects = []
        email_message_args = defaultdict(dict)
        email_message_args['is_multipart'] = False
        if attributes.get('from'):
            display_names = self._parse_email_display_names(attributes, 'from')
            value, uuid = self._select_single_feature(attributes, 'from')
            address_id = f'email-addr--{uuid}'
            email_address = self._create_email_address(
                address_id,
                value,
                display_name=display_names.get(value)
            )
            objects.append(email_address)
            email_message_args['from_ref'] = address_id
        for feature in ('to', 'cc', 'bcc'):
            if attributes.get(feature):
                display_names = self._parse_email_display_names(attributes, feature)
                references = []
                for value, uuid in attributes.pop(feature):
                    address_id = f'email-addr--{uuid}'
                    email_address = self._create_email_address(
                        address_id,
                        value,
                        display_name=display_names.get(value)
                    )
                    objects.append(email_address)
                    references.append(address_id)
                email_message_args[f'{feature}_refs'] = references
        if any(key in attributes for key in self._mapping.email_data_fields):
            body_multipart = []
            for feature in self._mapping.email_data_fields:
                if attributes.get(feature):
                    for attribute in attributes.pop(feature):
                        if len(attribute) == 3:
                            value, data, uuid = attribute
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
            if attributes.get('from'):
                attributes['from'] = [value[0] for value in attributes.pop('from')]
            email_message_args.update(self._parse_email_args(attributes))
        objects.insert(0, EmailMessage(**email_message_args))
        self._handle_object_observable(misp_object, objects)

    def _parse_file_observable_object(self, attributes: list) -> tuple:
        attributes = self._extract_multiple_object_attributes_with_uuid_and_data(
            attributes,
            with_uuid=self._mapping.file_uuid_fields,
            with_data=self._mapping.file_data_fields
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
            if len(value) == 3:
                value, data, uuid = value
                artifact_id = f'artifact--{uuid}'
                args = self._create_malware_sample_args(value, data)
                args['id'] = artifact_id
                objects.append(Artifact(**args))
                file_args['content_ref'] = artifact_id
            else:
                file_args.update(
                    {
                        'allow_custom': True,
                        'x_misp_malware_sample': value[0]
                    }
                )
            if attributes.get('attachment'):
                value = self._select_single_feature(attributes, 'attachment')
                file_args.update(self._parse_custom_attachment(value))
        elif attributes.get('attachment'):
            value = self._select_single_feature(attributes, 'attachment')
            if len(value) == 3:
                filename, data, uuid = value
                args = self._create_attachment_args(filename, data)
                args['id'] = f'artifact--{uuid}'
                objects.append(Artifact(**args))
            else:
                file_args.update(
                    {
                        'allow_custom': True,
                        'x_misp_attachment': value[0]
                    }
                )
        if attributes:
            file_args.update(self._parse_file_args(attributes))
        return file_args, objects

    def _parse_geolocation_object(self, misp_object: dict):
        location_id = getattr(self, self._id_parsing_function['object'])('location', misp_object)
        timestamp = self._datetime_from_timestamp(misp_object['timestamp'])
        location_args = {
            'id': location_id,
            'created': timestamp,
            'modified': timestamp,
            'labels': self._create_object_labels(
                misp_object,
                to_ids=self._fetch_ids_flag(misp_object['Attribute'])
            ),
            'interoperability': True
        }
        if misp_object.get('comment'):
            location_args['description'] = misp_object['comment']
        markings = self._handle_object_tags_and_galaxies(
            misp_object,
            location_id,
            location_args['modified']
        )
        if markings:
            self._handle_markings(location_args, markings)
        attributes = self._extract_object_attributes(misp_object['Attribute'])
        if attributes.get('accuracy-radius') and attributes.get('latitude') and attributes.get('longitude'):
            precision = float(attributes.pop('accuracy-radius')) * 1000
            location_args['precision'] = precision
        for key, feature in self._mapping.geolocation_object_mapping.items():
            if attributes.get(key):
                location_args[feature] = attributes.pop(key)
        if attributes:
            location_args.update(self._handle_observable_properties(attributes))
        self._append_SDO(Location(**location_args))

    def _parse_ip_port_object_observable(self, misp_object: dict):
        attributes = self._extract_object_attributes_with_multiple_and_uuid(
            misp_object['Attribute'],
            force_single=self._mapping.ip_port_single_fields,
            with_uuid=self._mapping.ip_port_uuid_fields
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

    def _parse_mutex_object_observable(self, misp_object: dict):
        mutex_args = self._parse_mutex_args(misp_object['Attribute'])
        self._handle_object_observable(misp_object, [Mutex(**mutex_args)])

    def _parse_network_connection_object_observable(self, misp_object: dict):
        attributes = self._extract_object_attributes_with_uuid(
            misp_object['Attribute'],
            with_uuid=self._mapping.network_traffic_uuid_fields
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
            pattern = self._parse_network_socket_object_pattern(misp_object['Attribute'])
            self._handle_object_indicator(misp_object, pattern)
        else:
            attributes = self._extract_object_attributes_with_multiple_and_uuid(
                misp_object['Attribute'],
                force_single=self._mapping.network_socket_single_fields,
                with_uuid=self._mapping.network_traffic_uuid_fields
            )
            network_traffic_args, objects = self._parse_network_references(attributes)
            if attributes:
                network_traffic_args.update(self._parse_network_socket_args(attributes))
            objects.insert(0, NetworkTraffic(**network_traffic_args))
            self._handle_object_observable(misp_object, objects)

    def _parse_process_object(self, misp_object: dict):
        if self._fetch_ids_flag(misp_object['Attribute']):
            pattern = self._parse_process_object_pattern(misp_object['Attribute'])
            self._handle_object_indicator(misp_object, pattern)
        else:
            attributes = self._extract_object_attributes_with_multiple_and_uuid(
                misp_object['Attribute'],
                force_single=self._mapping.process_single_fields,
                with_uuid=self._mapping.process_uuid_fields
            )
            objects = []
            parent_attributes = self._extract_parent_process_attributes(attributes)
            process_args = defaultdict(list)
            if parent_attributes:
                parent_args = {}
                if parent_attributes.get('parent-image'):
                    filename, uuid = parent_attributes.pop('parent-image')
                    image_uuid = f'file--{uuid}'
                    objects.append(File(id=image_uuid, name=filename))
                    parent_args['image_ref'] = image_uuid
                for feature in self._mapping.parent_process_fields:
                    if parent_attributes.get(feature):
                        parent_args['id'] = f"process--{parent_attributes[feature][1]}"
                        break
                for key, feature in self._mapping.process_object_mapping['parent'].items():
                    if parent_attributes.get(key):
                        parent_args[feature] = parent_attributes.pop(key)[0]
                if parent_attributes:
                    parent_args.update(self._handle_parent_process_properties(parent_attributes))
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

    @staticmethod
    def _parse_regkey_key_values_observable(attributes: dict) -> dict:
        registry_key_args = {}
        if attributes.get('key'):
            registry_key_args['key'] = attributes.pop('key')
        if attributes.get('last-modified'):
            modified = attributes.pop('last-modified')
            if not modified.endswith('Z'):
                modified = f"{modified}Z"
            registry_key_args['modified_time'] = modified
        return registry_key_args

    def _parse_regkey_key_values_pattern(self, attributes: dict, prefix: str) -> list:
        pattern = []
        if attributes.get('key'):
            value = self._sanitize_registry_key_value(attributes.pop('key').strip("'").strip('"'))
            pattern.append(f"{prefix}:key = '{value}'")
        if attributes.get('last-modified'):
            modified = self._handle_value_for_pattern(attributes.pop('last-modified'))
            pattern.append(f"{prefix}:modified_time = '{modified}'")
        return pattern

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
            args.update(
                {
                    'allow_custom': True,
                    'x_misp_filename': filename
                }
            )
        return Artifact(**args)

    def _create_attack_pattern_from_galaxy(self, args: dict, cluster: dict) -> AttackPattern:
        args['kill_chain_phases'] = self._create_killchain(cluster['type'])
        if cluster.get('meta', {}).get('synonyms'):
            args['aliases'] = cluster['meta']['synonyms']
        return AttackPattern(**args)

    @staticmethod
    def _create_attack_pattern(attack_pattern_args: dict) -> AttackPattern:
        return AttackPattern(**attack_pattern_args)

    def _create_bundle(self) -> Bundle:
        return Bundle(self.stix_objects, allow_custom=True)

    @staticmethod
    def _create_campaign(campaign_args: dict) -> Campaign:
        return Campaign(**campaign_args)

    @staticmethod
    def _create_course_of_action(course_of_action_args: dict) -> CourseOfAction:
        return CourseOfAction(**course_of_action_args)

    def _create_custom_attribute(self, custom_args: dict) -> CustomAttribute:
        self._clean_custom_properties(custom_args)
        return CustomAttribute(**custom_args)

    def _create_custom_object(self, custom_args: dict) -> CustomMispObject:
        self._clean_custom_properties(custom_args)
        return CustomMispObject(**custom_args)

    @staticmethod
    def _create_email_address(address_id: str, email_address: str, display_name: Optional[str] = None) -> EmailAddress:
        args = {
            'id': address_id,
            'value': email_address
        }
        if display_name is not None:
            args['display_name'] = display_name
        return EmailAddress(**args)

    @staticmethod
    def _create_file(file_id: str, filename: str) -> File:
        return File(id=file_id, name=filename)

    @staticmethod
    def _create_file_object(file_args: dict) -> File:
        return File(**file_args)

    @staticmethod
    def _create_identity(identity_args: dict) -> Identity:
        return Identity(**identity_args)

    def _create_identity_object(self, orgname: str) -> Identity:
        timestamp = self._datetime_from_timestamp(self._misp_event['timestamp'])
        identity_args = {
            'type': 'identity',
            'id': self.identity_id,
            'created': timestamp,
            'modified': timestamp,
            'name': orgname,
            'identity_class': 'organization',
            'interoperability': True
        }
        return Identity(**identity_args)

    @staticmethod
    def _create_indicator(indicator_args: dict) -> Indicator:
        indicator_args['spec_version'] = '2.1'
        if indicator_args.get('pattern_type') is None:
            indicator_args.update(
                {
                    "pattern_type": "stix",
                    "pattern_version": "2.1",
                }
            )
        return Indicator(**indicator_args)

    @staticmethod
    def _create_intrusion_set(intrusion_set_args: dict) -> IntrusionSet:
        return IntrusionSet(**intrusion_set_args)

    def _create_malware(self, malware_args: dict, cluster: Optional[dict]=None) -> Malware:
        if cluster is not None:
            malware_args.update(
                {
                    'kill_chain_phases': self._create_killchain(cluster['type']),
                    'is_family': True
                }
            )
            if cluster.get('meta', {}).get('synonyms'):
                malware_args['aliases'] = cluster['meta']['synonyms']
        if 'is_family' not in malware_args:
            malware_args['is_family'] = False
        return Malware(**malware_args)

    def _create_observed_data(self, args: dict, observables: list):
        args['object_refs'] = [observable.id for observable in observables]
        getattr(self, self._results_handling_function)(ObservedData(**args))
        for observable in observables:
            getattr(self, self._results_handling_function)(observable)

    @staticmethod
    def _create_PE_extension(extension_args: dict) -> WindowsPEBinaryExt:
        return WindowsPEBinaryExt(**extension_args)

    @staticmethod
    def _create_relationship(relationship_args: dict) -> Relationship:
        return Relationship(**relationship_args)

    @staticmethod
    def _create_report(report_args: dict) -> Report:
        return Report(**report_args)

    @staticmethod
    def _create_sighting(sighting_args: dict) -> Sighting:
        return Sighting(**sighting_args)

    @staticmethod
    def _create_threat_actor(threat_actor_args: dict) -> ThreatActor:
        return ThreatActor(**threat_actor_args)

    def _create_tool(self, tool_args: dict, cluster: Optional[dict]=None) -> Tool:
        if cluster is not None:
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
    #                         PATTERNS CREATION FUNCTIONS.                         #
    ################################################################################

    @staticmethod
    def _create_credential_pattern(attributes: dict) -> list:
        pattern = []
        if attributes.get('username'):
            pattern.append(f"user-account:user_id = '{attributes.pop('username')}'")
        if attributes.get('password'):
            for value in attributes.pop('password'):
                pattern.append(f"user-account:credential = '{value}'")
        return pattern

    @staticmethod
    def _create_process_image_pattern(image: str) -> str:
        return f"process:image_ref.name = '{image}'"

    ################################################################################
    #                              UTILITY FUNCTIONS.                              #
    ################################################################################

    @staticmethod
    def _get_address_type(address: str) -> Union[IPv4Address, IPv6Address]:
        if ':' in address:
            return IPv6Address
        return IPv4Address

    def _parse_email_display_names(self, attributes: dict, feature: str) -> dict:
        display_feature = f'{feature}-display-name'
        display_names = {}
        if attributes.get(display_feature):
            if len(attributes[feature]) == len(attributes[display_feature]) == 1:
                display_names[attributes[feature][0][0]] = attributes.pop(display_feature)[0]
                return display_names
            for value in attributes[feature]:
                value = value[0]
                index = self._get_matching_email_display_name(attributes[display_feature], value)
                if index is not None:
                    display_names[value] = attributes[display_feature].pop(index)
                if not attributes[display_feature]:
                    del attributes[display_feature]
                    break
        return display_names
