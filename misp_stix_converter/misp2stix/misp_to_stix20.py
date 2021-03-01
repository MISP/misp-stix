#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .misp_to_stix2 import MISPtoSTIX2Parser
from stix2.properties import DictionaryProperty, ListProperty, StringProperty, TimestampProperty
from stix2.v20.bundle import Bundle
from stix2.v20.common import MarkingDefinition
from stix2.v20.observables import (Artifact, AutonomousSystem, DomainName, EmailAddress,
                                   EmailMessage, EmailMIMEComponent, File, IPv4Address,
                                   IPv6Address, MACAddress, Mutex, NetworkTraffic,
                                   WindowsRegistryKey, WindowsRegistryValueType,
                                   X509Certificate)
from stix2.v20.sdo import (CustomObject, Identity, Indicator, ObservedData, Report,
                           Vulnerability)
from typing import Union


class MISPtoSTIX20Parser(MISPtoSTIX2Parser):
    def __init__(self):
        super().__init__()
        self._version = '2.0'

    def _handle_unpublished_report(self, report_args: dict) -> Report:
        report_args.update(
            {
                'id': f"report--{self._misp_event['uuid']}",
                'type': 'report',
                'published': report_args['modified']
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
            '1': Artifact(
                payload_bin=attribute['data']
            )
        }
        self._create_observed_data(attribute, observable_object)

    def _parse_autonomous_system_attribute_observable(self, attribute: dict):
        observable_object = {
            '0': AutonomousSystem(number=self._parse_AS_value(attribute['value']))
        }
        self._create_observed_data(attribute, observable_object)

    def _parse_domain_attribute_observable(self, attribute: dict):
        observable_object = {
            '0': DomainName(value=attribute['value'])
        }
        self._create_observed_data(attribute, observable_object)

    def _parse_domain_ip_attribute_observable(self, attribute: dict):
        domain, ip = attribute['value'].split('|')
        address_type = self._get_address_type(ip)
        address_object = address_type(value=ip)
        observable_object = {
            '0': DomainName(
                value=domain,
                _valid_refs={'1': address_object._type},
                resolves_to_refs=['1']
            ),
            '1': address_object
        }
        self._create_observed_data(attribute, observable_object)

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
            '1': File(name=attribute['value'])
        }
        self._create_observed_data(attribute, observable_object)

    def _parse_email_attribute_observable(self, attribute: dict):
        observable_object = {
            '0': EmailAddress(
                value=attribute['value']
            )
        }
        self._create_observed_data(attribute, observable_object)

    def _parse_email_body_attribute_observable(self, attribute: dict):
        observable_object = {
            '0': EmailMessage(
                is_multipart=False,
                body=attribute['value']
            )
        }
        self._create_observed_data(attribute, observable_object)

    def _parse_email_destination_attribute_observable(self, attribute: dict):
        observable_object = {
            '0': EmailMessage(
                is_multipart=False,
                _valid_refs={'1': 'email-addr'},
                to_refs=['1']
            ),
            '1': EmailAddress(
                value=attribute['value']
            )
        }
        self._create_observed_data(attribute, observable_object)

    def _parse_email_header_attribute_observable(self, attribute: dict):
        observable_object = {
            '0': EmailMessage(
                is_multipart=False,
                received_lines=[attribute['value']]
            )
        }
        self._create_observed_data(attribute, observable_object)

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
        self._create_observed_data(attribute, observable_object)

    def _parse_email_source_attribute_observable(self, attribute: dict):
        observable_object = {
            '0': EmailMessage(
                is_multipart=False,
                _valid_refs={'1': 'email-addr'},
                from_ref='1'
            ),
            '1': EmailAddress(
                value=attribute['value']
            )
        }
        self._create_observed_data(attribute, observable_object)

    def _parse_email_subject_attribute_observable(self, attribute: dict):
        observable_object = {
            '0': EmailMessage(
                is_multipart=False,
                subject=attribute['value']
            )
        }
        self._create_observed_data(attribute, observable_object)

    def _parse_email_x_mailer_attribute_observable(self, attribute: dict):
        observable_object = {
            '0': EmailMessage(
                is_multipart=False,
                additional_header_fields={
                    "X-Mailer": attribute['value']
                }
            )
        }
        self._create_observed_data(attribute, observable_object)

    def _parse_filename_attribute_observable(self, attribute: dict):
        observable_object = {
            '0': File(name=attribute['value'])
        }
        self._create_observed_data(attribute, observable_object)

    def _parse_hash_attribute_observable(self, attribute: dict):
        observable_object = {
            '0': File(
                hashes={
                    self._define_hash_type(attribute['type']): attribute['value']
                }
            )
        }
        self._create_observed_data(attribute, observable_object)

    def _parse_hash_composite_attribute_observable(self, attribute: dict):
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
        self._create_observed_data(attribute, observable_object)

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
        self._create_observed_data(attribute, observable_object)

    def _parse_ip_attribute_observable(self, attribute: dict):
        address_type = self._get_address_type(attribute['value'])
        address_object = address_type(value=attribute['value'])
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
        self._create_observed_data(attribute, observable_object)

    def _parse_ip_port_attribute_observable(self, attribute: dict):
        ip_value, port_value = attribute['value'].split('|')
        address_type = self._get_address_type(ip_value)
        address_object = address_type(value=ip_value)
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
        self._create_observed_data(attribute, observable_object)

    def _parse_mac_address_attribute_observable(self, attribute: dict):
        observable_object = {
            '0': MACAddress(value=attribute['value'])
        }
        self._create_observed_data(attribute, observable_object)

    def _parse_mutex_attribute_observable(self, attribute: dict):
        observable_object = {
            '0': Mutex(name=attribute['value'])
        }
        self._create_observed_data(attribute, observable_object)

    def _parse_regkey_attribute_observable(self, attribute: dict):
        observable_object = {
            '0': WindowsRegistryKey(
                key=attribute['value'].strip()
            )
        }
        self._create_observed_data(attribute, observable_object)

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
        self._create_observed_data(attribute, observable_object)

    def _parse_x509_fingerprint_attribute_observable(self, attribute: dict):
        hash_type = attribute['type'].split('-')[-1]
        observable_object = {
            '0': X509Certificate(
                hashes={
                    self._define_hash_type(hash_type): attribute['value']
                }
            )
        }
        self._create_observed_data(attribute, observable_object)

    ################################################################################
    #                    STIX OBJECTS CREATION HELPER FUNCTIONS                    #
    ################################################################################

    def _create_bundle(self) -> Bundle:
        return Bundle(self._objects)

    @staticmethod
    def _create_custom_object(object_type, custom_args):
        stix_labels = ListProperty(StringProperty)
        stix_labels.clean(custom_args['labels'])
        stix_markings = ListProperty(StringProperty)
        if custom_args.get('markings'):
            stix_markings.clean(custom_args['markings'])
        @CustomObject(object_type, [
            ('id', StringProperty(required=True)),
            ('labels', ListProperty(stix_labels, required=True)),
            ('x_misp_value', StringProperty(required=True)),
            ('created', TimestampProperty(required=True, precision='millisecond')),
            ('modified', TimestampProperty(required=True, precision='millisecond')),
            ('created_by_ref', StringProperty(required=True)),
            ('object_marking_refs', ListProperty(stix_markings)),
            ('x_misp_comment', StringProperty()),
            ('x_misp_category', StringProperty())
        ])
        class Custom(object):
            def __init__(self, **kwargs):
                return
        return Custom(**custom_args)

    @staticmethod
    def _create_grouping(grouping_args):
        return Grouping(**grouping_args)

    def _create_identity_object(self, orgname: str) -> Identity:
        identity_args = {
            'type': 'identity',
            'id': self._identity_id,
            'name': orgname,
            'identity_class': 'organization',
            'interoperability': True
        }
        return Identity(**identity_args)

    @staticmethod
    def _create_indicator(indicator_args: dict) -> Indicator:
        return Indicator(**indicator_args)

    def _create_marking(self, marking: str) -> Union[str, None]:
        if marking in stix2_mapping.tlp_markings_v20:
            marking_definition = deepcopy(stix2_mapping.tlp_markings_v20[marking])
            self._markings[marking] = marking_definition
            return marking_definition.id
        marking_args = self._create_marking_definition_args(marking)
        try:
            self._markings[marking] = MarkingDefinition(**marking_args)
        except (TLPMarkingDefinitionError, ValueError):
            return
        return marking_args['id']

    def _create_observed_data(self, attribute: dict, observable: dict):
        observable_args = self._create_observable_args(attribute)
        observable_args['objects'] = observable
        observable = ObservedData(**observable_args)
        self._append_SDO(observable)

    @staticmethod
    def _create_report(report_args: dict) -> Report:
        return Report(**report_args)

    @staticmethod
    def _create_vulnerability(vulnerability_args: dict) -> Vulnerability:
        return Vulnerability(**vulnerability_args)

    ################################################################################
    #                              UTILITY FUNCTIONS.                              #
    ################################################################################

    @staticmethod
    def _get_address_type(address):
        if ':' in address:
            return IPv6Address
        return IPv4Address
