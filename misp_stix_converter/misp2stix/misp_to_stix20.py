#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .misp_to_stix2 import MISPtoSTIX2Parser
from .stix20_mapping import Stix20Mapping
from collections import defaultdict
from datetime import datetime
from stix2.properties import (DictionaryProperty, IDProperty, ListProperty,
                              ReferenceProperty, StringProperty, TimestampProperty)
from stix2.v20.bundle import Bundle
from stix2.v20.observables import (Artifact, AutonomousSystem, Directory, DomainName,
    EmailAddress, EmailMessage, EmailMIMEComponent, File, IPv4Address, IPv6Address,
    MACAddress, Mutex, NetworkTraffic, Process, Software, URL, UserAccount,
    WindowsPEBinaryExt, WindowsPESection, WindowsRegistryKey, WindowsRegistryValueType,
    X509Certificate)
from stix2.v20.sdo import (AttackPattern, Campaign, CourseOfAction, CustomObject,
    Identity, Indicator, IntrusionSet, Malware, ObservedData, Report, ThreatActor,
    Tool, Vulnerability)
from stix2.v20.sro import Relationship, Sighting
from stix2.v20.vocab import HASHING_ALGORITHM
from typing import Optional, Union


@CustomObject(
    'x-misp-attribute',
    [
        ('id', IDProperty('x-misp-attribute')),
        ('labels', ListProperty(StringProperty, required=True)),
        ('created', TimestampProperty(required=True, precision='millisecond')),
        ('modified', TimestampProperty(required=True, precision='millisecond')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.0')),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.0'))),
        ('x_misp_type', StringProperty(required=True)),
        ('x_misp_value', StringProperty(required=True)),
        ('x_misp_comment', StringProperty()),
        ('x_misp_category', StringProperty())
    ]
)
class CustomAttribute:
    pass


@CustomObject(
    'x-misp-object',
    [
        ('id', IDProperty('x-misp-object')),
        ('labels', ListProperty(StringProperty, required=True)),
        ('created', TimestampProperty(required=True, precision='millisecond')),
        ('modified', TimestampProperty(required=True, precision='millisecond')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.0')),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.0'))),
        ('x_misp_name', StringProperty(required=True)),
        ('x_misp_attributes', ListProperty(DictionaryProperty())),
        ('x_misp_comment', StringProperty()),
        ('x_misp_meta_category', StringProperty())
    ]
)
class CustomMispObject:
    pass


@CustomObject(
    'x-misp-event-note',
    [
        ('id', IDProperty('x-misp-event-note')),
        ('created', TimestampProperty(required=True, precision='millisecond')),
        ('modified', TimestampProperty(required=True, precision='millisecond')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.0')),
        ('x_misp_event_note', StringProperty(required=True)),
        ('object_ref', ReferenceProperty(valid_types=['report'], spec_version='2.0'))
    ]
)
class CustomNote:
    pass


@CustomObject(
    'x-misp-opinion',
    [
        ('x_misp_authors', ListProperty(StringProperty)),
        ('x_misp_explanation', StringProperty()),
        ('x_misp_opinion', StringProperty(required=True)),
        ('object_ref', ReferenceProperty(
            valid_types=['campaign', 'indicator', 'observed-data', 'vulnerability', 'x-misp-attribute'],
            spec_version='2.0'
        ))
    ]
)
class CustomOpinion:
    pass


class MISPtoSTIX20Parser(MISPtoSTIX2Parser):
    def __init__(self, interoperability=False):
        super().__init__(interoperability)
        self._version = '2.0'
        self._mapping = Stix20Mapping()

    def _parse_event_data(self):
        if self._misp_event.get('Attribute'):
            for attribute in self._misp_event['Attribute']:
                self._resolve_attribute(attribute)
        if self._misp_event.get('Object'):
            self._objects_to_parse = defaultdict(dict)
            self._resolve_objects()
            if self._objects_to_parse:
                self._resolve_objects_to_parse()

    def _handle_empty_object_refs(self, object_id: str, timestamp: datetime):
        object_type = 'x-misp-event-note'
        custom_args = {
            'id': f"{object_type}--{self._misp_event['uuid']}",
            'created': timestamp,
            'modified': timestamp,
            'created_by_ref': self.identity_id,
            'x_misp_event_note': 'This MISP Event is empty and contains no attribute, object, galaxy or tag.',
            'object_ref': object_id,
            'interoperability': True
        }
        self._append_SDO(CustomNote(**custom_args))

    def _handle_opinion_object(self, authors: set, reference_id: str):
        opinion_args = {
            'object_ref': reference_id,
            'x_misp_authors': list(authors),
            'x_misp_explanation': 'False positive Sighting',
            'x_misp_opinion': 'strongly-disagree'
        }
        getattr(self, self._results_handling_function)(CustomOpinion(**opinion_args))

    def _handle_unpublished_report(self, report_args: dict) -> Report:
        report_id = f"report--{self._misp_event['uuid']}"
        if not self.object_refs:
            self._handle_empty_object_refs(report_id, report_args['modified'])
        report_args.update(
            {
                'id': report_id,
                'type': 'report',
                'published': report_args['modified'],
                'object_refs': self.object_refs,
                'allow_custom': True
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
                    "Reply-To": attribute['value']
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

    def _parse_github_username_attribute_observable(self, attribute: dict):
        self._parse_custom_attribute(attribute)

    def _parse_hash_attribute_observable(self, attribute: dict):
        hash_type = self._define_hash_type(attribute['type'])
        file_args = {
            'hashes': {
                hash_type: attribute['value']
            }
        }
        if hash_type not in HASHING_ALGORITHM:
            file_args['allow_custom'] = True
        observable_object = {
            '0': File(**file_args)
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_hash_composite_attribute_observable(self, attribute: dict, hash_type: Optional[str] = None):
        if hash_type is None:
            hash_type = attribute['type'].split('|')[1]
        hash_type = self._define_hash_type(hash_type)
        filename, hash_value = attribute['value'].split('|')
        file_args = {
            'name': filename,
            'hashes': {
                hash_type: hash_value
            }
        }
        if hash_type not in HASHING_ALGORITHM:
            file_args['allow_custom'] = True
        observable_object = {
            '0': File(**file_args)
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
            '0': MACAddress(value=attribute['value'].lower())
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
            '1': self._create_artifact(attribute['data'], malware_sample=True)
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

    def _handle_file_observable_object(self, args: dict) -> dict:
        return {'0': self._create_file_object(args)}

    def _handle_file_observable_objects(self, args: dict, observable_object: dict):
        observable_object['0'] = self._create_file_object(args)

    def _parse_account_object_observable(self, misp_object: dict, account_type: str):
        account_args = self._parse_account_args(misp_object['Attribute'], account_type)
        observable_object = {'0': UserAccount(**account_args)}
        self._handle_object_observable(misp_object, observable_object)

    def _parse_android_app_object_observable(self, misp_object: dict):
        software_args = self._parse_android_app_args(misp_object['Attribute'])
        observable_object = {'0': Software(**software_args)}
        self._handle_object_observable(misp_object, observable_object)

    def _parse_account_object_with_attachment_observable(self, misp_object: dict, account_type: str):
        account_args = self._parse_account_with_attachment_args(misp_object['Attribute'], account_type)
        observable_object = {'0': UserAccount(**account_args)}
        self._handle_object_observable(misp_object, observable_object)

    def _parse_asn_object_observable(self, misp_object: dict):
        as_args = self._parse_AS_args(misp_object['Attribute'])
        observable_object = {
            '0': AutonomousSystem(**as_args)
        }
        self._handle_object_observable(misp_object, observable_object)

    def _parse_cpe_asset_object_observable(self, misp_object: dict):
        software_args = self._parse_cpe_asset_args(misp_object['Attribute'])
        observable_object = {'0': Software(**software_args)}
        self._handle_object_observable(misp_object, observable_object)

    def _parse_credential_object_observable(self, misp_object: dict):
        credential_args = self._parse_credential_args(misp_object['Attribute'])
        observable_object = {
            '0': UserAccount(**credential_args)
        }
        self._handle_object_observable(misp_object, observable_object)

    def _parse_domain_ip_object_custom(self, misp_object: dict):
        attributes = self._extract_multiple_object_attributes(
            misp_object['Attribute'],
            force_single=self._mapping.domain_ip_single_fields
        )
        index = 1
        domain_args, observable_object, index = self._parse_domainip_ip_attributes(attributes, index)
        domain_args.update(self._parse_domain_args(attributes))
        observable_object['0'] = DomainName(**domain_args)
        self._handle_object_observable(misp_object, observable_object)

    def _parse_domain_ip_object_standard(self, misp_object: dict):
        attributes = self._extract_multiple_object_attributes(
            misp_object['Attribute'],
            force_single=self._mapping.domain_ip_single_fields
        )
        index = 0
        domain_args, observable_object, index = self._parse_domainip_ip_attributes(attributes, index)
        if attributes.get('hostname'):
            args = {
                'value': attributes.pop('hostname')
            }
            args.update(domain_args)
            observable_object[str(index)] = DomainName(**args)
            index += 1
        if attributes.get('domain'):
            for domain in attributes.pop('domain'):
                args = {
                    'value': domain
                }
                args.update(domain_args)
                observable_object[str(index)] = DomainName(**args)
                index += 1
        self._handle_object_observable(misp_object, observable_object)

    def _parse_domainip_ip_attributes(self, attributes: dict, index: int) -> tuple:
        domain_args = {}
        observable_object = {}
        if attributes.get('ip'):
            valid_refs = {}
            for ip_value in attributes.pop('ip'):
                str_index = str(index)
                address_object = self._get_address_type(ip_value)(value=ip_value)
                observable_object[str_index] = address_object
                valid_refs[str_index] = address_object._type
                index += 1
            domain_args['_valid_refs'] = valid_refs
            domain_args['resolves_to_refs'] = list(valid_refs.keys())
        return domain_args, observable_object, index

    def _parse_email_object_observable(self, misp_object: dict):
        attributes = self._extract_multiple_object_attributes_with_data(
            misp_object['Attribute'],
            with_data=self._mapping.email_data_fields
        )
        observable_object = {}
        email_message_args = defaultdict(dict)
        email_message_args['is_multipart'] = False
        index = 1
        if attributes.get('from'):
            display_names = self._parse_email_display_names(attributes, 'from')
            str_index = str(index)
            self._parse_email_object_reference(
                self._select_single_feature(attributes, 'from'),
                display_names,
                email_message_args,
                observable_object,
                str_index
            )
            email_message_args['from_ref'] = str_index
            index += 1
        for feature in ('to', 'cc', 'bcc'):
            if attributes.get(feature):
                references = []
                display_names = self._parse_email_display_names(attributes, feature)
                for value in attributes.pop(feature):
                    str_index = str(index)
                    self._parse_email_object_reference(
                        value,
                        display_names,
                        email_message_args,
                        observable_object,
                        str_index
                    )
                    references.append(str_index)
                    index += 1
                email_message_args[f'{feature}_refs'] = references
        if any(key in attributes for key in self._mapping.email_data_fields):
            body_multipart = []
            for feature in self._mapping.email_data_fields:
                if attributes.get(feature):
                    for value in attributes.pop(feature):
                        str_index = str(index)
                        if isinstance(value, tuple):
                            value, data = value
                            observable_object[str_index] = self._create_artifact(
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

    def _parse_email_object_reference(self, address: str, display_names: dict, email_args: dict, observable: dict, index: str):
        email_address = self._create_email_address(address, display_name=display_names.get(address))
        observable[index] = email_address
        email_args['_valid_refs'][index] = email_address._type

    def _parse_file_observable_object(self, misp_object: dict) -> tuple:
        attributes = self._extract_multiple_object_attributes_with_data(
            misp_object['Attribute'],
            force_single=self._mapping.file_single_fields,
            with_data=self._mapping.file_data_fields
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
        if attributes.get('malware-sample') and isinstance(attributes['malware-sample'], tuple):
            args = self._create_malware_sample_args(*attributes.pop('malware-sample'))
            str_index = str(index)
            observable_object[str_index] = Artifact(**args)
            file_args['content_ref'] = str_index
            file_args['_valid_refs'][str_index] = 'artifact'
            index += 1
            if attributes.get('attachment'):
                file_args.update(self._parse_custom_attachment(attributes.pop('attachment')))
        elif attributes.get('attachment') and isinstance(attributes['attachment'], tuple):
            args = self._create_attachment_args(*attributes.pop('attachment'))
            observable_object[str(index)] = Artifact(**args)
        if attributes:
            file_args.update(self._parse_file_args(attributes))
        return file_args, observable_object

    def _parse_image_object_observable(self, misp_object: dict):
        attributes = self._extract_multiple_object_attributes_with_data(
            misp_object['Attribute'],
            force_single=self._mapping.image_single_fields,
            with_data=self._mapping.image_data_fields
        )
        artifact_args = self._parse_image_args(attributes)
        file_args = {}
        if attributes.get('filename'):
            file_args['name'] = attributes.pop('filename')
        if attributes:
            file_args.update(self._handle_observable_multiple_properties(attributes))
        if artifact_args is not None:
            file_args['content_ref'] = '1'
            file_args['_valid_refs'] = {'1': 'artifact'}
            observable_object = {
                '0': File(**file_args),
                '1': Artifact(**artifact_args)
            }
            self._handle_object_observable(misp_object, observable_object)
        else:
            self._handle_object_observable(misp_object, {'0': File(**file_args)})

    def _parse_ip_port_object_observable(self, misp_object: dict):
        attributes = self._extract_multiple_object_attributes(
            misp_object['Attribute'],
            force_single=self._mapping.ip_port_single_fields
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

    def _parse_lnk_object(self, misp_object: dict):
        if self._fetch_ids_flag(misp_object['Attribute']):
            attributes = self._extract_multiple_object_attributes_with_data_escaped(
                misp_object['Attribute'],
                force_single=self._mapping.lnk_single_fields,
                with_data=self._mapping.lnk_data_fields
            )
            pattern = self._parse_lnk_object_pattern(attributes)
            self._handle_object_indicator(misp_object, pattern)
        else:
            attributes = self._extract_multiple_object_attributes_with_data(
                misp_object['Attribute'],
                force_single=self._mapping.lnk_single_fields,
                with_data=self._mapping.lnk_data_fields
            )
            observable_object = {}
            file_args = {}
            index = 1
            for feature in self._mapping.lnk_path_fields:
                if attributes.get(feature):
                    str_index = str(index)
                    observable_object[str_index] = Directory(
                        path=self._select_single_feature(
                            attributes,
                            feature
                        )
                    )
                    file_args['parent_directory_ref'] = str_index
                    file_args['_valid_refs'] = {str_index: 'directory'}
                    index += 1
                    break
            if attributes.get('malware-sample') and isinstance(attributes['malware-sample'], tuple):
                args = self._create_malware_sample_args(*attributes.pop('malware-sample'))
                str_index = str(index)
                observable_object[str_index] = Artifact(**args)
                file_args['content_ref'] = str_index
                file_args['_valid_refs'][str_index] = 'artifact'
            file_args.update(self._parse_lnk_args(attributes))
            observable_object['0'] = self._create_file_object(file_args)
            self._handle_object_observable(misp_object, observable_object)

    def _parse_mutex_object_observable(self, misp_object: dict):
        mutex_args = self._parse_mutex_args(misp_object['Attribute'])
        self._handle_object_observable(misp_object, {'0': Mutex(**mutex_args)})

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
                network_traffic_args[f'{feature}_ref'] = str_index
                index += 1
        return network_traffic_args, observable_object

    def _parse_network_socket_object(self, misp_object: dict):
        if self._fetch_ids_flag(misp_object['Attribute']):
            pattern = self._parse_network_socket_object_pattern(misp_object['Attribute'])
            self._handle_object_indicator(misp_object, pattern)
        else:
            attributes = self._extract_multiple_object_attributes(
                misp_object['Attribute'],
                force_single=self._mapping.network_socket_single_fields
            )
            network_traffic_args, observable_object = self._parse_network_references(attributes)
            if attributes:
                network_traffic_args.update(self._parse_network_socket_args(attributes))
            observable_object['0'] = NetworkTraffic(**network_traffic_args)
            self._handle_object_observable(misp_object, observable_object)

    def _parse_process_object(self, misp_object: dict):
        if self._fetch_ids_flag(misp_object['Attribute']):
            pattern = self._parse_process_object_pattern(misp_object['Attribute'])
            self._handle_object_indicator(misp_object, pattern)
        else:
            attributes = self._extract_multiple_object_attributes(
                misp_object['Attribute'],
                force_single=self._mapping.process_single_fields
            )
            observable_object = {}
            parent_attributes = self._extract_parent_process_attributes(attributes)
            process_args = defaultdict(dict)
            index = 1
            if parent_attributes:
                str_index = str(index)
                parent_args = {}
                if parent_attributes.get('parent-image'):
                    index += 1
                    str_index2 = str(index)
                    observable_object[str_index2] = File(name=parent_attributes.pop('parent-image'))
                    parent_args['binary_ref'] = str_index2
                    parent_args['_valid_refs'] = {str_index2: 'file'}
                for key, feature in self._mapping.process_object_mapping['parent'].items():
                    if parent_attributes.get(key):
                        parent_args[feature] = parent_attributes.pop(key)
                if parent_attributes:
                    parent_args.update(self._handle_parent_process_properties(parent_attributes))
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
                process_args['binary_ref'] = str_index
                process_args['_valid_refs'][str_index] = 'file'
            process_args.update(self._parse_process_args(attributes, 'features'))
            observable_object['0'] = Process(**process_args)
            self._handle_object_observable(misp_object, observable_object)

    def _parse_registry_key_object_observable(self, misp_object: dict):
        registry_key_args = self._parse_registry_key_args(misp_object['Attribute'])
        observable_object = {'0': WindowsRegistryKey(**registry_key_args)}
        self._handle_object_observable(misp_object, observable_object)

    @staticmethod
    def _parse_regkey_key_values_observable(attributes: dict) -> dict:
        registry_key_args = {}
        if attributes.get('key'):
            registry_key_args['key'] = attributes.pop('key')
        return registry_key_args

    def _parse_regkey_key_values_pattern(self, attributes: dict, prefix: str) -> list:
        pattern = []
        if attributes.get('key'):
            value = self._sanitize_registry_key_value(attributes.pop('key').strip("'").strip('"'))
            pattern.append(f"{prefix}:key = '{value}'")
        return pattern

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

    def _create_artifact(self, content: str, filename: Optional[str] = None, malware_sample: Optional[bool] = False) -> Artifact:
        args = {'payload_bin': content}
        if filename is not None:
            args.update(
                {
                    'allow_custom': True,
                    'x_misp_filename': filename
                }
            )
        if malware_sample:
            args.update(self._mapping.malware_sample_additional_observable_values)
        return Artifact(**args)

    def _create_attack_pattern_from_galaxy(self, args: dict, cluster: dict) -> AttackPattern:
        args['kill_chain_phases'] = self._create_killchain(cluster['type'])
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
    def _create_email_address(email_address: str, display_name: Optional[str] = None) -> EmailAddress:
        args = {
            'value': email_address
        }
        if display_name is not None:
            args['display_name'] = display_name
        return EmailAddress(**args)

    @staticmethod
    def _create_file(name: str) -> File:
        return File(name=name)

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
        return Indicator(**indicator_args)

    @staticmethod
    def _create_intrusion_set(intrusion_set_args: dict) -> IntrusionSet:
        return IntrusionSet(**intrusion_set_args)

    def _create_malware(self, malware_args: dict, cluster: Optional[dict]=None) -> Malware:
        if cluster is not None:
            malware_args['kill_chain_phases'] = self._create_killchain(cluster['type'])
        return Malware(**malware_args)

    def _create_observed_data(self, args: dict, observable: dict):
        args['objects'] = observable
        getattr(self, self._results_handling_function)(ObservedData(**args))

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
        return Tool(**tool_args)

    @staticmethod
    def _create_vulnerability(vulnerability_args: dict) -> Vulnerability:
        return Vulnerability(**vulnerability_args)

    @staticmethod
    def _create_windowsPESection(section_args: dict) -> WindowsPESection:
        return WindowsPESection(**section_args)

    ################################################################################
    #                     OBSERVABLE OBJECT PARSING FUNCTIONS.                     #
    ################################################################################

    def _parse_image_args(self, attributes: dict) -> Union[dict, None]:
        if not any(feature in attributes for feature in ('attachment', 'url')):
            return None
        if attributes.get('attachment'):
            attachment = attributes.pop('attachment')
            artifact_args = self._parse_image_attachment(attachment)
            if artifact_args is not None:
                if attributes.get('url'):
                    artifact_args['x_misp_url'] = attributes.pop('url')
                return artifact_args
            attributes['attachment'] = attachment
        if attributes.get('url'):
            return {'url': attributes.pop('url')}

    ################################################################################
    #                         PATTERNS CREATION FUNCTIONS.                         #
    ################################################################################

    @staticmethod
    def _create_credential_pattern(attributes: dict) -> list:
        pattern = []
        if attributes.get('username'):
            pattern.append(f"user-account:user_id = '{attributes.pop('username')}'")
        return pattern

    @staticmethod
    def _create_process_image_pattern(image: str) -> str:
        return f"process:binary_ref.name = '{image}'"

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
                display_names[attributes[feature][0]] = attributes.pop(display_feature)[0]
                return display_names
            for value in attributes[feature]:
                index = self._get_matching_email_display_name(attributes[display_feature], value)
                if index is not None:
                    display_names[value] = attributes[display_feature].pop(index)
                if not attributes[display_feature]:
                    del attributes[display_feature]
                    break
        return display_names

    @staticmethod
    def _parse_image_attachment(attachment: Union[str, tuple]) -> Union[dict, None]:
        if not isinstance(attachment, tuple):
            return None
        filename, data = attachment
        artifact_args = {
            'payload_bin': data,
            'allow_custom': True
        }
        if '.' in filename:
            artifact_args['mime_type'] = f"image/{filename.split('.')[-1]}"
        artifact_args['x_misp_filename'] = filename
        return artifact_args