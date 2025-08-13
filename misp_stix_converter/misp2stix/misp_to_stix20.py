#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .misp_to_stix2 import InvalidHashValueError, MISPtoSTIX2Parser
from .stix20_mapping import MISPtoSTIX20Mapping
from base64 import b64encode
from collections import defaultdict
from datetime import datetime
from pymisp import (
    MISPAttribute, MISPEventReport, MISPNote, MISPObject, MISPOpinion)
from stix2.properties import (
    DictionaryProperty, IDProperty, IntegerProperty, ListProperty,
    ReferenceProperty, StringProperty, TimestampProperty)
from stix2.v20.bundle import Bundle
from stix2.v20.observables import (
    Artifact, AutonomousSystem, Directory, DomainName, EmailAddress,
    EmailMessage, EmailMIMEComponent, File, IPv4Address, IPv6Address,
    MACAddress, Mutex, NetworkTraffic, Process, Software, URL, UserAccount,
    WindowsPEBinaryExt, WindowsPESection, WindowsRegistryKey,
    WindowsRegistryValueType, X509Certificate)
from stix2.v20.sdo import (
    AttackPattern, Campaign, CourseOfAction, CustomObject, Identity, Indicator,
    IntrusionSet, Malware, ObservedData, Report, ThreatActor, Tool,
    Vulnerability)
from stix2.v20.sro import Relationship, Sighting
from stix2.v20.vocab import HASHING_ALGORITHM
from typing import Optional, Union

_ANALYST_DATA_REFERENCE_TYPES = [
    'attack-pattern', 'campaign', 'course-of-action', 'identity', 'indicator',
    'intrusion-set', 'malware', 'observed-data', 'report', 'threat-actor',
    'tool', 'vulnerability', 'x-misp-analyst-note', 'x-misp-analyst-opinion',
    'x-misp-attribute', 'x-misp-event-note', 'x-misp-event-report',
    'x-misp-galaxy-cluster', 'x-misp-object'
]
_STIX_OBJECT_TYPING = Union[
    AttackPattern, Campaign, CourseOfAction, CustomObject, Identity, Indicator,
    IntrusionSet, Malware, ObservedData, Tool, Vulnerability, dict
]


@CustomObject(
    'x-misp-analyst-note',
    [
        ('id', IDProperty('x-misp-analyst-note')),
        ('created', TimestampProperty(precision='millisecond')),
        ('modified', TimestampProperty(precision='millisecond')),
        ('x_misp_note', StringProperty(required=True)),
        ('x_misp_author', StringProperty()),
        ('x_misp_language', StringProperty()),
        (
            'object_ref',
            ReferenceProperty(
                valid_types=_ANALYST_DATA_REFERENCE_TYPES, spec_version='2.0'
            )
        )
    ]
)
class CustomAnalystNote:
    pass


@CustomObject(
    'x-misp-analyst-opinion',
    [
        ('id', IDProperty('x-misp-analyst-opinion')),
        ('created', TimestampProperty(precision='millisecond')),
        ('modified', TimestampProperty(precision='millisecond')),
        ('x_misp_opinion', IntegerProperty(required=True)),
        ('x_misp_author', StringProperty()),
        ('x_misp_comment', StringProperty()),
        (
            'object_ref',
            ReferenceProperty(
                valid_types=_ANALYST_DATA_REFERENCE_TYPES, spec_version='2.0'
            )
        )
    ]
)
class CustomAnalystOpinion:
    pass


@CustomObject(
    'x-misp-attribute',
    [
        ('id', IDProperty('x-misp-attribute')),
        ('labels', ListProperty(StringProperty, required=True)),
        ('created', TimestampProperty(required=True, precision='millisecond')),
        ('modified', TimestampProperty(required=True, precision='millisecond')),
        (
            'created_by_ref',
            ReferenceProperty(valid_types='identity', spec_version='2.0')
        ),
        (
            'object_marking_refs',
            ListProperty(
                ReferenceProperty(
                    valid_types='marking-definition', spec_version='2.0'
                )
            )
        ),
        ('x_misp_type', StringProperty(required=True)),
        ('x_misp_value', StringProperty(required=True)),
        ('x_misp_comment', StringProperty()),
        ('x_misp_category', StringProperty())
    ]
)
class CustomAttribute:
    pass


@CustomObject(
    'x-misp-event-report',
    [
        ('id', IDProperty('x-misp-event-report')),
        ('created', TimestampProperty(required=True, precision='millisecond')),
        ('modified', TimestampProperty(required=True, precision='millisecond')),
        (
            'created_by_ref',
            ReferenceProperty(valid_types='identity', spec_version='2.0')
        ),
        (
            'object_refs',
            ListProperty(
                ReferenceProperty(
                    valid_types=_ANALYST_DATA_REFERENCE_TYPES,
                    spec_version='2.0'
                ),
                required=True
            )
        ),
        ('x_misp_content', StringProperty(required=True)),
        ('x_misp_name', StringProperty()),
    ]
)
class CustomEventReport:
    pass


@CustomObject(
    'x-misp-galaxy-cluster',
    [
        ('id', IDProperty('x-misp-galaxy-cluster')),
        ('labels', ListProperty(StringProperty, required=True)),
        ('created', TimestampProperty(precision='millisecond')),
        ('modified', TimestampProperty(precision='millisecond')),
        (
            'created_by_ref',
            ReferenceProperty(valid_types='identity', spec_version='2.0')
        ),
        ('x_misp_name', StringProperty(required=True)),
        ('x_misp_type', StringProperty(required=True)),
        ('x_misp_value', StringProperty(required=True)),
        ('x_misp_description', StringProperty(required=True)),
        ('x_misp_meta', DictionaryProperty())
    ]
)
class CustomGalaxyCluster:
    pass


@CustomObject(
    'x-misp-object',
    [
        ('id', IDProperty('x-misp-object')),
        ('labels', ListProperty(StringProperty, required=True)),
        ('created', TimestampProperty(required=True, precision='millisecond')),
        ('modified', TimestampProperty(required=True, precision='millisecond')),
        (
            'created_by_ref',
            ReferenceProperty(valid_types='identity', spec_version='2.0')
        ),
        (
            'object_marking_refs',
            ListProperty(
                ReferenceProperty(
                    valid_types='marking-definition', spec_version='2.0'
                )
            )
        ),
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
        (
            'created_by_ref',
            ReferenceProperty(valid_types='identity', spec_version='2.0')
        ),
        ('x_misp_event_note', StringProperty(required=True)),
        (
            'object_ref',
            ReferenceProperty(valid_types='report', spec_version='2.0')
        )
    ]
)
class CustomNote:
    pass


@CustomObject(
    'x-misp-opinion',
    [
        ('id', IDProperty('x-misp-opinion')),
        ('x_misp_author', StringProperty()),
        (
            'x_misp_author_ref',
            ReferenceProperty(valid_types='identity', spec_version='2.0')
        ),
        ('x_misp_explanation', StringProperty()),
        ('x_misp_opinion', StringProperty(required=True)),
        ('x_misp_source', StringProperty()),
        (
            'object_ref',
            ReferenceProperty(
                valid_types=[
                    'campaign', 'indicator', 'observed-data',
                    'vulnerability', 'x-misp-attribute'
                ],
                spec_version='2.0'
            )
        )
    ]
)
class CustomOpinion:
    pass


class MISPtoSTIX20Parser(MISPtoSTIX2Parser):
    def __init__(self, interoperability=False):
        super().__init__(interoperability)
        self._version = '2.0'
        self._mapping = MISPtoSTIX20Mapping

    def _parse_event_report(
            self, event_report: MISPEventReport | dict) -> CustomEventReport:
        timestamp = self._parse_timestamp_value(event_report)
        note_args = {
            'id': f"x-misp-event-report--{event_report['uuid']}",
            'created': timestamp, 'modified': timestamp,
            'created_by_ref': self.identity_id,
            'x_misp_content': event_report['content']
        }
        if event_report.get('name'):
            note_args['x_misp_name'] = event_report['name']
        references = set(self._parse_event_report_references(event_report))
        note_args['object_refs'] = (
            list(references) if references
            else [f"report--{self._misp_event['uuid']}"]
        )
        return CustomEventReport(**note_args)

    def _handle_empty_object_refs(self, object_id: str, timestamp: datetime):
        object_type = 'x-misp-event-note'
        custom_args = {
            'id': f"{object_type}--{self._misp_event['uuid']}",
            'created': timestamp, 'modified': timestamp,
            'created_by_ref': self.identity_id,
            'x_misp_event_note': 'This MISP Event is empty and contains no attribute, object, galaxy or tag.',
            'object_ref': object_id, 'interoperability': True
        }
        self._append_SDO(CustomNote(**custom_args))

    def _handle_markings(self, object_args: dict, markings: tuple):
        marking_ids = []
        for marking in markings:
            if marking in self._markings:
                marking_ids.append(self._markings[marking]['marking'].id)
                continue
            marking_definition = self._mapping.tlp_markings(marking)
            if marking_definition is not None:
                marking_id = marking_definition.id
                if marking_id not in self.unique_ids:
                    self._markings[marking] = {
                        'marking': marking_definition, 'used': False
                    }
                    self.unique_ids[marking_id] = marking_id
                marking_ids.append(marking_id)
                continue
            object_args['labels'].append(marking)
        if marking_ids:
            object_args['object_marking_refs'] = marking_ids

    def _handle_note_data(self, stix_object: _STIX_OBJECT_TYPING,
                          note: Union[MISPNote, dict]):
        note_args = {
            'id': f"x-misp-analyst-note--{note['uuid']}",
            'object_ref': stix_object['id'], 'x_misp_note': note['note'],
            **dict(self._handle_analyst_time_fields(stix_object, note))
        }
        if note.get('authors'):
            note_args['x_misp_author'] = note['authors']
        if note.get('language'):
            note_args['x_misp_language'] = note['language']
        if stix_object['id'].startswith('x-misp-'):
            note_args['allow_custom'] = True
        getattr(self, self._results_handling_function)(
            CustomAnalystNote(**note_args)
        )

    def _handle_opinion_data(self, stix_object: _STIX_OBJECT_TYPING,
                             opinion: Union[MISPOpinion, dict]):
        opinion_args = {
            'id': f"x-misp-analyst-opinion--{opinion['uuid']}",
            'object_ref': stix_object['id'],
            'x_misp_opinion': opinion['opinion'],
            **dict(self._handle_analyst_time_fields(stix_object, opinion))
        }
        if opinion.get('authors'):
            opinion_args['x_misp_author'] = opinion['authors']
        if opinion.get('comment'):
            opinion_args['x_misp_comment'] = opinion['comment']
        if stix_object['id'].startswith('x-misp-'):
            opinion_args['allow_custom'] = True
        getattr(self, self._results_handling_function)(
            CustomAnalystOpinion(**opinion_args)
        )

    def _handle_opinion_object(self, sighting: dict, reference_id: str):
        opinion_args = {
            'id': f"x-misp-opinion--{sighting['uuid']}",
            'object_ref': reference_id,
            'x_misp_explanation': 'False positive Sighting',
            'x_misp_opinion': 'strongly-disagree'
        }
        if sighting.get('date_sighting', ''):
            date_sighting = self._datetime_from_timestamp(
                sighting['date_sighting']
            )
            opinion_args.update(
                {'created': date_sighting, 'modified': date_sighting}
            )
        if sighting.get('Organisation', {}):
            name = sighting['Organisation']['name']
            opinion_args.update(
                {
                    'x_misp_author': name,
                    'x_misp_author_ref': self._handle_sighting_identity(
                        sighting['Organisation']['uuid'], name
                    )
                }
            )
        if sighting.get('source', ''):
            opinion_args['x_misp_source'] = sighting['source']
        getattr(self, self._results_handling_function)(
            CustomOpinion(**opinion_args)
        )

    def _handle_unpublished_report(self, report_args: dict) -> Report:
        report_id = f"report--{self._misp_event['uuid']}"
        if not self.object_refs:
            self._handle_empty_object_refs(report_id, report_args['modified'])
        report_args.update(
            {
                'id': report_id, 'type': 'report',
                'published': report_args['modified'], 'allow_custom': True
            }
        )
        self._handle_analyst_data(report_args)
        report_args['object_refs'] = self.object_refs
        report = self._create_report(report_args)
        return report

    ############################################################################
    #                       ATTRIBUTES PARSING FUNCTIONS                       #
    ############################################################################

    def _parse_attachment_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        data = attribute['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        observable_object = {
            '0': File(
                name=attribute['value'], content_ref='1',
                _valid_refs={'1': 'artifact'}
            ),
            '1': self._create_artifact(data)
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_autonomous_system_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        observable_object = {
            '0': AutonomousSystem(
                number=self._parse_AS_value(attribute['value'])
            )
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_domain_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        observable_object = {
            '0': DomainName(value=attribute['value'])
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_domain_ip_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        for separator in self.composite_separators:
            if separator in attribute['value']:
                domain, ip = attribute['value'].split(separator)
                address_object = self._get_address_type(ip)(value=ip)
                observable_object = {
                    '0': DomainName(
                        value=domain, resolves_to_refs=['1'],
                        _valid_refs={'1': address_object._type}
                    ),
                    '1': address_object
                }
                self._handle_attribute_observable(attribute, observable_object)
                break
        else:
            self._composite_attribute_value_warning(
                attribute['type'], attribute['value']
            )
            self._parse_custom_attribute(attribute)

    def _parse_email_attachment_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        observable_object = {
            '0': EmailMessage(
                is_multipart=True,
                body_multipart=[
                    EmailMIMEComponent(
                        content_disposition=(
                            f"attachment; filename='{attribute['value']}'"
                        ),
                        body_raw_ref='1'
                    )
                ]
            ),
            '1': self._create_file(attribute['value'])
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_email_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        observable_object = {
            '0': self._create_email_address(attribute['value'])
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_email_body_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        observable_object = {
            '0': EmailMessage(is_multipart=False, body=attribute['value'])
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_email_destination_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        observable_object = {
            '0': EmailMessage(
                is_multipart=False, to_refs=['1'],
                _valid_refs={'1': 'email-addr'}
            ),
            '1': self._create_email_address(attribute['value'])
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_email_header_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        observable_object = {
            '0': EmailMessage(
                is_multipart=False, received_lines=[attribute['value']]
            )
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_email_reply_to_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        observable_object = {
            '0': EmailMessage(
                is_multipart=False, additional_header_fields={
                    "Reply-To": attribute['value']
                }
            )
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_email_source_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        observable_object = {
            '0': EmailMessage(
                is_multipart=False, from_ref='1',
                _valid_refs={'1': 'email-addr'}
            ),
            '1': self._create_email_address(attribute['value'])
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_email_subject_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        observable_object = {
            '0': EmailMessage(is_multipart=False, subject=attribute['value'])
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_email_x_mailer_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        observable_object = {
            '0': EmailMessage(
                is_multipart=False, additional_header_fields={
                    "X-Mailer": attribute['value']
                }
            )
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_filename_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        observable_object = {
            '0': self._create_file(attribute['value'])
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_github_username_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        self._parse_custom_attribute(attribute)

    def _parse_hash_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        hash_type = self._define_hash_type(attribute['type'])
        if not self._check_hash_value(hash_type, attribute['value']):
            raise InvalidHashValueError()
        file_args: dict[str, Union[bool, dict]] = {
            'hashes': {hash_type: attribute['value']}
        }
        if hash_type not in HASHING_ALGORITHM:
            file_args['allow_custom'] = True
        observable_object = {
            '0': File(**file_args)
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_hash_composite_attribute_observable(
            self, attribute: Union[MISPAttribute, dict],
            hash_type: Optional[str] = None):
        for separator in self.composite_separators:
            if separator in attribute['value']:
                if hash_type is None:
                    hash_type = attribute['type'].split('|')[1]
                hash_type = self._define_hash_type(hash_type)
                filename, hash_value = attribute['value'].split(separator)
                if not self._check_hash_value(hash_type, hash_value):
                    raise InvalidHashValueError()
                file_args = {
                    'name': filename, 'hashes': {hash_type: hash_value}
                }
                if hash_type not in HASHING_ALGORITHM:
                    file_args['allow_custom'] = True
                observable_object = {'0': File(**file_args)}
                self._handle_attribute_observable(attribute, observable_object)
                break
        else:
            self._composite_attribute_value_warning(
                attribute['type'], attribute['value']
            )
            observable_object = {'0': File(**{'name': attribute['value']})}
            self._handle_attribute_observable(attribute, observable_object)

    def _parse_hostname_port_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        for separator in self.composite_separators:
            if separator in attribute['value']:
                hostname, port = attribute['value'].split(separator)
                observable_object = {
                    '0': DomainName(value=hostname),
                    '1': NetworkTraffic(
                        dst_port=port, dst_ref='0', protocols=['tcp'],
                        _valid_refs={'0': 'domain-name'}
                    )
                }
                self._handle_attribute_observable(attribute, observable_object)
                break
        else:
            self._composite_attribute_value_warning(
                attribute['type'], attribute['value']
            )
            self._parse_custom_attribute(attribute)

    def _parse_ip_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        address_object = self._get_address_type(attribute['value'])(
            value=attribute['value']
        )
        ip_type = attribute['type'].split('-')[1]
        network_traffic_args = {
            '_valid_refs': {'1': address_object._type},
            f'{ip_type}_ref': '1', 'protocols': ['tcp']
        }
        observable_object = {
            '0': NetworkTraffic(**network_traffic_args), '1': address_object
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_ip_port_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        for separator in self.composite_separators:
            if separator in attribute['value']:
                ip_value, port_value = attribute['value'].split(separator)
                address_object = self._get_address_type(ip_value)(
                    value=ip_value
                )
                ip_type = attribute['type'].split('|')[0].split('-')[1]
                network_traffic_args = {
                    '_valid_refs': {'1': address_object._type},
                    f'{ip_type}_ref': '1', f'{ip_type}_port': port_value,
                    'protocols': ['tcp']
                }
                observable_object = {
                    '0': NetworkTraffic(**network_traffic_args),
                    '1': address_object
                }
                self._handle_attribute_observable(attribute, observable_object)
                break
        else:
            self._composite_attribute_value_warning(
                attribute['type'], attribute['value']
            )
            self._parse_custom_attribute(attribute)

    def _parse_mac_address_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        observable_object = {
            '0': MACAddress(value=attribute['value'].lower())
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_malware_sample_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        file_args = {'content_ref': '1', '_valid_refs': {'1': 'artifact'}}
        for separator in self.composite_separators:
            if separator in attribute['value']:
                filename, hash_value = attribute['value'].split(separator)
                if not self._check_hash_value('MD5', hash_value):
                    raise InvalidHashValueError()
                file_args.update(
                    {'name': filename, 'hashes': {'MD5': hash_value}}
                )
                break
        else:
            self._composite_attribute_value_warning(
                attribute['type'], attribute['value']
            )
            file_args['name'] = attribute['value']
        data = attribute['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        observable_object = {
            '0': File(**file_args),
            '1': self._create_artifact(data, malware_sample=True)
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_mutex_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        observable_object = {'0': Mutex(name=attribute['value'])}
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_regkey_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        observable_object = {
            '0': WindowsRegistryKey(key=attribute['value'].strip())
        }
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_regkey_value_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        for separator in self.composite_separators:
            if separator in attribute['value']:
                key, value = attribute['value'].split(separator)
                observable_object = {
                    '0': WindowsRegistryKey(
                        key=key.strip(),
                        values=[
                            WindowsRegistryValueType(
                                name='', data=value.strip()
                            )
                        ]
                    )
                }
                self._handle_attribute_observable(attribute, observable_object)
                break
        else:
            self._composite_attribute_value_warning(
                attribute['type'], attribute['value']
            )
            observable_object = {
                '0': WindowsRegistryKey(key=attribute['value'].strip())
            }
            self._handle_attribute_observable(attribute, observable_object)

    def _parse_url_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        observable_object = {'0': URL(value=attribute['value'])}
        self._handle_attribute_observable(attribute, observable_object)

    def _parse_x509_fingerprint_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        hash_type = self._define_hash_type(attribute['type'].split('-')[-1])
        if not self._check_hash_value(hash_type, attribute['value']):
            raise InvalidHashValueError()
        observable_object = {
            '0': X509Certificate(hashes={hash_type: attribute['value']})
        }
        self._handle_attribute_observable(attribute, observable_object)

    ############################################################################
    #                      MISP OBJECTS PARSING FUNCTIONS                      #
    ############################################################################

    def _handle_file_observable_object(self, args: dict) -> dict:
        return {'0': self._create_file_object(args)}

    def _handle_file_observable_objects(
            self, args: dict, observable_object: dict):
        observable_object['0'] = self._create_file_object(args)

    def _parse_account_object_observable(
            self, misp_object: Union[MISPObject, dict], account_type: str):
        account_args = self._parse_account_args(
            misp_object['Attribute'], account_type
        )
        observable_object = {'0': UserAccount(**account_args)}
        self._handle_object_observable(misp_object, observable_object)

    def _parse_android_app_object_observable(
            self, misp_object: Union[MISPObject, dict]):
        software_args = self._parse_android_app_args(misp_object['Attribute'])
        observable_object = {'0': Software(**software_args)}
        self._handle_object_observable(misp_object, observable_object)

    def _parse_account_object_with_attachment_observable(
            self, misp_object: Union[MISPObject, dict], account_type: str):
        account_args = self._parse_account_with_attachment_args(
            misp_object['Attribute'], account_type
        )
        observable_object = {'0': UserAccount(**account_args)}
        self._handle_object_observable(misp_object, observable_object)

    def _parse_asn_object_observable(
            self, misp_object: Union[MISPObject, dict]):
        as_args = self._parse_AS_args(misp_object['Attribute'])
        observable_object = {'0': AutonomousSystem(**as_args)}
        self._handle_object_observable(misp_object, observable_object)

    def _parse_cpe_asset_object_observable(
            self, misp_object: Union[MISPObject, dict]):
        software_args = self._parse_cpe_asset_args(misp_object['Attribute'])
        observable_object = {'0': Software(**software_args)}
        self._handle_object_observable(misp_object, observable_object)

    def _parse_credential_object_observable(
            self, misp_object: Union[MISPObject, dict]):
        credential_args = self._parse_credential_args(misp_object['Attribute'])
        observable_object = {'0': UserAccount(**credential_args)}
        self._handle_object_observable(misp_object, observable_object)

    def _parse_domain_ip_object_custom(
            self, misp_object: Union[MISPObject, dict]):
        attributes = self._extract_multiple_object_attributes(
            misp_object['Attribute'],
            force_single=self._mapping.domain_ip_single_fields()
        )
        index = 1
        domain_args, observable, index = self._parse_domainip_ip_attributes(
            attributes, index
        )
        domain_args.update(self._parse_domain_args(attributes))
        observable['0'] = DomainName(**domain_args)
        self._handle_object_observable(misp_object, observable)

    def _parse_domain_ip_object_standard(
            self, misp_object: Union[MISPObject, dict]):
        attributes = self._extract_multiple_object_attributes(
            misp_object['Attribute'],
            force_single=self._mapping.domain_ip_single_fields()
        )
        index = 0
        domain_args, observable, index = self._parse_domainip_ip_attributes(
            attributes, index
        )
        if attributes.get('hostname'):
            args = {'value': attributes.pop('hostname'), **domain_args}
            observable[str(index)] = DomainName(**args)
            index += 1
        if attributes.get('domain'):
            for domain in attributes.pop('domain'):
                args = {'value': domain, **domain_args}
                observable[str(index)] = DomainName(**args)
                index += 1
        self._handle_object_observable(misp_object, observable)

    def _parse_domainip_ip_attributes(
            self, attributes: Union[MISPObject, dict], index: int) -> tuple:
        domain_args: dict[str, Union[dict, list, str]] = {}
        observable_object = {}
        if attributes.get('ip'):
            valid_refs = {}
            for ip_value in attributes.pop('ip'):
                str_index = str(index)
                address_object = self._get_address_type(ip_value)(
                    value=ip_value
                )
                observable_object[str_index] = address_object
                valid_refs[str_index] = address_object._type
                index += 1
            domain_args['_valid_refs'] = valid_refs
            domain_args['resolves_to_refs'] = list(valid_refs.keys())
        return domain_args, observable_object, index

    def _parse_email_object_observable(
            self, misp_object: Union[MISPObject, dict]):
        attributes = self._extract_multiple_object_attributes_with_data(
            misp_object['Attribute'],
            with_data=self._mapping.email_data_fields()
        )
        observable: dict = {}
        email_message_args: defaultdict = defaultdict(dict)
        email_message_args['is_multipart'] = False
        index = 1
        if attributes.get('from'):
            display_names = self._parse_email_display_names(attributes, 'from')
            str_index = str(index)
            self._parse_email_object_reference(
                self._select_single_feature(attributes, 'from'),
                display_names, email_message_args, observable, str_index
            )
            email_message_args['from_ref'] = str_index
            index += 1
        for feature in ('to', 'cc', 'bcc'):
            if attributes.get(feature):
                references = []
                display_names = self._parse_email_display_names(
                    attributes, feature
                )
                for value in attributes.pop(feature):
                    str_index = str(index)
                    self._parse_email_object_reference(
                        value, display_names, email_message_args,
                        observable, str_index
                    )
                    references.append(str_index)
                    index += 1
                email_message_args[f'{feature}_refs'] = references
        if any(key in attributes for key in self._mapping.email_data_fields()):
            body_multipart = []
            for feature in self._mapping.email_data_fields():
                if attributes.get(feature):
                    for value in attributes.pop(feature):
                        str_index = str(index)
                        if isinstance(value, tuple):
                            value, data = value
                            if not isinstance(data, str):
                                data = b64encode(data.getvalue()).decode()
                            observable[str_index] = self._create_artifact(
                                data, filename=value
                            )
                        else:
                            observable[str_index] = self._create_file(value)
                        body = {
                            'content_disposition': (
                                f"{feature}; filename='{value}'"
                            ),
                            'body_raw_ref': str_index
                        }
                        body_multipart.append(body)
                        index += 1
            email_message_args.update(
                {'body_multipart': body_multipart, 'is_multipart': True}
            )
        if attributes:
            email_message_args.update(self._parse_email_args(attributes))
        observable['0'] = EmailMessage(**email_message_args)
        self._handle_object_observable(misp_object, observable)

    def _parse_email_object_reference(
            self, address: str, display_names: dict, email_args: dict,
            observable: dict, index: str):
        email_address = self._create_email_address(
            address, display_name=display_names.get(address)
        )
        observable[index] = email_address
        email_args['_valid_refs'][index] = email_address._type

    def _parse_file_observable_object(
            self, misp_object: Union[MISPObject, dict]) -> tuple:
        attributes = self._extract_multiple_object_attributes_with_data(
            misp_object['Attribute'],
            force_single=self._mapping.file_single_fields(),
            with_data=self._mapping.file_data_fields()
        )
        observable_object = {}
        file_args: defaultdict = defaultdict(dict)
        index = 1
        if attributes.get('path'):
            str_index = str(index)
            observable_object[str_index] = Directory(
                path=attributes.pop('path')
            )
            file_args['parent_directory_ref'] = str_index
            file_args['_valid_refs'][str_index] = 'directory'
            index += 1
        if isinstance(attributes.get('malware-sample'), tuple):
            malware_sample = attributes.pop('malware-sample')
            try:
                args = self._parse_malware_sample_args(*malware_sample)
            except InvalidHashValueError:
                self._invalid_object_hash_value_error('MD5', misp_object)
                args = self._parse_malware_sample_custom_args(*malware_sample)
            str_index = str(index)
            observable_object[str_index] = Artifact(**args)
            file_args['content_ref'] = str_index
            file_args['_valid_refs'][str_index] = 'artifact'
            index += 1
            if attributes.get('attachment'):
                file_args.update(
                    self._parse_custom_attachment(attributes.pop('attachment'))
                )
        elif isinstance(attributes.get('attachment'), tuple):
            args = self._create_attachment_args(*attributes.pop('attachment'))
            observable_object[str(index)] = Artifact(**args)
        if attributes:
            file_args.update(
                self._parse_file_args(
                    attributes,
                    {'uuid': misp_object['uuid'], 'name': misp_object['name']}
                )
            )
        return file_args, observable_object

    def _parse_http_request_object_observable(
            self, misp_object: Union[MISPObject, dict]):
        attributes = self._extract_multiple_object_attributes(
            misp_object['Attribute'],
            force_single=self._mapping.http_request_single_fields()
        )
        observable_object = {}
        network_args: defaultdict = defaultdict(dict)
        index = 1
        for feature in ('ip-src', 'ip-dst'):
            if attributes.get(feature):
                str_index = str(index)
                ip_value = attributes.pop(feature)
                address_object = self._get_address_type(ip_value)(
                    value=ip_value
                )
                observable_object[str_index] = address_object
                network_args['_valid_refs'][str_index] = address_object._type
                ref_type = 'src_ref' if feature == 'ip-src' else 'dst_ref'
                network_args[ref_type] = str_index
                index += 1
        if attributes.get('host'):
            str_index = str(index)
            domain_args = {'value': attributes.pop('host')}
            if 'dst_ref' in network_args:
                reference = network_args['dst_ref']
                domain_args.update(
                    {
                        'resolves_to_refs': [reference],
                        '_valid_refs': {
                            reference: observable_object[reference]._type
                        }
                    }
                )
            else:
                network_args['_valid_refs'][str_index] = 'domain-name'
                network_args['dst_ref'] = str_index
            observable_object[str_index] = DomainName(**domain_args)
        network_args.update(self._parse_http_request_args(attributes))
        observable_object['0'] = NetworkTraffic(**network_args)
        self._handle_object_observable(misp_object, observable_object)

    def _parse_identity_object(self, misp_object: Union[MISPObject, dict]):
        identity_args = self._extract_multiple_object_attributes(
            misp_object['Attribute'],
            force_single=self._mapping.identity_single_fields()
        )
        if 'roles' in identity_args:
            roles = identity_args.pop('roles')
            identity_args.update(
                {
                    'allow_custom': True,
                    'x_misp_roles': roles[0] if len(roles) == 1 else roles
                }
            )
        self._handle_non_indicator_object(
            misp_object, identity_args, 'identity'
        )

    def _parse_image_object_observable(
            self, misp_object: Union[MISPObject, dict]):
        attributes = self._extract_multiple_object_attributes_with_data(
            misp_object['Attribute'],
            force_single=self._mapping.image_single_fields(),
            with_data=self._mapping.image_data_fields()
        )
        artifact_args = self._parse_image_args(attributes)
        file_args = {}
        if attributes.get('filename'):
            file_args['name'] = attributes.pop('filename')
        if attributes:
            file_args.update(
                self._handle_observable_multiple_properties(attributes)
            )
        if artifact_args is not None:
            file_args['content_ref'] = '1'
            file_args['_valid_refs'] = {'1': 'artifact'}
            observable_object = {
                '0': File(**file_args), '1': Artifact(**artifact_args)
            }
            self._handle_object_observable(misp_object, observable_object)
        else:
            self._handle_object_observable(
                misp_object, {'0': File(**file_args)}
            )

    def _parse_ip_port_object_observable(
            self, misp_object: Union[MISPObject, dict]):
        attributes = self._extract_multiple_object_attributes(
            misp_object['Attribute'],
            force_single=self._mapping.ip_port_single_fields()
        )
        protocols = set()
        observable_object = {}
        network_args: defaultdict = defaultdict(dict)
        index = 1
        for feature in ('ip-src', 'ip-dst', 'ip'):
            if attributes.get(feature):
                str_index = str(index)
                ip_value = self._select_single_feature(attributes, feature)
                address_object = self._get_address_type(ip_value)(
                    value=ip_value
                )
                observable_object[str_index] = address_object
                network_args['_valid_refs'][str_index] = address_object._type
                protocols.add(address_object._type.split('-')[0])
                ref_type = 'src_ref' if feature == 'ip-src' else 'dst_ref'
                network_args[ref_type] = str_index
                if ref_type == 'dst_ref':
                    break
                index += 1
        if attributes:
            network_args.update(self._parse_ip_port_args(attributes, protocols))
        else:
            network_args['protocols'] = (
                list(protocols) if protocols else ['tcp']
            )
        observable_object['0'] = NetworkTraffic(**network_args)
        self._handle_object_observable(misp_object, observable_object)

    def _parse_lnk_object_observable(
            self, misp_object: Union[MISPObject, dict]):
        attributes = self._extract_multiple_object_attributes_with_data(
            misp_object['Attribute'],
            force_single=self._mapping.lnk_single_fields(),
            with_data=self._mapping.lnk_data_fields()
        )
        observable_object = {}
        file_args: dict[str, Union[bool, dict, str]] = {}
        index = 1
        for feature in self._mapping.lnk_path_fields():
            if attributes.get(feature):
                str_index = str(index)
                observable_object[str_index] = Directory(
                    path=self._select_single_feature(attributes, feature)
                )
                file_args['parent_directory_ref'] = str_index
                file_args['_valid_refs'] = {str_index: 'directory'}
                index += 1
                break
        if isinstance(attributes.get('malware-sample'), tuple):
            malware_sample = attributes.pop('malware-sample')
            try:
                args = self._parse_malware_sample_args(*malware_sample)
            except InvalidHashValueError:
                self._invalid_object_hash_value_error('MD5', misp_object)
                args = self._parse_malware_sample_custom_args(*malware_sample)
            str_index = str(index)
            observable_object[str_index] = Artifact(**args)
            file_args['content_ref'] = str_index
            file_args['_valid_refs'][str_index] = 'artifact'
        file_args.update(
            self._parse_lnk_args(
                attributes,
                {'uuid': misp_object['uuid'], 'name': misp_object['name']}
            )
        )
        observable_object['0'] = self._create_file_object(file_args)
        self._handle_object_observable(misp_object, observable_object)

    def _parse_mutex_object_observable(
            self, misp_object: Union[MISPObject, dict]):
        mutex_args = self._parse_mutex_args(misp_object['Attribute'])
        self._handle_object_observable(misp_object, {'0': Mutex(**mutex_args)})

    def _parse_netflow_object_observable(
            self, misp_object: Union[MISPObject, dict]):
        attributes = self._extract_object_attributes_escaped(
            misp_object['Attribute']
        )
        observable_object = {}
        network_args: defaultdict = defaultdict(dict)
        index = 1
        for ref_type in ('src', 'dst'):
            if attributes.get(f'ip-{ref_type}'):
                str_index = str(index)
                ip_value = attributes.pop(f'ip-{ref_type}')
                address_args = {'value': ip_value}
                if attributes.get(f'{ref_type}-as'):
                    index += 1
                    as_index = str(index)
                    address_args.update(
                        {
                            '_valid_refs': {as_index: 'autonomous-system'},
                            'belongs_to_refs': [as_index]
                        }
                    )
                    observable_object[as_index] = AutonomousSystem(
                        number=self._parse_AS_value(
                            attributes.pop(f'{ref_type}-as')
                        )
                    )
                address_object = self._get_address_type(ip_value)(
                    **address_args
                )
                observable_object[str_index] = address_object
                network_args['_valid_refs'][str_index] = address_object._type
                network_args[f'{ref_type}_ref'] = str_index
                index += 1
        network_args.update(self._parse_netflow_args(attributes))
        observable_object['0'] = NetworkTraffic(**network_args)
        self._handle_object_observable(misp_object, observable_object)


    def _parse_network_connection_object_observable(
            self, misp_object: Union[MISPObject, dict]):
        attributes = self._extract_object_attributes(misp_object['Attribute'])
        network_args, observable_object = self._parse_network_references(
            attributes
        )
        if attributes:
            network_args.update(self._parse_network_connection_args(attributes))
        observable_object['0'] = NetworkTraffic(**network_args)
        self._handle_object_observable(misp_object, observable_object)

    def _parse_network_references(
            self, attributes: Union[MISPObject, dict]) -> tuple:
        index = 1
        network_args: defaultdict = defaultdict(dict)
        observable_object = {}
        for feature in ('src', 'dst'):
            if attributes.get(f'ip-{feature}'):
                str_index = str(index)
                ip_value = attributes.pop(f'ip-{feature}')
                address_object = self._get_address_type(ip_value)(
                    value=ip_value
                )
                observable_object[str_index] = address_object
                network_args['_valid_refs'][str_index] = address_object._type
                network_args[f'{feature}_ref'] = str_index
                index += 1
                continue
            if attributes.get(f'hostname-{feature}'):
                str_index = str(index)
                observable_object[str_index] = DomainName(
                    value=attributes.pop(f'hostname-{feature}')
                )
                network_args['_valid_refs'][str_index] = 'domain-name'
                network_args[f'{feature}_ref'] = str_index
                index += 1
        return network_args, observable_object

    def _parse_network_socket_object(
            self, misp_object: Union[MISPObject, dict]):
        if self._fetch_ids_flag(misp_object['Attribute']):
            pattern = self._parse_network_socket_object_pattern(
                misp_object['Attribute']
            )
            self._handle_object_indicator(misp_object, pattern)
        else:
            attributes = self._extract_multiple_object_attributes(
                misp_object['Attribute'],
                force_single=self._mapping.network_socket_single_fields()
            )
            network_args, observable_object = self._parse_network_references(
                attributes
            )
            if attributes:
                network_args.update(self._parse_network_socket_args(attributes))
            observable_object['0'] = NetworkTraffic(**network_args)
            self._handle_object_observable(misp_object, observable_object)

    def _parse_process_object(self, misp_object: Union[MISPObject, dict]):
        if self._fetch_ids_flag(misp_object['Attribute']):
            pattern = self._parse_process_object_pattern(
                misp_object['Attribute']
            )
            self._handle_object_indicator(misp_object, pattern)
        else:
            attributes = self._extract_multiple_object_attributes(
                misp_object['Attribute'],
                force_single=self._mapping.process_single_fields()
            )
            observable_object = {}
            parent_attributes = self._extract_parent_process_attributes(
                attributes
            )
            process_args: defaultdict = defaultdict(dict)
            index = 1
            if parent_attributes:
                str_index = str(index)
                parent_args: dict[str, Union[dict, str]] = {}
                if parent_attributes.get('parent-image'):
                    index += 1
                    str_index2 = str(index)
                    observable_object[str_index2] = File(
                        name=parent_attributes.pop('parent-image')
                    )
                    parent_args['binary_ref'] = str_index2
                    parent_args['_valid_refs'] = {str_index2: 'file'}
                parent_mapping = self._mapping.process_object_mapping('parent')
                for key, feature in parent_mapping.items():
                    if parent_attributes.get(key):
                        parent_args[feature] = parent_attributes.pop(key)
                if parent_attributes:
                    parent_args.update(
                        self._handle_parent_process_properties(
                            parent_attributes
                        )
                    )
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
                observable_object[str_index] = File(
                    name=attributes.pop('image')
                )
                process_args['binary_ref'] = str_index
                process_args['_valid_refs'][str_index] = 'file'
            process_args.update(
                self._parse_process_args(attributes, 'features')
            )
            observable_object['0'] = Process(**process_args)
            self._handle_object_observable(misp_object, observable_object)

    def _parse_registry_key_object_observable(
            self, misp_object: Union[MISPObject, dict]
        ):
        registry_key_args = self._parse_registry_key_args(
            misp_object['Attribute']
        )
        observable_object = {'0': WindowsRegistryKey(**registry_key_args)}
        self._handle_object_observable(misp_object, observable_object)

    @staticmethod
    def _parse_regkey_key_values_observable(attributes: dict) -> dict:
        registry_key_args = {}
        if attributes.get('key'):
            registry_key_args['key'] = attributes.pop('key')
        if attributes.get('last-modified'):
            modif = attributes.pop('last-modified')
            if not isinstance(modif, datetime) and not modif.endswith('Z'):
                modif = f"{modif}Z"
            registry_key_args['modified'] = modif
        return registry_key_args

    def _parse_regkey_key_values_pattern(
            self, attributes: dict, prefix: str) -> list:
        pattern = []
        if attributes.get('key'):
            value = self._sanitize_registry_key_value(
                attributes.pop('key').strip("'").strip('"')
            )
            pattern.append(f"{prefix}:key = '{value}'")
        if attributes.get('last-modified'):
            modified = self._handle_value_for_pattern(
                attributes.pop('last-modified')
            )
            pattern.append(f"{prefix}:modified = '{modified}'")
        return pattern

    def _parse_url_object_observable(
            self, misp_object: Union[MISPObject, dict]
        ):
        url_args = self._parse_url_args(misp_object['Attribute'])
        observable_object = {'0': URL(**url_args)}
        self._handle_object_observable(misp_object, observable_object)

    def _parse_user_account_object_observable(
            self, misp_object: Union[MISPObject, dict]
        ):
        user_account_args = self._parse_user_account_args(
            misp_object['Attribute']
        )
        observable_object = {'0': UserAccount(**user_account_args)}
        self._handle_object_observable(misp_object, observable_object)

    def _parse_x509_object_observable(
            self, misp_object: Union[MISPObject, dict]):
        x509_args = self._parse_x509_args(misp_object)
        observable_object = {'0': X509Certificate(**x509_args)}
        self._handle_object_observable(misp_object, observable_object)

    ############################################################################
    #                  STIX OBJECTS CREATION HELPER FUNCTIONS                  #
    ############################################################################

    def _create_artifact(
            self, content: str, filename: Optional[str] = None,
            malware_sample: Optional[bool] = False) -> Artifact:
        args: dict[str, Union[bool, str]] = {'payload_bin': content}
        if filename is not None:
            args.update({'allow_custom': True, 'x_misp_filename': filename})
        if malware_sample:
            args.update(
                self._mapping.malware_sample_additional_observable_values()
            )
        return Artifact(**args)

    @staticmethod
    def _create_attack_pattern(attack_pattern_args: dict) -> AttackPattern:
        return AttackPattern(**attack_pattern_args)

    def _create_bundle(self) -> Bundle:
        return Bundle(
            self.stix_objects, allow_custom=True,
            id=f"bundle--{self._misp_event.get('uuid')}"
            if hasattr(self, "_misp_event") else None
        )

    @staticmethod
    def _create_campaign(campaign_args: dict) -> Campaign:
        return Campaign(**campaign_args)

    @staticmethod
    def _create_course_of_action(course_of_action_args: dict) -> CourseOfAction:
        return CourseOfAction(**course_of_action_args)

    def _create_custom_attribute(self, custom_args: dict) -> CustomAttribute:
        self._clean_custom_properties(custom_args)
        return CustomAttribute(**custom_args)

    def _create_custom_galaxy(self, custom_args: dict) -> CustomGalaxyCluster:
        return CustomGalaxyCluster(**custom_args)

    def _create_custom_object(self, custom_args: dict) -> CustomMispObject:
        self._clean_custom_properties(custom_args)
        return CustomMispObject(**custom_args)

    @staticmethod
    def _create_email_address(
            email_address: str,
            display_name: Optional[str] = None) -> EmailAddress:
        args = {'value': email_address}
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
        if any(field.startswith('x_') for field in identity_args):
            identity_args['allow_custom'] = True
        return Identity(**identity_args)

    def _create_identity_object(self, orgname: str) -> Identity:
        identity_args = {
            'type': 'identity', 'id': self.identity_id, 'name': orgname,
            'created': self.event_timestamp, 'modified': self.event_timestamp,
            'identity_class': 'organization', 'interoperability': True
        }
        return self._create_identity(identity_args)

    @staticmethod
    def _create_indicator(indicator_args: dict) -> Indicator:
        return Indicator(**indicator_args)

    @staticmethod
    def _create_intrusion_set(intrusion_set_args: dict) -> IntrusionSet:
        return IntrusionSet(**intrusion_set_args)

    @staticmethod
    def _create_malware(malware_args: dict) -> Malware:
        return Malware(**malware_args)

    def _create_observed_data(
            self, args: dict, observable: dict) -> ObservedData:
        args['objects'] = observable
        observed_data = ObservedData(**args)
        getattr(self, self._results_handling_function)(observed_data)
        return observed_data

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

    @staticmethod
    def _create_tool(tool_args: dict) -> Tool:
        return Tool(**tool_args)

    @staticmethod
    def _create_vulnerability(vulnerability_args: dict) -> Vulnerability:
        return Vulnerability(**vulnerability_args)

    @staticmethod
    def _create_windowsPESection(section_args: dict) -> WindowsPESection:
        return WindowsPESection(**section_args)

    ############################################################################
    #                   OBSERVABLE OBJECT PARSING FUNCTIONS.                   #
    ############################################################################

    def _parse_image_args(self, attributes: dict) -> Union[dict, None]:
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
        return None

    ############################################################################
    #                       PATTERNS CREATION FUNCTIONS.                       #
    ############################################################################

    @staticmethod
    def _create_credential_pattern(attributes: dict) -> list:
        pattern = []
        if attributes.get('username'):
            pattern.append(
                f"user-account:user_id = '{attributes.pop('username')}'"
            )
        return pattern

    @staticmethod
    def _create_process_image_pattern(image: str) -> str:
        return f"process:binary_ref.name = '{image}'"

    ############################################################################
    #                            UTILITY FUNCTIONS.                            #
    ############################################################################

    @staticmethod
    def _get_address_type(address: str) -> Union[IPv4Address, IPv6Address]:
        if ':' in address:
            return IPv6Address
        return IPv4Address

    @staticmethod
    def _parse_image_attachment(
        attachment: Union[str, tuple]) -> Union[dict, None]:
        if not isinstance(attachment, tuple):
            return None
        filename, data = attachment
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        artifact_args = {
            'payload_bin': data,
            'allow_custom': True
        }
        if '.' in filename:
            artifact_args['mime_type'] = f"image/{filename.split('.')[-1]}"
        artifact_args['x_misp_filename'] = filename
        return artifact_args
