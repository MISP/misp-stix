#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .misp_to_stix2 import InvalidHashValueError, MISPtoSTIX2Parser
from .stix21_mapping import MISPtoSTIX21Mapping
from base64 import b64encode
from collections import defaultdict
from datetime import datetime
from pycountry import countries
from pymisp import (
    MISPAttribute, MISPEventReport, MISPGalaxy, MISPGalaxyCluster, MISPNote,
    MISPObject, MISPOpinion)
from stix2.properties import (
    DictionaryProperty, IDProperty, ListProperty, ReferenceProperty,
    StringProperty, TimestampProperty)
from stix2.v21.bundle import Bundle
from stix2.v21.observables import (
    Artifact, AutonomousSystem, Directory, DomainName, EmailAddress,
    EmailMessage, EmailMIMEComponent, File, IPv4Address, IPv6Address,
    MACAddress, Mutex, NetworkTraffic, Process, Software, URL, UserAccount,
    WindowsPEBinaryExt, WindowsPESection, WindowsRegistryKey,
    WindowsRegistryValueType, X509Certificate)
from stix2.v21.sdo import (
    AttackPattern, Campaign, CourseOfAction, CustomObject, Grouping, Identity,
    Indicator, IntrusionSet, Location, Malware, Note, ObservedData, Opinion,
    Report, ThreatActor, Tool, Vulnerability)
from stix2.v21.sro import Relationship, Sighting
from stix2.v21.vocab import HASHING_ALGORITHM
from typing import Optional, Union

_STIX_OBJECT_TYPING = Union[
    AttackPattern, Campaign, CourseOfAction, CustomObject, Identity,
    Indicator, IntrusionSet, Location, Malware, Note, ObservedData, Tool,
    Vulnerability, dict
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


@CustomObject(
    'x-misp-galaxy-cluster',
    [
        ('id', IDProperty('x-misp-galaxy-cluster')),
        ('labels', ListProperty(StringProperty, required=True)),
        ('created', TimestampProperty(precision='millisecond')),
        ('modified', TimestampProperty(precision='millisecond')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('x_misp_name', StringProperty(required=True)),
        ('x_misp_type', StringProperty(required=True)),
        ('x_misp_value', StringProperty(required=True)),
        ('x_misp_description', StringProperty(required=True)),
        ('x_misp_meta', DictionaryProperty())
    ]
)
class CustomGalaxyCluster:
    pass


class MISPtoSTIX21Parser(MISPtoSTIX2Parser):
    def __init__(self, interoperability=False):
        super().__init__(interoperability)
        self._version = '2.1'
        self._mapping = MISPtoSTIX21Mapping

    def _parse_event_report(
            self, event_report: MISPEventReport | dict) -> Note:
        timestamp = self._parse_timestamp_value(event_report)
        note_args = {
            'id': f"note--{event_report['uuid']}",
            'created': timestamp, 'modified': timestamp,
            'created_by_ref': self.identity_id,
            'content': event_report['content'],
            'abstract': event_report['name'],
            'labels': ['misp:data-layer="Event Report"']
        }
        references = set(self._parse_event_report_references(event_report))
        note_args['object_refs'] = (
            list(references) if references else self._handle_empty_note_refs()
        )
        if any(ref.startswith('x-misp-') for ref in note_args['object_refs']):
            note_args['allow_custom'] = True
        return self._create_note(note_args)

    def _handle_empty_object_refs(self, object_id: str, timestamp: datetime):
        note_args = {
            'id': f"note--{self._misp_event['uuid']}",
            'created': timestamp, 'modified': timestamp,
            'created_by_ref': self.identity_id, 'object_refs': [object_id],
            'content': (
                'This MISP Event is empty and contains '
                'no attribute, object, galaxy or tag.'
            )
        }
        self._append_SDO(self._create_note(note_args))

    def _handle_markings(self, object_args: dict, markings: tuple):
        marking_ids = []
        confidence_score = []
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
            score = self._mapping.confidence_tags(marking)
            if score is not None:
                confidence_score.append(score)
            object_args['labels'].append(marking)
        if confidence_score:
            object_args['confidence'] = min(confidence_score)
        if marking_ids:
            object_args['object_marking_refs'] = marking_ids

    def _handle_note_data(self, stix_object: _STIX_OBJECT_TYPING,
                          note: Union[MISPNote, dict]):
        note_args = {
            'content': note['note'], 'id': f"note--{note['uuid']}",
            'labels': ['misp:context-layer="Analyst Note"'],
            'object_refs': [stix_object['id']],
            **dict(self._handle_analyst_time_fields(stix_object, note))
        }
        if note.get('authors'):
            note_args['authors'] = [note['authors']]
        if note.get('language'):
            note_args['lang'] = note['language']
        if stix_object['id'].startswith('x-misp--'):
            note_args['allow_custom'] = True
        getattr(self, self._results_handling_function)(
            self._create_note(note_args)
        )

    def _handle_opinion_data(self, stix_object: _STIX_OBJECT_TYPING,
                             opinion: Union[MISPOpinion, dict]):
        opinion_value = int(opinion['opinion'])
        opinion_args = {
            'allow_custom': True, 'id': f"opinion--{opinion['uuid']}",
            'labels': ['misp:context-layer="Analyst Opinion"'],
            'opinion': self._parse_opinion_level(opinion_value),
            'object_refs': [stix_object['id']], 'x_misp_opinion': opinion_value,
            **dict(self._handle_analyst_time_fields(stix_object, opinion))
        }
        if opinion.get('authors'):
            opinion_args['authors'] = [opinion['authors']]
        if opinion.get('comment'):
            opinion_args['explanation'] = opinion['comment']
        if stix_object['id'].startswith('x-misp--'):
            opinion_args['allow_custom'] = True
        getattr(self, self._results_handling_function)(
            self._create_opinion(opinion_args)
        )

    def _handle_opinion_object(self, sighting: dict, reference_id: str):
        opinion_args = {
            'id': f"opinion--{sighting['uuid']}",
            'type': 'opinion', 'explanation': 'False positive Sighting',
            'opinion': 'strongly-disagree', 'object_refs': [reference_id]
        }
        if 'x-misp-' in reference_id:
            opinion_args['allow_custom'] = True
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
                    'authors': [name], 'allow_custom': True,
                    'x_misp_author_ref': self._handle_sighting_identity(
                        sighting['Organisation']['uuid'], name
                    )
                }
            )
        getattr(self, self._results_handling_function)(
            self._create_opinion(opinion_args)
        )

    def _handle_unpublished_report(self, report_args: dict) -> Grouping:
        grouping_id = f"grouping--{self._misp_event['uuid']}"
        if not self.object_refs:
            self._handle_empty_object_refs(grouping_id, report_args['modified'])
        report_args.update(
            {
                'id': grouping_id, 'type': 'grouping',
                'context': 'suspicious-activity', 'allow_custom': True
            }
        )
        self._handle_analyst_data(report_args)
        report_args['object_refs'] = self.object_refs
        grouping = Grouping(**report_args)
        return grouping

    ############################################################################
    #                       ATTRIBUTES PARSING FUNCTIONS                       #
    ############################################################################

    def _parse_attachment_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        artifact_id = f"artifact--{attribute['uuid']}"
        data = attribute['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        objects = [
            File(
                id=f"file--{attribute['uuid']}",
                name=attribute['value'], content_ref=artifact_id
            ),
            Artifact(id=artifact_id, payload_bin=data)
        ]
        self._handle_attribute_observable(attribute, objects)

    def _parse_autonomous_system_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        AS_object = AutonomousSystem(
            id=f"autonomous-system--{attribute['uuid']}",
            number=self._parse_AS_value(attribute['value'])
        )
        self._handle_attribute_observable(attribute, [AS_object])

    def _parse_domain_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        domain_object = DomainName(
            id=f"domain-name--{attribute['uuid']}", value=attribute['value']
        )
        self._handle_attribute_observable(attribute, [domain_object])

    def _parse_domain_ip_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        for separator in self.composite_separators:
            if separator in attribute['value']:
                domain, ip = attribute['value'].split(separator)
                address_type = self._get_address_type(ip)
                address_id = f"{address_type._type}--{attribute['uuid']}"
                objects = [
                    DomainName(
                        id=f"domain-name--{attribute['uuid']}",
                        value=domain, resolves_to_refs=[address_id]
                    ),
                    address_type(id=address_id, value=ip)
                ]
                self._handle_attribute_observable(attribute, objects)
                break
        else:
            self._composite_attribute_value_warning(
                attribute['type'], attribute['value']
            )
            self._parse_custom_attribute(attribute)

    def _parse_email_attachment_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        file_id = f"file--{attribute['uuid']}"
        value = attribute['value']
        objects = [
            EmailMessage(
                id=f"email-message--{attribute['uuid']}", is_multipart=True,
                body_multipart=[
                    EmailMIMEComponent(
                        content_disposition=f"attachment; filename='{value}'",
                        body_raw_ref=file_id
                    )
                ]
            ),
            self._create_file(file_id, value)
        ]
        self._handle_attribute_observable(attribute, objects)

    def _parse_email_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        address_object = self._create_email_address(
            f"email-addr--{attribute['uuid']}", attribute['value']
        )
        self._handle_attribute_observable(attribute, [address_object])

    def _parse_email_body_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        message_object = EmailMessage(
            id=f"email-message--{attribute['uuid']}",
            is_multipart=False, body=attribute['value']
        )
        self._handle_attribute_observable(attribute, [message_object])

    def _parse_email_destination_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        address_id = f"email-addr--{attribute['uuid']}"
        objects = [
            EmailMessage(
                id=f"email-message--{attribute['uuid']}",
                is_multipart=False, to_refs=[address_id]
            ),
            self._create_email_address(address_id, attribute['value'])
        ]
        self._handle_attribute_observable(attribute, objects)

    def _parse_email_header_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        message_object = EmailMessage(
            id=f"email-message--{attribute['uuid']}",
            is_multipart=False, received_lines=[attribute['value']]
        )
        self._handle_attribute_observable(attribute, [message_object])

    def _parse_email_message_id_attribute(
            self, attribute: Union[MISPAttribute, dict]):
        if attribute.get('to_ids', False):
            value = self._handle_value_for_pattern(attribute['value'])
            pattern = f"[email-message:message_id = '{value}']"
            self._handle_attribute_indicator(attribute, pattern)
        else:
            message_object = EmailMessage(
                id=f"email-message--{attribute['uuid']}",
                is_multipart=False, message_id=attribute['value']
            )
            self._handle_attribute_observable(attribute, [message_object])

    def _parse_email_reply_to_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        message_object = EmailMessage(
            id=f"email-message--{attribute['uuid']}", is_multipart=False,
            additional_header_fields={"Reply-To": attribute['value']}
        )
        self._handle_attribute_observable(attribute, [message_object])

    def _parse_email_source_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        address_id = f"email-addr--{attribute['uuid']}"
        objects = [
            EmailMessage(
                id=f"email-message--{attribute['uuid']}",
                is_multipart=False, from_ref=address_id
            ),
            self._create_email_address(address_id, attribute['value'])
        ]
        self._handle_attribute_observable(attribute, objects)

    def _parse_email_subject_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        message_object = EmailMessage(
            id=f"email-message--{attribute['uuid']}",
            is_multipart=False, subject=attribute['value']
        )
        self._handle_attribute_observable(attribute, [message_object])

    def _parse_email_x_mailer_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        message_object = EmailMessage(
            id=f"email-message--{attribute['uuid']}", is_multipart=False,
            additional_header_fields={"X-Mailer": attribute['value']}
        )
        self._handle_attribute_observable(attribute, [message_object])

    def _parse_filename_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        file_object = self._create_file(
            f"file--{attribute['uuid']}", attribute['value']
        )
        self._handle_attribute_observable(attribute, [file_object])

    def _parse_github_username_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        account_object = UserAccount(
            id=f"user-account--{attribute['uuid']}",
            account_type='github', account_login=attribute['value']
        )
        self._handle_attribute_observable(attribute, [account_object])

    def _parse_hash_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        hash_type = self._define_hash_type(attribute['type'])
        if not self._check_hash_value(hash_type, attribute['value']):
            raise InvalidHashValueError()
        file_args: dict[str, Union[bool, dict, str]] = {
            'id': f"file--{attribute['uuid']}",
            'hashes': {hash_type: attribute['value']}
        }
        if hash_type not in HASHING_ALGORITHM:
            file_args['allow_custom'] = True
        file_object = File(**file_args)
        self._handle_attribute_observable(attribute, [file_object])

    def _parse_hash_composite_attribute_observable(
            self, attribute: Union[MISPAttribute, dict],
            hash_type: Optional[str] = None):
        file_args = {
            'id': f"file--{attribute['uuid']}"
        }
        for separator in self.composite_separators:
            if separator in attribute['value']:
                if hash_type is None:
                    hash_type = attribute['type'].split('|')[1]
                hash_type = self._define_hash_type(hash_type)
                filename, hash_value = attribute['value'].split(separator)
                if not self._check_hash_value(hash_type, hash_value):
                    raise InvalidHashValueError()
                file_args.update(
                    {'name': filename, 'hashes': {hash_type: hash_value}}
                )
                if hash_type not in HASHING_ALGORITHM:
                    file_args['allow_custom'] = True
                break
        else:
            self._composite_attribute_value_warning(
                attribute['type'], attribute['value']
            )
            file_args['name'] = attribute['value']
        file_object = File(**file_args)
        self._handle_attribute_observable(attribute, [file_object])

    def _parse_hostname_port_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        for separator in self.composite_separators:
            if separator in attribute['value']:
                hostname, port = attribute['value'].split(separator)
                domain_id = f"domain-name--{attribute['uuid']}"
                objects = [
                    DomainName(id=domain_id, value=hostname),
                    NetworkTraffic(
                        id=f"network-traffic--{attribute['uuid']}",
                        dst_port=port, dst_ref=domain_id, protocols=['tcp']
                    )
                ]
                self._handle_attribute_observable(attribute, objects)
                break
        else:
            self._composite_attribute_value_warning(
                attribute['type'], attribute['value']
            )
            self._parse_custom_attribute(attribute)

    def _parse_ip_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        address_type = self._get_address_type(attribute['value'])
        address_id = f"{address_type._type}--{attribute['uuid']}"
        ip_type = attribute['type'].split('-')[1]
        network_traffic_args = {
            'id': f"network-traffic--{attribute['uuid']}",
            f'{ip_type}_ref': address_id, 'protocols': ['tcp']
        }
        objects = [
            NetworkTraffic(**network_traffic_args),
            address_type(id=address_id, value=attribute['value'])
        ]
        self._handle_attribute_observable(attribute, objects)

    def _parse_ip_port_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        for separator in self.composite_separators:
            if separator in attribute['value']:
                ip_value, port_value = attribute['value'].split(separator)
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
                    address_type(id=address_id, value=ip_value)
                ]
                self._handle_attribute_observable(attribute, objects)
                break
        else:
            self._composite_attribute_value_warning(
                attribute['type'], attribute['value']
            )
            self._parse_custom_attribute(attribute)

    def _parse_mac_address_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        mac_address_object = MACAddress(
            id=f"mac-addr--{attribute['uuid']}",
            value=attribute['value'].lower()
        )
        self._handle_attribute_observable(attribute, [mac_address_object])

    def _parse_malware_sample_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        artifact_id = f"artifact--{attribute['uuid']}"
        file_args = {
            'id': f"file--{attribute['uuid']}",
            'content_ref': artifact_id
        }
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
        objects = [
            File(**file_args),
            self._create_artifact(artifact_id, data, malware_sample=True)
        ]
        self._handle_attribute_observable(attribute, objects)

    def _parse_mutex_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        mutex_object = Mutex(
            id=f"mutex--{attribute['uuid']}", name=attribute['value']
        )
        self._handle_attribute_observable(attribute, [mutex_object])

    def _parse_patterning_language_attribute(
            self, attribute: Union[MISPAttribute, dict]):
        indicator_args = {'pattern_type': attribute['type']}
        self._handle_attribute_indicator(
            attribute, f"[{attribute['value']}]", indicator_args=indicator_args
        )

    def _parse_regkey_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        regkey_object = WindowsRegistryKey(
            id=f"windows-registry-key--{attribute['uuid']}",
            key=attribute['value'].strip()
        )
        self._handle_attribute_observable(attribute, [regkey_object])

    def _parse_regkey_value_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        registry_key_args = {
            'id': f"windows-registry-key--{attribute['uuid']}"
        }
        for separator in self.composite_separators:
            if separator in attribute['value']:
                key, value = attribute['value'].split(separator)
                registry_key_args.update(
                    {
                        'key': key.strip(),
                        'values': [WindowsRegistryValueType(data=value.strip())]
                    }
                )
                break
        else:
            self._composite_attribute_value_warning(
                attribute['type'], attribute['value']
            )
            registry_key_args['key'] = attribute['value'].strip()
        regkey_object = WindowsRegistryKey(**registry_key_args)
        self._handle_attribute_observable(attribute, [regkey_object])

    def _parse_url_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        url_object = URL(
            id=f"url--{attribute['uuid']}", value=attribute['value']
        )
        self._handle_attribute_observable(attribute, [url_object])

    def _parse_x509_fingerprint_attribute_observable(
            self, attribute: Union[MISPAttribute, dict]):
        hash_type = self._define_hash_type(attribute['type'].split('-')[-1])
        if not self._check_hash_value(hash_type, attribute['value']):
            raise InvalidHashValueError()
        x509_object = X509Certificate(
            id=f"x509-certificate--{attribute['uuid']}",
            hashes={hash_type: attribute['value']}
        )
        self._handle_attribute_observable(attribute, [x509_object])

    ############################################################################
    #                      MISP OBJECTS PARSING FUNCTIONS                      #
    ############################################################################

    @staticmethod
    def _extract_multiple_object_attributes_with_uuid_and_data(
            attributes: list, force_single: tuple = (), with_uuid: tuple = (),
            with_data: tuple = ()) -> dict:
        attributes_dict = defaultdict(list)
        for attribute in attributes:
            relation = attribute['object_relation']
            if relation not in with_uuid and relation not in with_data:
                if relation in force_single:
                    attributes_dict[relation] = attribute['value']
                else:
                    attributes_dict[relation].append(attribute['value'])
                continue
            value = [attribute['value']]
            if relation in with_data and attribute.get('data'):
                value.append(attribute['data'])
            if relation in with_uuid:
                value.append(attribute['uuid'])
            if relation in force_single:
                attributes_dict[relation] = tuple(value)
            else:
                attributes_dict[relation].append(tuple(value))
        return attributes_dict

    @staticmethod
    def _extract_object_attributes_with_multiple_and_uuid(
        attributes: list, force_single: tuple = (),
        with_uuid: tuple = ()) -> dict:
        attributes_dict = defaultdict(list)
        for attribute in attributes:
            relation = attribute['object_relation']
            value = (
                (attribute['value'], attribute['uuid'])
                if relation in with_uuid else attribute['value']
            )
            if relation in force_single:
                attributes_dict[relation] = value
            else:
                attributes_dict[relation].append(value)
        return attributes_dict

    def _handle_file_observable_object(self, args: dict) -> list:
        return [self._create_file_object(args)]

    def _handle_file_observable_objects(self, args: dict, objects: list):
        objects.insert(0, self._create_file_object(args))

    def _parse_account_object_observable(
            self, misp_object: Union[MISPObject, dict], account_type: str):
        account_args = self._parse_account_args(
            misp_object['Attribute'], account_type
        )
        account_args['id'] = self._parse_stix_object_id(
            'object', 'user-account', misp_object
        )
        account_object = UserAccount(**account_args)
        self._handle_object_observable(misp_object, [account_object])

    def _parse_account_object_with_attachment_observable(
            self, misp_object: Union[MISPObject, dict], account_type: str):
        account_args = self._parse_account_with_attachment_args(
            misp_object['Attribute'], account_type
        )
        account_args['id'] = self._parse_stix_object_id(
            'object', 'user-account', misp_object
        )
        account_object = UserAccount(**account_args)
        self._handle_object_observable(misp_object, [account_object])

    def _parse_android_app_object_observable(
            self, misp_object: Union[MISPObject, dict]):
        software_args = self._parse_android_app_args(misp_object['Attribute'])
        software_args['id'] = self._parse_stix_object_id(
            'object', 'software', misp_object
        )
        software_object = Software(**software_args)
        self._handle_object_observable(misp_object, [software_object])

    def _parse_annotation_object(
            self, to_ids: bool, misp_object: Union[MISPObject, dict]):
        object_refs = []
        for reference in misp_object['ObjectReference']:
            for object_ref in self.object_refs:
                if reference['referenced_uuid'] in object_ref:
                    object_refs.append(object_ref)
                    break
        if not object_refs:
            return self._parse_custom_object(misp_object)
        note_id = self._parse_stix_object_id('object', 'note', misp_object)
        timestamp = self._parse_timestamp_value(misp_object)
        note_args = {
            'id': note_id, 'created': timestamp, 'modified': timestamp,
            'labels': self._create_object_labels(misp_object, to_ids=to_ids),
            'object_refs': object_refs, 'created_by_ref': self.identity_id,
            'interoperability': True
        }
        markings = self._handle_object_tags_and_galaxies(
            misp_object, note_id, timestamp
        )
        if markings:
            self._handle_markings(note_args, markings)
        attributes = self._extract_multiple_object_attributes_with_data(
            misp_object['Attribute'],
            force_single=self._mapping.annotation_single_fields(),
            with_data=self._mapping.annotation_data_fields()
        )
        if attributes.get('text'):
            note_args['content'] = attributes.pop('text')
        if attributes:
            note_args['allow_custom'] = True
            for key, values in attributes.items():
                feature = f"x_misp_{key.replace('-', '_')}"
                if key in self._mapping.annotation_data_fields():
                    note_args[feature] = self._handle_custom_data_field(values)
                    continue
                note_args[feature] = (
                    values[0] if isinstance(values, list) and len(values) == 1
                    else values
                )
        note = self._create_note(note_args)
        getattr(self, self._results_handling_function)(note)
        self._handle_object_analyst_data(note, misp_object)

    def _parse_asn_object_observable(
            self, misp_object: Union[MISPObject, dict]):
        as_args = self._parse_AS_args(misp_object['Attribute'])
        as_args['id'] = self._parse_stix_object_id(
            'object', 'autonomous-system', misp_object
        )
        AS_object = AutonomousSystem(**as_args)
        self._handle_object_observable(misp_object, [AS_object])

    def _parse_cpe_asset_object_observable(
            self, misp_object: Union[MISPObject, dict]):
        software_args = self._parse_cpe_asset_args(misp_object['Attribute'])
        software_args['id'] = self._parse_stix_object_id(
            'object', 'software', misp_object
        )
        software_object = Software(**software_args)
        self._handle_object_observable(misp_object, [software_object])

    def _parse_credential_object_observable(
            self, misp_object: Union[MISPObject, dict]):
        credential_args = self._parse_credential_args(misp_object['Attribute'])
        credential_args['id'] = self._parse_stix_object_id(
            'object', 'user-account', misp_object
        )
        user_object = UserAccount(**credential_args)
        self._handle_object_observable(misp_object, [user_object])

    def _parse_directory_ref(
            self, file_args: dict, objects: list, value: str, uuid: str):
        directory_id = self._parse_stix_object_id(
            'attribute', 'directory', {'uuid': uuid}
        )
        directory = Directory(id=directory_id, path=value)
        objects.append(directory)
        file_args['parent_directory_ref'] = directory_id

    def _parse_domain_ip_object_custom(self, misp_object: list):
        attributes = self._extract_object_attributes_with_multiple_and_uuid(
            misp_object['Attribute'],
            force_single=self._mapping.domain_ip_single_fields(),
            with_uuid=('ip',)
        )
        observables, resolves_to_refs = self._parse_domainip_ip_attributes(
            attributes
        )
        domain_args = {
            'resolves_to_refs': resolves_to_refs,
            'id': self._parse_stix_object_id(
                'object', 'domain-name', misp_object
            )
        }
        domain_args.update(self._parse_domain_args(attributes))
        observables.insert(0, DomainName(**domain_args))
        self._handle_object_observable(misp_object, observables)

    def _parse_domain_ip_object_standard(
            self, misp_object: Union[MISPObject, dict]):
        attributes = self._extract_object_attributes_with_multiple_and_uuid(
            misp_object['Attribute'],
            force_single=self._mapping.domain_ip_single_fields(),
            with_uuid=self._mapping.domain_ip_standard_fields()
        )
        observables, resolves_to_refs = self._parse_domainip_ip_attributes(
            attributes
        )
        if attributes.get('hostname'):
            value, uuid = attributes['hostname']
            domain_args = {
                'id': f'domain-name--{uuid}', 'value': value,
                'resolves_to_refs': resolves_to_refs
            }
            observables.append(DomainName(**domain_args))
        if attributes.get('domain'):
            for domain in attributes['domain']:
                value, uuid = domain
                domain_args = {
                    'id': f'domain-name--{uuid}', 'value': value,
                    'resolves_to_refs': resolves_to_refs
                }
                observables.append(DomainName(**domain_args))
        self._handle_object_observable(misp_object, observables)

    def _parse_domainip_ip_attributes(self, attributes: dict) -> tuple:
        observable_objects = []
        resolves_to_refs = []
        if attributes.get('ip'):
            for ip_value, uuid in attributes.pop('ip'):
                address_type = self._get_address_type(ip_value)
                address_id = f'{address_type._type}--{uuid}'
                observable_objects.append(
                    address_type(id=address_id, value=ip_value)
                )
                resolves_to_refs.append(address_id)
        return observable_objects, resolves_to_refs

    def _parse_email_object_observable(
            self, misp_object: Union[MISPObject, dict]):
        attributes = self._extract_multiple_object_attributes_with_uuid_and_data(
            misp_object['Attribute'],
            with_uuid=self._mapping.email_uuid_fields(),
            with_data=self._mapping.email_data_fields()
        )
        objects = []
        email_message_args: defaultdict = defaultdict(dict)
        email_message_args['is_multipart'] = False
        if attributes.get('from'):
            display_names = self._parse_email_display_names(attributes, 'from')
            value, uuid = self._select_single_feature(attributes, 'from')
            address_id = f'email-addr--{uuid}'
            email_address = self._create_email_address(
                address_id, value, display_name=display_names.get(value)
            )
            objects.append(email_address)
            email_message_args['from_ref'] = address_id
        for feature in ('to', 'cc', 'bcc'):
            if attributes.get(feature):
                display_names = self._parse_email_display_names(
                    attributes, feature
                )
                references = []
                for value, uuid in attributes.pop(feature):
                    address_id = f'email-addr--{uuid}'
                    email_address = self._create_email_address(
                        address_id, value, display_name=display_names.get(value)
                    )
                    objects.append(email_address)
                    references.append(address_id)
                email_message_args[f'{feature}_refs'] = references
        if any(key in attributes for key in self._mapping.email_data_fields()):
            body_multipart = []
            for feature in self._mapping.email_data_fields():
                if not attributes.get(feature):
                    continue
                for attribute in attributes.pop(feature):
                    if len(attribute) == 3:
                        value, data, uuid = attribute
                        if not isinstance(data, str):
                            data = b64encode(data.getvalue()).decode()
                        object_id = f'artifact--{uuid}'
                        objects.append(
                            self._create_artifact(
                                object_id, data, filename=value
                            )
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
                    {'body_multipart': body_multipart, 'is_multipart': True}
                )
        if attributes:
            if attributes.get('from'):
                attributes['from'] = [
                    value[0] for value in attributes.pop('from')
                ]
            email_message_args.update(self._parse_email_args(attributes))
        email_message_args['id'] = self._parse_stix_object_id(
            'object', 'email-message', misp_object
        )
        objects.insert(0, EmailMessage(**email_message_args))
        self._handle_object_observable(misp_object, objects)

    def _parse_file_observable_object(
            self, misp_object: Union[MISPObject, dict]) -> tuple:
        attributes = self._extract_multiple_object_attributes_with_uuid_and_data(
            misp_object['Attribute'],
            force_single=self._mapping.file_single_fields(),
            with_uuid=self._mapping.file_uuid_fields(),
            with_data=self._mapping.file_data_fields()
        )
        objects: list = []
        file_args: defaultdict = defaultdict(dict)
        if attributes.get('path'):
            self._parse_directory_ref(
                file_args, objects, *self._select_single_feature(
                    attributes, 'path'
                )
            )
        if attributes.get('malware-sample'):
            value = self._select_single_feature(attributes, 'malware-sample')
            if len(value) == 3:
                value, data, uuid = value
                artifact_id = f'artifact--{uuid}'
                try:
                    args = self._parse_malware_sample_args(value, data)
                except InvalidHashValueError:
                    self._invalid_object_hash_value_error('MD5', misp_object)
                    args = self._parse_malware_sample_custom_args(value, data)
                args['id'] = artifact_id
                objects.append(Artifact(**args))
                file_args['content_ref'] = artifact_id
            else:
                file_args.update(
                    {'allow_custom': True, 'x_misp_malware_sample': value[0]}
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
                    {'allow_custom': True, 'x_misp_attachment': value[0]}
                )
        if attributes:
            file_args.update(
                self._parse_file_args(
                    attributes,
                    {'uuid': misp_object['uuid'], 'name': misp_object['name']}
                )
            )
        file_args['id'] = self._parse_stix_object_id(
            'object', 'file', misp_object
        )
        return file_args, objects

    def _parse_geolocation_object(self, misp_object: Union[MISPObject, dict]):
        location_id = self._parse_stix_object_id(
            'object', 'location', misp_object
        )
        timestamp = self._parse_timestamp_value(misp_object)
        location_args = {
            'id': location_id, 'created': timestamp, 'modified': timestamp,
            'created_by_ref': self.identity_id, 'interoperability': True,
            'labels': self._create_object_labels(
                misp_object,
                to_ids=self._fetch_ids_flag(misp_object['Attribute'])
            )
        }
        if misp_object.get('comment'):
            location_args['description'] = misp_object['comment']
        markings = self._handle_object_tags_and_galaxies(
            misp_object, location_id, location_args['modified']
        )
        if markings:
            self._handle_markings(location_args, markings)
        attributes = self._extract_object_attributes(misp_object['Attribute'])
        precision = (
            attributes.get('accuracy-radius') and attributes.get('latitude')
            and attributes.get('longitude')
        )
        if precision:
            location_args['precision'] = (
                float(attributes.pop('accuracy-radius')) * 1000
            )
        for key, feature in self._mapping.geolocation_object_mapping().items():
            if attributes.get(key):
                location_args[feature] = attributes.pop(key)
        if attributes:
            location_args.update(self._handle_observable_properties(attributes))
        location = self._create_location(location_args)
        getattr(self, self._results_handling_function)(location)
        self._handle_object_analyst_data(location, misp_object)

    def _parse_http_request_object_observable(
            self, misp_object: Union[MISPObject, dict]):
        attributes = self._extract_object_attributes_with_multiple_and_uuid(
            misp_object['Attribute'],
            force_single=self._mapping.http_request_single_fields(),
            with_uuid=self._mapping.http_request_uuid_fields()
        )
        network_traffic_args = {
            'id': self._parse_stix_object_id(
                'object', 'network-traffic', misp_object
            )
        }
        objects = []
        for feature in ('ip-src', 'ip-dst'):
            if attributes.get(feature):
                ip_value, uuid = attributes.pop(feature)
                address_type = self._get_address_type(ip_value)
                address_id = f'{address_type._type}--{uuid}'
                objects.append(address_type(id=address_id, value=ip_value))
                ref_type = 'src_ref' if feature == 'ip-src' else 'dst_ref'
                network_traffic_args[ref_type] = address_id
        if attributes.get('host'):
            value, uuid = attributes.pop('host')
            domain_id = f'domain-name--{uuid}'
            domain_args = {'id': domain_id, 'value': value}
            if 'dst_ref' in network_traffic_args:
                domain_args['resolves_to_refs'] = [
                    network_traffic_args['dst_ref']
                ]
            else:
                network_traffic_args['dst_ref'] = domain_id
            objects.append(DomainName(**domain_args))
        network_traffic_args.update(self._parse_http_request_args(attributes))
        objects.insert(0, NetworkTraffic(**network_traffic_args))
        self._handle_object_observable(misp_object, objects)

    def _parse_identity_object(self, misp_object: Union[MISPObject, dict]):
        identity_args = self._extract_multiple_object_attributes(
            misp_object['Attribute'],
            force_single=self._mapping.identity_single_fields()
        )
        self._handle_non_indicator_object(
            misp_object, identity_args, 'identity'
        )

    def _parse_image_object_observable(
            self, misp_object: Union[MISPObject, dict]):
        attributes = self._extract_multiple_object_attributes_with_uuid_and_data(
            misp_object['Attribute'],
            with_uuid=self._mapping.image_uuid_fields(),
            with_data=self._mapping.image_data_fields()
        )
        artifact_args = self._parse_image_args(attributes)
        file_args = {
            'id': self._parse_stix_object_id('object', 'file', misp_object)
        }
        if attributes.get('filename'):
            file_args['name'] = self._select_single_feature(
                attributes, 'filename'
            )
        if attributes:
            file_args.update(
                self._handle_observable_multiple_properties(attributes)
            )
        if artifact_args is not None:
            file_args['content_ref'] = artifact_args['id']
            objects = [File(**file_args), Artifact(**artifact_args)]
            self._handle_object_observable(misp_object, objects)
        else:
            self._handle_object_observable(misp_object, [File(**file_args)])

    def _parse_ip_port_object_observable(
            self, misp_object: Union[MISPObject, dict]):
        attributes = self._extract_object_attributes_with_multiple_and_uuid(
            misp_object['Attribute'],
            force_single=self._mapping.ip_port_single_fields(),
            with_uuid=self._mapping.ip_port_uuid_fields()
        )
        protocols = set()
        network_traffic_args = {
            'id': self._parse_stix_object_id(
                'object', 'network-traffic', misp_object
            )
        }
        objects = []
        for feature in ('ip-src', 'ip-dst', 'ip'):
            if attributes.get(feature):
                ref_type = 'src_ref' if feature == 'ip-src' else 'dst_ref'
                if ref_type not in network_traffic_args:
                    ip_value, uuid = self._select_single_feature(
                        attributes, feature
                    )
                    if attributes.get(feature):
                        attributes[feature] = [
                            value[0] for value in attributes.pop(feature)
                        ]
                    address_type = self._get_address_type(ip_value)
                    address_id = f'{address_type._type}--{uuid}'
                    objects.append(address_type(id=address_id, value=ip_value))
                    network_traffic_args[ref_type] = address_id
                    protocols.add(address_type._type.split('-')[0])
                else:
                    attributes[feature] = [
                        value[0] for value in attributes.pop(feature)
                    ]
        if attributes:
            network_traffic_args.update(
                self._parse_ip_port_args(attributes, protocols)
            )
        else:
            network_traffic_args['protocols'] = (
                list(protocols) if protocols else ['tcp']
            )
        objects.insert(0, NetworkTraffic(**network_traffic_args))
        self._handle_object_observable(misp_object, objects)

    def _parse_lnk_object_observable(
            self, misp_object: Union[MISPObject, dict]):
        attributes = self._extract_multiple_object_attributes_with_uuid_and_data(
            misp_object['Attribute'],
            force_single=self._mapping.lnk_single_fields(),
            with_uuid=self._mapping.lnk_uuid_fields(),
            with_data=self._mapping.lnk_data_fields()
        )
        objects: list = []
        file_args: dict[str, Union[bool, datetime, str]] = {
            'id': f"file--{misp_object['uuid']}"
        }
        if attributes.get('path'):
            self._parse_directory_ref(
                file_args, objects, *self._select_single_feature(
                    attributes, 'path'
                )
            )
        elif attributes.get('fullpath'):
            self._parse_directory_ref(
                file_args, objects, *self._select_single_feature(
                    attributes, 'fullpath'
                )
            )
        if attributes.get('malware-sample'):
            value = self._select_single_feature(attributes, 'malware-sample')
            if len(value) == 3:
                value, data, uuid = value
                artifact_id = f'artifact--{uuid}'
                try:
                    args = self._parse_malware_sample_args(value, data)
                except InvalidHashValueError:
                    self._invalid_object_hash_value_error('MD5', misp_object)
                    args = self._parse_malware_sample_custom_args(value, data)
                args['id'] = artifact_id
                objects.append(Artifact(**args))
                file_args['content_ref'] = artifact_id
            else:
                file_args.update(
                    {'allow_custom': True, 'x_misp_malware_sample': value[0]}
                )
        file_args.update(
            self._parse_lnk_args(
                attributes,
                {'uuid': misp_object['uuid'], 'name': misp_object['name']}
            )
        )
        objects.insert(0, self._create_file_object(file_args))
        self._handle_object_observable(misp_object, objects)

    def _parse_mutex_object_observable(
            self, misp_object: Union[MISPObject, dict]):
        mutex_args = self._parse_mutex_args(misp_object['Attribute'])
        mutex_args['id'] = self._parse_stix_object_id(
            'object', 'mutex', misp_object
        )
        self._handle_object_observable(misp_object, [Mutex(**mutex_args)])

    def _parse_netflow_object_observable(
            self, misp_object: Union[MISPObject, dict]):
        attributes = self._extract_object_attributes_with_uuid(
            misp_object['Attribute'],
            with_uuid=self._mapping.netflow_uuid_fields()
        )
        network_traffic_args = {
            'id': self._parse_stix_object_id(
                'object', 'network-traffic', misp_object
            )
        }
        objects = []
        for ref_type in ('src', 'dst'):
            if attributes.get(f'ip-{ref_type}'):
                ip_value, uuid = attributes.pop(f'ip-{ref_type}')
                address_type = self._get_address_type(ip_value)
                address_id = f'{address_type._type}--{uuid}'
                if attributes.get(f'{ref_type}-as'):
                    as_value, uuid = attributes.pop(f'{ref_type}-as')
                    as_id = f'autonomous-system--{uuid}'
                    objects.extend(
                        (
                            address_type(
                                id=address_id, value=ip_value,
                                belongs_to_refs=[as_id]
                            ),
                            AutonomousSystem(
                                id=as_id, number=self._parse_AS_value(as_value)
                            )
                        )

                    )
                else:
                    objects.append(address_type(id=address_id, value=ip_value))
                network_traffic_args[f'{ref_type}_ref'] = address_id
            elif attributes.get(f'{ref_type}-as'):
                attribute = attributes.pop(f'{ref_type}-as')
                attributes[f'{ref_type}-as'] = attribute[0]
        network_traffic_args.update(self._parse_netflow_args(attributes))
        objects.insert(0, NetworkTraffic(**network_traffic_args))
        self._handle_object_observable(misp_object, objects)

    def _parse_network_connection_object_observable(
            self, misp_object: Union[MISPObject, dict]):
        attributes = self._extract_object_attributes_with_uuid(
            misp_object['Attribute'],
            with_uuid=self._mapping.network_traffic_uuid_fields()
        )
        network_traffic_args, objects = self._parse_network_references(
            attributes
        )
        if attributes:
            network_traffic_args.update(
                self._parse_network_connection_args(attributes)
            )
        network_traffic_args['id'] = self._parse_stix_object_id(
            'object', 'network-traffic', misp_object
        )
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

    def _parse_network_socket_object(
            self, misp_object: Union[MISPObject, dict]):
        if self._fetch_ids_flag(misp_object['Attribute']):
            pattern = self._parse_network_socket_object_pattern(
                misp_object['Attribute']
            )
            self._handle_object_indicator(misp_object, pattern)
        else:
            attributes = self._extract_object_attributes_with_multiple_and_uuid(
                misp_object['Attribute'],
                force_single=self._mapping.network_socket_single_fields(),
                with_uuid=self._mapping.network_traffic_uuid_fields()
            )
            network_traffic_args, objects = self._parse_network_references(
                attributes
            )
            if attributes:
                network_traffic_args.update(
                    self._parse_network_socket_args(attributes)
                )
            network_traffic_args['id'] = self._parse_stix_object_id(
                'object', 'network-traffic', misp_object
            )
            objects.insert(0, NetworkTraffic(**network_traffic_args))
            self._handle_object_observable(misp_object, objects)

    def _parse_process_object(self, misp_object: Union[MISPObject, dict]):
        if self._fetch_ids_flag(misp_object['Attribute']):
            pattern = self._parse_process_object_pattern(
                misp_object['Attribute']
            )
            self._handle_object_indicator(misp_object, pattern)
        else:
            attributes = self._extract_object_attributes_with_multiple_and_uuid(
                misp_object['Attribute'],
                force_single=self._mapping.process_single_fields(),
                with_uuid=self._mapping.process_uuid_fields()
            )
            objects = []
            parent_attributes = self._extract_parent_process_attributes(
                attributes
            )
            process_args = defaultdict(list)
            if parent_attributes:
                parent_args = {}
                if parent_attributes.get('parent-image'):
                    filename, uuid = parent_attributes.pop('parent-image')
                    image_uuid = f'file--{uuid}'
                    objects.append(File(id=image_uuid, name=filename))
                    parent_args['image_ref'] = image_uuid
                for feature in self._mapping.parent_process_fields():
                    if parent_attributes.get(feature):
                        parent_args['id'] = (
                            f"process--{parent_attributes[feature][1]}"
                        )
                        break
                parent_mapping = self._mapping.process_object_mapping('parent')
                for key, feature in parent_mapping.items():
                    if parent_attributes.get(key):
                        parent_args[feature] = parent_attributes.pop(key)[0]
                if parent_attributes:
                    parent_args.update(
                        self._handle_parent_process_properties(
                            parent_attributes
                        )
                    )
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
            process_args.update(
                self._parse_process_args(attributes, 'features')
            )
            process_args['id'] = self._parse_stix_object_id(
                'object', 'process', misp_object
            )
            objects.insert(0, Process(**process_args))
            self._handle_object_observable(misp_object, objects)

    def _parse_registry_key_object_observable(
            self, misp_object: Union[MISPObject, dict]):
        registry_key_args = self._parse_registry_key_args(
            misp_object['Attribute']
        )
        registry_key_args['id'] = self._parse_stix_object_id(
            'object', 'windows-registry-key', misp_object
        )
        registry_key = WindowsRegistryKey(**registry_key_args)
        self._handle_object_observable(misp_object, [registry_key])

    @staticmethod
    def _parse_regkey_key_values_observable(attributes: dict) -> dict:
        registry_key_args = {}
        if attributes.get('key'):
            registry_key_args['key'] = attributes.pop('key')
        if attributes.get('last-modified'):
            modif = attributes.pop('last-modified')
            if not isinstance(modif, datetime) and not modif.endswith('Z'):
                modif = f"{modif}Z"
            registry_key_args['modified_time'] = modif
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
            pattern.append(f"{prefix}:modified_time = '{modified}'")
        return pattern

    def _parse_sigma_object(self, misp_object: Union[MISPObject, dict]):
        indicator_args = {}
        custom_fields = defaultdict(list)
        for attribute in misp_object['Attribute']:
            relation = attribute['object_relation']
            value = attribute['value']
            if relation == 'reference':
                reference = {'source_name': 'url', 'url': value}
                if attribute.get('comment'):
                    reference['description'] = attribute['comment']
                indicator_args['external_references'] = [reference]
                continue
            feature = self._mapping.sigma_object_mapping(relation)
            if feature is not None:
                if relation == 'sigma':
                    value = self._handle_value_for_pattern(attribute['value'])
                    indicator_args['pattern_type'] = attribute['type']
                indicator_args[feature] = value
            else:
                custom_fields[f'x_misp_{relation}'].append(attribute['value'])
        if custom_fields:
            indicator_args.update(
                {
                    key: value[0] if len(value) == 1 else value
                    for key, value in custom_fields.items()
                }
            )
        self._handle_patterning_object_indicator(misp_object, indicator_args)

    def _parse_suricata_object(self, misp_object: Union[MISPObject, dict]):
        indicator_args = {}
        for attribute in misp_object['Attribute']:
            relation = attribute['object_relation']
            value = attribute['value']
            if relation == 'ref':
                reference = {'source_name': 'url', 'url': value}
                if attribute.get('comment'):
                    reference['description'] = attribute['comment']
                indicator_args['external_references'] = [reference]
                continue
            feature = self._mapping.suricata_object_mapping(relation)
            if feature is not None:
                if relation == 'suricata':
                    value = self._handle_value_for_pattern(value)
                    indicator_args['pattern_type'] = attribute['type']
                indicator_args[feature] = value
            else:
                indicator_args[f'x_misp_{relation}'] = value
        self._handle_patterning_object_indicator(misp_object, indicator_args)

    def _parse_url_object_observable(
            self, misp_object: Union[MISPObject, dict]):
        url_args = self._parse_url_args(misp_object['Attribute'])
        url_args['id'] = self._parse_stix_object_id(
            'object', 'url', misp_object
        )
        self._handle_object_observable(misp_object, [URL(**url_args)])

    def _parse_user_account_object_observable(
            self, misp_object: Union[MISPObject, dict]):
        user_account_args = self._parse_user_account_args(
            misp_object['Attribute']
        )
        user_account_args['id'] = self._parse_stix_object_id(
            'object', 'user-account', misp_object
        )
        user_account = UserAccount(**user_account_args)
        self._handle_object_observable(misp_object, [user_account])

    def _parse_x509_object_observable(
            self, misp_object: Union[MISPObject, dict]):
        x509_args = self._parse_x509_args(misp_object)
        x509_args['id'] = self._parse_stix_object_id(
            'object', 'x509-certificate', misp_object
        )
        x509_certificate = X509Certificate(**x509_args)
        self._handle_object_observable(misp_object, [x509_certificate])

    def _parse_yara_object(self, misp_object: Union[MISPObject, dict]):
        indicator_args = {}
        for attribute in misp_object['Attribute']:
            relation = attribute['object_relation']
            value = attribute['value']
            feature = self._mapping.yara_object_mapping(relation)
            if feature is not None:
                if relation == 'yara':
                    value = self._handle_value_for_pattern(value)
                    indicator_args['pattern_type'] = attribute['type']
                indicator_args[feature] = value
            else:
                indicator_args[f"x_misp_{relation.replace('-', '_')}"] = value
        self._handle_patterning_object_indicator(misp_object, indicator_args)

    ############################################################################
    #                        GALAXIES PARSING FUNCTIONS                        #
    ############################################################################

    def _create_region_galaxy_args(
            self, cluster: Union[MISPGalaxyCluster, dict], description: str,
            name: str, timestamp: datetime) -> dict:
        region_value = cluster['value'].split(' - ')[1]
        location_args = {
            'id': f"location--{cluster['uuid']}", 'type': 'location',
            'description': f"{description} | {cluster['description']}",
            'labels': self._create_galaxy_labels(name, cluster),
            'name': region_value, 'interoperability': True,
            'region': (
                self._mapping.regions_mapping(region_value)
                or region_value.lower().replace(' ', '-')
            )
        }
        if timestamp is None:
            if not cluster.get('timestamp'):
                return location_args
            timestamp = self._datetime_from_timestamp(cluster['timestamp'])
        location_args.update({'created': timestamp, 'modified': timestamp})
        return location_args

    def _parse_country_galaxy(self, galaxy: Union[MISPGalaxy, dict],
                              timestamp: Union[datetime, None]) -> list:
        object_refs = []
        ids = {}
        for cluster in galaxy['GalaxyCluster']:
            if self._is_galaxy_parsed(object_refs, cluster):
                continue
            location_id = f"location--{cluster['uuid']}"
            country_value = cluster['meta'].get('ISO', cluster['value'])
            location_args = {
                'id': location_id, 'type': 'location',
                'country': self._parse_country_value(country_value),
                'description': f"{galaxy['description']} | {cluster['value']}",
                'labels': self._create_galaxy_labels(galaxy['name'], cluster),
                'name': cluster['description'], 'interoperability': True,
                **self._parse_meta_custom_fields(cluster['meta'])
            }
            if timestamp is None:
                if not cluster.get('timestamp'):
                    location = self._create_location(location_args)
                    self._append_SDO_without_refs(location)
                    object_refs.append(location_id)
                    ids[cluster['uuid']] = location_id
                    continue
                timestamp = self._datetime_from_timestamp(
                    cluster.pop('timestamp')
                )
            location_args.update({'created': timestamp, 'modified': timestamp})
            location = self._create_location(location_args)
            self._append_SDO_without_refs(location)
            object_refs.append(location_id)
            ids[cluster['uuid']] = location_id
        self.populate_unique_ids(ids)
        return object_refs

    def _parse_country_meta_field(self, meta_args: dict, country: list | str):
        if isinstance(country, list):
            country = country[0]
        meta_args['country'] = self._parse_country_value(country)

    def _parse_country_value(
            self, country_value: str, alpha_3: Optional[bool] = False) -> str:
        try:
            country = countries.lookup(country_value)
            if country is None:
                self._country_code_warning(country_value)
                return country_value
            return country.alpha_3 if alpha_3 else country.alpha_2
        except LookupError:
            self._country_code_warning(country_value)
            return country_value

    def _parse_location_attribute_galaxy(self, galaxy: Union[MISPGalaxy, dict],
                                         object_id: str, timestamp: datetime):
        object_refs = self._parse_location_galaxy(galaxy, timestamp)
        self._handle_attribute_galaxy_relationships(
            object_id, object_refs, timestamp
        )

    def _parse_location_event_galaxy(self, galaxy: Union[MISPGalaxy, dict]):
        object_refs = self._parse_location_galaxy(galaxy, self.event_timestamp)
        self._handle_object_refs(object_refs)

    def _parse_location_galaxy(self, galaxy: Union[MISPGalaxy, dict],
                               timestamp: Optional[datetime] = None) -> list:
        if galaxy['type'] == 'country':
            return self._parse_country_galaxy(galaxy, timestamp)
        if galaxy['type'] == 'region':
            return self._parse_region_galaxy(galaxy, timestamp)
        object_refs = []
        ids = {}
        for cluster in galaxy['GalaxyCluster']:
            if self._is_galaxy_parsed(object_refs, cluster):
                continue
            location_id = f"location--{cluster['uuid']}"
            location_args = self._create_galaxy_args(
                cluster, galaxy['name'], location_id, timestamp
            )
            location = self._create_location(location_args)
            self._append_SDO_without_refs(location)
            object_refs.append(location_id)
            ids[cluster['uuid']] = location_id
        self.populate_unique_ids(ids)
        return object_refs

    def _parse_location_parent_galaxy(self, galaxy: Union[MISPGalaxy, dict]):
        object_refs = self._parse_location_galaxy(galaxy)
        self._handle_object_refs(object_refs)

    def _parse_region_galaxy(self, galaxy: Union[MISPGalaxy, dict],
                             timestamp: Union[datetime, None]) -> list:
        object_refs = []
        ids = {}
        for cluster in galaxy['GalaxyCluster']:
            if self._is_galaxy_parsed(object_refs, cluster):
                continue
            location_args = self._create_region_galaxy_args(
                cluster, galaxy['description'], galaxy['name'], timestamp
            )
            location_args.update(
                self._parse_meta_custom_fields(cluster['meta'])
            )
            location = self._create_location(location_args)
            self._append_SDO_without_refs(location)
            object_refs.append(location.id)
            ids[cluster['uuid']] = location.id
        self.populate_unique_ids(ids)
        return object_refs

    ############################################################################
    #                  STIX OBJECTS CREATION HELPER FUNCTIONS                  #
    ############################################################################

    def _create_artifact(
            self, artifact_id: str, content: str,
            filename: Optional[str] = None,
            malware_sample: Optional[bool] = False) -> Artifact:
        args: dict[str, Union[bool, str]] = {
            'id': artifact_id, 'payload_bin': content
        }
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
            id=(
                f"bundle--{self._misp_event.get('uuid')}"
                if hasattr(self, "_misp_event") else None
            )
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

    @staticmethod
    def _create_custom_galaxy(custom_args: dict) -> CustomGalaxyCluster:
        return CustomGalaxyCluster(**custom_args)

    def _create_custom_object(self, custom_args: dict) -> CustomMispObject:
        self._clean_custom_properties(custom_args)
        return CustomMispObject(**custom_args)

    @staticmethod
    def _create_email_address(
            address_id: str, email_address: str,
            display_name: Optional[str] = None) -> EmailAddress:
        args = {'id': address_id, 'value': email_address}
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
        if any(field.startswith('x_') for field in identity_args):
            identity_args['allow_custom'] = True
        return Identity(**identity_args)

    def _create_identity_object(self, orgname: str) -> Identity:
        identity_args = {
            'type': 'identity', 'id': self.identity_id,
            'created': self.event_timestamp, 'modified': self.event_timestamp,
            'name': orgname, 'identity_class': 'organization',
            'interoperability': True
        }
        return self._create_identity(identity_args)

    @staticmethod
    def _create_indicator(indicator_args: dict) -> Indicator:
        indicator_args['spec_version'] = '2.1'
        if indicator_args.get('pattern_type') is None:
            indicator_args['pattern_type'] = 'stix'
        if indicator_args.get('pattern_version') is None:
            indicator_args['pattern_version'] = '2.1'
        return Indicator(**indicator_args)

    @staticmethod
    def _create_intrusion_set(intrusion_set_args: dict) -> IntrusionSet:
        return IntrusionSet(**intrusion_set_args)

    @staticmethod
    def _create_location(location_args: dict) -> Location:
        return Location(**location_args)

    @staticmethod
    def _create_malware(malware_args: dict) -> Malware:
        if 'is_family' not in malware_args:
            malware_args['is_family'] = False
        return Malware(**malware_args)

    @staticmethod
    def _create_note(note_args: dict) -> Note:
        if any(ref.startswith('x-misp-') for ref in note_args['object_refs']):
            note_args['allow_custom'] = True
        return Note(**note_args)

    def _create_observed_data(
            self, args: dict, observables: list) -> ObservedData:
        args['object_refs'] = [observable.id for observable in observables]
        observed_data = ObservedData(**args)
        getattr(self, self._results_handling_function)(observed_data)
        for observable in observables:
            getattr(self, self._results_handling_function)(observable)
        return observed_data

    @staticmethod
    def _create_opinion(opinion_args: dict) -> Opinion:
        return Opinion(**opinion_args)

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
            attachment = self._select_single_feature(attributes, 'attachment')
            artifact_args = self._parse_image_attachment(attachment)
            if artifact_args is not None:
                if attributes.get('url'):
                    value = self._select_single_feature(attributes, 'url')
                    artifact_args['x_misp_url'] = value[0]
                return artifact_args
            attributes['attachment'] = attachment[0]
        if attributes.get('url'):
            url, uuid = self._select_single_feature(attributes, 'url')
            return {
                'id': self._parse_stix_object_id(
                    'attribute', 'artifact', {'uuid': uuid}
                ),
                'url': url
            }
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
        if attributes.get('password'):
            for value in attributes.pop('password'):
                pattern.append(f"user-account:credential = '{value}'")
        return pattern

    @staticmethod
    def _create_process_image_pattern(image: str) -> str:
        return f"process:image_ref.name = '{image}'"

    ############################################################################
    #                            UTILITY FUNCTIONS.                            #
    ############################################################################

    @staticmethod
    def _annotates(references: list) -> bool:
        for reference in references:
            if reference['relationship_type'] == 'annotates':
                return True
        return False

    @staticmethod
    def _get_address_type(address: str) -> Union[IPv4Address, IPv6Address]:
        if ':' in address:
            return IPv6Address
        return IPv4Address

    def _handle_empty_note_refs(self) -> list:
        object_type = 'report' if self._is_published() else 'grouping'
        return [f"{object_type}--{self._misp_event['uuid']}"]

    def _parse_image_attachment(self, attachment: tuple) -> Union[dict, None]:
        if len(attachment) < 3:
            return None
        filename, data, uuid = attachment
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        artifact_args = {
            'payload_bin': data, 'allow_custom': True,
            'id': self._parse_stix_object_id(
                'attribute', 'artifact', {'uuid': uuid}
            )
        }
        if '.' in filename:
            artifact_args['mime_type'] = f"image/{filename.split('.')[-1]}"
        artifact_args['x_misp_filename'] = filename
        return artifact_args

    def _parse_opinion_level(self, opinion: int) -> str:
        if opinion > 80:
            return 'strongly-agree'
        if opinion > 60:
            return 'agree'
        if opinion > 40:
            return 'neutral'
        if opinion > 20:
            return 'disagree'
        return 'strongly-disagree'
