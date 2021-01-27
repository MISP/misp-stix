#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
from . import stix1_mapping
from base64 import b64encode
from collections import defaultdict
from cybox.core import Object, Observable, ObservableComposition, RelatedObject
from cybox.common import Hash, HashList, ByteRun, ByteRuns
from cybox.common.hashes import _set_hash_type
from cybox.common.object_properties import CustomProperties,  Property
from cybox.objects.account_object import Account, Authentication, StructuredAuthenticationMechanism
from cybox.objects.address_object import Address
from cybox.objects.artifact_object import Artifact, RawArtifact
from cybox.objects.as_object import AutonomousSystem
from cybox.objects.custom_object import Custom
from cybox.objects.domain_name_object import DomainName
from cybox.objects.email_message_object import EmailMessage, EmailHeader, EmailRecipients, Attachments
from cybox.objects.file_object import File
from cybox.objects.hostname_object import Hostname
from cybox.objects.http_session_object import HTTPClientRequest, HTTPRequestHeader, HTTPRequestHeaderFields, HTTPRequestLine, HTTPRequestResponse, HTTPSession
from cybox.objects.mutex_object import Mutex
from cybox.objects.network_connection_object import NetworkConnection
from cybox.objects.network_socket_object import NetworkSocket
from cybox.objects.pipe_object import Pipe
from cybox.objects.port_object import Port
from cybox.objects.process_object import ChildPIDList, ImageInfo, PortList, Process
from cybox.objects.socket_address_object import SocketAddress
from cybox.objects.system_object import System, NetworkInterface, NetworkInterfaceList
from cybox.objects.unix_user_account_object import UnixGroup, UnixGroupList, UnixUserAccount
from cybox.objects.uri_object import URI
from cybox.objects.user_account_object import UserAccount
from cybox.objects.whois_object import WhoisEntry, WhoisRegistrants, WhoisRegistrant, WhoisRegistrar, WhoisNameservers
from cybox.objects.win_executable_file_object import (
    Entropy, PEHeaders, PEFileHeader, PEOptionalHeader, PEResourceList,
    PESectionHeaderStruct, PESection, PESectionList, PEVersionInfoResource,
    WinExecutableFile
)
from cybox.objects.win_registry_key_object import RegistryValue, RegistryValues, WinRegistryKey
from cybox.objects.win_service_object import WinService
from cybox.objects.win_user_account_object import WinGroup, WinGroupList, WinUser
from cybox.objects.x509_certificate_object import X509Certificate, X509CertificateSignature, X509Cert, SubjectPublicKey, RSAPublicKey, Validity
from cybox.utils import Namespace
from datetime import datetime
from io import BytesIO
from mixbox import idgen
from stix.coa import CourseOfAction
from stix.common import InformationSource, Identity, ToolInformation
from stix.common.confidence import Confidence
from stix.common.related import RelatedCOA, RelatedIndicator, RelatedObservable, RelatedThreatActor, RelatedTTP
from stix.common.vocabs import IncidentStatus
from stix.core import STIXPackage, STIXHeader
from stix.data_marking import Marking, MarkingSpecification
from stix.exploit_target import ExploitTarget, Vulnerability, Weakness
from stix.exploit_target.vulnerability import CVSSVector
from stix.extensions.identity.ciq_identity_3_0 import CIQIdentity3_0Instance, STIXCIQIdentity3_0, PartyName, ElectronicAddressIdentifier, FreeTextAddress
from stix.extensions.identity.ciq_identity_3_0 import Address as ciq_Address
from stix.extensions.marking.simple_marking import SimpleMarkingStructure
from stix.extensions.marking.tlp import TLPMarkingStructure
from stix.extensions.test_mechanism.snort_test_mechanism import SnortTestMechanism
from stix.extensions.test_mechanism.yara_test_mechanism import YaraTestMechanism
from stix.incident import Incident, Time, ExternalID, AffectedAsset, AttributedThreatActors, COATaken
from stix.incident.history import History, HistoryItem
from stix.indicator import Indicator
from stix.indicator.valid_time import ValidTime
from stix.threat_actor import ThreatActor
from stix.ttp import TTP, Behavior
from stix.ttp.attack_pattern import AttackPattern
from stix.ttp.malware_instance import MalwareInstance
from stix.ttp.resource import Resource, Tools
from typing import List, Optional, Union

_FILE_SINGLE_ATTRIBUTES = (
    "attachment", "authentihash", "entropy", "imphash", "malware-sample", "md5",
    "sha1", "sha224", "sha256", "sha384", "sha512", "sha512/224", "sha512/256",
    "size-in-bytes", "ssdeep", "tlsh", "vhash"
)
_OBSERVABLE_OBJECT_TYPES = Union[
    Address, Artifact, AutonomousSystem, Custom, DomainName, EmailMessage,
    File, Hostname, HTTPSession, Mutex, Pipe, Port, SocketAddress, System,
    URI, WinRegistryKey, WinService, X509Certificate
]
_PE_RELATIONSHIP_TYPES = ('includes', 'included-in')


class MISPtoSTIX1Parser():
    def __init__(self, orgname: str):
        self._orgname = orgname
        self._errors = []
        self._warnings = set()
        self._header_comment = []
        self._objects_to_parse = defaultdict(dict)
        self._contextualised_data = defaultdict(dict)
        self._courses_of_action = {}
        self._threat_actors = {}
        self._ttps = {}
        self._ttp_references = {}

    def parse_misp_event(self, misp_event: dict, version: str):
        if 'Event' in misp_event:
            misp_event = misp_event['Event']
        self._misp_event = misp_event
        self._stix_package = self._create_stix_package(version)
        self._incident = self._create_incident()
        self._generate_stix_objects()
        if 'course_of_action' in self._contextualised_data:
            for course_of_action in self._contextualised_data['course_of_action'].values():
                self._incident.add_coa_taken(course_of_action)
        if 'threat_actor' in self._contextualised_data:
            self._incident.attributed_threat_actors = AttributedThreatActors()
            for threat_actor in self._contextualised_data['threat_actor'].values():
                self._incident.attributed_threat_actors.append(threat_actor)
        if 'ttp' in self._contextualised_data:
            for ttp in self._contextualised_data['ttp'].values():
                self._incident.add_leveraged_ttps(ttp)
        for course_of_action in self._courses_of_action.values():
            self._stix_package.add_course_of_action(course_of_action)
        for threat_actor in self._threat_actors.values():
            self._stix_package.add_threat_actor(threat_actor)
        for uuid, ttp in self._ttps.items():
            if uuid in self._ttp_references:
                for referenced_uuid, relationship in self._ttp_references[uuid]:
                    if referenced_uuid in self._ttps:
                        referenced_ttp = self._ttps[referenced_uuid]
                        related_ttp = self._create_related_ttp(
                            referenced_ttp.id_,
                            relationship,
                            timestamp=referenced_ttp.timestamp
                        )
                        ttp.add_related_ttp(related_ttp)
            self._stix_package.add_ttp(ttp)
        self._stix_package.add_incident(self._incident)
        stix_header = STIXHeader()
        stix_header.title = f"Export from {self._orgname}'s MISP"
        stix_header.package_intents = "Threat Report"
        if self._header_comment and len(self._header_comment) == 1:
            stix_header.description = self._header_comment[0]
        self._stix_package.stix_header = stix_header

    @property
    def stix_package(self) -> STIXPackage:
        return self._stix_package

    ################################################################################
    #                     MAIN STIX PACKAGE CREATION FUNCTIONS                     #
    ################################################################################

    def _create_incident(self) -> Incident:
        incident_id = f"{self._orgname}:Incident-{self._misp_event['uuid']}"
        incident = Incident(
            id_=incident_id,
            title=self._misp_event['info'],
            timestamp=self._datetime_from_timestamp(self._misp_event['timestamp'])
        )
        incident_time = Time()
        incident_time.incident_discovery = self._misp_event['date']
        if self._misp_event.get('published') and self._misp_event.get('publish_timestamp'):
            incident_time.incident_reported = self._datetime_from_timestamp(self._misp_event['publish_timestamp'])
        incident.time = incident_time
        return incident

    def _create_stix_package(self, version: str) -> STIXPackage:
        package_id = f"{self._orgname}:STIXPackage-{self._misp_event['uuid']}"
        timestamp = self._datetime_from_timestamp(self._misp_event['timestamp'])
        stix_package = STIXPackage(id_=package_id, timestamp=timestamp)
        stix_package.version = version
        return stix_package

    def _generate_stix_objects(self):
        if self._misp_event.get('threat_level_id'):
            threat_level = stix1_mapping.threat_level_mapping[int(self._misp_event['threat_level_id'])]
            self._add_journal_entry(f'Event Threat Level: {threat_level}')
        self._add_journal_entry('MISP Tag: misp:tool="MISP-STIX-Converter"')
        tags = self._handle_event_tags_and_galaxies()
        if tags:
            self._incident.handling = self._set_handling(tags)
        if self._misp_event.get('id'):
            external_id = ExternalID(value=self._misp_event['id'], source='MISP Event')
            self._incident.add_external_id(external_id)
        if self._misp_event.get('analysis'):
            status = stix1_mapping.status_mapping[int(self._misp_event['analysis'])]
            self._incident.status = IncidentStatus(status)
        self.orgc_name = self._set_creator()
        self._incident.information_source = self._set_source()
        self._incident.reporter = self._set_reporter()
        if self._misp_event.get('Attribute'):
            self._resolve_attributes()
        if self._misp_event.get('Object'):
            self._resolve_objects()

    def _handle_event_tags_and_galaxies(self) -> tuple:
        if self._misp_event.get('Galaxy'):
            tag_names = []
            for galaxy in self._misp_event['Galaxy']:
                galaxy_type = galaxy['type']
                if galaxy_type in stix1_mapping.galaxy_types_mapping:
                    to_call = stix1_mapping.galaxy_types_mapping[galaxy_type]
                    getattr(self, to_call.format('event'))(galaxy)
                    tag_names.extend(self._quick_fetch_tag_names(galaxy))
                else:
                    self._warnings.add(f'{galaxy_type} galaxy in event not mapped.')
            return tuple(tag['name'] for tag in self._misp_event.get('Tag', []) if tag['name'] not in tag_names)
        return tuple(tag['name'] for tag in self._misp_event.get('Tag', []))

    ################################################################################
    #                         ATTRIBUTES PARSING FUNCTIONS                         #
    ################################################################################

    def _resolve_attributes(self):
        for attribute in self._misp_event['Attribute']:
            attribute_type = attribute['type']
            try:
                if attribute_type in stix1_mapping.attribute_types_mapping:
                    getattr(self, stix1_mapping.attribute_types_mapping[attribute_type])(attribute)
                else:
                    self._parse_custom_attribute(attribute)
                    self._warnings.add(f'MISP Attribute type {attribute_type} not mapped.')
            except Exception:
                self._errors.append(f"Error with the {attribute_type} attribute: {attribute['value']}.")

    def _handle_attribute(self, attribute: dict, observable: Observable):
        if attribute.get('to_ids', False):
            indicator = self._create_indicator_from_attribute(attribute)
            indicator.add_indicator_type(self._set_indicator_type(attribute['type']))
            indicator.add_valid_time_position(ValidTime())
            indicator.add_observable(observable)
            tags = self._handle_attribute_tags_and_galaxies(attribute, indicator)
            if tags:
                indicator.handling = self._set_handling(tags)
            related_indicator = RelatedIndicator(
                indicator,
                relationship=attribute['category']
            )
            self._incident.related_indicators.append(related_indicator)
        else:
            related_observable = RelatedObservable(
                observable,
                relationship=attribute['category']
            )
            self._incident.related_observables.append(related_observable)

    def _handle_attribute_tags_and_galaxies(self, attribute: dict, indicator: Indicator) -> tuple:
        if attribute.get('Galaxy'):
            tag_names = []
            for galaxy in attribute['Galaxy']:
                galaxy_type = galaxy['type']
                if galaxy_type in stix1_mapping.galaxy_types_mapping:
                    to_call = stix1_mapping.galaxy_types_mapping[galaxy_type]
                    getattr(self, to_call.format('attribute'))(galaxy, indicator)
                    tag_names.extend(self._quick_fetch_tag_names(galaxy))
                else:
                    self._warnings.add(f"{galaxy_type} galaxy in {attribute['type']} attribute not mapped.")
            return tuple(tag['name'] for tag in attribute.get('Tag', []) if tag['name'] not in tag_names)
        return tuple(tag['name'] for tag in attribute.get('Tag', []))

    def _handle_exploit_target(self, attribute: dict, stix_object: Union[Vulnerability, Weakness], stix_type: str):
        attribute_uuid = attribute['uuid']
        ttp = self._create_ttp(attribute)
        timestamp = self._datetime_from_timestamp(attribute['timestamp'])
        exploit_target = ExploitTarget(timestamp=timestamp)
        exploit_target.id_ = f"{self._orgname}:ExploitTarget-{attribute_uuid}"
        if attribute.get('comment') and attribute['comment'] != "Imported via the freetext import.":
            exploit_target.description = attribute['comment']
        exploit_target.title = f"{stix_type.capitalize()} {attribute['value']}"
        getattr(exploit_target, f"add_{stix_type}")(stix_object)
        ttp.add_exploit_target(exploit_target)
        tags = self._handle_non_indicator_attribute_tags_and_galaxies(attribute, ttp)
        if tags:
            ttp.handling = self._set_handling(tags)
        related_ttp = self._create_related_ttp(ttp.id_, attribute['type'], timestamp=timestamp)
        self._handle_related_ttps({attribute_uuid: related_ttp})
        self._ttps[attribute_uuid] = ttp

    def _handle_non_indicator_attribute_tags_and_galaxies(self, attribute: dict, ttp: TTP) -> tuple:
        if attribute.get('Galaxy'):
            tag_names = []
            for galaxy in attribute['Galaxy']:
                galaxy_type = galaxy['type']
                if galaxy_type not in stix1_mapping.ttp_names:
                    if galaxy_type not in stix1_mapping.galaxy_types_mapping:
                        self._warnings.add(f"{galaxy_type} galaxy in {attribute['type']} attribute not mapped.")
                    continue
                to_call = stix1_mapping.galaxy_types_mapping[galaxy_type]
                getattr(self, to_call.format('object'))(galaxy, ttp)
                tag_names.extend(self._quick_fetch_tag_names(galaxy))
            return tuple(tag['name'] for tag in attribute.get('Tag', []) if tag['name'] not in tag_names)
        return tuple(tag['name'] for tag in attribute.get('Tag', []))

    def _parse_attachment(self, attribute: dict):
        if attribute.get('data'):
            observable = self._create_attachment_observable(
                attribute['value'],
                attribute['data'],
                attribute['uuid']
            )
            self._handle_attribute(attribute, observable)
        else:
            self._parse_file_attribute(attribute)

    def _parse_autonomous_system_attribute(self, attribute: dict):
        autonomous_system = self._create_autonomous_system_object(attribute['value'])
        observable = self._create_observable(autonomous_system, attribute['uuid'], 'AS')
        self._handle_attribute(attribute, observable)

    def _parse_custom_attribute(self, attribute: dict):
        custom_object = Custom()
        custom_object.custom_properties = CustomProperties()
        custom_object.custom_properties.append(self._create_property(
            attribute['type'],
            attribute['value']
        ))
        observable = self._create_observable(custom_object, attribute['uuid'], 'Custom')
        self._handle_attribute(attribute, observable)

    def _parse_domain_attribute(self, attribute: dict):
        observable = self._create_domain_observable(attribute['value'], attribute['uuid'])
        self._handle_attribute(attribute, observable)

    def _parse_domain_ip_attribute(self, attribute: dict):
        domain, ip = attribute['value'].split('|')
        domain_observable = self._create_domain_observable(domain, attribute['uuid'])
        address_observable = self._create_address_observable(attribute['type'], ip, attribute['uuid'])
        composite_object = ObservableComposition(
            observables=[domain_observable, address_observable]
        )
        composite_object.operator = "AND"
        observable = Observable(
            id_=f"{self._orgname}:ObservableComposition-{attribute['uuid']}"
        )
        observable.observable_composition = composite_object
        self._handle_attribute(attribute, observable)

    def _parse_email_attachment(self, attribute: dict):
        file_object = File()
        file_object.file_name = attribute['value']
        file_object.file_name.condition = "Equals"
        file_object.parent.id_ = f"{self._orgname}:File-{attribute['uuid']}"
        email = EmailMessage()
        email.attachments = Attachments()
        email.attachments.append(file_object.parent.id_)
        email.add_related(file_object, "Contains", inline=True)
        email.parent.related_objects[0].id_ = f"{self._orgname}:File-{attribute['uuid']}"
        observable = self._create_observable(email, attribute['uuid'], 'EmailMessage')
        self._handle_attribute(attribute, observable)

    def _parse_email_attribute(self, attribute: dict):
        email_object = EmailMessage()
        email_header = EmailHeader()
        feature = stix1_mapping.email_attribute_mapping[attribute['type']]
        setattr(email_header, feature, attribute['value'])
        setattr(getattr(email_header, feature), 'condition', 'Equals')
        email_object.header = email_header
        observable = self._create_observable(email_object, attribute['uuid'], 'EmailMessage')
        self._handle_attribute(attribute, observable)

    def _parse_file_attribute(self, attribute: dict):
        file_object = self._create_file_object(attribute['value'])
        observable = self._create_observable(file_object, attribute['uuid'], 'File')
        self._handle_attribute(attribute, observable)

    def _parse_hash_attribute(self, attribute: dict):
        hash = self._parse_hash_value(attribute['type'], attribute['value'])
        file_object = File()
        file_object.add_hash(hash)
        observable = self._create_observable(file_object, attribute['uuid'], 'File')
        self._handle_attribute(attribute, observable)

    def _parse_hash_composite_attribute(self, attribute: dict):
        filename, hash_value = attribute['value'].split('|')
        file_object = self._create_file_object(filename)
        attribute_type = attribute['type'].split('|')[1] if '|' in attribute['type'] else 'filename|md5'
        hash = self._parse_hash_value(attribute_type, hash_value)
        file_object.add_hash(hash)
        observable = self._create_observable(file_object, attribute['uuid'], 'File')
        self._handle_attribute(attribute, observable)

    @staticmethod
    def _parse_hash_value(attribute_type: str, attribute_value: str):
        args = {'hash_value': attribute_value, 'exact': True}
        if hasattr(Hash, f'TYPE_{attribute_type.upper()}'):
            args['type_'] = getattr(Hash, f'TYPE_{attribute_type.upper()}')
            return Hash(**args)
        hash = Hash(**args)
        _set_hash_type(hash, attribute_value)
        return hash

    def _parse_hostname_attribute(self, attribute: dict):
        observable = self._create_hostname_observable(attribute['value'], attribute['uuid'])
        self._handle_attribute(attribute, observable)

    def _parse_hostname_port_attribute(self, attribute: dict):
        hostname, port = attribute['value'].split('|')
        socket_address = self._create_socket_address_object(hostname=hostname, port=port)
        observable = self._create_observable(socket_address, attribute['uuid'], 'SocketAddress')
        self._handle_attribute(attribute, observable)

    def _parse_http_method_attribute(self, attribute: dict):
        http_client_request = HTTPClientRequest()
        http_request_line = HTTPRequestLine()
        http_request_line.http_method = attribute['value']
        http_request_line.http_method.condition = "Equals"
        http_client_request.http_request_line = http_request_line
        self._parse_http_session(attribute, http_client_request)

    def _parse_http_session(self, attribute: dict, http_client_request: HTTPClientRequest):
        http_request_response = HTTPRequestResponse()
        http_request_response.http_client_request = http_client_request
        http_session_object = HTTPSession()
        http_session_object.http_request_response = http_request_response
        observable = self._create_observable(http_session_object, attribute['uuid'], 'HTTPSession')
        self._handle_attribute(attribute, observable)

    def _parse_ip_attribute(self, attribute: dict):
        address_object = self._create_address_object(attribute['type'], attribute['value'])
        observable = self._create_observable(address_object, attribute['uuid'], 'Address')
        self._handle_attribute(attribute, observable)

    def _parse_ip_port_attribute(self, attribute: dict):
        ip, port = attribute['value'].split('|')
        ip_type = attribute['type'].split('|')[0]
        socket_address = self._create_socket_address_object(ip=(ip_type, ip), port=port)
        observable = self._create_observable(socket_address, attribute['uuid'], 'SocketAddress')
        self._handle_attribute(attribute, observable)

    def _parse_mac_address(self, attribute: dict):
        network_interface = NetworkInterface()
        network_interface.mac = attribute['value']
        network_interface_list = NetworkInterfaceList()
        network_interface_list.append(network_interface)
        system_object = System()
        system_object.network_interface_list = network_interface_list
        observable = self._create_observable(system_object, attribute['uuid'], 'System')
        self._handle_attribute(attribute, observable)

    def _parse_malware_sample(self, attribute: dict):
        if attribute.get('data'):
            observable = self._create_malware_sample_observable(
                attribute['value'],
                attribute['data'],
                attribute['uuid']
            )
            self._handle_attribute(attribute, observable)
        else:
            self._parse_hash_composite_attribute(attribute)

    def _parse_mutex_attribute(self, attribute: dict):
        mutex_object = self._create_mutex_object(attribute['value'])
        observable = self._create_observable(mutex_object, attribute['uuid'], 'Mutex')
        self._handle_attribute(attribute, observable)

    def _parse_named_pipe(self, attribute: dict):
        pipe_object = Pipe()
        pipe_object.named = True
        pipe_object.name = attribute['value']
        pipe_object.name.condition = "Equals"
        observable = self._create_observable(pipe_object, attribute['uuid'], 'Pipe')
        self._handle_attribute(attribute, observable)

    def _parse_pattern_attribute(self, attribute: dict):
        byte_run = ByteRun()
        byte_run.byte_run_data = attribute['value']
        file_object = File()
        file_object.byte_runs = ByteRuns(byte_run)
        observable = self._create_observable(file_object, attribute['uuid'], 'File')
        self._handle_attribute(attribute, observable)

    def _parse_port_attribute(self, attribute: dict):
        observable = self._create_port_observable(attribute['value'], attribute['uuid'])
        self._handle_attribute(attribute, observable)

    def _parse_regkey_attribute(self, attribute: dict):
        registry_key = self._create_registry_key_object(attribute['value'])
        observable = self._create_observable(registry_key, attribute['uuid'], 'WindowsRegistryKey')
        self._handle_attribute(attribute, observable)

    def _parse_regkey_value_attribute(self, attribute: dict):
        regkey, value = attribute['value'].split('|')
        registry_key = self._create_registry_key_object(regkey)
        registry_value = RegistryValue()
        registry_value.data = value.strip()
        registry_value.data.condition = "Equals"
        registry_key.values = RegistryValues(registry_value)
        observable = self._create_observable(registry_key, attribute['uuid'], 'WindowsRegistryKey')
        self._handle_attribute(attribute, observable)

    def _parse_snort_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            test_mechanism = SnortTestMechanism()
            test_mechanism.rules = [
                {
                    "value": attribute['value'],
                    "encoded": True
                }
            ]
            self._parse_test_mechanism(attribute, test_mechanism)
        else:
            self._parse_custom_attribute(attribute)

    def _parse_target_attribute(self, attribute: dict, identity_spec: STIXCIQIdentity3_0):
        ciq_identity = CIQIdentity3_0Instance()
        ciq_identity.specification = identity_spec
        ciq_identity.id_ = f"{self._orgname}:Identity-{attribute['uuid']}"
        ciq_identity.name = f"{attribute['category']}: {attribute['value']} (MISP Attribute)"
        self._incident.add_victim(ciq_identity)

    def _parse_target_email(self, attribute: dict):
        identity_spec = STIXCIQIdentity3_0()
        identity_spec.add_electronic_address_identifier(ElectronicAddressIdentifier(value=attribute['value']))
        self._parse_target_attribute(attribute, identity_spec)

    def _parse_target_external(self, attribute: dict):
        identity_spec = STIXCIQIdentity3_0()
        identity_spec.party_name = PartyName(name_lines=[f"External target: {attribute['value']}"])
        self._parse_target_attribute(attribute, identity_spec)

    def _parse_target_location(self, attribute: dict):
        identity_spec = STIXCIQIdentity3_0()
        identity_spec.add_address(ciq_Address(FreeTextAddress(address_lines=[attribute['value']])))
        self._parse_target_attribute(attribute, identity_spec)

    def _parse_target_machine(self, attribute: dict):
        affected_asset = AffectedAsset()
        description = attribute['value']
        if attribute.get('comment'):
            description = f"{description} ({attribute['comment']})"
        affected_asset.description = description
        self._incident.affected_assets.append(affected_asset)

    def _parse_target_org(self, attribute: dict):
        identity_spec = STIXCIQIdentity3_0()
        identity_spec.party_name = PartyName(organisation_names=[attribute['value']])
        self._parse_target_attribute(attribute, identity_spec)

    def _parse_target_user(self, attribute: dict):
        identity_spec = STIXCIQIdentity3_0()
        identity_spec.party_name = PartyName(person_names=[attribute['value']])
        self._parse_target_attribute(attribute, identity_spec)

    def _parse_test_mechanism(self, attribute: dict, test_mechanism: Union[SnortTestMechanism, YaraTestMechanism]):
        indicator = self._create_indicator_from_attribute(attribute)
        tags = self._handle_attribute_tags_and_galaxies(attribute, indicator)
        if tags:
            indicator.handling = self._set_handling(tags)
        indicator.add_indicator_type("Malware Artifacts")
        indicator.add_valid_time_position(ValidTime())
        indicator.add_test_mechanism(test_mechanism)
        related_indicator = RelatedIndicator(indicator, relationship=attribute['category'])
        self._incident.related_indicators.append(related_indicator)

    def _parse_url_attribute(self, attribute: dict):
        observable = self._create_uri_observable(attribute['value'], attribute['uuid'])
        self._handle_attribute(attribute, observable)

    def _parse_undefined_attribute(self, attribute: dict):
        if attribute.get('comment') and attribute['comment'] == 'Imported from STIX header description':
            self._header_comment.append(attribute['value'])
        else:
            self._add_journal_entry(f"Attribute ({attribute['category']} - {attribute['type']}): {attribute['value']}")

    def _parse_user_agent_attribute(self, attribute: dict):
        http_client_request = HTTPClientRequest()
        http_request_header = HTTPRequestHeader()
        header_fields = HTTPRequestHeaderFields()
        header_fields.user_agent = attribute['value']
        header_fields.user_agent.condition = "Equals"
        http_request_header.parsed_header = header_fields
        http_client_request.http_request_header = http_request_header
        self._parse_http_session(attribute, http_client_request)

    def _parse_vulnerability_attribute(self, attribute: dict):
        vulnerability = Vulnerability()
        vulnerability.cve_id = attribute['value']
        self._handle_exploit_target(attribute, vulnerability, 'vulnerability')

    def _parse_weakness_attribute(self, attribute: dict):
        weakness = Weakness()
        weakness.cwe_id = attribute['value']
        self._handle_exploit_target(attribute, weakness, 'weakness')

    def _parse_windows_service_attribute(self, attribute: dict):
        windows_service = WinService()
        feature = 'service_name' if attribute['type'] == 'windows-service-name' else 'display_name'
        setattr(windows_service, feature, attribute['value'])
        observable = self._create_observable(windows_service, attribute['uuid'], 'WindowsService')
        self._handle_attribute(attribute, observable)

    def _parse_x509_fingerprint_attribute(self, attribute: dict):
        x509_signature = X509CertificateSignature()
        signature_algorithm = attribute['type'].split('-')[-1].upper()
        for feature, value in zip(('signature', 'signature_algorithm'), (attribute['value'], signature_algorithm)):
            setattr(x509_signature, feature, value)
            setattr(getattr(x509_signature, feature), 'condition', 'Equals')
        x509_certificate = X509Certificate()
        x509_certificate.certificate_signature = x509_signature
        observable = self._create_observable(x509_certificate, attribute['uuid'], 'X509Certificate')
        self._handle_attribute(attribute, observable)

    def _parse_yara_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            test_mechanism = YaraTestMechanism()
            test_mechanism.rule = {
                "value": attribute['value'],
                "encoded": True
            }
            self._parse_test_mechanism(attribute, test_mechanism)
        else:
            self._parse_custom_attribute(attribute)

    ################################################################################
    #                        MISP OBJECTS PARSING FUNCTIONS                        #
    ################################################################################

    def _resolve_objects(self):
        for misp_object in self._misp_event['Object']:
            object_name = misp_object['name']
            if self._check_object_name(misp_object):
                continue
            try:
                if object_name in stix1_mapping.non_indicator_names:
                    getattr(self, stix1_mapping.non_indicator_names[object_name])(misp_object)
                else:
                    to_ids = self._fetch_ids_flags(misp_object['Attribute'])
                    to_call = self._fetch_objects_mapping_function(object_name)
                    observable = getattr(self, to_call)(misp_object)
                    if to_ids:
                        self._handle_misp_object_with_context(misp_object, observable)
                    else:
                        self._handle_misp_object(observable, misp_object.get('meta-category'))
            except Exception:
                self._errors.append(f"Error with the {object_name} object: {misp_object['uuid']}.")
        if self._objects_to_parse:
            if 'file' in self._objects_to_parse:
                self._resolve_files_to_parse()

    def _add_custom_property(self, stix_object: File, name: str, value: str):
        prop = self._create_property(name, value)
        try:
            stix_object.custom_properties.append(prop)
        except AttributeError:
            stix_object.custom_properties = CustomProperties()
            stix_object.custom_properties.append(prop)

    def _check_object_name(self, misp_object: dict) -> bool:
        object_name = misp_object['name']
        if object_name == 'original-imported-file':
            return True
        if object_name in ('pe', 'pe-section'):
            self._objects_to_parse[object_name][misp_object['uuid']] = misp_object
            return True
        if object_name == 'file' and misp_object.get('ObjectReference'):
            for reference in misp_object['ObjectReference']:
                if self._check_references_fields(reference, ('includes', 'included-in'), 'pe'):
                    self._objects_to_parse[object_name][misp_object['uuid']] = misp_object
                    return True
        return False

    def _check_reference(self, reference: dict, relationship_types: tuple, object_name: str) -> bool:
        if self._check_references_fields(reference, relationship_types, object_name):
            if reference['referenced_uuid'] not in self._objects_to_parse[object_name]:
                self._warnings.add(f"Reference to a non existing {object_name} object: {reference['referenced_uuid']}")
                return False
            return True
        return False

    @staticmethod
    def _check_references_fields(reference: dict, relationship_types: tuple, object_name: str) -> bool:
        if reference['relationship_type'] not in relationship_types:
            return False
        if reference.get('Object') and reference['Object']['name'] == object_name:
            return True
        return False

    @staticmethod
    def _extract_file_attributes(attributes: list) -> dict:
        attributes_dict = defaultdict(list)
        for attribute in attributes:
            value = attribute['value']
            relation = attribute['object_relation']
            if relation in _FILE_SINGLE_ATTRIBUTES:
                if attribute.get('data'):
                    value = (value, attribute['data'], attribute['uuid'])
                attributes_dict[relation] = value
            else:
                attributes_dict[relation].append(value)
        return attributes_dict

    @staticmethod
    def _extract_multiple_object_attributes(attributes: list, force_single: Optional[tuple] = None) -> dict:
        attributes_dict = defaultdict(list)
        if force_single is not None:
            for attribute in attributes:
                relation = attribute['object_relation']
                if relation in force_single:
                    attributes_dict[relation] = attribute['value']
                else:
                    attributes_dict[relation].append(attribute['value'])
            return attributes_dict
        for attribute in attributes:
            attributes_dict[attribute['object_relation']].append(attribute['value'])
        return attributes_dict

    @staticmethod
    def _extract_multiple_object_attributes_with_uuid(attributes: list, with_uuid: Optional[list] = None) -> dict:
        attributes_dict = defaultdict(list)
        if with_uuid is not None:
            for attribute in attributes:
                relation = attribute['object_relation']
                value = (attribute['value'], attribute['uuid']) if relation in with_uuid else attribute['value']
                attributes_dict[relation].append(value)
            return attributes_dict
        for attribute in attributes:
            attributes_dict[attribute['object_relation']].append(
                (
                    attribute['value'],
                    attribute['uuid']
                )
            )
        return attributes_dict

    def _extract_object_attribute_tags_and_galaxies(self, misp_object: dict) -> tuple:
        tags = set()
        galaxies = {}
        for attribute in misp_object['Attribute']:
            if attribute.get('Galaxy'):
                for galaxy in attribute['Galaxy']:
                    galaxy_type = galaxy['type']
                    if galaxy_type not in stix1_mapping.galaxy_types_mapping:
                        self._warnings.add(f"{galaxy_type} galaxy in {misp_object['name']} object not mapped.")
                        continue
                    if galaxy_type in galaxies:
                        self._merge_galaxy_clusters(galaxies[galaxy_type], galaxy)
                    else:
                        galaxies[galaxy_type] = galaxy
            if attribute.get('Tag'):
                tags.update(tag['name'] for tag in attribute['Tag'])
        return tags, galaxies

    @staticmethod
    def _extract_object_attributes(attributes: list) -> dict:
        return {attribute['object_relation']: attribute['value'] for attribute in attributes}

    @staticmethod
    def _extract_object_attributes_with_uuid(attributes: list) -> dict:
        return {attribute['object_relation']: (attribute['value'], attribute['uuid']) for attribute in attributes}

    @staticmethod
    def _fetch_ids_flags(attributes: list) -> bool:
        for attribute in attributes:
            if attribute.get('to_ids', False):
                return True
        return False

    @staticmethod
    def _fetch_objects_mapping_function(object_name: str) -> str:
        if object_name in stix1_mapping.objects_mapping:
            return stix1_mapping.objects_mapping[object_name]
        return '_parse_custom_object'

    def _handle_custom_properties(self, attributes: dict, multiple: Optional[bool] = True) -> CustomProperties:
        custom_properties = CustomProperties()
        if not multiple:
            for object_relation, value in attributes.items():
                custom_properties.append(self._create_property(object_relation, value))
            return custom_properties
        for object_relation, values in attributes.items():
            for value in values:
                custom_properties.append(self._create_property(object_relation, value))
        return custom_properties

    def _handle_misp_object(self, observable: Observable, category: str):
        related_observable = RelatedObservable(
            observable,
            relationship=category
        )
        self._incident.related_observables.append(related_observable)

    def _handle_misp_object_with_context(self, misp_object: dict, observable: Observable):
        indicator = self._create_indicator_from_object(misp_object)
        indicator.add_indicator_type(self._set_indicator_type(misp_object['name']))
        indicator.add_valid_time_position(ValidTime())
        indicator.add_observable(observable)
        tags = self._handle_object_tags_and_galaxies(misp_object, indicator)
        if tags:
            indicator.handling = self._set_handling(tags)
        related_indicator = RelatedIndicator(
            indicator,
            relationship=misp_object.get('meta-category')
        )
        self._incident.related_indicators.append(related_indicator)

    def _handle_non_indicator_object_tags_and_galaxies(self, misp_object: dict, stix_object: Union[TTP, CourseOfAction], galaxy_name: str) -> tuple:
        tags, galaxies = self._extract_object_attribute_tags_and_galaxies(misp_object)
        tag_names = set()
        if galaxies:
            for galaxy_type, galaxy in galaxies.items():
                if galaxy_type in getattr(stix1_mapping, galaxy_name):
                    to_call = stix1_mapping.galaxy_types_mapping[galaxy_type]
                    getattr(self, to_call.format('object'))(galaxy, stix_object)
                    tag_names.update(self._quick_fetch_tag_names(galaxy))
            return tuple(tag for tag in tags if tag not in tag_names)
        return tuple(tag for tag in tags)

    def _handle_object_tags_and_galaxies(self, misp_object: dict, indicator: Indicator) -> tuple:
        tags, galaxies = self._extract_object_attribute_tags_and_galaxies(misp_object)
        tag_names = set()
        if galaxies:
            for galaxy_type, galaxy in galaxies.items():
                to_call = stix1_mapping.galaxy_types_mapping[galaxy_type]
                getattr(self, to_call.format('attribute'))(galaxy, indicator)
                tag_names.update(self._quick_fetch_tag_names(galaxy))
            return tuple(tag for tag in tags if tag not in tag_names)
        return tuple(tag for tag in tags)

    def _handle_ttp_from_object(self, misp_object: dict, ttp: TTP):
        tags = self._handle_non_indicator_object_tags_and_galaxies(misp_object, ttp, 'ttp_names')
        if tags:
            ttp.handling = self._set_handling(tags)
        related_ttp = self._create_related_ttp(
            ttp.id_,
            misp_object['name'],
            timestamp=self._datetime_from_timestamp(misp_object['timestamp'])
        )
        self._contextualised_data['ttp'][misp_object['uuid']] = related_ttp
        self._ttps[misp_object['uuid']] = ttp

    def _parse_asn_object(self, misp_object: dict) -> Observable:
        attributes = self._extract_multiple_object_attributes(
            misp_object['Attribute'],
            force_single=('asn', 'description')
        )
        as_object = self._create_autonomous_system_object(attributes.pop('asn'))
        if 'description' in attributes:
            as_object.name = attributes.pop('description')
        if attributes:
            as_object.custom_properties = self._handle_custom_properties(attributes)
        observable = self._create_observable(as_object, misp_object['uuid'], 'AS')
        return observable

    def _parse_attack_pattern_object(self, misp_object: dict):
        ttp = self._create_ttp_from_object(misp_object)
        attack_pattern = AttackPattern()
        attack_pattern.id_ = f"{self._orgname}:AttackPattern-{misp_object['uuid']}"
        attributes = self._extract_object_attributes(misp_object['Attribute'])
        for key, feature in stix1_mapping.attack_pattern_object_mapping.items():
            if key in attributes:
                setattr(attack_pattern, feature, attributes.pop(key))
        if attack_pattern.capec_id and not attack_pattern.capec_id.startswith('CAPEC'):
            attack_pattern.capec_id = f'CAPEC-{attack_pattern.capec_id}'
        if misp_object.get('ObjectReference'):
            references = tuple((reference['referenced_uuid'], reference['relationship_type']) for reference in misp_object['ObjectReference'])
            self._ttp_references[misp_object['uuid']] = references
        behavior = Behavior()
        behavior.add_attack_pattern(attack_pattern)
        ttp.behavior = behavior
        self._handle_ttp_from_object(misp_object, ttp)

    def _parse_course_of_action_object(self, misp_object: dict):
        course_of_action = CourseOfAction()
        uuid = misp_object['uuid']
        course_of_action.id_ = f'{self._orgname}:CourseOfAction-{uuid}'
        attributes = self._extract_object_attributes(misp_object['Attribute'])
        for key, feature in stix1_mapping.course_of_action_object_mapping.items():
            if key in attributes:
                setattr(course_of_action, feature, attributes.pop(key))
        tags = self._handle_non_indicator_object_tags_and_galaxies(misp_object, course_of_action, 'course_of_action_names')
        if tags:
            course_of_action.handling = self._set_handling(tags)
        coa_taken = self._create_coa_taken(
            course_of_action.id_,
            timestamp=self._datetime_from_timestamp(misp_object['timestamp'])
        )
        self._contextualised_data['course_of_action'][uuid] = coa_taken
        self._courses_of_action[uuid] = course_of_action

    def _parse_credential_arguments(self, attributes: dict) -> dict:
        args = {}
        if 'format' in attributes:
            struct_auth_meca = StructuredAuthenticationMechanism()
            struct_auth_meca.description = attributes.pop('format')[0]
            args['auth_format'] = struct_auth_meca
        if 'type' in attributes:
            args['auth_type'] = attributes.pop('type')[0]
        return args

    def _parse_credential_authentication(self, attributes: dict) -> list:
        args = self._parse_credential_arguments(attributes)
        authentication_list = []
        if 'password' in attributes:
            for password in attributes.pop('password'):
                authentication = self._create_authentication_object(password=password, **args)
                authentication_list.append(authentication)
            return authentication_list
        if args:
            return [self._create_authentication_object(**args)]
        return []

    def _parse_credential_object(self, misp_object: dict) -> Observable:
        single_attributes = ('username', 'text')
        attributes = self._extract_multiple_object_attributes(
            misp_object['Attribute'],
            force_single=single_attributes
        )
        account_object = UserAccount()
        for feature, field in zip(single_attributes, ('username', 'description')):
            if feature in attributes:
                setattr(account_object, field, attributes.pop(feature))
        authentication_list = self._parse_credential_authentication(attributes)
        if authentication_list:
            account_object.authentication = authentication_list
        if attributes:
            account_object.custom_properties = self._handle_custom_properties(attributes)
        observable = self._create_observable(account_object, misp_object['uuid'], 'UserAccount')
        return observable

    def _parse_custom_object(self, misp_object: dict) -> Observable:
        custom_object = Custom()
        custom_object.custom_name = misp_object['name']
        if misp_object.get('description'):
            custom_object.description = misp_object['description']
        custom_object.custom_properties = CustomProperties()
        for attribute in misp_object['Attribute']:
            custom_object.custom_properties.append(self._create_property(
                attribute['object_relation'],
                attribute['value']
            ))
        observable = self._create_observable(custom_object, misp_object['uuid'], 'Custom')
        self._warnings.add(f"MISP Object name {misp_object['name']} not mapped.")
        return observable

    def _parse_domain_ip_object(self, misp_object: dict) -> Observable:
        attributes = self._extract_multiple_object_attributes_with_uuid(misp_object['Attribute'])
        observables = []
        if 'domain' in attributes:
            for attribute in attributes['domain']:
                observables.append(self._create_domain_observable(*attribute))
        if 'ip' in attributes:
            for attribute in attributes['ip']:
                observables.append(self._create_address_observable('ip-dst', *attribute))
        if 'port' in attributes:
            for attribute in attributes['port']:
                observables.append(self._create_port_observable(*attribute))
        observable_composition = self._create_observable_composition(
            observables,
            misp_object['name'],
            misp_object['uuid']
        )
        return observable_composition

    def _parse_email_object(self, misp_object: dict) -> Observable:
        attributes = self._extract_multiple_object_attributes_with_uuid(
            misp_object['Attribute'],
            with_uuid=['attachment']
        )
        email_object = EmailMessage()
        email_header = EmailHeader()
        for feature in ('to', 'cc'):
            if feature in attributes:
                recipients = EmailRecipients()
                for value in attributes.pop(feature):
                    recipients.append(value)
                setattr(email_header, feature, recipients)
        for feature, key in stix1_mapping.email_object_mapping.items():
            if feature in attributes:
                setattr(email_header, key, attributes.pop(feature)[0])
                setattr(getattr(email_header, key), 'condition', 'Equals')
        email_object.header = email_header
        if 'attachment' in attributes:
            email_object.attachments = Attachments()
            for attachment in attributes.pop('attachment'):
                filename, uuid = attachment
                file = self._create_file_object(filename)
                file.parent.id_ = f"{self._orgname}:FileObject-{uuid}"
                related_file = RelatedObject(
                    relationship='Contains',
                    inline=True,
                    id_=file.parent.id_,
                    properties=file
                )
                email_object.parent.related_objects.append(related_file)
                email_object.attachments.append(related_file.id_)
        if attributes:
            email_object.custom_properties = self._handle_custom_properties(attributes)
        observable = self._create_observable(email_object, misp_object['uuid'], 'EmailMessage')
        return observable

    def _parse_file_attributes(self, attributes: dict, file_object: Union[File, WinExecutableFile]):
        if 'filename' in attributes:
            filename = attributes.pop('filename')[0] if len(attributes['filename']) == 1 else attributes['filename'].pop(0)
            file_object.file_name = filename
            file_object.file_name.condition = 'Equals'
        for feature, key in stix1_mapping.file_object_mapping.items():
            if feature in attributes:
                value = attributes[feature].pop(0) if isinstance(attributes[feature], list) else attributes.pop(feature)
                setattr(file_object, key, value)
                setattr(getattr(file_object, key), 'condition', 'Equals')
        if attributes:
            for object_relation, value in attributes.items():
                if object_relation in stix1_mapping.hash_type_attributes['single']:
                    hash = self._parse_hash_value(object_relation, value)
                    file_object.add_hash(hash)
                else:
                    for single_value in value:
                        self._add_custom_property(file_object, object_relation, single_value)

    def _parse_file_object(self, misp_object: dict) -> Observable:
        attributes = self._extract_file_attributes(misp_object['Attribute'])
        observables = self._parse_file_observables(attributes)
        file_object = File()
        self._parse_file_attributes(attributes, file_object)
        file_observable = self._create_observable(file_object, misp_object['uuid'], 'File')
        if observables:
            observables.append(file_observable)
            observable_composition = self._create_observable_composition(
                observables,
                misp_object['name'],
                misp_object['uuid']
            )
            return observable_composition
        return file_observable

    def _parse_file_observables(self, attributes: dict) -> list:
        observables = []
        if 'malware-sample' in attributes:
            if isinstance(attributes['malware-sample'], tuple):
                value, data, uuid = attributes.pop('malware-sample')
                malware_observable = self._create_malware_sample_observable(value, data, uuid)
                observables.append(malware_observable)
            else:
                attributes['malware-sample'] = [attributes['malware-sample']]
        if 'attachment' in attributes:
            if isinstance(attributes['attachment'], tuple):
                filename, data, uuid = attributes.pop('attachment')
                attachment_observable = self._create_attachment_observable(filename, data, uuid)
                observables.append(attachment_observable)
            else:
                attributes['attachment'] = [attributes['attachment']]
        return observables

    def _parse_file_with_pe_object(self, misp_object: dict) -> Observable:
        attributes = self._extract_file_attributes(misp_object['Attribute'])
        observables = self._parse_file_observables(attributes)
        file_object = WinExecutableFile()
        self._parse_file_attributes(attributes, file_object)
        for reference in misp_object['ObjectReference']:
            if self._check_reference(reference, _PE_RELATIONSHIP_TYPES, 'pe'):
                misp_pe = self._objects_to_parse['pe'].pop(reference['referenced_uuid'])
                self._parse_pe_object(file_object, misp_pe)
                break
        file_observable = self._create_observable(file_object, misp_object['uuid'], 'WindowsExecutableFile')
        if observables:
            observables.append(file_observable)
            observable_composition = self._create_observable_composition(
                observables,
                misp_object['name'],
                misp_object['uuid']
            )
            return observable_composition
        return file_observable

    def _parse_ip_port_object(self, misp_object: dict) -> Observable:
        attributes = self._extract_multiple_object_attributes_with_uuid(misp_object['Attribute'])
        observables = []
        for feature in ('ip-src', 'ip-dst'):
            if feature in attributes:
                for attribute in attributes[feature]:
                    observables.append(self._create_address_observable(feature, *attribute))
        if 'ip' in attributes:
            for attribute in attributes['ip']:
                observables.append(self._create_address_observable('ip-dst', *attribute))
        for feature in ('src-port', 'dst-port'):
            if feature in attributes:
                for attribute in attributes[feature]:
                    observables.append(self._create_port_observable(
                        *attribute,
                        feature=feature.split('-')[0]
                    ))
        if 'domain' in attributes:
            for attribute in attributes['domain']:
                observables.append(self._create_domain_observable(*attribute))
        if 'hostname' in attributes:
            for attribute in attributes['hostname']:
                observables.append(self._create_hostname_observable(*attribute))
        observable_composition = self._create_observable_composition(
            observables,
            misp_object['name'],
            misp_object['uuid']
        )
        return observable_composition

    def _parse_network_connection_object(self, misp_object: dict) -> Observable:
        attributes = self._extract_object_attributes(misp_object['Attribute'])
        connection_object = NetworkConnection()
        self._parse_socket_addresses(
            connection_object,
            attributes,
            ('source_socket', 'destination_socket')
        )
        for feature in ('layer3-protocol', 'layer4-protocol', 'layer7-protocol'):
            if feature in attributes:
                field = feature.replace('-', '_')
                setattr(connection_object, field, attributes.pop(feature))
                setattr(getattr(connection_object, field), 'condition', 'Equals')
        if attributes:
            connection_object.custom_properties = self._handle_custom_properties(attributes)
        observable = self._create_observable(
            connection_object,
            misp_object['uuid'],
            'NetworkConnection'
        )
        return observable

    def _parse_network_socket_object(self, misp_object: dict) -> Observable:
        attributes = self._extract_multiple_object_attributes(
            misp_object['Attribute'],
            force_single=(
                'ip-src', 'ip-dst', 'src-port', 'dst-port', 'hostname-src',
                'hostname-dst', 'ptotocol', 'address-family', 'domain-family'
            )
        )
        socket_object = NetworkSocket()
        self._parse_socket_addresses(socket_object, attributes, ('local', 'remote'))
        for key, feature in stix1_mapping.network_socket_mapping.items():
            if key in attributes:
                setattr(socket_object, feature, attributes.pop(key))
                setattr(getattr(socket_object, feature), 'condition', 'Equals')
        if 'state' in attributes:
            states = attributes.pop('state')
            socket_object.is_listening = True if 'listening' in states else False
            socket_object.is_blocking = True if 'blocking' in states else False
        if attributes:
            socket_object.custom_properties = self._handle_custom_properties(attributes)
        observable = self._create_observable(socket_object, misp_object['uuid'], 'NetworkSocket')
        return observable

    def _parse_pe_object(self, file_object: WinExecutableFile, misp_pe: dict):
        attributes = self._extract_multiple_object_attributes(
            misp_pe['Attribute'],
            force_single=(
                'company-name', 'entrypoint-address', 'file-description',
                'file-version', 'impfuzzy', 'imphash', 'type', 'lang-id',
                'internal-filename', 'legal-copyright', 'number-sections',
                'original-filename', 'pehash', 'product-name', 'product-version'
            )
        )
        if any(feature in attributes for feature in stix1_mapping.pe_resource_mapping):
            resource = PEVersionInfoResource()
            for key, feature in stix1_mapping.pe_resource_mapping.items():
                if key in attributes:
                    setattr(resource, feature, attributes.pop(key))
                    setattr(getattr(resource, feature), 'condition', 'Equals')
            resource_list = PEResourceList()
            resource_list.append(resource)
            file_object.resources = resource_list
        headers_fields = ('entrypoint-address', 'impfuzzy', 'imphash', 'number-sections', 'pehash')
        if any(feature in attributes for feature in headers_fields):
            pe_headers = PEHeaders()
            if 'entrypoint-address' in attributes:
                optional_header = PEOptionalHeader()
                optional_header.address_of_entry_point = attributes.pop('entrypoint-address')
                optional_header.address_of_entry_point.condition = 'Equals'
                pe_headers.optional_header = optional_header
            if 'number-sections' in attributes:
                file_header = PEFileHeader()
                file_header.number_of_sections = attributes.pop('number-sections')
                file_header.number_of_sections.condition = 'Equals'
                pe_headers.file_header = file_header
            file_object.headers = pe_headers
        if 'type' in attributes:
            file_object.type_ = attributes.pop('type')
            file_object.type_.condition = 'Equals'
        if attributes:
            hashes = []
            for object_relation, value in attributes.items():
                if object_relation in stix1_mapping.hash_type_attributes['single']:
                    hashes.append(self._parse_hash_value(object_relation, value))
                else:
                    for single_value in value:
                        self._add_custom_property(file_object, object_relation, single_value)
            if hashes:
                hashlist = HashList()
                hashlist.hashes = hashes
                file_object.headers.file_header.hashes = hashlist
        if misp_pe.get('ObjectReference'):
            for reference in misp_pe['ObjectReference']:
                if self._check_reference(reference, _PE_RELATIONSHIP_TYPES, 'pe-section'):
                    misp_pe_section = self._objects_to_parse['pe-section'][reference['referenced_uuid']]
                    pe_section = self._parse_pe_section_object(misp_pe_section)
                    try:
                        file_object.sections.append(pe_section)
                    except AttributeError:
                        file_object.sections = PESectionList()
                        file_object.sections.append(pe_section)

    def _parse_pe_section_object(self, misp_pe_section: dict) -> PESection:
        section_attributes = self._extract_object_attributes(misp_pe_section['Attribute'])
        pe_section = PESection()
        if 'entropy' in section_attributes:
            pe_section.entropy = Entropy()
            pe_section.entropy.value = section_attributes.pop('entropy')
        if any(feature in section_attributes for feature in ('name', 'size-in-bytes')):
            pe_section.section_header = PESectionHeaderStruct()
            if 'name' in section_attributes:
                pe_section.section_header.name = section_attributes.pop('name')
                pe_section.section_header.name.condition = 'Equals'
            if 'size-in-bytes' in section_attributes:
                pe_section.section_header.size_of_raw_data = section_attributes.pop('size-in-bytes')
                pe_section.section_header.size_of_raw_data.condition = 'Equals'
        hashlist = []
        for key, value in section_attributes.items():
            if key in stix1_mapping.hash_type_attributes['single']:
                hashlist.append(self._parse_hash_value(key, value))
        if hashlist:
            pe_section.data_hashes = HashList()
            pe_section.data_hashes.hashes = hashlist
        return pe_section

    def _parse_process_object(self, misp_object: dict) -> Observable:
        attributes = self._extract_multiple_object_attributes(
            misp_object['Attribute'],
            force_single=(
                'command-line', 'creation-time', 'image',
                'name', 'parent-pid', 'pid', 'start-time'
            )
        )
        process_object = Process()
        for key, feature in stix1_mapping.process_object_mapping.items():
            if key in attributes:
                setattr(process_object, feature, attributes.pop(key))
                setattr(getattr(process_object, feature), 'condition', 'Equals')
        if 'child-pid' in attributes:
            process_object.child_pid_list = ChildPIDList()
            for child in attributes.pop('child-pid'):
                process_object.child_pid_list.append(child)
        if 'port' in attributes:
            process_object.port_list = PortList()
            for port in attributes.pop('port'):
                port_object = self._create_port_object(port)
                process_object.port_list.append(port_object)
        image_info_keys = ('image', 'command-line')
        if any(key in attributes for key in image_info_keys):
            process_object.image_info = ImageInfo()
            for key, feature in zip(image_info_keys, ('file_name', 'command_line')):
                if key in attributes:
                    setattr(process_object.image_info, feature, attributes.pop(key))
                    setattr(getattr(process_object.image_info, feature), 'condition', 'Equals')
        if attributes:
            process_object.custom_properties = self._handle_custom_properties(attributes)
        observable = self._create_observable(process_object, misp_object['uuid'], 'Process')
        return observable

    def _parse_registry_key_object(self, misp_object: dict) -> Observable:
        attributes = self._extract_object_attributes(misp_object['Attribute'])
        registry_object = self._create_registry_key_object(attributes.pop('key')) if 'key' in attributes else WinRegistryKey()
        if 'hive' in attributes:
            hive = attributes.pop('hive').lstrip('\\').upper()
            if hive in stix1_mapping.misp_reghive:
                hive = stix1_mapping.misp_reghive[hive]
            registry_object.hive = hive
            registry_object.hive.condition = 'Equals'
        if any(key in attributes for key in stix1_mapping.regkey_object_mapping.keys()):
            value_object = RegistryValue()
            for key, feature in stix1_mapping.regkey_object_mapping.items():
                if key in attributes:
                    setattr(value_object, feature, attributes.pop(key))
                    setattr(getattr(value_object, feature), 'condition', 'Equals')
            registry_object.values = RegistryValues(value_object)
        if 'last-modified' in attributes:
            registry_object.modified_time = attributes.pop('last-modified')
            registry_object.modified_time.condition = 'Equals'
        if attributes:
            registry_object.custom_properties = self._handle_custom_properties(
                attributes,
                multiple=False
            )
        observable = self._create_observable(
            registry_object,
            misp_object['uuid'],
            'WindowsRegistryKey'
        )
        return observable

    def _parse_socket_addresses(self, stix_object: Union[NetworkConnection, NetworkSocket], attributes: dict, fields: tuple):
        for key, field in zip(('src', 'dst'), fields):
            args = {}
            if f'ip-{key}' in attributes:
                attribute_type = f'ip-{key}'
                args['ip'] = (attribute_type, attributes.pop(attribute_type))
            if f'hostname-{key}' in attributes:
                args['hostname'] = attributes.pop(f'hostname-{key}')
            if f'{key}-port' in attributes:
                args['port'] = attributes.pop(f'{key}-port')
            if args:
                setattr(
                    stix_object,
                    f'{field}_address',
                    self._create_socket_address_object(**args)
                )

    def _parse_url_object(self, misp_object: dict) -> Observable:
        attributes = self._extract_object_attributes_with_uuid(misp_object['Attribute'])
        observables = []
        if 'url' in attributes:
            observables.append(self._create_uri_observable(*attributes['url']))
        if 'domain' in attributes:
            observables.append(self._create_domain_observable(*attributes['domain']))
        if 'host' in attributes:
            observables.append(self._create_hostname_observable(*attributes['host']))
        if 'ip' in attributes:
            observables.append(self._create_address_observable('ip-dst', *attributes['ip']))
        if 'port' in attributes:
            observables.append(self._create_port_observable(*attributes['port']))
        observable_composition = self._create_observable_composition(
            observables,
            misp_object['name'],
            misp_object['uuid']
        )
        return observable_composition

    def _parse_user_account_object(self, misp_object: dict) -> Observable:
        attributes = self._extract_multiple_object_attributes(
            misp_object['Attribute'],
            force_single=(
                'account-type', 'created', 'disabled', 'display-name', 'home_dir',
                'last_login', 'password', 'shell', 'text', 'username'
            )
        )
        account_object = self._create_user_account_object(attributes)
        if 'password' in attributes:
            account_object.authentication = self._create_authentication_object(
                auth_type='password',
                password=attributes.pop('password')
            )
        for key, feature in stix1_mapping.user_account_object_mapping.items():
            if key in attributes:
                setattr(account_object, feature, attributes.pop(key))
                setattr(getattr(account_object, feature), 'condition', 'Equals')
        if attributes:
            account_object.custom_properties = self._handle_custom_properties(attributes)
        observable = self._create_observable(
            account_object,
            misp_object['uuid'],
            account_object._XSI_TYPE.split('ObjectType')[0]
        )
        return observable

    def _parse_vulnerability_object(self, misp_object: dict):
        ttp = self._create_ttp_from_object(misp_object)
        vulnerability = Vulnerability()
        attributes = self._extract_multiple_object_attributes(
            misp_object['Attribute'],
            force_single=(
                'created', 'cvss-score', 'published', 'summary'
            )
        )
        if 'id' in attributes:
            cve_id = attributes.pop('id')[0] if len(attributes['id']) == 1 else attributes['id'].pop(0)
            vulnerability.cve_id = cve_id
        if 'cvss-score' in attributes:
            cvss = CVSSVector()
            cvss.overall_score = attributes.pop('cvss-score')
            vulnerability.cvss_score = cvss
        for key, feature in stix1_mapping.vulnerability_object_mapping.items():
            if key in attributes:
                setattr(vulnerability, feature, attributes.pop(key))
                setattr(getattr(vulnerability, feature), 'condition', 'Equals')
        if 'references' in attributes:
            for reference in attributes.pop('references'):
                vulnerability.add_reference(reference)
        if misp_object.get('ObjectReference'):
            references = tuple((reference['referenced_uuid'], reference['relationship_type']) for reference in misp_object['ObjectReference'])
            self._ttp_references[misp_object['uuid']] = references
        exploit_target = ExploitTarget(timestamp=self._datetime_from_timestamp(misp_object['timestamp']))
        exploit_target.id_ = f"{self._orgname}:ExploitTarget-{misp_object['uuid']}"
        exploit_target.add_vulnerability(vulnerability)
        ttp.add_exploit_target(exploit_target)
        self._handle_ttp_from_object(misp_object, ttp)

    def _parse_weakness_object(self, misp_object: dict):
        ttp = self._create_ttp_from_object(misp_object)
        weakness = Weakness()
        attributes = self._extract_object_attributes(misp_object['Attribute'])
        for key, feature in stix1_mapping.weakness_object_mapping.items():
            if key in attributes:
                setattr(weakness, feature, attributes.pop(key))
        if misp_object.get('ObjectReference'):
            references = tuple((reference['referenced_uuid'], reference['relationship_type']) for reference in misp_object['ObjectReference'])
            self._ttp_references[misp_object['uuid']] = references
        exploit_target = ExploitTarget(timestamp=self._datetime_from_timestamp(misp_object['timestamp']))
        exploit_target.id_ = f"{self._orgname}:ExploitTarget-{misp_object['uuid']}"
        exploit_target.add_weakness(weakness)
        ttp.add_exploit_target(exploit_target)
        self._handle_ttp_from_object(misp_object, ttp)

    def _parse_whois_object(self, misp_object: dict) -> Observable:
        attributes = self._extract_multiple_object_attributes(
            misp_object['Attribute'],
            force_single=(
                'comment', 'creation-date', 'expiration-date', 'modification-date',
                'registrant-email', 'registrant-name', 'registrant-org',
                'registrant-phone', 'registrar', 'text'
            )
        )
        whois_object = WhoisEntry()
        if 'registrar' in attributes:
            whois_registrar = WhoisRegistrar()
            whois_registrar.name = attributes.pop('registrar')
            whois_object.registrar_info = whois_registrar
        if any(key.startswith('registrant-') for key in attributes.keys()):
            registrants = WhoisRegistrants()
            registrant = WhoisRegistrant()
            for key, feature in stix1_mapping.whois_registrant_mapping.items():
                if key in attributes:
                    setattr(registrant, feature, attributes.pop(key))
                    setattr(getattr(registrant, feature), 'condition', 'Equals')
            registrants.append(registrant)
            whois_object.registrants = registrants
        for key, feature in stix1_mapping.whois_object_mapping.items():
            if key in attributes:
                setattr(whois_object, feature, attributes.pop(key))
                setattr(getattr(whois_object, feature), 'condition', 'Equals')
        if 'nameserver' in attributes:
            nameservers = WhoisNameservers()
            for nameserver in attributes.pop('nameserver'):
                nameservers.append(URI(value=nameserver))
            whois_object.nameservers = nameservers
        if 'domain' in attributes:
            domain_name = attributes.pop('domain')[0] if len(attributes['domain']) == 1 else attributes['domain'].pop(0)
            whois_object.domain_name = URI(value=domain_name)
        if 'ip-address' in attributes:
            ip_address = attributes.pop('ip-address')[0] if len(attributes['ip-address']) == 1 else attribute['ip-address'].pop(0)
            whois_object.ip_address = Address(address_value=ip_address)
        if 'comment' in attributes:
            whois_object.remarks = attributes.pop('comment')
        elif 'text' in attributes:
            whois_object.remarks = attributes.pop('text')
        if attributes:
            whois_object.custom_properties = self._handle_custom_properties(attributes)
        observable = self._create_observable(whois_object, misp_object['uuid'], 'Whois')
        return observable

    def _parse_x509_object(self, misp_object: dict) -> Observable:
        single_attributes = tuple(stix1_mapping.x509_creation_mapping.keys())
        attributes = defaultdict(list)
        content = defaultdict(bool)
        for attribute in misp_object['Attribute']:
            relation = attribute['object_relation']
            if relation in single_attributes:
                attributes[relation] = attribute['value']
                content[stix1_mapping.x509_creation_mapping[relation]] = True
            else:
                attributes[relation].append(attribute['value'])
        x509_object = X509Certificate()
        if any(content[feature] for feature in ('certificate', 'validity', 'pubkey')):
            x509_cert = X509Cert()
            if content['certificate']:
                for key, feature in stix1_mapping.x509_object_mapping.items():
                    if key in attributes:
                        setattr(x509_cert, feature, attributes.pop(key))
                        setattr(getattr(x509_cert, feature), 'condition', 'Equals')
            if content['validity']:
                validity = Validity()
                for key in ('before', 'after'):
                    if f'validity-not-{key}' in attributes:
                        setattr(validity, f'not_{key}', attributes.pop(f'validity-not-{key}'))
                        setattr(getattr(validity, f'not_{key}'), 'condition', 'Equals')
                x509_cert.validity = validity
            if content['pubkey']:
                pubkey = SubjectPublicKey()
                if 'pubkey-info-algorithm' in attributes:
                    pubkey.public_key_algorithm = attributes.pop('pubkey-info-algorithm')
                    pubkey.public_key_algorithm.condition = 'Equals'
                pubkey_keys = ('exponent', 'modulus')
                if any(f'pubkey-info-{key}' in attributes for key in pubkey_keys):
                    rsa_pubkey = RSAPublicKey()
                    for key in pubkey_keys:
                        if f'pubkey-info-{key}' in attributes:
                            setattr(rsa_pubkey, key, attributes.pop(f'pubkey-info-{key}'))
                            setattr(getattr(rsa_pubkey, key), 'condition', 'Equals')
                    pubkey.rsa_public_key = rsa_pubkey
                x509_cert.subject_public_key = pubkey
            x509_object.certificate = x509_cert
        if content['raw_certificate']:
            if 'pem' in attributes:
                x509_object.raw_certificate = attributes.pop('pem')
                if 'raw-base64' in attributes:
                    attributes['raw-base64'] = [attributes['raw-base64']]
            elif 'raw-base64' in attributes:
                x509_object.raw_certificate = attributes.pop('raw-base64')
            x509_object.raw_certificate.condition = 'Equals'
        if content['signature']:
            signature = X509CertificateSignature()
            signature_set = False
            for algo in ('sha256', 'sha1', 'md5'):
                key = f'x509-fingerprint-{algo}'
                if signature_set:
                    if key in attributes:
                        attributes[key] = [attributes[key]]
                    continue
                if key in attributes:
                    signature.signature_algorithm = algo.upper()
                    signature.signature_algorithm.condition = 'Equals'
                    signature.signature = attributes.pop(key)
                    signature.signature.condition = 'Equals'
                    signature_set = True
            x509_object.certificate_signature = signature
        if attributes:
            x509_object.custom_properties = self._handle_custom_properties(attributes)
        observable = self._create_observable(x509_object, misp_object['uuid'], 'X509Certificate')
        return observable

    def _resolve_files_to_parse(self):
        for uuid, misp_object in self._objects_to_parse.pop('file').items():
            try:
                to_ids = self._fetch_ids_flags(misp_object['Attribute'])
                observable = self._parse_file_with_pe_object(misp_object)
                if to_ids:
                    self._handle_misp_object_with_context(misp_object, observable)
                else:
                    self._handle_misp_object(observable, misp_object.get('meta-category'))
            except Exception:
                self._errors.append(f"Error with the {misp_object['name']} object: {misp_object['uuid']}.")

    ################################################################################
    #                          GALAXIES PARSING FUNCTIONS                          #
    ################################################################################

    def _get_related_ttps(self, galaxy: dict, feature: str) -> dict:
        related_ttps = {}
        for cluster in galaxy['GalaxyCluster']:
            cluster_uuid = cluster['uuid']
            if cluster_uuid in self._ttps:
                related_ttps[cluster_uuid] = self._create_related_ttp(
                    self._ttps[cluster_uuid].id_,
                    galaxy['name']
                )
                continue
            ttp = self._create_ttp_from_galaxy(galaxy['name'], cluster_uuid)
            getattr(self, f'_parse_{feature}_galaxy')(cluster, ttp)
            related_ttps[cluster_uuid] = self._create_related_ttp(ttp.id_, galaxy['name'])
            self._ttps[cluster_uuid] = ttp
        return related_ttps

    def _handle_related_ttps(self, related_ttps: dict):
        for uuid, related_ttp in related_ttps.items():
            if uuid not in self._contextualised_data['ttp']:
                self._contextualised_data['ttp'][uuid] = related_ttp

    def _parse_attack_pattern_attribute_galaxy(self, galaxy: dict, indicator: Indicator):
        related_ttps = self._get_related_ttps(galaxy, 'attack_pattern')
        for related_ttp in related_ttps.values():
            indicator.add_indicated_ttp(related_ttp)

    def _parse_attack_pattern_event_galaxy(self, galaxy: dict):
        related_ttps = self._get_related_ttps(galaxy, 'attack_pattern')
        self._handle_related_ttps(related_ttps)

    def _parse_attack_pattern_galaxy(self, cluster: dict, ttp: TTP):
        behavior = Behavior()
        attack_pattern = AttackPattern()
        attack_pattern.id_ = f"{self._orgname}:AttackPattern-{cluster['uuid']}"
        attack_pattern.title = cluster['value']
        attack_pattern.description = cluster['description']
        if cluster['meta'].get('external_id'):
            external_id = cluster['meta']['external_id'][0]
            if external_id.startswith('CAPEC'):
                attack_pattern.capec_id = external_id
        behavior.add_attack_pattern(attack_pattern)
        ttp.behavior = behavior

    def _parse_attack_pattern_object_galaxy(self, galaxy: dict, ttp: TTP):
        related_ttps = self._get_related_ttps(galaxy, 'attack_pattern')
        for related_ttp in related_ttps.values():
            ttp.add_related_ttp(related_ttp)

    def _parse_course_of_action_attribute_galaxy(self, galaxy: dict, indicator: Indicator):
        for cluster in galaxy['GalaxyCluster']:
            cluster_uuid = cluster['uuid']
            if cluster_uuid in self._courses_of_action:
                related_coa = self._create_related_coa(
                    self._courses_of_action[cluster_uuid].id_,
                    galaxy['name']
                )
                indicator.suggested_coas.append(related_coa)
                continue
            course_of_action = self._create_course_of_action_from_galaxy(cluster)
            related_coa = self._create_related_coa(course_of_action.id_, galaxy['name'])
            indicator.suggested_coas.append(related_coa)
            self._courses_of_action[cluster_uuid] = course_of_action

    def _parse_course_of_action_event_galaxy(self, galaxy: dict):
        for cluster in galaxy['GalaxyCluster']:
            cluster_uuid = cluster['uuid']
            if cluster_uuid in self._courses_of_action:
                coa_taken = self._create_coa_taken(self._courses_of_action[cluster_uuid].id_)
                self._contextualised_data['course_of_action'][cluster_uuid] = coa_taken
                continue
            course_of_action = self._create_course_of_action_from_galaxy(cluster)
            coa_taken = self._create_coa_taken(course_of_action.id_)
            self._contextualised_data['course_of_action'][cluster_uuid] = coa_taken
            self._courses_of_action[cluster_uuid] = course_of_action

    def _parse_course_of_action_object_galaxy(self, galaxy: dict, object_coa: CourseOfAction):
        for cluster in galaxy['GalaxyCluster']:
            cluster_uuid = cluster['uuid']
            if cluster_uuid in self._courses_of_action:
                related_coa = self._create_related_coa(
                    self._courses_of_action[cluster_uuid].id_,
                    galaxy['name']
                )
                object_coa.related_coas.append(related_coa)
                continue
            course_of_action = self._create_course_of_action_from_galaxy(cluster)
            related_coa = self._create_related_coa(course_of_action.id_, galaxy['name'])
            object_coa.related_coas.append(related_coa)
            self._courses_of_action[cluster_uuid] = course_of_action

    def _parse_malware_attribute_galaxy(self, galaxy: dict, indicator: Indicator):
        related_ttps = self._get_related_ttps(galaxy, 'malware')
        for related_ttp in related_ttps.values():
            indicator.add_indicated_ttp(related_ttp)

    def _parse_malware_event_galaxy(self, galaxy: dict):
        related_ttps = self._get_related_ttps(galaxy, 'malware')
        self._handle_related_ttps(related_ttps)

    def _parse_malware_galaxy(self, cluster: dict, ttp: TTP):
        behavior = Behavior()
        malware = MalwareInstance()
        malware.id_ = f"{self._orgname}:MalwareInstance-{cluster['uuid']}"
        malware.title = cluster['value']
        if cluster.get('description'):
            malware.description = cluster['description']
        if cluster['meta'].get('synonyms'):
            for synonym in cluster['meta']['synonyms']:
                malware.add_name(synonym)
        behavior.add_malware_instance(malware)
        ttp.behavior = behavior

    def _parse_malware_object_galaxy(self, galaxy: dict, ttp: TTP):
        related_ttps = self._get_related_ttps(galaxy, 'malware')
        for related_ttp in related_ttps.values():
            ttp.add_related_ttp(related_ttp)

    def _parse_threat_actor_galaxy(self, galaxy: dict):
        for cluster in galaxy['GalaxyCluster']:
            cluster_uuid = cluster['uuid']
            if cluster_uuid not in self._contextualised_data['threat_actor']:
                if cluster_uuid in self._threat_actors:
                    related_threat_actor = self._create_related_threat_actor(
                        self._threat_actors[cluster_uuid].id_,
                        galaxy['name']
                    )
                    self._contextualised_data['threat_actor'][cluster_uuid] = related_threat_actor
                    continue
                threat_actor = self._create_threat_actor_from_galaxy(cluster)
                related_threat_actor = self._create_related_threat_actor(
                    threat_actor.id_,
                    galaxy['name']
                )
                self._contextualised_data['threat_actor'][cluster_uuid] = related_threat_actor
                self._threat_actors[cluster_uuid] = threat_actor

    def _parse_tool_attribute_galaxy(self, galaxy: dict, indicator: Indicator):
        related_ttps = self._get_related_ttps(galaxy, 'tool')
        for related_ttp in related_ttps.values():
            indicator.add_indicated_ttp(related_ttp)

    def _parse_tool_event_galaxy(self, galaxy: dict):
        related_ttps = self._get_related_ttps(galaxy, 'tool')
        self._handle_related_ttps(related_ttps)

    def _parse_tool_galaxy(self, cluster: dict, ttp: TTP):
        tools = Tools()
        tool = ToolInformation()
        tool.id_ = f"{self._orgname}:ToolInformation-{cluster['uuid']}"
        tool.name = cluster['value']
        if cluster.get('description'):
            tool.description = cluster['description']
        tools.append(tool)
        resource = Resource()
        resource.tools = tools
        ttp.resources = resource

    def _parse_tool_object_galaxy(self, galaxy: dict, ttp: TTP):
        related_ttps = self._get_related_ttps(galaxy, 'tool')
        for related_ttp in related_ttps.values():
            ttp.add_related_ttp(related_ttp)

    def _parse_vulnerability_attribute_galaxy(self, galaxy: dict, indicator: Indicator):
        related_ttps = self._get_related_ttps(galaxy, 'vulnerability')
        for related_ttp in related_ttps.values():
            indicator.add_indicated_ttp(related_ttp)

    def _parse_vulnerability_event_galaxy(self, galaxy: dict):
        related_ttps = self._get_related_ttps(galaxy, 'vulnerability')
        self._handle_related_ttps(related_ttps)

    def _parse_vulnerability_galaxy(self, cluster: dict, ttp: TTP):
        exploit_target = ExploitTarget()
        exploit_target.id_ = f"{self._orgname}:ExploitTarget-{cluster['uuid']}"
        vulnerability = Vulnerability()
        vulnerability.id_ = f"{self._orgname}:Vulnerability-{cluster['uuid']}"
        vulnerability.title = cluster['value']
        vulnerability.description = cluster['description']
        if cluster['meta'].get('aliases'):
            vulnerability.cve_id = cluster['meta']['aliases'][0]
        if cluster['meta'].get('refs'):
            for reference in cluster['meta']['refs']:
                vulnerability.add_reference(reference)
        exploit_target.add_vulnerability(vulnerability)
        ttp.add_exploit_target(exploit_target)

    def _parse_vulnerability_object_galaxy(self, galaxy: dict, ttp: TTP):
        related_ttps = self._get_related_ttps(galaxy, 'vulnerability')
        for related_ttp in related_ttps.values():
            ttp.add_related_ttp(related_ttp)

    ################################################################################
    #                      OBJECTS CREATION HELPER FUNCTIONS.                      #
    ################################################################################

    def _add_journal_entry(self, entryline: str):
        history_item = HistoryItem()
        history_item.journal_entry = entryline
        try:
            self._incident.history.append(history_item)
        except AttributeError:
            self._incident.history = History()
            self._incident.history.append(history_item)

    @staticmethod
    def _create_address_object(attribute_type: str, attribute_value: str) -> Address:
        address_object = Address()
        if '/' in attribute_value:
            address_object.category = "cidr"
            condition = "Contains"
        else:
            try:
                socket.inet_aton(attribute_value)
                address_object.category = "ipv4-addr"
            except socket.error:
                address_object.category = "ipv6-addr"
            condition = "Equals"
        if 'src' in attribute_type:
            address_object.is_source = True
            address_object.is_destination = False
        else:
            address_object.is_source = False
            address_object.is_destination = True
        address_object.address_value = attribute_value
        address_object.address_value.condition = condition
        return address_object

    def _create_address_observable(self, feature: str, value: str, uuid: str) -> Observable:
        address_object = self._create_address_object(feature, value)
        observable = self._create_observable(address_object, uuid, 'Address')
        return observable

    def _create_artifact_object(self, data: BytesIO) -> Artifact:
        raw_artifact = RawArtifact(data)
        artifact = Artifact()
        artifact.raw_artifact = raw_artifact
        artifact.raw_artifact.condition = "Equals"
        return artifact

    def _create_attachment_observable(self, filename: str, data: BytesIO, uuid: str) -> Observable:
        artifact_object = self._create_artifact_object(data)
        observable = self._create_observable(artifact_object, uuid, 'Artifact')
        observable.title = filename
        return observable

    @staticmethod
    def _create_authentication_object(auth_type: str = None, auth_format: str = None, password: str = None) -> Authentication:
        authentication = Authentication()
        # At least one of the params is not None, otherwise we do not actually call the function
        if auth_type is not None:
            authentication.authentication_type = auth_type
        if auth_format is not None:
            authentication.structured_authentication_mechanism = auth_format
        if password is not None:
            authentication.authentication_data = password
        return authentication

    @staticmethod
    def _create_autonomous_system_object(AS: str) -> AutonomousSystem:
        autonomous_system = AutonomousSystem()
        feature = 'handle' if AS.startswith('AS') else 'number'
        setattr(autonomous_system, feature, AS)
        setattr(getattr(autonomous_system, feature), 'condition', 'Equals')
        return autonomous_system

    @staticmethod
    def _create_coa_taken(coa_id: str, timestamp: Optional[datetime] = None) -> COATaken:
        coa = CourseOfAction(idref=coa_id)
        if timestamp is not None:
            coa.timestamp = timestamp
        coa_taken = COATaken(coa)
        return coa_taken

    def _create_course_of_action_from_galaxy(self, cluster: dict) -> CourseOfAction:
        course_of_action = CourseOfAction()
        course_of_action.id_ = f"{self._orgname}:CourseOfAction-{cluster['uuid']}"
        course_of_action.title = cluster['value']
        course_of_action.description = cluster['description']
        return course_of_action

    @staticmethod
    def _create_domain_object(domain: str) -> DomainName:
        domain_object = DomainName()
        domain_object.value = domain
        domain_object.value.condition = "Equals"
        return domain_object

    def _create_domain_observable(self, domain: str, uuid: str) -> Observable:
        domain_object = self._create_domain_object(domain)
        observable = self._create_observable(domain_object, uuid, 'DomainName')
        return observable

    @staticmethod
    def _create_file_object(filename: str) -> File:
        file_object = File()
        file_object.file_name = filename
        file_object.file_name.condition = "Equals"
        return file_object

    @staticmethod
    def _create_hostname_object(hostname: str) -> Hostname:
        hostname_object = Hostname()
        hostname_object.hostname_value = hostname
        hostname_object.hostname_value.condition = "Equals"
        return hostname_object

    def _create_hostname_observable(self, hostname: str, uuid: str) -> Observable:
        hostname_object = self._create_hostname_object(hostname)
        observable = self._create_observable(hostname_object, uuid, 'Hostname')
        return observable

    def _create_indicator_from_attribute(self, attribute: dict) -> Indicator:
        timestamp = self._datetime_from_timestamp(attribute['timestamp'])
        indicator = Indicator(timestamp=timestamp)
        indicator.id_ = f"{self._orgname}:Indicator-{attribute['uuid']}"
        indicator.producer = self._set_producer()
        indicator.title = f"{attribute['category']}: {attribute['value']} (MISP Attribute)"
        indicator.description = attribute['comment'] if attribute.get('comment') else indicator.title
        indicator.confidence = Confidence(
            value=stix1_mapping.confidence_value,
            description=stix1_mapping.confidence_description,
            timestamp=timestamp
        )
        return indicator

    def _create_indicator_from_object(self, misp_object: dict) -> Indicator:
        timestamp = self._datetime_from_timestamp(misp_object['timestamp'])
        indicator = Indicator(timestamp=timestamp)
        indicator.id_ = f"{self._orgname}:Indicator-{misp_object['uuid']}"
        indicator.producer = self._set_producer()
        indicator.title = f"{misp_object.get('meta-category')}: {misp_object['name']} (MISP Object)"
        if any(misp_object.get(feature) for feature in ('comment', 'description')):
            indicator.description = misp_object['comment'] if misp_object.get('comment') else misp_object['description']
        indicator.confidence = Confidence(
            value=stix1_mapping.confidence_value,
            description=stix1_mapping.confidence_description,
            timestamp=timestamp
        )
        return indicator

    @staticmethod
    def _create_information_source(identity: Identity) -> InformationSource:
        information_source = InformationSource(identity=identity)
        return information_source

    def _create_malware_sample_observable(self, value: str, data: BytesIO, uuid: str) -> Observable:
        filename, hash_value = value.split('|')
        artifact_object = self._create_artifact_object(data)
        artifact_object.hashes = HashList(self._parse_hash_value('md5', hash_value))
        observable = self._create_observable(artifact_object, uuid, 'Artifact')
        observable.title = filename
        return observable

    @staticmethod
    def _create_mutex_object(name: str) -> Mutex:
        mutex_object = Mutex()
        mutex_object.name = name
        mutex_object.name.condition = "Equals"
        return mutex_object

    def _create_observable(self, stix_object: _OBSERVABLE_OBJECT_TYPES, attribute_uuid: str, feature: str) -> Observable:
        stix_object.parent.id_ = f"{self._orgname}:{feature}-{attribute_uuid}"
        observable = Observable(stix_object)
        observable.id_ = f"{self._orgname}:Observable-{attribute_uuid}"
        return observable

    def _create_observable_composition(self, observables: list, name: str, uuid: str) -> Observable:
        observable_composition = ObservableComposition(observables=observables)
        observable_composition.operator = 'AND'
        observable = Observable(id_=f'{self._orgname}:{name}_ObservableComposition-{uuid}')
        observable.observable_composition = observable_composition
        return observable

    @staticmethod
    def _create_port_object(port: str) -> Port:
        port_object = Port()
        port_object.port_value = port
        port_object.port_value.condition = "Equals"
        return port_object

    def _create_port_observable(self, port: str, uuid: str, feature: str = None) -> Observable:
        object_type = 'Port'
        if feature is not None:
            object_type = f'{feature}{object_type}'
        port_object = self._create_port_object(port)
        observable = self._create_observable(port_object, uuid, object_type)
        return observable

    @staticmethod
    def _create_property(name: str, value: str) -> Property:
        prop = Property()
        prop.name = name
        prop.value = value
        return prop

    @staticmethod
    def _create_registry_key_object(regkey: str) -> WinRegistryKey:
        registry_key = WinRegistryKey()
        registry_key.key = regkey.strip()
        registry_key.key.condition = "Equals"
        return registry_key

    @staticmethod
    def _create_related_coa(coa_id: str, category: str, timestamp: Optional[datetime] = None) -> RelatedCOA:
        coa = CourseOfAction(idref=coa_id)
        if timestamp is not None:
            coa.timestamp = timestamp
        related_coa = RelatedCOA(coa, relationship=category)
        return related_coa

    @staticmethod
    def _create_related_threat_actor(ta_id: str, category: str, timestamp: Optional[datetime] = None) -> RelatedThreatActor:
        rta = ThreatActor(idref=ta_id)
        if timestamp is not None:
            rta.timestamp = timestamp
        related_ta = RelatedThreatActor(rta, relationship=category)
        return related_ta

    @staticmethod
    def _create_related_ttp(ttp_id: str, category: str, timestamp: Optional[datetime] = None) -> RelatedTTP:
        rttp = TTP(idref=ttp_id)
        if timestamp is not None:
            rttp.timestamp = timestamp
        related_ttp = RelatedTTP(rttp, relationship=category)
        return related_ttp

    def _create_socket_address_object(self, hostname: Optional[str] = None, ip: Optional[tuple] = None, port: Optional[str] = None) -> SocketAddress:
        socket_address_object = SocketAddress()
        if hostname is not None:
            socket_address_object.hostname = self._create_hostname_object(hostname)
        if ip is not None:
            socket_address_object.ip_address = self._create_address_object(*ip)
        if port is not None:
            socket_address_object.port = self._create_port_object(port)
        return socket_address_object

    def _create_threat_actor_from_galaxy(self, cluster: dict) -> ThreatActor:
        threat_actor = ThreatActor()
        threat_actor.id_ = f"{self._orgname}:ThreatActor-{cluster['uuid']}"
        threat_actor.title = cluster['value']
        if cluster.get('description'):
            threat_actor.description = cluster['description']
        meta = cluster['meta']
        if meta.get('cfr-type-of-incident'):
            intended_effect = meta['cfr-type-of-incident']
            if isinstance(intended_effect, list):
                for effect in intended_effect:
                    threat_actor.add_intended_effect(effect)
            else:
                threat_actor.add_intended_effect(intended_effect)
        return threat_actor

    def _create_ttp(self, attribute: dict) -> TTP:
        ttp = TTP(timestamp=self._datetime_from_timestamp(attribute['timestamp']))
        ttp.id_ = f"{self._orgname}:TTP-{attribute['uuid']}"
        if attribute.get('Tag'):
            tags = tuple(tag['name'] for tag in attribute['Tag'])
            ttp.handling = self._set_handling(tags)
        ttp.title = f"{attribute['category']}: {attribute['value']} (MISP Attribute)"
        return ttp

    def _create_ttp_from_galaxy(self, galaxy_name: str, uuid: str) -> TTP:
        ttp = TTP()
        ttp.id_ = f'{self._orgname}:TTP-{uuid}'
        ttp.title = f'{galaxy_name} (MISP Galaxy)'
        return ttp

    def _create_ttp_from_object(self, misp_object: dict) -> TTP:
        ttp = TTP(timestamp=self._datetime_from_timestamp(misp_object['timestamp']))
        ttp.id_ = f"{self._orgname}:TTP-{misp_object['uuid']}"
        ttp.title = f"{misp_object['meta-category']}: {misp_object['name']} (MISP Object)"
        return ttp

    @staticmethod
    def _create_uri_object(url: str) -> URI:
        uri_object = URI(value=url, type_='URL')
        uri_object.value.condition = "Equals"
        return uri_object

    def _create_uri_observable(self, url: str, uuid: str) -> Observable:
        uri_object = self._create_uri_object(url)
        observable = self._create_observable(uri_object, uuid, 'URI')
        return observable

    def _create_unix_user_account_object(self, attributes: dict) -> UnixUserAccount:
        account_object = UnixUserAccount()
        if 'user-id' in attributes:
            self._set_user_id(account_object, attributes, 'user_id')
        if 'group-id' in attributes:
            account_object.group_id = attributes.pop('group-id')[0]
            account_object.group_id.condition = 'Equals'
        if 'group' in attributes:
            self._set_group_list(account_object, attributes, UnixGroupList, UnixGroup, 'group_id')
            group_list = UnixGroupList()
            groups = attributes.pop('group')
            try:
                for group in groups:
                    unix_group = UnixGroup()
                    unix_group.group_id = group
                    group_list.append(unix_group)
                account_object.group_list = group_list
            except ValueError:
                attributes['group'] = groups
        return account_object

    def _create_user_account_object(self, attributes: dict) -> Union[UnixUserAccount, UserAccount, WinUser]:
        account_types = ('unix', 'windows-domain', 'windows-local')
        if 'account-type' in attributes and attributes['account-type'] in account_types:
            account_type = attributes.pop('account-type')
            if account_type == 'unix':
                return self._create_unix_user_account_object(attributes)
            attributes['account-type'] = [account_type]
            return self._create_windows_user_account_object(attributes)
        account_object = UserAccount()
        return account_object

    def _create_windows_user_account_object(self, attributes: dict) -> WinUser:
        account_object = WinUser()
        if 'user-id' in attributes:
            self._set_user_id(account_object, attributes, 'security_id')
        if 'group' in attributes:
            self._set_group_list(account_object, attributes, WinGroupList, WinGroup, 'name')
        return account_object

    @staticmethod
    def _fetch_colors(tags: list) -> tuple:
        return (tag.split(':')[-1].upper() for tag in tags)

    @staticmethod
    def _set_color(colors: list) -> str:
        tlp_color = 0
        for color in colors:
            color_num = stix1_mapping.TLP_order[color]
            if color_num > tlp_color:
                tlp_color = color_num
                color_value = color
        return color_value

    def _set_creator(self) -> str:
        if self._misp_event.get('Orgc'):
            return self._misp_event['Orgc']['name']
        return self._orgname

    @staticmethod
    def _set_group_list(
        account_object: Union[UnixUserAccount, WinUser],
        attributes: dict,
        group_list_class: Union[UnixGroupList, WinGroupList],
        group_class: Union[UnixGroup, WinGroup],
        feature: str
    ):
        group_list = group_list_class()
        groups = attributes.pop('group')
        try:
            for grp in groups:
                group = group_class()
                setattr(group, feature, grp)
                group_list.append(group)
            account_object.group_list = group_list
        except ValueError:
            attributes['group'] = groups

    def _set_handling(self, tags: list) -> Marking:
        sorted_tags = defaultdict(list)
        for tag in tags:
            feature = 'tlp_tags' if tag.startswith('tlp:') else 'simple_tags'
            sorted_tags[feature].append(tag)
        handling = Marking()
        marking_specification = MarkingSpecification()
        if 'tlp_tags' in sorted_tags:
            tlp_marking = TLPMarkingStructure()
            tlp_marking.color = self._set_color(self._fetch_colors(sorted_tags['tlp_tags']))
            marking_specification.marking_structures.append(tlp_marking)
        for tag in sorted_tags['simple_tags']:
            simple_marking = SimpleMarkingStructure()
            simple_marking.statement = tag
            marking_specification.marking_structures.append(simple_marking)
        handling.add_marking(marking_specification)
        return handling

    @staticmethod
    def _set_indicator_type(attribute_type: str) -> str:
        if attribute_type in stix1_mapping.misp_indicator_type:
            return stix1_mapping.misp_indicator_type[attribute_type]
        return 'Malware Artifacts'

    def _set_producer(self) -> Identity:
        identity = Identity(name=self.orgc_name)
        information_source = InformationSource(identity=identity)
        return information_source

    def _set_reporter(self) -> Identity:
        reporter = self._misp_event['Org']['name'] if self._misp_event.get('Org') else self._orgname
        identity = Identity(name=reporter)
        return self._create_information_source(identity)

    def _set_source(self) -> Identity:
        identity = Identity(name=self.orgc_name)
        return self._create_information_source(identity)

    @staticmethod
    def _set_user_id(account_object: Union[UnixUserAccount, WinUser], attributes: dict, feature: str):
        user_id = attributes.pop('user-id')[0]
        try:
            setattr(account_object, feature, user_id)
            setattr(getattr(account_object, feature), 'condition', 'Equals')
        except ValueError:
            attributes['user-id'] = [user_id]

    ################################################################################
    #                              UTILITY FUNCTIONS.                              #
    ################################################################################

    @staticmethod
    def _datetime_from_timestamp(timestamp):
        return datetime.utcfromtimestamp(int(timestamp))

    @staticmethod
    def _from_datetime_to_str(date):
        return date.strftime("%Y-%m-%dT%H:%M:%S+00:00")

    @staticmethod
    def _merge_galaxy_clusters(galaxies, galaxy):
        for cluster in galaxy['GalaxyCluster']:
            for galaxy_cluster in galaxies['GalaxyCluster']:
                if cluster['uuid'] == galaxy_cluster['uuid']:
                    break
            else:
                galaxies['GalaxyCluster'].append(cluster)

    @staticmethod
    def _quick_fetch_tag_names(galaxy: dict) -> list:
        attribute_galaxies = []
        for cluster in galaxy['GalaxyCluster']:
            attribute_galaxies.append(f'misp-galaxy:{galaxy["type"]}="{cluster["value"]}"')
        return attribute_galaxies
