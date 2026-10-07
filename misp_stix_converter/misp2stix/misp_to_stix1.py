#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import socket
from .exceptions import InvalidMISPInputError
from .exportparser import MISPtoSTIXParser
from ..tools.stix1_framing import _create_stix_package
from .stix1_mapping import MISPtoSTIX1Mapping
from abc import ABCMeta
from base64 import b64encode
from collections import defaultdict
from cybox.core import Observable, ObservableComposition, RelatedObject
from cybox.common import Hash, HashList, ByteRun, ByteRuns
from cybox.common.hashes import _set_hash_type
from cybox.common.object_properties import CustomProperties,  Property
from cybox.common.vocabs import ObjectRelationship, VocabString
from cybox.objects.account_object import Authentication, StructuredAuthenticationMechanism
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
from datetime import datetime, timezone
from io import BytesIO
from math import isinf, isnan
from stix.campaign import Campaign, Names
from stix.coa import CourseOfAction
from stix.common import InformationSource, Identity, StructuredText, ToolInformation
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
from stix.ttp.victim_targeting import VictimTargeting
from typing import Any, Iterable, Optional, Tuple, Union
from uuid import uuid5, UUID

_FILE_SINGLE_ATTRIBUTES = (
    "attachment", "authentihash", "entropy", "imphash", "malware-sample", "md5",
    "sha1", "sha224", "sha256", "sha384", "sha512", "sha512/224", "sha512/256",
    "size-in-bytes", "ssdeep", "tlsh", "vhash"
)
# The decimal literal a native CybOX float field writes back as the number it
# reads: `float()` takes more, a `nan`, an `inf`, digits of any script
_CANONICAL_FLOAT = re.compile(r'[+-]?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?')
# The spellings of a boolean a MISP value of a `boolean` relation takes
_MISP_BOOLEAN_SPELLINGS = {
    '1': True, 'true': True, 'True': True,
    '0': False, 'false': False, 'False': False
}
# The templates whose CybOX type another template writes too: a `credential`
# is a `UserAccount`, like a `user-account` with no unix or windows account
# type. On an Indicator the Record Title names the template; an Observable
# written without one carries that title itself, which every other object
# Observable goes without
_TITLED_OBSERVABLE_OBJECT_NAMES = ('credential',)
# The CybOX ObjectRelationship terms, by the MISP relationship spelling each
# one matches whatever its case and separators: taken from the vocabulary
# rather than spelled by a rule, `Sub-domain_Of` mixing both separators
_OBJECT_RELATIONSHIP_TERMS = {
    term.lower().replace('_', '-'): term
    for name, term in vars(ObjectRelationship).items()
    if name.startswith('TERM_')
}
_NON_INDICATOR_OBJECT_TYPES = Union[Campaign, CourseOfAction, TTP]
_OBSERVABLE_OBJECT_TYPES = Union[
    Address, Artifact, AutonomousSystem, Custom, DomainName, EmailMessage,
    File, Hostname, HTTPSession, Mutex, Pipe, Port, SocketAddress, System,
    URI, WinRegistryKey, WinService, X509Certificate
]


class MISPtoSTIX1Parser(MISPtoSTIXParser, metaclass=ABCMeta):
    def __init__(self, orgname: str, version: str):
        super().__init__()
        self._orgname = orgname
        self._orgname_id = re.sub('[\W]+', '', orgname.replace(" ", "_"))
        self._version = version
        self._mapping = MISPtoSTIX1Mapping

    @property
    def stix_package(self) -> STIXPackage:
        return self._stix_package

    def _optional_timestamp(self, data: dict) -> datetime | None:
        timestamp = data.get('timestamp')
        if timestamp is None:
            return None
        return self._datetime_from_timestamp(timestamp)

    ################################################################################
    #                         ATTRIBUTES PARSING FUNCTIONS                         #
    ################################################################################

    def _resolve_attribute(self, attribute: dict):
        attribute_type = attribute['type']
        try:
            to_call = self._mapping.attribute_types_mapping(attribute_type)
            if to_call is not None:
                getattr(self, to_call)(attribute)
            else:
                self._parse_custom_attribute(attribute)
                self._attribute_not_mapped_warning(attribute_type)
        except Exception as exception:
            self._attribute_error(attribute, exception)

    def _handle_attribute_indicator(self, attribute: dict, observable: Observable) -> Indicator:
        indicator = self._create_indicator_from_attribute(attribute)
        indicator.add_observable(observable)
        return indicator

    def _handle_attribute_indicator_tags(self, attribute: dict, indicator: Indicator, timestamp: datetime) -> Confidence:
        tags = self._handle_attribute_tags_and_galaxies(attribute, indicator)
        if tags:
            sorted_tags, confidence_tags = self._sort_tags(tags)
            indicator.handling = self._create_handling(sorted_tags)
            if confidence_tags:
                return Confidence(
                    value = confidence_tags[min(confidence_tags)],
                    timestamp = timestamp
                )
        return Confidence(
            value = self._mapping.confidence_value(),
            description = self._mapping.confidence_description(),
            timestamp = timestamp
        )

    def _handle_attribute_tags_and_galaxies(self, attribute: dict, indicator: Indicator) -> tuple:
        galaxies = attribute.get('Galaxy', [])
        for galaxy in galaxies:
            galaxy_type = galaxy['type']
            to_call = self._mapping.galaxy_types_mapping(galaxy_type)
            if to_call is not None:
                getattr(self, to_call.format('attribute'))(galaxy, indicator)
            else:
                self._attribute_galaxy_not_mapped_warning(galaxy_type, attribute['type'])
        return self._with_galaxy_tags(
            (tag['name'] for tag in attribute.get('Tag', [])), galaxies
        )

    def _handle_exploit_target(self, attribute: dict, stix_object: Union[Vulnerability, Weakness], stix_type: str):
        attribute_uuid = attribute['uuid']
        ttp = self._create_ttp(attribute)
        timestamp = self._optional_timestamp(attribute)
        exploit_target = ExploitTarget(timestamp=timestamp)
        exploit_target.id_ = f"{self._orgname_id}:ExploitTarget-{attribute_uuid}"
        if attribute.get('comment') and attribute['comment'] != "Imported via the freetext import.":
            exploit_target.description = attribute['comment']
        exploit_target.title = f"{stix_type.capitalize()} {attribute['value']}"
        getattr(exploit_target, f"add_{stix_type}")(stix_object)
        ttp.add_exploit_target(exploit_target)
        tags = self._handle_non_indicator_attribute_tags_and_galaxies(attribute, ttp)
        if tags:
            ttp.handling = self._set_handling(tags)
        self._stix_package.add_ttp(ttp)
        if self.identifier != 'attributes collection':
            related_ttp = self._create_related_ttp(ttp.id_, attribute['type'], timestamp=timestamp)
            self._incident.add_leveraged_ttps(related_ttp)

    def _handle_non_indicator_attribute_tags_and_galaxies(self, attribute: dict, ttp: TTP) -> tuple:
        galaxies = attribute.get('Galaxy', [])
        for galaxy in galaxies:
            galaxy_type = galaxy['type']
            to_call = self._mapping.galaxy_types_mapping(galaxy_type)
            if galaxy_type not in self._mapping.ttp_names() or to_call is None:
                self._attribute_galaxy_not_mapped_warning(galaxy_type, attribute['type'])
                continue
            getattr(self, to_call.format('object'))(galaxy, ttp)
        return self._with_galaxy_tags(
            (tag['name'] for tag in attribute.get('Tag', [])), galaxies
        )

    def _parse_attachment(self, attribute: dict):
        if attribute.get('data'):
            observable = self._create_attachment_observable(
                attribute['value'], attribute['data'], attribute['uuid']
            )
            self._handle_attribute(attribute, observable)
        else:
            self._parse_file_attribute(attribute)

    def _parse_autonomous_system_attribute(self, attribute: dict):
        value = attribute['value']
        if not self._is_as_handle(value):
            if not self._canonical_attribute_integer(attribute, value):
                return
        autonomous_system = self._create_autonomous_system_object(value)
        observable = self._create_observable(autonomous_system, attribute['uuid'], 'AS')
        self._handle_attribute(attribute, observable)

    def _parse_campaign_name_attribute(self, attribute: dict):
        timestamp = self._optional_timestamp(attribute)
        campaign = Campaign(timestamp=timestamp)
        campaign.id_ = f"{self._orgname_id}:Campaign-{attribute['uuid']}"
        campaign.title = f"{attribute.get('category', 'Other')}: {attribute['value']} (MISP Attribute)"
        if attribute.get('comment') and attribute['comment'] != "Imported via the freetext import.":
            campaign.description = attribute['comment']
        names = Names()
        names.name = attribute['value']
        campaign.names = names
        tags = self._handle_non_indicator_attribute_tags_and_galaxies(attribute, campaign)
        if tags:
            sorted_tags, confidence_tags = self._sort_tags(tags)
            if confidence_tags:
                campaign.confidence = Confidence(
                    value = confidence_tags[min(confidence_tags)],
                    timestamp = timestamp
                )
            campaign.handling = self._create_handling(sorted_tags)
        self._stix_package.add_campaign(campaign)

    def _canonical_attribute_integer(self, attribute: dict,
                                     value: Any) -> bool:
        """Whether the native CybOX integer field of an attribute holds its
        number unchanged - an attribute whose number the field would rewrite
        or refuse goes out whole as a custom attribute instead, its value
        under its type."""
        record = self._attribute_record(attribute)
        if self._canonical_integer(value, attribute['type'], record):
            return True
        self._parse_custom_attribute(attribute)
        return False

    @staticmethod
    def _attribute_record(attribute: dict) -> str:
        return f"{attribute['type']} attribute (uuid: {attribute['uuid']})"

    def _parse_custom_attribute(self, attribute: dict):
        custom_object = Custom()
        custom_object.custom_properties = CustomProperties()
        self._append_property(
            custom_object.custom_properties,
            attribute['type'], attribute['value'],
            self._attribute_record(attribute)
        )
        observable = self._create_observable(custom_object, attribute['uuid'], 'Custom')
        self._handle_attribute(attribute, observable)

    def _write_custom_attribute(self, attribute: dict):
        """The attribute error fallback: the attribute a route failed on goes
        out as a `Custom` Observable.

        :param attribute: the MISP attribute the export failed on
        """
        try:
            self._parse_custom_attribute(attribute)
        except Exception:
            # The Observable is written the way the failed route writes its
            # own, from the same attribute fields: what failed there - a
            # timestamp the Indicator cannot parse - fails here again, with
            # nothing left to catch it. The attribute is lost, and the error
            # already says so
            return

    def _parse_domain_attribute(self, attribute: dict):
        observable = self._create_domain_observable(attribute['value'], attribute['uuid'])
        self._handle_attribute(attribute, observable)

    def _parse_domain_ip_attribute(self, attribute: dict):
        for separator in self.composite_separators:
            if separator in attribute['value']:
                domain, ip = attribute['value'].split(separator)
                domain_observable = self._create_domain_observable(
                    domain, attribute['uuid'],
                    alternative_uuid=uuid5(UUID(attribute['uuid']), domain)
                )
                address_observable = self._create_address_observable(
                    attribute['type'], ip, attribute['uuid'],
                    alternative_uuid=uuid5(UUID(attribute['uuid']), ip)
                )
                observable = self._create_observable_composition(
                    [domain_observable, address_observable],
                    attribute['uuid']
                )
                self._handle_attribute(attribute, observable)
                break
        else:
            self._composite_attribute_value_warning(attribute['type'], attribute['value'])
            self._parse_custom_attribute(attribute)

    def _parse_email_attachment(self, attribute: dict):
        file_object = File()
        file_object.file_name = attribute['value']
        file_object.file_name.condition = "Equals"
        file_object.parent.id_ = f"{self._orgname_id}:File-{attribute['uuid']}"
        email = EmailMessage()
        email.attachments = Attachments()
        email.attachments.append(file_object.parent.id_)
        email.add_related(file_object, "Contains", inline=True)
        email.parent.related_objects[0].id_ = f"{self._orgname_id}:File-{attribute['uuid']}"
        observable = self._create_observable(email, attribute['uuid'], 'EmailMessage')
        self._handle_attribute(attribute, observable)

    def _parse_email_attribute(self, attribute: dict):
        email_object = EmailMessage()
        email_header = EmailHeader()
        feature = self._mapping.email_attribute_mapping(attribute['type'])
        setattr(email_header, feature, attribute['value'])
        setattr(getattr(email_header, feature), 'condition', 'Equals')
        email_object.header = email_header
        observable = self._create_observable(email_object, attribute['uuid'], 'EmailMessage')
        self._handle_attribute(attribute, observable)

    def _parse_email_body_attribute(self, attribute: dict):
        email_object = EmailMessage()
        email_object.raw_body = attribute['value']
        email_object.raw_body.condition = 'Equals'
        observable = self._create_observable(email_object, attribute['uuid'], 'EmailMessage')
        self._handle_attribute(attribute, observable)

    def _parse_email_header_attribute(self, attribute: dict):
        email_object = EmailMessage()
        email_object.raw_header = attribute['value']
        email_object.raw_header.condition = 'Equals'
        observable = self._create_observable(email_object, attribute['uuid'], 'EmailMessage')
        self._handle_attribute(attribute, observable)

    def _parse_file_attribute(self, attribute: dict):
        file_object = self._create_file_object(attribute['value'])
        observable = self._create_observable(file_object, attribute['uuid'], 'File')
        self._handle_attribute(attribute, observable)

    def _parse_hash_attribute(self, attribute: dict):
        _hash = self._parse_hash_value(attribute['type'], attribute['value'])
        file_object = File()
        file_object.add_hash(_hash)
        observable = self._create_observable(file_object, attribute['uuid'], 'File')
        self._handle_attribute(attribute, observable)

    def _parse_hash_composite_attribute(self, attribute: dict):
        for separator in self.composite_separators:
            if separator in attribute['value']:
                filename, hash_value = attribute['value'].split(separator)
                file_object = self._create_file_object(filename)
                attribute_type = attribute['type'].split('|')[1] if '|' in attribute['type'] else 'md5'
                file_object.add_hash(self._parse_hash_value(attribute_type, hash_value))
                observable = self._create_observable(file_object, attribute['uuid'], 'File')
                self._handle_attribute(attribute, observable)
                break
        else:
            self._composite_attribute_value_warning(attribute['type'], attribute['value'])
            file_object = self._create_file_object(attribute['value'])
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
        for separator in self.composite_separators:
            if separator in attribute['value']:
                hostname, port = attribute['value'].split(separator)
                if not self._canonical_attribute_integer(attribute, port):
                    break
                socket_address = self._create_socket_address_object(
                    hostname=hostname, port=port)
                observable = self._create_observable(
                    socket_address, attribute['uuid'], 'SocketAddress')
                self._handle_attribute(attribute, observable)
                break
        else:
            self._composite_attribute_value_warning(attribute['type'], attribute['value'])
            self._parse_custom_attribute(attribute)

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
        for separator in self.composite_separators:
            if separator in attribute['value']:
                ip, port = attribute['value'].split(separator)
                if not self._canonical_attribute_integer(attribute, port):
                    break
                ip_type = attribute['type'].split('|')[0]
                socket_address = self._create_socket_address_object(ip=(ip_type, ip), port=port)
                observable = self._create_observable(
                    socket_address, attribute['uuid'], 'SocketAddress')
                self._handle_attribute(attribute, observable)
                break
        else:
            self._composite_attribute_value_warning(attribute['type'], attribute['value'])
            self._parse_custom_attribute(attribute)

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
        if not self._canonical_attribute_integer(attribute, attribute['value']):
            return
        observable = self._create_port_observable(attribute['value'], attribute['uuid'])
        self._handle_attribute(attribute, observable)

    def _parse_regkey_attribute(self, attribute: dict):
        registry_key = self._create_registry_key_object(attribute['value'])
        observable = self._create_observable(registry_key, attribute['uuid'], 'WindowsRegistryKey')
        self._handle_attribute(attribute, observable)

    def _parse_regkey_value_attribute(self, attribute: dict):
        for separator in self.composite_separators:
            if separator in attribute['value']:
                regkey, value = attribute['value'].split(separator)
                registry_key = self._create_registry_key_object(regkey)
                registry_value = RegistryValue()
                registry_value.data = value.strip()
                registry_value.data.condition = "Equals"
                registry_key.values = RegistryValues(registry_value)
                observable = self._create_observable(
                    registry_key, attribute['uuid'], 'WindowsRegistryKey')
                self._handle_attribute(attribute, observable)
                break
        else:
            self._composite_attribute_value_warning(attribute['type'], attribute['value'])
            registry_key = self._create_registry_key_object(attribute['value'])
            observable = self._create_observable(
                registry_key, attribute['uuid'], 'WindowsRegistryKey')
            self._handle_attribute(attribute, observable)

    def _parse_size_in_bytes_attribute(self, attribute: dict):
        if not self._canonical_attribute_integer(attribute, attribute['value']):
            return
        file_object = File()
        file_object.size_in_bytes = attribute['value']
        file_object.size_in_bytes.condition = 'Equals'
        observable = self._create_observable(file_object, attribute['uuid'], 'File')
        self._handle_attribute(attribute, observable)

    def _parse_snort_attribute(self, attribute: dict):
        if attribute.get('to_ids', False):
            test_mechanism = SnortTestMechanism()
            # The rule text itself: python-stix wraps it in the CDATA the
            # schema wants, and a dict here was written as its Python repr
            test_mechanism.rules = [attribute['value']]
            self._handle_test_mechanism(attribute, test_mechanism)
        else:
            self._parse_custom_attribute(attribute)

    def _parse_target_email(self, attribute: dict):
        identity_spec = STIXCIQIdentity3_0()
        identity_spec.add_electronic_address_identifier(ElectronicAddressIdentifier(value=attribute['value']))
        self._handle_target_attribute(attribute, identity_spec)

    def _parse_target_external(self, attribute: dict):
        identity_spec = STIXCIQIdentity3_0()
        identity_spec.party_name = PartyName(name_lines=[f"External target: {attribute['value']}"])
        self._handle_target_attribute(attribute, identity_spec)

    def _parse_target_location(self, attribute: dict):
        identity_spec = STIXCIQIdentity3_0()
        identity_spec.add_address(ciq_Address(FreeTextAddress(address_lines=[attribute['value']])))
        self._handle_target_attribute(attribute, identity_spec)

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
        self._handle_target_attribute(attribute, identity_spec)

    def _parse_target_user(self, attribute: dict):
        identity_spec = STIXCIQIdentity3_0()
        identity_spec.party_name = PartyName(person_names=[attribute['value']])
        self._handle_target_attribute(attribute, identity_spec)

    def _parse_url_attribute(self, attribute: dict):
        observable = self._create_uri_observable(attribute['value'], attribute['uuid'])
        self._handle_attribute(attribute, observable)

    def _parse_undefined_attribute(self, attribute: dict):
        if attribute.get('comment') and attribute['comment'] == 'Imported from STIX header description':
            self._header_description_attributes.append(attribute)
        else:
            self._add_attribute_journal_entry(attribute)
        # Text has no handling for a cluster tag
        record = self._attribute_record(attribute)
        for tag_name in self._with_galaxy_tags((), attribute.get('Galaxy', ())):
            self._journal_entry_galaxy_warning(tag_name, record)

    def _add_attribute_journal_entry(self, attribute: dict):
        self._add_journal_entry(f"Attribute ({attribute.get('category', 'Other')} - {attribute['type']}): {attribute['value']}")

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

    def _parse_whois_registrant_attribute(self, attribute: dict):
        whois_object = WhoisEntry()
        registrants = WhoisRegistrants()
        registrant = WhoisRegistrant()
        object_relation = '-'.join(attribute['type'].split('-')[1:])
        feature = self._mapping.whois_registrant_mapping(object_relation)
        setattr(registrant, feature, attribute['value'])
        setattr(getattr(registrant, feature), 'condition', 'Equals')
        registrants.append(registrant)
        whois_object.registrants = registrants
        observable = self._create_observable(whois_object, attribute['uuid'], 'Whois')
        self._handle_attribute(attribute, observable)

    def _parse_whois_registrar_attribute(self, attribute: dict):
        whois_object = WhoisEntry()
        whois_registrar = WhoisRegistrar()
        whois_registrar.name = attribute['value']
        whois_object.registrar_info = whois_registrar
        observable = self._create_observable(whois_object, attribute['uuid'], 'Whois')
        self._handle_attribute(attribute, observable)

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
            # The rule text itself, as for a `snort` attribute
            test_mechanism.rule = attribute['value']
            self._handle_test_mechanism(attribute, test_mechanism)
        else:
            self._parse_custom_attribute(attribute)

    ################################################################################
    #                          GALAXIES PARSING FUNCTIONS                          #
    ################################################################################

    def _parse_attack_pattern_attribute_galaxy(self, galaxy: dict, indicator: Indicator):
        galaxy_name = galaxy['name']
        for cluster in galaxy['GalaxyCluster']:
            ttp_id = self._parse_ttp(cluster, 'attack_pattern', galaxy_name)
            related_ttp = self._create_related_ttp(ttp_id, galaxy_name)
            indicator.add_indicated_ttp(related_ttp)

    def _parse_attack_pattern_galaxy(self, cluster: dict, ttp: TTP):
        behavior = Behavior()
        attack_pattern = AttackPattern()
        attack_pattern.id_ = f"{self._orgname_id}:AttackPattern-{cluster['uuid']}"
        attack_pattern.title = cluster['value']
        attack_pattern.description = cluster['description']
        if cluster.get('meta', {}).get('external_id') is not None:
            external_id = cluster['meta']['external_id'][0]
            if external_id.startswith('CAPEC'):
                attack_pattern.capec_id = external_id
        behavior.add_attack_pattern(attack_pattern)
        ttp.behavior = behavior

    def _parse_attack_pattern_object_galaxy(self, galaxy: dict, stix_object: _NON_INDICATOR_OBJECT_TYPES):
        galaxy_name = galaxy['name']
        for cluster in galaxy['GalaxyCluster']:
            ttp_id = self._parse_ttp(cluster, 'attack_pattern', galaxy_name)
            related_ttp = self._create_related_ttp(ttp_id, galaxy_name)
            stix_object.add_related_ttp(related_ttp)

    def _parse_course_of_action_attribute_galaxy(self, galaxy: dict, indicator: Indicator):
        for cluster in galaxy['GalaxyCluster']:
            coa_id = self._parse_course_of_action_galaxy(cluster)
            related_coa = self._create_related_coa(coa_id, galaxy['name'])
            indicator.suggested_coas.append(related_coa)

    def _parse_course_of_action_galaxy(self, cluster: dict) -> str:
        if cluster['uuid'] not in self._ids:
            course_of_action = self._create_course_of_action_from_galaxy(cluster)
            self._stix_package.add_course_of_action(course_of_action)
            self._ids.add(cluster['uuid'])
            return course_of_action.id_
        return f"{self._orgname_id}:CourseOfAction-{cluster['uuid']}"

    def _parse_course_of_action_object_galaxy(self, galaxy: dict, object_coa: CourseOfAction):
        for cluster in galaxy['GalaxyCluster']:
            coa_id = self._parse_course_of_action_galaxy(cluster)
            related_coa = self._create_related_coa(coa_id, galaxy['name'])
            object_coa.related_coas.append(related_coa)

    def _parse_malware_attribute_galaxy(self, galaxy: dict, indicator: Indicator):
        galaxy_name = galaxy['name']
        for cluster in galaxy['GalaxyCluster']:
            ttp_id = self._parse_ttp(cluster, 'malware', galaxy_name)
            related_ttp = self._create_related_ttp(ttp_id, galaxy_name)
            indicator.add_indicated_ttp(related_ttp)

    def _parse_malware_galaxy(self, cluster: dict, ttp: TTP):
        behavior = Behavior()
        malware = MalwareInstance()
        malware.id_ = f"{self._orgname_id}:MalwareInstance-{cluster['uuid']}"
        malware.title = cluster['value']
        if cluster.get('description'):
            malware.description = cluster['description']
        if cluster.get('meta', {}).get('synonyms') is not None:
            for synonym in cluster['meta']['synonyms']:
                malware.add_name(synonym)
        behavior.add_malware_instance(malware)
        ttp.behavior = behavior

    def _parse_malware_object_galaxy(self, galaxy: dict, stix_object: _NON_INDICATOR_OBJECT_TYPES):
        galaxy_name = galaxy['name']
        for cluster in galaxy['GalaxyCluster']:
            ttp_id = self._parse_ttp(cluster, 'malware', galaxy_name)
            related_ttp = self._create_related_ttp(ttp_id, galaxy_name)
            stix_object.add_related_ttp(related_ttp)

    def _parse_threat_actor(self, cluster: dict) -> str:
        if cluster['uuid'] not in self._ids:
            threat_actor = self._create_threat_actor_from_galaxy(cluster)
            self._stix_package.add_threat_actor(threat_actor)
            self._ids.add(cluster['uuid'])
            return threat_actor.id_
        return f"{self._orgname_id}:ThreatActor-{cluster['uuid']}"

    def _parse_threat_actor_attribute_galaxy(self, galaxy: dict, indicator: Indicator):
        # A STIX 1 Indicator has no threat actor slot: the actor lands where
        # an event-level one does
        self._parse_threat_actor_galaxy(galaxy)

    def _parse_tool_attribute_galaxy(self, galaxy: dict, indicator: Indicator):
        galaxy_name = galaxy['name']
        for cluster in galaxy['GalaxyCluster']:
            ttp_id = self._parse_ttp(cluster, 'tool', galaxy_name)
            related_ttp = self._create_related_ttp(ttp_id, galaxy_name)
            indicator.add_indicated_ttp(related_ttp)

    def _parse_tool_galaxy(self, cluster: dict, ttp: TTP):
        tools = Tools()
        tool = ToolInformation()
        tool.id_ = f"{self._orgname_id}:ToolInformation-{cluster['uuid']}"
        tool.name = cluster['value']
        if cluster.get('description'):
            tool.description = cluster['description']
        tools.append(tool)
        resource = Resource()
        resource.tools = tools
        ttp.resources = resource

    def _parse_tool_object_galaxy(self, galaxy: dict, stix_object: _NON_INDICATOR_OBJECT_TYPES):
        galaxy_name = galaxy['name']
        for cluster in galaxy['GalaxyCluster']:
            ttp_id = self._parse_ttp(cluster, 'tool', galaxy_name)
            related_ttp = self._create_related_ttp(ttp_id, galaxy_name)
            stix_object.add_related_ttp(related_ttp)

    def _parse_ttp(self, cluster: dict, feature: str, galaxy_name: str) -> str:
        if cluster['uuid'] not in self._ids:
            ttp = self._create_ttp_from_galaxy(galaxy_name, cluster['uuid'])
            getattr(self, f'_parse_{feature}_galaxy')(cluster, ttp)
            self._stix_package.add_ttp(ttp)
            self._ids.add(cluster['uuid'])
            return ttp.id_
        return f"{self._orgname_id}:TTP-{cluster['uuid']}"

    def _parse_vulnerability_attribute_galaxy(self, galaxy: dict, indicator: Indicator):
        galaxy_name = galaxy['name']
        for cluster in galaxy['GalaxyCluster']:
            ttp_id = self._parse_ttp(cluster, 'vulnerability', galaxy_name)
            related_ttp = self._create_related_ttp(ttp_id, galaxy_name)
            indicator.add_indicated_ttp(related_ttp)

    def _parse_vulnerability_galaxy(self, cluster: dict, ttp: TTP):
        exploit_target = ExploitTarget()
        exploit_target.id_ = f"{self._orgname_id}:ExploitTarget-{cluster['uuid']}"
        vulnerability = Vulnerability()
        vulnerability.id_ = f"{self._orgname_id}:Vulnerability-{cluster['uuid']}"
        vulnerability.title = cluster['value']
        vulnerability.description = cluster['description']
        if cluster.get('meta') is not None:
            if cluster['meta'].get('aliases'):
                vulnerability.cve_id = cluster['meta']['aliases'][0]
            if cluster['meta'].get('refs'):
                for reference in cluster['meta']['refs']:
                    vulnerability.add_reference(reference)
        exploit_target.add_vulnerability(vulnerability)
        ttp.add_exploit_target(exploit_target)

    def _parse_vulnerability_object_galaxy(self, galaxy: dict, stix_object: _NON_INDICATOR_OBJECT_TYPES):
        galaxy_name = galaxy['name']
        for cluster in galaxy['GalaxyCluster']:
            ttp_id = self._parse_ttp(cluster, 'vulnerability', galaxy_name)
            related_ttp = self._create_related_ttp(ttp_id, galaxy_name)
            stix_object.add_related_ttp(related_ttp)

    ################################################################################
    #                    STIX OBJECTS CREATION HELPER FUNCTIONS                    #
    ################################################################################

    def _append_property(self, custom_properties: CustomProperties,
                         name: str, value: Any, record: Optional[str] = None):
        prop = self._create_property(name, value, record)
        if prop is not None:
            custom_properties.append(prop)

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

    def _create_address_observable(self, feature: str, value: str, uuid: str,
                                   alternative_uuid: Optional[str] = None) -> Observable:
        address_object = self._create_address_object(feature, value)
        observable = self._create_observable(address_object, uuid, 'Address', alternative_uuid)
        return observable

    def _create_artifact_object(self, data: Union[str, BytesIO]) -> Artifact:
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
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
    def _is_as_handle(AS: Any) -> bool:
        # An integer is the number itself, never an `AS`-prefixed handle
        return isinstance(AS, str) and AS.startswith('AS')

    def _create_autonomous_system_object(
            self, AS: Union[int, str]) -> AutonomousSystem:
        autonomous_system = AutonomousSystem()
        feature = 'handle' if self._is_as_handle(AS) else 'number'
        setattr(autonomous_system, feature, AS)
        setattr(getattr(autonomous_system, feature), 'condition', 'Equals')
        return autonomous_system

    def _create_ciq_identity_instance(self, attribute: dict, identity_spec):
        ciq_identity = CIQIdentity3_0Instance()
        ciq_identity.specification = identity_spec
        ciq_identity.id_ = f"{self._orgname_id}:Identity-{attribute['uuid']}"
        ciq_identity.name = f"{attribute.get('category', 'Other')}: {attribute['value']} (MISP Attribute)"
        return ciq_identity

    def _create_course_of_action_from_galaxy(self, cluster: dict) -> CourseOfAction:
        course_of_action = CourseOfAction()
        course_of_action.id_ = f"{self._orgname_id}:CourseOfAction-{cluster['uuid']}"
        course_of_action.title = cluster['value']
        course_of_action.description = cluster['description']
        return course_of_action

    @staticmethod
    def _create_domain_object(domain: str) -> DomainName:
        domain_object = DomainName()
        domain_object.value = domain
        domain_object.value.condition = "Equals"
        return domain_object

    def _create_domain_observable(self, domain: str, uuid: str,
                                  alternative_uuid: Optional[str] = None) -> Observable:
        domain_object = self._create_domain_object(domain)
        observable = self._create_observable(domain_object, uuid, 'DomainName', alternative_uuid)
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
        timestamp = self._optional_timestamp(attribute)
        indicator = Indicator(timestamp=timestamp)
        indicator.id_ = f"{self._orgname_id}:Indicator-{attribute['uuid']}"
        indicator.producer = self._producer
        indicator.title = f"{attribute.get('category', 'Other')}: {attribute['value']} (MISP Attribute)"
        indicator.description = attribute['comment'] if attribute.get('comment') else indicator.title
        indicator.add_indicator_type(self._set_indicator_type(attribute['type']))
        indicator.add_valid_time_position(ValidTime())
        indicator.confidence = self._handle_attribute_indicator_tags(attribute, indicator, timestamp)
        return indicator

    @staticmethod
    def _create_information_source(name: str) -> InformationSource:
        identity = Identity(name=name)
        information_source = InformationSource(identity=identity)
        return information_source

    def _create_malware_sample_observable(self, filename: str, data: BytesIO,
                                          uuid: str) -> Observable:
        artifact_object = self._create_artifact_object(data)
        for separator in self.composite_separators:
            if separator in filename:
                filename, hash_value = filename.split(separator)
                artifact_object.hashes = HashList(self._parse_hash_value('md5', hash_value))
                break
        else:
            self._composite_attribute_value_warning('malware-sample', filename)
        observable = self._create_observable(artifact_object, uuid, 'Artifact')
        observable.title = filename
        return observable

    @staticmethod
    def _create_mutex_object(name: str) -> Mutex:
        mutex_object = Mutex()
        mutex_object.name = name
        mutex_object.name.condition = "Equals"
        return mutex_object

    def _create_observable(
            self, stix_object: _OBSERVABLE_OBJECT_TYPES, attribute_uuid: str,
            feature: str, alternative_uuid: Optional[str] = None) -> Observable:
        stix_object.parent.id_ = f"{self._orgname_id}:{feature}-{attribute_uuid}"
        observable = Observable(stix_object)
        if alternative_uuid is None:
            alternative_uuid = attribute_uuid
        observable.id_ = f"{self._orgname_id}:Observable-{alternative_uuid}"
        return observable

    @staticmethod
    def _add_record_comment(
            stix_object: Union[ExploitTarget, Observable, TTP], record: dict):
        # A record exported without `to_ids` has no Indicator to carry its
        # comment, and a context object is a TTP with none either. The
        # Observable's own description carries it, the Exploit Target's for a
        # `vulnerability` or `weakness` object, the TTP's own for an
        # `attack-pattern` object, whose Attack Pattern descriptions all carry
        # relations. Only when there is one: an uncommented record writes no
        # description
        if record.get('comment'):
            stix_object.description = record['comment']

    def _create_observable_composition(self, observables: list, uuid: str,
                                       name: Optional[str] = None) -> Observable:
        object_type = 'ObservableComposition' if name is None else f'{name}_ObservableComposition'
        observable_composition = ObservableComposition(observables=observables)
        observable_composition.operator = 'AND'
        observable = Observable(id_=f'{self._orgname_id}:{object_type}-{uuid}')
        observable.observable_composition = observable_composition
        return observable

    def _create_custom_members(self, misp_object: dict,
                                     written: tuple) -> list:
        """Build a composition member for each relation of a MISP object the
        composition has no member of its own for.

        A composition has no property bag to put them in: each value is one
        nameless `Custom` object holding one property named with the
        relation, under the attribute's uuid as every other member is, so
        that each member still carries one attribute.

        :param misp_object: the MISP object the composition is written from
        :param written: the relations the composition writes a member for
        :return: the members, one per value a property can carry
        """
        record = self._object_features(misp_object)
        observables = []
        for attribute in misp_object['Attribute']:
            relation = attribute['object_relation']
            if relation in written:
                continue
            observable = self._create_custom_member(
                relation, attribute['value'], attribute['uuid'], record
            )
            if observable is not None:
                observables.append(observable)
        return observables

    def _create_custom_member(self, relation: str, value: Any, uuid: str,
                              record: str) -> Optional[Observable]:
        prop = self._create_property(relation, value, record)
        if prop is None:
            return None
        custom_object = Custom()
        custom_object.custom_properties = CustomProperties()
        custom_object.custom_properties.append(prop)
        return self._create_observable(custom_object, uuid, 'Custom')

    def _create_port_members(self, misp_object: dict, relation: str,
                             ports: list,
                             feature: Optional[str] = None) -> list:
        """Build the composition member of each port of a relation, as a
        `Custom` one where the port is a number the CybOX field would
        rewrite or refuse.

        :param misp_object: the MISP object the composition is written from
        :param relation: the relation the ports are values of
        :param ports: the value and the uuid of each port attribute
        :param feature: the side a port is on, where the relation names one
        :return: the members, one per value a property can carry
        """
        record = self._object_features(misp_object)
        observables = []
        for port, uuid in ports:
            if self._canonical_integer(port, relation, record):
                observables.append(
                    self._create_port_observable(port, uuid, feature=feature)
                )
                continue
            observable = self._create_custom_member(
                relation, port, uuid, record
            )
            if observable is not None:
                observables.append(observable)
        return observables

    @staticmethod
    def _create_port_object(port: str) -> Port:
        port_object = Port()
        port_object.port_value = port
        port_object.port_value.condition = "Equals"
        return port_object

    def _create_port_observable(self, port: str, uuid: str,
                                feature: Optional[str] = None) -> Observable:
        object_type = 'Port'
        if feature is not None:
            object_type = f'{feature}{object_type}'
        port_object = self._create_port_object(port)
        observable = self._create_observable(port_object, uuid, object_type)
        return observable

    def _create_property(
            self, name: str, value: Any,
            record: Optional[str] = None) -> Optional[Property]:
        """Build a CybOX custom property out of a MISP value.

        A MISP object template names the type of the relation it declares, so
        a boolean, an integer or a float goes out in the lexical form XSD has
        for it, under the CybOX `datatype` saying which - values cybox
        refuses outright today, so no document that has ever been written
        changes. A value with no such form is skipped with a warning rather
        than raising: the property is built from routes nothing above
        catches.
        """
        if isinstance(value, list) and len(value) == 1:
            value = value[0]
        if isinstance(value, list):
            # cybox validates a list element by element, so one value with no
            # lexical form costs the property exactly as it would alone - an
            # empty one carries nothing to write in the first place
            forms = [self._lexical_form(item) for item in value]
            if not forms or None in forms:
                self._unstorable_property_warning(name, value, record)
                return None
            datatypes = {datatype for datatype, _ in forms}
            # Values of one relation share a type; a list that mixes them has
            # no one name, so it goes out as the strings it already is
            datatype = datatypes.pop() if len(datatypes) == 1 else None
            lexical_form = [form for _, form in forms]
        else:
            form = self._lexical_form(value)
            if form is None:
                self._unstorable_property_warning(name, value, record)
                return None
            datatype, lexical_form = form
        prop = Property()
        prop.name = name
        if datatype is not None:
            prop.datatype = datatype
        prop.value = lexical_form
        return prop

    def _canonical_integer(self, value: Any, relation: str, record: str,
                           signed: bool = False) -> bool:
        """Whether a native CybOX integer field holds a MISP value unchanged.

        cybox casts a string with `int(value, 0)` and checks no sign against
        an unsigned type: `'0x1f'` goes out as `31`, `'-3'` as a value the
        schema refuses. Only the decimal digits the field writes back are
        canonical; any other value is warned of, for the property bag to
        carry verbatim under its relation.
        """
        if isinstance(value, bool):
            canonical = False
        elif isinstance(value, int):
            canonical = signed or value >= 0
        elif isinstance(value, str):
            digits = value[1:] if signed and value.startswith('-') else value
            canonical = (
                digits.isascii() and digits.isdigit()
                and value == str(int(value))
            )
        else:
            canonical = False
        if not canonical:
            self._non_canonical_number_warning(
                relation, value, record,
                'decimal integer' if signed else 'unsigned decimal integer'
            )
        return canonical

    def _canonical_float(self, value: Any, relation: str,
                         record: str) -> bool:
        """Whether a native CybOX float field holds a MISP value as the
        number it spells: `float()` reads a `nan`, an `inf`, digits of any
        script and underscores, and refuses a `0x1f` with the whole object.
        Any value but a decimal literal is warned of, for the property bag to
        carry verbatim under its relation."""
        if isinstance(value, bool):
            canonical = False
        elif isinstance(value, int):
            canonical = True
        elif isinstance(value, float):
            canonical = not (isnan(value) or isinf(value))
        elif isinstance(value, str):
            canonical = _CANONICAL_FLOAT.fullmatch(value) is not None
        else:
            canonical = False
        if not canonical:
            self._non_canonical_number_warning(
                relation, value, record, 'decimal number'
            )
        return canonical

    def _native_boolean(self, attributes: dict, relation: str,
                        misp_object: dict) -> Optional[bool]:
        """Pop a relation a native CybOX boolean field holds, as the boolean
        its value spells.

        A value spelling no boolean stays in the attributes, for the custom
        properties to carry verbatim: the field would drop it, and a reader
        of the field would never see it.
        """
        if relation not in attributes:
            return None
        value = attributes[relation]
        if isinstance(value, bool):
            return attributes.pop(relation)
        if isinstance(value, str) and value in _MISP_BOOLEAN_SPELLINGS:
            return _MISP_BOOLEAN_SPELLINGS[attributes.pop(relation)]
        # A value the bag cannot carry either is warned of there, once
        if self._lexical_form(value) is not None:
            self._unrecognised_boolean_warning(
                relation, value, self._object_features(misp_object)
            )
        return None

    @staticmethod
    def _create_registry_key_object(regkey: str) -> WinRegistryKey:
        registry_key = WinRegistryKey()
        registry_key.key = regkey.strip()
        registry_key.key.condition = "Equals"
        return registry_key

    @staticmethod
    def _create_related_coa(coa_id: str, category: str,
                            timestamp: Optional[datetime] = None) -> RelatedCOA:
        coa = CourseOfAction(idref=coa_id)
        if timestamp is not None:
            coa.timestamp = timestamp
        related_coa = RelatedCOA(coa, relationship=category)
        return related_coa

    @staticmethod
    def _create_related_ttp(ttp_id: str, category: str,
                            timestamp: Optional[datetime] = None) -> RelatedTTP:
        rttp = TTP(idref=ttp_id)
        if timestamp is not None:
            rttp.timestamp = timestamp
        related_ttp = RelatedTTP(rttp, relationship=category)
        return related_ttp

    def _create_socket_address_object(
            self, hostname: Optional[str] = None, ip: Optional[tuple] = None,
            port: Optional[str] = None) -> SocketAddress:
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
        threat_actor.id_ = f"{self._orgname_id}:ThreatActor-{cluster['uuid']}"
        threat_actor.title = cluster['value']
        if cluster.get('description'):
            threat_actor.description = cluster['description']
        if cluster.get('meta', {}).get('cfr-type-of-incident') is not None:
            intended_effect = cluster['meta']['cfr-type-of-incident']
            if isinstance(intended_effect, list):
                for effect in intended_effect:
                    threat_actor.add_intended_effect(effect)
            else:
                threat_actor.add_intended_effect(intended_effect)
        return threat_actor

    def _create_ttp(self, attribute: dict) -> TTP:
        ttp = TTP(timestamp=self._optional_timestamp(attribute))
        ttp.id_ = f"{self._orgname_id}:TTP-{attribute['uuid']}"
        if attribute.get('Tag'):
            tags = tuple(tag['name'] for tag in attribute['Tag'])
            ttp.handling = self._set_handling(tags)
        ttp.title = f"{attribute.get('category', 'Other')}: {attribute['value']} (MISP Attribute)"
        return ttp

    def _create_ttp_from_galaxy(self, galaxy_name: str, uuid: str) -> TTP:
        ttp = TTP()
        ttp.id_ = f'{self._orgname_id}:TTP-{uuid}'
        ttp.title = f'{galaxy_name} (MISP Galaxy)'
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

    @staticmethod
    def _fetch_colors(tags: list) -> tuple:
        return (':'.join(tag.split(':')[1:]) for tag in tags)

    def _set_color(self, colors: list) -> str:
        tlp_color = 0
        for color in colors:
            color_num = self._mapping.TLP_order(color) or 0
            if color_num > tlp_color:
                tlp_color = color_num
                color_value = color.upper()
        return color_value

    @staticmethod
    def _set_group_list(
        account_object: Union[UnixUserAccount, WinUser], groups: list,
        group_list_class: Union[UnixGroupList, WinGroupList],
        group_class: Union[UnixGroup, WinGroup], feature: str):
        group_list = group_list_class()
        for grp in groups:
            group = group_class()
            setattr(group, feature, grp)
            group_list.append(group)
        account_object.group_list = group_list

    def _set_handling(self, tags: list) -> Marking:
        sorted_tags = defaultdict(list)
        for tag in tags:
            feature = 'tlp_tags' if self._is_tlp_tag(tag) else 'simple_tags'
            sorted_tags[feature].append(tag)
        return self._create_handling(sorted_tags)

    def _set_indicator_type(self, attribute_type: str) -> str:
        return self._mapping.misp_indicator_type(attribute_type) or 'Malware Artifacts'

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

    def _create_handling(self, sorted_tags: dict) -> Marking:
        handling = Marking()
        marking_specification = MarkingSpecification()
        if 'tlp_tags' in sorted_tags:
            tlp_marking = TLPMarkingStructure()
            tlp_marking.color = self._set_color(self._fetch_colors(sorted_tags['tlp_tags']))
            marking_specification.marking_structures.append(tlp_marking)
        if 'simple_tags' in sorted_tags:
            for tag in sorted_tags['simple_tags']:
                simple_marking = SimpleMarkingStructure()
                simple_marking.statement = tag
                marking_specification.marking_structures.append(simple_marking)
        handling.add_marking(marking_specification)
        return handling

    @staticmethod
    def _datetime_to_str(timestamp):
        return datetime.strftime(timestamp, "%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def _with_galaxy_tags(tag_names: Iterable[str], galaxies: Iterable[dict]) -> tuple:
        """The tags a STIX 1 record carries: its own, then the tag of every
        galaxy cluster attached to it the record does not already carry.

        A STIX 1 construct names a cluster by its value alone, and a galaxy no
        construct holds is written nowhere else: the tag is what brings the
        cluster back, type included, mapped or not. MISP gives a record the tag
        of every cluster it carries already, so the tags of a MISP event are
        written as they are - a cluster's own tag name first, since a custom
        galaxy's differs from the one its type and value would build.

        :param tag_names: the tag names of the record, in their order
        :param galaxies: the galaxies attached to the record
        :return: the tag names, the cluster ones missing appended
        """
        tag_names = list(tag_names)
        for galaxy in galaxies:
            for cluster in galaxy['GalaxyCluster']:
                tag_name = cluster.get('tag_name') or (
                    f'misp-galaxy:{galaxy["type"]}="{cluster["value"]}"'
                )
                if tag_name not in tag_names:
                    tag_names.append(tag_name)
        return tuple(tag_names)

    def _warn_plain_observable_galaxies(self, attributes: Iterable[dict],
                                        record: str):
        """Warn about every galaxy cluster on a record exported without
        `to_ids`: the plain Observable it is written as has no handling for
        the cluster tags to go on, and the clusters are written as no
        construct either, so nothing in the document says they were there.

        :param attributes: the attribute, or the attributes of the object
        :param record: the record, as the warning names it
        """
        galaxies = (
            galaxy for attribute in attributes
            for galaxy in attribute.get('Galaxy', ())
        )
        for tag_name in self._with_galaxy_tags((), galaxies):
            self._plain_observable_galaxy_warning(tag_name, record)

    def _is_tlp_tag(self, tag: str) -> bool:
        if not tag.startswith('tlp:'):
            return False
        return tag.startswith('tlp:') and self._mapping.TLP_order(':'.join(tag.split(':')[1:])) is not None

    def _lexical_form(self, value: Any) -> Optional[tuple]:
        """The form a MISP value takes on the wire and the CybOX `datatype`
        naming it - `None` for that datatype where the form is a string XSD
        needs no name for, and `None` for the pair where the value has no
        form at all."""
        if isinstance(value, str):
            return None, value
        if isinstance(value, datetime):
            # No datatype: the documents this form ships in predate it
            return None, self._datetime_to_str(value)
        if isinstance(value, bool):
            return 'boolean', 'true' if value else 'false'
        if isinstance(value, int):
            # `counter` and `port` included: CybOX names neither, and an
            # integer type is what a consumer can act on
            return self._integer_datatype(value), str(value)
        if isinstance(value, float):
            if isnan(value):
                return 'float', 'NaN'
            if isinf(value):
                return 'float', 'INF' if value > 0 else '-INF'
            return 'float', str(value)
        return None

    @staticmethod
    def _integer_datatype(value: int) -> str:
        # XSD bounds the names it gives: `int` is 32-bit and `long` 64-bit,
        # so a value outside them would declare a type it does not satisfy
        if -2 ** 31 <= value < 2 ** 31:
            return 'int'
        if -2 ** 63 <= value < 2 ** 63:
            return 'long'
        return 'integer'

    def _sort_tags(self, tags: list) -> Tuple[dict, dict]:
        sorted_tags = defaultdict(list)
        confidence_tags = {}
        for tag in tags:
            confidence = self._mapping.confidence_mapping(tag)
            if confidence is not None:
                confidence_tags[confidence['score']] = confidence['stix_value']
                sorted_tags['simple_tags'].append(tag)
            else:
                feature = 'tlp_tags' if self._is_tlp_tag(tag) else 'simple_tags'
                sorted_tags[feature].append(tag)
        return sorted_tags, confidence_tags


class MISPtoSTIX1AttributesParser(MISPtoSTIX1Parser):
    def __init__(self, orgname: str, version: str):
        super().__init__(orgname, version)
        self._producer = self._create_information_source(orgname)
        self._set_identifier('attributes collection')
        self._ids = set()

    def _parse_json_content(self, attributes: dict | list):
        if isinstance(attributes, dict) and attributes.get('response') is not None:
            attributes = attributes['response']
        if isinstance(attributes, dict) and 'Attribute' in attributes:
            attributes = attributes['Attribute']
        if not isinstance(attributes, list):
            raise InvalidMISPInputError(
                'Input does not look like a MISP attributes collection.'
            )
        for index, attribute in enumerate(attributes):
            if not (isinstance(attribute, dict) and 'type' in attribute):
                raise InvalidMISPInputError(
                    'Input does not look like a MISP attributes collection: '
                    f'item {index} is not a MISP attribute.'
                )
        self._stix_package = _create_stix_package(
            self._orgname, self._version
        )
        for attribute in attributes:
            self._resolve_attribute(attribute)

    ################################################################################
    #                         ATTRIBUTES PARSING FUNCTIONS                         #
    ################################################################################

    def _handle_attribute(self, attribute: dict, observable: Observable):
        if attribute.get('to_ids', False):
            indicator = self._handle_attribute_indicator(attribute, observable)
            self._stix_package.add_indicator(indicator)
        else:
            self._add_record_comment(observable, attribute)
            self._warn_plain_observable_galaxies(
                (attribute,), self._attribute_record(attribute)
            )
            self._stix_package.add_observable(observable)

    def _handle_target_attribute(self, attribute: dict, identity_spec: STIXCIQIdentity3_0):
        identity = self._create_ciq_identity_instance(attribute, identity_spec)
        ttp = self._create_ttp(attribute)
        victim_targeting = VictimTargeting()
        victim_targeting.identity = identity
        ttp.victim_targeting = victim_targeting
        tags = self._handle_non_indicator_attribute_tags_and_galaxies(attribute, ttp)
        if tags:
            ttp.handling = self._set_handling(tags)
        self._stix_package.add_ttp(ttp)

    def _handle_test_mechanism(self, attribute: dict, test_mechanism: Union[SnortTestMechanism, YaraTestMechanism]):
        indicator = self._create_indicator_from_attribute(attribute)
        indicator.add_test_mechanism(test_mechanism)
        self._stix_package.add_indicator(indicator)

    def _parse_target_machine(self, attribute: dict):
        # No Incident to hold an Affected_Asset: the machine falls back to the
        # Custom observable, like every type with no native slot on this parser
        self._parse_custom_attribute(attribute)

    def _parse_undefined_attribute(self, attribute: dict):
        # No Incident to hold a journal entry, no STIX Header to describe:
        # the Custom observable keeps the value, uuid, comment and tags alike
        self._parse_custom_attribute(attribute)

    ################################################################################
    #                          GALAXIES PARSING FUNCTIONS                          #
    ################################################################################
    def _parse_threat_actor_galaxy(self, galaxy: dict):
        for cluster in galaxy['GalaxyCluster']:
            self._parse_threat_actor(cluster)


class MISPtoSTIX1EventsParser(MISPtoSTIX1Parser):
    def __init__(self, orgname: str, version: str):
        super().__init__(orgname, version)

    def _parse_json_content(self, json_content: dict):
        if not isinstance(json_content, dict):
            raise InvalidMISPInputError('Input does not look like a MISP event.')
        if json_content.get('response') is not None:
            events = json_content['response']
            if not isinstance(events, list):
                raise InvalidMISPInputError(
                    'Input does not look like a MISP events collection.'
                )
            for index, event in enumerate(events):
                if not (isinstance(event, dict)
                        and ('Event' in event or 'info' in event)):
                    raise InvalidMISPInputError(
                        'Input does not look like a MISP events collection: '
                        f'item {index} is not a MISP event.'
                    )
            package = _create_stix_package(
                self._orgname, self._version, header=False
            )
            for event in events:
                self.parse_misp_event(event)
                package.add_related_package(self._stix_package)
            self._stix_package = package
        elif 'Event' in json_content or 'info' in json_content:
            self.parse_misp_event(json_content)
        else:
            raise InvalidMISPInputError('Input does not look like a MISP event.')

    def parse_misp_event(self, misp_event: dict):
        self._header_description_attributes = []
        self._objects_to_parse = defaultdict(dict)
        self._contextualised_data = set()
        self._ids = set()
        self._ttp_references = {}
        self._written_cybox_objects = {}
        self._folding_references = set()
        self._course_of_action_slots = {}
        self._written_indicators = {}
        self._written_courses_of_action = {}
        self._written_object_ttps = {}
        if 'Event' in misp_event:
            misp_event = misp_event['Event']
        self._misp_event = misp_event
        self._set_identifier(self._misp_event['uuid'])
        producer = self._set_producer()
        self._producer = self._create_information_source(producer)
        self._stix_package = self._create_stix_package()
        self._incident = self._create_incident()
        self._generate_stix_objects()
        self._write_object_references()
        # The header holds one description: with more than one attribute
        # meant for it, each goes to the journal like the others of its type
        if len(self._header_description_attributes) > 1:
            for attribute in self._header_description_attributes:
                self._add_attribute_journal_entry(attribute)
        self._stix_package.add_incident(self._incident)
        stix_header = STIXHeader()
        stix_header.title = f"Export from {producer}'s MISP"
        stix_header.package_intents = "Threat Report"
        if len(self._header_description_attributes) == 1:
            stix_header.description = self._header_description_attributes[0]['value']
        self._stix_package.stix_header = stix_header

    ################################################################################
    #                         INCIDENT HANDLING FUNCTIONS.                         #
    ################################################################################

    def _create_incident(self) -> Incident:
        incident_args = {
            'id_': f"{self._orgname_id}:Incident-{self._misp_event['uuid']}",
            'title': self._misp_event['info']
        }
        if self._misp_event.get('timestamp'):
            incident_args['timestamp'] = self._datetime_from_timestamp(
                self._misp_event['timestamp']
            )
        incident = Incident(**incident_args)
        incident_time = Time()
        if self._misp_event.get('date'):
            incident_time.incident_discovery = self._handle_date_value()
        if self._is_published():
            incident_time.incident_reported = self._datetime_from_timestamp(self._misp_event['publish_timestamp'])
        incident.time = incident_time
        if self._misp_event.get('id'):
            external_id = ExternalID(value=self._misp_event['id'], source='MISP Event')
            incident.add_external_id(external_id)
        if self._misp_event.get('analysis'):
            status = self._mapping.status_mapping(self._misp_event['analysis'])
            incident.status = IncidentStatus(status)
        source = self._set_information_source()
        incident.information_source = self._create_information_source(source)
        incident.reporter = self._producer
        return incident

    def _handle_event_tags_and_galaxies(self) -> tuple:
        galaxies = self._misp_event.get('Galaxy', [])
        for galaxy in galaxies:
            to_call = self._mapping.galaxy_types_mapping(galaxy['type'])
            if to_call is not None:
                getattr(self, to_call.format('event'))(galaxy)
            else:
                self._handle_undefined_event_galaxy(galaxy)
        return self._with_galaxy_tags(
            (tag['name'] for tag in self._misp_event.get('Tag', [])), galaxies
        )

    def _generate_stix_objects(self):
        tags = self._handle_event_tags_and_galaxies()
        if tags:
            sorted_tags, confidence_tags = self._sort_tags(tags)
            if confidence_tags:
                self._incident.confidence = Confidence(
                    value = confidence_tags[min(confidence_tags)],
                    timestamp = self._incident.timestamp
                )
            self._incident.handling = self._create_handling(sorted_tags)
        if self._misp_event.get('threat_level_id'):
            threat_level = self._mapping.threat_level_mapping(self._misp_event['threat_level_id'])
            self._add_journal_entry(f'Event Threat Level: {threat_level}')
        self._add_journal_entry('MISP Tag: misp:tool="MISP-STIX-Converter"')
        if self._misp_event.get('Attribute'):
            for attribute in self._misp_event['Attribute']:
                self._resolve_attribute(attribute)
        if self._misp_event.get('Object'):
            self._resolve_objects()

    ################################################################################
    #                         ATTRIBUTES PARSING FUNCTIONS                         #
    ################################################################################

    def _handle_attribute(self, attribute: dict, observable: Observable):
        category = attribute.get('category', 'Other')
        if attribute.get('to_ids', False):
            indicator = self._handle_attribute_indicator(attribute, observable)
            related_indicator = RelatedIndicator(
                indicator,
                relationship=category
            )
            self._incident.related_indicators.append(related_indicator)
        else:
            self._add_record_comment(observable, attribute)
            self._warn_plain_observable_galaxies(
                (attribute,), self._attribute_record(attribute)
            )
            related_observable = RelatedObservable(
                observable,
                relationship=category
            )
            self._incident.related_observables.append(related_observable)
        self._written_cybox_objects[attribute['uuid']] = observable.object_

    def _handle_target_attribute(self, attribute: dict, identity_spec: STIXCIQIdentity3_0):
        ciq_identity = self._create_ciq_identity_instance(attribute, identity_spec)
        self._incident.add_victim(ciq_identity)

    def _handle_test_mechanism(self, attribute: dict, test_mechanism: Union[SnortTestMechanism, YaraTestMechanism]):
        indicator = self._create_indicator_from_attribute(attribute)
        indicator.add_test_mechanism(test_mechanism)
        related_indicator = RelatedIndicator(indicator, relationship=attribute.get('category', 'Other'))
        self._incident.related_indicators.append(related_indicator)

    ################################################################################
    #                        MISP OBJECTS PARSING FUNCTIONS                        #
    ################################################################################

    def _resolve_objects(self):
        for misp_object in self._misp_event['Object']:
            object_name = misp_object['name']
            if self._check_object_name(misp_object):
                continue
            try:
                to_call = self._mapping.non_indicator_names(object_name)
                if to_call is not None:
                    getattr(self, to_call)(misp_object)
                else:
                    to_ids = self._fetch_ids_flag(misp_object['Attribute'])
                    to_call = self._mapping.objects_mapping(object_name) or '_parse_custom_object'
                    observable = getattr(self, to_call)(misp_object)
                    # None where the parser refused the object and said why
                    if observable is not None:
                        self._handle_object_observable(
                            misp_object, observable, to_ids
                        )
            except Exception as exception:
                self._object_error(misp_object, exception)
        if self._objects_to_parse:
            if self._objects_to_parse.get('file'):
                for misp_object in self._objects_to_parse.pop('file').values():
                    try:
                        attributes, observable = self._parse_file_with_pe_object(misp_object)
                        record = self._folded_record(misp_object, attributes)
                        if self._fetch_ids_flag(attributes):
                            self._handle_misp_object_with_context(record, observable)
                        else:
                            self._handle_misp_object(record, observable)
                    except Exception as exception:
                        self._object_error(misp_object, exception)
            if self._objects_to_parse.get('pe'):
                for misp_object in self._objects_to_parse.pop('pe').values():
                    try:
                        file_object = WinExecutableFile()
                        attributes = self._parse_pe_object(file_object, misp_object)
                        observable = self._create_observable(file_object, misp_object['uuid'], 'WindowsExecutableFile')
                        record = self._folded_record(misp_object, attributes)
                        if self._fetch_ids_flag(attributes):
                            self._handle_misp_object_with_context(record, observable)
                        else:
                            self._handle_misp_object(record, observable)
                    except Exception as exception:
                        self._object_error(misp_object, exception)
            if self._objects_to_parse.get('pe-section'):
                # No `pe` references these, or the `pe` failed: no executable
                # to fold them into. The template is mapped under a `pe`, so
                # the `Custom` Observable comes with no "not mapped" warning
                for misp_object in self._objects_to_parse.pop('pe-section').values():
                    try:
                        to_ids = self._fetch_ids_flag(misp_object['Attribute'])
                        observable = self._create_custom_observable(misp_object)
                        self._handle_object_observable(misp_object, observable, to_ids)
                    except Exception as exception:
                        self._object_error(misp_object, exception)

    @staticmethod
    def _folded_record(misp_object: dict, attributes: list) -> dict:
        """The record a `file` or a lone `pe` is written as, once the objects
        it references are folded into its CybOX object: the object itself,
        holding the attributes of every object folded in. Its `to_ids`, the
        markings written for it and the warnings about those it cannot carry
        are those of all of them, not of the `file` or the `pe` alone. A
        section written standalone is not folded in and counts for none.

        :param misp_object: the `file` or the lone `pe`
        :param attributes: its attributes and those of the objects folded in
        :return: the object, holding the attributes given
        """
        return {**misp_object, 'Attribute': attributes}

    def _write_object_references(self):
        """Write the references of the MISP objects, once every record is
        written: a source may come before its target.

        A reference between two objects written as TTPs is a Related_TTP. One
        from an object written as a single CybOX Object to a record written as
        one too is a Related_Object on the source's Object, pointing at the
        target's. One a Related_Object cannot carry goes in the relationship
        slot of the source's own construct naming the target's kind, where
        there is one. A `pe` folded into its `file` and a section folded into
        its `pe` take their reference with them. Every other reference has no
        slot of the source's own to go in, or points at nothing the document
        holds: it is named in a Warning.
        """
        written = self._write_related_ttps()
        for misp_object in self._misp_event.get('Object', []):
            source = self._written_cybox_objects.get(misp_object['uuid'])
            for reference in misp_object.get('ObjectReference', []):
                pair = (misp_object['uuid'], reference['referenced_uuid'])
                if pair in written or pair in self._folding_references:
                    continue
                target = self._written_cybox_objects.get(
                    reference['referenced_uuid']
                )
                if source is None or target is None:
                    if self._write_slot_reference(
                            misp_object['uuid'], reference['referenced_uuid'],
                            reference['relationship_type']):
                        continue
                    self._unwritten_object_reference_warning(
                        self._object_features(misp_object),
                        reference['relationship_type'],
                        self._referenced_record(reference['referenced_uuid'])
                    )
                    continue
                source.related_objects.append(
                    RelatedObject(
                        idref=target.id_,
                        relationship=self._object_relationship(
                            reference['relationship_type']
                        )
                    )
                )

    def _write_slot_reference(self, source_uuid: str, target_uuid: str,
                              relationship: str) -> bool:
        """Write a reference in the relationship slot of the source's own
        construct naming the target's kind, the relationship verbatim: one to
        a `course-of-action` object in the Potential_COAs of the Exploit
        Target of a `vulnerability` or `weakness`, the Related_COAs of a
        Course of Action or the Suggested_COAs of an Indicator; one from an
        Indicator to an `attack-pattern`, `vulnerability` or `weakness` object
        in its Indicated_TTP. The galaxy clusters fill the same slots.

        :param source_uuid: the uuid of the object making the reference
        :param target_uuid: the uuid of the record it references
        :param relationship: the relationship of the reference
        :return: whether the source's construct has a slot for the target
        """
        course_of_action = self._written_courses_of_action.get(target_uuid)
        if course_of_action is not None:
            slot = self._course_of_action_slots.get(source_uuid)
            if slot is None:
                return False
            slot.append(
                self._create_related_coa(
                    course_of_action.id_, relationship,
                    timestamp=course_of_action.timestamp
                )
            )
            return True
        ttp = self._written_object_ttps.get(target_uuid)
        indicator = self._written_indicators.get(source_uuid)
        if ttp is None or indicator is None:
            return False
        indicator.add_indicated_ttp(
            self._create_related_ttp(
                ttp.id_, relationship, timestamp=ttp.timestamp
            )
        )
        return True

    def _write_related_ttps(self) -> set:
        """Add a Related_TTP to the TTP of an object written as one for each
        reference it makes to another record written as a TTP.

        :return: the source and target uuids of each reference written
        """
        written = set()
        if self._stix_package.ttps is None:
            return written
        for ttp in self._stix_package.ttps.ttp:
            uuid = '-'.join(ttp.id_.split('-')[-5:])
            for referenced_uuid, relationship in self._ttp_references.get(uuid, ()):
                if referenced_uuid in self._contextualised_data:
                    referenced_id = f'{self._orgname_id}:TTP-{referenced_uuid}'
                    related_ttp = self._create_related_ttp(
                        referenced_id, relationship,
                        timestamp=self._quick_fetch_ttp_timestamp(referenced_id)
                    )
                    ttp.add_related_ttp(related_ttp)
                    written.add((uuid, referenced_uuid))
        return written

    def _referenced_record(self, uuid: str) -> str:
        # How a Warning names the target of a reference: the record of the
        # event holding the uuid, where there is one
        for attribute in self._misp_event.get('Attribute', []):
            if attribute['uuid'] == uuid:
                return self._attribute_record(attribute)
        for misp_object in self._misp_event.get('Object', []):
            if misp_object['uuid'] == uuid:
                return self._object_features(misp_object)
        return f'record (uuid: {uuid})'

    @staticmethod
    def _object_relationship(relationship: str) -> Union[str, VocabString]:
        # A relationship the CybOX vocabulary has a term for is written as
        # the term, any other verbatim as free text
        term = _OBJECT_RELATIONSHIP_TERMS.get(
            relationship.lower().replace('_', '-')
        )
        return VocabString(relationship) if term is None else term

    def _handle_object_observable(self, misp_object: dict,
                                  observable: Observable, to_ids: bool):
        """Add the Observable a MISP object was exported as to the package:
        wrapped in an Indicator when an attribute of the object is `to_ids`,
        related to the Incident as it is otherwise.

        :param misp_object: the MISP object
        :param observable: the Observable it was exported as
        :param to_ids: whether any attribute of the object is `to_ids`
        """
        if to_ids:
            self._handle_misp_object_with_context(misp_object, observable)
        else:
            if misp_object['name'] in _TITLED_OBSERVABLE_OBJECT_NAMES:
                observable.title = self._object_record_title(misp_object)
            self._handle_misp_object(misp_object, observable)

    def _write_custom_object(self, misp_object: dict):
        """The object error fallback: the object a mapped route failed on
        goes out the way an unmapped one does, a `Custom` Observable carrying
        its relations - with no warning its template is not mapped, the error
        already says why the object is in this shape.

        :param misp_object: the MISP object the export failed on
        """
        try:
            self._handle_object_observable(
                misp_object, self._create_custom_observable(misp_object),
                self._fetch_ids_flag(misp_object['Attribute'])
            )
        except Exception:
            # The Observable is written the way the failed route writes its
            # own, from the same object fields: what failed there - an object
            # timestamp the Indicator cannot parse - fails here again, with
            # nothing left to catch it. The object is lost, and the error
            # already says so
            return

    def _add_custom_property(self, stix_object: File, name: str, value: Any,
                             misp_object: dict):
        if stix_object.custom_properties is None:
            stix_object.custom_properties = CustomProperties()
        self._append_property(
            stix_object.custom_properties, name, value,
            self._object_features(misp_object)
        )

    def _check_object_name(self, misp_object: dict) -> bool:
        object_name = misp_object['name']
        if object_name == 'original-imported-file':
            return True
        if object_name in ('pe', 'pe-section'):
            self._objects_to_parse[object_name][misp_object['uuid']] = misp_object
            return True
        if object_name == 'file' and misp_object.get('ObjectReference'):
            for reference in misp_object['ObjectReference']:
                if self._is_reference_included(reference, 'pe'):
                    self._objects_to_parse[object_name][misp_object['uuid']] = misp_object
                    return True
        return False

    def _check_reference(self, source_uuid: str, reference: dict,
                         object_name: str) -> bool:
        if self._is_reference_included(reference, object_name):
            if reference['referenced_uuid'] not in self._objects_to_parse[object_name]:
                self._referenced_object_name_warning(object_name, reference['referenced_uuid'])
                # Warned about here: the reference is the folding's own
                self._folding_references.add(
                    (source_uuid, reference['referenced_uuid'])
                )
                return False
            return True
        return False

    @staticmethod
    def _extract_file_attributes(attributes: list) -> tuple:
        """Extract the values of a `file` object by relation, a relation
        whose native field holds one value taking its first value alone.

        :param attributes: the attributes of the `file` object
        :return: the values by relation, and the further values of each
            relation holding one; a value carrying data is a tuple of the
            value, the data and the attribute uuid
        """
        attributes_dict = defaultdict(list)
        repeated = defaultdict(list)
        for attribute in attributes:
            value = attribute['value']
            relation = attribute['object_relation']
            if relation not in _FILE_SINGLE_ATTRIBUTES:
                attributes_dict[relation].append(value)
                continue
            if attribute.get('data'):
                value = (value, attribute['data'], attribute['uuid'])
            if relation in attributes_dict:
                repeated[relation].append(value)
            else:
                attributes_dict[relation] = value
        return attributes_dict, repeated

    @staticmethod
    def _extract_single_field_attributes(attributes: list,
                                         force_single: tuple) -> tuple:
        """Extract the values of a MISP object by relation, a relation whose
        native field holds one value taking its first value alone.

        :param attributes: the attributes of the MISP object
        :param force_single: the relations a native field holds one value of
        :return: the values by relation, and the further values of each
            relation forced single, which the field has no room for
        """
        attributes_dict = defaultdict(list)
        repeated = defaultdict(list)
        for attribute in attributes:
            relation = attribute['object_relation']
            if relation not in force_single:
                attributes_dict[relation].append(attribute['value'])
            elif relation in attributes_dict:
                repeated[relation].append(attribute['value'])
            else:
                attributes_dict[relation] = attribute['value']
        return attributes_dict, repeated

    def _add_repeated_values(self, stix_object: Any, repeated: dict,
                             misp_object: dict):
        """Write the values a native field holding one had no room for to
        the property bag, under their relation.

        :param stix_object: the CybOX object carrying the bag
        :param repeated: the further values, by relation
        :param misp_object: the MISP object they belong to
        """
        for relation, values in repeated.items():
            for value in values:
                self._add_custom_property(
                    stix_object, relation, value, misp_object
                )

    def _pop_canonical_integers(self, attributes: dict, relation: str,
                                record: str) -> list:
        """Take the values of a relation a native CybOX unsigned integer
        field holds unchanged, leaving the others where the property bag
        takes them.

        :param attributes: the values of the object, by relation
        :param relation: the relation the native field holds
        :param record: the MISP object the values belong to, as warnings
            name it
        :return: the canonical values
        """
        canonical, others = [], []
        for value in attributes.pop(relation, ()):
            if self._canonical_integer(value, relation, record):
                canonical.append(value)
            else:
                others.append(value)
        if others:
            attributes[relation] = others
        return canonical

    @staticmethod
    def _pop_first_value(attributes: dict, relation: str) -> Any:
        """Take the first value of a relation for a native field holding one,
        leaving the others where the property bag takes them.

        :param attributes: the values of the object, by relation
        :param relation: the relation the native field holds
        :return: the first value
        """
        first, *others = attributes.pop(relation)
        if others:
            attributes[relation] = others
        return first

    def _handle_custom_properties(self, attributes: dict, misp_object: dict,
                                  multiple: Optional[bool] = True) -> CustomProperties:
        custom_properties = CustomProperties()
        record = self._object_features(misp_object)
        if not multiple:
            for object_relation, value in attributes.items():
                self._append_property(
                    custom_properties, object_relation, value, record
                )
            return custom_properties
        for object_relation, values in attributes.items():
            # A relation its parser forced single is a scalar here, not a
            # list: iterating it spreads a string over one property per
            # character, and a boolean is not iterable at all
            if not isinstance(values, list):
                values = [values]
            for value in values:
                self._append_property(
                    custom_properties, object_relation, value, record
                )
        return custom_properties

    def _warn_unwritable_relations(self, misp_object: dict, written: tuple):
        """Warn of each relation of a MISP object the STIX type it is written
        as has no field for, and no property bag either.

        :param misp_object: the MISP object
        :param written: the relations the STIX type has room for
        """
        record = self._object_features(misp_object)
        for attribute in misp_object['Attribute']:
            if attribute['object_relation'] not in written:
                self._unwritable_relation_warning(
                    attribute['object_relation'], attribute['value'], record
                )

    def _handle_misp_object(self, misp_object: dict, observable: Observable):
        self._add_record_comment(observable, misp_object)
        self._warn_plain_observable_galaxies(
            misp_object['Attribute'], self._object_features(misp_object)
        )
        related_observable = RelatedObservable(
            observable,
            relationship=misp_object.get('meta-category')
        )
        self._incident.related_observables.append(related_observable)
        self._written_cybox_objects[misp_object['uuid']] = observable.object_

    def _handle_misp_object_with_context(self, misp_object: dict, observable: Observable):
        indicator = self._create_indicator_from_object(misp_object)
        indicator.add_observable(observable)
        related_indicator = RelatedIndicator(
            indicator,
            relationship=misp_object.get('meta-category')
        )
        self._incident.related_indicators.append(related_indicator)
        self._written_cybox_objects[misp_object['uuid']] = observable.object_
        self._written_indicators[misp_object['uuid']] = indicator
        self._course_of_action_slots[misp_object['uuid']] = indicator.suggested_coas

    def _handle_non_indicator_object_tags_and_galaxies(self, misp_object: dict, stix_object: _NON_INDICATOR_OBJECT_TYPES, galaxy_name: str) -> tuple:
        tags, galaxies = self._extract_object_attribute_tags_and_galaxies(misp_object)
        for galaxy_type, galaxy in galaxies.items():
            if galaxy_type in getattr(self._mapping, galaxy_name)():
                to_call = self._mapping.galaxy_types_mapping(galaxy_type)
                getattr(self, to_call.format('object'))(galaxy, stix_object)
            else:
                self._object_galaxy_incompatible_warning(
                    galaxy_type,
                    misp_object['name']
                )
        return self._with_galaxy_tags(tags, galaxies.values())

    def _handle_object_indicator_tags(self, misp_object: dict, indicator: Indicator, timestamp: datetime) -> Confidence:
        tags = self._handle_object_tags_and_galaxies(misp_object, indicator)
        if tags:
            sorted_tags, confidence_tags = self._sort_tags(tags)
            indicator.handling = self._create_handling(sorted_tags)
            if confidence_tags:
                return Confidence(
                    value = confidence_tags[min(confidence_tags)],
                    timestamp = timestamp
                )
        return Confidence(
            value=self._mapping.confidence_value(),
            description=self._mapping.confidence_description(),
            timestamp=timestamp
        )

    def _handle_object_tags_and_galaxies(self, misp_object: dict, indicator: Indicator) -> tuple:
        tags, galaxies = self._extract_object_attribute_tags_and_galaxies(misp_object)
        for galaxy_type, galaxy in galaxies.items():
            to_call = self._mapping.galaxy_types_mapping(galaxy_type)
            if to_call is not None:
                getattr(self, to_call.format('attribute'))(galaxy, indicator)
            else:
                self._object_galaxy_not_mapped_warning(
                    galaxy_type,
                    misp_object['name']
                )
        return self._with_galaxy_tags(tags, galaxies.values())

    def _handle_ttp_from_object(self, misp_object: dict, ttp: TTP):
        tags = self._handle_non_indicator_object_tags_and_galaxies(misp_object, ttp, 'ttp_names')
        if tags:
            ttp.handling = self._set_handling(tags)
        related_ttp = self._create_related_ttp(
            ttp.id_,
            misp_object['name'],
            timestamp=self._optional_timestamp(misp_object)
        )
        self._incident.add_leveraged_ttps(related_ttp)
        self._contextualised_data.add(misp_object['uuid'])
        self._stix_package.add_ttp(ttp)
        self._written_object_ttps[misp_object['uuid']] = ttp

    def _parse_asn_object(self, misp_object: dict) -> Optional[Observable]:
        attributes, repeated = self._extract_single_field_attributes(
            misp_object['Attribute'], self._mapping.as_single_fields()
        )
        if 'asn' not in attributes:
            # The template requires it, and the CybOX `AS` is its number: an
            # object without one has nowhere to go
            self._required_relation_missing_error(misp_object, 'asn')
            return None
        asn = attributes['asn']
        if self._is_as_handle(asn) or self._canonical_integer(
                asn, 'asn', self._object_features(misp_object)):
            as_object = self._create_autonomous_system_object(
                attributes.pop('asn')
            )
        else:
            as_object = AutonomousSystem()
        if attributes.get('description'):
            as_object.name = attributes.pop('description')
        if attributes:
            as_object.custom_properties = self._handle_custom_properties(attributes, misp_object)
        self._add_repeated_values(as_object, repeated, misp_object)
        observable = self._create_observable(as_object, misp_object['uuid'], 'AS')
        return observable

    def _parse_attack_pattern_object(self, misp_object: dict):
        ttp = self._create_ttp_from_object(misp_object)
        self._add_record_comment(ttp, misp_object)
        attack_pattern = AttackPattern()
        attack_pattern.id_ = f"{self._orgname_id}:AttackPattern-{misp_object['uuid']}"
        attributes = self._extract_object_attributes(misp_object['Attribute'])
        mapping = self._mapping.attack_pattern_object_mapping()
        for key, feature in mapping.items():
            if attributes.get(key):
                setattr(attack_pattern, feature, attributes.pop(key))
        if attack_pattern.capec_id and not attack_pattern.capec_id.startswith('CAPEC'):
            attack_pattern.capec_id = f'CAPEC-{attack_pattern.capec_id}'
        # The summary is the one untagged description: every other free text
        # relation is a description of its own, tagged with the relation, and
        # a related weakness is the Exploit Target the TTP has room for
        described = self._mapping.attack_pattern_description_relations()
        for attribute in misp_object['Attribute']:
            relation = attribute['object_relation']
            if relation in described:
                description = StructuredText(attribute['value'])
                description.structuring_format = relation
                attack_pattern.add_description(description)
            elif relation == 'related-weakness':
                ttp.add_exploit_target(
                    self._create_related_weakness(attribute, misp_object)
                )
        self._warn_unwritable_relations(
            misp_object, (*mapping, *described, 'related-weakness')
        )
        if misp_object.get('ObjectReference'):
            references = tuple((reference['referenced_uuid'], reference['relationship_type']) for reference in misp_object['ObjectReference'])
            self._ttp_references[misp_object['uuid']] = references
        behavior = Behavior()
        behavior.add_attack_pattern(attack_pattern)
        ttp.behavior = behavior
        self._handle_ttp_from_object(misp_object, ttp)

    def _parse_course_of_action_object(self, misp_object: dict):
        course_of_action = CourseOfAction(
            timestamp=self._optional_timestamp(misp_object)
        )
        uuid = misp_object['uuid']
        course_of_action.id_ = f'{self._orgname_id}:CourseOfAction-{uuid}'
        attributes = self._extract_object_attributes(misp_object['Attribute'])
        mapping = self._mapping.course_of_action_object_mapping()
        for key, feature in mapping.items():
            if attributes.get(key):
                setattr(course_of_action, feature, attributes.pop(key))
        self._warn_unwritable_relations(misp_object, tuple(mapping))
        tags = self._handle_non_indicator_object_tags_and_galaxies(
            misp_object,
            course_of_action,
            'course_of_action_types'
        )
        if tags:
            course_of_action.handling = self._set_handling(tags)
        coa_taken = self._create_coa_taken(
            course_of_action.id_,
            timestamp=self._optional_timestamp(misp_object)
        )
        self._incident.add_coa_taken(coa_taken)
        self._stix_package.add_course_of_action(course_of_action)
        self._written_courses_of_action[uuid] = course_of_action
        self._course_of_action_slots[uuid] = course_of_action.related_coas

    def _parse_credential_authentication(self, attributes: dict) -> list:
        args = {}
        if attributes.get('format'):
            struct_auth_meca = StructuredAuthenticationMechanism()
            struct_auth_meca.description = self._pop_first_value(attributes, 'format')
            args['auth_format'] = struct_auth_meca
        if attributes.get('type'):
            args['auth_type'] = self._pop_first_value(attributes, 'type')
        authentication_list = []
        if attributes.get('password'):
            for password in attributes.pop('password'):
                authentication = self._create_authentication_object(password=password, **args)
                authentication_list.append(authentication)
            return authentication_list
        if args:
            return [self._create_authentication_object(**args)]
        return []

    def _parse_credential_object(self, misp_object: dict) -> Observable:
        attributes, repeated = self._extract_single_field_attributes(
            misp_object['Attribute'], tuple(self._mapping.credential_object_mapping().keys())
        )
        account_object = UserAccount()
        for feature, field in self._mapping.credential_object_mapping().items():
            if attributes.get(feature):
                setattr(account_object, field, attributes.pop(feature))
        authentication_list = self._parse_credential_authentication(attributes)
        if authentication_list:
            account_object.authentication = authentication_list
        if attributes:
            account_object.custom_properties = self._handle_custom_properties(attributes, misp_object)
        self._add_repeated_values(account_object, repeated, misp_object)
        observable = self._create_observable(account_object, misp_object['uuid'], 'UserAccount')
        return observable

    def _parse_custom_object(self, misp_object: dict) -> Observable:
        observable = self._create_custom_observable(misp_object)
        self._object_not_mapped_warning(misp_object['name'])
        return observable

    def _create_custom_observable(self, misp_object: dict) -> Observable:
        custom_object = Custom()
        custom_object.custom_name = misp_object['name']
        if misp_object.get('description'):
            custom_object.description = misp_object['description']
        custom_object.custom_properties = CustomProperties()
        record = self._object_features(misp_object)
        for attribute in misp_object['Attribute']:
            self._append_property(
                custom_object.custom_properties,
                attribute['object_relation'], attribute['value'], record
            )
        return self._create_observable(custom_object, misp_object['uuid'], 'Custom')

    def _parse_domain_ip_object(self, misp_object: dict) -> Observable:
        attributes = self._extract_multiple_object_attributes_with_uuid(misp_object['Attribute'])
        observables = []
        if attributes.get('domain'):
            for attribute in attributes['domain']:
                observables.append(self._create_domain_observable(*attribute))
        if attributes.get('ip'):
            for attribute in attributes['ip']:
                observables.append(self._create_address_observable('ip-dst', *attribute))
        if attributes.get('port'):
            observables.extend(
                self._create_port_members(
                    misp_object, 'port', attributes['port']
                )
            )
        if attributes.get('hostname'):
            for attribute in attributes['hostname']:
                observables.append(self._create_hostname_observable(*attribute))
        observables.extend(
            self._create_custom_members(
                misp_object, ('domain', 'ip', 'port', 'hostname')
            )
        )
        observable_composition = self._create_observable_composition(
            observables,
            misp_object['uuid'],
            name=misp_object['name'].replace('|', '-')
        )
        return observable_composition

    def _parse_email_object(self, misp_object: dict) -> Observable:
        attributes = self._extract_multiple_object_attributes_with_uuid(
            misp_object['Attribute'],
            with_uuid=self._mapping.email_uuid_fields()
        )
        email_object = EmailMessage()
        email_header = EmailHeader()
        for feature in ('to', 'cc', 'bcc'):
            if attributes.get(feature):
                recipients = EmailRecipients()
                for value in attributes.pop(feature):
                    recipients.append(value)
                setattr(email_header, feature, recipients)
        for feature, key in self._mapping.email_object_mapping().items():
            if attributes.get(feature):
                setattr(email_header, key, self._pop_first_value(attributes, feature))
                setattr(getattr(email_header, key), 'condition', 'Equals')
        email_object.header = email_header
        if attributes.get('attachment'):
            email_object.attachments = Attachments()
            for attachment in attributes.pop('attachment'):
                filename, uuid = attachment
                file = self._create_file_object(filename)
                file.parent.id_ = f"{self._orgname_id}:FileObject-{uuid}"
                related_file = RelatedObject(
                    relationship='Contains',
                    inline=True,
                    id_=file.parent.id_,
                    properties=file
                )
                email_object.parent.related_objects.append(related_file)
                email_object.attachments.append(related_file.id_)
        if attributes:
            email_object.custom_properties = self._handle_custom_properties(attributes, misp_object)
        observable = self._create_observable(email_object, misp_object['uuid'], 'EmailMessage')
        return observable

    def _parse_file_attributes(self, attributes: dict, misp_object: dict,
                               file_object: Union[File, WinExecutableFile]):
        if attributes.get('filename'):
            filename = self._select_single_feature(attributes, 'filename')
            file_object.file_name = filename
            file_object.file_name.condition = 'Equals'
        record = self._object_features(misp_object)
        numbers = {
            'entropy': self._canonical_float,
            'size-in-bytes': self._canonical_integer
        }
        for feature, key in self._mapping.file_object_mapping().items():
            if not attributes.get(feature):
                continue
            canonical = numbers.get(feature)
            if canonical is not None and not canonical(
                    attributes[feature], feature, record):
                # One value, the relation is single: a list for the bag loop
                # below, which spreads a string over one property per
                # character
                attributes[feature] = [attributes[feature]]
                continue
            value = attributes[feature].pop(0) if isinstance(attributes[feature], list) else attributes.pop(feature)
            setattr(file_object, key, value)
            setattr(getattr(file_object, key), 'condition', 'Equals')
        if attributes:
            for object_relation, value in attributes.items():
                if object_relation in self._mapping.hash_type_attributes('single'):
                    # A hash relation the `file` template has not, such as
                    # `pehash`, holds a list of values
                    values = value if isinstance(value, list) else [value]
                    for hash_value in values:
                        file_object.add_hash(
                            self._parse_hash_value(object_relation, hash_value)
                        )
                else:
                    for single_value in value:
                        self._add_custom_property(
                            file_object, object_relation, single_value,
                            misp_object
                        )

    def _parse_file_object(self, misp_object: dict) -> Observable:
        attributes, repeated = self._extract_file_attributes(
            misp_object['Attribute']
        )
        observables = self._parse_file_observables(attributes, repeated)
        file_object = File()
        self._parse_file_attributes(attributes, misp_object, file_object)
        self._add_repeated_values(file_object, repeated, misp_object)
        file_observable = self._create_observable(file_object, misp_object['uuid'], 'File')
        if observables:
            observables.append(file_observable)
            observable_composition = self._create_observable_composition(
                observables,
                misp_object['uuid'],
                name=misp_object['name']
            )
            return observable_composition
        return file_observable

    def _parse_file_observables(self, attributes: dict,
                                repeated: dict) -> list:
        """Write every `malware-sample` and `attachment` value carrying
        data as an Artifact of its own, the others staying where the
        property bag takes them.

        :param attributes: the values of the `file` object, by relation
        :param repeated: the further values of its relations holding one
        :return: the Artifact Observables, members of the file composition
        """
        observables = []
        for relation, create_observable in (
                ('malware-sample', self._create_malware_sample_observable),
                ('attachment', self._create_attachment_observable)):
            if isinstance(attributes.get(relation), tuple):
                observables.append(create_observable(*attributes.pop(relation)))
            elif attributes.get(relation):
                attributes[relation] = [attributes[relation]]
            values = []
            for value in repeated.pop(relation, ()):
                if isinstance(value, tuple):
                    observables.append(create_observable(*value))
                else:
                    values.append(value)
            if values:
                repeated[relation] = values
        return observables

    def _parse_file_with_pe_object(self, misp_object: dict) -> tuple:
        folded = list(misp_object['Attribute'])
        attributes, repeated = self._extract_file_attributes(
            misp_object['Attribute']
        )
        observables = self._parse_file_observables(attributes, repeated)
        file_object = WinExecutableFile()
        self._parse_file_attributes(attributes, misp_object, file_object)
        self._add_repeated_values(file_object, repeated, misp_object)
        for reference in misp_object['ObjectReference']:
            if self._check_reference(misp_object['uuid'], reference, 'pe'):
                misp_pe = self._objects_to_parse['pe'].pop(reference['referenced_uuid'])
                try:
                    folded.extend(self._parse_pe_object(file_object, misp_pe))
                    self._folding_references.add(
                        (misp_object['uuid'], misp_pe['uuid'])
                    )
                except Exception as exception:
                    self._object_error(misp_pe, exception)
                break
        file_observable = self._create_observable(file_object, misp_object['uuid'], 'WindowsExecutableFile')
        if observables:
            observables.append(file_observable)
            observable_composition = self._create_observable_composition(
                observables,
                misp_object['uuid'],
                name=misp_object['name']
            )
            return folded, observable_composition
        return folded, file_observable

    def _parse_ip_port_object(self, misp_object: dict) -> Observable:
        attributes = self._extract_multiple_object_attributes_with_uuid(misp_object['Attribute'])
        observables = []
        for feature in ('ip-src', 'ip-dst'):
            if attributes.get(feature):
                for attribute in attributes[feature]:
                    observables.append(self._create_address_observable(feature, *attribute))
        if attributes.get('ip'):
            for attribute in attributes['ip']:
                observables.append(self._create_address_observable('ip-dst', *attribute))
        for feature in ('src-port', 'dst-port'):
            if attributes.get(feature):
                observables.extend(
                    self._create_port_members(
                        misp_object, feature, attributes[feature],
                        feature=feature.split('-')[0]
                    )
                )
        if attributes.get('domain'):
            for attribute in attributes['domain']:
                observables.append(self._create_domain_observable(*attribute))
        if attributes.get('hostname'):
            for attribute in attributes['hostname']:
                observables.append(self._create_hostname_observable(*attribute))
        observables.extend(
            self._create_custom_members(
                misp_object,
                ('ip-src', 'ip-dst', 'ip', 'src-port', 'dst-port', 'domain',
                 'hostname')
            )
        )
        observable_composition = self._create_observable_composition(
            observables,
            misp_object['uuid'],
            name=misp_object['name'].replace('|', '-')
        )
        return observable_composition

    def _parse_mutex_object(self, misp_object: dict) -> Observable:
        attributes = self._extract_object_attributes(misp_object['Attribute'])
        mutex_object = Mutex()
        if attributes.get('name'):
            mutex_object.name = attributes.pop('name')
        if attributes:
            mutex_object.custom_properties = self._handle_custom_properties(
                attributes, misp_object, multiple=False
            )
        observable = self._create_observable(
            mutex_object,
            misp_object['uuid'],
            'Mutex'
        )
        return observable

    def _parse_network_connection_object(self, misp_object: dict) -> Observable:
        attributes = self._extract_object_attributes(misp_object['Attribute'])
        connection_object = NetworkConnection()
        self._parse_socket_addresses(
            connection_object,
            attributes,
            ('source_socket', 'destination_socket'),
            misp_object
        )
        for feature in ('layer3-protocol', 'layer4-protocol', 'layer7-protocol'):
            if attributes.get(feature):
                field = feature.replace('-', '_')
                setattr(connection_object, field, attributes.pop(feature))
                setattr(getattr(connection_object, field), 'condition', 'Equals')
        if attributes:
            connection_object.custom_properties = self._handle_custom_properties(attributes, misp_object)
        observable = self._create_observable(
            connection_object,
            misp_object['uuid'],
            'NetworkConnection'
        )
        return observable

    def _parse_network_socket_object(self, misp_object: dict) -> Observable:
        attributes, repeated = self._extract_single_field_attributes(
            misp_object['Attribute'], self._mapping.network_socket_single_fields()
        )
        socket_object = NetworkSocket()
        self._parse_socket_addresses(
            socket_object, attributes, ('local', 'remote'), misp_object
        )
        for key, feature in self._mapping.network_socket_mapping().items():
            if attributes.get(key):
                setattr(socket_object, feature, attributes.pop(key))
                setattr(getattr(socket_object, feature), 'condition', 'Equals')
        if attributes.get('state'):
            states = attributes.pop('state')
            socket_object.is_listening = True if 'listening' in states else False
            socket_object.is_blocking = True if 'blocking' in states else False
            # CybOX names two states, as booleans: any other goes to the bag
            others = [
                state for state in states
                if state not in ('listening', 'blocking')
            ]
            if others:
                attributes['state'] = others
        if attributes:
            socket_object.custom_properties = self._handle_custom_properties(attributes, misp_object)
        self._add_repeated_values(socket_object, repeated, misp_object)
        observable = self._create_observable(socket_object, misp_object['uuid'], 'NetworkSocket')
        return observable

    def _parse_pe_object(self, file_object: WinExecutableFile,
                         misp_pe: dict) -> list:
        folded = list(misp_pe['Attribute'])
        attributes, repeated = self._extract_single_field_attributes(
            misp_pe['Attribute'], self._mapping.pe_single_fields()
        )
        if any(feature in attributes for feature in self._mapping.pe_resource_mapping()):
            resource = PEVersionInfoResource()
            for key, feature in self._mapping.pe_resource_mapping().items():
                if attributes.get(key):
                    setattr(resource, feature, attributes.pop(key))
                    setattr(getattr(resource, feature), 'condition', 'Equals')
            resource_list = PEResourceList()
            resource_list.append(resource)
            file_object.resources = resource_list
        # Out of the way of the headers, which have nothing to hold for it
        bagged = None
        if attributes.get('number-sections') and not self._canonical_integer(
                attributes['number-sections'], 'number-sections',
                self._object_features(misp_pe)):
            bagged = attributes.pop('number-sections')
        headers_fields = ('entrypoint-address', 'impfuzzy', 'imphash', 'number-sections', 'pehash')
        if any(feature in attributes for feature in headers_fields):
            pe_headers = PEHeaders()
            if attributes.get('entrypoint-address'):
                optional_header = PEOptionalHeader()
                optional_header.address_of_entry_point = attributes.pop('entrypoint-address')
                optional_header.address_of_entry_point.condition = 'Equals'
                pe_headers.optional_header = optional_header
            if attributes.get('number-sections'):
                file_header = PEFileHeader()
                file_header.number_of_sections = attributes.pop('number-sections')
                file_header.number_of_sections.condition = 'Equals'
                pe_headers.file_header = file_header
            file_object.headers = pe_headers
        if attributes.get('type'):
            file_object.type_ = attributes.pop('type')
            file_object.type_.condition = 'Equals'
        if bagged is not None:
            # A list for the bag loop below, which spreads a string over one
            # property per character
            attributes['number-sections'] = [bagged]
        if attributes:
            hashes = []
            for object_relation, value in attributes.items():
                if object_relation in self._mapping.hash_type_attributes('single'):
                    hashes.append(self._parse_hash_value(object_relation, value))
                else:
                    for single_value in value:
                        self._add_custom_property(
                            file_object, object_relation, single_value, misp_pe
                        )
            if hashes:
                # The gate above creates the headers for five relations and
                # the file header for one of them, so a `pe` carrying a header
                # hash and no `number-sections` had nowhere to write the hash
                # list to - no file header, and no headers at all for an
                # `authentihash` or an `impfuzzy` alone. Created here, where
                # the hashes are, the object no longer costs a document.
                if file_object.headers is None:
                    file_object.headers = PEHeaders()
                if file_object.headers.file_header is None:
                    file_object.headers.file_header = PEFileHeader()
                hashlist = HashList()
                hashlist.hashes = hashes
                file_object.headers.file_header.hashes = hashlist
        self._add_repeated_values(file_object, repeated, misp_pe)
        if misp_pe.get('ObjectReference'):
            for reference in misp_pe['ObjectReference']:
                if self._check_reference(misp_pe['uuid'], reference, 'pe-section'):
                    misp_pe_section = self._objects_to_parse['pe-section'].pop(reference['referenced_uuid'])
                    try:
                        pe_section = self._parse_pe_section_object(misp_pe_section)
                        if pe_section is None:
                            # A section has no property bag: one with a value
                            # its fields would rewrite goes out standalone, as
                            # the object error fallback writes it
                            self._write_custom_object(misp_pe_section)
                        else:
                            self._append_pe_section(file_object, pe_section)
                            self._folding_references.add(
                                (misp_pe['uuid'], misp_pe_section['uuid'])
                            )
                            # Only a folded section counts: one written
                            # standalone carries its own markings and its
                            # own `to_ids`
                            folded.extend(misp_pe_section['Attribute'])
                    except Exception as exception:
                        self._object_error(misp_pe_section, exception)
        return folded

    @staticmethod
    def _append_pe_section(file_object: WinExecutableFile,
                           pe_section: PESection):
        try:
            file_object.sections.append(pe_section)
        except AttributeError:
            file_object.sections = PESectionList()
            file_object.sections.append(pe_section)

    def _parse_pe_section_object(
            self, misp_pe_section: dict) -> Optional[PESection]:
        section_attributes = self._extract_object_attributes(misp_pe_section['Attribute'])
        if section_attributes.get('entropy') and not self._canonical_float(
                section_attributes['entropy'], 'entropy',
                self._object_features(misp_pe_section)):
            return None
        pe_section = PESection()
        if section_attributes.get('entropy'):
            pe_section.entropy = Entropy()
            pe_section.entropy.value = section_attributes.pop('entropy')
        if any(feature in section_attributes for feature in ('name', 'size-in-bytes')):
            pe_section.section_header = PESectionHeaderStruct()
            if section_attributes.get('name'):
                pe_section.section_header.name = section_attributes.pop('name')
                pe_section.section_header.name.condition = 'Equals'
            if section_attributes.get('size-in-bytes'):
                pe_section.section_header.size_of_raw_data = section_attributes.pop('size-in-bytes')
                pe_section.section_header.size_of_raw_data.condition = 'Equals'
        hashlist = []
        for key, value in section_attributes.items():
            if key in self._mapping.hash_type_attributes('single'):
                hashlist.append(self._parse_hash_value(key, value))
        if hashlist:
            pe_section.data_hashes = HashList()
            pe_section.data_hashes.hashes = hashlist
        self._warn_unwritable_relations(
            misp_pe_section,
            ('entropy', 'name', 'size-in-bytes',
             *self._mapping.hash_type_attributes('single'))
        )
        return pe_section

    def _parse_process_object(self, misp_object: dict) -> Observable:
        attributes, repeated = self._extract_single_field_attributes(
            misp_object['Attribute'], self._mapping.process_single_fields()
        )
        process_object = Process()
        record = self._object_features(misp_object)
        for key, feature in self._mapping.process_object_mapping().items():
            if not attributes.get(key):
                continue
            # cybox takes a pid as an integer, the template as text: a value
            # the field would not write back stays for the bag to carry
            if key in ('pid', 'parent-pid') and not self._canonical_integer(
                    attributes[key], key, record):
                continue
            setattr(process_object, feature, attributes.pop(key))
            setattr(getattr(process_object, feature), 'condition', 'Equals')
        children = self._pop_canonical_integers(attributes, 'child-pid', record)
        if children:
            process_object.child_pid_list = ChildPIDList()
            for child in children:
                process_object.child_pid_list.append(child)
        ports = self._pop_canonical_integers(attributes, 'port', record)
        if ports:
            process_object.port_list = PortList()
            for port in ports:
                port_object = self._create_port_object(port)
                process_object.port_list.append(port_object)
        image_info_keys = ('image', 'command-line')
        if any(key in attributes for key in image_info_keys):
            process_object.image_info = ImageInfo()
            for key, feature in zip(image_info_keys, ('file_name', 'command_line')):
                if attributes.get(key):
                    setattr(process_object.image_info, feature, attributes.pop(key))
                    setattr(getattr(process_object.image_info, feature), 'condition', 'Equals')
        hidden = self._native_boolean(attributes, 'hidden', misp_object)
        if hidden is not None:
            process_object.is_hidden = hidden
        if attributes:
            process_object.custom_properties = self._handle_custom_properties(attributes, misp_object)
        self._add_repeated_values(process_object, repeated, misp_object)
        observable = self._create_observable(process_object, misp_object['uuid'], 'Process')
        return observable

    def _parse_registry_key_object(self, misp_object: dict) -> Observable:
        attributes = self._extract_object_attributes(misp_object['Attribute'])
        registry_object = self._create_registry_key_object(attributes.pop('key')) if attributes.get('key') else WinRegistryKey()
        if attributes.get('hive'):
            # A hive in the CybOX enumeration is spelled its way; any other -
            # a file on disk, as the template has it - goes out verbatim
            hive = attributes.pop('hive')
            registry_object.hive = self._mapping.misp_reghive(
                hive.lstrip('\\').upper()
            ) or hive
            registry_object.hive.condition = 'Equals'
        if any(key in attributes for key in self._mapping.regkey_object_mapping().keys()):
            value_object = RegistryValue()
            for key, feature in self._mapping.regkey_object_mapping().items():
                if attributes.get(key):
                    setattr(value_object, feature, attributes.pop(key))
                    setattr(getattr(value_object, feature), 'condition', 'Equals')
            registry_object.values = RegistryValues(value_object)
        if attributes.get('last-modified'):
            registry_object.modified_time = attributes.pop('last-modified')
            registry_object.modified_time.condition = 'Equals'
        if attributes:
            registry_object.custom_properties = self._handle_custom_properties(
                attributes,
                misp_object,
                multiple=False
            )
        observable = self._create_observable(
            registry_object,
            misp_object['uuid'],
            'WindowsRegistryKey'
        )
        return observable

    def _parse_socket_addresses(self, stix_object: Union[NetworkConnection, NetworkSocket], attributes: dict,
                                fields: tuple, misp_object: dict):
        record = self._object_features(misp_object)
        for key, field in zip(('src', 'dst'), fields):
            args = {}
            if attributes.get(f'ip-{key}'):
                attribute_type = f'ip-{key}'
                args['ip'] = (attribute_type, attributes.pop(attribute_type))
            if attributes.get(f'hostname-{key}'):
                args['hostname'] = attributes.pop(f'hostname-{key}')
            relation = f'{key}-port'
            if attributes.get(relation) and self._canonical_integer(
                    attributes[relation], relation, record):
                args['port'] = attributes.pop(relation)
            if args:
                setattr(
                    stix_object,
                    f'{field}_address',
                    self._create_socket_address_object(**args)
                )

    def _parse_url_object(self, misp_object: dict) -> Observable:
        attributes = self._extract_multiple_object_attributes_with_uuid(misp_object['Attribute'])
        observables = []
        for attribute in attributes.get('url', ()):
            observables.append(self._create_uri_observable(*attribute))
        for attribute in attributes.get('domain', ()):
            observables.append(self._create_domain_observable(*attribute))
        for attribute in attributes.get('host', ()):
            observables.append(self._create_hostname_observable(*attribute))
        for attribute in attributes.get('ip', ()):
            observables.append(self._create_address_observable('ip-dst', *attribute))
        observables.extend(
            self._create_port_members(
                misp_object, 'port', attributes.get('port', ())
            )
        )
        observables.extend(
            self._create_custom_members(
                misp_object, ('url', 'domain', 'host', 'ip', 'port')
            )
        )
        observable_composition = self._create_observable_composition(
            observables,
            misp_object['uuid'],
            name=misp_object['name']
        )
        return observable_composition

    def _parse_user_account_object(self, misp_object: dict) -> Observable:
        attributes, repeated = self._extract_single_field_attributes(
            misp_object['Attribute'], self._mapping.user_account_single_fields()
        )
        account_object = self._create_user_account_object(
            attributes, misp_object
        )
        if attributes.get('password'):
            account_object.authentication = self._create_authentication_object(
                auth_type='password',
                password=attributes.pop('password')
            )
        for key, feature in self._mapping.user_account_object_mapping().items():
            if attributes.get(key):
                setattr(account_object, feature, attributes.pop(key))
                setattr(getattr(account_object, feature), 'condition', 'Equals')
        disabled = self._native_boolean(attributes, 'disabled', misp_object)
        if disabled is not None:
            account_object.disabled = disabled
        if attributes:
            account_object.custom_properties = self._handle_custom_properties(attributes, misp_object)
        self._add_repeated_values(account_object, repeated, misp_object)
        observable = self._create_observable(
            account_object,
            misp_object['uuid'],
            account_object._XSI_TYPE.split('ObjectType')[0]
        )
        return observable

    def _parse_vulnerability_object(self, misp_object: dict):
        ttp = self._create_ttp_from_object(misp_object)
        vulnerability = Vulnerability()
        attributes, repeated = self._extract_single_field_attributes(
            misp_object['Attribute'], self._mapping.vulnerability_single_fields()
        )
        if attributes.get('id'):
            vulnerability.cve_id = attributes.pop('id')
        if attributes.get('cvss-score'):
            cvss = CVSSVector()
            cvss.overall_score = attributes.pop('cvss-score')
            vulnerability.cvss_score = cvss
        for key, feature in self._mapping.vulnerability_object_mapping().items():
            if attributes.get(key):
                setattr(vulnerability, feature, attributes.pop(key))
                setattr(getattr(vulnerability, feature), 'condition', 'Equals')
        if attributes.get('references'):
            for reference in attributes.pop('references'):
                vulnerability.add_reference(reference)
        self._warn_unwritable_relations(
            misp_object,
            ('id', 'cvss-score', 'references',
             *self._mapping.vulnerability_object_mapping())
        )
        record = self._object_features(misp_object)
        for relation, values in repeated.items():
            for value in values:
                if relation == 'summary':
                    # One more description, as the attack pattern writes
                    # every free text relation it has
                    vulnerability.add_description(value)
                else:
                    self._unwritable_relation_warning(relation, value, record)
        if misp_object.get('ObjectReference'):
            references = tuple((reference['referenced_uuid'], reference['relationship_type']) for reference in misp_object['ObjectReference'])
            self._ttp_references[misp_object['uuid']] = references
        exploit_target = ExploitTarget(timestamp=self._optional_timestamp(misp_object))
        exploit_target.id_ = f"{self._orgname_id}:ExploitTarget-{misp_object['uuid']}"
        self._add_record_comment(exploit_target, misp_object)
        exploit_target.add_vulnerability(vulnerability)
        ttp.add_exploit_target(exploit_target)
        self._handle_ttp_from_object(misp_object, ttp)
        self._course_of_action_slots[misp_object['uuid']] = (
            exploit_target.potential_coas
        )

    def _parse_weakness_object(self, misp_object: dict):
        ttp = self._create_ttp_from_object(misp_object)
        weakness = Weakness()
        attributes = self._extract_object_attributes(misp_object['Attribute'])
        mapping = self._mapping.weakness_object_mapping()
        for key, feature in mapping.items():
            if attributes.get(key):
                setattr(weakness, feature, attributes.pop(key))
        self._warn_unwritable_relations(misp_object, tuple(mapping))
        if misp_object.get('ObjectReference'):
            references = tuple((reference['referenced_uuid'], reference['relationship_type']) for reference in misp_object['ObjectReference'])
            self._ttp_references[misp_object['uuid']] = references
        exploit_target = ExploitTarget(timestamp=self._optional_timestamp(misp_object))
        exploit_target.id_ = f"{self._orgname_id}:ExploitTarget-{misp_object['uuid']}"
        self._add_record_comment(exploit_target, misp_object)
        exploit_target.add_weakness(weakness)
        ttp.add_exploit_target(exploit_target)
        self._handle_ttp_from_object(misp_object, ttp)
        self._course_of_action_slots[misp_object['uuid']] = (
            exploit_target.potential_coas
        )

    def _parse_whois_object(self, misp_object: dict) -> Observable:
        attributes, repeated = self._extract_single_field_attributes(
            misp_object['Attribute'], self._mapping.whois_single_fields()
        )
        whois_object = WhoisEntry()
        if attributes.get('registrar'):
            whois_registrar = WhoisRegistrar()
            whois_registrar.name = attributes.pop('registrar')
            whois_object.registrar_info = whois_registrar
        if any(key.startswith('registrant-') for key in attributes.keys()):
            registrants = WhoisRegistrants()
            registrant = WhoisRegistrant()
            for key, feature in self._mapping.whois_registrant_object_mapping().items():
                if attributes.get(key):
                    setattr(registrant, feature, attributes.pop(key))
                    setattr(getattr(registrant, feature), 'condition', 'Equals')
            registrants.append(registrant)
            whois_object.registrants = registrants
        for key, feature in self._mapping.whois_object_mapping().items():
            if attributes.get(key):
                value = attributes.pop(key)
                if isinstance(value, datetime):
                    value = value.date()
                setattr(whois_object, feature, value)
                setattr(getattr(whois_object, feature), 'condition', 'Equals')
        if attributes.get('nameserver'):
            nameservers = WhoisNameservers()
            for nameserver in attributes.pop('nameserver'):
                nameservers.append(URI(value=nameserver))
            whois_object.nameservers = nameservers
        if attributes.get('domain'):
            domain_name = self._select_single_feature(attributes, 'domain')
            whois_object.domain_name = URI(value=domain_name)
        if attributes.get('ip-address'):
            ip_address = self._select_single_feature(attributes, 'ip-address')
            whois_object.ip_address = Address(address_value=ip_address)
        if attributes.get('comment'):
            whois_object.remarks = attributes.pop('comment')
        elif attributes.get('text'):
            whois_object.remarks = attributes.pop('text')
        if attributes:
            whois_object.custom_properties = self._handle_custom_properties(attributes, misp_object)
        self._add_repeated_values(whois_object, repeated, misp_object)
        observable = self._create_observable(whois_object, misp_object['uuid'], 'Whois')
        return observable

    def _parse_x509_object(self, misp_object: dict) -> Observable:
        attributes = defaultdict(list)
        content = defaultdict(bool)
        # The two integers are signed: a negative one is written natively
        bagged = defaultdict(list)
        record = self._object_features(misp_object)
        for attribute in misp_object['Attribute']:
            relation = attribute['object_relation']
            feature = self._mapping.x509_creation_mapping(relation)
            if feature is not None:
                if relation in ('version', 'pubkey-info-exponent'):
                    if not self._canonical_integer(
                            attribute['value'], relation, record,
                            signed=True):
                        bagged[relation].append(attribute['value'])
                        continue
                attributes[relation] = attribute['value']
                content[feature] = True
            else:
                attributes[relation].append(attribute['value'])
        x509_object = X509Certificate()
        if any(content[feature] for feature in ('certificate', 'validity', 'pubkey')):
            x509_cert = X509Cert()
            if content['certificate']:
                for key, feature in self._mapping.x509_object_mapping().items():
                    if attributes.get(key):
                        setattr(x509_cert, feature, attributes.pop(key))
                        setattr(getattr(x509_cert, feature), 'condition', 'Equals')
            if content['validity']:
                validity = Validity()
                for key in ('before', 'after'):
                    if attributes.get(f'validity-not-{key}'):
                        value = attributes.pop(f'validity-not-{key}')
                        setattr(validity, f'not_{key}', self._datetime_from_str(value))
                        setattr(getattr(validity, f'not_{key}'), 'condition', 'Equals')
                x509_cert.validity = validity
            if content['pubkey']:
                pubkey = SubjectPublicKey()
                if attributes.get('pubkey-info-algorithm'):
                    pubkey.public_key_algorithm = attributes.pop('pubkey-info-algorithm')
                    pubkey.public_key_algorithm.condition = 'Equals'
                pubkey_keys = ('exponent', 'modulus')
                if any(f'pubkey-info-{key}' in attributes for key in pubkey_keys):
                    rsa_pubkey = RSAPublicKey()
                    for key in pubkey_keys:
                        if attributes.get(f'pubkey-info-{key}'):
                            setattr(rsa_pubkey, key, attributes.pop(f'pubkey-info-{key}'))
                            setattr(getattr(rsa_pubkey, key), 'condition', 'Equals')
                    pubkey.rsa_public_key = rsa_pubkey
                x509_cert.subject_public_key = pubkey
            x509_object.certificate = x509_cert
        if content['raw_certificate']:
            if 'pem' in attributes:
                x509_object.raw_certificate = attributes.pop('pem')
                if attributes.get('raw-base64'):
                    attributes['raw-base64'] = [attributes.pop('raw-base64')]
            elif attributes.get('raw-base64'):
                x509_object.raw_certificate = attributes.pop('raw-base64')
            x509_object.raw_certificate.condition = 'Equals'
        if content['signature']:
            signature = X509CertificateSignature()
            signature_set = False
            for algo in ('sha256', 'sha1', 'md5'):
                key = f'x509-fingerprint-{algo}'
                if signature_set:
                    if attributes.get(key):
                        attributes[key] = [attributes.pop(key)]
                    continue
                if attributes.get(key):
                    signature.signature_algorithm = algo.upper()
                    signature.signature_algorithm.condition = 'Equals'
                    signature.signature = attributes.pop(key)
                    signature.signature.condition = 'Equals'
                    signature_set = True
            x509_object.certificate_signature = signature
        attributes.update(bagged)
        if attributes:
            x509_object.custom_properties = self._handle_custom_properties(attributes, misp_object)
        observable = self._create_observable(x509_object, misp_object['uuid'], 'X509Certificate')
        return observable

    ################################################################################
    #                          GALAXIES PARSING FUNCTIONS                          #
    ################################################################################

    def _handle_undefined_event_galaxy(self, galaxy: dict):
        self._event_galaxy_not_mapped_warning(galaxy['type'])

    def _handle_undefined_parent_galaxy(self, galaxy: dict):
        self._parent_galaxy_not_mapping_warning(galaxy['type'])

    def _parse_attack_pattern_event_galaxy(self, galaxy: dict):
        galaxy_name = galaxy['name']
        for cluster in galaxy['GalaxyCluster']:
            ttp_id = self._parse_ttp(cluster, 'attack_pattern', galaxy_name)
            if cluster['uuid'] not in self._contextualised_data:
                related_ttp = self._create_related_ttp(ttp_id, galaxy_name)
                self._incident.add_leveraged_ttps(related_ttp)
                self._contextualised_data.add(cluster['uuid'])

    def _parse_course_of_action_event_galaxy(self, galaxy: dict):
        for cluster in galaxy['GalaxyCluster']:
            coa_id = self._parse_course_of_action_galaxy(cluster)
            if cluster['uuid'] not in self._contextualised_data:
                coa_taken = self._create_coa_taken(coa_id)
                self._incident.add_coa_taken(coa_taken)
                self._contextualised_data.add(cluster['uuid'])

    def _parse_malware_event_galaxy(self, galaxy: dict):
        galaxy_name = galaxy['name']
        for cluster in galaxy['GalaxyCluster']:
            ttp_id = self._parse_ttp(cluster, 'malware', galaxy_name)
            if cluster['uuid'] not in self._contextualised_data:
                related_ttp = self._create_related_ttp(ttp_id, galaxy_name)
                self._incident.add_leveraged_ttps(related_ttp)
                self._contextualised_data.add(cluster['uuid'])

    def _parse_threat_actor_event_galaxy(self, galaxy: dict):
        self._parse_threat_actor_galaxy(galaxy)

    def _parse_threat_actor_galaxy(self, galaxy: dict):
        for cluster in galaxy['GalaxyCluster']:
            threat_actor_id = self._parse_threat_actor(cluster)
            if cluster['uuid'] not in self._contextualised_data:
                related_threat_actor = self._create_related_threat_actor(
                    threat_actor_id,
                    galaxy['name']
                )
                try:
                    self._incident.attributed_threat_actors.append(related_threat_actor)
                except AttributeError:
                    self._incident.attributed_threat_actors = AttributedThreatActors()
                    self._incident.attributed_threat_actors.append(related_threat_actor)
                self._contextualised_data.add(cluster['uuid'])

    def _parse_tool_event_galaxy(self, galaxy: dict):
        galaxy_name = galaxy['name']
        for cluster in galaxy['GalaxyCluster']:
            ttp_id = self._parse_ttp(cluster, 'tool', galaxy_name)
            if cluster['uuid'] not in self._contextualised_data:
                related_ttp = self._create_related_ttp(ttp_id, galaxy_name)
                self._incident.add_leveraged_ttps(related_ttp)
                self._contextualised_data.add(cluster['uuid'])

    def _parse_vulnerability_event_galaxy(self, galaxy: dict):
        galaxy_name = galaxy['name']
        for cluster in galaxy['GalaxyCluster']:
            ttp_id = self._parse_ttp(cluster, 'vulnerability', galaxy_name)
            if cluster['uuid'] not in self._contextualised_data:
                related_ttp = self._create_related_ttp(ttp_id, galaxy_name)
                self._incident.add_leveraged_ttps(related_ttp)
                self._contextualised_data.add(cluster['uuid'])

    ################################################################################
    #                    STIX OBJECTS CREATION HELPER FUNCTIONS                    #
    ################################################################################

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
    def _create_coa_taken(coa_id: str, timestamp: Optional[datetime] = None) -> COATaken:
        coa = CourseOfAction(idref=coa_id)
        if timestamp is not None:
            coa.timestamp = timestamp
        coa_taken = COATaken(coa)
        return coa_taken

    def _create_indicator_from_object(self, misp_object: dict) -> Indicator:
        timestamp = self._optional_timestamp(misp_object)
        indicator = Indicator(timestamp=timestamp)
        indicator.id_ = f"{self._orgname_id}:Indicator-{misp_object['uuid']}"
        indicator.producer = self._producer
        indicator.title = self._object_record_title(misp_object)
        if any(misp_object.get(feature) for feature in ('comment', 'description')):
            indicator.description = misp_object['comment'] if misp_object.get('comment') else misp_object['description']
        indicator.add_indicator_type(self._set_indicator_type(misp_object['name']))
        indicator.add_valid_time_position(ValidTime())
        indicator.confidence = self._handle_object_indicator_tags(misp_object, indicator, timestamp)
        return indicator

    @staticmethod
    def _object_record_title(misp_object: dict) -> str:
        return f"{misp_object.get('meta-category')}: {misp_object['name']} (MISP Object)"

    @staticmethod
    def _create_related_threat_actor(ta_id: str, category: str, timestamp: Optional[datetime] = None) -> RelatedThreatActor:
        rta = ThreatActor(idref=ta_id)
        if timestamp is not None:
            rta.timestamp = timestamp
        related_ta = RelatedThreatActor(rta, relationship=category)
        return related_ta

    def _create_stix_package(self) -> STIXPackage:
        package_args = {
            'id_': f"{self._orgname_id}:STIXPackage-{self._misp_event['uuid']}"
        }
        if self._misp_event.get('timestamp') is not None:
            package_args['timestamp'] = self._datetime_from_timestamp(
                self._misp_event['timestamp']
            )
        stix_package = STIXPackage(**package_args)
        stix_package.version = self._version
        return stix_package

    def _create_related_weakness(self, attribute: dict,
                                 misp_object: dict) -> ExploitTarget:
        exploit_target = ExploitTarget(
            timestamp=self._optional_timestamp(misp_object)
        )
        exploit_target.id_ = f"{self._orgname_id}:ExploitTarget-{attribute['uuid']}"
        weakness = Weakness()
        weakness.cwe_id = attribute['value']
        exploit_target.add_weakness(weakness)
        return exploit_target

    def _create_ttp_from_object(self, misp_object: dict) -> TTP:
        ttp = TTP(timestamp=self._optional_timestamp(misp_object))
        ttp.id_ = f"{self._orgname_id}:TTP-{misp_object['uuid']}"
        ttp.title = f"{misp_object.get('meta-category', 'misc')}: {misp_object['name']} (MISP Object)"
        return ttp

    def _create_unix_user_account_object(self, attributes: dict,
                                         misp_object: dict) -> UnixUserAccount:
        account_object = UnixUserAccount()
        record = self._object_features(misp_object)
        for relation, feature in (('user-id', 'user_id'), ('group-id', 'group_id')):
            values = self._pop_canonical_integers(attributes, relation, record)
            if values:
                setattr(account_object, feature, values.pop(0))
                setattr(getattr(account_object, feature), 'condition', 'Equals')
            if values:
                # One field: the further values go to the bag with the others
                attributes[relation] = [*values, *attributes.get(relation, ())]
        groups = self._pop_canonical_integers(attributes, 'group', record)
        if groups:
            self._set_group_list(account_object, groups, UnixGroupList, UnixGroup, 'group_id')
        return account_object

    def _create_user_account_object(self, attributes: dict, misp_object: dict) -> Union[UnixUserAccount, UserAccount, WinUser]:
        account_types = ('unix', 'windows-domain', 'windows-local')
        if 'account-type' in attributes and attributes['account-type'] in account_types:
            account_type = attributes.pop('account-type')
            if account_type == 'unix':
                return self._create_unix_user_account_object(
                    attributes, misp_object
                )
            attributes['account-type'] = [account_type]
            return self._create_windows_user_account_object(attributes)
        account_object = UserAccount()
        return account_object

    def _create_windows_user_account_object(self, attributes: dict) -> WinUser:
        account_object = WinUser()
        if attributes.get('user-id'):
            self._set_user_id(account_object, attributes, 'security_id')
        if attributes.get('group'):
            self._set_group_list(
                account_object, attributes.pop('group'), WinGroupList, WinGroup, 'name'
            )
        return account_object

    def _set_information_source(self) -> str:
        if self._misp_event.get('Org') and self._misp_event['Org'].get('name'):
            return self._misp_event['Org']['name']
        return self._orgname

    def _set_producer(self) -> str:
        if self._misp_event.get('Orgc') and self._misp_event['Orgc'].get('name'):
            return self._misp_event['Orgc']['name']
        return self._set_information_source()

    ################################################################################
    #                              UTILITY FUNCTIONS.                              #
    ################################################################################

    def _handle_date_value(self) -> datetime:
        date_value = self._misp_event['date']
        if isinstance(date_value, str):
            return datetime.strptime(date_value, '%Y-%m-%d').replace(
                tzinfo=timezone.utc
            )
        return datetime(
            date_value.year, date_value.month, date_value.day
        ).replace(tzinfo=timezone.utc)

    def _quick_fetch_ttp_timestamp(self, object_id: str) -> datetime:
        for ttp in self._stix_package.ttps.ttp:
            if ttp.id_ == object_id:
                return ttp.timestamp
