#!/usr/bin/env python
# -*- coding: utf-8 -*-

import inspect
import json
from collections import Counter
from cybox.common import Hash, HashList
from cybox.common.object_properties import CustomProperties, Property
from cybox.core import (
    Object, Observable, ObservableComposition, Observables, RelatedObject)
from cybox.objects.address_object import Address, EmailAddress
from cybox.objects.custom_object import Custom
from cybox.objects.dns_record_object import DNSRecord
from cybox.objects.domain_name_object import DomainName
from cybox.objects.email_message_object import EmailMessage
from cybox.objects.file_object import File
from cybox.objects.library_object import Library
from cybox.objects.network_connection_object import NetworkConnection
from cybox.objects.network_socket_object import NetworkSocket
from cybox.objects.port_object import Port
from cybox.objects.process_object import (
    ImageInfo, NetworkConnectionList, Process)
from cybox.objects.socket_address_object import SocketAddress
from cybox.objects.uri_object import URI
from cybox.objects.user_account_object import UserAccount
from cybox.objects.whois_object import (
    WhoisEntry, WhoisRegistrant, WhoisRegistrants, WhoisRegistrar)
from cybox.objects.win_executable_file_object import (
    Entropy, PEFileHeader, PEHeaders, PESection, PESectionHeaderStruct,
    PESectionList, WinExecutableFile)
from cybox.objects.win_registry_key_object import (
    RegistryValue, RegistryValues, WinRegistryKey)
from cybox.objects.x509_certificate_object import (
    Validity, X509Cert, X509Certificate, X509CertificateSignature)
from datetime import datetime, timezone
from misp_stix_converter import (
    MISPtoSTIX1AttributesParser, MISPtoSTIX1EventsParser,
    MissingSTIXContentError, stix_1_to_misp, STIXLoadingError)
from misp_stix_converter.abstract import _UUIDv4
from misp_stix_converter.tools import (
    is_stix1_from_misp, load_stix1_package, stix1_loading_helpers)
from misp_stix_converter.tools.misp_object_templates import (
    _template_attribute_types, _template_description)
from mixbox.namespaces import NamespaceNotFoundError
from misp_stix_converter.stix2misp import (
    external_stix1_to_misp, internal_stix1_to_misp, stix1_to_misp)
from misp_stix_converter.stix2misp.external_stix1_to_misp import (
    ExternalSTIX1toMISPParser)
from misp_stix_converter.stix2misp.internal_stix1_to_misp import (
    InternalSTIX1toMISPParser)
from misp_stix_converter.misp2stix.stix1_mapping import MISPtoSTIX1Mapping
from misp_stix_converter.stix2misp.stix1_mapping import (
    InternalSTIX1toMISPMapping, STIX1toMISPMapping)
from pymisp import MISPEvent
from pymisp.api import describe_types
from unittest.mock import ANY, patch
from uuid import UUID, uuid5
from stix.campaign import Campaign
from stix.coa import CourseOfAction, Objective
from stix.common import Statement, ToolInformation
from stix.common.related import (
    RelatedIndicator, RelatedObservable, RelatedPackage, RelatedPackages)
from stix.core import STIXHeader, STIXPackage
from stix.data_marking import Marking, MarkingSpecification
from stix.extensions.marking.simple_marking import SimpleMarkingStructure
from stix.extensions.marking.tlp import TLPMarkingStructure
from stix.extensions.test_mechanism.generic_test_mechanism import (
    GenericTestMechanism)
from stix.extensions.test_mechanism.snort_test_mechanism import (
    SnortTestMechanism)
from stix.extensions.test_mechanism.yara_test_mechanism import (
    YaraTestMechanism)
from stix.exploit_target import ExploitTarget
from stix.exploit_target.vulnerability import Vulnerability
from stix.extensions.identity.ciq_identity_3_0 import (
    CIQIdentity3_0Instance, ElectronicAddressIdentifier, PartyName,
    STIXCIQIdentity3_0)
from stix.incident import Incident
from stix.incident.affected_asset import AffectedAsset
from stix.incident.history import History, HistoryItem, JournalEntry
from stix.indicator import Indicator
from stix.threat_actor import ThreatActor
from stix.ttp import TTP, Behavior
from stix.ttp.attack_pattern import AttackPattern
from stix.ttp.infrastructure import Infrastructure
from stix.ttp.malware_instance import MalwareInstance
from stix.ttp.resource import Resource, Tools
from pathlib import Path
from tempfile import TemporaryDirectory
from ._test_stix import TestSTIX
from ._test_stix_import import (
    CLASSIFICATION_FROM_CONTENT_WARNING,
    CLASSIFICATION_OVERRIDDEN_TO_EXTERNAL_WARNING, SANITISED_TAG_VALUE,
    SMUGGLING_TAG_VALUE)
from . import test_events
from .test_events import (
    get_base_event, get_event_with_account_objects_with_attachment,
    get_event_with_asn_object,
    get_event_with_attack_pattern_galaxy, get_event_with_attack_pattern_object,
    get_event_with_campaign_name_attribute,
    get_event_with_course_of_action_galaxy,
    get_event_with_course_of_action_object, get_event_with_credential_object,
    get_event_with_domain_attribute,
    get_event_with_domain_ip_object,
    get_event_with_email_body_attribute, get_event_with_email_header_attribute,
    get_event_with_email_object, get_event_with_email_with_display_names_object,
    get_event_with_file_object, get_event_with_file_object_with_artifact,
    get_event_with_github_username_attribute,
    get_event_with_ip_port_attributes, get_event_with_ip_port_object,
    get_event_with_malware_galaxy,
    get_event_with_full_pe_object, get_event_with_file_and_pe_objects,
    get_event_with_hash_composite_attributes, get_event_with_mutex_object,
    get_event_with_pattern_attribute, get_event_with_pe_objects,
    get_event_with_process_object, get_event_with_process_object_v2,
    get_event_with_regkey_attribute, get_event_with_regkey_value_attribute,
    get_event_with_target_attributes,
    get_event_with_test_mechanism_attributes,
    get_event_with_threat_actor_galaxy, get_event_with_tool_galaxy,
    get_event_with_undefined_attributes, get_event_with_url_object,
    get_event_with_user_account_object, get_event_with_user_account_objects,
    get_event_with_vulnerability_attribute,
    get_event_with_vulnerability_galaxy, get_event_with_vulnerability_object,
    get_event_with_weakness_attribute, get_event_with_weakness_object,
    get_event_with_whois_registrar_attribute,
    get_event_with_x509_fingerprint_attributes, get_event_with_x509_object,
    get_event_with_windows_service_attributes, get_hash_attributes)

_COA_UUID = '4c1e5f2a-8b3d-4a6c-9e7f-1d2b3c4d5e6f'
_OBSERVABLE_UUID = '7a9b0c1d-2e3f-4a5b-8c9d-0e1f2a3b4c5d'
_RELATED_UUID = '1b2c3d4e-5f6a-4b8c-9d0e-1f2a3b4c5d6e'
_ACTOR_UUID = '5e6f7a8b-9c0d-4e1f-8a2b-3c4d5e6f7a8b'
_DOMAIN_UUID = '2d3e4f5a-6b7c-4d8e-9f0a-1b2c3d4e5f6a'
_IP_UUID = '3e4f5a6b-7c8d-4e9f-8a0b-1c2d3e4f5a6b'
_URL_UUID = '4f5a6b7c-8d9e-4f0a-8b1c-2d3e4f5a6b7c'
_MD5_HASH = '8a2a5fc2ce56b3b04d58539a9d3d8d3e'
_VULNERABILITY_UUID = '6c3d4e5f-7a8b-4c9d-8e0f-1a2b3c4d5e6f'
_PLAIN_OBJECT_UUID = '7d4e5f6a-8b9c-4d0e-9f1a-2b3c4d5e6f7a'
# `Type=Other` with the value in `Simple_Hash_Value`: how MISP's own STIX 1
# export wrote an ssdeep hash, cybox naming nothing better for its length
_SSDEEP_HASH = '6144:BvqbV6zoA5yJlTKCjXsJK4Tdv:BvqbV6zoA5yJlTKCjXsJK4T'
# Two rules on one Snort test mechanism: the export writes one, python-stix
# lets a mechanism carry a list
_SNORT_RULES = (
    'alert tcp any any -> any any (msg:"first")',
    'alert udp any any -> any any (msg:"second")'
)


# What a STIX 1 round trip of every MISP object fixture still loses, per
# object: its name, the object relations that do not come back, the ones that
# come back under a name the MISP object never had, and the ticket that owns
# the gap. 664 of 719 object attributes survive; the rest is the campaign's
# remaining work, and this table is where its progress is visible.
_CORPUS_ROUND_TRIP_LOSSES = {
    ('get_event_with_attack_pattern_object', 0): (
        'attack-pattern',
        ('prerequisites', 'related-weakness', 'related-weakness', 'solutions'),
        (), 'ticket 21'
    ),
    ('get_event_with_credential_object', 0): (
        'credential', ('format', 'password', 'text', 'type'), (),
        'tickets 21 and 23'
    ),
    ('get_event_with_domain_ip_object_custom', 0): (
        'domain-ip', ('hostname',), (), 'ticket 21'
    ),
    ('get_event_with_email_object', 0): (
        'email', ('bcc',), (), 'ticket 21'
    ),
    ('get_event_with_email_with_display_names_object', 0): (
        'email', ('bcc',), (), 'ticket 21'
    ),
    ('get_event_with_escaped_values_v20', 1): (
        'credential', ('text',), (), 'tickets 21 and 23'
    ),
    # `_handle_composition` reads the `src`/`dst` prefix off the Observable
    # id, where the export writes it on the CybOX object id: unticketed
    ('get_event_with_escaped_values_v20', 5): (
        'ip-port', ('dst-port',), ('port',), 'unticketed'
    ),
    ('get_event_with_escaped_values_v20', 14): (
        'user-account', ('password',), (), 'ticket 21'
    ),
    ('get_event_with_escaped_values_v21', 1): (
        'credential', ('text',), (), 'tickets 21 and 23'
    ),
    ('get_event_with_escaped_values_v21', 5): (
        'ip-port', ('dst-port',), ('port',), 'unticketed'
    ),
    ('get_event_with_escaped_values_v21', 14): (
        'user-account', ('password',), (), 'ticket 21'
    ),
    ('get_event_with_file_object', 0): (
        'file', ('creation-time', 'modification-time'), (), 'ticket 21'
    ),
    ('get_event_with_file_object_with_artifact', 0): (
        'file', ('creation-time', 'modification-time'), (), 'ticket 21'
    ),
    ('get_event_with_ip_port_object', 0): (
        'ip-port', ('dst-port', 'first-seen'), ('port',),
        'ticket 21, and unticketed for the port'
    ),
    ('get_event_with_network_socket_object', 0): (
        'network-socket', ('socket-type',), (), 'ticket 21'
    ),
    ('get_event_with_non_conforming_object_relations', 2): (
        'url', ('Odd.Case/Relation', 'weird-relation'), (), 'ticket 22'
    ),
    ('get_event_with_object_confidence_tags', 0): (
        'ip-port', ('dst-port', 'first-seen'), ('port',),
        'ticket 21, and unticketed for the port'
    ),
    ('get_event_with_object_references', 0): (
        'attack-pattern',
        ('prerequisites', 'related-weakness', 'related-weakness', 'solutions'),
        (), 'ticket 21'
    ),
    ('get_event_with_object_references', 4): (
        'ip-port', ('dst-port', 'first-seen'), ('port',),
        'ticket 21, and unticketed for the port'
    ),
    ('get_event_with_process_object', 0): (
        'process', ('hidden',), (), 'ticket 21'
    ),
    ('get_event_with_process_object_v2', 0): (
        'process', ('hidden',), (), 'ticket 21'
    ),
    ('get_event_with_registry_key_and_values_objects', 0): (
        'registry-key', ('hive', 'key', 'last-modified'), (), 'ticket 21'
    ),
    ('get_event_with_registry_key_and_values_objects_custom', 0): (
        'registry-key', ('hive', 'key', 'last-modified'), (), 'ticket 21'
    ),
    ('get_event_with_registry_key_object', 0): (
        'registry-key', ('last-modified',), (), 'ticket 21'
    ),
    ('get_event_with_user_account_object', 0): (
        'user-account', ('account-type', 'password'), (), 'ticket 21'
    ),
    ('get_event_with_user_account_objects', 0): (
        'user-account', ('password',), (), 'ticket 21'
    ),
    ('get_event_with_user_account_objects', 1): (
        'user-account', ('account-type', 'password'), (), 'ticket 21'
    ),
    # `group` is on the wire, in a `group_list` carrier no handler visits -
    # ADR-0015 point 2's family, not a relation the export never wrote
    ('get_event_with_user_account_objects', 2): (
        'user-account', ('group', 'group', 'password'), (),
        'ticket 21 for the password, unticketed for the groups'
    ),
    ('get_event_with_vulnerability_and_weakness_objects', 0): (
        'vulnerability', ('created', 'cvss-score', 'references', 'references'),
        (), 'ticket 21'
    ),
    ('get_event_with_vulnerability_object', 0): (
        'vulnerability', ('created', 'cvss-score', 'references', 'references'),
        (), 'ticket 21'
    ),
    ('get_event_with_x509_object', 0): (
        'x509', ('signature_algorithm',), (), 'ticket 21'
    )
}

# A `cdhash` is 40 hexadecimal characters, the length of a sha1; an `impfuzzy`
# has the `blocksize:hash:hash` shape of an ssdeep. Neither is in the fixture
# corpus, and both are in the export's hash vocabulary
_CDHASH = 'c0ffee' + 'a' * 34
_IMPFUZZY_HASH = '24:BvqbV6zoA5yJlTKCjXsJK4Tdv:BvqbV6zoA5yJlTKCjXsJK4T'
# What a STIX 1 round trip gives back the type of each hash the export writes
# as a CybOX `Hash`. cybox types a hash by the length of its value, so seven
# of the sixteen come back as the type whose length they share - a documented
# loss no import-side rule can undo, nothing on the wire telling them apart
# (ADR-0015, session A1). `Other` is the fallback for a length cybox names
# nothing for: an ssdeep shape and a tlsh shape name themselves, and a `vhash`
# has no shape to read
_HASH_TYPE_ROUND_TRIP = {
    'md5': 'md5',
    'sha1': 'sha1',
    'sha224': 'sha224',
    'sha256': 'sha256',
    'sha384': 'sha384',
    'sha512': 'sha512',
    'ssdeep': 'ssdeep',
    'tlsh': 'tlsh',
    'authentihash': 'sha256',
    'cdhash': 'sha1',
    'impfuzzy': 'ssdeep',
    'imphash': 'md5',
    'pehash': 'sha1',
    'sha512/224': 'sha224',
    'sha512/256': 'sha256',
    'vhash': 'other'
}


class TestSTIX1Import(TestSTIX):

    # Every STIX 1 import mapping table, the object template of the object the
    # handler reading it names, and the shape of its entries: `relation` for a
    # table naming an object relation alone - the template types those -
    # `type-relation` and `type-feature-relation` for the two tuple shapes,
    # and `key` for the one table whose relation is the key itself.
    _IMPORT_MAPPING_TABLES = (
        ('as_mapping', ('asn',), 'type-relation'),
        ('attack_pattern_object_mapping', ('attack-pattern',), 'relation'),
        ('course_of_action_mapping', ('course-of-action',), 'key'),
        (
            'credential_authentication_mapping', ('credential',),
            'type-feature-relation'
        ),
        ('email_mapping', ('email',), 'type-feature-relation'),
        ('file_mapping', ('file',), 'type-feature-relation'),
        (
            'network_reference_mapping',
            ('network-connection', 'network-socket'), 'type-feature-relation'
        ),
        ('network_socket_mapping', ('network-socket',), 'type-feature-relation'),
        ('pe_header_mapping', ('pe',), 'relation'),
        ('pe_mapping', ('pe',), 'relation'),
        ('pe_resource_mapping', ('pe',), 'relation'),
        ('process_mapping', ('process',), 'type-relation'),
        ('regkey_mapping', ('registry-key',), 'type-relation'),
        ('regkey_value_mapping', ('registry-key',), 'type-relation'),
        ('user_account_object_mapping', ('user-account',), 'type-relation'),
        ('vulnerability_object_mapping', ('vulnerability',), 'type-relation'),
        ('weakness_object_mapping', ('weakness',), 'relation'),
        ('whois_mapping', ('whois',), 'type-feature-relation'),
        ('whois_registrant_mapping', ('whois',), 'type-feature-relation')
    )

    ############################################################################
    #                            UTILITY FUNCTIONS.                            #
    ############################################################################

    @staticmethod
    def _course_of_action():
        course_of_action = CourseOfAction()
        course_of_action.id_ = f'MISP:CourseOfAction-{_COA_UUID}'
        course_of_action.title = 'Block the command and control channel'
        course_of_action.description = 'Drop traffic to the C2 at the perimeter'
        course_of_action.stage = 'Response'
        course_of_action.type_ = 'Perimeter Blocking'
        objective = Objective()
        objective.description = 'Prevent further exfiltration'
        course_of_action.objective = objective
        for feature in ('cost', 'impact', 'efficacy'):
            statement = Statement()
            statement.value = 'Low'
            setattr(course_of_action, feature, statement)
        return course_of_action

    @staticmethod
    def _object_with_related_object(properties, related_uuid=_RELATED_UUID,
                                    relationship='Contains'):
        cybox_object = Object(properties)
        cybox_object.id_ = f'MISP:File-{_OBSERVABLE_UUID}'
        related_object = RelatedObject()
        related_object.idref = f'MISP:Address-{related_uuid}'
        if relationship is not None:
            related_object.relationship = relationship
        cybox_object.related_objects.append(related_object)
        return cybox_object

    @classmethod
    def _observable_with_related_object(cls):
        """An Observable whose own properties yield no attribute value, so the
        related objects are recorded as MISP references rather than folded into
        the passive-dns special case."""
        return Observable(cls._object_with_related_object(File()))

    @staticmethod
    def _indicator(observable_object, uuid):
        indicator = Indicator()
        indicator.id_ = f'MISP:Indicator-{uuid}'
        indicator.add_observable(Observable(observable_object))
        return indicator

    @classmethod
    def _domain_indicator(cls, value):
        domain = DomainName()
        domain.value = value
        domain_object = Object(domain)
        domain_object.id_ = f'MISP:DomainName-{_DOMAIN_UUID}'
        return cls._indicator(domain_object, _DOMAIN_UUID)

    @classmethod
    def _ip_indicator(cls, value):
        address = Address()
        address.address_value = value
        address.category = 'ipv4-addr'
        address.is_source = False
        address_object = Object(address)
        address_object.id_ = f'MISP:Address-{_IP_UUID}'
        return cls._indicator(address_object, _IP_UUID)

    @classmethod
    def _url_indicator(cls, value):
        """A URL Indicator resolving to the IP one above: the pair the parser
        holds back in its DNS bookkeeping until the whole package is parsed,
        then turns into a `passive-dns` object."""
        uri = URI()
        uri.value = value
        uri.type_ = URI.TYPE_URL
        uri_object = Object(uri)
        uri_object.id_ = f'MISP:URI-{_URL_UUID}'
        related_object = RelatedObject()
        related_object.idref = f'MISP:Address-{_IP_UUID}'
        related_object.relationship = 'Resolved_To'
        uri_object.related_objects.append(related_object)
        return cls._indicator(uri_object, _URL_UUID)

    @staticmethod
    def _threat_actor(title):
        threat_actor = ThreatActor()
        threat_actor.id_ = f'MISP:ThreatActor-{_ACTOR_UUID}'
        threat_actor.title = title
        return threat_actor

    def _parse_external_package(self, stix_package, parser=None, **kwargs):
        parser = parser or ExternalSTIX1toMISPParser()
        parser.load_stix_package(stix_package)
        parser.parse_stix_package(**kwargs)
        return parser

    def _parse_internal_package(self, stix_package, parser=None, **kwargs):
        parser = parser or InternalSTIX1toMISPParser()
        parser.load_stix_package(stix_package)
        parser.parse_stix_package(**kwargs)
        return parser

    @staticmethod
    def _course_of_action_attributes():
        """The MISP `course-of-action` attributes the fixture above maps to."""
        return {
            'name': 'Block the command and control channel',
            'description': 'Drop traffic to the C2 at the perimeter',
            'objective': 'Prevent further exfiltration',
            'stage': 'Response',
            'type': 'Perimeter Blocking',
            'cost': 'Low',
            'impact': 'Low',
            'efficacy': 'Low'
        }

    @staticmethod
    def _stix_header(title):
        header = STIXHeader()
        header.title = title
        return header

    @staticmethod
    def _write_package(tmp_dir, stix_package, name='package.xml'):
        filename = Path(tmp_dir) / name
        with open(filename, 'wt', encoding='utf-8') as f:
            f.write(stix_package.to_xml().decode())
        return filename

    @classmethod
    def _internal_package(cls, incident, inner_title=None, outer_title=None,
                          threat_actor=None):
        """Wrap an Incident the way the MISP STIX 1 export does: one related
        package per event, each carrying its own header, inside a wrapper
        package carrying the collection-level header."""
        inner_package = STIXPackage()
        inner_package.add_incident(incident)
        if threat_actor is not None:
            inner_package.add_threat_actor(threat_actor)
        if inner_title is not None:
            inner_package.stix_header = cls._stix_header(inner_title)
        return cls._wrapped_package(inner_package, outer_title)

    @classmethod
    def _wrapped_package(cls, inner_package, outer_title=None):
        stix_package = STIXPackage()
        if outer_title is not None:
            stix_package.stix_header = cls._stix_header(outer_title)
        stix_package.related_packages = RelatedPackages()
        stix_package.related_packages.append(RelatedPackage(inner_package))
        return stix_package

    @staticmethod
    def _header_only_package(title):
        """A package carrying a header and nothing below it."""
        stix_package = STIXPackage()
        stix_package.stix_header = STIXHeader()
        stix_package.stix_header.title = title
        return stix_package

    @classmethod
    def _incident_with_content(cls):
        """An Incident given one attribute to convert: a conversion yielding no
        attribute, object or galaxy is refused, so the tests reading the event
        metadata off a bare Incident give it something to yield."""
        incident = Incident()
        domain = DomainName()
        domain.value = 'circl.lu'
        incident.related_observables.append(
            RelatedObservable(
                cls._observable(domain, 'DomainName', _DOMAIN_UUID),
                relationship='Network activity'
            )
        )
        return incident

    @staticmethod
    def _load_misp_event(filename):
        misp_event = MISPEvent()
        misp_event.load_file(filename)
        return misp_event

    ############################################################################
    #                          COURSE OF ACTION TESTS.                         #
    ############################################################################

    def test_external_course_of_action_converts(self):
        stix_package = STIXPackage()
        stix_package.add_course_of_action(self._course_of_action())
        parser = self._parse_external_package(stix_package)
        self.assertEqual(len(parser.misp_event.objects), 1)
        misp_object = parser.misp_event.objects[0]
        self.assertEqual(misp_object.name, 'course-of-action')
        self.assertEqual(misp_object.uuid, _COA_UUID)
        self.assertEqual(
            {
                attribute.object_relation: attribute.value
                for attribute in misp_object.attributes
            },
            self._course_of_action_attributes()
        )

    def test_external_course_of_action_with_parameter_observables_converts(self):
        course_of_action = self._course_of_action()
        domain = DomainName()
        domain.value = 'circl.lu'
        domain_object = Object(domain)
        domain_object.id_ = f'MISP:DomainName-{_OBSERVABLE_UUID}'
        course_of_action.parameter_observables = Observables(
            [Observable(domain_object)]
        )
        stix_package = STIXPackage()
        stix_package.add_course_of_action(course_of_action)
        parser = self._parse_external_package(stix_package)
        self.assertEqual(
            [attribute.value for attribute in parser.misp_event.attributes],
            ['circl.lu']
        )
        misp_object = parser.misp_event.objects[0]
        self.assertEqual(len(misp_object.references), 1)
        self.assertEqual(misp_object.references[0].relationship_type, 'observable')

    def test_internal_course_of_action_taken_converts(self):
        incident = Incident()
        incident.title = 'Incident with a Course of Action taken'
        incident.add_coa_taken(self._course_of_action())
        parser = self._parse_internal_package(self._internal_package(incident))
        misp_objects = [
            misp_object for misp_object in parser.misp_event.objects
            if misp_object.name == 'course-of-action'
        ]
        self.assertEqual(len(misp_objects), 1)
        self.assertEqual(misp_objects[0].uuid, _COA_UUID)
        self.assertEqual(
            {
                attribute.object_relation: attribute.value
                for attribute in misp_objects[0].attributes
            },
            self._course_of_action_attributes()
        )

    ############################################################################
    #                           RELATED OBJECT TESTS.                          #
    ############################################################################

    def test_external_observable_with_related_object_converts(self):
        stix_package = STIXPackage()
        stix_package.observables = Observables(
            [self._observable_with_related_object()]
        )
        # something for the package to convert to: the record alone is none
        stix_package.add_indicator(self._domain_indicator('circl.lu'))
        parser = self._parse_external_package(stix_package)
        # An Observable with no value of its own yields no MISP object the
        # reference could land on: the record is kept, with the sanitised
        # idref, and that is where it stops.
        self.assertEqual(
            parser.references[_OBSERVABLE_UUID],
            [{'idref': _RELATED_UUID, 'relationship': 'contains'}]
        )
        self.assertEqual(parser.misp_event.objects, [])

    def _assert_file_object_references(self, parser, referenced_uuid):
        self.assertEqual(parser.diagnostics()['errors'], {})
        misp_object = parser.misp_event.get_objects_by_name('file')[0]
        self.assertEqual(misp_object.uuid, _OBSERVABLE_UUID)
        self.assertEqual(
            [
                (reference.relationship_type, reference.referenced_uuid)
                for reference in misp_object.references
            ],
            [('contains', referenced_uuid)]
        )

    def test_external_object_with_related_object_carries_the_reference(self):
        """The legacy importer applied the related objects it recorded as
        object references once the whole package was parsed: an Observable
        that yields a MISP object carries them as its references."""
        stix_package = STIXPackage()
        stix_package.observables = Observables(
            [
                Observable(
                    self._object_with_related_object(
                        self._file_with_three_properties()
                    )
                )
            ]
        )
        parser = self._parse_external_package(stix_package)
        self._assert_file_object_references(parser, _RELATED_UUID)

    def test_external_indicator_object_with_related_object_carries_the_reference(self):
        stix_package = STIXPackage()
        stix_package.add_indicator(
            self._indicator(
                self._object_with_related_object(
                    self._file_with_three_properties()
                ),
                _OBSERVABLE_UUID
            )
        )
        parser = self._parse_external_package(stix_package)
        self._assert_file_object_references(parser, _RELATED_UUID)

    def test_external_related_object_without_a_relationship_converts(self):
        """A related object naming no relationship still names a reference:
        reading the relationship off it unguarded crashed the conversion."""
        stix_package = STIXPackage()
        stix_package.observables = Observables(
            [
                Observable(
                    self._object_with_related_object(
                        self._file_with_three_properties(), relationship=None
                    )
                )
            ]
        )
        parser = self._parse_external_package(stix_package)
        misp_object = parser.misp_event.get_objects_by_name('file')[0]
        self.assertEqual(
            [
                (reference.relationship_type, reference.referenced_uuid)
                for reference in misp_object.references
            ],
            [('related-to', _RELATED_UUID)]
        )

    def test_external_reference_to_an_attribute_names_the_attribute_uuid(self):
        """A related object that became an attribute rather than an object is
        referenced by the attribute uuid, which MISP accepts."""
        stix_package = STIXPackage()
        stix_package.add_indicator(self._ip_indicator('198.51.100.4'))
        stix_package.observables = Observables(
            [
                Observable(
                    self._object_with_related_object(
                        self._file_with_three_properties(), _IP_UUID
                    )
                )
            ]
        )
        parser = self._parse_external_package(stix_package)
        self._assert_file_object_references(parser, _IP_UUID)
        self.assertEqual(
            [
                (attribute.type, attribute.uuid)
                for attribute in parser.misp_event.attributes
            ],
            [('ip-dst', _IP_UUID)]
        )

    ############################################################################
    #                          INCIDENT HISTORY TESTS.                         #
    ############################################################################

    def test_internal_incident_history_converts(self):
        incident = self._incident_with_content()
        incident.title = 'Incident carrying a History section'
        history = History()
        for value in ('MISP Tag: tlp:amber', 'Event Threat Level: High'):
            history_item = HistoryItem()
            history_item.journal_entry = JournalEntry(value)
            history.append(history_item)
        incident.history = history
        parser = self._parse_internal_package(self._internal_package(incident))
        self.assertIn('tlp:amber', [tag['name'] for tag in parser.misp_event.tags])

    @classmethod
    def _journal_package(cls, *entries):
        """An Incident carrying the given journal entries next to one
        attribute to convert, wrapped the way the MISP export wraps it."""
        incident = cls._incident_with_content()
        incident.id_ = f'MISP:Incident-{_PLAIN_OBJECT_UUID}'
        history = History()
        for value in entries:
            history_item = HistoryItem()
            history_item.journal_entry = JournalEntry(value)
            history.append(history_item)
        incident.history = history
        return cls._internal_package(incident)

    @staticmethod
    def _journal_attributes(parser):
        return sorted(
            (attribute.type, attribute.category, attribute.value)
            for attribute in parser.misp_event.attributes
            if attribute.type != 'domain'
        )

    def test_internal_journal_entry_attributes_round_trip(self):
        """`comment`, `text` and `other` have no CybOX shape and the export
        writes each as a journal entry of the Incident, a grammar the reader
        did not know: all three came back as nothing, with no message. The
        entry carries the category, the type and the value, and the uuid is
        derived from the Incident id, stable across two reads."""
        for attribute_type in ('comment', 'text', 'other'):
            with self.subTest(type=attribute_type):
                event = get_base_event()
                event['Event']['Attribute'] = [
                    {
                        'uuid': _PLAIN_OBJECT_UUID, 'type': attribute_type,
                        'category': 'Internal reference',
                        'value': f'My {attribute_type} value'
                    }
                ]
                stix_package = self._misp_export(event)
                parser = self._parse_internal_package(stix_package)
                self.assertEqual(parser.diagnostics()['errors'], {})
                self.assertEqual(parser.diagnostics()['warnings'], {})
                converted, = parser.misp_event.attributes
                self.assertEqual(
                    (converted.type, converted.category, converted.value),
                    (
                        attribute_type, 'Internal reference',
                        f'My {attribute_type} value'
                    )
                )
                incident_id = stix_package.related_packages.related_package[
                    0
                ].item.incidents[0].id_
                self.assertEqual(
                    converted.uuid,
                    str(
                        uuid5(
                            _UUIDv4,
                            f'{incident_id} - {attribute_type} - '
                            f'My {attribute_type} value'
                        )
                    )
                )
                again = self._parse_internal_package(stix_package)
                self.assertEqual(
                    again.misp_event.attributes[0].uuid, converted.uuid
                )

    def test_internal_journal_entry_value_holding_the_separator(self):
        """An entry was split on every `': '` into exactly two names, so a
        value holding one more - a tag with a colon in it included - raised
        and was skipped without a word. The entry splits on the first."""
        parser = self._parse_internal_package(
            self._journal_package(
                'Attribute (Other - comment): a value: with a colon',
                'MISP Tag: a: b'
            )
        )
        self.assertEqual(parser.diagnostics()['warnings'], {})
        self.assertEqual(
            self._journal_attributes(parser),
            [('comment', 'Other', 'a value: with a colon')]
        )
        self.assertIn('a: b', [tag.name for tag in parser.misp_event.tags])

    def test_internal_legacy_journal_entry_grammar_still_reads(self):
        """`attribute[Category][type]: value`, the grammar MISP core's own STIX
        1 export wrote, is read next to ours. A category MISP has not is left
        to pymisp's default for the type: pymisp raises a bare `KeyError`
        for it, which escaped the guard and aborted the whole package."""
        parser = self._parse_internal_package(
            self._journal_package(
                'attribute[Internal reference][text]: legacy text',
                'attribute[No such category][comment]: legacy comment'
            )
        )
        self.assertEqual(parser.diagnostics()['errors'], {})
        self.assertEqual(parser.diagnostics()['warnings'], {})
        self.assertEqual(
            self._journal_attributes(parser),
            [
                ('comment', 'Other', 'legacy comment'),
                ('text', 'Internal reference', 'legacy text')
            ]
        )

    def test_internal_unread_journal_entries_are_one_warning(self):
        """An entry matching no grammar - free text, a malformed
        `attribute[` prefix, an entry with no `': '` - was skipped silently.
        The loss is one Warning per document, the count its only size."""
        parser = self._parse_internal_package(
            self._journal_package(
                'Some free text: the analyst wrote',
                'attribute[Other: malformed',
                'no separator at all',
                'Attribute (no category): value'
            )
        )
        self.assertEqual(self._journal_attributes(parser), [])
        warnings = [
            warning for warnings in parser.diagnostics()['warnings'].values()
            for warning in warnings
        ]
        self.assertEqual(len(warnings), 1)
        self.assertIn('4 Incident journal entries', warnings[0])

    def test_internal_header_description_attribute_round_trips(self):
        """The attribute whose comment is `Imported from STIX header
        description` is exported as the package header description, which
        the reader never read. It comes back as a `comment` attribute
        carrying the marker, so a re-export puts it back in the header."""
        event = get_event_with_undefined_attributes()
        header, journal = event['Event']['Attribute']
        stix_package = self._misp_export(event)
        parser = self._parse_internal_package(stix_package)
        self.assertEqual(parser.diagnostics()['errors'], {})
        self.assertEqual(parser.diagnostics()['warnings'], {})
        self.assertEqual(
            sorted(
                (
                    attribute.type, attribute.category, attribute.value,
                    getattr(attribute, 'comment', None)
                )
                for attribute in parser.misp_event.attributes
            ),
            [
                ('comment', 'Other', journal['value'], None),
                ('comment', 'Other', header['value'], header['comment'])
            ]
        )
        package_id = stix_package.related_packages.related_package[0].item.id_
        self.assertIn(
            str(uuid5(_UUIDv4, f'{package_id} - header description')),
            [attribute.uuid for attribute in parser.misp_event.attributes]
        )
        exporter = MISPtoSTIX1EventsParser('MISP', '1.1.1')
        exporter.parse_misp_event(parser.misp_event.to_dict())
        self.assertEqual(
            exporter.stix_package.stix_header.description.value,
            header['value']
        )

    def test_internal_undefined_attributes_alone_convert(self):
        """An event holding only journal entry attributes converted to nothing
        and was refused as a document carrying no content."""
        parser = self._parse_internal_package(
            self._misp_export(get_event_with_undefined_attributes())
        )
        self.assertEqual(len(parser.misp_event.attributes), 2)

    ############################################################################
    #                          PUBLIC ENTRY POINT TESTS.                       #
    ############################################################################

    def test_stix_1_to_misp_converts_a_course_of_action_package(self):
        """The failure the parser tests cover escapes `stix_1_to_misp` entirely:
        only `load_stix1_package` is guarded, so a crash in
        `parse_stix_package` reaches the caller as a traceback rather than as
        the documented error dict."""
        stix_package = STIXPackage()
        stix_package.add_course_of_action(self._course_of_action())
        with TemporaryDirectory() as tmp_dir:
            filename = self._write_package(
                tmp_dir, stix_package, 'course_of_action.xml'
            )
            results = stix_1_to_misp(filename, single_event=True)
        self.assertNotIn('errors', results)
        self.assertEqual(results['success'], 1)

    ############################################################################
    #                          ERROR HANDLING TESTS.                           #
    ############################################################################

    def test_load_stix1_package_raises_a_catchable_error(self):
        """The loader called `sys.exit()` on malformed content - `SystemExit`
        derives from `BaseException`, so a caller's `except Exception` never
        saw it and one hostile document killed the hosting process."""
        with TemporaryDirectory() as tmp_dir:
            filename = Path(tmp_dir) / 'malformed.xml'
            with open(filename, 'wt', encoding='utf-8') as f:
                f.write('<not-stix>not a STIX package</not-stix')
            with self.assertRaises(STIXLoadingError):
                load_stix1_package(filename)

    def test_load_stix1_package_does_not_honour_file_url_strings(self):
        """lxml treats a plain string argument as a filename *or* a URL, so a
        `file://` string turned a conversion request into a local file read.
        String input is now resolved to a `Path` first, like the top-level
        helpers already did."""
        stix_package = STIXPackage()
        stix_package.add_course_of_action(self._course_of_action())
        with TemporaryDirectory() as tmp_dir:
            filename = self._write_package(
                tmp_dir, stix_package, 'course_of_action.xml'
            )
            with self.assertRaises(STIXLoadingError):
                load_stix1_package(f'file://{filename}')

    def test_parse_stix_content_does_not_honour_file_url_strings(self):
        stix_package = STIXPackage()
        stix_package.add_course_of_action(self._course_of_action())
        with TemporaryDirectory() as tmp_dir:
            filename = self._write_package(
                tmp_dir, stix_package, 'course_of_action.xml'
            )
            parser = ExternalSTIX1toMISPParser()
            with self.assertRaises(STIXLoadingError):
                parser.parse_stix_content(f'file://{filename}')

    def test_parse_stix_content_accepts_a_plain_path_string(self):
        stix_package = STIXPackage()
        stix_package.add_course_of_action(self._course_of_action())
        with TemporaryDirectory() as tmp_dir:
            filename = self._write_package(
                tmp_dir, stix_package, 'course_of_action.xml'
            )
            parser = ExternalSTIX1toMISPParser()
            parser.parse_stix_content(str(filename))
        self.assertEqual(len(parser.misp_event.objects), 1)

    def test_load_stix1_package_parses_a_failing_document_exactly_once(self):
        """A document engineered to be expensive to parse and then fail was
        parsed twice: the generic fallback imported `maec` and retried, even
        though a successful `import maec` never changes the parse outcome -
        `stix` imports it lazily during the first attempt when it is needed."""
        with patch.object(
                stix1_loading_helpers.STIXPackage, 'from_xml',
                side_effect=ValueError('generic parse failure')) as from_xml:
            with self.assertRaises(STIXLoadingError) as context:
                load_stix1_package('input.xml')
        self.assertEqual(from_xml.call_count, 1)
        self.assertIn('generic parse failure', str(context.exception))

    def test_load_stix1_package_retries_once_for_unregistered_namespaces(self):
        stix_package = STIXPackage()
        with patch.object(
                stix1_loading_helpers.STIXPackage, 'from_xml',
                side_effect=[
                    NamespaceNotFoundError('http://us-cert.gov/ciscp'),
                    stix_package
                ]) as from_xml:
            self.assertIs(load_stix1_package('input.xml'), stix_package)
        self.assertEqual(from_xml.call_count, 2)

    def test_load_stix1_package_namespace_retry_is_bounded(self):
        with patch.object(
                stix1_loading_helpers.STIXPackage, 'from_xml',
                side_effect=NamespaceNotFoundError(
                    'http://unknown.namespace')) as from_xml:
            with self.assertRaises(STIXLoadingError) as context:
                load_stix1_package('input.xml')
        self.assertEqual(from_xml.call_count, 2)
        self.assertIn('Cannot handle STIX namespace', str(context.exception))

    def test_load_stix1_package_propagates_memory_error(self):
        """`MemoryError` from a memory bomb was swallowed into the generic
        retry - the document was parsed a second time and the exhaustion
        reported as a plain loading error."""
        with patch.object(
                stix1_loading_helpers.STIXPackage, 'from_xml',
                side_effect=MemoryError()) as from_xml:
            with self.assertRaises(MemoryError):
                load_stix1_package('input.xml')
        self.assertEqual(from_xml.call_count, 1)

    def test_load_stix1_package_reports_io_errors_without_retry(self):
        with patch.object(
                stix1_loading_helpers.STIXPackage, 'from_xml',
                side_effect=OSError('Error reading file')) as from_xml:
            with self.assertRaises(STIXLoadingError) as context:
                load_stix1_package('input.xml')
        self.assertEqual(from_xml.call_count, 1)
        self.assertIn(
            'Error while reading the STIX1 document', str(context.exception)
        )

    def test_load_stix1_package_reports_a_missing_parsing_dependency(self):
        """`stix` raises `ImportError` from its lazy `maec` import when the
        library is missing - the loader turns it into the diagnostic the old
        import-and-retry fallback existed to produce."""
        with patch.object(
                stix1_loading_helpers.STIXPackage, 'from_xml',
                side_effect=ModuleNotFoundError(
                    "No module named 'maec'", name='maec')) as from_xml:
            with self.assertRaises(STIXLoadingError) as context:
                load_stix1_package('input.xml')
        self.assertEqual(from_xml.call_count, 1)
        self.assertEqual(
            str(context.exception), 'Missing python library: maec'
        )

    def test_load_stix1_package_loads_maec_carrying_documents(self):
        """MAEC support must survive the removal of the import-and-retry
        fallback: `stix` imports `maec` on its own during the first parse."""
        from maec.package.package import Package as MAECPackage
        from stix.extensions.malware.maec_4_1_malware import MAECInstance
        from stix.ttp import TTP, Behavior
        ttp = TTP(title='MAEC carrying TTP')
        behavior = Behavior()
        behavior.add_malware_instance(MAECInstance(MAECPackage()))
        ttp.behavior = behavior
        stix_package = STIXPackage()
        stix_package.add_ttp(ttp)
        with TemporaryDirectory() as tmp_dir:
            filename = self._write_package(tmp_dir, stix_package, 'maec_ttp.xml')
            package = load_stix1_package(filename)
        self.assertEqual(package.ttps.ttp[0].title, 'MAEC carrying TTP')

    def test_load_stix1_package_refuses_an_oversized_document(self):
        """Nothing checked an input size: libxml2 built the whole tree - 2 to 7
        times the document size in memory - before `mixbox` looked at what the
        document even is, so an oversized document cost the whole parse."""
        from misp_stix_converter import STIXInputSizeError
        stix_package = STIXPackage()
        stix_package.add_course_of_action(self._course_of_action())
        with TemporaryDirectory() as tmp_dir:
            filename = self._write_package(
                tmp_dir, stix_package, 'course_of_action.xml'
            )
            with patch.object(
                    stix1_loading_helpers.STIXPackage, 'from_xml') as from_xml:
                with self.assertRaises(STIXInputSizeError) as context:
                    load_stix1_package(filename, max_size=64)
        from_xml.assert_not_called()
        self.assertIn('64 bytes', str(context.exception))

    def test_load_stix1_package_input_size_limit_is_raisable(self):
        stix_package = STIXPackage()
        stix_package.add_course_of_action(self._course_of_action())
        with TemporaryDirectory() as tmp_dir:
            filename = self._write_package(
                tmp_dir, stix_package, 'course_of_action.xml'
            )
            for max_size in (filename.stat().st_size, 0):
                package = load_stix1_package(filename, max_size=max_size)
                self.assertEqual(len(package.courses_of_action), 1)

    def test_load_stix1_package_refuses_a_document_that_is_not_a_package(self):
        """`mixbox` checks the root element only once the tree it builds is
        complete: reading the root element on its own refuses a document that
        is not a STIX package without materialising any of it."""
        with TemporaryDirectory() as tmp_dir:
            filename = Path(tmp_dir) / 'not_stix.xml'
            with open(filename, 'wt', encoding='utf-8') as f:
                f.write(f'<not-stix>{"a" * 4096}</not-stix>')
            with patch.object(
                    stix1_loading_helpers.STIXPackage, 'from_xml') as from_xml:
                with self.assertRaises(STIXLoadingError) as context:
                    load_stix1_package(filename)
        from_xml.assert_not_called()
        self.assertIn('not-stix', str(context.exception))

    def test_load_stix1_package_root_element_check_accepts_a_package(self):
        """The peek refuses only what it positively identified as something
        else: a STIX package reaches the parser, whatever the size of the root
        element it starts with."""
        stix_package = STIXPackage()
        stix_package.stix_header = STIXHeader(
            title=f'Package with a long title: {"a" * 8192}'
        )
        stix_package.add_course_of_action(self._course_of_action())
        with TemporaryDirectory() as tmp_dir:
            filename = self._write_package(
                tmp_dir, stix_package, 'course_of_action.xml'
            )
            package = load_stix1_package(filename)
        self.assertEqual(len(package.courses_of_action), 1)

    def test_parse_stix_content_honours_the_input_size_limit(self):
        # MISP core converts through the parsers rather than through the entry
        # functions (ADR-0009), so the limit has to be reachable there too.
        from misp_stix_converter import STIXInputSizeError
        stix_package = STIXPackage()
        stix_package.add_course_of_action(self._course_of_action())
        with TemporaryDirectory() as tmp_dir:
            filename = self._write_package(
                tmp_dir, stix_package, 'course_of_action.xml'
            )
            parser = ExternalSTIX1toMISPParser()
            with self.assertRaises(STIXInputSizeError) as context:
                parser.parse_stix_content(filename, max_size=64)
        self.assertIn('64 bytes', str(context.exception))

    def test_stix_1_to_misp_reports_the_input_size_limit(self):
        stix_package = STIXPackage()
        stix_package.add_course_of_action(self._course_of_action())
        with TemporaryDirectory() as tmp_dir:
            filename = self._write_package(
                tmp_dir, stix_package, 'course_of_action.xml'
            )
            results = stix_1_to_misp(filename, max_size=64)
        self.assertIn('errors', results)
        self.assertTrue(
            any('64 bytes' in error for error in results['errors'])
        )

    def test_stix_1_to_misp_returns_error_dict_on_malformed_content(self):
        with TemporaryDirectory() as tmp_dir:
            filename = Path(tmp_dir) / 'malformed.xml'
            with open(filename, 'wt', encoding='utf-8') as f:
                f.write('not even xml')
            results = stix_1_to_misp(filename)
        self.assertIn('errors', results)

    def test_stix_1_to_misp_reduces_the_input_path(self):
        # The loading helpers reduce the path their own message embeds, but the
        # error dict the entry function returns prefixed the resolved path
        # again: what a caller reads back names the input file only.
        with TemporaryDirectory() as tmp_dir:
            missing = Path(tmp_dir) / 'missing.xml'
            results = stix_1_to_misp(missing, output_dir=Path(tmp_dir))
            self.assertEqual(len(results['errors']), 1)
            self.assertTrue(
                results['errors'][0].startswith('missing.xml - '),
                results['errors'][0]
            )
            self.assertNotIn(tmp_dir, results['errors'][0])
            malformed = Path(tmp_dir) / 'malformed.xml'
            with open(malformed, 'wt', encoding='utf-8') as f:
                f.write('not even xml')
            results = stix_1_to_misp(malformed, output_dir=Path(tmp_dir))
            self.assertEqual(len(results['errors']), 1)
            self.assertTrue(
                results['errors'][0].startswith('malformed.xml - '),
                results['errors'][0]
            )
            self.assertNotIn(tmp_dir, results['errors'][0])

    def test_stix_1_to_misp_returns_error_dict_when_parsing_fails(self):
        """Only the loading call was guarded - a crash in the parsing stage
        escaped `stix_1_to_misp` as a traceback instead of the documented
        error dict."""
        stix_package = STIXPackage()
        stix_package.add_course_of_action(self._course_of_action())
        with TemporaryDirectory() as tmp_dir:
            filename = self._write_package(
                tmp_dir, stix_package, 'course_of_action.xml'
            )
            with patch.object(
                    ExternalSTIX1toMISPParser, 'parse_stix_package',
                    side_effect=RuntimeError('parser stage crash')):
                results = stix_1_to_misp(filename, single_event=True)
        self.assertNotIn('success', results)
        self.assertTrue(
            any('parser stage crash' in error for error in results['errors'])
        )

    def test_stix_1_output_writes_are_owner_only_and_refuse_to_overwrite(self):
        stix_package = STIXPackage()
        stix_package.add_course_of_action(self._course_of_action())
        with TemporaryDirectory() as tmp_dir:
            filename = self._write_package(
                tmp_dir, stix_package, 'course_of_action.xml'
            )
            self._check_output_write_safety(
                stix_1_to_misp, filename, single_event=True
            )
            # Same rules on the destination the caller names as on the default
            self._check_output_write_safety(
                stix_1_to_misp, filename, single_event=True,
                output_name=Path(tmp_dir) / 'event.misp.json'
            )

    def test_stix_1_internal_import_yields_one_event_by_itself(self):
        """A STIX 1 import produces one MISP event whatever `single_event`
        says - the Internal parser merges every related package into one, and
        the External one forces the flag - so the entry function's per-event
        branch was reached by the default parameters and could only crash
        there: nothing sets `misp_events`, so it iterated a `MISPEvent`."""
        stix_package = self._internal_titled_package()
        with TemporaryDirectory() as tmp_dir:
            filename = self._write_package(tmp_dir, stix_package, 'internal.xml')
            results = stix_1_to_misp(filename)
            self.assertEqual(results['success'], 1)
            self.assertEqual(len(results['results']), 1)
            output = results['results'][0]
            self.assertEqual(output.name, 'internal.xml.out')
            self.assertTrue(output.is_file())
            # The explicit flag asks for what the parser does anyway, so it
            # writes the same file rather than a differently named one
            self.assertEqual(
                stix_1_to_misp(
                    filename, single_event=True, overwrite=True
                )['results'],
                [output]
            )

    def test_stix_1_output_dir_takes_a_str_and_is_created(self):
        external = STIXPackage()
        external.add_course_of_action(self._course_of_action())
        with TemporaryDirectory() as tmp_dir:
            # Both classifications, since only one MISP event comes out of
            # either: whatever `single_event` says, a STIX 1 import goes
            # through the output funnels and never builds a per-event path
            for name, package in (('external', external),
                                  ('internal', self._internal_titled_package())):
                self._check_output_dir_handling(
                    stix_1_to_misp,
                    self._write_package(tmp_dir, package, f'{name}.xml')
                )

    ############################################################################
    #                         CLASSIFICATION OVERRIDE.                         #
    ############################################################################

    def _internal_titled_package(self):
        """A package whose header title matches the MISP export convention, so
        content-based detection classifies it as internal - shaped with the
        related packages the Internal parser expects."""
        return self._internal_package(
            self._incident_with_content(), inner_title='Incident title',
            outer_title="Export from ACME's MISP"
        )

    def test_stix_1_classification_auto_detection_warns_and_explicit_is_silent(self):
        stix_package = self._internal_titled_package()
        with TemporaryDirectory() as tmp_dir:
            filename = self._write_package(tmp_dir, stix_package, 'internal.xml')
            results = stix_1_to_misp(filename, single_event=True)
            self.assertEqual(results['success'], 1)
            self.assertTrue(
                any(
                    'selected from the document content' in warning
                    for warnings in results['warnings'].values()
                    for warning in warnings
                )
            )
            results = stix_1_to_misp(
                filename, single_event=True, classification='internal',
                overwrite=True
            )
            self.assertEqual(results['success'], 1)
            self.assertNotIn('warnings', results)

    def test_stix_1_classification_forced_external_warns_on_mismatch(self):
        stix_package = self._internal_titled_package()
        # The External parser reads the wrapper package only, and a MISP export
        # carries nothing there: a conversion yielding nothing is refused, so
        # the wrapper is given something the warning can be reported next to
        stix_package.add_course_of_action(self._course_of_action())
        with TemporaryDirectory() as tmp_dir:
            filename = self._write_package(tmp_dir, stix_package, 'internal.xml')
            results = stix_1_to_misp(
                filename, single_event=True, classification='external'
            )
            self.assertEqual(results['success'], 1)
            self.assertTrue(
                any(
                    'detected as internal' in warning
                    for warnings in results['warnings'].values()
                    for warning in warnings
                )
            )

    def test_stix_1_record_classification_on_the_parsers(self):
        # Driven in memory: the same two Warnings the entry function records,
        # under `misp event`, the identifier a STIX 1 import keeps throughout
        stix_package = self._internal_titled_package()
        parser = InternalSTIX1toMISPParser()
        parser.load_stix_package(stix_package)
        parser.record_classification(True)
        self.assertEqual(
            parser.diagnostics()['warnings'],
            {'misp event': [CLASSIFICATION_FROM_CONTENT_WARNING]}
        )
        parser = ExternalSTIX1toMISPParser()
        parser.load_stix_package(stix_package)
        parser.record_classification(True, overridden=True)
        self.assertEqual(
            parser.diagnostics()['warnings'],
            {'misp event': [CLASSIFICATION_OVERRIDDEN_TO_EXTERNAL_WARNING]}
        )

    def test_stix_1_detection_logs_a_warning(self):
        stix_package = self._internal_titled_package()
        with self.assertLogs('misp_stix_converter', level='WARNING'):
            self.assertTrue(is_stix1_from_misp(stix_package))

    def test_stix_1_classification_rejects_invalid_value(self):
        with self.assertRaises(ValueError):
            stix_1_to_misp('unused.xml', classification='banana')

    def test_stix_1_detection_reads_the_related_package_headers(self):
        """The collection export titles the packages it relates and leaves the
        wrapper around them untitled - the shape of this repo's own
        `test_event*_stix1*.xml` - so a wrapper carrying no title of its own is
        classified from the headers inside it: a MISP export when every one of
        them is titled as one, and another producer's document as soon as one
        related package is theirs."""
        stix_package = self._internal_package(
            self._incident_with_content(),
            inner_title="Export from ACME's MISP"
        )
        with self.assertLogs('misp_stix_converter', level='WARNING'):
            self.assertTrue(is_stix1_from_misp(stix_package))
        stix_package.related_packages.append(
            RelatedPackage(self._header_only_package('Threat report'))
        )
        self.assertFalse(is_stix1_from_misp(stix_package))
        self.assertFalse(
            is_stix1_from_misp(self._internal_package(Incident()))
        )

    def test_stix_1_misp_export_without_a_wrapper_title_converts(self):
        """The reference export of the event export tests carries its MISP
        title in the related package only: classified External, it converted
        to an event holding nothing, reported as a success."""
        filename = Path(__file__).parent / 'test_event1_stix11.xml'
        with TemporaryDirectory() as tmp_dir:
            results = stix_1_to_misp(
                filename, output_name=Path(tmp_dir) / 'event.misp.json'
            )
            self.assertEqual(results['success'], 1)
            misp_event = self._load_misp_event(results['results'][0])
        self.assertEqual(
            sorted(
                (attribute.type, attribute.value)
                for attribute in misp_event.attributes
            ),
            [('AS', 'AS174'), ('domain', 'circl.lu')]
        )
        self.assertIn(
            CLASSIFICATION_FROM_CONTENT_WARNING,
            results['warnings']['misp event']
        )

    ############################################################################
    #                            EMPTY CONVERSION.                             #
    ############################################################################

    def test_conversion_yielding_nothing_raises(self):
        """An event with no attribute, object or galaxy is what a document the
        parser could read nothing from produces - a package made of a header,
        a MISP export parsed as External - and reporting it as a success shows
        the user an imported event holding nothing. The error is the one MISP
        core already reads as `contains nothing to import`."""
        with self.assertRaises(MissingSTIXContentError) as context:
            self._parse_external_package(
                self._header_only_package('Threat report')
            )
        self.assertEqual(
            str(context.exception),
            'The STIX 1.2 package converted to no MISP attribute, object or '
            'galaxy.'
        )
        with self.assertRaises(MissingSTIXContentError):
            self._parse_internal_package(self._internal_package(Incident()))
        with self.assertRaises(MissingSTIXContentError):
            self._parse_external_package(self._internal_titled_package())

    def test_stix_1_to_misp_reports_a_conversion_yielding_nothing(self):
        with TemporaryDirectory() as tmp_dir:
            filename = self._write_package(
                tmp_dir, self._header_only_package('Threat report'), 'empty.xml'
            )
            results = stix_1_to_misp(filename)
            self.assertEqual(list(results), ['errors'])
            self.assertIn(
                'converted to no MISP attribute, object or galaxy',
                results['errors'][0]
            )
            self.assertFalse((Path(tmp_dir) / 'empty.xml.out').exists())

    ############################################################################
    #                          EVENT DISTRIBUTION.                             #
    ############################################################################

    def _external_package(self):
        stix_package = STIXPackage()
        stix_package.add_course_of_action(self._course_of_action())
        return stix_package

    def test_external_event_takes_the_distribution_parameter(self):
        """An event JSON without a distribution is saved by MISP with the
        column default, org-only: the caller's choice has to be on the event."""
        parser = self._parse_external_package(
            self._external_package(), distribution=3
        )
        self.assertEqual(parser.misp_event.distribution, 3)
        self.assertFalse(hasattr(parser.misp_event, 'sharing_group_id'))

    def test_external_event_takes_the_sharing_group_parameters(self):
        parser = self._parse_external_package(
            self._external_package(), distribution=4, sharing_group_id=7
        )
        self.assertEqual(parser.misp_event.distribution, 4)
        self.assertEqual(parser.misp_event.sharing_group_id, 7)

    def test_external_sharing_group_distribution_needs_a_sharing_group(self):
        parser = self._parse_external_package(
            self._external_package(), distribution=4
        )
        self.assertEqual(parser.misp_event.distribution, 0)
        self.assertIn(
            'Invalid Sharing Group ID - cannot be None when distribution is 4',
            parser.diagnostics()['errors']['init']
        )

    def test_internal_event_takes_the_distribution_parameters(self):
        stix_package = self._internal_package(self._incident_with_content())
        parser = self._parse_internal_package(stix_package, distribution=3)
        self.assertEqual(parser.misp_event.distribution, 3)
        parser = self._parse_internal_package(
            stix_package, distribution=4, sharing_group_id=7
        )
        self.assertEqual(parser.misp_event.distribution, 4)
        self.assertEqual(parser.misp_event.sharing_group_id, 7)

    ############################################################################
    #                           EVENT INFO FALLBACK.                           #
    ############################################################################

    def test_internal_event_info_falls_back_to_stix_header_title(self):
        """A title-less Incident takes its event info from the header of its own
        related package, which is where the MISP export writes the per-event
        title - not from the collection-level wrapper header."""
        parser = self._parse_internal_package(
            self._internal_package(
                self._incident_with_content(),
                inner_title="Export from ACME's MISP",
                outer_title='Collection level title'
            )
        )
        self.assertEqual(parser.misp_event.info, "Export from ACME's MISP")

    def test_internal_event_info_falls_back_to_wrapper_header_title(self):
        parser = self._parse_internal_package(
            self._internal_package(
                self._incident_with_content(),
                outer_title='Collection level title'
            )
        )
        self.assertEqual(parser.misp_event.info, 'Collection level title')

    def test_internal_event_info_falls_back_to_generic_message(self):
        parser = self._parse_internal_package(
            self._internal_package(self._incident_with_content())
        )
        self.assertEqual(
            parser.misp_event.info,
            'Imported from STIX 1.2 Package generated with MISP'
        )

    def test_external_event_info_falls_back_past_a_titleless_header(self):
        """A STIX header always carries a `title` field, so a header present but
        untitled must not become the event info."""
        stix_package = self._external_package()
        stix_package.stix_header = self._stix_header(None)
        parser = self._parse_external_package(stix_package)
        self.assertEqual(
            parser.misp_event.info, 'Imported from external STIX 1.2 Package'
        )

    def test_external_event_info_reports_the_declared_version(self):
        """python-stix names the package version `version`: the generic event
        info must report what the package declares, not a constant."""
        for version in ('1.1', '1.2'):
            with self.subTest(version=version):
                stix_package = self._external_package()
                stix_package.version = version
                parser = self._parse_external_package(stix_package)
                self.assertEqual(
                    parser.misp_event.info,
                    f'Imported from external STIX {version} Package'
                )

    def test_external_event_info_falls_back_on_a_version_less_package(self):
        """Loading a document with no version fails earlier, but a package
        built in memory - what MISP core hands over - can carry none."""
        stix_package = self._external_package()
        stix_package.version = None
        parser = self._parse_external_package(stix_package)
        self.assertEqual(
            parser.misp_event.info, 'Imported from external STIX 1.1.1 Package'
        )

    ############################################################################
    #                              GALAXY TAGS.                                #
    ############################################################################

    @staticmethod
    def _ttp_with_malware(title):
        """A TTP whose only content is the malware naming a galaxy tag: no
        infrastructure or exploit target, so no attribute the tag could land
        on."""
        ttp = TTP()
        ttp.id_ = f'MISP:TTP-{_ACTOR_UUID}'
        malware_instance = MalwareInstance()
        malware_instance.title = title
        ttp.behavior = Behavior()
        ttp.behavior.add_malware_instance(malware_instance)
        return ttp

    @classmethod
    def _ttp_with_malware_title(cls, title):
        """A TTP naming a malware what a taxonomy tag value cannot carry, over
        infrastructure the galaxy tag then lands on as an attribute."""
        ttp = cls._ttp_with_malware(title)
        address = Address()
        address.address_value = '198.51.100.16'
        address.category = 'ipv4-addr'
        address_object = Object(address)
        address_object.id_ = f'MISP:Address-{_IP_UUID}'
        infrastructure = Infrastructure()
        infrastructure.observable_characterization = Observables(
            [Observable(address_object)]
        )
        ttp.resources = Resource()
        ttp.resources.infrastructure = infrastructure
        return ttp

    def test_external_ttp_galaxy_title_writes_one_taxonomy_entry(self):
        """A malware title is written into the tag the galaxy is: whatever
        further taxonomy entries the title asks for, what is written is one."""
        stix_package = STIXPackage()
        stix_package.add_ttp(self._ttp_with_malware_title(SMUGGLING_TAG_VALUE))
        parser = self._parse_external_package(stix_package)
        attribute = parser.misp_event.attributes[0]
        tags = {tag['name'] for tag in attribute.tags}
        self.assertIn(f'misp-galaxy:mitre-malware="{SANITISED_TAG_VALUE}"', tags)
        self.assertNotIn(
            f'misp-galaxy:mitre-malware="{SMUGGLING_TAG_VALUE}"', tags
        )

    def test_external_threat_actor_galaxy_lands_on_the_event(self):
        """A threat actor names no attribute or object of its own: the galaxy
        tag built from its title is only kept if the event carries it."""
        stix_package = STIXPackage()
        stix_package.add_threat_actor(self._threat_actor('APT-A'))
        parser = self._parse_external_package(stix_package)
        tags = {tag['name'] for tag in parser.misp_event.tags}
        self.assertIn('misp-galaxy:threat-actor="APT-A"', tags)

    def test_external_contentless_ttp_galaxy_lands_on_the_event(self):
        """A TTP carrying no infrastructure or exploit target yields no
        attribute the galaxy tag could land on, so it lands on the event."""
        stix_package = STIXPackage()
        stix_package.add_ttp(self._ttp_with_malware('WannaCry'))
        parser = self._parse_external_package(stix_package)
        tags = {tag['name'] for tag in parser.misp_event.tags}
        self.assertIn('misp-galaxy:mitre-malware="WannaCry"', tags)

    def test_internal_threat_actor_galaxy_lands_on_the_event(self):
        """A threat actor of a MISP-generated package is the export of an event
        galaxy tag - the export drops the tag once the actor carries it, so the
        import has to put it back on the event."""
        incident = Incident()
        incident.title = 'Event with a threat actor galaxy'
        incident.timestamp = datetime(2026, 7, 1, 12, 0)
        stix_package = self._internal_package(
            incident, threat_actor=self._threat_actor('APT-A')
        )
        parser = self._parse_internal_package(stix_package)
        tags = {tag['name'] for tag in parser.misp_event.tags}
        self.assertIn('misp-galaxy:threat-actor="APT-A"', tags)

    @staticmethod
    def _galaxy_tags(misp_event):
        return {
            tag['name'] for tag in misp_event.tags
            if tag['name'].startswith('misp-galaxy:')
        }

    def test_external_galaxy_tags_name_galaxies_that_exist(self):
        """A STIX 1 construct carries a cluster value and no galaxy: the tag
        written for it names the galaxy the construct stands for, which has to
        be one MISP has - `misp-attack-pattern`, `ransomware` and `tool` named
        none, or none the MITRE clusters a document carries live in. No course
        of action here: an external one is an object, never a galaxy."""
        ttp = TTP()
        ttp.id_ = f'MISP:TTP-{_ACTOR_UUID}'
        attack_pattern = AttackPattern()
        attack_pattern.title = 'DLL Search Order Hijacking - T1038'
        malware_instance = MalwareInstance()
        malware_instance.title = 'Elise - S0081'
        ttp.behavior = Behavior()
        ttp.behavior.add_attack_pattern(attack_pattern)
        ttp.behavior.add_malware_instance(malware_instance)
        tool = ToolInformation()
        tool.name = 'ifconfig - S0101'
        ttp.resources = Resource()
        ttp.resources.tools = Tools([tool])
        vulnerability = Vulnerability()
        vulnerability.title = 'Ghost'
        exploit_target = ExploitTarget()
        exploit_target.add_vulnerability(vulnerability)
        ttp.add_exploit_target(exploit_target)
        stix_package = STIXPackage()
        stix_package.add_ttp(ttp)
        parser = self._parse_external_package(stix_package)
        self.assertEqual(
            self._galaxy_tags(parser.misp_event),
            {
                'misp-galaxy:mitre-attack-pattern='
                '"DLL Search Order Hijacking - T1038"',
                'misp-galaxy:mitre-malware="Elise - S0081"',
                'misp-galaxy:mitre-tool="ifconfig - S0101"',
                'misp-galaxy:branded-vulnerability="Ghost"'
            }
        )

    def test_internal_galaxy_tags_name_galaxies_that_exist(self):
        """The MISP export writes each cluster's value and never its galaxy:
        the tags the import writes back name the galaxy each construct stands
        for, and it has to be one MISP has - a MISP export used to re-import
        with `course-of-action` and `misp-attack-pattern` tags naming no galaxy
        at all, and `ransomware` and `tool` ones naming no cluster."""
        event = get_base_event()
        event['Event']['Attribute'] = [
            {
                'uuid': _IP_UUID, 'type': 'ip-src', 'value': '203.0.113.0',
                'category': 'Network activity', 'to_ids': True,
                'Galaxy': [
                    get_event()['Event']['Galaxy'][0] for get_event in (
                        get_event_with_attack_pattern_galaxy,
                        get_event_with_course_of_action_galaxy,
                        get_event_with_malware_galaxy,
                        get_event_with_tool_galaxy
                    )
                ]
            }
        ]
        parser = self._parse_internal_package(self._misp_export(event))
        self.assertEqual(parser.diagnostics()['errors'], {})
        self.assertEqual(
            self._galaxy_tags(parser.misp_event),
            {
                'misp-galaxy:mitre-attack-pattern='
                '"Access Token Manipulation - T1134"',
                'misp-galaxy:mitre-course-of-action='
                '"Automated Exfiltration Mitigation - T1020"',
                'misp-galaxy:mitre-malware="BISCUIT - S0017"',
                'misp-galaxy:mitre-tool="cmd - S0106"'
            }
        )

    def test_external_tlp_marking_writes_one_taxonomy_entry(self):
        """A TLP colour is written into a taxonomy tag of the library's own: it
        names one entry of the `tlp` taxonomy, whatever the colour carries."""
        stix_package = self._external_package()
        header = STIXHeader()
        marking = MarkingSpecification()
        tlp_marking = TLPMarkingStructure()
        tlp_marking.color = 'AMBER" tlp:red'
        marking.marking_structures.append(tlp_marking)
        handling = Marking()
        handling.add_marking(marking)
        header.handling = handling
        stix_package.stix_header = header
        parser = self._parse_external_package(stix_package)
        tags = {tag['name'] for tag in parser.misp_event.tags}
        self.assertIn('tlp:amber tlp:red', tags)
        self.assertNotIn('tlp:amber" tlp:red', tags)

    ############################################################################
    #                          TTP EXPLOIT TARGETS.                            #
    ############################################################################

    @staticmethod
    def _ttp_with_exploit_target_cve(cve_id):
        """A TTP whose content is an exploit target: the documented way a CVE
        reaches a MISP `vulnerability` attribute."""
        ttp = TTP()
        ttp.id_ = f'MISP:TTP-{_ACTOR_UUID}'
        vulnerability = Vulnerability()
        vulnerability.cve_id = cve_id
        exploit_target = ExploitTarget()
        exploit_target.add_vulnerability(vulnerability)
        ttp.add_exploit_target(exploit_target)
        return ttp

    def test_external_ttp_exploit_target_converts_to_vulnerability(self):
        """A CVE carried by an exploit target lands as a `vulnerability`
        attribute - the content check reads the `vulnerabilities` field the
        `stix` library defines, not the `vulnerability` it does not."""
        stix_package = STIXPackage()
        stix_package.add_ttp(
            self._ttp_with_exploit_target_cve('CVE-2021-44228')
        )
        parser = self._parse_external_package(stix_package)
        attribute = parser.misp_event.attributes[0]
        self.assertEqual(attribute.type, 'vulnerability')
        self.assertEqual(attribute.value, 'CVE-2021-44228')

    ############################################################################
    #                         PARSER STATE ISOLATION.                          #
    ############################################################################

    def _external_package_with_state(self):
        """A package exercising every accumulator the External parser keeps: the
        DNS bookkeeping (the URL/IP pair), the references (the related object of
        an observable with no value of its own) and the galaxies."""
        stix_package = STIXPackage()
        stix_package.add_indicator(self._url_indicator('http://evil.example/a'))
        stix_package.add_indicator(self._ip_indicator('198.51.100.4'))
        stix_package.add_threat_actor(self._threat_actor('APT-A'))
        stix_package.observables = Observables(
            [self._observable_with_related_object()]
        )
        return stix_package

    @staticmethod
    def _event_content(misp_event):
        # A package with no timestamp of its own leaves the event without a
        # date and a timestamp at all, so neither can simply be read
        return {
            'info': misp_event.info,
            'date': str(getattr(misp_event, 'date', None)),
            'timestamp': getattr(misp_event, 'timestamp', None),
            'tags': sorted(tag['name'] for tag in misp_event.tags),
            'attributes': sorted(
                (attribute.type, attribute.value)
                for attribute in misp_event.attributes
            ),
            'objects': sorted(
                (misp_object.name, attribute.object_relation, attribute.value)
                for misp_object in misp_event.objects
                for attribute in misp_object.attributes
            )
        }

    def test_external_parser_reused_for_a_second_package_starts_clean(self):
        """The event a reused parser builds from a package has to be the event a
        fresh parser builds from it: the first package's DNS bookkeeping,
        references and galaxies are its own, and a second package inheriting
        them takes in content no document of its own ever carried."""
        first = self._external_package_with_state()
        second = STIXPackage()
        second.add_indicator(self._domain_indicator('circl.lu'))
        expected = self._event_content(
            self._parse_external_package(second).misp_event
        )
        parser = self._parse_external_package(first)
        # the first package's own event is the one it gets on a fresh parser
        self.assertEqual(
            self._event_content(parser.misp_event),
            self._event_content(
                self._parse_external_package(first).misp_event
            )
        )
        self._parse_external_package(second, parser)
        self.assertEqual(self._event_content(parser.misp_event), expected)
        self.assertEqual(parser.galaxies, set())
        self.assertEqual(parser.references, {})
        self.assertEqual(parser.dns_objects, {})
        self.assertEqual(parser.dns_ips, [])

    def test_internal_parser_reused_for_a_second_package_starts_clean(self):
        """The Internal parser merges every related package of one document
        into one event - the titles, dates and timestamps of all of them - so a
        reused instance has to drop them between documents, or the second event
        is named after both and dated from whichever is the later."""
        first_incident = Incident()
        first_incident.title = 'Event A'
        first_incident.timestamp = datetime(2026, 7, 1, 12, 0)
        first = self._internal_package(
            first_incident, threat_actor=self._threat_actor('APT-A')
        )
        second_incident = self._incident_with_content()
        second_incident.title = 'Event B'
        second_incident.timestamp = datetime(2026, 1, 15, 8, 0)
        second = self._internal_package(second_incident)
        expected = self._event_content(
            self._parse_internal_package(second).misp_event
        )
        parser = self._parse_internal_package(first)
        # the first package's own event is the one it gets on a fresh parser
        self.assertEqual(
            self._event_content(parser.misp_event),
            self._event_content(
                self._parse_internal_package(first).misp_event
            )
        )
        self._parse_internal_package(second, parser)
        self.assertEqual(self._event_content(parser.misp_event), expected)
        self.assertEqual(parser.misp_event.info, 'Event B')
        self.assertEqual(parser.galaxies, set())
        self.assertEqual(parser.dates, {second_incident.timestamp.date()})
        self.assertEqual(parser.titles, {'Event B'})

    ############################################################################
    #                    EXPORTED MISP CONTENT ROUND TRIP.                     #
    ############################################################################

    @staticmethod
    def _misp_event_reaching_every_import_path():
        """A MISP event whose STIX 1 export reaches each Internal parsing path:
        an attribute exported as an Observable (`to_ids` unset), one as an
        Indicator over an observable composition, one as a `Custom` CybOX
        object, one as a File byte run and two as the two names of a Windows
        service; an object exported as an Observable of a non-file CybOX type,
        one as an Indicator, one as an Indicator over an observable composition
        and one as the attack pattern of a TTP the Incident leverages."""
        event = get_base_event()
        domain = get_event_with_domain_attribute()['Event']['Attribute'][0]
        domain['to_ids'] = False
        ip_port = get_event_with_ip_port_attributes()['Event']['Attribute'][1]
        github = get_event_with_github_username_attribute()['Event']['Attribute'][0]
        pattern = get_event_with_pattern_attribute()['Event']['Attribute'][0]
        services = get_event_with_windows_service_attributes()['Event']['Attribute']
        event['Event']['Attribute'] = [domain, ip_port, github, pattern, *services]
        domain_ip = get_event_with_domain_ip_object()['Event']['Object'][0]
        process = get_event_with_process_object()['Event']['Object'][0]
        for misp_object in (domain_ip, process):
            for attribute in misp_object['Attribute']:
                attribute['to_ids'] = True
        event['Event']['Object'] = [
            get_event_with_asn_object()['Event']['Object'][0],
            get_event_with_attack_pattern_object()['Event']['Object'][0],
            domain_ip, process
        ]
        return event

    @classmethod
    def _misp_export(cls, event):
        """The package the MISP STIX 1 export writes for the event, framed the
        way the collection export frames it."""
        parser = MISPtoSTIX1EventsParser('MISP', '1.1.1')
        parser.parse_misp_event(event)
        return cls._wrapped_package(parser.stix_package)

    def test_internal_misp_export_round_trip_converts(self):
        event = self._misp_event_reaching_every_import_path()
        parser = self._parse_internal_package(self._misp_export(event))
        self.assertEqual(parser.diagnostics()['errors'], {})
        self.assertEqual(
            sorted(
                (attribute.type, attribute.value, attribute.to_ids)
                for attribute in parser.misp_event.attributes
            ),
            [
                ('domain', 'circl.lu', False),
                ('github-username', 'chrisr3d', False),
                ('ip-dst|port', '5.6.7.8|5678', True),
                ('pattern-in-file', 'P4tt3rn_1n_f1l3_t3st', True),
                ('windows-service-displayname', 'Report for bugs', False),
                ('windows-service-name', 'BUGREPORT', False)
            ]
        )
        self.assertEqual(
            {
                misp_object.name: misp_object.uuid
                for misp_object in parser.misp_event.objects
            },
            {
                misp_object['name']: misp_object['uuid']
                for misp_object in event['Event']['Object']
            }
        )
        misp_objects = {
            misp_object.name: misp_object
            for misp_object in parser.misp_event.objects
        }
        self.assertEqual(
            {
                attribute.object_relation: attribute.value
                for attribute in misp_objects['domain-ip'].attributes
            },
            {'domain': 'circl.lu', 'ip': '149.13.33.14'}
        )
        self.assertTrue(
            all(attribute.to_ids for attribute in misp_objects['process'].attributes)
        )
        self.assertFalse(
            any(attribute.to_ids for attribute in misp_objects['asn'].attributes)
        )
        self.assertIn(
            'name',
            [attribute.object_relation
             for attribute in misp_objects['attack-pattern'].attributes]
        )

    def test_internal_misp_export_target_attributes_round_trip(self):
        """The export writes a `target-*` attribute as a Victim of the
        Incident - a CIQ identity filling the one field its type is told by,
        named with the Record Title - and a `target-machine` as an Affected
        Asset whose description folds the comment behind the value. The import
        never visited either: six attributes exported, none read back."""
        event = get_event_with_target_attributes()
        parser = self._parse_internal_package(self._misp_export(event))
        self.assertEqual(parser.diagnostics()['errors'], {})
        exported = {
            attribute['type']: attribute
            for attribute in event['Event']['Attribute']
        }
        converted = {
            attribute.type: attribute
            for attribute in parser.misp_event.attributes
        }
        self.assertEqual(set(converted), set(exported))
        for attribute_type, attribute in exported.items():
            with self.subTest(type=attribute_type):
                converted_attribute = converted[attribute_type]
                self.assertEqual(converted_attribute.value, attribute['value'])
                self.assertEqual(converted_attribute.category, 'Targeting data')
                self.assertFalse(converted_attribute.to_ids)
                if attribute_type == 'target-machine':
                    self.assertEqual(
                        converted_attribute.comment, attribute['comment']
                    )
                else:
                    self.assertEqual(converted_attribute.uuid, attribute['uuid'])

    def test_internal_affected_asset_description_is_split_on_the_last_parenthesis(self):
        """The export writes `{value} ({comment})` as the description of the
        Affected Asset a `target-machine` is - the value alone when the
        attribute carries no comment. The last ` (` is the export's own,
        whatever parentheses the value holds; the element has no id, so the
        uuid is pymisp's."""
        incident = self._incident_with_content()
        for description in ('plain.machine', 'machine (v2) (Comment on the machine)'):
            affected_asset = AffectedAsset()
            affected_asset.description = description
            incident.add_affected_asset(affected_asset)
        parser = self._parse_internal_package(self._internal_package(incident))
        self.assertEqual(parser.diagnostics()['errors'], {})
        self.assertEqual(
            sorted(
                (attribute.value, attribute.to_dict().get('comment'))
                for attribute in parser.misp_event.attributes
                if attribute.type == 'target-machine'
            ),
            [
                ('machine (v2)', 'Comment on the machine'),
                ('plain.machine', None)
            ]
        )

    def test_internal_misp_export_campaign_name_attribute_round_trips(self):
        """A `campaign-name` attribute is written as a Campaign on the package
        - the value as its name, the Record Title, the uuid, the timestamp -
        and the package context never visited the Campaigns."""
        event = get_event_with_campaign_name_attribute()
        attribute = event['Event']['Attribute'][0]
        parser = self._parse_internal_package(self._misp_export(event))
        self.assertEqual(parser.diagnostics()['errors'], {})
        self.assertEqual(
            [
                (
                    converted.uuid, converted.type, converted.category,
                    converted.value, converted.to_ids,
                    int(converted.timestamp.timestamp())
                )
                for converted in parser.misp_event.attributes
            ],
            [
                (
                    attribute['uuid'], 'campaign-name', 'Attribution',
                    'MartyMcFly', False, int(attribute['timestamp'])
                )
            ]
        )

    def _assert_attributes_round_trip(self, parser, attributes, to_ids):
        """The attributes come back with the uuid, type, category and value
        they went out with, and the timestamp when exported as Indicators -
        an Observable travels with none."""
        self.assertEqual(
            {
                converted.uuid: (
                    converted.type, converted.category,
                    converted.value, converted.to_ids
                )
                for converted in parser.misp_event.attributes
            },
            {
                attribute['uuid']: (
                    attribute['type'], attribute['category'],
                    attribute['value'], to_ids
                )
                for attribute in attributes
            }
        )
        if to_ids:
            self.assertEqual(
                {
                    converted.uuid: int(converted.timestamp.timestamp())
                    for converted in parser.misp_event.attributes
                },
                {
                    attribute['uuid']: int(attribute['timestamp'])
                    for attribute in attributes
                }
            )

    def test_internal_misp_export_test_mechanism_attributes_round_trip(self):
        """A `snort` or `yara` attribute with `to_ids` set is exported as an
        Indicator carrying the rule as a test mechanism and no observable -
        the one shape the export writes an Indicator with no observable in -
        and the import returned on the missing observable without a word.
        With `to_ids` unset both take the Custom observable route, which
        round-tripped already."""
        for to_ids in (True, False):
            with self.subTest(to_ids=to_ids):
                event = get_event_with_test_mechanism_attributes()
                for attribute in event['Event']['Attribute']:
                    attribute['to_ids'] = to_ids
                parser = self._parse_internal_package(self._misp_export(event))
                self.assertEqual(parser.diagnostics()['errors'], {})
                self._assert_attributes_round_trip(
                    parser, event['Event']['Attribute'], to_ids
                )

    def test_internal_snort_mechanism_with_several_rules_yields_one_attribute_per_rule(self):
        """The export writes one rule per Snort mechanism; python-stix lets a
        mechanism carry several. Each is a `snort` attribute of its own under
        the Indicator's category, the Indicator's uuid on the first - the rest
        take pymisp's."""
        incident = self._incident_with_content()
        indicator = Indicator()
        indicator.id_ = f'MISP:Indicator-{_IP_UUID}'
        test_mechanism = SnortTestMechanism()
        test_mechanism.rules = list(_SNORT_RULES)
        indicator.add_test_mechanism(test_mechanism)
        incident.related_indicators.append(
            RelatedIndicator(indicator, relationship='Network activity')
        )
        parser = self._parse_internal_package(self._internal_package(incident))
        self.assertEqual(parser.diagnostics()['errors'], {})
        snort_attributes = [
            attribute for attribute in parser.misp_event.attributes
            if attribute.type == 'snort'
        ]
        self.assertEqual(
            [
                (attribute.category, attribute.value, attribute.to_ids)
                for attribute in snort_attributes
            ],
            [('Network activity', rule, True) for rule in _SNORT_RULES]
        )
        self.assertEqual(
            [attribute.uuid == _IP_UUID for attribute in snort_attributes],
            [True, False]
        )

    def test_internal_indicator_with_neither_observable_nor_rule_records_an_error(self):
        """An Indicator with no observable carries rules in a MISP export; one
        carrying neither - no mechanism at all, or a mechanism of a known type
        with no rule text - is no export of ours, and the error names it where
        the import returned without a word. The rest of the event converts."""
        for shape in ('no mechanism', 'yara mechanism with no rule'):
            with self.subTest(shape=shape):
                incident = self._incident_with_content()
                indicator = Indicator()
                indicator.id_ = f'MISP:Indicator-{_IP_UUID}'
                if shape != 'no mechanism':
                    indicator.add_test_mechanism(YaraTestMechanism())
                incident.related_indicators.append(
                    RelatedIndicator(indicator, relationship='Network activity')
                )
                parser = self._parse_internal_package(
                    self._internal_package(incident)
                )
                self.assertEqual(
                    [
                        (attribute.type, attribute.value)
                        for attribute in parser.misp_event.attributes
                    ],
                    [('domain', 'circl.lu')]
                )
                self.assertEqual(
                    parser.diagnostics()['errors'],
                    {
                        'misp event': [
                            'Unable to convert the Indicator with id '
                            f'MISP:Indicator-{_IP_UUID}: no observable or test '
                            'mechanism rule to read a MISP attribute from'
                        ]
                    }
                )

    def test_internal_victim_of_an_unreadable_shape_records_an_error(self):
        """A Victim is read for the one CIQ identity field the export fills -
        which tells the `target-*` type - and the Record Title it is named
        with - which tells the category. One filling no field or several, or
        named with no Record Title, is no export of ours: the error names it
        where the import dropped it without a word, and the rest of the event
        converts."""
        no_field = 'no single CIQ identity field to read a target attribute from'
        for shape, reason in (
                ('empty specification', no_field),
                ('two fields', no_field),
                ('no Record Title', 'no MISP category to read off its name')):
            incident = self._incident_with_content()
            identity = CIQIdentity3_0Instance()
            identity.id_ = f'MISP:Identity-{_ACTOR_UUID}'
            identity.name = (
                'Some organisation' if shape == 'no Record Title'
                else 'Targeting data: nobody (MISP Attribute)'
            )
            identity.specification = STIXCIQIdentity3_0()
            if shape != 'empty specification':
                identity.specification.add_electronic_address_identifier(
                    ElectronicAddressIdentifier(value='target@email.test')
                )
            if shape == 'two fields':
                identity.specification.party_name = PartyName(
                    organisation_names=['Blizzard']
                )
            incident.add_victim(identity)
            with self.subTest(shape=shape):
                parser = self._parse_internal_package(
                    self._internal_package(incident)
                )
                self.assertEqual(
                    [attribute.type for attribute in parser.misp_event.attributes],
                    ['domain']
                )
                self.assertIn(
                    'Unable to convert the Victim identity with id '
                    f'MISP:Identity-{_ACTOR_UUID}: {reason}',
                    parser.diagnostics()['errors']['misp event']
                )

    def test_internal_affected_asset_without_description_records_an_error(self):
        """The description is all an Affected Asset carries of the
        `target-machine` it was: one with none is no export of ours, and the
        error names the Incident, the one id near it."""
        incident = self._incident_with_content()
        incident.add_affected_asset(AffectedAsset())
        parser = self._parse_internal_package(self._internal_package(incident))
        self.assertEqual(
            [attribute.type for attribute in parser.misp_event.attributes],
            ['domain']
        )
        self.assertIn(
            'Unable to convert an Affected Asset of the Incident with id '
            f'{incident.id_}: no description to read a target-machine '
            'attribute from',
            parser.diagnostics()['errors']['misp event']
        )

    def test_internal_campaign_without_name_records_an_error(self):
        """The name is where the export writes the value of a `campaign-name`:
        a Campaign carrying none is no export of ours, and the error names
        it."""
        campaign = Campaign()
        campaign.id_ = f'MISP:Campaign-{_ACTOR_UUID}'
        campaign.title = 'Attribution: nothing (MISP Attribute)'
        inner_package = STIXPackage()
        inner_package.add_incident(self._incident_with_content())
        inner_package.add_campaign(campaign)
        parser = self._parse_internal_package(
            self._wrapped_package(inner_package)
        )
        self.assertEqual(
            [attribute.type for attribute in parser.misp_event.attributes],
            ['domain']
        )
        self.assertIn(
            f'Unable to convert the Campaign with id MISP:Campaign-{_ACTOR_UUID}: '
            'no name to read a campaign-name attribute from',
            parser.diagnostics()['errors']['misp event']
        )

    def test_internal_misp_export_event_galaxies_round_trip_as_tags(self):
        """The export writes an event galaxy the way it writes the MISP object
        of the same kind - a TTP the Incident leverages, a Course of Action it
        takes - and the import told the two apart by that reference alone: an
        attack pattern or vulnerability cluster came back as an object, a
        malware or tool one as nothing at all. Each cluster is its tag, and
        only its tag."""
        for get_event in (
                get_event_with_attack_pattern_galaxy,
                get_event_with_course_of_action_galaxy,
                get_event_with_malware_galaxy,
                get_event_with_threat_actor_galaxy,
                get_event_with_tool_galaxy,
                get_event_with_vulnerability_galaxy):
            event = get_event()
            galaxy = event['Event']['Galaxy'][0]
            cluster = galaxy['GalaxyCluster'][0]
            with self.subTest(galaxy=galaxy['type']):
                parser = self._parse_internal_package(self._misp_export(event))
                self.assertEqual(parser.diagnostics()['errors'], {})
                self.assertEqual(
                    self._galaxy_tags(parser.misp_event),
                    {f'misp-galaxy:{galaxy["type"]}="{cluster["value"]}"'}
                )
                self.assertEqual(parser.misp_event.objects, [])
                self.assertEqual(parser.misp_event.attributes, [])

    def test_internal_misp_export_course_of_action_object_round_trips(self):
        """A `course-of-action` object is written as a Course of Action the
        Incident takes, as a course of action galaxy is - and every Course of
        Action of the package came back as a galaxy tag, the object lost. The
        object carries the fields a cluster has none of, and the Incident
        takes it stamped with the object's timestamp: it comes back as the
        object it was, next to the tag the cluster is."""
        event = get_event_with_course_of_action_object()
        event['Event']['Galaxy'] = get_event_with_course_of_action_galaxy()['Event']['Galaxy']
        parser = self._parse_internal_package(self._misp_export(event))
        self.assertEqual(parser.diagnostics()['errors'], {})
        misp_object = event['Event']['Object'][0]
        self.assertEqual(
            [
                (
                    converted.name, converted.uuid,
                    {
                        attribute.object_relation: attribute.value
                        for attribute in converted.attributes
                    }
                )
                for converted in parser.misp_event.objects
            ],
            [
                (
                    'course-of-action', misp_object['uuid'],
                    {
                        attribute['object_relation']: attribute['value']
                        for attribute in misp_object['Attribute']
                    }
                )
            ]
        )
        self.assertEqual(
            self._galaxy_tags(parser.misp_event),
            {
                'misp-galaxy:mitre-course-of-action='
                '"Automated Exfiltration Mitigation - T1020"'
            }
        )

    def test_internal_misp_export_course_of_action_object_is_told_by_either_signal(self):
        """The two things a `course-of-action` object leaves on the export and
        a cluster does not - the fields beyond a name and a description, the
        timestamp the Incident takes it with - each tell it on their own: an
        object stripped of one still comes back as an object."""
        for stripped in ('timestamp', 'fields'):
            event = get_event_with_course_of_action_object()
            misp_object = event['Event']['Object'][0]
            if stripped == 'timestamp':
                del misp_object['timestamp']
            else:
                misp_object['Attribute'] = [
                    attribute for attribute in misp_object['Attribute']
                    if attribute['object_relation'] in ('name', 'description')
                ]
            with self.subTest(stripped=stripped):
                parser = self._parse_internal_package(self._misp_export(event))
                self.assertEqual(parser.diagnostics()['errors'], {})
                self.assertEqual(
                    [
                        (
                            converted.name,
                            {
                                attribute.object_relation: attribute.value
                                for attribute in converted.attributes
                            }
                        )
                        for converted in parser.misp_event.objects
                    ],
                    [
                        (
                            'course-of-action',
                            {
                                attribute['object_relation']: attribute['value']
                                for attribute in misp_object['Attribute']
                            }
                        )
                    ]
                )
                self.assertEqual(self._galaxy_tags(parser.misp_event), set())

    def test_internal_misp_export_pe_section_header_with_one_field_round_trips(self):
        """The export writes a section header as soon as the `pe-section`
        object carries a `name` or a `size-in-bytes`, each set on its own; the
        import read both fields of the header it found. A section carrying one
        of them cost the whole document when the `pe` object was an Indicator,
        and the section - as a recorded error - when it was an Observable. An
        absent header field is an absent attribute, nothing more."""
        for field in ('name', 'size-in-bytes'):
            for to_ids in (True, False):
                event = get_event_with_pe_objects()
                pe_object, section = event['Event']['Object']
                for attribute in pe_object['Attribute']:
                    if attribute['object_relation'] == 'original-filename':
                        attribute['to_ids'] = to_ids
                section['Attribute'] = [
                    attribute for attribute in section['Attribute']
                    if attribute['object_relation'] == field
                ]
                with self.subTest(field=field, to_ids=to_ids):
                    parser = self._parse_internal_package(self._misp_export(event))
                    self.assertEqual(parser.diagnostics()['errors'], {})
                    sections = parser.misp_event.get_objects_by_name('pe-section')
                    self.assertEqual(
                        [
                            {
                                attribute.object_relation: str(attribute.value)
                                for attribute in converted.attributes
                            }
                            for converted in sections
                        ],
                        [{field: section['Attribute'][0]['value']}]
                    )
                    converted_pe = parser.misp_event.get_objects_by_name('pe')[0]
                    self.assertIn(
                        ('includes', sections[0].uuid),
                        [
                            (reference.relationship_type, reference.referenced_uuid)
                            for reference in converted_pe.references
                        ]
                    )

    @staticmethod
    def _converted_content(misp_object):
        """The relation, type and value of every attribute an object came back
        with - a datetime spelt the way the MISP JSON spells it, pymisp having
        parsed it into a `datetime`."""
        content = []
        for attribute in misp_object.attributes:
            value = attribute.value
            if isinstance(value, datetime):
                value = value.strftime('%Y-%m-%dT%H:%M:%SZ')
            content.append(
                (attribute.object_relation, attribute.type, str(value))
            )
        return sorted(content)

    @staticmethod
    def _exported_content(misp_object: dict):
        """The same, off the MISP object the event carried."""
        return sorted(
            (
                attribute['object_relation'], attribute['type'],
                attribute['value']
            )
            for attribute in misp_object['Attribute']
        )

    @staticmethod
    def _references(misp_object):
        return [
            (reference.relationship_type, reference.referenced_uuid)
            for reference in misp_object.references
        ]

    def test_internal_misp_export_pe_objects_round_trip(self):
        """A `pe` object with no file content is one `WinExecutableFile`
        spread over six carriers, of which the import read two: thirteen of
        the fifteen attributes were dropped in silence, and the object's uuid
        went to an empty `file` object the event never had. Every carrier is
        read now, the `pe` keeps its uuid, and the section takes a uuid
        derived from it - cybox `PESection` carries none."""
        event = get_event_with_pe_objects()
        pe_object, section_object = event['Event']['Object']
        parser = self._parse_internal_package(self._misp_export(event))
        self.assertEqual(parser.diagnostics()['errors'], {})
        self.assertEqual(parser.diagnostics()['warnings'], {})
        self.assertEqual(
            sorted(misp_object.name for misp_object in parser.misp_event.objects),
            ['pe', 'pe-section']
        )
        converted_pe = parser.misp_event.get_objects_by_name('pe')[0]
        converted_section = parser.misp_event.get_objects_by_name('pe-section')[0]
        self.assertEqual(converted_pe.uuid, pe_object['uuid'])
        self.assertEqual(
            converted_section.uuid,
            str(uuid5(_UUIDv4, f"{pe_object['uuid']} - pe - sections - 0"))
        )
        self.assertEqual(
            self._converted_content(converted_pe),
            self._exported_content(pe_object)
        )
        self.assertEqual(
            self._converted_content(converted_section),
            self._exported_content(section_object)
        )
        self.assertEqual(
            self._references(converted_pe),
            [('includes', converted_section.uuid)]
        )

    def test_internal_misp_export_full_pe_object_round_trips(self):
        """Every relation the `pe` template defines, over every carrier the
        export spreads them on: the four hashes typed by the length of their
        value on the PE file header, the nine the version info resource folds
        the spelling of, and the custom properties the rest travel as, the
        ones carrying several values included."""
        event = get_event_with_full_pe_object()
        pe_object = event['Event']['Object'][0]
        parser = self._parse_internal_package(self._misp_export(event))
        self.assertEqual(parser.diagnostics()['errors'], {})
        self.assertEqual(parser.diagnostics()['warnings'], {})
        converted_pe = parser.misp_event.get_objects_by_name('pe')[0]
        self.assertEqual(converted_pe.uuid, pe_object['uuid'])
        self.assertEqual(
            self._converted_content(converted_pe),
            self._exported_content(pe_object)
        )

    def test_internal_misp_export_file_and_pe_objects_round_trip(self):
        """A `file` and the `pe` under it are one `WinExecutableFile`: the
        file keeps the uuid and the `pe` takes a derived one, its
        `original-filename` read off the version info resource rather than
        off the file's own name."""
        event = get_event_with_file_and_pe_objects()
        file_object, pe_object, section_object = event['Event']['Object']
        parser = self._parse_internal_package(self._misp_export(event))
        self.assertEqual(parser.diagnostics()['errors'], {})
        self.assertEqual(parser.diagnostics()['warnings'], {})
        converted_file = parser.misp_event.get_objects_by_name('file')[0]
        converted_pe = parser.misp_event.get_objects_by_name('pe')[0]
        converted_section = parser.misp_event.get_objects_by_name('pe-section')[0]
        self.assertEqual(converted_file.uuid, file_object['uuid'])
        self.assertEqual(
            converted_pe.uuid,
            str(uuid5(_UUIDv4, f"{file_object['uuid']} - pe"))
        )
        self.assertEqual(
            converted_section.uuid,
            str(uuid5(_UUIDv4, f"{file_object['uuid']} - pe - sections - 0"))
        )
        for converted, exported in (
                (converted_file, file_object), (converted_pe, pe_object),
                (converted_section, section_object)):
            with self.subTest(name=exported['name']):
                self.assertEqual(
                    self._converted_content(converted),
                    self._exported_content(exported)
                )
        self.assertEqual(
            self._references(converted_file), [('includes', converted_pe.uuid)]
        )
        self.assertEqual(
            self._references(converted_pe),
            [('includes', converted_section.uuid)]
        )

    def test_internal_misp_export_file_with_one_attribute_keeps_its_pe(self):
        """One or two file attributes fold into a single MISP attribute, which
        has nowhere to reference the `pe` from: the `pe` sat in the event
        referenced by nothing. A file carrying a `pe` is an object however few
        attributes it has."""
        event = get_event_with_file_and_pe_objects()
        file_object = event['Event']['Object'][0]
        file_object['Attribute'] = [
            attribute for attribute in file_object['Attribute']
            if attribute['object_relation'] == 'filename'
        ]
        parser = self._parse_internal_package(self._misp_export(event))
        self.assertEqual(parser.diagnostics()['errors'], {})
        self.assertEqual(
            sorted(misp_object.name for misp_object in parser.misp_event.objects),
            ['file', 'pe', 'pe-section']
        )
        self.assertEqual(parser.misp_event.attributes, [])
        converted_file = parser.misp_event.get_objects_by_name('file')[0]
        converted_pe = parser.misp_event.get_objects_by_name('pe')[0]
        self.assertEqual(converted_file.uuid, file_object['uuid'])
        self.assertEqual(
            self._converted_content(converted_file),
            self._exported_content(file_object)
        )
        self.assertEqual(
            self._references(converted_file), [('includes', converted_pe.uuid)]
        )

    def test_internal_misp_export_pe_objects_to_ids_round_trips(self):
        """The export folds the file, the `pe` and every section into one
        `to_ids` decision: the import applied it to the file's attributes only,
        and the two halves of one object disagreed, in both directions."""
        for to_ids in (False, True):
            with self.subTest(to_ids=to_ids):
                event = get_event_with_file_and_pe_objects()
                for misp_object in event['Event']['Object']:
                    for attribute in misp_object['Attribute']:
                        attribute['to_ids'] = to_ids
                parser = self._parse_internal_package(self._misp_export(event))
                self.assertEqual(parser.diagnostics()['errors'], {})
                self.assertEqual(
                    {
                        (misp_object.name, attribute.to_ids)
                        for misp_object in parser.misp_event.objects
                        for attribute in misp_object.attributes
                    },
                    {('file', to_ids), ('pe', to_ids), ('pe-section', to_ids)}
                )

    def test_internal_record_misp_refuses_costs_that_record_only(self):
        """A package of two events, the first carrying a journal entry naming
        an attribute type MISP has not: pymisp refuses the attribute, and the
        refusal used to escape `parse_stix_package()` with the whole package -
        the second event, every other record of the first, and the
        diagnostics that would have said so. The one attribute is the loss,
        and the Error names the record and where it came from."""
        first = self._incident_with_content()
        first.id_ = f'MISP:Incident-{_PLAIN_OBJECT_UUID}'
        history = History()
        history_item = HistoryItem()
        history_item.journal_entry = JournalEntry(
            'attribute[Other][no-such-type]: what MISP has no type for'
        )
        history.append(history_item)
        first.history = history
        second = Incident()
        second.id_ = f'MISP:Incident-{_RELATED_UUID}'
        url = URI()
        url.value = 'http://example.com/malicious'
        second.related_observables.append(
            RelatedObservable(
                self._observable(url, 'URI', _URL_UUID),
                relationship='Network activity'
            )
        )
        stix_package = STIXPackage()
        stix_package.related_packages = RelatedPackages()
        for incident in (first, second):
            inner_package = STIXPackage()
            inner_package.add_incident(incident)
            stix_package.related_packages.append(RelatedPackage(inner_package))
        parser = self._parse_internal_package(stix_package)
        self.assertEqual(
            sorted(
                (attribute.type, attribute.value)
                for attribute in parser.misp_event.attributes
            ),
            [
                ('domain', 'circl.lu'),
                ('url', 'http://example.com/malicious')
            ]
        )
        errors = parser.diagnostics()['errors']['misp event']
        self.assertEqual(len(errors), 1)
        self.assertIn('no-such-type attribute', errors[0])
        self.assertIn('what MISP has no type for', errors[0])
        self.assertIn(_PLAIN_OBJECT_UUID, errors[0])

    def test_internal_hash_types_the_wire_renames_round_trip(self):
        """cybox types a hash by the length of its value, so the sixteen hash
        types the export writes as a `Hash` come back as the eleven cybox has
        names for: the table is the documented loss, and a future change has
        to move a row of it deliberately. `Type=Other` is the fallback for a
        length cybox names nothing for - an ssdeep and a tlsh shape name
        themselves, and what neither names stays the MISP `other` type."""
        values = {
            hash_type: attribute['value']
            for hash_type, attribute in get_hash_attributes().items()
        }
        values.update({'cdhash': _CDHASH, 'impfuzzy': _IMPFUZZY_HASH})
        self.assertEqual(
            sorted(_HASH_TYPE_ROUND_TRIP),
            sorted(MISPtoSTIX1Mapping.hash_type_attributes('single'))
        )
        for hash_type, expected in _HASH_TYPE_ROUND_TRIP.items():
            with self.subTest(hash_type=hash_type):
                hash_property = MISPtoSTIX1EventsParser._parse_hash_value(
                    hash_type, values[hash_type]
                )
                self.assertEqual(
                    InternalSTIX1toMISPParser._handle_hashes_attribute(
                        hash_property
                    ),
                    (expected, values[hash_type], expected)
                )

    def test_internal_misp_export_hash_composite_attributes_round_trip(self):
        """A `filename|<hash>` attribute exports as a `File` carrying the file
        name and the hash, and the composite type is rebuilt from the hash
        type read off the wire: `filename|other`, which MISP has no such type
        for, was handed to pymisp, which refused it - out of
        `parse_stix_package()`, costing the whole package. The composite is
        checked against MISP's own types now, and the residue comes back as
        the two attributes its halves are, both `to_ids` variants over."""
        for to_ids in (False, True):
            with self.subTest(to_ids=to_ids):
                event = get_event_with_hash_composite_attributes(to_ids)
                parser = self._parse_internal_package(self._misp_export(event))
                self.assertEqual(parser.diagnostics()['errors'], {})
                expected = []
                for attribute in event['Event']['Attribute']:
                    filename, _, hash_value = attribute['value'].rpartition('|')
                    hash_type = attribute['type'].split('|')[1]
                    # A type the export writes as a `Hash` comes back as the
                    # one cybox named it; the rest travels as a custom
                    # attribute, under the type it was written with
                    read_back = _HASH_TYPE_ROUND_TRIP.get(hash_type, hash_type)
                    if f'filename|{read_back}' in describe_types['types']:
                        expected.append(
                            (f'filename|{read_back}', attribute['value'])
                        )
                        continue
                    expected.extend(
                        (('filename', filename), (read_back, hash_value))
                    )
                self.assertEqual(
                    [
                        (attribute.type, attribute.value)
                        for attribute in parser.misp_event.attributes
                    ],
                    expected
                )
                # The hash is the value the attribute existed for, so it keeps
                # the uuid of the Observable; the file name qualifying it takes
                # a random one, as every other import-side attribute does
                residue = [
                    attribute for attribute in parser.misp_event.attributes
                    if attribute.type in ('filename', 'other')
                ]
                self.assertEqual(
                    [attribute.type for attribute in residue],
                    ['filename', 'other']
                )
                self.assertEqual(
                    residue[1].uuid,
                    get_hash_attributes()['vhash']['uuid']
                )
                self.assertNotEqual(
                    residue[0].uuid, get_hash_attributes()['vhash']['uuid']
                )
                # Both halves keep what the attribute they came from carried -
                # the comment on the Indicator a `to_ids` attribute is
                # written as, an Observable carrying none (ADR-0015, ticket 16)
                for attribute in residue:
                    self.assertEqual(attribute.to_ids, to_ids)
                    self.assertEqual(
                        attribute.get('comment'),
                        'Filename|vhash test attribute' if to_ids else None
                    )
                self.assertEqual(
                    parser.diagnostics()['warnings']['misp event'],
                    [
                        'Unknown hash type in the object with id MISP:File-'
                        f"{get_hash_attributes()['vhash']['uuid']}: "
                        f"{get_hash_attributes()['vhash']['value']} read as "
                        'an other hash.',
                        "'filename|other' is no MISP attribute type in the "
                        'object with id MISP:File-'
                        f"{get_hash_attributes()['vhash']['uuid']}: "
                        'filename14 and '
                        f"{get_hash_attributes()['vhash']['value']} converted "
                        'separately.'
                    ]
                )

    def _assert_relations_round_trip(self, converted, exported, relations):
        """Every named relation back under its own spelling, with the type and
        the value the MISP object had."""
        content = self._converted_content(converted)
        self.assertEqual(
            [entry for entry in content if entry[0] in relations],
            [
                entry for entry in self._exported_content(exported)
                if entry[0] in relations
            ]
        )

    @staticmethod
    def _object_fixtures():
        """Every MISP event fixture carrying objects: the corpus the round
        trip baseline below is measured over."""
        for name, fixture in sorted(vars(test_events).items()):
            if not name.startswith('get_event_with_'):
                continue
            if not inspect.isfunction(fixture):
                continue
            if inspect.signature(fixture).parameters:
                continue
            event = fixture()
            if event.get('Event', {}).get('Object'):
                yield name, event

    @staticmethod
    def _pair_objects(exported: list, converted: list):
        """Pair each exported MISP object with the one it came back as - by
        uuid, then by name, so an object taking a derived uuid by design is
        still measured on its content."""
        remaining = list(converted)
        for misp_object in exported:
            match = None
            for candidate in remaining:
                if candidate.uuid == misp_object['uuid']:
                    match = candidate
                    break
            if match is None:
                for candidate in remaining:
                    if candidate.name == misp_object['name']:
                        match = candidate
                        break
            if match is not None:
                remaining.remove(match)
            yield misp_object, match

    def test_internal_misp_export_object_corpus_round_trip_baseline(self):
        """The ledger of what a STIX 1 round trip of the whole fixture corpus
        still loses: 664 of the 719 object attributes come back, and every row
        below names the ticket that owns its gap. `n -> n` is not the
        assertion - the campaign is not over - and the table is what fails on
        a regression and on an improvement nobody wrote down."""
        losses = {}
        for name, event in self._object_fixtures():
            exported = event['Event']['Object']
            try:
                stix_package = self._misp_export(event)
            except Exception as exception:
                losses[(name, -1)] = (
                    f'export error: {type(exception).__name__}', (), ()
                )
                continue
            parser = self._parse_internal_package(stix_package)
            for index, (misp_object, converted) in enumerate(
                    self._pair_objects(exported, parser.misp_event.objects)):
                in_relations = Counter(
                    attribute['object_relation']
                    for attribute in misp_object['Attribute']
                )
                out_relations = Counter(
                    attribute.object_relation
                    for attribute in converted.attributes
                ) if converted is not None else Counter()
                lost = tuple(sorted((in_relations - out_relations).elements()))
                gained = tuple(sorted((out_relations - in_relations).elements()))
                if lost or gained:
                    losses[(name, index)] = (misp_object['name'], lost, gained)
        # The last element of each row names the owning ticket, which is
        # documentation rather than measurement: it is not compared
        self.assertEqual(
            losses,
            {key: row[:-1] for key, row in _CORPUS_ROUND_TRIP_LOSSES.items()}
        )

    @staticmethod
    def _cybox_hash_types():
        """Every hash type cybox's own vocabulary holds, lowercased the way
        the import reads them."""
        return sorted(
            str(getattr(Hash, name)).lower()
            for name in vars(Hash) if name.startswith('TYPE_')
        )

    def _table_entries(self, table: dict, shape: str):
        """The MISP type and the object relation each entry of an import
        mapping table names - `None` for a type the table leaves to the
        template. A relation carrying a `{}` is one per network feature."""
        for key, entry in table.items():
            if shape == 'relation':
                attribute_type, relation = None, entry
            elif shape == 'key':
                # The relations of a `course-of-action` are the keys
                # themselves, and every one of them is text
                attribute_type, relation = 'text', key.replace('_', '')
            elif shape == 'type-relation':
                attribute_type, relation = entry
            else:
                attribute_type, _, relation = entry
            if '{}' in relation:
                for feature in STIX1toMISPMapping.network_fields():
                    yield (
                        attribute_type.format(feature), relation.format(feature)
                    )
                continue
            yield attribute_type, relation

    def test_import_mapping_tables_agree_with_the_object_templates(self):
        """The template of the object a handler builds is what types the
        relations the document supplies, so a table naming a relation the
        template does not define - or typing one against the template - is
        the two sources drifting apart in silence: `whois-registrar`, the
        attribute type, stood where the `registrar` relation belongs, and
        pymisp logged every whois registrar as invalid."""
        disagreements = set()
        entries = 0
        for table_name, names, shape in self._IMPORT_MAPPING_TABLES:
            table = getattr(InternalSTIX1toMISPMapping, table_name)()
            for attribute_type, relation in self._table_entries(table, shape):
                entries += 1
                for name in names:
                    template_types = _template_attribute_types(name)
                    if relation not in template_types:
                        disagreements.add((table_name, name, relation))
                        continue
                    if attribute_type is None:
                        continue
                    self.assertEqual(
                        template_types[relation], attribute_type,
                        f'{table_name}: {relation} on the {name} template'
                    )
        # The hashes a `pe` header carries are named by a table of their own,
        # read through a per-key accessor: every cybox hash type it names a
        # relation for names a `pe` relation like any other
        pe_types = _template_attribute_types('pe')
        for hash_type in self._cybox_hash_types():
            relation = STIX1toMISPMapping.pe_header_hash_mapping(hash_type)
            if relation is None:
                continue
            entries += 1
            if relation not in pe_types:
                disagreements.add(('pe_header_hash_mapping', 'pe', relation))
        self.assertGreater(entries, 0)
        self.assertEqual(disagreements, set())

    def test_every_attribute_add_goes_through_the_guarded_funnel(self):
        """Both STIX 1 import parsers add every attribute through
        `_add_attribute`, the one place a record MISP refuses is caught: a
        call site adding one itself is guarded only by whoever remembers to,
        which is how `filename|other` came to cost whole packages. The count
        is the assertion because a new call site is a new line of code, not a
        failing test somewhere else."""
        self.assertEqual(
            {
                module.__name__.rsplit('.', 1)[1]:
                inspect.getsource(module).count('misp_event.add_attribute(')
                for module in (
                    stix1_to_misp, internal_stix1_to_misp,
                    external_stix1_to_misp
                )
            },
            {
                # The funnel itself, in the shared base
                'stix1_to_misp': 1,
                'internal_stix1_to_misp': 0,
                'external_stix1_to_misp': 0
            }
        )

    def test_internal_misp_export_property_bags_round_trip(self):
        """Every MISP object relation the export has no CybOX slot for travels
        as a custom property named after the relation itself, and the import
        read the bag of `Custom` objects and of a `pe` alone: eight more
        object types lost every relation the bag carried, in silence. The
        template of the object the handler builds is what types them back."""
        for fixture, name, relations in (
                (get_event_with_asn_object, 'asn', ('subnet-announced',)),
                (
                    get_event_with_email_with_display_names_object, 'email',
                    (
                        'from-display-name', 'to-display-name',
                        'cc-display-name', 'bcc-display-name'
                    )
                ),
                (
                    get_event_with_file_object, 'file',
                    ('attachment', 'malware-sample', 'file-encoding')
                ),
                (
                    get_event_with_mutex_object, 'mutex',
                    ('name', 'description', 'operating-system')
                ),
                (
                    get_event_with_process_object_v2, 'process',
                    ('parent-image', 'parent-command-line', 'parent-process-name')
                ),
                (
                    get_event_with_user_account_objects, 'user-account',
                    (
                        'user-id', 'group-id', 'user-avatar', 'account-type',
                        'password_last_changed'
                    )
                ),
                (
                    get_event_with_user_account_object, 'user-account',
                    (
                        'user-id', 'group', 'user-avatar',
                        'password_last_changed'
                    )
                ),
                (
                    get_event_with_x509_object, 'x509',
                    ('x509-fingerprint-md5',)
                )):
            with self.subTest(name=name):
                event = fixture()
                exported = event['Event']['Object'][0]
                parser = self._parse_internal_package(self._misp_export(event))
                self.assertEqual(parser.diagnostics()['errors'], {})
                converted = parser.misp_event.get_objects_by_name(name)[0]
                self.assertEqual(converted.uuid, exported['uuid'])
                self._assert_relations_round_trip(
                    converted, exported, relations
                )

    def test_internal_misp_export_declared_types_read_back(self):
        """A MISP object template declares the type of every relation it
        names, and the export writes a value cybox refuses - a boolean, an
        integer, a float - in XSD's lexical form under the CybOX `datatype`
        saying which (ADR-0015, session A1). Reading that name back is the
        document being read as written, not the coercion no contract allows:
        the `human` of a `parler-account` comes back as `False`, and a
        property carrying no `datatype` stays the string it is."""
        event = get_event_with_account_objects_with_attachment()
        parser = self._parse_internal_package(self._misp_export(event))
        self.assertEqual(parser.diagnostics()['errors'], {})
        converted = parser.misp_event.get_objects_by_name('parler-account')[0]
        self.assertEqual(
            {
                attribute.object_relation: attribute.value
                for attribute in converted.attributes
            },
            {
                'account-id': '42', 'account-name': 'ParlerOctocat',
                'human': False, 'profile-photo': 'octocat.png'
            }
        )
        self.assertEqual(
            [
                (attribute.object_relation, attribute.type)
                for attribute in converted.attributes
                if attribute.object_relation == 'human'
            ],
            [('human', 'boolean')]
        )

    def test_internal_declared_types_are_read_from_the_datatype_alone(self):
        """Only the `datatype` restores a type: every lexical form the export
        writes comes back, a form the declared type does not hold stays the
        string it is, and a property written before the export declared
        anything - which is every document that shipped - stays a string
        too."""
        for datatype, value, expected in (
                ('boolean', 'true', True),
                ('boolean', 'false', False),
                ('boolean', 'not a boolean', 'not a boolean'),
                ('int', '1234', 1234),
                ('long', '-4294967296', -4294967296),
                ('integer', '9' * 25, int('9' * 25)),
                ('int', 'not an integer', 'not an integer'),
                ('float', '3.5', 3.5),
                ('float', 'INF', float('inf')),
                ('float', '-INF', float('-inf')),
                ('float', 'not a float', 'not a float'),
                ('base64Binary', 'Zm9v', 'Zm9v'),
                (None, 'false', 'false')):
            with self.subTest(datatype=datatype, value=value):
                prop = Property()
                prop.name = 'human'
                if datatype is not None:
                    prop.datatype = datatype
                prop.value = value
                self.assertEqual(
                    InternalSTIX1toMISPParser._property_value(prop), expected
                )
        # A `NaN` is the one form no equality reads back
        prop = Property()
        prop.name = 'human'
        prop.datatype = 'float'
        prop.value = 'NaN'
        self.assertNotEqual(
            InternalSTIX1toMISPParser._property_value(prop),
            InternalSTIX1toMISPParser._property_value(prop)
        )

    def test_internal_misp_export_registry_key_is_not_prefixed_twice(self):
        """MISP's `key` holds its hive, CybOX's does not, and the import's
        join of `Hive` and `Key` prepended the hive to a key already carrying
        it (ticket 25). The object still folds into a `regkey` attribute -
        the right value, the wrong kind: finding 11, not this ticket."""
        for fixture in ('get_event_with_registry_key_and_values_objects',
                        'get_event_with_registry_key_and_values_objects_custom'):
            with self.subTest(fixture=fixture):
                event = getattr(test_events, fixture)()
                parser = self._parse_internal_package(self._misp_export(event))
                self.assertEqual(parser.diagnostics()['errors'], {})
                self.assertEqual(
                    parser.misp_event.get_objects_by_name('registry-key'), []
                )
                self.assertEqual(
                    [
                        (attribute.type, attribute.value)
                        for attribute in parser.misp_event.attributes
                    ],
                    [('regkey', 'hkey_local_machine\\system\\bar\\foo')]
                )

    def test_internal_misp_export_whois_dates_come_back_as_utc_midnight(self):
        """CybOX types the three `whois` dates as a `Date`: the time is gone
        on the wire, a named loss. What comes back is the midnight of the
        exported date, in UTC like every other `datetime` - not naive."""
        event = test_events.get_event_with_whois_object()
        parser = self._parse_internal_package(self._misp_export(event))
        self.assertEqual(parser.diagnostics()['errors'], {})
        converted, = parser.misp_event.get_objects_by_name('whois')
        self.assertEqual(
            {
                attribute.object_relation: attribute.value
                for attribute in converted.attributes
                if attribute.type == 'datetime'
            },
            {
                'creation-date': datetime(2017, 10, 1, tzinfo=timezone.utc),
                'modification-date': datetime(
                    2020, 10, 25, tzinfo=timezone.utc
                ),
                'expiration-date': datetime(2021, 1, 1, tzinfo=timezone.utc)
            }
        )

    def test_internal_misp_export_attack_pattern_id_loses_its_capec_prefix(self):
        """The export writes `id` `9` as the STIX 1 `capec_id` `CAPEC-9`; the
        import strips the prefix back, as the STIX 2 import does. An original
        written `CAPEC-9` returns `9` too: the wire cannot tell the two
        apart."""
        for fixture in ('get_event_with_attack_pattern_object',
                        'get_event_with_object_references'):
            for original in ('9', 'CAPEC-9'):
                with self.subTest(fixture=fixture, original=original):
                    event = getattr(test_events, fixture)()
                    exported = event['Event']['Object'][0]
                    for attribute in exported['Attribute']:
                        if attribute['object_relation'] == 'id':
                            attribute['value'] = original
                    parser = self._parse_internal_package(
                        self._misp_export(event)
                    )
                    self.assertEqual(parser.diagnostics()['errors'], {})
                    converted, = parser.misp_event.get_objects_by_name(
                        'attack-pattern'
                    )
                    self.assertEqual(
                        [
                            attribute.value
                            for attribute in converted.attributes
                            if attribute.object_relation == 'id'
                        ],
                        ['9']
                    )

    def test_internal_misp_export_asn_and_mutex_objects_round_trip_whole(self):
        """The two carriers the bag completes: every attribute they hold is
        back, under its own relation. A `mutex` object stopped folding into a
        single `mutex` attribute on the way - the properties are counted
        before the fold, and two attributes are an object."""
        for fixture, name in (
                (get_event_with_asn_object, 'asn'),
                (get_event_with_mutex_object, 'mutex')):
            with self.subTest(name=name):
                event = fixture()
                exported = event['Event']['Object'][0]
                parser = self._parse_internal_package(self._misp_export(event))
                self.assertEqual(parser.diagnostics()['errors'], {})
                self.assertEqual(parser.diagnostics()['warnings'], {})
                converted = parser.misp_event.get_objects_by_name(name)[0]
                self.assertEqual(
                    self._converted_content(converted),
                    self._exported_content(exported)
                )

    def test_internal_misp_export_credential_object_still_comes_back_as_a_user_account(self):
        """The export writes a `credential` object as a `UserAccount`, which
        the import types as a `user-account`: the template name is lost on the
        wire, and the properties are typed by a template defining neither of
        them - two `text` attributes and two warnings, under the right
        relations on the wrong object. Value and spelling survive; the object
        name is ticket 23's."""
        event = get_event_with_credential_object()
        exported = event['Event']['Object'][0]
        parser = self._parse_internal_package(self._misp_export(event))
        self.assertEqual(parser.diagnostics()['errors'], {})
        self.assertEqual(
            [misp_object.name for misp_object in parser.misp_event.objects],
            ['user-account']
        )
        converted = parser.misp_event.objects[0]
        self._assert_relations_round_trip(
            converted, exported, ('origin', 'notification')
        )
        self.assertEqual(
            {
                attribute.object_relation: attribute.type
                for attribute in converted.attributes
                if attribute.object_relation in ('origin', 'notification')
            },
            {'origin': 'text', 'notification': 'text'}
        )
        warnings = [
            warning for warnings in parser.diagnostics()['warnings'].values()
            for warning in warnings
        ]
        self.assertEqual(len(warnings), 2)
        for warning in warnings:
            self.assertIn('is no user-account object relation', warning)

    def test_internal_misp_export_file_and_pe_split_the_property_bag(self):
        """A `file` and the `pe` under it are one `WinExecutableFile` with one
        property bag: the whole of it went to the `pe`, so a `file` relation
        no CybOX field holds came back on the wrong object. The `pe` takes
        every name its own template types, the `file` what the `file`
        template types, and what neither names stays on the `pe`."""
        event = get_event_with_file_and_pe_objects()
        file_object, pe_object, _ = event['Event']['Object']
        file_object['Attribute'].append(
            {
                'type': 'text', 'object_relation': 'file-encoding',
                'value': 'UTF-8'
            }
        )
        parser = self._parse_internal_package(self._misp_export(event))
        self.assertEqual(parser.diagnostics()['errors'], {})
        self.assertEqual(parser.diagnostics()['warnings'], {})
        converted_file = parser.misp_event.get_objects_by_name('file')[0]
        converted_pe = parser.misp_event.get_objects_by_name('pe')[0]
        self.assertEqual(
            self._converted_content(converted_file),
            self._exported_content(file_object)
        )
        self.assertEqual(
            self._converted_content(converted_pe),
            self._exported_content(pe_object)
        )

    def test_internal_misp_object_ttp_with_unconvertible_content_records_an_error(self):
        """A TTP the export titles as a MISP attribute or object is read for
        the attack pattern, vulnerability or weakness those are written as:
        one carrying anything else was dropped without a word."""
        ttp = self._ttp_with_malware('Elise - S0081')
        ttp.title = 'misc: malware (MISP Object)'
        inner_package = STIXPackage()
        inner_package.add_incident(self._incident_with_content())
        inner_package.add_ttp(ttp)
        parser = self._parse_internal_package(
            self._wrapped_package(inner_package)
        )
        self.assertEqual(parser.misp_event.objects, [])
        self.assertEqual(self._galaxy_tags(parser.misp_event), set())
        self.assertIn(
            f'Unable to convert the TTP with id MISP:TTP-{_ACTOR_UUID}: no '
            'attack pattern, vulnerability, weakness or victim targeting to '
            'read a MISP attribute or object from',
            parser.diagnostics()['errors']['misp event']
        )

    def test_internal_incident_without_timestamp_converts(self):
        """A fresh Incident is stamped with the time of its creation - one an
        export left unstamped has none, and the merged event then has no date
        or timestamp to take from it rather than nothing to parse."""
        incident = self._incident_with_content()
        incident.title = 'Incident without a timestamp'
        incident.timestamp = None
        parser = self._parse_internal_package(self._internal_package(incident))
        self.assertEqual(parser.misp_event.info, 'Incident without a timestamp')
        self.assertEqual(parser.diagnostics()['errors'], {})

    ############################################################################
    #                      COMMENTS AND TAGS ROUND TRIP.                       #
    ############################################################################

    @staticmethod
    def _misp_event_carrying_comments_and_tags():
        """A MISP event whose every comment-and-tag carrier is filled: the
        event's own tags, a `to_ids` attribute exported as an Indicator, one
        with no comment at all, one with `to_ids` unset - the Observable the
        shape carries neither on - a `campaign-name`, a `vulnerability`
        exported as a TTP over an Exploit Target, and two objects, one with a
        comment of its own and one with the template's description alone."""
        event = get_base_event()
        event['Event']['Tag'] = [
            {'name': 'tlp:white'}, {'name': 'event:level="tag"'}
        ]
        domain = get_event_with_domain_attribute()['Event']['Attribute'][0]
        domain['to_ids'] = False
        domain['comment'] = 'the Observable carries no comment'
        domain['Tag'] = [{'name': 'my:lost="tag"'}]
        github = get_event_with_github_username_attribute()['Event']['Attribute'][0]
        github['to_ids'] = True
        github['comment'] = 'seen in logs'
        github['Tag'] = [
            {'name': 'tlp:amber'},
            {'name': 'misp-galaxy:mitre-attack-pattern="Phishing - T1566"'},
            {'name': 'my:custom="tag"'}
        ]
        pattern = get_event_with_pattern_attribute()['Event']['Attribute'][0]
        pattern['to_ids'] = True
        pattern.pop('comment', None)
        campaign = get_event_with_campaign_name_attribute()['Event']['Attribute'][0]
        campaign['comment'] = 'campaign comment'
        campaign['Tag'] = [{'name': 'tlp:red'}, {'name': 'my:camp="tag"'}]
        vulnerability = {
            'uuid': _VULNERABILITY_UUID, 'type': 'vulnerability',
            'category': 'External analysis', 'value': 'CVE-2021-44228',
            'to_ids': False, 'timestamp': '1603642920',
            'comment': 'log4shell',
            'Tag': [{'name': 'my:vuln="tag"'}]
        }
        event['Event']['Attribute'] = [
            domain, github, pattern, campaign, vulnerability
        ]
        commented, plain = (
            get_event_with_domain_ip_object()['Event']['Object'][0],
            get_event_with_domain_ip_object()['Event']['Object'][0]
        )
        for misp_object in (commented, plain):
            for attribute in misp_object['Attribute']:
                attribute['to_ids'] = True
                attribute['Tag'] = [{'name': 'my:inobject="tag"'}]
        commented['comment'] = 'object comment'
        plain['uuid'] = _PLAIN_OBJECT_UUID
        # The template description the export writes, spelt out rather than
        # read through the helper the conversion itself reads it with
        plain['description'] = (
            'A domain/hostname and IP address seen as a tuple in a specific '
            'time frame.'
        )
        event['Event']['Object'] = [commented, plain]
        return event

    @staticmethod
    def _attribute_context(misp_event):
        """The comment and the tags each attribute of the event came back
        with, by value."""
        return {
            attribute.value: (
                getattr(attribute, 'comment', None),
                sorted(tag.name for tag in attribute.tags)
            )
            for attribute in misp_event.attributes
        }

    def test_internal_attribute_comments_and_tags_read_back(self):
        """The export writes an attribute's comment as the Indicator's
        description - the Record Title when there is none - and its tags as
        the handling: a TLP structure for the colours, a Simple Marking per
        other tag. A `misp-galaxy:` tag the export could not write as a TTP
        travels as a Simple Marking too, and comes back as the tag it is."""
        event = self._misp_event_carrying_comments_and_tags()
        parser = self._parse_internal_package(self._misp_export(event))
        context = self._attribute_context(parser.misp_event)
        self.assertEqual(
            context['chrisr3d'],
            (
                'seen in logs',
                [
                    'misp-galaxy:mitre-attack-pattern="Phishing - T1566"',
                    'my:custom="tag"', 'tlp:amber'
                ]
            )
        )
        self.assertEqual(parser.diagnostics()['errors'], {})

    def test_internal_attribute_without_comment_reads_back_no_comment(self):
        """The description of an Indicator the attribute had no comment for is
        the Record Title, not a comment: it reads back as none."""
        event = self._misp_event_carrying_comments_and_tags()
        parser = self._parse_internal_package(self._misp_export(event))
        context = self._attribute_context(parser.misp_event)
        self.assertEqual(context['P4tt3rn_1n_f1l3_t3st'], (None, []))

    def test_internal_observable_carries_no_comment_and_no_tag(self):
        """The shape an attribute with `to_ids` unset is exported as carries
        neither: the gap is the Observable's, and stays named."""
        event = self._misp_event_carrying_comments_and_tags()
        parser = self._parse_internal_package(self._misp_export(event))
        context = self._attribute_context(parser.misp_event)
        self.assertEqual(context['circl.lu'], (None, []))

    def test_internal_campaign_comment_and_tags_read_back(self):
        """The Campaign a `campaign-name` was exported as carries both, and
        its description needs no Record Title guard: the export writes it only
        when the attribute has a comment of its own."""
        event = self._misp_event_carrying_comments_and_tags()
        parser = self._parse_internal_package(self._misp_export(event))
        context = self._attribute_context(parser.misp_event)
        self.assertEqual(
            context['MartyMcFly'],
            ('campaign comment', ['my:camp="tag"', 'tlp:red'])
        )

    def test_internal_exploit_target_comment_and_tags_read_back(self):
        """A `vulnerability` attribute travels as a TTP over an Exploit
        Target: the comment on the Exploit Target's description, the tags on
        the TTP's handling. It comes back as an attribute - the one Exploit
        Target shape that does - so both land on it."""
        event = self._misp_event_carrying_comments_and_tags()
        parser = self._parse_internal_package(self._misp_export(event))
        context = self._attribute_context(parser.misp_event)
        self.assertEqual(
            context['CVE-2021-44228'], ('log4shell', ['my:vuln="tag"'])
        )

    def test_internal_event_tags_read_back(self):
        """The event's tags travel on the Incident's handling, and the
        `misp:tool` tag as a journal entry: pymisp adds a name it already has
        once, so the entry the handling repeats is not doubled."""
        event = self._misp_event_carrying_comments_and_tags()
        parser = self._parse_internal_package(self._misp_export(event))
        tags = [tag.name for tag in parser.misp_event.tags]
        self.assertEqual(
            sorted(tags),
            [
                'event:level="tag"', 'misp:tool="MISP-STIX-Converter"',
                'tlp:white'
            ]
        )
        self.assertEqual(len(tags), len(set(tags)))

    def test_internal_object_comment_reads_back_through_the_template(self):
        """The export writes a MISP object's comment as the Indicator's
        description and falls back to the object template's own description,
        which every MISP object carries. The template is the inverse: the
        object that had a comment gets it back, the one that had none gets
        nothing rather than the template blurb."""
        event = self._misp_event_carrying_comments_and_tags()
        parser = self._parse_internal_package(self._misp_export(event))
        comments = {
            misp_object.uuid: getattr(misp_object, 'comment', None)
            for misp_object in parser.misp_event.objects
        }
        self.assertEqual(
            comments[event['Event']['Object'][0]['uuid']], 'object comment'
        )
        self.assertIsNone(comments[_PLAIN_OBJECT_UUID])

    def test_internal_object_comment_is_guarded_against_its_own_template(self):
        """The template the description is told from is the one of the object
        the content builds, not the one the Observable id names: `_define_name`
        names compositions, `Custom`, `file` and `registry-key` and nothing
        else, so an `x509` was guarded against no template at all and a `pe`
        against the `file` one. Both came back carrying the template
        description as a comment their author never wrote."""
        for getter, name, description in (
                (
                    get_event_with_pe_objects, 'pe',
                    'Object describing a Portable Executable'
                ),
                (
                    get_event_with_x509_object, 'x509',
                    'x509 object describing a X.509 certificate'
                )):
            # The template description the export writes, spelt out rather
            # than read through the helper the conversion itself reads it with
            self.assertEqual(_template_description(name), description)
            for comment in ('a comment of my own', None):
                with self.subTest(name=name, comment=comment):
                    event = getter()
                    misp_object = event['Event']['Object'][0]
                    misp_object['description'] = description
                    if comment is not None:
                        misp_object['comment'] = comment
                    for attribute in misp_object['Attribute']:
                        attribute['to_ids'] = True
                    parser = self._parse_internal_package(self._misp_export(event))
                    self.assertEqual(parser.diagnostics()['errors'], {})
                    converted = parser.misp_event.get_objects_by_name(name)[0]
                    self.assertEqual(
                        getattr(converted, 'comment', None), comment
                    )

    def test_internal_object_tags_are_dropped_with_one_warning(self):
        """A MISP object takes no tag, and the handling the export writes
        holds the tags of every attribute it held merged into one set: there
        is neither a field to write them to nor a way to tell them apart. One
        warning per converted document says so, however many objects hit it."""
        event = self._misp_event_carrying_comments_and_tags()
        parser = self._parse_internal_package(self._misp_export(event))
        self.assertEqual(
            parser.diagnostics()['warnings']['misp event'],
            [
                'MISP objects carry no tag: the markings on the STIX objects a '
                'MISP object is built from are not read back.'
            ]
        )
        for misp_object in parser.misp_event.objects:
            for attribute in misp_object.attributes:
                self.assertEqual(attribute.tags, [])

    def test_internal_attributes_collection_reads_comments_and_tags_back(self):
        """The Attribute Collection writes its Indicators on the package
        itself, with the same description and handling, and a `target-*`
        attribute as a TTP targeting an identity - the one carrier whose tags
        the Incident holds in an event export."""
        event = self._misp_event_carrying_comments_and_tags()
        target = get_event_with_target_attributes()['Event']['Attribute'][0]
        target['Tag'] = [{'name': 'my:target="tag"'}]
        attributes = [*event['Event']['Attribute'], target]
        parser = MISPtoSTIX1AttributesParser('MISP', '1.1.1')
        parser.parse_json_content({'response': {'Attribute': attributes}})
        imported = self._parse_internal_package(parser.stix_package)
        context = self._attribute_context(imported.misp_event)
        self.assertEqual(
            context['chrisr3d'],
            (
                'seen in logs',
                [
                    'misp-galaxy:mitre-attack-pattern="Phishing - T1566"',
                    'my:custom="tag"', 'tlp:amber'
                ]
            )
        )
        self.assertEqual(context[target['value']][1], ['my:target="tag"'])
        self.assertEqual(imported.diagnostics()['errors'], {})

    def test_internal_empty_simple_marking_statement_is_dropped(self):
        """A Simple Marking a taxonomy tag can be made of nothing from writes
        no tag, as a Built Tag with an empty slot does - never an empty one."""
        incident = self._incident_with_content()
        incident.handling = self._handling_with_statements(
            None, '', '   ', 'my:kept="tag"'
        )
        parser = self._parse_internal_package(self._internal_package(incident))
        self.assertEqual(
            [tag.name for tag in parser.misp_event.tags], ['my:kept="tag"']
        )

    def test_external_simple_marking_statements_read_back_as_tags(self):
        """A Simple Marking on a package header is the sender's own tag: the
        External parser copies it whole, as the shared reader now gives it."""
        stix_package = STIXPackage()
        stix_package.stix_header = STIXHeader()
        stix_package.stix_header.title = 'External report'
        stix_package.stix_header.handling = self._handling_with_statements(
            'my:external="tag"', 'another statement'
        )
        domain = DomainName()
        domain.value = 'circl.lu'
        stix_package.add_observable(Observable(Object(domain)))
        parser = ExternalSTIX1toMISPParser()
        parser.load_stix_package(stix_package)
        parser.parse_stix_package(single_event=True)
        self.assertEqual(
            sorted(tag.name for tag in parser.misp_event.tags),
            ['another statement', 'my:external="tag"']
        )

    @staticmethod
    def _handling_with_statements(*statements):
        """A Handling holding one Simple Marking per statement, the shape the
        export writes for the tags that are not a TLP colour."""
        handling = Marking()
        marking_specification = MarkingSpecification()
        for statement in statements:
            simple_marking = SimpleMarkingStructure()
            simple_marking.statement = statement
            marking_specification.marking_structures.append(simple_marking)
        handling.add_marking(marking_specification)
        return handling

    def test_internal_indicator_with_several_rules_gives_each_its_context(self):
        """An Indicator yielding one attribute per rule gives each of them the
        comment and the tags it carried: context for every rule it held, where
        the uuid is an identity and goes to the first alone. Each attribute
        takes tags of its own, not a list the others share."""
        incident = self._incident_with_content()
        indicator = Indicator()
        indicator.id_ = f'MISP:Indicator-{_IP_UUID}'
        indicator.description = 'two rules, one comment'
        indicator.handling = self._handling_with_statements('my:rule="tag"')
        test_mechanism = SnortTestMechanism()
        test_mechanism.rules = list(_SNORT_RULES)
        indicator.add_test_mechanism(test_mechanism)
        incident.related_indicators.append(
            RelatedIndicator(indicator, relationship='Network activity')
        )
        parser = self._parse_internal_package(self._internal_package(incident))
        self.assertEqual(parser.diagnostics()['errors'], {})
        snort_attributes = [
            attribute for attribute in parser.misp_event.attributes
            if attribute.type == 'snort'
        ]
        self.assertEqual(
            [
                (
                    attribute.value, attribute.comment,
                    [tag.name for tag in attribute.tags]
                )
                for attribute in snort_attributes
            ],
            [
                (rule, 'two rules, one comment', ['my:rule="tag"'])
                for rule in _SNORT_RULES
            ]
        )
        first, second = snort_attributes
        self.assertIsNot(first.tags, second.tags)
        first.add_tag('my:first="only"')
        self.assertEqual([tag.name for tag in second.tags], ['my:rule="tag"'])

    ############################################################################
    #              ATTRIBUTE OBSERVABLES READ BACK AS ATTRIBUTES.              #
    ############################################################################

    @staticmethod
    def _attributes_yielding_several_values():
        """Every attribute whose CybOX carrier the handlers read as an object
        yield, each on an event of its own - the x509 fingerprints included,
        which the fixture holds three of."""
        for getter in (
                get_event_with_email_body_attribute,
                get_event_with_email_header_attribute,
                get_event_with_regkey_attribute,
                get_event_with_regkey_value_attribute,
                get_event_with_whois_registrar_attribute,
                get_event_with_x509_fingerprint_attributes):
            for attribute in getter()['Event']['Attribute']:
                yield attribute

    def _round_trip_attribute(self, attribute, to_ids):
        """Export an attribute alone on an event, with a comment, a tag and a
        timestamp forced on it, and read it back."""
        attribute = {
            **attribute, 'to_ids': to_ids, 'comment': 'my own comment',
            'timestamp': '1603642920', 'Tag': [{'name': 'my:kept="tag"'}]
        }
        event = get_base_event()
        event['Event']['Attribute'] = [attribute]
        return attribute, self._parse_internal_package(self._misp_export(event))

    def test_internal_attribute_observables_yielding_several_values_read_back_as_attributes(self):
        """An Attribute Observable is read back as the MISP attribute it was
        exported from, never as a MISP object: the value under its own type,
        the uuid off the Indicator's or the Observable's id, and the comment,
        the tags and the timestamp where the carrier holds them - the
        Indicator does, the Observable holds none of the three. These came
        back as one-attribute objects, or empty ones for `email-body` and
        `email-header`, with all of it dropped."""
        for original in self._attributes_yielding_several_values():
            for to_ids in (True, False):
                with self.subTest(type=original['type'], to_ids=to_ids):
                    attribute, parser = self._round_trip_attribute(
                        original, to_ids
                    )
                    self.assertEqual(parser.diagnostics()['errors'], {})
                    self.assertEqual(parser.diagnostics()['warnings'], {})
                    self.assertEqual(parser.misp_event.objects, [])
                    converted, = parser.misp_event.attributes
                    self.assertEqual(
                        (
                            converted.uuid, converted.type, converted.category,
                            converted.value, converted.to_ids
                        ),
                        (
                            attribute['uuid'], attribute['type'],
                            attribute['category'], attribute['value'], to_ids
                        )
                    )
                    self.assertEqual(
                        (
                            getattr(converted, 'comment', None),
                            [tag.name for tag in converted.tags]
                        ),
                        ('my own comment', ['my:kept="tag"']) if to_ids
                        else (None, [])
                    )
                    if to_ids:
                        self.assertEqual(
                            int(converted.timestamp.timestamp()), 1603642920
                        )

    def test_internal_regkey_value_is_rebuilt_with_the_canonical_separator(self):
        """A `regkey|value` travels as a registry key holding one value, and
        is rebuilt with the canonical `|`. What the export does to the value
        before the wire is not undone: it splits on `_` too, and a key written
        `key_data` comes back `key|data`; it strips both halves, and the
        padding around the separator is gone."""
        for value, expected in (
                ('HKLM\\Software\\mthjk|%DATA%\\1234567890',
                 'HKLM\\Software\\mthjk|%DATA%\\1234567890'),
                ('HKLM\\Software\\mthjk | %DATA%', 'HKLM\\Software\\mthjk|%DATA%'),
                ('HKLM\\Software\\mthjk_1234', 'HKLM\\Software\\mthjk|1234')):
            for to_ids in (True, False):
                with self.subTest(value=value, to_ids=to_ids):
                    original = get_event_with_regkey_value_attribute()
                    original = original['Event']['Attribute'][0]
                    original['value'] = value
                    _, parser = self._round_trip_attribute(original, to_ids)
                    self.assertEqual(parser.misp_event.objects, [])
                    self.assertEqual(
                        [
                            (attribute.type, attribute.value)
                            for attribute in parser.misp_event.attributes
                        ],
                        [('regkey|value', expected)]
                    )

    @classmethod
    def _registry_key_indicator(cls, registry_key):
        """The Indicator a `to_ids` attribute is exported as, carrying a
        registry key, a comment, a tag and a timestamp, related to an
        Incident."""
        registry_object = Object(registry_key)
        registry_object.id_ = f'MISP:WindowsRegistryKey-{_OBSERVABLE_UUID}'
        indicator = cls._indicator(registry_object, _OBSERVABLE_UUID)
        indicator.description = 'my own comment'
        indicator.handling = cls._handling_with_statements('my:lost="tag"')
        indicator.timestamp = '2020-10-25T16:22:00+00:00'
        incident = cls._incident_with_content()
        incident.related_indicators.append(
            RelatedIndicator(indicator, relationship='Persistence mechanism')
        )
        return incident

    def test_internal_attribute_observable_reducing_to_no_attribute_falls_back_to_an_object(self):
        """A yield no MISP attribute type spells - a registry key with a value
        name beside its key, which our export never writes - lands as the
        object it reads as, carrying what the attribute carried: the uuid off
        the Indicator's id, the comment, the timestamp. The tags the object
        cannot take are warned of, and a warning names the Indicator the
        attribute did not come back from."""
        registry_key = WinRegistryKey()
        registry_key.key = 'HKLM\\Software\\mthjk'
        registry_value = RegistryValue()
        registry_value.name = 'Run'
        registry_key.values = RegistryValues(registry_value)
        incident = self._registry_key_indicator(registry_key)
        parser = self._parse_internal_package(self._internal_package(incident))
        self.assertEqual(parser.diagnostics()['errors'], {})
        self.assertEqual(
            [attribute.value for attribute in parser.misp_event.attributes],
            ['circl.lu']
        )
        misp_object, = parser.misp_event.objects
        self.assertEqual(
            (
                misp_object.name, misp_object.uuid, misp_object.comment,
                misp_object.timestamp
            ),
            ('registry-key', _OBSERVABLE_UUID, 'my own comment', 1603642920)
        )
        self.assertEqual(
            sorted(
                (attribute.object_relation, attribute.value, attribute.to_ids)
                for attribute in misp_object.attributes
            ),
            [('key', 'HKLM\\Software\\mthjk', True), ('name', 'Run', True)]
        )
        self.assertEqual(
            parser.diagnostics()['warnings']['misp event'],
            [
                'Unable to read the STIX object with id '
                f'MISP:Indicator-{_OBSERVABLE_UUID} back as a MISP attribute: '
                'converted as a registry-key object.',
                'MISP objects carry no tag: the markings on the STIX objects a '
                'MISP object is built from are not read back.'
            ]
        )

    def test_internal_attribute_observable_with_complementary_data_is_never_reduced(self):
        """A yield carrying complementary data is not reduced even when it holds
        one attribute: the attribute branch would drop the data. A named Custom
        object - the shape our export writes MISP objects in, never attributes
        - hands its template bookkeeping over that way, and lands as the object
        it names, with the warning."""
        custom = Custom()
        custom.custom_name = 'registry-key'
        custom.custom_properties = CustomProperties()
        key = Property()
        key.name = 'key'
        key.value = 'HKLM\\Software\\mthjk'
        custom.custom_properties.append(key)
        custom_object = Object(custom)
        custom_object.id_ = f'MISP:Custom-{_OBSERVABLE_UUID}'
        incident = self._incident_with_content()
        incident.related_indicators.append(
            RelatedIndicator(
                self._indicator(custom_object, _OBSERVABLE_UUID),
                relationship='Persistence mechanism'
            )
        )
        parser = self._parse_internal_package(self._internal_package(incident))
        self.assertEqual(parser.diagnostics()['errors'], {})
        misp_object, = parser.misp_event.objects
        self.assertEqual(
            (
                misp_object.name, misp_object.uuid,
                [
                    (attribute.object_relation, attribute.value)
                    for attribute in misp_object.attributes
                ]
            ),
            (
                'registry-key', _OBSERVABLE_UUID,
                [('key', 'HKLM\\Software\\mthjk')]
            )
        )
        self.assertEqual(
            parser.diagnostics()['warnings']['misp event'],
            [
                'Unable to read the STIX object with id '
                f'MISP:Indicator-{_OBSERVABLE_UUID} back as a MISP attribute: '
                'converted as a registry-key object.'
            ]
        )

    def test_internal_attribute_observable_yielding_nothing_records_an_error(self):
        """An email message carrying none of the fields the parser reads is no
        export of ours, and there is no record to build from it: the error
        names the Indicator, where an `email` object holding no attribute
        reached the event. The rest of the event converts."""
        email_object = Object(EmailMessage())
        email_object.id_ = f'MISP:EmailMessage-{_OBSERVABLE_UUID}'
        incident = self._incident_with_content()
        incident.related_indicators.append(
            RelatedIndicator(
                self._indicator(email_object, _OBSERVABLE_UUID),
                relationship='Payload delivery'
            )
        )
        parser = self._parse_internal_package(self._internal_package(incident))
        self.assertEqual(parser.misp_event.objects, [])
        self.assertEqual(
            [attribute.value for attribute in parser.misp_event.attributes],
            ['circl.lu']
        )
        self.assertEqual(
            parser.diagnostics()['errors']['misp event'],
            [
                'Unable to convert the STIX object with id '
                f'MISP:Indicator-{_OBSERVABLE_UUID}: nothing to fill a MISP '
                'email object with'
            ]
        )

    def test_internal_text_object_relation_keeps_the_author_comment(self):
        """An object read back as one `text` attribute takes the relation as
        its comment only where the author wrote none: an `email` reading its
        `user-agent` as a Custom Property replaced the comment with the
        property name, a `file` reading one `text` relation overwrote it with
        the empty string."""
        for name, relation, value in (
                ('email', 'user-agent', 'Mozilla/5.0'),
                ('file', 'path', '/tmp'),
                ('file', 'magic', 'PE32 executable')):
            for comment in ('my own comment', None):
                with self.subTest(name=name, relation=relation, comment=comment):
                    misp_object = {
                        'name': name, 'meta-category': 'misc',
                        'uuid': _PLAIN_OBJECT_UUID,
                        'Attribute': [
                            {
                                'uuid': _OBSERVABLE_UUID, 'type': 'text',
                                'object_relation': relation, 'value': value,
                                'to_ids': True
                            }
                        ]
                    }
                    if comment is not None:
                        misp_object['comment'] = comment
                    event = get_base_event()
                    event['Event']['Object'] = [misp_object]
                    parser = self._parse_internal_package(
                        self._misp_export(event)
                    )
                    converted, = parser.misp_event.attributes
                    self.assertEqual(converted.value, value)
                    self.assertEqual(
                        getattr(converted, 'comment', None),
                        comment if comment is not None
                        else ('user-agent' if name == 'email' else None)
                    )

    def test_external_course_of_action_markings_warning_names_no_export(self):
        """The Course of Action parser is shared, so a third-party one
        carrying a marking records the loss too - in words true of any
        document, not of one our export wrote."""
        course_of_action = self._course_of_action()
        course_of_action.handling = self._handling_with_statements(
            'my:coa="tag"'
        )
        stix_package = STIXPackage()
        stix_package.add_course_of_action(course_of_action)
        parser = self._parse_external_package(stix_package)
        self.assertEqual(len(parser.misp_event.objects), 1)
        self.assertEqual(
            parser.diagnostics()['warnings']['misp event'],
            [
                'MISP objects carry no tag: the markings on the STIX objects a '
                'MISP object is built from are not read back.'
            ]
        )

    ############################################################################
    #                 EXPORTED ATTRIBUTES COLLECTION ROUND TRIP.               #
    ############################################################################

    @staticmethod
    def _exported_attributes(*numbers):
        """The attributes the attributes collection fixtures were exported
        from, by uuid: type, value and `to_ids` for each, the category for the
        `to_ids` ones - the only ones the export writes it for - and the
        timestamp the Indicators are stamped with."""
        attributes = {}
        for number in numbers:
            filename = Path(__file__).parent / f'test_attributes_collection_{number}.json'
            with open(filename, 'rb') as f:
                for attribute in json.load(f)['response']['Attribute']:
                    attributes[attribute['uuid']] = attribute
        return attributes

    def test_internal_attributes_collection_export_reads_back(self):
        """The attribute-level export - what `stix1_attributes_framing` frames -
        carries its Indicators and Observables on the package itself, with no
        related packages: the Internal parser iterated the ones it did not have
        and died on the `None`. Read back from the reference files the export
        tests check the export against."""
        exported = self._exported_attributes(1, 2)
        for version in ('11', '12'):
            with self.subTest(version=version):
                filename = Path(__file__).parent / f'test_attributes_collection_stix{version}.xml'
                with TemporaryDirectory() as tmp_dir:
                    results = stix_1_to_misp(
                        filename,
                        output_name=Path(tmp_dir) / 'attributes.misp.json'
                    )
                    self.assertEqual(results['success'], 1)
                    self.assertNotIn('errors', results)
                    misp_event = self._load_misp_event(results['results'][0])
                self.assertEqual(misp_event.info, "Export from MISP's MISP")
                self.assertEqual(
                    {
                        attribute.uuid: (
                            attribute.type, attribute.value, attribute.to_ids
                        )
                        for attribute in misp_event.attributes
                    },
                    {
                        uuid: (
                            attribute['type'], attribute['value'],
                            bool(attribute.get('to_ids'))
                        )
                        for uuid, attribute in exported.items()
                    }
                )
                self.assertEqual(
                    {
                        attribute.uuid: (
                            attribute.category,
                            int(attribute.timestamp.timestamp())
                        )
                        for attribute in misp_event.attributes
                        if attribute.to_ids
                    },
                    {
                        uuid: (attribute['category'], int(attribute['timestamp']))
                        for uuid, attribute in exported.items()
                        if attribute.get('to_ids')
                    }
                )

    def test_internal_attributes_collection_reads_the_category_off_the_title(self):
        """With no Incident to relate an Indicator to under its category, an
        Attribute Collection writes `{category}: {value} (MISP Attribute)` as
        the title - the one place the category travels. An Observable gets
        neither title nor relationship, and pymisp's default for the type
        stands in."""
        exporter = MISPtoSTIX1AttributesParser('MISP', '1.1.1')
        exporter.parse_json_content(
            [
                {
                    'uuid': _DOMAIN_UUID, 'type': 'domain',
                    'category': 'Payload delivery', 'value': 'circl.lu',
                    'to_ids': True, 'timestamp': '1603642920'
                },
                {
                    'uuid': _IP_UUID, 'type': 'ip-dst',
                    'category': 'Payload delivery', 'value': '198.51.100.4',
                    'to_ids': False
                }
            ]
        )
        parser = self._parse_internal_package(exporter.stix_package)
        self.assertEqual(parser.diagnostics()['errors'], {})
        self.assertEqual(
            parser.misp_event.info,
            'Imported from STIX 1.2 Package generated with MISP'
        )
        self.assertEqual(
            {
                attribute.uuid: (
                    attribute.type, attribute.category,
                    attribute.value, attribute.to_ids
                )
                for attribute in parser.misp_event.attributes
            },
            {
                _DOMAIN_UUID: ('domain', 'Payload delivery', 'circl.lu', True),
                _IP_UUID: ('ip-dst', 'Network activity', '198.51.100.4', False)
            }
        )

    def test_internal_attributes_collection_target_attributes_round_trip(self):
        """An Attribute Collection has no Incident to make a Victim of: the
        export writes a `target-*` attribute as a TTP targeting the same CIQ
        identity, the Record Title on both and the timestamp on the TTP. The
        TTP reached the object reader, which recorded it as an error and lost
        the attribute. The `target-machine`, with no Incident to write an
        Affected_Asset on, is the Custom observable every type with no native
        slot takes on that parser, and reads back like one."""
        attributes = get_event_with_target_attributes()['Event']['Attribute']
        attributes[0]['timestamp'] = '1603642920'
        exporter = MISPtoSTIX1AttributesParser('MISP', '1.1.1')
        exporter.parse_json_content(attributes)
        parser = self._parse_internal_package(exporter.stix_package)
        self.assertEqual(parser.diagnostics()['errors'], {})
        self.assertEqual(
            {
                converted.uuid: (
                    converted.type, converted.category,
                    converted.value, converted.to_ids
                )
                for converted in parser.misp_event.attributes
            },
            {
                # The machine's fixture carries no category: pymisp's default
                # for the type stands in
                attribute['uuid']: (
                    attribute['type'],
                    attribute.get('category', 'Targeting data'),
                    attribute['value'], False
                )
                for attribute in attributes
            }
        )
        stamped = next(
            converted for converted in parser.misp_event.attributes
            if converted.uuid == attributes[0]['uuid']
        )
        self.assertEqual(int(stamped.timestamp.timestamp()), 1603642920)

    def test_internal_attributes_collection_test_mechanism_attributes_round_trip(self):
        """An Attribute Collection writes the same Indicator on the package -
        the rule as a test mechanism, no observable, the category in the
        title - and the package path returned on the missing observable
        alike."""
        attributes = get_event_with_test_mechanism_attributes()['Event']['Attribute']
        exporter = MISPtoSTIX1AttributesParser('MISP', '1.1.1')
        exporter.parse_json_content(attributes)
        parser = self._parse_internal_package(exporter.stix_package)
        self.assertEqual(parser.diagnostics()['errors'], {})
        self._assert_attributes_round_trip(parser, attributes, True)

    def test_internal_attributes_collection_exploit_target_attributes_convert(self):
        """A `vulnerability` or `weakness` attribute is exported as a TTP with
        an exploit target, as a vulnerability galaxy is: in an event export
        the Incident leverages the former and the Indicators only indicate
        the latter, which is what tells them apart. An Attribute Collection
        has no Incident, so the title the export gives each TTP tells them
        apart instead - and the attributes come back as the event path brings
        them, the weakness as the `weakness` object it makes of one."""
        cluster_uuid = '9d0e1f2a-3b4c-4d5e-8f6a-7b8c9d0e1f2a'
        exporter = MISPtoSTIX1AttributesParser('MISP', '1.1.1')
        exporter.parse_json_content(
            [
                {
                    'uuid': _DOMAIN_UUID, 'type': 'vulnerability',
                    'category': 'External analysis',
                    'value': 'CVE-2021-44228', 'to_ids': False
                },
                {
                    'uuid': _IP_UUID, 'type': 'weakness',
                    'category': 'External analysis', 'value': 'CWE-79',
                    'to_ids': False
                },
                {
                    'uuid': _URL_UUID, 'type': 'domain',
                    'category': 'Network activity', 'value': 'circl.lu',
                    'to_ids': True,
                    'Galaxy': [
                        {
                            'type': 'branded-vulnerability',
                            'name': 'Branded Vulnerability',
                            'GalaxyCluster': [
                                {
                                    'uuid': cluster_uuid,
                                    'type': 'branded-vulnerability',
                                    'value': 'Log4Shell',
                                    'description': 'Log4j remote code execution',
                                    'meta': {'aliases': ['CVE-2021-44228']}
                                }
                            ]
                        }
                    ]
                }
            ]
        )
        parser = self._parse_internal_package(exporter.stix_package)
        self.assertEqual(parser.diagnostics()['errors'], {})
        self.assertEqual(
            {
                attribute.uuid: (attribute.type, attribute.value)
                for attribute in parser.misp_event.attributes
            },
            {
                _DOMAIN_UUID: ('vulnerability', 'CVE-2021-44228'),
                _URL_UUID: ('domain', 'circl.lu')
            }
        )
        self.assertEqual(
            [
                (
                    misp_object.name, misp_object.uuid,
                    [
                        (attribute.object_relation, attribute.value)
                        for attribute in misp_object.attributes
                    ]
                )
                for misp_object in parser.misp_event.objects
            ],
            [('weakness', _IP_UUID, [('id', 'CWE-79')])]
        )
        self.assertIn(
            'misp-galaxy:branded-vulnerability="Log4Shell"',
            {tag['name'] for tag in parser.misp_event.tags}
        )

    ############################################################################
    #                       EXTERNAL OBSERVABLE TYPES.                         #
    ############################################################################

    @staticmethod
    def _observable(properties, feature, uuid=_OBSERVABLE_UUID):
        cybox_object = Object(properties)
        cybox_object.id_ = f'MISP:{feature}-{uuid}'
        return Observable(cybox_object)

    @staticmethod
    def _socket_address(ip, port):
        address = Address()
        address.address_value = ip
        address.category = 'ipv4-addr'
        port_object = Port()
        port_object.port_value = port
        socket_address = SocketAddress()
        socket_address.ip_address = address
        socket_address.port = port_object
        return socket_address

    @staticmethod
    def _custom(name, *properties):
        custom = Custom()
        if name is not None:
            custom.custom_name = name
        custom.custom_properties = CustomProperties()
        for property_name, value in properties:
            prop = Property()
            prop.name = property_name
            prop.value = value
            custom.custom_properties.append(prop)
        return custom

    @staticmethod
    def _file_with_three_properties():
        """Three properties, so the file lands as a `file` object rather than
        as the `filename|md5` attribute two of them fold into."""
        file_object = File()
        file_object.file_name = 'evil.exe'
        file_object.size_in_bytes = 1024
        file_object.add_hash(_MD5_HASH)
        return file_object

    @staticmethod
    def _pe_with_section(*hashes):
        """A Windows executable with one section: a `file` object including a
        `pe` object, itself including the `pe-section` the hashes go to."""
        section = PESection()
        section.entropy = Entropy()
        section.entropy.value = 7.83
        section.section_header = PESectionHeaderStruct()
        section.section_header.name = '.text'
        section.section_header.size_of_raw_data = 4096
        if hashes:
            section.data_hashes = HashList()
            section.data_hashes.hashes = list(hashes)
        pe_file = WinExecutableFile()
        pe_file.file_name = 'evil.exe'
        pe_file.size_in_bytes = 1024
        pe_file.add_hash(_MD5_HASH)
        pe_file.sections = PESectionList()
        pe_file.sections.append(section)
        return pe_file

    def _parse_external_observable(self, properties, feature):
        stix_package = STIXPackage()
        stix_package.observables = Observables(
            [self._observable(properties, feature)]
        )
        return self._parse_external_package(stix_package)

    def _assert_single_object(self, parser, name, attributes):
        self.assertEqual(parser.diagnostics()['errors'], {})
        self.assertEqual(
            [misp_object.name for misp_object in parser.misp_event.objects],
            [name]
        )
        misp_object = parser.misp_event.objects[0]
        self.assertEqual(misp_object.uuid, _OBSERVABLE_UUID)
        # The whole attribute set, so an attribute the conversion adds on top
        # of the expected ones fails here rather than passing unnoticed
        self.assertEqual(
            {
                attribute.object_relation: str(attribute.value)
                for attribute in misp_object.attributes
            },
            attributes
        )
        return misp_object

    def test_external_domain_observable_converts(self):
        """An Observable of the package itself - not the one of an Indicator -
        with a plain value lands as an attribute, `to_ids` unset."""
        domain = DomainName()
        domain.value = 'circl.lu'
        parser = self._parse_external_observable(domain, 'DomainName')
        self.assertEqual(parser.diagnostics()['errors'], {})
        self.assertEqual(
            [
                (attribute.type, attribute.value, attribute.to_ids, attribute.uuid)
                for attribute in parser.misp_event.attributes
            ],
            [('domain', 'circl.lu', False, _OBSERVABLE_UUID)]
        )

    def test_external_process_observable_converts(self):
        process = Process()
        process.name = 'svchost.exe'
        process.pid = 4242
        process.image_info = ImageInfo()
        process.image_info.file_name = 'C:\\Windows\\svchost.exe'
        parser = self._parse_external_observable(process, 'Process')
        self._assert_single_object(
            parser, 'process',
            {
                'name': 'svchost.exe', 'pid': '4242',
                'image': 'C:\\Windows\\svchost.exe'
            }
        )

    def test_external_registry_key_observable_converts(self):
        registry_key = WinRegistryKey()
        registry_key.hive = 'HKEY_LOCAL_MACHINE'
        registry_key.key = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
        value = RegistryValue()
        value.name = 'Updater'
        value.data = 'C:\\evil.exe'
        value.datatype = 'REG_SZ'
        registry_key.values = RegistryValues([value])
        parser = self._parse_external_observable(
            registry_key, 'WindowsRegistryKey'
        )
        self._assert_single_object(
            parser, 'registry-key',
            {
                'hive': 'HKEY_LOCAL_MACHINE',
                'key': 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                'name': 'Updater', 'data': 'C:\\evil.exe', 'data-type': 'REG_SZ'
            }
        )

    def test_external_registry_key_hive_joins_a_key_omitting_it(self):
        """A key and its hive alone fold into a `regkey`: joined when the key
        omits the hive, as CybOX has it, and kept verbatim when it already
        begins with it - spelled in full or abbreviated, in any case."""
        for key, expected in (
                ('system\\bar\\foo', 'HKEY_LOCAL_MACHINE\\system\\bar\\foo'),
                ('HKLM\\system\\bar\\foo', 'HKLM\\system\\bar\\foo'),
                ('hklm\\system\\bar\\foo', 'hklm\\system\\bar\\foo'),
                ('hkey_local_machine\\system\\bar\\foo',
                 'hkey_local_machine\\system\\bar\\foo'),
                ('\\HKLM\\system', '\\HKLM\\system'),
                ('HKLMX\\system', 'HKEY_LOCAL_MACHINE\\HKLMX\\system')):
            with self.subTest(key=key):
                registry_key = WinRegistryKey()
                registry_key.hive = 'HKEY_LOCAL_MACHINE'
                registry_key.key = key
                parser = self._parse_external_observable(
                    registry_key, 'WindowsRegistryKey'
                )
                self.assertEqual(parser.diagnostics()['errors'], {})
                self.assertEqual(
                    [
                        (attribute.type, attribute.value)
                        for attribute in parser.misp_event.attributes
                    ],
                    [('regkey', expected)]
                )

    def test_external_whois_observable_converts(self):
        """The registrar comes back under `registrar`, the relation the
        `whois` template defines: the table named it `whois-registrar`, which
        is the attribute type and no relation of that template - pymisp logged
        it as invalid and kept the attribute under a name MISP has no field
        for."""
        whois = WhoisEntry()
        whois.registrar_info = WhoisRegistrar()
        whois.registrar_info.name = 'GANDI SAS'
        whois.domain_name = URI(value='circl.lu')
        registrant = WhoisRegistrant()
        registrant.name = 'CIRCL'
        registrant.email_address = EmailAddress('info@circl.lu')
        whois.registrants = WhoisRegistrants([registrant])
        whois.creation_date = datetime(2020, 1, 1)
        parser = self._parse_external_observable(whois, 'Whois')
        self._assert_single_object(
            parser, 'whois',
            {
                'registrar': 'GANDI SAS', 'domain': 'circl.lu',
                'registrant-name': 'CIRCL', 'registrant-email': 'info@circl.lu',
                'creation-date': '2020-01-01 00:00:00+00:00'
            }
        )

    def test_external_x509_observable_converts(self):
        x509 = X509Certificate()
        certificate = X509Cert()
        certificate.serial_number = '00:aa:bb'
        certificate.issuer = 'CN=issuer'
        certificate.subject = 'CN=subject'
        certificate.version = '3'
        certificate.validity = Validity()
        certificate.validity.not_before = datetime(2020, 1, 1)
        certificate.validity.not_after = datetime(2021, 1, 1)
        x509.certificate = certificate
        x509.certificate_signature = X509CertificateSignature()
        x509.certificate_signature.signature_algorithm = 'SHA256'
        x509.certificate_signature.signature = 'abcd'
        parser = self._parse_external_observable(x509, 'X509Certificate')
        misp_object = self._assert_single_object(
            parser, 'x509',
            {
                'serial-number': '00:aa:bb', 'issuer': 'CN=issuer',
                'subject': 'CN=subject', 'version': '3',
                'x509-fingerprint-sha256': 'abcd',
                'validity-not-before': '2020-01-01 00:00:00',
                'validity-not-after': '2021-01-01 00:00:00'
            }
        )
        self.assertEqual(
            {
                attribute.object_relation: attribute.value
                for attribute in misp_object.attributes
                if attribute.object_relation.startswith('validity-')
            },
            {
                'validity-not-before': datetime(2020, 1, 1),
                'validity-not-after': datetime(2021, 1, 1)
            }
        )

    def test_external_x509_signature_of_unknown_algorithm_costs_that_hash_only(self):
        """The signature algorithm the document names types the fingerprint,
        and MISP has an attribute type for three of them: a `sha512`
        signature built `x509-fingerprint-sha512`, which is neither an `x509`
        relation nor a MISP type - pymisp refused it and the whole object was
        lost. The one attribute nothing can type is the whole loss."""
        x509 = X509Certificate()
        certificate = X509Cert()
        certificate.subject = 'CN=subject'
        x509.certificate = certificate
        x509.certificate_signature = X509CertificateSignature()
        x509.certificate_signature.signature_algorithm = 'SHA512'
        x509.certificate_signature.signature = 'abcd'
        parser = self._parse_external_observable(x509, 'X509Certificate')
        self._assert_single_object(parser, 'x509', {'subject': 'CN=subject'})
        warnings = [
            warning for warnings in parser.diagnostics()['warnings'].values()
            for warning in warnings
        ]
        self.assertEqual(len(warnings), 1)
        self.assertIn(repr('x509-fingerprint-sha512'), warnings[0])
        self.assertIn('abcd', warnings[0])
        self.assertIn(f'MISP:X509Certificate-{_OBSERVABLE_UUID}', warnings[0])

    def test_external_x509_custom_properties_convert_under_their_own_names(self):
        """cybox holds one signature, so the export writes the other
        fingerprints of an `x509` object as custom properties named after
        their relation: the bag was never read."""
        x509 = X509Certificate()
        x509.custom_properties = CustomProperties()
        for name, value in (
                ('x509-fingerprint-md5', _MD5_HASH), ('is_ca', 'True')):
            prop = Property()
            prop.name = name
            prop.value = value
            x509.custom_properties.append(prop)
        parser = self._parse_external_observable(x509, 'X509Certificate')
        misp_object = self._assert_single_object(
            parser, 'x509', {'x509-fingerprint-md5': _MD5_HASH, 'is_ca': 'True'}
        )
        self.assertEqual(
            {
                attribute.object_relation: attribute.type
                for attribute in misp_object.attributes
            },
            {'x509-fingerprint-md5': 'x509-fingerprint-md5', 'is_ca': 'boolean'}
        )
        self.assertEqual(parser.diagnostics()['warnings'], {})

    def test_external_network_connection_observable_converts(self):
        connection = NetworkConnection()
        connection.source_socket_address = self._socket_address(
            '198.51.100.7', 49152
        )
        connection.destination_socket_address = self._socket_address(
            '203.0.113.9', 443
        )
        connection.layer4_protocol = 'TCP'
        parser = self._parse_external_observable(
            connection, 'NetworkConnection'
        )
        self._assert_single_object(
            parser, 'network-connection',
            {
                'ip-src': '198.51.100.7', 'src-port': '49152',
                'ip-dst': '203.0.113.9', 'dst-port': '443',
                'layer4-protocol': 'TCP'
            }
        )

    def test_external_network_socket_observable_converts(self):
        socket = NetworkSocket()
        socket.local_address = self._socket_address('198.51.100.7', 8080)
        socket.remote_address = self._socket_address('203.0.113.9', 51000)
        socket.protocol = 'TCP'
        socket.address_family = 'AF_INET'
        socket.is_listening = True
        parser = self._parse_external_observable(socket, 'NetworkSocket')
        self._assert_single_object(
            parser, 'network-socket',
            {
                'ip-src': '198.51.100.7', 'src-port': '8080',
                'ip-dst': '203.0.113.9', 'dst-port': '51000',
                'protocol': 'TCP', 'address-family': 'AF_INET',
                'state': 'listening'
            }
        )

    def test_external_user_account_observable_converts(self):
        user_account = UserAccount()
        user_account.username = 'jdoe'
        user_account.full_name = 'John Doe'
        parser = self._parse_external_observable(user_account, 'UserAccount')
        self._assert_single_object(
            parser, 'user-account',
            {'username': 'jdoe', 'display-name': 'John Doe'}
        )

    def test_external_custom_object_observable_converts(self):
        """A named `Custom` object is what the MISP export writes an object
        no other CybOX object holds into: the name is the template, the
        properties its attributes by object relation, typed from the template."""
        custom = self._custom(
            'github-user', ('username', 'chrisr3d'),
            ('link', 'https://github.com/chrisr3d')
        )
        parser = self._parse_external_observable(custom, 'Custom')
        misp_object = self._assert_single_object(
            parser, 'github-user',
            {'username': 'chrisr3d', 'link': 'https://github.com/chrisr3d'}
        )
        self.assertEqual(
            {
                attribute.object_relation: attribute.type
                for attribute in misp_object.attributes
            },
            {'username': 'github-username', 'link': 'link'}
        )

    def test_external_custom_object_of_unknown_template_converts_as_text(self):
        """A template pymisp does not ship - a custom one, local to the
        instance the document came from - types nothing: every attribute is
        text, and the object is worth one warning rather than one per
        relation, which would repeat the same nothing."""
        custom = self._custom(
            'vendor-specific-record', ('severity', 'high'), ('ticket', 'INC-42')
        )
        parser = self._parse_external_observable(custom, 'Custom')
        misp_object = self._assert_single_object(
            parser, 'vendor-specific-record',
            {'severity': 'high', 'ticket': 'INC-42'}
        )
        self.assertEqual(
            {attribute.type for attribute in misp_object.attributes}, {'text'}
        )
        warnings = [
            warning for warnings in parser.diagnostics()['warnings'].values()
            for warning in warnings
        ]
        self.assertEqual(len(warnings), 1)
        self.assertIn(repr('vendor-specific-record'), warnings[0])
        self.assertIn(f'MISP:Custom-{_OBSERVABLE_UUID}', warnings[0])

    def test_external_custom_object_property_off_its_template_converts_as_text(self):
        """A template pymisp ships types the relations it defines, and a name
        it does not define keeps its spelling as a `text` attribute, which any
        relation validates as - with the warning the same name gets on a typed
        CybOX object. One precedence for every carrier."""
        custom = self._custom(
            'github-user', ('username', 'chrisr3d'), ('severity', 'high')
        )
        parser = self._parse_external_observable(custom, 'Custom')
        misp_object = self._assert_single_object(
            parser, 'github-user', {'username': 'chrisr3d', 'severity': 'high'}
        )
        self.assertEqual(
            {
                attribute.object_relation: attribute.type
                for attribute in misp_object.attributes
            },
            {'username': 'github-username', 'severity': 'text'}
        )
        warnings = [
            warning for warnings in parser.diagnostics()['warnings'].values()
            for warning in warnings
        ]
        self.assertEqual(len(warnings), 1)
        self.assertIn(repr('severity'), warnings[0])
        self.assertIn('is no github-user object relation', warnings[0])
        self.assertIn(f'MISP:Custom-{_OBSERVABLE_UUID}', warnings[0])

    def test_external_custom_object_name_never_reaches_template_resolution(self):
        """pymisp joins the object name into a filesystem path to find its
        template: a `Custom` name from the document is data, not a path."""
        with TemporaryDirectory() as tmp_dir:
            name = self._plant_template_definition(tmp_dir)
            custom = self._custom(name, ('severity', 'high'))
            parser = self._parse_external_observable(custom, 'Custom')
        misp_object = self._assert_single_object(
            parser, 'unknown-template', {'severity': 'high'}
        )
        self.assertFalse(misp_object._known_template)
        self.assertIn(name, misp_object.comment)
        warnings = [
            warning for warnings in parser.diagnostics()['warnings'].values()
            for warning in warnings
            if 'Invalid MISP object template name' in warning
        ]
        self.assertEqual(len(warnings), 1)
        # The rejected value and the object it came from, as ADR-0010 asks
        self.assertIn(repr(name), warnings[0])
        self.assertIn(f'MISP:Custom-{_OBSERVABLE_UUID}', warnings[0])

    def test_external_custom_attribute_observable_converts(self):
        """A `Custom` object with no name is the export of a MISP attribute no
        CybOX object represents: one property, named by the attribute type."""
        custom = self._custom(None, ('github-username', 'chrisr3d'))
        parser = self._parse_external_observable(custom, 'Custom')
        self.assertEqual(parser.diagnostics()['errors'], {})
        self.assertEqual(
            [
                (attribute.type, attribute.value, attribute.uuid)
                for attribute in parser.misp_event.attributes
            ],
            [('github-username', 'chrisr3d', _OBSERVABLE_UUID)]
        )

    def test_external_custom_property_of_unknown_type_converts_as_text(self):
        custom = self._custom(None, ('severity', 'high'))
        parser = self._parse_external_observable(custom, 'Custom')
        self.assertEqual(parser.diagnostics()['errors'], {})
        attribute = parser.misp_event.attributes[0]
        self.assertEqual((attribute.type, attribute.value), ('text', 'high'))
        self.assertEqual(attribute.comment, 'severity')

    def test_external_custom_attribute_with_several_properties_converts(self):
        """A nameless `Custom` object carrying several properties has no
        object to put them in: they all land on the event."""
        custom = self._custom(
            None, ('github-username', 'chrisr3d'), ('severity', 'high')
        )
        parser = self._parse_external_observable(custom, 'Custom')
        self.assertEqual(parser.diagnostics()['errors'], {})
        self.assertEqual(
            sorted(
                (attribute.type, attribute.value)
                for attribute in parser.misp_event.attributes
            ),
            [('github-username', 'chrisr3d'), ('text', 'high')]
        )

    def test_internal_custom_object_without_properties_records_an_error(self):
        """A `Custom` object carrying no property names neither an attribute
        nor an object: reading one off it unguarded crashed the conversion.
        Being the one thing the package carries, the conversion yields nothing
        and is refused - naming the error recorded on the way, which is what
        tells this document from one carrying nothing at all."""
        incident = Incident()
        incident.title = 'Incident with an empty Custom observable'
        custom_object = Object(self._custom(None))
        custom_object.id_ = f'MISP:Custom-{_OBSERVABLE_UUID}'
        observable = Observable(custom_object)
        observable.id_ = f'MISP:Observable-{_OBSERVABLE_UUID}'
        incident.related_observables.append(
            RelatedObservable(observable, relationship='misc')
        )
        parser = InternalSTIX1toMISPParser()
        with self.assertRaises(MissingSTIXContentError) as context:
            self._parse_internal_package(
                self._internal_package(incident), parser
            )
        self.assertEqual(
            str(context.exception),
            'The STIX 1.2 package converted to no MISP attribute, object or '
            'galaxy - 1 error recorded.'
        )
        self.assertEqual(parser.misp_event.objects, [])
        self.assertEqual(parser.misp_event.attributes, [])
        self.assertTrue(
            any(
                'nothing to name a MISP object with' in error
                for errors in parser.diagnostics()['errors'].values()
                for error in errors
            )
        )

    def test_internal_unnameable_composition_converts_as_unknown_template(self):
        """The export writes the object name into the Observable id it gives
        a composition: one this parser cannot read a name from keeps its
        attributes, under a name that resolves no template file."""
        incident = Incident()
        incident.title = 'Incident with an unnameable composition'
        domain = DomainName()
        domain.value = 'circl.lu'
        domain_object = Object(domain)
        domain_object.id_ = f'MISP:DomainName-{_DOMAIN_UUID}'
        inner = Observable(domain_object)
        inner.id_ = f'MISP:Observable-{_DOMAIN_UUID}'
        composition = ObservableComposition(observables=[inner])
        composition.operator = 'AND'
        observable = Observable()
        observable.id_ = f'MISP:Observable-{_OBSERVABLE_UUID}'
        observable.observable_composition = composition
        incident.related_observables.append(
            RelatedObservable(observable, relationship='misc')
        )
        parser = self._parse_internal_package(self._internal_package(incident))
        misp_object = self._assert_single_object(
            parser, 'unknown-template', {'domain': 'circl.lu'}
        )
        self.assertFalse(misp_object._known_template)
        self.assertTrue(
            any(
                'Unable to define the MISP object name' in warning
                for warnings in parser.diagnostics()['warnings'].values()
                for warning in warnings
            )
        )

    def _composition_observable(self, *members):
        """The Observable the export writes a MISP object as: a composition
        of one Observable per attribute."""
        observable = Observable()
        observable.id_ = f'MISP:Observable-{_OBSERVABLE_UUID}'
        observable.observable_composition = ObservableComposition(
            observables=list(members)
        )
        observable.observable_composition.operator = 'AND'
        return observable

    def test_internal_file_composition_splits_a_hash_of_no_composite_type(self):
        """A `File` member carrying a file name and a hash of a shape nothing
        names rebuilt `filename|other`, which pymisp refused - and in a
        composition that cost the whole object rather than the attribute. Both
        halves are `file` relations, so the pairing is the whole loss."""
        file_object = File()
        file_object.file_name = 'evil.exe'
        file_object.add_hash(
            Hash('115056655d15151138z66hz1021z55z66z3', Hash.TYPE_OTHER,
                 exact=True)
        )
        member = self._observable(file_object, 'File', _PLAIN_OBJECT_UUID)
        incident = Incident()
        incident.title = 'Incident with a file composition'
        incident.related_observables.append(
            RelatedObservable(
                self._composition_observable(member), relationship='file'
            )
        )
        parser = self._parse_internal_package(self._internal_package(incident))
        self.assertEqual(parser.diagnostics()['errors'], {})
        self._assert_single_object(
            parser, 'file',
            {
                'filename': 'evil.exe',
                'other': '115056655d15151138z66hz1021z55z66z3'
            }
        )

    def test_internal_refused_composition_record_costs_that_object_only(self):
        """The composition branch builds its object without going through
        `_handle_object_case`, so it needs the same guard: a member naming a
        MISP attribute type whose value MISP will not read costs the object,
        not the package, and the Error names it."""
        member = self._observable(
            self._custom(None, ('datetime', 'not a date')), 'Custom',
            _PLAIN_OBJECT_UUID
        )
        incident = self._incident_with_content()
        incident.title = 'Incident with a refused composition'
        incident.related_observables.append(
            RelatedObservable(
                self._composition_observable(member), relationship='file'
            )
        )
        parser = self._parse_internal_package(self._internal_package(incident))
        self.assertEqual(parser.misp_event.objects, [])
        self.assertEqual(
            [
                (attribute.type, attribute.value)
                for attribute in parser.misp_event.attributes
            ],
            [('domain', 'circl.lu')]
        )
        errors = parser.diagnostics()['errors']['misp event']
        self.assertEqual(len(errors), 1)
        self.assertIn('Error with the file object', errors[0])
        self.assertIn('not a date', errors[0])

    def test_internal_composition_pairing_into_no_composite_records_an_error(self):
        """An attribute exported as a composition is read back by pairing the
        values its members hold into a MISP composite type: a pair MISP has
        none for returned nothing, and unpacking the nothing raised a
        `TypeError` out of `parse_stix_package()` - which no pymisp guard
        catches. The Error names the types it could not pair."""
        domain = DomainName()
        domain.value = 'circl.lu'
        incident = self._incident_with_content()
        incident.title = 'Incident with an unpairable composition'
        incident.related_observables.append(
            RelatedObservable(
                self._composition_observable(
                    self._observable(domain, 'DomainName', _PLAIN_OBJECT_UUID)
                ),
                relationship='Network activity'
            )
        )
        parser = self._parse_internal_package(self._internal_package(incident))
        self.assertEqual(
            [
                (attribute.type, attribute.value)
                for attribute in parser.misp_event.attributes
            ],
            [('domain', 'circl.lu')]
        )
        errors = parser.diagnostics()['errors']['misp event']
        self.assertEqual(len(errors), 1)
        self.assertIn(
            'domain make no MISP composite attribute', errors[0]
        )
        self.assertIn(_OBSERVABLE_UUID, errors[0])

    def test_external_dns_record_observable_converts(self):
        dns_record = DNSRecord()
        dns_record.domain_name = 'circl.lu'
        dns_record.ip_address = '149.13.33.14'
        parser = self._parse_external_observable(dns_record, 'DNSRecord')
        self._assert_single_object(
            parser, 'passive-dns',
            {'rrname': 'circl.lu', 'rdata': '149.13.33.14', 'rrtype': 'A'}
        )

    def _assert_pe_section(self, parser, hashes):
        """The whole document converted: the three objects, the `pe` one
        including the section, and the section holding exactly `hashes` on
        top of its header fields, each typed after its relation."""
        self.assertEqual(parser.diagnostics()['errors'], {})
        self.assertEqual(
            sorted(misp_object.name for misp_object in parser.misp_event.objects),
            ['file', 'pe', 'pe-section']
        )
        pe_object = parser.misp_event.get_objects_by_name('pe')[0]
        section = parser.misp_event.get_objects_by_name('pe-section')[0]
        self.assertEqual(
            [
                (reference.relationship_type, reference.referenced_uuid)
                for reference in pe_object.references
            ],
            [('includes', section.uuid)]
        )
        self.assertEqual(
            {
                attribute.object_relation: str(attribute.value)
                for attribute in section.attributes
            },
            {
                'entropy': '7.83', 'name': '.text', 'size-in-bytes': '4096',
                **hashes
            }
        )
        self.assertEqual(
            {
                attribute.object_relation: attribute.type
                for attribute in section.attributes
                if attribute.object_relation in hashes
            },
            {relation: relation for relation in hashes}
        )

    def test_external_pe_section_with_well_known_hashes_converts(self):
        hashes = {
            'md5': _MD5_HASH,
            'sha1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
            'sha256': (
                'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
            ),
            'sha512': (
                'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce'
                '47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e'
            )
        }
        parser = self._parse_external_observable(
            self._pe_with_section(
                *(Hash(value, exact=True) for value in hashes.values())
            ),
            'WinExecutableFile'
        )
        self._assert_pe_section(parser, hashes)
        self.assertEqual(parser.diagnostics()['warnings'], {})

    def test_external_pe_section_with_an_other_typed_ssdeep_hash_converts(self):
        """MISP's own STIX 1 export wrote ssdeep hashes as `Type=Other`, which
        names no `pe-section` relation: added by relation alone, pymisp had no
        type to give the attribute, raised, and one hash cost the document.
        The shape of the value - `blocksize:hash:hash` - names the relation."""
        parser = self._parse_external_observable(
            self._pe_with_section(
                Hash(_MD5_HASH, exact=True),
                Hash(_SSDEEP_HASH, Hash.TYPE_OTHER, exact=True)
            ),
            'WinExecutableFile'
        )
        self._assert_pe_section(
            parser, {'md5': _MD5_HASH, 'ssdeep': _SSDEEP_HASH}
        )
        self.assertEqual(parser.diagnostics()['warnings'], {})

    def test_external_pe_section_hash_of_unknown_type_costs_that_hash_only(self):
        """A hash whose type the `pe-section` template has no relation for, and
        whose value names none either, is the one thing not converted: dropped
        with a warning naming it and the object it came from, as ADR-0010 asks
        of rejected content, while the rest of the document survives."""
        md6 = 'b' * 64
        parser = self._parse_external_observable(
            self._pe_with_section(
                Hash(_MD5_HASH, exact=True), Hash(md6, Hash.TYPE_MD6, exact=True)
            ),
            'WinExecutableFile'
        )
        self._assert_pe_section(parser, {'md5': _MD5_HASH})
        warnings = [
            warning for warnings in parser.diagnostics()['warnings'].values()
            for warning in warnings
        ]
        self.assertEqual(len(warnings), 1)
        self.assertIn(repr('md6'), warnings[0])
        self.assertIn(md6, warnings[0])
        self.assertIn(f'MISP:WinExecutableFile-{_OBSERVABLE_UUID}', warnings[0])

    @staticmethod
    def _pe_with_header_hashes(*hashes):
        """A Windows executable no file attribute is read from: the `pe`
        object itself, its hashes on the PE file header the export writes
        them to."""
        pe_file = WinExecutableFile()
        pe_file.headers = PEHeaders()
        pe_file.headers.file_header = PEFileHeader()
        pe_file.headers.file_header.number_of_sections = 2
        if hashes:
            pe_file.headers.file_header.hashes = HashList()
            pe_file.headers.file_header.hashes.hashes = list(hashes)
        return pe_file

    def test_external_pe_header_hashes_convert_under_their_own_relations(self):
        """cybox names no hash type for any of the four `pe` relations the
        export writes as header hashes: it types each of them by the length of
        its value, and the same table backwards is the whole inverse. None of
        them was read at all, and the `pe` carried the uuid of an empty `file`
        object rather than its own."""
        pehash = 'a' * 40
        authentihash = 'b' * 64
        parser = self._parse_external_observable(
            self._pe_with_header_hashes(
                Hash(_MD5_HASH, exact=True), Hash(pehash, exact=True),
                Hash(authentihash, exact=True),
                Hash(_SSDEEP_HASH, Hash.TYPE_OTHER, exact=True)
            ),
            'WinExecutableFile'
        )
        misp_object = self._assert_single_object(
            parser, 'pe',
            {
                'number-sections': '2', 'imphash': _MD5_HASH,
                'pehash': pehash, 'authentihash': authentihash,
                'impfuzzy': _SSDEEP_HASH
            }
        )
        self.assertEqual(
            {
                attribute.object_relation: attribute.type
                for attribute in misp_object.attributes
            },
            {
                'number-sections': 'counter', 'imphash': 'imphash',
                'pehash': 'pehash', 'authentihash': 'authentihash',
                'impfuzzy': 'impfuzzy'
            }
        )
        self.assertEqual(parser.diagnostics()['warnings'], {})

    def test_external_pe_header_hash_written_the_way_older_exports_wrote_it(self):
        """`authentihash` was the one hash relation missing from the export's
        single-value fields, so its value reached the hash wrapped in a list,
        the length measured was the list's - 1 - and the hash went out
        `Type=Other`, the type `impfuzzy` falls back to. The shape of the
        value tells the two apart, and the list the XML flattens but a JSON or
        an in-memory package keeps is no attribute value."""
        authentihash = 'b' * 64
        parser = self._parse_external_observable(
            self._pe_with_header_hashes(
                Hash([authentihash], Hash.TYPE_OTHER, exact=True)
            ),
            'WinExecutableFile'
        )
        misp_object = self._assert_single_object(
            parser, 'pe',
            {'number-sections': '2', 'authentihash': authentihash}
        )
        self.assertEqual(
            {
                attribute.object_relation: attribute.type
                for attribute in misp_object.attributes
            },
            {'number-sections': 'counter', 'authentihash': 'authentihash'}
        )
        self.assertEqual(parser.diagnostics()['warnings'], {})

    def test_external_pe_header_hash_of_unknown_type_costs_that_hash_only(self):
        """A header hash of a type the table does not name - no export writes
        one, a hand-edited or a third-party document can - names no relation,
        and the relation is what types the attribute: dropped with a warning
        naming it and the object it came from, the rest of the object read."""
        sha224 = 'c' * 56
        parser = self._parse_external_observable(
            self._pe_with_header_hashes(
                Hash(_MD5_HASH, exact=True),
                Hash(sha224, Hash.TYPE_SHA224, exact=True)
            ),
            'WinExecutableFile'
        )
        self._assert_single_object(
            parser, 'pe', {'number-sections': '2', 'imphash': _MD5_HASH}
        )
        warnings = [
            warning for warnings in parser.diagnostics()['warnings'].values()
            for warning in warnings
        ]
        self.assertEqual(len(warnings), 1)
        self.assertIn(repr('sha224'), warnings[0])
        self.assertIn(sha224, warnings[0])
        self.assertIn(f'MISP:WinExecutableFile-{_OBSERVABLE_UUID}', warnings[0])

    def test_external_pe_properties_convert_under_the_names_they_carry(self):
        """The export writes a `pe` relation no cybox field holds as a custom
        property named after the relation itself, and the import read the
        properties of `Custom` objects alone: the whole bag was dropped. A
        name the template cannot type keeps its spelling and travels as a
        `text` attribute, with a warning - a `text` attribute validates under
        any relation."""
        pdb = 'C:\\projects\\putty\\Release\\putty.pdb'
        pe_file = WinExecutableFile()
        pe_file.custom_properties = CustomProperties()
        for name, value in (
                ('pdb', pdb), ('compilation-timestamp', '2019-03-16T12:31:22'),
                ('not-a-pe-relation', 'whatever')):
            prop = Property()
            prop.name = name
            prop.value = value
            pe_file.custom_properties.append(prop)
        parser = self._parse_external_observable(pe_file, 'WinExecutableFile')
        misp_object = self._assert_single_object(
            parser, 'pe',
            {
                'pdb': pdb, 'compilation-timestamp': '2019-03-16 12:31:22',
                'not-a-pe-relation': 'whatever'
            }
        )
        self.assertEqual(
            {
                attribute.object_relation: attribute.type
                for attribute in misp_object.attributes
            },
            {
                'pdb': 'pdb', 'compilation-timestamp': 'datetime',
                'not-a-pe-relation': 'text'
            }
        )
        warnings = [
            warning for warnings in parser.diagnostics()['warnings'].values()
            for warning in warnings
        ]
        self.assertEqual(len(warnings), 1)
        self.assertIn(repr('not-a-pe-relation'), warnings[0])
        self.assertIn('whatever', warnings[0])
        self.assertIn(f'MISP:WinExecutableFile-{_OBSERVABLE_UUID}', warnings[0])

    def test_external_pe_section_without_hashes_converts(self):
        """MISP's export writes a section with no hash attribute without any
        hash list: iterating the missing list crashed the conversion."""
        parser = self._parse_external_observable(
            self._pe_with_section(), 'WinExecutableFile'
        )
        self._assert_pe_section(parser, {})
        self.assertEqual(parser.diagnostics()['warnings'], {})

    def test_external_file_with_an_other_typed_ssdeep_hash_converts(self):
        """The same `Type=Other` ssdeep on a plain file went through the same
        hash helper: `filename|other` is no MISP attribute type, pymisp
        refused it. `filename|ssdeep` is."""
        file_object = File()
        file_object.file_name = 'evil.exe'
        file_object.add_hash(Hash(_SSDEEP_HASH, Hash.TYPE_OTHER, exact=True))
        parser = self._parse_external_observable(file_object, 'File')
        self.assertEqual(parser.diagnostics()['errors'], {})
        self.assertEqual(
            [
                (attribute.type, attribute.value)
                for attribute in parser.misp_event.attributes
            ],
            [('filename|ssdeep', f'evil.exe|{_SSDEEP_HASH}')]
        )

    def test_external_record_misp_refuses_costs_that_record_only(self):
        """The record boundary is the unit of the guard: a relation the `file`
        template types `datetime` carrying a value MISP will not read as one
        is refused by pymisp, and the refusal used to escape
        `parse_stix_package()` - costing every other record of the package,
        the recorded error included, since the diagnostics never reached a
        caller. The object is the whole loss, and the Error names it."""
        stix_package = STIXPackage()
        stix_package.observables = Observables(
            [
                self._observable(
                    self._custom(
                        'file',
                        ('filename', 'evil.exe'),
                        ('creation-time', 'not a date')
                    ),
                    'Custom'
                ),
                self._observable(
                    self._custom('github-user', ('username', 'chrisr3d')),
                    'Custom', _PLAIN_OBJECT_UUID
                )
            ]
        )
        parser = self._parse_external_package(stix_package)
        self.assertEqual(
            [
                (misp_object.name, misp_object.uuid)
                for misp_object in parser.misp_event.objects
            ],
            [('github-user', _PLAIN_OBJECT_UUID)]
        )
        errors = parser.diagnostics()['errors']['misp event']
        self.assertEqual(len(errors), 1)
        self.assertIn(f'file object with id {_OBSERVABLE_UUID}', errors[0])
        self.assertIn('not a date', errors[0])

    def test_external_file_with_an_other_typed_tlsh_hash_converts(self):
        """A tlsh is 70 hexadecimal characters, optionally behind the `T1`
        version prefix, and cybox has no name for that length: the shape is
        what names it, the one `Type=Other` a value tells apart besides the
        ssdeep above."""
        for digest in (
                'c325af62e2f15cf7c32316389d1b57a46827be703d3879866bf52c385f396'
                '813829297',
                'T1c325af62e2f15cf7c32316389d1b57a46827be703d3879866bf52c385f3'
                '96813829297'):
            with self.subTest(digest=digest):
                file_object = File()
                file_object.file_name = 'evil.exe'
                file_object.add_hash(
                    Hash(digest, Hash.TYPE_OTHER, exact=True)
                )
                parser = self._parse_external_observable(file_object, 'File')
                self.assertEqual(parser.diagnostics()['errors'], {})
                self.assertEqual(parser.diagnostics()['warnings'], {})
                self.assertEqual(
                    [
                        (attribute.type, attribute.value)
                        for attribute in parser.misp_event.attributes
                    ],
                    [('filename|tlsh', f'evil.exe|{digest}')]
                )

    def test_external_lone_hash_of_an_unnameable_shape_converts_as_other(self):
        """A hash with no file name beside it is the whole attribute: a tlsh
        comes back under its own type, and a `vhash` - which no shape names -
        comes back under the MISP `other` type, with the one warning saying
        the type is what was lost."""
        for digest, attribute_type, warnings in (
                (
                    'c325af62e2f15cf7c32316389d1b57a46827be703d3879866bf52c385'
                    'f396813829297', 'tlsh', {}
                ),
                (
                    '115056655d15151138z66hz1021z55z66z3', 'other',
                    {
                        'misp event': [
                            'Unknown hash type in the object with id '
                            f'MISP:File-{_OBSERVABLE_UUID}: '
                            '115056655d15151138z66hz1021z55z66z3 read as an '
                            'other hash.'
                        ]
                    }
                )):
            with self.subTest(attribute_type=attribute_type):
                file_object = File()
                file_object.add_hash(Hash(digest, Hash.TYPE_OTHER, exact=True))
                parser = self._parse_external_observable(file_object, 'File')
                self.assertEqual(parser.diagnostics()['errors'], {})
                self.assertEqual(
                    [
                        (attribute.type, attribute.value)
                        for attribute in parser.misp_event.attributes
                    ],
                    [(attribute_type, digest)]
                )
                self.assertEqual(parser.diagnostics()['warnings'], warnings)

    def test_external_refused_attribute_costs_that_record_only(self):
        """The External parser reaches the same funnel: a `Custom` property
        named after a MISP attribute type carries a value MISP will not read
        as one, and the refusal used to escape `parse_stix_package()` with
        the whole package. The attribute is the whole loss, the Error names
        it, and the Observable next to it converts."""
        stix_package = STIXPackage()
        stix_package.observables = Observables(
            [
                self._observable(
                    self._custom(None, ('datetime', 'not a date')), 'Custom'
                ),
                self._observable(
                    self._custom(None, ('md5', _MD5_HASH)), 'Custom',
                    _PLAIN_OBJECT_UUID
                )
            ]
        )
        parser = self._parse_external_package(stix_package)
        self.assertEqual(
            [
                (attribute.type, attribute.value, attribute.uuid)
                for attribute in parser.misp_event.attributes
            ],
            [('md5', _MD5_HASH, _PLAIN_OBJECT_UUID)]
        )
        errors = parser.diagnostics()['errors']['misp event']
        self.assertEqual(len(errors), 1)
        self.assertIn('Error with the datetime attribute: not a date', errors[0])
        self.assertIn(f'MISP:Custom-{_OBSERVABLE_UUID}', errors[0])

    def test_external_file_name_and_hash_of_no_composite_type_convert_apart(self):
        """A `File` carrying a file name and a hash of a shape nothing names
        rebuilt the `filename|other` composite MISP has no type for: pymisp
        refused it, out of `parse_stix_package()`, and the whole package was
        lost. Both values come back now, as the two attributes they are - the
        hash keeping the id of the Observable, the file name qualifying it
        taking a random uuid - with one warning naming the observable."""
        digest = '115056655d15151138z66hz1021z55z66z3'
        file_object = File()
        file_object.file_name = 'evil.exe'
        file_object.add_hash(Hash(digest, Hash.TYPE_OTHER, exact=True))
        parser = self._parse_external_observable(file_object, 'File')
        self.assertEqual(parser.diagnostics()['errors'], {})
        self.assertEqual(
            [
                (attribute.type, attribute.value, attribute.uuid)
                for attribute in parser.misp_event.attributes
            ],
            [
                ('filename', 'evil.exe', ANY),
                ('other', digest, _OBSERVABLE_UUID)
            ]
        )
        self.assertNotEqual(
            parser.misp_event.attributes[0].uuid, _OBSERVABLE_UUID
        )
        self.assertEqual(
            parser.diagnostics()['warnings'],
            {
                'misp event': [
                    'Unknown hash type in the object with id '
                    f'MISP:File-{_OBSERVABLE_UUID}: {digest} read as an '
                    'other hash.',
                    "'filename|other' is no MISP attribute type in the object "
                    f'with id MISP:File-{_OBSERVABLE_UUID}: evil.exe and '
                    f'{digest} converted separately.'
                ]
            }
        )

    def test_external_file_with_an_other_typed_hash_converts(self):
        """`Other` is a MISP attribute type of its own, and no `file` object
        relation: a hash of no well-known length and of no shape naming a
        relation keeps working off-template, as it does today. A uniform skip
        would start dropping values that survive - and the one warning says
        the type is what was lost, the value being kept."""
        digest = 'f' * 24
        file_object = File()
        file_object.add_hash(Hash(_MD5_HASH, exact=True))
        file_object.add_hash(Hash(digest, Hash.TYPE_OTHER, exact=True))
        parser = self._parse_external_observable(file_object, 'File')
        misp_object = self._assert_single_object(
            parser, 'file', {'md5': _MD5_HASH, 'other': digest}
        )
        self.assertEqual(
            {
                attribute.object_relation: attribute.type
                for attribute in misp_object.attributes
            },
            {'md5': 'md5', 'other': 'other'}
        )
        self.assertEqual(
            parser.diagnostics()['warnings'],
            {
                'misp event': [
                    'Unknown hash type in the object with id '
                    f'MISP:File-{_OBSERVABLE_UUID}: {digest} read as an '
                    'other hash.'
                ]
            }
        )

    def test_external_file_hash_of_unknown_type_costs_that_hash_only(self):
        """The cybox hash type is the MISP type and the object relation of the
        attribute a file hash builds, and cybox's vocabulary is not MISP's:
        an `MD6` hash was handed to pymisp, which refused it and cost the
        whole `file` object. The one hash nothing can type is the whole
        loss."""
        md6 = 'b' * 64
        file_object = File()
        file_object.file_name = 'evil.exe'
        file_object.add_hash(Hash(_MD5_HASH, exact=True))
        file_object.add_hash(Hash(md6, Hash.TYPE_MD6, exact=True))
        parser = self._parse_external_observable(file_object, 'File')
        self.assertEqual(parser.diagnostics()['errors'], {})
        self.assertEqual(
            [
                (attribute.type, attribute.value)
                for attribute in parser.misp_event.attributes
            ],
            [('filename|md5', f'evil.exe|{_MD5_HASH}')]
        )
        warnings = [
            warning for warnings in parser.diagnostics()['warnings'].values()
            for warning in warnings
        ]
        self.assertEqual(len(warnings), 1)
        self.assertIn(repr('md6'), warnings[0])
        self.assertIn(md6, warnings[0])
        self.assertIn(f'MISP:File-{_OBSERVABLE_UUID}', warnings[0])

    def test_external_property_value_that_is_no_attribute_value_is_dropped(self):
        """The export writes one property per value, and every value it writes
        is a string - a package built in memory and handed to
        `load_stix_package`, the path MISP core takes, carries whatever it was
        built with. A one-element list is the value it holds - the
        `_hash_value` precedent - and a list holding several is no attribute
        value: refused rather than coerced, since `str()` would store it as
        its Python repr."""
        file_object = File()
        file_object.custom_properties = CustomProperties()
        for name, value in (
                ('magic', ['ELF 64-bit LSB executable']),
                ('state', ['no', 'value'])):
            prop = Property()
            prop.name = name
            prop.value = value
            file_object.custom_properties.append(prop)
        parser = self._parse_external_observable(file_object, 'File')
        self.assertEqual(parser.diagnostics()['errors'], {})
        self.assertEqual(
            [
                (attribute.type, attribute.value)
                for attribute in parser.misp_event.attributes
            ],
            [('text', 'ELF 64-bit LSB executable')]
        )
        warnings = [
            warning for warnings in parser.diagnostics()['warnings'].values()
            for warning in warnings
        ]
        self.assertEqual(len(warnings), 1)
        self.assertIn(repr('state'), warnings[0])
        self.assertIn(f'MISP:File-{_OBSERVABLE_UUID}', warnings[0])

    @staticmethod
    def _yara_test_mechanism():
        test_mechanism = YaraTestMechanism()
        test_mechanism.rule = 'rule evil { condition: true }'
        return test_mechanism

    def test_external_indicator_with_yara_test_mechanism_converts(self):
        """The yara rule an Indicator carries as a test mechanism lands as a
        `yara` attribute the object the Indicator yields is detected with."""
        indicator = self._indicator(
            Object(self._file_with_three_properties()), _OBSERVABLE_UUID
        )
        indicator.observable.object_.id_ = f'MISP:File-{_OBSERVABLE_UUID}'
        indicator.add_test_mechanism(self._yara_test_mechanism())
        stix_package = STIXPackage()
        stix_package.add_indicator(indicator)
        parser = self._parse_external_package(stix_package)
        misp_object = self._assert_single_object(
            parser, 'file',
            {
                'filename': 'evil.exe', 'size-in-bytes': '1024',
                'md5': _MD5_HASH
            }
        )
        self.assertEqual(
            [
                (attribute.type, attribute.value)
                for attribute in parser.misp_event.attributes
            ],
            [('yara', 'rule evil { condition: true }')]
        )
        self.assertEqual(
            [
                (reference.relationship_type, reference.referenced_uuid)
                for reference in misp_object.references
            ],
            [('detected-with', parser.misp_event.attributes[0].uuid)]
        )

    def test_external_attribute_indicator_with_yara_test_mechanism_converts(self):
        """The legacy importer converted an Indicator's test mechanisms
        whatever the Indicator yielded: one yielding an attribute keeps its
        yara rule too, as a `yara` attribute next to it."""
        indicator = self._ip_indicator('198.51.100.4')
        indicator.add_test_mechanism(self._yara_test_mechanism())
        stix_package = STIXPackage()
        stix_package.add_indicator(indicator)
        parser = self._parse_external_package(stix_package)
        self.assertEqual(parser.diagnostics()['errors'], {})
        self.assertEqual(
            sorted(
                (attribute.type, attribute.value)
                for attribute in parser.misp_event.attributes
            ),
            [
                ('ip-dst', '198.51.100.4'),
                ('yara', 'rule evil { condition: true }')
            ]
        )

    def test_external_yara_survives_an_unconvertible_observable(self):
        """The rules are converted before the observable, as the legacy
        importer did: an observable of a type the parser does not map loses
        itself, not the yara rule the Indicator carries with it."""
        library_object = Object(Library())
        library_object.id_ = f'MISP:Library-{_OBSERVABLE_UUID}'
        indicator = self._indicator(library_object, _OBSERVABLE_UUID)
        indicator.add_test_mechanism(self._yara_test_mechanism())
        stix_package = STIXPackage()
        stix_package.add_indicator(indicator)
        parser = self._parse_external_package(stix_package)
        self.assertEqual(
            [
                (attribute.type, attribute.value)
                for attribute in parser.misp_event.attributes
            ],
            [('yara', 'rule evil { condition: true }')]
        )
        self.assertTrue(
            any(
                'LibraryObjectType' in error
                for errors in parser.diagnostics()['errors'].values()
                for error in errors
            )
        )

    def test_external_unknown_test_mechanism_records_an_error(self):
        indicator = self._domain_indicator('circl.lu')
        indicator.add_test_mechanism(GenericTestMechanism())
        stix_package = STIXPackage()
        stix_package.add_indicator(indicator)
        parser = self._parse_external_package(stix_package)
        self.assertEqual(
            [
                (attribute.type, attribute.value)
                for attribute in parser.misp_event.attributes
            ],
            [('domain', 'circl.lu')]
        )
        self.assertIn(
            'Unknown Test Mechanism type: genericTM:GenericTestMechanismType',
            parser.diagnostics()['errors']['misp event']
        )

    def test_external_indicator_with_snort_test_mechanism_converts(self):
        """A Snort mechanism was the one test mechanism type the mapping did
        not know: an Indicator carrying one recorded an error and lost the
        rules. Each rule lands as a `snort` attribute next to what the
        observable yields - python-stix lets a Snort mechanism carry
        several."""
        indicator = self._ip_indicator('198.51.100.4')
        test_mechanism = SnortTestMechanism()
        test_mechanism.rules = list(_SNORT_RULES)
        indicator.add_test_mechanism(test_mechanism)
        stix_package = STIXPackage()
        stix_package.add_indicator(indicator)
        parser = self._parse_external_package(stix_package)
        self.assertEqual(parser.diagnostics()['errors'], {})
        self.assertEqual(
            sorted(
                (attribute.type, attribute.value)
                for attribute in parser.misp_event.attributes
            ),
            [
                ('ip-dst', '198.51.100.4'),
                *(('snort', rule) for rule in _SNORT_RULES)
            ]
        )

    def test_external_ttp_with_resources_and_no_infrastructure_converts(self):
        """A TTP's resources may name tools and no infrastructure: the exploit
        target still lands as an attribute, carrying the tool galaxy tag."""
        ttp = self._ttp_with_exploit_target_cve('CVE-2021-44228')
        tool = ToolInformation()
        tool.name = 'Mimikatz'
        ttp.resources = Resource()
        ttp.resources.tools = Tools([tool])
        stix_package = STIXPackage()
        stix_package.add_ttp(ttp)
        parser = self._parse_external_package(stix_package)
        attribute = parser.misp_event.attributes[0]
        self.assertEqual(attribute.type, 'vulnerability')
        self.assertIn(
            'misp-galaxy:mitre-tool="Mimikatz"',
            {tag['name'] for tag in attribute.tags}
        )

    ############################################################################
    #                        RECORD UUIDS READ OFF IDS.                        #
    ############################################################################

    @staticmethod
    def _address_observable(value, object_id, observable_id=None):
        address = Address()
        address.address_value = value
        address.category = 'ipv4-addr'
        address_object = Object(address)
        address_object.id_ = object_id
        observable = Observable(address_object)
        observable.id_ = observable_id
        return observable

    def test_external_id_that_is_no_uuid_takes_a_uuid_derived_from_it(self):
        """A STIX 1 id is a QName, nothing makes its tail a uuid: one that is
        none aborted the whole package. The record takes a uuid derived from
        the whole id, prefix and type included - two types numbered alike in
        one namespace are two records."""
        port = Port()
        port.port_value = 443
        port_object = Object(port)
        port_object.id_ = 'example:Port-1'
        stix_package = STIXPackage()
        stix_package.add_observable(
            self._address_observable('198.51.100.4', 'example:Address-1')
        )
        stix_package.add_observable(Observable(port_object))
        parser = self._parse_external_package(stix_package)
        self.assertEqual(parser.diagnostics()['errors'], {})
        self.assertEqual(parser.diagnostics()['warnings'], {})
        attributes = {
            attribute.type: attribute for attribute in parser.misp_event.attributes
        }
        address, port = attributes['ip-dst'], attributes['port']
        self.assertEqual(
            str(address.uuid), str(uuid5(_UUIDv4, 'example:Address-1'))
        )
        self.assertEqual(address.comment, 'Original id was: example:Address-1')
        self.assertEqual(str(port.uuid), str(uuid5(_UUIDv4, 'example:Port-1')))
        self.assertEqual(port.comment, 'Original id was: example:Port-1')

    def test_external_id_ending_with_no_well_formed_uuid_is_no_uuid(self):
        object_id = f'example:Address-{_IP_UUID[:-3]}ZZZ'
        stix_package = STIXPackage()
        stix_package.add_observable(
            self._address_observable('198.51.100.4', object_id)
        )
        parser = self._parse_external_package(stix_package)
        attribute = parser.misp_event.attributes[0]
        self.assertEqual(str(attribute.uuid), str(uuid5(_UUIDv4, object_id)))
        self.assertEqual(attribute.comment, f'Original id was: {object_id}')

    def test_external_idref_to_an_id_that_is_no_uuid_resolves(self):
        """The derived uuid is what an `idref` to the record resolves to: the
        `Resolved_To` pair still makes a `passive-dns` object, and a related
        object still references the attribute its target became."""
        url = self._url_indicator('https://circl.lu/')
        url.observable.object_.related_objects[0].idref = 'example:Address-1'
        ip = Indicator()
        ip.add_observable(
            self._address_observable('198.51.100.4', 'example:Address-1')
        )
        file_object = self._object_with_related_object(
            File(), related_uuid=None
        )
        file_object.id_ = 'example:File-1'
        file_object.properties.file_name = 'evil.exe'
        file_object.properties.size_in_bytes = 12
        file_object.related_objects[0].idref = 'example:Address-1'
        stix_package = STIXPackage()
        stix_package.add_indicator(url)
        stix_package.add_indicator(ip)
        stix_package.add_observable(Observable(file_object))
        parser = self._parse_external_package(stix_package)
        self.assertEqual(parser.diagnostics()['errors'], {})
        misp_objects = {
            misp_object.name: misp_object
            for misp_object in parser.misp_event.objects
        }
        self.assertEqual(
            {
                attribute.object_relation: attribute.value
                for attribute in misp_objects['passive-dns'].attributes
            },
            {'rrname': 'https://circl.lu/', 'rdata': '198.51.100.4', 'rrtype': 'A'}
        )
        file_object = misp_objects['file']
        self.assertEqual(str(file_object.uuid), str(uuid5(_UUIDv4, 'example:File-1')))
        self.assertEqual(file_object.comment, 'Original id was: example:File-1')
        self.assertEqual(
            [
                str(reference.referenced_uuid)
                for reference in file_object.references
            ],
            [str(uuid5(_UUIDv4, 'example:Address-1'))]
        )

    def test_external_idless_object_takes_the_uuid_of_its_observable(self):
        """`id` is optional on a CybOX Object, and a producer routinely puts
        it on the Observable alone: the Object carrying none aborted the
        whole package. The record takes the Observable's id, read the same
        way, and an element carrying neither takes a random uuid."""
        stix_package = STIXPackage()
        stix_package.add_observable(
            self._address_observable(
                '198.51.100.4', None, f'example:Observable-{_IP_UUID}'
            )
        )
        stix_package.add_observable(
            self._address_observable(
                '198.51.100.5', None, 'example:Observable-1'
            )
        )
        indicator = Indicator()
        indicator.id_ = 'example:Indicator-1'
        indicator.add_observable(self._address_observable('198.51.100.6', None))
        stix_package.add_indicator(indicator)
        parser = self._parse_external_package(stix_package)
        self.assertEqual(parser.diagnostics()['errors'], {})
        self.assertEqual(parser.diagnostics()['warnings'], {})
        attributes = {
            attribute.value: attribute
            for attribute in parser.misp_event.attributes
        }
        self.assertEqual(attributes['198.51.100.4'].uuid, _IP_UUID)
        self.assertEqual(
            str(attributes['198.51.100.5'].uuid),
            str(uuid5(_UUIDv4, 'example:Observable-1'))
        )
        self.assertNotIn(
            attributes['198.51.100.6'].uuid,
            (_IP_UUID, str(uuid5(_UUIDv4, 'example:Indicator-1')))
        )

    def test_external_idless_ttp_and_course_of_action_convert(self):
        ttp = self._ttp_with_exploit_target_cve('CVE-2021-44228')
        ttp.id_ = None
        course_of_action = self._course_of_action()
        course_of_action.id_ = None
        stix_package = STIXPackage()
        stix_package.add_ttp(ttp)
        stix_package.add_course_of_action(course_of_action)
        parser = self._parse_external_package(stix_package)
        self.assertEqual(parser.diagnostics()['errors'], {})
        self.assertEqual(
            [attribute.type for attribute in parser.misp_event.attributes],
            ['vulnerability']
        )
        self.assertEqual(
            [misp_object.name for misp_object in parser.misp_event.objects],
            ['course-of-action']
        )

    def test_external_uuid_of_a_version_misp_refuses_is_replaced(self):
        """Unchanged by the id reading: a uuid of a version MISP refuses is
        replaced by one derived from the bare uuid, whatever id carries it."""
        object_uuid = '3fa85f64-5717-0562-b3fc-2c963f66afa6'
        stix_package = STIXPackage()
        stix_package.add_observable(
            self._address_observable(
                '198.51.100.4', f'example:Address-{object_uuid}'
            )
        )
        parser = self._parse_external_package(stix_package)
        attribute = parser.misp_event.attributes[0]
        self.assertEqual(str(attribute.uuid), str(uuid5(_UUIDv4, object_uuid)))
        self.assertEqual(attribute.comment, f'Original UUID was: {object_uuid}')

    def test_external_replaced_uuid_keeps_the_relation_standing_in_for_a_comment(self):
        """The comment keeping the original id is appended to the one a text
        attribute reads off its relation, never put in its place."""
        custom_object = Object(self._custom(None, ('myprop', 'some text')))
        custom_object.id_ = 'example:Custom-1'
        stix_package = STIXPackage()
        stix_package.add_observable(Observable(custom_object))
        parser = self._parse_external_package(stix_package)
        attribute = parser.misp_event.attributes[0]
        self.assertEqual(
            (attribute.type, attribute.value), ('text', 'some text')
        )
        self.assertEqual(
            attribute.comment, 'myprop - Original id was: example:Custom-1'
        )

    def test_internal_composition_object_keeps_its_uuid(self):
        """The export writes a composition id as
        `MISP:{name}_ObservableComposition-{uuid}`, the first hyphen inside a
        template name carrying one: the object came back with a uuid of
        `ip_ObservableComposition-{uuid}`."""
        event = get_event_with_domain_ip_object()
        parser = self._parse_internal_package(self._misp_export(event))
        self.assertEqual(
            [misp_object.uuid for misp_object in parser.misp_event.objects],
            [event['Event']['Object'][0]['uuid']]
        )

    @staticmethod
    def _derived_attribute_uuid(object_uuid, attribute, value=None):
        """The uuid an object attribute derives, from the value as the import
        read it - which pymisp may have parsed since, a datetime read as a
        string off the wire among others."""
        return str(
            uuid5(
                _UUIDv4,
                f'{object_uuid} - {attribute.object_relation} - '
                f'{attribute.value if value is None else value}'
            )
        )

    def _assert_derived_attribute_uuids(self, misp_object, values=None):
        for attribute in misp_object.attributes:
            with self.subTest(relation=attribute.object_relation):
                self.assertEqual(
                    attribute.uuid,
                    self._derived_attribute_uuid(
                        misp_object.uuid, attribute,
                        (values or {}).get(attribute.object_relation)
                    )
                )

    def test_internal_composition_members_keep_their_uuids(self):
        """The export writes every member of a `domain-ip`, `ip-port` or `url`
        composition as an Observable carrying the attribute's own uuid: read
        per attribute, as the object reads its own."""
        for fixture in (get_event_with_domain_ip_object,
                        get_event_with_ip_port_object,
                        get_event_with_url_object):
            event = fixture()
            misp_object = event['Event']['Object'][0]
            with self.subTest(name=misp_object['name']):
                parser = self._parse_internal_package(self._misp_export(event))
                self.assertEqual(parser.diagnostics()['errors'], {})
                converted = parser.misp_event.objects[0]
                # What comes back, that is: the relations the export drops
                # are ticket 21's
                exported = {
                    attribute['uuid']: str(attribute['value'])
                    for attribute in misp_object['Attribute']
                }
                self.assertTrue(converted.attributes)
                for attribute in converted.attributes:
                    with self.subTest(relation=attribute.object_relation):
                        self.assertEqual(
                            exported.get(attribute.uuid), str(attribute.value)
                        )

    def test_internal_file_composition_reads_the_members_carrying_data(self):
        """A `malware-sample` and an `attachment` carrying their data are
        Observables of their own, written with the attribute's uuid; the File
        member carries the object's, so every other attribute derives."""
        event = get_event_with_file_object_with_artifact()
        misp_object = event['Event']['Object'][0]
        parser = self._parse_internal_package(self._misp_export(event))
        self.assertEqual(parser.diagnostics()['errors'], {})
        converted = parser.misp_event.get_objects_by_name('file')[0]
        self.assertEqual(converted.uuid, misp_object['uuid'])
        read = {
            attribute['object_relation']: attribute['uuid']
            for attribute in misp_object['Attribute'] if attribute.get('data')
        }
        self.assertEqual(sorted(read), ['attachment', 'malware-sample'])
        for attribute in converted.attributes:
            with self.subTest(relation=attribute.object_relation):
                self.assertEqual(
                    attribute.uuid,
                    read.get(
                        attribute.object_relation,
                        self._derived_attribute_uuid(converted.uuid, attribute)
                    )
                )

    def test_internal_email_attachment_keeps_its_uuid(self):
        """The export writes an attachment as a related File carrying the
        attribute's uuid in its id; the header fields carry none and derive."""
        event = get_event_with_email_object()
        misp_object = event['Event']['Object'][0]
        parser = self._parse_internal_package(self._misp_export(event))
        self.assertEqual(parser.diagnostics()['errors'], {})
        converted = parser.misp_event.get_objects_by_name('email')[0]
        attachments = {
            attribute['value']: attribute['uuid']
            for attribute in misp_object['Attribute']
            if attribute['object_relation'] == 'attachment'
        }
        self.assertTrue(attachments)
        for attribute in converted.attributes:
            with self.subTest(relation=attribute.object_relation):
                if attribute.object_relation == 'attachment':
                    self.assertEqual(
                        attribute.uuid, attachments[attribute.value]
                    )
                    continue
                self.assertEqual(
                    attribute.uuid,
                    self._derived_attribute_uuid(converted.uuid, attribute)
                )

    def test_internal_folded_object_attributes_take_derived_uuids(self):
        """Nothing on the wire carries the uuid of an attribute folded into
        a CybOX object: it derives from the uuid the object takes, the
        relation and the value - the `pe` and each `pe-section` from their
        own derived uuid."""
        for fixture in (get_event_with_x509_object,
                        get_event_with_file_and_pe_objects):
            event = fixture()
            with self.subTest(fixture=fixture.__name__):
                parser = self._parse_internal_package(self._misp_export(event))
                self.assertEqual(parser.diagnostics()['errors'], {})
                for misp_object in parser.misp_event.objects:
                    with self.subTest(name=misp_object.name):
                        # A `pe` custom property is read as the string the
                        # wire carries, and pymisp parses the datetime after
                        values = {
                            attribute['object_relation']: attribute['value']
                            for exported in event['Event']['Object']
                            if exported['name'] == misp_object.name == 'pe'
                            for attribute in exported['Attribute']
                            if attribute['type'] == 'datetime'
                        }
                        self._assert_derived_attribute_uuids(
                            misp_object, values
                        )

    def test_internal_context_object_attributes_take_derived_uuids(self):
        """The `attack-pattern`, `vulnerability` and `weakness` objects a TTP
        carries and the `course-of-action` object derive off the uuid of the
        object they build."""
        for fixture in (get_event_with_attack_pattern_object,
                        get_event_with_vulnerability_object,
                        get_event_with_weakness_object,
                        get_event_with_course_of_action_object):
            event = fixture()
            misp_object = event['Event']['Object'][0]
            with self.subTest(name=misp_object['name']):
                parser = self._parse_internal_package(self._misp_export(event))
                self.assertEqual(parser.diagnostics()['errors'], {})
                converted = parser.misp_event.get_objects_by_name(
                    misp_object['name']
                )[0]
                self.assertEqual(converted.uuid, misp_object['uuid'])
                self._assert_derived_attribute_uuids(converted)

    def test_internal_two_imports_give_identical_attribute_uuids(self):
        """The property the derivation exists for: one document imported
        twice lands the same attribute uuids, not a disjoint set."""
        event = self._misp_event_reaching_every_import_path()
        event['Event']['Object'].extend(
            fixture()['Event']['Object'][0] for fixture in (
                get_event_with_x509_object, get_event_with_email_object,
                get_event_with_file_object_with_artifact
            )
        )

        def attribute_uuids():
            parser = self._parse_internal_package(self._misp_export(event))
            return {
                misp_object.uuid: sorted(
                    attribute.uuid for attribute in misp_object.attributes
                )
                for misp_object in parser.misp_event.objects
            }

        self.assertEqual(attribute_uuids(), attribute_uuids())

    def test_external_observable_object_attributes_take_derived_uuids(self):
        """The observable object builder is shared: the External import
        derives the same way, off the uuid the CybOX object id gives."""
        connection = NetworkConnection()
        connection.source_socket_address = self._socket_address(
            '198.51.100.7', 49152
        )
        connection.layer4_protocol = 'TCP'
        parser = self._parse_external_observable(
            connection, 'NetworkConnection'
        )
        self.assertEqual(parser.diagnostics()['errors'], {})
        misp_object = parser.misp_event.objects[0]
        self.assertEqual(misp_object.uuid, _OBSERVABLE_UUID)
        self._assert_derived_attribute_uuids(misp_object)

    def test_external_process_network_connections_take_derived_uuids(self):
        """A network connection a process lists has no id of its own: its
        object derives from the process object's uuid and its index, and its
        attributes from that."""
        process = Process()
        process.pid = 4242
        process.network_connection_list = NetworkConnectionList()
        for address, port in (('203.0.113.9', 443), ('203.0.113.10', 80)):
            connection = NetworkConnection()
            connection.destination_socket_address = self._socket_address(
                address, port
            )
            process.network_connection_list.append(connection)
        parser = self._parse_external_observable(process, 'Process')
        self.assertEqual(parser.diagnostics()['errors'], {})
        process_object = parser.misp_event.get_objects_by_name('process')[0]
        self.assertEqual(process_object.uuid, _OBSERVABLE_UUID)
        connections = parser.misp_event.get_objects_by_name(
            'network-connection'
        )
        self.assertEqual(
            [connection.uuid for connection in connections],
            [
                str(
                    uuid5(
                        _UUIDv4,
                        f'{_OBSERVABLE_UUID} - network-connections - {index}'
                    )
                )
                for index in range(2)
            ]
        )
        self.assertEqual(
            sorted(
                reference.referenced_uuid
                for reference in process_object.references
            ),
            sorted(connection.uuid for connection in connections)
        )
        for misp_object in (process_object, *connections):
            with self.subTest(name=misp_object.name, uuid=misp_object.uuid):
                self._assert_derived_attribute_uuids(misp_object)

    @classmethod
    def _external_package_of_export(cls, event):
        """The Indicators and Observables the MISP export relates to its
        Incident, written on the package itself where the External parser
        reads them."""
        incident = cls._misp_export(event).related_packages.related_package[
            0].item.incidents[0]
        stix_package = STIXPackage()
        for related in incident.related_indicators or ():
            stix_package.add_indicator(related.item)
        for related in incident.related_observables or ():
            stix_package.add_observable(related.item)
        return stix_package

    def test_external_email_attachment_keeps_its_uuid(self):
        """The attachment reader is shared: the External import reads the
        related File id the same way."""
        event = get_event_with_email_object()
        attachments = {
            attribute['value']: attribute['uuid']
            for attribute in event['Event']['Object'][0]['Attribute']
            if attribute['object_relation'] == 'attachment'
        }
        parser = self._parse_external_package(
            self._external_package_of_export(event)
        )
        self.assertEqual(parser.diagnostics()['errors'], {})
        converted = parser.misp_event.get_objects_by_name('email')[0]
        self.assertTrue(attachments)
        for attribute in converted.attributes:
            with self.subTest(relation=attribute.object_relation):
                self.assertEqual(
                    attribute.uuid,
                    attachments.get(
                        attribute.value,
                        self._derived_attribute_uuid(converted.uuid, attribute)
                    )
                )

    def test_external_two_imports_give_identical_attribute_uuids(self):
        event = get_base_event()
        event['Event']['Object'] = [
            fixture()['Event']['Object'][0] for fixture in (
                get_event_with_x509_object, get_event_with_email_object,
                get_event_with_process_object
            )
        ]

        def attribute_uuids():
            parser = self._parse_external_package(
                self._external_package_of_export(event)
            )
            self.assertEqual(len(parser.misp_event.objects), 3)
            return {
                misp_object.uuid: sorted(
                    attribute.uuid for attribute in misp_object.attributes
                )
                for misp_object in parser.misp_event.objects
            }

        self.assertEqual(attribute_uuids(), attribute_uuids())

    def test_internal_attributes_derive_from_a_remapped_object_uuid(self):
        """The prefix is the uuid the object takes: one of a version MISP
        refuses is replaced, and the attributes derive from the replacement."""
        event = get_event_with_x509_object()
        object_uuid = '3fa85f64-5717-0562-b3fc-2c963f66afa6'
        event['Event']['Object'][0]['uuid'] = object_uuid
        parser = self._parse_internal_package(self._misp_export(event))
        self.assertEqual(parser.diagnostics()['errors'], {})
        converted = parser.misp_event.objects[0]
        self.assertEqual(str(converted.uuid), str(uuid5(_UUIDv4, object_uuid)))
        self._assert_derived_attribute_uuids(converted)

    def test_external_passive_dns_attributes_stay_random(self):
        """The object the DNS bookkeeping builds has no uuid in hand: nothing
        to derive its attributes from."""
        stix_package = STIXPackage()
        stix_package.add_indicator(self._url_indicator('https://circl.lu/'))
        stix_package.add_indicator(self._ip_indicator('198.51.100.4'))
        parser = self._parse_external_package(stix_package)
        self.assertEqual(parser.diagnostics()['errors'], {})
        passive_dns = parser.misp_event.get_objects_by_name('passive-dns')[0]
        for attribute in passive_dns.attributes:
            with self.subTest(relation=attribute.object_relation):
                self.assertEqual(UUID(attribute.uuid).version, 4)

    @staticmethod
    def _flagged(event):
        """The event with every attribute of every object flagged `to_ids`:
        what the export writes an object as an Indicator for."""
        for misp_object in event['Event'].get('Object', ()):
            for attribute in misp_object['Attribute']:
                attribute['to_ids'] = True
        return event

    def _assert_timestamp(self, record, timestamp):
        # pymisp parses an attribute timestamp into a datetime, and keeps the
        # one set on an object as it was given
        value = record.timestamp
        if isinstance(value, datetime):
            value = value.timestamp()
        self.assertEqual(int(value), int(timestamp))

    def test_internal_single_observable_object_reads_the_indicator_timestamp(self):
        """An object whose attributes fold into one CybOX object is exported
        as an Indicator carrying its timestamp: read, as a composition's is."""
        for fixture in (get_event_with_x509_object, get_event_with_asn_object):
            event = self._flagged(fixture())
            misp_object = event['Event']['Object'][0]
            with self.subTest(name=misp_object['name']):
                parser = self._parse_internal_package(self._misp_export(event))
                self.assertEqual(parser.diagnostics()['errors'], {})
                self._assert_timestamp(
                    parser.misp_event.objects[0], misp_object['timestamp']
                )

    def test_internal_standalone_pe_reads_its_indicator_timestamp(self):
        """A `pe` no `file` includes is its own Indicator; the sections under
        it carry no timestamp of their own on the wire, and take none."""
        event = self._flagged(get_event_with_pe_objects())
        parser = self._parse_internal_package(self._misp_export(event))
        self.assertEqual(parser.diagnostics()['errors'], {})
        pe_object = parser.misp_event.get_objects_by_name('pe')[0]
        self._assert_timestamp(
            pe_object, event['Event']['Object'][0]['timestamp']
        )
        for section in parser.misp_event.get_objects_by_name('pe-section'):
            self.assertIsNone(getattr(section, 'timestamp', None))

    def test_internal_pe_under_a_file_indicator_takes_no_timestamp(self):
        """The one timestamp on the wire is the `file` Indicator's: the `pe`
        and its sections are not stamped with it."""
        event = self._flagged(get_event_with_file_and_pe_objects())
        parser = self._parse_internal_package(self._misp_export(event))
        self.assertEqual(parser.diagnostics()['errors'], {})
        file_object = parser.misp_event.get_objects_by_name('file')[0]
        self._assert_timestamp(
            file_object, event['Event']['Object'][0]['timestamp']
        )
        for name in ('pe', 'pe-section'):
            for misp_object in parser.misp_event.get_objects_by_name(name):
                with self.subTest(name=name):
                    self.assertIsNone(getattr(misp_object, 'timestamp', None))

    def test_internal_context_objects_read_their_timestamp(self):
        """The TTP an `attack-pattern`, `vulnerability` or `weakness` object
        is written as carries its timestamp, and the COA_Taken stub the
        Incident takes a `course-of-action` object with carries it too."""
        for fixture in (get_event_with_attack_pattern_object,
                        get_event_with_vulnerability_object,
                        get_event_with_weakness_object,
                        get_event_with_course_of_action_object):
            event = fixture()
            misp_object = event['Event']['Object'][0]
            with self.subTest(name=misp_object['name']):
                parser = self._parse_internal_package(self._misp_export(event))
                self.assertEqual(parser.diagnostics()['errors'], {})
                converted = parser.misp_event.get_objects_by_name(
                    misp_object['name']
                )[0]
                self._assert_timestamp(converted, misp_object['timestamp'])

    def test_internal_course_of_action_reads_the_stub_timestamp(self):
        """The stub is what is read, not the full Course of Action: one
        exported before the export stamped it carries the export time."""
        event = get_event_with_course_of_action_object()
        misp_object = event['Event']['Object'][0]
        stix_package = self._misp_export(event)
        inner = stix_package.related_packages.related_package[0].item
        inner.courses_of_action[0].timestamp = datetime(2026, 9, 24, 12, 0)
        parser = self._parse_internal_package(stix_package)
        self._assert_timestamp(
            parser.misp_event.objects[0], misp_object['timestamp']
        )

    def test_internal_ttp_attributes_read_their_timestamp(self):
        """A `vulnerability` or `weakness` attribute without `to_ids` is a
        TTP, stamped with the attribute's timestamp."""
        for fixture in (get_event_with_vulnerability_attribute,
                        get_event_with_weakness_attribute):
            event = fixture()
            attribute = event['Event']['Attribute'][0]
            with self.subTest(type=attribute['type']):
                parser = self._parse_internal_package(self._misp_export(event))
                self.assertEqual(parser.diagnostics()['errors'], {})
                records = (
                    *parser.misp_event.attributes, *parser.misp_event.objects
                )
                self.assertEqual(len(records), 1)
                self._assert_timestamp(records[0], attribute['timestamp'])

    def test_internal_plain_observables_take_no_timestamp(self):
        """An object or an attribute exported without `to_ids` is a plain
        Observable, which carries no timestamp: the named loss."""
        event = get_event_with_domain_attribute()
        event['Event']['Attribute'][0]['to_ids'] = False
        event['Event']['Object'] = get_event_with_x509_object()['Event'][
            'Object']
        parser = self._parse_internal_package(self._misp_export(event))
        self.assertEqual(parser.diagnostics()['errors'], {})
        for record in (*parser.misp_event.attributes,
                       *parser.misp_event.objects):
            with self.subTest(uuid=record.uuid):
                self.assertIsNone(getattr(record, 'timestamp', None))

    def test_external_single_observable_object_reads_the_indicator_timestamp(self):
        """The External Indicator path builds the object through the shared
        builder, and hands it the Indicator's timestamp the same way - the
        standalone `pe` included, its sections left with none."""
        for fixture in (get_event_with_x509_object, get_event_with_asn_object,
                        get_event_with_pe_objects):
            event = self._flagged(fixture())
            misp_object = event['Event']['Object'][0]
            with self.subTest(name=misp_object['name']):
                parser = self._parse_external_package(
                    self._external_package_of_export(event)
                )
                self.assertEqual(parser.diagnostics()['errors'], {})
                self._assert_timestamp(
                    parser.misp_event.get_objects_by_name(
                        misp_object['name']
                    )[0],
                    misp_object['timestamp']
                )
                for section in parser.misp_event.get_objects_by_name(
                        'pe-section'):
                    self.assertIsNone(getattr(section, 'timestamp', None))
