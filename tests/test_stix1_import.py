#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
from cybox.common import Hash, HashList
from cybox.common.object_properties import CustomProperties, Property
from cybox.core import (
    Object, Observable, ObservableComposition, Observables, RelatedObject)
from cybox.objects.address_object import Address, EmailAddress
from cybox.objects.custom_object import Custom
from cybox.objects.dns_record_object import DNSRecord
from cybox.objects.domain_name_object import DomainName
from cybox.objects.file_object import File
from cybox.objects.library_object import Library
from cybox.objects.network_connection_object import NetworkConnection
from cybox.objects.network_socket_object import NetworkSocket
from cybox.objects.port_object import Port
from cybox.objects.process_object import ImageInfo, Process
from cybox.objects.socket_address_object import SocketAddress
from cybox.objects.uri_object import URI
from cybox.objects.user_account_object import UserAccount
from cybox.objects.whois_object import (
    WhoisEntry, WhoisRegistrant, WhoisRegistrants, WhoisRegistrar)
from cybox.objects.win_executable_file_object import (
    Entropy, PESection, PESectionHeaderStruct, PESectionList,
    WinExecutableFile)
from cybox.objects.win_registry_key_object import (
    RegistryValue, RegistryValues, WinRegistryKey)
from cybox.objects.x509_certificate_object import (
    Validity, X509Cert, X509Certificate, X509CertificateSignature)
from datetime import datetime
from misp_stix_converter import (
    MISPtoSTIX1AttributesParser, MISPtoSTIX1EventsParser,
    MissingSTIXContentError, stix_1_to_misp, STIXLoadingError)
from misp_stix_converter.tools import (
    is_stix1_from_misp, load_stix1_package, stix1_loading_helpers)
from mixbox.namespaces import NamespaceNotFoundError
from misp_stix_converter.stix2misp.external_stix1_to_misp import (
    ExternalSTIX1toMISPParser)
from misp_stix_converter.stix2misp.internal_stix1_to_misp import (
    InternalSTIX1toMISPParser)
from pymisp import MISPEvent
from unittest.mock import patch
from stix.coa import CourseOfAction, Objective
from stix.common import Statement, ToolInformation
from stix.common.related import (
    RelatedObservable, RelatedPackage, RelatedPackages)
from stix.core import STIXHeader, STIXPackage
from stix.data_marking import Marking, MarkingSpecification
from stix.extensions.marking.tlp import TLPMarkingStructure
from stix.extensions.test_mechanism.generic_test_mechanism import (
    GenericTestMechanism)
from stix.extensions.test_mechanism.yara_test_mechanism import (
    YaraTestMechanism)
from stix.exploit_target import ExploitTarget
from stix.exploit_target.vulnerability import Vulnerability
from stix.incident import Incident
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
from .test_events import (
    get_base_event, get_event_with_asn_object,
    get_event_with_attack_pattern_galaxy, get_event_with_attack_pattern_object,
    get_event_with_course_of_action_galaxy, get_event_with_domain_attribute,
    get_event_with_domain_ip_object, get_event_with_github_username_attribute,
    get_event_with_ip_port_attributes, get_event_with_malware_galaxy,
    get_event_with_pattern_attribute, get_event_with_process_object,
    get_event_with_tool_galaxy, get_event_with_windows_service_attributes)

_COA_UUID = '4c1e5f2a-8b3d-4a6c-9e7f-1d2b3c4d5e6f'
_OBSERVABLE_UUID = '7a9b0c1d-2e3f-4a5b-8c9d-0e1f2a3b4c5d'
_RELATED_UUID = '1b2c3d4e-5f6a-4b8c-9d0e-1f2a3b4c5d6e'
_ACTOR_UUID = '5e6f7a8b-9c0d-4e1f-8a2b-3c4d5e6f7a8b'
_DOMAIN_UUID = '2d3e4f5a-6b7c-4d8e-9f0a-1b2c3d4e5f6a'
_IP_UUID = '3e4f5a6b-7c8d-4e9f-8a0b-1c2d3e4f5a6b'
_URL_UUID = '4f5a6b7c-8d9e-4f0a-8b1c-2d3e4f5a6b7c'
_MD5_HASH = '8a2a5fc2ce56b3b04d58539a9d3d8d3e'
# `Type=Other` with the value in `Simple_Hash_Value`: how MISP's own STIX 1
# export wrote an ssdeep hash, cybox naming nothing better for its length
_SSDEEP_HASH = '6144:BvqbV6zoA5yJlTKCjXsJK4Tdv:BvqbV6zoA5yJlTKCjXsJK4T'


class TestSTIX1Import(TestSTIX):

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

    def test_external_whois_observable_converts(self):
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
                'whois-registrar': 'GANDI SAS', 'domain': 'circl.lu',
                'registrant-name': 'CIRCL', 'registrant-email': 'info@circl.lu',
                'creation-date': '2020-01-01 00:00:00'
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
        """A property the template does not define - or a template pymisp
        does not know - has no type to take from it: the attribute is text."""
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
