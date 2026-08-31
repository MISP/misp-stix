#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cybox.common import Hash
from cybox.core import Object, Observable, Observables, RelatedObject
from cybox.objects.address_object import Address
from cybox.objects.domain_name_object import DomainName
from cybox.objects.file_object import File
from cybox.objects.uri_object import URI
from datetime import datetime
from misp_stix_converter import stix_1_to_misp, STIXLoadingError
from misp_stix_converter.tools import load_stix1_package, stix1_loading_helpers
from mixbox.namespaces import NamespaceNotFoundError
from misp_stix_converter.stix2misp.external_stix1_to_misp import (
    ExternalSTIX1toMISPParser)
from misp_stix_converter.stix2misp.internal_stix1_to_misp import (
    InternalSTIX1toMISPParser)
from misp_stix_converter.stix2misp.stix1_mapping import (
    ExternalSTIX1toMISPMapping)
from unittest.mock import patch
from stix.coa import CourseOfAction, Objective
from stix.common import EncodedCDATA, Statement
from stix.common.related import RelatedPackage, RelatedPackages
from stix.core import STIXHeader, STIXPackage
from stix.data_marking import Marking, MarkingSpecification
from stix.extensions.marking.tlp import TLPMarkingStructure
from stix.extensions.test_mechanism.yara_test_mechanism import YaraTestMechanism
from stix.incident import Incident
from stix.incident.history import History, HistoryItem, JournalEntry
from stix.indicator import Indicator
from stix.threat_actor import ThreatActor
from stix.ttp import TTP, Behavior
from stix.ttp.infrastructure import Infrastructure
from stix.ttp.malware_instance import MalwareInstance
from stix.ttp.resource import Resource
from pathlib import Path
from tempfile import TemporaryDirectory
from ._test_stix import TestSTIX
from ._test_stix_import import (
    SANITISED_TAG_VALUE, SMUGGLING_TAG_VALUE)

_COA_UUID = '4c1e5f2a-8b3d-4a6c-9e7f-1d2b3c4d5e6f'
_OBSERVABLE_UUID = '7a9b0c1d-2e3f-4a5b-8c9d-0e1f2a3b4c5d'
_RELATED_UUID = '1b2c3d4e-5f6a-4b8c-9d0e-1f2a3b4c5d6e'
_ACTOR_UUID = '5e6f7a8b-9c0d-4e1f-8a2b-3c4d5e6f7a8b'
_DOMAIN_UUID = '2d3e4f5a-6b7c-4d8e-9f0a-1b2c3d4e5f6a'
_IP_UUID = '3e4f5a6b-7c8d-4e9f-8a0b-1c2d3e4f5a6b'
_URL_UUID = '4f5a6b7c-8d9e-4f0a-8b1c-2d3e4f5a6b7c'


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
    def _observable_with_related_object():
        """An Observable whose own properties yield no attribute value, so the
        related objects are turned into MISP references rather than folded into
        the passive-dns special case."""
        file_object = Object(File())
        file_object.id_ = f'MISP:File-{_OBSERVABLE_UUID}'
        related_object = RelatedObject()
        related_object.idref = f'MISP:Address-{_RELATED_UUID}'
        related_object.relationship = 'Contains'
        file_object.related_objects.append(related_object)
        return Observable(file_object)

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

    def _parse_external_package(self, stix_package, parser=None):
        parser = parser or ExternalSTIX1toMISPParser()
        parser.load_stix_package(stix_package)
        parser.parse_stix_package()
        return parser

    def _parse_internal_package(self, stix_package, parser=None):
        parser = parser or InternalSTIX1toMISPParser()
        parser.load_stix_package(stix_package)
        parser.parse_stix_package()
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
        stix_package = STIXPackage()
        if outer_title is not None:
            stix_package.stix_header = cls._stix_header(outer_title)
        stix_package.related_packages = RelatedPackages()
        stix_package.related_packages.append(RelatedPackage(inner_package))
        return stix_package

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
        parser = self._parse_external_package(stix_package)
        # `references` is parser-internal bookkeeping - nothing in the library
        # reads it back yet - so this pins the sanitised idref at the only place
        # it is observable.
        self.assertEqual(
            parser.references[_OBSERVABLE_UUID],
            [{'idref': _RELATED_UUID, 'relationship': 'contains'}]
        )

    ############################################################################
    #                          TEST MECHANISM TESTS.                          #
    ############################################################################

    @staticmethod
    def _object_indicator_with_test_mechanism():
        """A File observable with enough properties (a filename and two
        hashes) that its value resolves to a list of attribute dicts - the
        object case - carrying a Yara test mechanism with a rule value, which
        is the only combination that reaches the `test_mechanisms.append(...)`
        line."""
        file_ = File()
        file_.file_name = 'test.exe'
        file_.add_hash(Hash('d41d8cd98f00b204e9800998ecf8427e', type_='MD5'))
        file_.add_hash(
            Hash('da39a3ee5e6b4b0d3255bfef95601890afd80709', type_='SHA1')
        )
        file_object = Object(file_)
        file_object.id_ = f'MISP:File-{_OBSERVABLE_UUID}'
        indicator = Indicator()
        indicator.id_ = f'MISP:Indicator-{_OBSERVABLE_UUID}'
        indicator.add_observable(Observable(file_object))
        test_mechanism = YaraTestMechanism()
        test_mechanism.rule = EncodedCDATA(value='rule test {}', encoded=True)
        indicator.add_test_mechanism(test_mechanism)
        return indicator

    def test_external_object_indicator_with_test_mechanism_converts(self):
        """Regression test for the `attribute.uuid` `NameError` in the object
        case of `_parse_indicator`: `attribute` is never bound on this branch,
        so any external STIX 1 indicator resolving to an object and carrying a
        test mechanism used to crash outright.

        `test_mechanisms_mapping` is patched in because the mapping class only
        defines `test_mechanism_mapping` (singular) - a separate, pre-existing
        typo on the line just above the one this test targets, out of scope
        here - which would otherwise raise its own `AttributeError` before
        this code is ever reached.
        """
        stix_package = STIXPackage()
        stix_package.add_indicator(self._object_indicator_with_test_mechanism())
        with patch.object(
            ExternalSTIX1toMISPMapping, 'test_mechanisms_mapping',
            classmethod(ExternalSTIX1toMISPMapping.test_mechanism_mapping.__func__),
            create=True
        ):
            parser = self._parse_external_package(stix_package)
        self.assertEqual(len(parser.misp_event.objects), 1)
        misp_object = parser.misp_event.objects[0]
        self.assertEqual(len(parser.misp_event.attributes), 1)
        yara_attribute = parser.misp_event.attributes[0]
        self.assertEqual(yara_attribute.type, 'yara')
        self.assertEqual(yara_attribute.value, 'rule test {}')
        self.assertEqual(len(misp_object.references), 1)
        reference = misp_object.references[0]
        self.assertEqual(reference.relationship_type, 'detected-with')
        # The reference has to point at the uuid of the attribute the test
        # mechanism's rule was turned into - not at some other uuid, and not
        # crash trying to read one off an unbound name.
        self.assertEqual(reference.referenced_uuid, yara_attribute.uuid)

    ############################################################################
    #                          INCIDENT HISTORY TESTS.                         #
    ############################################################################

    def test_internal_incident_history_converts(self):
        incident = Incident()
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
            Incident(), inner_title='Incident title',
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

    def test_stix_1_detection_logs_a_warning(self):
        from misp_stix_converter.tools.stix1_to_misp_helpers import (
            is_stix1_from_misp)
        stix_package = self._internal_titled_package()
        with self.assertLogs('misp_stix_converter', level='WARNING'):
            self.assertTrue(is_stix1_from_misp(stix_package))

    def test_stix_1_classification_rejects_invalid_value(self):
        with self.assertRaises(ValueError):
            stix_1_to_misp('unused.xml', classification='banana')

    ############################################################################
    #                           EVENT INFO FALLBACK.                           #
    ############################################################################

    def test_internal_event_info_falls_back_to_stix_header_title(self):
        """A title-less Incident takes its event info from the header of its own
        related package, which is where the MISP export writes the per-event
        title - not from the collection-level wrapper header."""
        parser = self._parse_internal_package(
            self._internal_package(
                Incident(),
                inner_title="Export from ACME's MISP",
                outer_title='Collection level title'
            )
        )
        self.assertEqual(parser.misp_event.info, "Export from ACME's MISP")

    def test_internal_event_info_falls_back_to_wrapper_header_title(self):
        parser = self._parse_internal_package(
            self._internal_package(
                Incident(), outer_title='Collection level title'
            )
        )
        self.assertEqual(parser.misp_event.info, 'Collection level title')

    def test_internal_event_info_falls_back_to_generic_message(self):
        parser = self._parse_internal_package(
            self._internal_package(Incident())
        )
        self.assertEqual(
            parser.misp_event.info,
            'Imported from STIX 1.1.1 Package generated with MISP'
        )

    def test_external_event_info_falls_back_past_a_titleless_header(self):
        """A STIX header always carries a `title` field, so a header present but
        untitled must not become the event info."""
        stix_package = STIXPackage()
        stix_package.stix_header = self._stix_header(None)
        parser = self._parse_external_package(stix_package)
        self.assertEqual(
            parser.misp_event.info, 'Imported from external STIX 1.1.1 Package'
        )

    ############################################################################
    #                              GALAXY TAGS.                                #
    ############################################################################

    @classmethod
    def _ttp_with_malware_title(cls, title):
        """A TTP naming a malware what a taxonomy tag value cannot carry, over
        infrastructure the galaxy tag then lands on as an attribute."""
        ttp = TTP()
        ttp.id_ = f'MISP:TTP-{_ACTOR_UUID}'
        malware_instance = MalwareInstance()
        malware_instance.title = title
        ttp.behavior = Behavior()
        ttp.behavior.add_malware_instance(malware_instance)
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
        self.assertIn(f'misp-galaxy:ransomware="{SANITISED_TAG_VALUE}"', tags)
        self.assertNotIn(
            f'misp-galaxy:ransomware="{SMUGGLING_TAG_VALUE}"', tags
        )

    def test_external_tlp_marking_writes_one_taxonomy_entry(self):
        """A TLP colour is written into a taxonomy tag of the library's own: it
        names one entry of the `tlp` taxonomy, whatever the colour carries."""
        stix_package = STIXPackage()
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
        second_incident = Incident()
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
