#!/usr/bin/env python
# -*- coding: utf-8 -*-

from misp_stix_converter import InternalSTIX2toMISPParser
from .test_stix20_bundles import TestSTIX20Bundles
from .test_stix21_bundles import TestSTIX21Bundles
from .update_documentation import DocumentationUpdater
from ._test_stix import TestSTIX20, TestSTIX21
from ._test_stix_import import TestSTIX2Import


class TestInternalSTIX2Import(TestSTIX2Import):
    def setUp(self):
        self.parser = InternalSTIX2toMISPParser(False)


class TestInternalSTIX20Import(TestInternalSTIX2Import, TestSTIX20):
    @classmethod
    def tearDownClass(self):
        attributes_documentation = DocumentationUpdater('stix20_to_misp_attributes')
        attributes_documentation.check_stix20_mapping(self._attributes)
        objects_documentation = DocumentationUpdater('stix20_to_misp_objects')
        objects_documentation.check_stix20_mapping(self._objects)

    ################################################################################
    #                          MISP OBJECTS IMPORT TESTS.                          #
    ################################################################################

    def test_stix20_attack_pattern_object(self):
        bundle = TestSTIX20Bundles.get_bundle_with_attack_pattern_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, attack_pattern = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        self._check_attack_pattern_object(misp_object, attack_pattern)
        self._populate_documentation(misp_object=misp_object, attack_pattern=attack_pattern)


class TestInternalSTIX21Import(TestInternalSTIX2Import, TestSTIX21):
    @classmethod
    def tearDownClass(self):
        attributes_documentation = DocumentationUpdater('stix21_to_misp_attributes')
        attributes_documentation.check_stix21_mapping(self._attributes)
        objects_documentation = DocumentationUpdater('stix21_to_misp_objects')
        objects_documentation.check_stix21_mapping(self._objects)

    ################################################################################
    #                          MISP OBJECTS IMPORT TESTS.                          #
    ################################################################################

    def test_stix21_attack_pattern_object(self):
        bundle = TestSTIX21Bundles.get_bundle_with_attack_pattern_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, attack_pattern = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        self._check_attack_pattern_object(misp_object, attack_pattern)
        self._populate_documentation(misp_object=misp_object, attack_pattern=attack_pattern)