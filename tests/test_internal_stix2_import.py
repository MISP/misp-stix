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

    def _check_attack_pattern_object(self, misp_object, attack_pattern):
        self.assertEqual(misp_object.uuid, attack_pattern.id.split('--')[1])
        self._assert_multiple_equal(
            misp_object.timestamp,
            self._timestamp_from_datetime(attack_pattern.created),
            self._timestamp_from_datetime(attack_pattern.modified)
        )
        self._check_object_labels(misp_object, attack_pattern.labels, False)
        summary, name, prerequisites, weakness1, weakness2, solution, capec_id = misp_object.attributes
        self.assertEqual(summary.value, attack_pattern.description)
        self.assertEqual(name.value, attack_pattern.name)
        self.assertEqual(prerequisites.value, attack_pattern.x_misp_prerequisites)
        self.assertEqual(weakness1.value, attack_pattern.x_misp_related_weakness[0])
        self.assertEqual(weakness2.value, attack_pattern.x_misp_related_weakness[1])
        self.assertEqual(solution.value, attack_pattern.x_misp_solutions)
        self.assertEqual(
            f"CAPEC-{capec_id.value}",
            attack_pattern.external_references[0].external_id
        )

    def _check_course_of_action_object(self, misp_object, course_of_action):
        self.assertEqual(misp_object.uuid, course_of_action.id.split('--')[1])
        self._assert_multiple_equal(
            misp_object.timestamp,
            self._timestamp_from_datetime(course_of_action.created),
            self._timestamp_from_datetime(course_of_action.modified)
        )
        self._check_object_labels(misp_object, course_of_action.labels, False)
        name, description, *attributes = misp_object.attributes
        self.assertEqual(name.value, course_of_action.name)
        self.assertEqual(description.value, course_of_action.description)
        for attribute in attributes:
            self.assertEqual(
                attribute.value,
                getattr(course_of_action, f"x_misp_{attribute.object_relation}")
            )


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

    def test_stix20_course_of_action_object(self):
        bundle = TestSTIX20Bundles.get_bundle_with_course_of_action_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, course_of_action = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        self._check_course_of_action_object(misp_object, course_of_action)
        self._populate_documentation(misp_object=misp_object, course_of_action=course_of_action)


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

    def test_stix21_course_of_action_object(self):
        bundle = TestSTIX21Bundles.get_bundle_with_course_of_action_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, course_of_action = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        self._check_course_of_action_object(misp_object, course_of_action)
        self._populate_documentation(misp_object=misp_object, course_of_action=course_of_action)
