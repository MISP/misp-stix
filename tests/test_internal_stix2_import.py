#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
from misp_stix_converter import InternalSTIX2toMISPParser
from .test_stix20_bundles import TestSTIX20Bundles
from .test_stix21_bundles import TestSTIX21Bundles
from .update_documentation import AttributesDocumentationUpdater, ObjectsDocumentationUpdater
from ._test_stix import TestSTIX20, TestSTIX21
from ._test_stix_import import TestSTIX2Import


class TestInternalSTIX2Import(TestSTIX2Import):
    def setUp(self):
        self.parser = InternalSTIX2toMISPParser(False)

    ################################################################################
    #                      MISP ATTRIBUTES CHECKING FUNCTIONS                      #
    ################################################################################

    def _check_campaign_name_attribute(self, attribute, campaign):
        self.assertEqual(attribute.uuid, campaign.id.split('--')[1])
        self.assertEqual(attribute.type, 'campaign-name')
        self._assert_multiple_equal(
            attribute.timestamp,
            campaign.created,
            campaign.modified
        )
        self._check_attribute_labels(attribute, campaign.labels)
        self.assertEqual(attribute.value, campaign.name)

    def _check_indicator_attribute(self, attribute, indicator):
        self.assertEqual(attribute.uuid, indicator.id.split('--')[1])
        self._assert_multiple_equal(
            attribute.timestamp,
            indicator.created,
            indicator.modified
        )
        self._check_attribute_labels(attribute, indicator.labels)
        return indicator.pattern

    def _check_vulnerability_attribute(self, attribute, vulnerability):
        self.assertEqual(attribute.uuid, vulnerability.id.split('--')[1])
        self.assertEqual(attribute.type, vulnerability.type)
        self._assert_multiple_equal(
            attribute.timestamp,
            vulnerability.created,
            vulnerability.modified
        )
        self._check_attribute_labels(attribute, vulnerability.labels)
        self._assert_multiple_equal(
            attribute.value,
            vulnerability.name,
            vulnerability.external_references[0].external_id
        )

    ################################################################################
    #                       MISP OBJECTS CHECKING FUNCTIONS.                       #
    ################################################################################

    def _check_attack_pattern_object(self, misp_object, attack_pattern):
        self.assertEqual(misp_object.uuid, attack_pattern.id.split('--')[1])
        self.assertEqual(misp_object.name, attack_pattern.type)
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
        self.assertEqual(misp_object.name, course_of_action.type)
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

    def _check_employee_object(self, misp_object, identity):
        self.assertEqual(misp_object.uuid, identity.id.split('--')[1])
        self.assertEqual(misp_object.name, 'employee')
        self._assert_multiple_equal(
            misp_object.timestamp,
            self._timestamp_from_datetime(identity.created),
            self._timestamp_from_datetime(identity.modified)
        )
        self._check_object_labels(misp_object, identity.labels, False)
        name, description, employee_type, email = misp_object.attributes
        self.assertEqual(name.value, identity.name)
        self.assertEqual(description.value, identity.description)
        self.assertEqual(
            identity.contact_information,
            f"{email.object_relation}: {email.value}"
        )
        return employee_type

    def _check_legal_entity_object(self, misp_object, identity):
        self.assertEqual(misp_object.uuid, identity.id.split('--')[1])
        self.assertEqual(misp_object.name, 'legal-entity')
        self._assert_multiple_equal(
            misp_object.timestamp,
            self._timestamp_from_datetime(identity.created),
            self._timestamp_from_datetime(identity.modified)
        )
        self._check_object_labels(misp_object, identity.labels, False)
        name, description, business, registration_number, phone, website, logo = misp_object.attributes
        self.assertEqual(name.value, identity.name)
        self.assertEqual(description.value, identity.description)
        self.assertEqual([business.value], identity.sectors)
        phone_info, website_info = identity.contact_information.split(' / ')
        self.assertEqual(phone_info, f"{phone.object_relation}: {phone.value}")
        self.assertEqual(website_info, f"{website.object_relation}: {website.value}")
        self.assertEqual(registration_number.value, identity.x_misp_registration_number)
        self.assertEqual(logo.value, identity.x_misp_logo['value'])
        self.assertEqual(self._get_data_value(logo.data), identity.x_misp_logo['data'])

    def _check_news_agency_object(self, misp_object, identity):
        self.assertEqual(misp_object.uuid, identity.id.split('--')[1])
        self.assertEqual(misp_object.name, 'news-agency')
        self._assert_multiple_equal(
            misp_object.timestamp,
            self._timestamp_from_datetime(identity.created),
            self._timestamp_from_datetime(identity.modified)
        )
        self._check_object_labels(misp_object, identity.labels, False)
        name, address, email, phone, attachment = misp_object.attributes
        self.assertEqual(name.value, identity.name)
        address_info, email_info, phone_info = identity.contact_information.split(' / ')
        self.assertEqual(address_info, f'{address.object_relation}: {address.value}')
        self.assertEqual(email_info, f'{email.object_relation}: {email.value}')
        self.assertEqual(phone_info, f'{phone.object_relation}: {phone.value}')
        self.assertEqual(attachment.value, identity.x_misp_attachment['value'])
        self.assertEqual(
            self._get_data_value(attachment.data),
            identity.x_misp_attachment['data']
        )

    def _check_organization_object(self, misp_object, identity):
        self.assertEqual(misp_object.uuid, identity.id.split('--')[1])
        self.assertEqual(misp_object.name, 'organization')
        self._assert_multiple_equal(
            misp_object.timestamp,
            self._timestamp_from_datetime(identity.created),
            self._timestamp_from_datetime(identity.modified)
        )
        self._check_object_labels(misp_object, identity.labels, False)
        name, description, role, alias, address, email, phone = misp_object.attributes
        self.assertEqual(name.value, identity.name)
        self.assertEqual(description.value, identity.description)
        self.assertEqual(alias.value, identity.x_misp_alias)
        address_info, email_info, phone_info = identity.contact_information.split(' / ')
        self.assertEqual(address_info, f'{address.object_relation}: {address.value}')
        self.assertEqual(email_info, f'{email.object_relation}: {email.value}')
        self.assertEqual(phone_info, f'{phone.object_relation}: {phone.value}')
        return role

    def _check_script_object(self, misp_object, stix_object):
        self.assertEqual(misp_object.uuid, stix_object.id.split('--')[1])
        self.assertEqual(misp_object.name, 'script')
        self._assert_multiple_equal(
            misp_object.timestamp,
            self._timestamp_from_datetime(stix_object.created),
            self._timestamp_from_datetime(stix_object.modified)
        )
        self._check_object_labels(misp_object, stix_object.labels, False)
        filename, comment, language, script, state, attachment = misp_object.attributes
        self.assertEqual(filename.value, stix_object.name)
        self.assertEqual(comment.value, stix_object.description)
        self.assertEqual(script.value, stix_object.x_misp_script)
        self.assertEqual(attachment.value, stix_object.x_misp_script_as_attachment['value'])
        self.assertEqual(
            self._get_data_value(attachment.data),
            stix_object.x_misp_script_as_attachment['data']
        )
        return language, state

    def _check_vulnerability_object(self, misp_object, vulnerability):
        self.assertEqual(misp_object.uuid, vulnerability.id.split('--')[1])
        self.assertEqual(misp_object.name, vulnerability.type)
        self._assert_multiple_equal(
            misp_object.timestamp,
            self._timestamp_from_datetime(vulnerability.created),
            self._timestamp_from_datetime(vulnerability.modified)
        )
        self._check_object_labels(misp_object, vulnerability.labels, False)
        external_id, external_ref1, external_ref2 = vulnerability.external_references
        cve_id, reference1, reference2, description, created, cvss_score, published = misp_object.attributes
        self._assert_multiple_equal(
            cve_id.value,
            vulnerability.name,
            external_id.external_id
        )
        self.assertEqual(reference1.value, external_ref1.url)
        self.assertEqual(reference2.value, external_ref2.url)
        self.assertEqual(description.value, vulnerability.description)
        self.assertEqual(self._datetime_to_str(created.value), vulnerability.x_misp_created)
        self.assertEqual(cvss_score.value, vulnerability.x_misp_cvss_score)
        self.assertEqual(self._datetime_to_str(published.value), vulnerability.x_misp_published)


class TestInternalSTIX20Import(TestInternalSTIX2Import, TestSTIX20):
    @classmethod
    def tearDownClass(self):
        attributes_documentation = AttributesDocumentationUpdater(
            'stix20_to_misp_attributes',
            self._attributes
        )
        attributes_documentation.check_mapping('stix20')
        objects_documentation = ObjectsDocumentationUpdater(
            'stix20_to_misp_objects',
            self._objects
        )
        objects_documentation.check_mapping('stix20')

    ################################################################################
    #                      MISP ATTRIBUTES CHECKING FUNCTIONS                      #
    ################################################################################

    def _check_observed_data_attribute(self, attribute, observed_data):
        self.assertEqual(attribute.uuid, observed_data.id.split('--')[1])
        self._assert_multiple_equal(
            attribute.timestamp,
            observed_data.created,
            observed_data.modified
        )
        self._check_attribute_labels(attribute, observed_data.labels)
        return observed_data.objects

    ################################################################################
    #                         MISP ATTRIBUTES IMPORT TESTS                         #
    ################################################################################

    def test_stix20_bundle_with_campaign_name_attribute(self):
        bundle = TestSTIX20Bundles.get_bundle_with_campaign_name_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, campaign = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        self._check_campaign_name_attribute(attribute, campaign)
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            campaign = campaign
        )

    def test_stix20_bundle_with_hash_composite_observable_attributes(self):
        bundle = TestSTIX20Bundles.get_bundle_with_hash_composite_observable_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, *observables = bundle.objects
        attributes = self._check_misp_event_features(event, report)
        for attribute, observed_data in zip(attributes, observables):
            observable = self._check_observed_data_attribute(attribute, observed_data)['0']
            filename, hash_value = attribute.value.split('|')
            hash_type = self.hash_types_mapping(attribute.type.split('|')[1])
            self.assertEqual(filename, observable.name)
            self.assertEqual(hash_value, observable.hashes[hash_type])
            self._populate_documentation(
                attribute = json.loads(attribute.to_json()),
                observed_data = observed_data
            )

    def test_stix20_bundle_with_hash_composite_pattern_attributes(self):
        bundle = TestSTIX20Bundles.get_bundle_with_hash_composite_pattern_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, *indicators = bundle.objects
        attributes = self._check_misp_event_features(event, report)
        for attribute, indicator in zip(attributes, indicators):
            pattern = self._check_indicator_attribute(attribute, indicator)
            filename, hash_value = attribute.value.split('|')
            filename_pattern, hash_pattern = pattern[1:-1].split(' AND ')
            self.assertEqual(filename, filename_pattern.split(' = ')[1].strip("'"))
            self.assertEqual(hash_value, hash_pattern.split(' = ')[1].strip("'"))
            self._populate_documentation(
                attribute = json.loads(attribute.to_json()),
                indicator = indicator
            )

    def test_stix20_bundle_with_hash_observable_attributes(self):
        bundle = TestSTIX20Bundles.get_bundle_with_hash_observable_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, *observables = bundle.objects
        attributes = self._check_misp_event_features(event, report)
        for attribute, observed_data in zip(attributes, observables):
            observable = self._check_observed_data_attribute(attribute, observed_data)['0']
            hash_type = self.hash_types_mapping(attribute.type)
            self.assertEqual(attribute.value, observable.hashes[hash_type])
            self._populate_documentation(
                attribute = json.loads(attribute.to_json()),
                observed_data = observed_data
            )

    def test_stix20_bundle_with_hash_pattern_attributes(self):
        bundle = TestSTIX20Bundles.get_bundle_with_hash_pattern_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, *indicators = bundle.objects
        attributes = self._check_misp_event_features(event, report)
        for attribute, indicator in zip(attributes, indicators):
            pattern = self._check_indicator_attribute(attribute, indicator)
            self.assertEqual(attribute['value'], pattern[1:-1].split(' = ')[1].strip("'"))
            self._populate_documentation(
                attribute = json.loads(attribute.to_json()),
                indicator = indicator
            )

    def test_stix20_bundle_with_vulnerability_attribute(self):
        bundle = TestSTIX20Bundles.get_bundle_with_vulnerability_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, vulnerability = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        self._check_vulnerability_attribute(attribute, vulnerability)
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            vulnerability = vulnerability
        )

    ################################################################################
    #                          MISP OBJECTS IMPORT TESTS.                          #
    ################################################################################

    def test_stix20_bundle_with_attack_pattern_object(self):
        bundle = TestSTIX20Bundles.get_bundle_with_attack_pattern_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, attack_pattern = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        self._check_attack_pattern_object(misp_object, attack_pattern)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            attack_pattern = attack_pattern
        )

    def test_stix20_bundle_with_course_of_action_object(self):
        bundle = TestSTIX20Bundles.get_bundle_with_course_of_action_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, course_of_action = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        self._check_course_of_action_object(misp_object, course_of_action)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            course_of_action = course_of_action
        )

    def test_stix20_bundle_with_employee_object(self):
        bundle = TestSTIX20Bundles.get_bundle_with_employee_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, identity = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        employee_type = self._check_employee_object(misp_object, identity)
        self.assertEqual(employee_type.value, identity.x_misp_employee_type)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            identity = identity
        )

    def test_stix20_bundle_with_legal_entity_object(self):
        bundle = TestSTIX20Bundles.get_bundle_with_legal_entity_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, identity = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        self._check_legal_entity_object(misp_object, identity)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            identity = identity
        )

    def test_stix20_bundle_with_news_agency_object(self):
        bundle = TestSTIX20Bundles.get_bundle_with_news_agency_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, identity = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        self._check_news_agency_object(misp_object, identity)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            identity = identity
        )

    def test_stix20_bundle_with_organization_object(self):
        bundle = TestSTIX20Bundles.get_bundle_with_organization_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, identity = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        role = self._check_organization_object(misp_object, identity)
        self.assertEqual(role.value, identity.x_misp_role)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            identity = identity
        )

    def test_stix20_bundle_with_script_objects(self):
        bundle = TestSTIX20Bundles.get_bundle_with_script_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, malware, tool = bundle.objects
        script_from_malware, script_from_tool = self._check_misp_event_features(event, report)
        language, state = self._check_script_object(script_from_malware, malware)
        self.assertEqual([language.value], malware.implementation_languages)
        self.assertEqual(state.value, 'Malicious')
        self._populate_documentation(
            misp_object = json.loads(script_from_malware.to_json()),
            malware = malware,
            name = 'Script object where state is "Malicious"'
        )
        language, state = self._check_script_object(script_from_tool, tool)
        self.assertEqual(language.value, tool.x_misp_language)
        self.assertEqual(state.value, 'Harmless')
        self._populate_documentation(
            misp_object = json.loads(script_from_tool.to_json()),
            tool = tool,
            name = 'Script object where state is not "Malicious"'
        )

    def test_stix20_bundle_with_vulnerability_object(self):
        bundle = TestSTIX20Bundles.get_bundle_with_vulnerability_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, vulnerability = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        self._check_vulnerability_object(misp_object, vulnerability)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            vulnerability = vulnerability
        )


class TestInternalSTIX21Import(TestInternalSTIX2Import, TestSTIX21):
    @classmethod
    def tearDownClass(self):
        attributes_documentation = AttributesDocumentationUpdater(
            'stix21_to_misp_attributes',
            self._attributes
        )
        attributes_documentation.check_mapping('stix21')
        objects_documentation = ObjectsDocumentationUpdater(
            'stix21_to_misp_objects',
            self._objects
        )
        objects_documentation.check_mapping('stix21')

    ################################################################################
    #                      MISP ATTRIBUTES CHECKING FUNCTIONS                      #
    ################################################################################

    def _check_observed_data_attribute(self, attribute, observed_data):
        self.assertEqual(attribute.uuid, observed_data.id.split('--')[1])
        self._assert_multiple_equal(
            attribute.timestamp,
            observed_data.created,
            observed_data.modified
        )
        self._check_attribute_labels(attribute, observed_data.labels)
        return observed_data.object_refs

    def _check_patterning_language_attribute(self, attribute, indicator):
        self.assertEqual(attribute.uuid, indicator.id.split('--')[1])
        self.assertEqual(attribute.type, indicator.pattern_type)
        self._assert_multiple_equal(
            attribute.timestamp,
            indicator.created,
            indicator.modified
        )
        self.assertEqual(attribute.comment, indicator.description)
        self._check_attribute_labels(attribute, indicator.labels)
        self.assertEqual(attribute.value, indicator.pattern)

    ################################################################################
    #                       MISP OBJECTS CHECKING FUNCTIONS.                       #
    ################################################################################

    def _check_patterning_language_object(self, misp_object, indicator):
        self.assertEqual(misp_object.uuid, indicator.id.split('--')[1])
        self._assert_multiple_equal(
            misp_object.timestamp,
            self._timestamp_from_datetime(indicator.created),
            self._timestamp_from_datetime(indicator.modified)
        )
        self._check_object_labels(misp_object, indicator.labels, True)
        pattern, comment, version, attribute = misp_object.attributes
        self.assertEqual(pattern.value, indicator.pattern)
        self.assertEqual(pattern.type, indicator.pattern_type)
        self.assertEqual(comment.value, indicator.description)
        self.assertEqual(version.value, indicator.pattern_version)
        return attribute

    ################################################################################
    #                         MISP ATTRIBUTES IMPORT TESTS                         #
    ################################################################################

    def test_stix21_bundle_with_campaign_name_attribute(self):
        bundle = TestSTIX21Bundles.get_bundle_with_campaign_name_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, campaign = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        self._check_campaign_name_attribute(attribute, campaign)
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            campaign = campaign
        )

    def test_stix21_bundle_with_hash_composite_observable_attributes(self):
        bundle = TestSTIX21Bundles.get_bundle_with_hash_composite_observable_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, *observables = bundle.objects
        attributes = self._check_misp_event_features_from_grouping(event, grouping)
        for attribute, observed_data, observable in zip(attributes, observables[::2], observables[1::2]):
            object_ref = self._check_observed_data_attribute(attribute, observed_data)[0]
            self._assert_multiple_equal(
                attribute.uuid,
                object_ref.split('--')[1],
                observable.id.split('--')[1]
            )
            filename, hash_value = attribute.value.split('|')
            hash_type = self.hash_types_mapping(attribute.type.split('|')[1])
            self.assertEqual(filename, observable.name)
            self.assertEqual(hash_value, observable.hashes[hash_type])
            self._populate_documentation(
                attribute = json.loads(attribute.to_json()),
                observed_data = [observed_data, observable]
            )

    def test_stix21_bundle_with_hash_composite_pattern_attributes(self):
        bundle = TestSTIX21Bundles.get_bundle_with_hash_composite_pattern_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, *indicators = bundle.objects
        attributes = self._check_misp_event_features_from_grouping(event, grouping)
        for attribute, indicator in zip(attributes, indicators):
            pattern = self._check_indicator_attribute(attribute, indicator)
            filename, hash_value = attribute.value.split('|')
            filename_pattern, hash_pattern = pattern[1:-1].split(' AND ')
            self.assertEqual(filename, filename_pattern.split(' = ')[1].strip("'"))
            self.assertEqual(hash_value, hash_pattern.split(' = ')[1].strip("'"))
            self._populate_documentation(
                attribute = json.loads(attribute.to_json()),
                indicator = indicator
            )

    def test_stix21_bundle_with_hash_observable_attributes(self):
        bundle = TestSTIX21Bundles.get_bundle_with_hash_observable_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, *observables = bundle.objects
        attributes = self._check_misp_event_features_from_grouping(event, grouping)
        for attribute, observed_data, observable in zip(attributes, observables[::2], observables[1::2]):
            object_ref = self._check_observed_data_attribute(attribute, observed_data)[0]
            self._assert_multiple_equal(
                attribute.uuid,
                object_ref.split('--')[1],
                observable.id.split('--')[1]
            )
            hash_type = self.hash_types_mapping(attribute.type)
            self.assertEqual(attribute.value, observable.hashes[hash_type])
            self._populate_documentation(
                attribute = json.loads(attribute.to_json()),
                observed_data = [observed_data, observable]
            )

    def test_stix21_bundle_with_hash_pattern_attributes(self):
        bundle = TestSTIX21Bundles.get_bundle_with_hash_pattern_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, *indicators = bundle.objects
        attributes = self._check_misp_event_features_from_grouping(event, grouping)
        for attribute, indicator in zip(attributes, indicators):
            pattern = self._check_indicator_attribute(attribute, indicator)
            self.assertEqual(attribute['value'], pattern[1:-1].split(' = ')[1].strip("'"))
            self._populate_documentation(
                attribute = json.loads(attribute.to_json()),
                indicator = indicator
            )

    def test_stix21_bundle_with_patterning_language_attributes(self):
        bundle = TestSTIX21Bundles.get_bundle_with_patterning_language_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, sigma_indicator, snort_indicator, yara_indicator = bundle.objects
        sigma, snort, yara = self._check_misp_event_features_from_grouping(event, grouping)
        self._check_patterning_language_attribute(sigma, sigma_indicator)
        self._populate_documentation(
            attribute = json.loads(sigma.to_json()),
            indicator = sigma_indicator
        )
        self._check_patterning_language_attribute(snort, snort_indicator)
        self._populate_documentation(
            attribute = json.loads(snort.to_json()),
            indicator = snort_indicator
        )
        self._check_patterning_language_attribute(yara, yara_indicator)
        self._populate_documentation(
            attribute = json.loads(yara.to_json()),
            indicator = yara_indicator
        )

    def test_stix21_bundle_with_vulnerability_attribute(self):
        bundle = TestSTIX21Bundles.get_bundle_with_vulnerability_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, vulnerability = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        self._check_vulnerability_attribute(attribute, vulnerability)
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            vulnerability = vulnerability
        )

    ################################################################################
    #                          MISP OBJECTS IMPORT TESTS.                          #
    ################################################################################

    def test_stix21_bundle_with_attack_pattern_object(self):
        bundle = TestSTIX21Bundles.get_bundle_with_attack_pattern_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, attack_pattern = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        self._check_attack_pattern_object(misp_object, attack_pattern)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            attack_pattern = attack_pattern
        )

    def test_stix21_bundle_with_course_of_action_object(self):
        bundle = TestSTIX21Bundles.get_bundle_with_course_of_action_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, course_of_action = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        self._check_course_of_action_object(misp_object, course_of_action)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            course_of_action = course_of_action
        )

    def test_stix21_bundle_with_employee_object(self):
        bundle = TestSTIX21Bundles.get_bundle_with_employee_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, identity = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        employee_type = self._check_employee_object(misp_object, identity)
        self.assertEqual([employee_type.value], identity.roles)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            identity = identity
        )

    def test_stix21_bundle_with_geolocation_object(self):
        bundle = TestSTIX21Bundles.get_bundle_with_geolocation_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, location = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        city, countrycode, latitude, longitude, zipcode, region, address, altitude, country, accuracy = misp_object.attributes
        self.assertEqual(city.value, location.city)
        self.assertEqual(countrycode.value, location.country)
        self.assertEqual(latitude.value, location.latitude)
        self.assertEqual(longitude.value, location.longitude)
        self.assertEqual(zipcode.value, location.postal_code)
        self.assertEqual(region.value, location.region)
        self.assertEqual(address.value, location.street_address)
        self.assertEqual(altitude.value, location.x_misp_altitude)
        self.assertEqual(country.value, location.x_misp_country)
        self.assertEqual(accuracy.value, location.precision / 1000)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            location = location
        )

    def test_stix21_bundle_with_legal_entity_object(self):
        bundle = TestSTIX21Bundles.get_bundle_with_legal_entity_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, identity = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        self._check_legal_entity_object(misp_object, identity)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            identity = identity
        )

    def test_stix21_bundle_with_news_agency_object(self):
        bundle = TestSTIX21Bundles.get_bundle_with_news_agency_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, identity = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        self._check_news_agency_object(misp_object, identity)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            identity = identity
        )

    def test_stix21_bundle_with_patterning_language_objects(self):
        bundle = TestSTIX21Bundles.get_bundle_with_patterning_language_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, suricata_indicator, yara_indicator = bundle.objects
        suricata, yara = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(suricata.name, 'suricata')
        attribute = self._check_patterning_language_object(suricata, suricata_indicator)
        self.assertEqual(attribute.value, suricata_indicator.external_references[0].url)
        self._populate_documentation(
            misp_object = json.loads(suricata.to_json()),
            indicator = suricata_indicator
        )
        self.assertEqual(yara.name, yara_indicator.pattern_type)
        attribute = self._check_patterning_language_object(yara, yara_indicator)
        self.assertEqual(attribute.value, yara_indicator.x_misp_yara_rule_name)
        self._populate_documentation(
            misp_object = json.loads(yara.to_json()),
            indicator = yara_indicator
        )

    def test_stix21_bundle_with_organization_object(self):
        bundle = TestSTIX21Bundles.get_bundle_with_organization_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, identity = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        role = self._check_organization_object(misp_object, identity)
        self.assertEqual(identity.roles, [role.value])
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            identity = identity
        )

    def test_stix21_bundle_with_script_objects(self):
        bundle = TestSTIX21Bundles.get_bundle_with_script_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, malware, tool = bundle.objects
        script_from_malware, script_from_tool = self._check_misp_event_features_from_grouping(
            event,
            grouping
        )
        language, state = self._check_script_object(script_from_malware, malware)
        self.assertEqual([language.value], malware.implementation_languages)
        self.assertEqual(state.value, 'Malicious')
        self._populate_documentation(
            misp_object = json.loads(script_from_malware.to_json()),
            malware = malware,
            name = 'Script object where state is "Malicious"'
        )
        language, state = self._check_script_object(script_from_tool, tool)
        self.assertEqual(language.value, tool.x_misp_language)
        self.assertEqual(state.value, 'Harmless')
        self._populate_documentation(
            misp_object = json.loads(script_from_tool.to_json()),
            tool = tool,
            name = 'Script object where state is not "Malicious"'
        )

    def test_stix21_bundle_with_vulnerability_object(self):
        bundle = TestSTIX21Bundles.get_bundle_with_vulnerability_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, vulnerability = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        self._check_vulnerability_object(misp_object, vulnerability)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            vulnerability = vulnerability
        )
