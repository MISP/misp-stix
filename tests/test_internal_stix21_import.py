#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
from .test_stix21_bundles import TestSTIX21Bundles
from .update_documentation import AttributesDocumentationUpdater, ObjectsDocumentationUpdater
from ._test_stix import TestSTIX21
from ._test_stix_import import TestInternalSTIX2Import


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

    def test_stix21_bundle_with_AS_indicator_attribute(self):
        bundle = TestSTIX21Bundles.get_bundle_with_AS_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'AS')
        self.assertEqual(attribute.value, f'AS{self._get_pattern_value(pattern[1:-1])}')
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_AS_observable_attribute(self):
        bundle = TestSTIX21Bundles.get_bundle_with_AS_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, autonomous_system = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        object_ref = self._check_observed_data_attribute(attribute, observed_data)[0]
        self._assert_multiple_equal(
            attribute.uuid,
            object_ref.split('--')[1],
            autonomous_system.id.split('--')[1]
        )
        self.assertEqual(attribute.type, 'AS')
        self.assertEqual(attribute.value, f'AS{autonomous_system.number}')
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = [observed_data, autonomous_system]
        )

    def test_stix21_bundle_with_attachment_indicator_attribute(self):
        bundle = TestSTIX21Bundles.get_bundle_with_attachment_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'attachment')
        name_pattern, data_pattern = pattern[1:-1].split(' AND ')
        self.assertEqual(attribute.value, self._get_pattern_value(name_pattern))
        self.assertEqual(
            self._get_data_value(attribute.data),
            self._get_pattern_value(data_pattern)
        )
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_attachment_observable_attribute(self):
        bundle = TestSTIX21Bundles.get_bundle_with_attachment_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, file_observable, artifact_observable = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        file_ref, artifact_ref = self._check_observed_data_attribute(attribute, observed_data)
        self._assert_multiple_equal(
            attribute.uuid,
            file_observable.id.split('--')[1],
            file_ref.split('--')[1],
            artifact_observable.id.split('--')[1],
            artifact_ref.split('--')[1]
        )
        self.assertEqual(attribute.type, 'attachment')
        self.assertEqual(attribute.value, file_observable.name)
        self.assertEqual(self._get_data_value(attribute.data), artifact_observable.payload_bin)
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = [observed_data, file_observable, artifact_observable]
        )

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

    def test_stix21_bundle_with_domain_ip_indicator_attribute(self):
        bundle = TestSTIX21Bundles.get_bundle_with_domain_ip_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'domain|ip')
        domain, address = pattern[1:-1].split(' AND ')
        self.assertEqual(
            attribute.value,
            f'{self._get_pattern_value(domain)}|{self._get_pattern_value(address)}'
        )
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_domain_ip_observable_attribute(self):
        bundle = TestSTIX21Bundles.get_bundle_with_domain_ip_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, domain, address = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        domain_ref, address_ref = self._check_observed_data_attribute(attribute, observed_data)
        self._assert_multiple_equal(
            attribute.uuid,
            domain.id.split('--')[1],
            domain_ref.split('--')[1],
            address.id.split('--')[1],
            address_ref.split('--')[1]
        )
        self.assertEqual(attribute.type, 'domain|ip')
        self.assertEqual(
            attribute.value,
            f'{domain.value}|{address.value}'
        )
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = [observed_data, domain, address]
        )

    def test_stix21_bundle_with_domain_indicator_attribute(self):
        bundle = TestSTIX21Bundles.get_bundle_with_domain_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'domain')
        self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_domain_observable_attribute(self):
        bundle = TestSTIX21Bundles.get_bundle_with_domain_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, domain = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        object_ref = self._check_observed_data_attribute(attribute, observed_data)[0]
        self._assert_multiple_equal(
            attribute.uuid,
            object_ref.split('--')[1],
            domain.id.split('--')[1]
        )
        self.assertEqual(attribute.type, 'domain')
        self.assertEqual(attribute.value, domain.value)
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = [observed_data, domain]
        )

    def test_stix21_bundle_with_email_attachment_indicator_attribute(self):
        bundle = TestSTIX21Bundles.get_bundle_with_email_attachment_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'email-attachment')
        self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_email_attachment_observable_attribute(self):
        bundle = TestSTIX21Bundles.get_bundle_with_email_attachment_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, email_message, file_observable = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        message_ref, file_ref = self._check_observed_data_attribute(attribute, observed_data)
        self.assertEqual(attribute.type, 'email-attachment')
        self._assert_multiple_equal(
            attribute.uuid,
            email_message.id.split('--')[1],
            message_ref.split('--')[1],
            file_observable.id.split('--')[1],
            file_ref.split('--')[1]
        )
        self._assert_multiple_equal(
            attribute.value,
            email_message.body_multipart[0]['content_disposition'].split('=')[1].strip("'"),
            file_observable.name
        )
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = [observed_data, email_message, file_observable]
        )

    def test_stix21_bundle_with_email_body_indicator_attribute(self):
        bundle = TestSTIX21Bundles.get_bundle_with_email_body_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'email-body')
        self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_email_body_observable_attribute(self):
        bundle = TestSTIX21Bundles.get_bundle_with_email_body_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, email_message = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        message_ref = self._check_observed_data_attribute(attribute, observed_data)[0]
        self.assertEqual(attribute.type, 'email-body')
        self._assert_multiple_equal(
            attribute.uuid,
            email_message.id.split('--')[1],
            message_ref.split('--')[1]
        )
        self.assertEqual(attribute.value, email_message.body)
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = [observed_data, email_message]
        )

    def test_stix21_bundle_with_email_destination_indicator_attribute(self):
        bundle = TestSTIX21Bundles.get_bundle_with_email_destination_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'email-dst')
        self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_email_destination_observable_attribute(self):
        bundle = TestSTIX21Bundles.get_bundle_with_email_destination_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, email_message, email_address = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        message_ref, address_ref = self._check_observed_data_attribute(attribute, observed_data)
        self.assertEqual(attribute.type, 'email-dst')
        self._assert_multiple_equal(
            attribute.uuid,
            email_message.id.split('--')[1],
            message_ref.split('--')[1],
            email_address.id.split('--')[1],
            address_ref.split('--')[1]
        )
        self.assertEqual(attribute.value, email_address.value)
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = [observed_data, email_message, email_address]
        )

    def test_stix21_bundle_with_email_header_indicator_attribute(self):
        bundle = TestSTIX21Bundles.get_bundle_with_email_header_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'email-header')
        self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_email_header_observable_attribute(self):
        bundle = TestSTIX21Bundles.get_bundle_with_email_header_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, email_message = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        message_ref = self._check_observed_data_attribute(attribute, observed_data)[0]
        self.assertEqual(attribute.type, 'email-header')
        self._assert_multiple_equal(
            attribute.uuid,
            email_message.id.split('--')[1],
            message_ref.split('--')[1]
        )
        self.assertEqual(attribute.value, email_message.received_lines[0])
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = [observed_data, email_message]
        )

    def test_stix21_bundle_with_email_indicator_attribute(self):
        bundle = TestSTIX21Bundles.get_bundle_with_email_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'email')
        self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_email_message_id_indicator_attribute(self):
        bundle = TestSTIX21Bundles.get_bundle_with_email_message_id_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'email-message-id')
        self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_email_message_id_observable_attribute(self):
        bundle = TestSTIX21Bundles.get_bundle_with_email_message_id_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, email_message = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        message_ref = self._check_observed_data_attribute(attribute, observed_data)[0]
        self.assertEqual(attribute.type, 'email-message-id')
        self._assert_multiple_equal(
            attribute.uuid,
            email_message.id.split('--')[1],
            message_ref.split('--')[1]
        )
        self.assertEqual(attribute.value, email_message.message_id)
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = [observed_data, email_message]
        )

    def test_stix21_bundle_with_email_observable_attribute(self):
        bundle = TestSTIX21Bundles.get_bundle_with_email_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, email_address = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        address_ref = self._check_observed_data_attribute(attribute, observed_data)[0]
        self.assertEqual(attribute.type, 'email')
        self._assert_multiple_equal(
            attribute.uuid,
            email_address.id.split('--')[1],
            address_ref.split('--')[1]
        )
        self.assertEqual(attribute.value, email_address.value)
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = [observed_data, email_address]
        )

    def test_stix21_bundle_with_email_reply_to_indicator_attribute(self):
        bundle = TestSTIX21Bundles.get_bundle_with_email_reply_to_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'email-reply-to')
        self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_email_reply_to_observable_attribute(self):
        bundle = TestSTIX21Bundles.get_bundle_with_email_reply_to_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, email_message = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        message_ref = self._check_observed_data_attribute(attribute, observed_data)[0]
        self.assertEqual(attribute.type, 'email-reply-to')
        self._assert_multiple_equal(
            attribute.uuid,
            email_message.id.split('--')[1],
            message_ref.split('--')[1]
        )
        self.assertEqual(attribute.value, email_message.additional_header_fields['Reply-To'])
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = [observed_data, email_message]
        )

    def test_stix21_bundle_with_email_source_indicator_attribute(self):
        bundle = TestSTIX21Bundles.get_bundle_with_email_source_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'email-src')
        self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_email_source_observable_attribute(self):
        bundle = TestSTIX21Bundles.get_bundle_with_email_source_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, email_message, email_address = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        message_ref, address_ref = self._check_observed_data_attribute(attribute, observed_data)
        self.assertEqual(attribute.type, 'email-src')
        self._assert_multiple_equal(
            attribute.uuid,
            email_message.id.split('--')[1],
            message_ref.split('--')[1],
            email_address.id.split('--')[1],
            address_ref.split('--')[1]
        )
        self.assertEqual(attribute.value, email_address.value)
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = [observed_data, email_message, email_address]
        )

    def test_stix21_bundle_with_email_subject_indicator_attribute(self):
        bundle = TestSTIX21Bundles.get_bundle_with_email_subject_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'email-subject')
        self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_email_subject_observable_attribute(self):
        bundle = TestSTIX21Bundles.get_bundle_with_email_subject_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, email_message = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        message_ref = self._check_observed_data_attribute(attribute, observed_data)[0]
        self.assertEqual(attribute.type, 'email-subject')
        self._assert_multiple_equal(
            attribute.uuid,
            email_message.id.split('--')[1],
            message_ref.split('--')[1]
        )
        self.assertEqual(attribute.value, email_message.subject)
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = [observed_data, email_message]
        )

    def test_stix21_bundle_with_email_x_mailer_indicator_attribute(self):
        bundle = TestSTIX21Bundles.get_bundle_with_email_x_mailer_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'email-x-mailer')
        self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_email_x_mailer_observable_attribute(self):
        bundle = TestSTIX21Bundles.get_bundle_with_email_x_mailer_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, email_message = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        message_ref = self._check_observed_data_attribute(attribute, observed_data)[0]
        self.assertEqual(attribute.type, 'email-x-mailer')
        self._assert_multiple_equal(
            attribute.uuid,
            email_message.id.split('--')[1],
            message_ref.split('--')[1]
        )
        self.assertEqual(attribute.value, email_message.additional_header_fields['X-Mailer'])
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = [observed_data, email_message]
        )

    def test_stix21_bundle_with_hash_composite_indicator_attributes(self):
        bundle = TestSTIX21Bundles.get_bundle_with_hash_composite_indicator_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, *indicators = bundle.objects
        attributes = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(attributes), 14)
        for attribute, indicator in zip(attributes, indicators):
            pattern = self._check_indicator_attribute(attribute, indicator)
            filename, hash_value = attribute.value.split('|')
            filename_pattern, hash_pattern = pattern[1:-1].split(' AND ')
            self.assertEqual(filename, self._get_pattern_value(filename_pattern))
            self.assertEqual(hash_value, self._get_pattern_value(hash_pattern))
            self._populate_documentation(
                attribute = json.loads(attribute.to_json()),
                indicator = indicator
            )

    def test_stix21_bundle_with_hash_composite_observable_attributes(self):
        bundle = TestSTIX21Bundles.get_bundle_with_hash_composite_observable_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, *observables = bundle.objects
        attributes = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(attributes), 14)
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

    def test_stix21_bundle_with_hash_indicator_attributes(self):
        bundle = TestSTIX21Bundles.get_bundle_with_hash_indicator_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, *indicators = bundle.objects
        attributes = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(attributes), 15)
        for attribute, indicator in zip(attributes, indicators):
            pattern = self._check_indicator_attribute(attribute, indicator)
            self.assertEqual(attribute['value'], self._get_pattern_value(pattern[1:-1]))
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
        self.assertEqual(len(attributes), 15)
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

    def test_stix21_bundle_with_ip_indicator_attributes(self):
        bundle = TestSTIX21Bundles.get_bundle_with_ip_indicator_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, *indicators = bundle.objects
        attributes = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(attributes), 2)
        for attribute, indicator in zip(attributes, indicators):
            pattern = self._check_indicator_attribute(attribute, indicator)[1:-1].split(' AND ')[1]
            identifier, value = pattern.split(' = ')
            self.assertEqual(attribute.type, f"ip-{identifier.split(':')[1].split('_')[0]}")
            self.assertEqual(attribute.value, value.strip("'"))
            self._populate_documentation(
                attribute = json.loads(attribute.to_json()),
                indicator = indicator
            )

    def test_stix21_bundle_with_ip_observable_attributes(self):
        bundle = TestSTIX21Bundles.get_bundle_with_ip_observable_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, *observables = bundle.objects
        attributes = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(attributes), 2)
        for attribute, observed_data, network, address in zip(attributes, *[iter(observables)]*3):
            network_ref, address_ref = self._check_observed_data_attribute(attribute, observed_data)
            self._assert_multiple_equal(
                attribute.uuid,
                network.id.split('--')[1],
                network_ref.split('--')[1],
                address.id.split('--')[1],
                address_ref.split('--')[1]
            )
            feature = attribute.type.split('-')[1]
            self.assertTrue(hasattr(network, f"{feature}_ref"))
            self.assertEqual(attribute.value, address.value)
            self._populate_documentation(
                attribute = json.loads(attribute.to_json()),
                observed_data = [observed_data, network, address]
            )

    def test_stix21_bundle_with_ip_port_indicator_attributes(self):
        bundle = TestSTIX21Bundles.get_bundle_with_ip_port_indicator_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, *indicators = bundle.objects
        attributes = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(attributes), 2)
        for attribute, indicator in zip(attributes, indicators):
            pattern = self._check_indicator_attribute(attribute, indicator)
            ip_pattern, port_pattern = pattern[1:-1].split(' AND ')[1:]
            ip_identifier, ip_value = ip_pattern.split(' = ')
            port_identifier, port_value = port_pattern.split(' = ')
            self._assert_multiple_equal(
                attribute.type,
                f"ip-{ip_identifier.split(':')[1].split('_')[0]}|port",
                f"ip-{port_identifier.split(':')[1].split('_')[0]}|port"
            )
            self.assertEqual(
                attribute.value,
                "%s|%s" % (ip_value.strip("'"), port_value.strip("'"))
            )
            self._populate_documentation(
                attribute = json.loads(attribute.to_json()),
                indicator = indicator
            )

    def test_stix21_bundle_with_ip_port_observable_attributes(self):
        bundle = TestSTIX21Bundles.get_bundle_with_ip_port_observable_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, *observables = bundle.objects
        attributes = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(attributes), 2)
        for attribute, observed_data, network, address in zip(attributes, *[iter(observables)]*3):
            network_ref, address_ref = self._check_observed_data_attribute(attribute, observed_data)
            self._assert_multiple_equal(
                attribute.uuid,
                network.id.split('--')[1],
                network_ref.split('--')[1],
                address.id.split('--')[1],
                address_ref.split('--')[1]
            )
            feature = attribute.type.split('|')[0].split('-')[1]
            ip_value, port_value = attribute.value.split('|')
            self.assertEqual(ip_value, address.value)
            self.assertEqual(int(port_value), getattr(network, f'{feature}_port'))
            self._populate_documentation(
                attribute = json.loads(attribute.to_json()),
                observed_data = [observed_data, network, address]
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

    def test_stix21_bundle_with_url_indicator_attributes(self):
        bundle = TestSTIX21Bundles.get_bundle_with_url_indicator_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, *indicators = bundle.objects
        attributes = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(attributes), 3)
        for attribute, indicator in zip(attributes, indicators):
            pattern = self._check_indicator_attribute(attribute, indicator)[1:-1]
            self.assertEqual(attribute.value, self._get_pattern_value(pattern))
            self._populate_documentation(
                attribute = json.loads(attribute.to_json()),
                indicator = indicator
            )

    def test_stix21_bundle_with_url_observable_attributes(self):
        bundle = TestSTIX21Bundles.get_bundle_with_url_observable_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, *observables = bundle.objects
        attributes = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(attributes), 3)
        for attribute, observed_data, observable in zip(attributes, observables[::2], observables[1::2]):
            object_ref = self._check_observed_data_attribute(attribute, observed_data)[0]
            self._assert_multiple_equal(
                attribute.uuid,
                object_ref.split('--')[1],
                observable.id.split('--')[1]
            )
            self.assertEqual(attribute.value, observable.value)
            self._populate_documentation(
                attribute = json.loads(attribute.to_json()),
                observed_data = [observed_data, observable]
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

    def test_stix21_bundle_with_x509_fingerprint_indicator_attributes(self):
        bundle = TestSTIX21Bundles.get_bundle_with_x509_fingerprint_indicator_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, *indicators = bundle.objects
        attributes = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(attributes), 3)
        for attribute, indicator in zip(attributes, indicators):
            pattern = self._check_indicator_attribute(attribute, indicator)
            identifier, value = pattern[1:-1].split(' = ')
            self.assertEqual(
                attribute.type,
                f"x509-fingerprint-{self.hash_types_mapping(identifier.split('.')[-1])}"
            )
            self.assertEqual(attribute.value, value.strip("'"))
            self._populate_documentation(
                attribute = json.loads(attribute.to_json()),
                indicator = indicator
            )

    def test_stix21_bundle_with_x509_fingerprint_observable_attributes(self):
        bundle = TestSTIX21Bundles.get_bundle_with_x509_fingerprint_observable_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, *observables = bundle.objects
        attributes = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(attributes), 3)
        for attribute, observed_data, observable in zip(attributes, observables[::2], observables[1::2]):
            object_ref = self._check_observed_data_attribute(attribute, observed_data)[0]
            self._assert_multiple_equal(
                attribute.uuid,
                object_ref.split('--')[1],
                observable.id.split('--')[1]
            )
            hash_type = self.hash_types_mapping(attribute.type.split('-')[-1])
            self.assertEqual(attribute.value, observable.hashes[hash_type])
            self._populate_documentation(
                attribute = json.loads(attribute.to_json()),
                observed_data = [observed_data, observable]
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
