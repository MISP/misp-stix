#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
from uuid import uuid5
from .test_internal_stix21_bundles import TestInternalSTIX21Bundles
from ._test_stix import TestSTIX21
from ._test_stix_import import TestInternalSTIX2Import, TestSTIX21Import


class TestInternalSTIX21Import(TestInternalSTIX2Import, TestSTIX21, TestSTIX21Import):

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

    def _check_observed_data_object(self, misp_object, observed_data):
        self.assertEqual(misp_object.uuid, observed_data.id.split('--')[1])
        self._assert_multiple_equal(
            misp_object.timestamp,
            observed_data.created,
            observed_data.modified
        )
        self._check_object_labels(misp_object, observed_data.labels, False)
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
    #                         MISP ATTRIBUTES IMPORT TESTS                         #
    ################################################################################

    def test_stix21_bundle_with_AS_indicator_attribute(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_AS_indicator_attribute()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_AS_observable_attribute()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_attachment_indicator_attribute()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_attachment_observable_attribute()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_campaign_name_attribute()
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

    def test_stix21_bundle_with_custom_attributes(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_custom_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, *custom_attributes = bundle.objects
        attributes = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(attributes), len(custom_attributes))
        for attribute, custom_attribute in zip(attributes, custom_attributes):
            self._check_custom_attribute(attribute, custom_attribute)

    def test_stix21_bundle_with_domain_ip_indicator_attribute(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_domain_ip_indicator_attribute()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_domain_ip_observable_attribute()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_domain_indicator_attribute()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_domain_observable_attribute()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_email_attachment_indicator_attribute()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_email_attachment_observable_attribute()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_email_body_indicator_attribute()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_email_body_observable_attribute()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_email_destination_indicator_attribute()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_email_destination_observable_attribute()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_email_header_indicator_attribute()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_email_header_observable_attribute()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_email_indicator_attribute()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_email_message_id_indicator_attribute()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_email_message_id_observable_attribute()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_email_observable_attribute()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_email_reply_to_indicator_attribute()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_email_reply_to_observable_attribute()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_email_source_indicator_attribute()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_email_source_observable_attribute()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_email_subject_indicator_attribute()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_email_subject_observable_attribute()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_email_x_mailer_indicator_attribute()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_email_x_mailer_observable_attribute()
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

    def test_stix21_bundle_with_filename_indicator_attribute(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_filename_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'filename')
        self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_filename_observable_attribute(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_filename_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, file_object = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        file_ref = self._check_observed_data_attribute(attribute, observed_data)[0]
        self.assertEqual(attribute.type, 'filename')
        self._assert_multiple_equal(
            attribute.uuid,
            file_object.id.split('--')[1],
            file_ref.split('--')[1]
        )
        self.assertEqual(attribute.value, file_object.name)
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = [observed_data, file_object]
        )

    def test_stix21_bundl_with_github_username_indicator_attribute(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_github_username_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'github-username')
        self.assertEqual(
            attribute.value,
            self._get_pattern_value(pattern[1:-1].split(' AND ')[1])
        )
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_github_username_observable_attribute(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_github_username_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, user_account = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        account_ref = self._check_observed_data_attribute(attribute, observed_data)[0]
        self.assertEqual(attribute.type, 'github-username')
        self._assert_multiple_equal(
            attribute.uuid,
            user_account.id.split('--')[1],
            account_ref.split('--')[1]
        )
        self.assertEqual(attribute.value, user_account.account_login)
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = [observed_data, user_account]
        )

    def test_stix21_bundle_with_hash_composite_indicator_attributes(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_hash_composite_indicator_attributes()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_hash_composite_observable_attributes()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_hash_indicator_attributes()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_hash_observable_attributes()
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

    def test_stix21_bundle_with_hostname_indicator_attribute(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_hostname_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'hostname')
        self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_hostname_observable_attribute(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_hostname_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, domain = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        domain_ref = self._check_observed_data_attribute(attribute, observed_data)[0]
        self.assertEqual(attribute.type, 'hostname')
        self._assert_multiple_equal(
            attribute.uuid,
            domain.id.split('--')[1],
            domain_ref.split('--')[1]
        )
        self.assertEqual(attribute.value, domain.value)
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = [observed_data, domain]
        )

    def test_stix21_bundle_with_hostname_port_indicator_attribute(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_hostname_port_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'hostname|port')
        hostname_pattern, port_pattern = pattern[1:-1].split(' AND ')
        hostname_value = self._get_pattern_value(hostname_pattern)
        port_value = self._get_pattern_value(port_pattern)
        self.assertEqual(attribute.value, f'{hostname_value}|{port_value}')
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_hostname_port_observable_attribute(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_hostname_port_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, domain, network = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        domain_ref, network_ref = self._check_observed_data_attribute(attribute, observed_data)
        self.assertEqual(attribute.type, 'hostname|port')
        self._assert_multiple_equal(
            attribute.uuid,
            domain.id.split('--')[1],
            domain_ref.split('--')[1],
            network.id.split('--')[1],
            network_ref.split('--')[1]
        )
        self.assertEqual(attribute.value, f'{domain.value}|{network.dst_port}')
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = [observed_data, domain, network]
        )

    def test_stix21_bundle_with_http_indicator_attributes(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_http_indicator_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, *indicators = bundle.objects
        attributes = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(attributes), 2)
        types = ('http-method', 'user-agent')
        for attribute, indicator, attribute_type in zip(attributes, indicators, types):
            pattern = self._check_indicator_attribute(attribute, indicator)
            self.assertEqual(attribute.type, attribute_type)
            self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
            self._populate_documentation(
                attribute = json.loads(attribute.to_json()),
                indicator = indicator
            )

    def test_stix21_bundle_with_ip_indicator_attributes(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_ip_indicator_attributes()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_ip_observable_attributes()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_ip_port_indicator_attributes()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_ip_port_observable_attributes()
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

    def test_stix21_bundle_with_mac_address_indicator_attribute(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_mac_address_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'mac-address')
        self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_mac_address_observable_attribute(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_mac_address_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, mac_address = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        mac_address_ref = self._check_observed_data_attribute(attribute, observed_data)[0]
        self.assertEqual(attribute.type, 'mac-address')
        self._assert_multiple_equal(
            attribute.uuid,
            mac_address.id.split('--')[1],
            mac_address_ref.split('--')[1]
        )
        self.assertEqual(attribute.value, mac_address.value)
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = [observed_data, mac_address]
        )

    def test_stix21_bundle_with_malware_sample_indicator_attribute(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_malware_sample_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'malware-sample')
        filename_pattern, md5_pattern, data_pattern, *_ = pattern[1:-1].split(' AND ')
        filename_value = self._get_pattern_value(filename_pattern)
        md5_value = self._get_pattern_value(md5_pattern)
        self.assertEqual(attribute.value, f'{filename_value}|{md5_value}')
        self.assertEqual(
            self._get_data_value(attribute.data),
            self._get_pattern_value(data_pattern)
        )
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_malware_sample_observable_attribute(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_malware_sample_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, file_object, artifact = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        file_ref, artifact_ref = self._check_observed_data_attribute(attribute, observed_data)
        self.assertEqual(attribute.type, 'malware-sample')
        self._assert_multiple_equal(
            attribute.uuid,
            file_object.id.split('--')[1],
            file_ref.split('--')[1],
            artifact.id.split('--')[1],
            artifact_ref.split('--')[1]
        )
        self.assertEqual(attribute.value, f"{file_object.name}|{file_object.hashes['MD5']}")
        self.assertEqual(self._get_data_value(attribute.data), artifact.payload_bin)
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = [observed_data, file_object, artifact]
        )

    def test_stix21_bundle_with_mutex_indicator_attribute(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_mutex_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'mutex')
        self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_mutex_observable_attribute(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_mutex_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, mutex = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        mutex_ref = self._check_observed_data_attribute(attribute, observed_data)[0]
        self.assertEqual(attribute.type, 'mutex')
        self._assert_multiple_equal(
            attribute.uuid,
            mutex.id.split('--')[1],
            mutex_ref.split('--')[1]
        )
        self.assertEqual(attribute.value, mutex.name)
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = [observed_data, mutex]
        )

    def test_stix21_bundle_with_patterning_language_attributes(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_patterning_language_attributes()
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

    def test_stix21_bundle_with_port_indicator_attribute(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_port_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'port')
        self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_regkey_indicator_attribute(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_regkey_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'regkey')
        self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_regkey_observable_attribute(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_regkey_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, registry_key = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        registry_ref = self._check_observed_data_attribute(attribute, observed_data)[0]
        self.assertEqual(attribute.type, 'regkey')
        self._assert_multiple_equal(
            attribute.uuid,
            registry_key.id.split('--')[1],
            registry_ref.split('--')[1]
        )
        self.assertEqual(attribute.value, registry_key.key)
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = [observed_data, registry_key]
        )

    def test_stix21_bundle_with_regkey_value_indicator_attribute(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_regkey_value_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'regkey|value')
        key_pattern, data_pattern = pattern[1:-1].split(' AND ')
        key_value = self._get_pattern_value(key_pattern)
        data_value = self._get_pattern_value(data_pattern)
        self.assertEqual(attribute.value, f'{key_value}|{data_value}')
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_regkey_value_observable_attribute(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_regkey_value_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, registry_key = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        registry_ref = self._check_observed_data_attribute(attribute, observed_data)[0]
        self.assertEqual(attribute.type, 'regkey|value')
        self._assert_multiple_equal(
            attribute.uuid,
            registry_key.id.split('--')[1],
            registry_ref.split('--')[1]
        )
        self.assertEqual(
            attribute.value,
            f"{registry_key.key}|{registry_key['values'][0].data}"
        )
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = [observed_data, registry_key]
        )

    def test_stix21_bundle_with_size_in_bytes_indicator_attribute(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_size_in_bytes_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'size-in-bytes')
        self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_url_indicator_attributes(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_url_indicator_attributes()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_url_observable_attributes()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_vulnerability_attribute()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_x509_fingerprint_indicator_attributes()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_x509_fingerprint_observable_attributes()
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
    #                           MISP EVENTS IMPORT TESTS                           #
    ################################################################################

    def test_stix21_bundle_with_invalid_uuids(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_invalid_uuids()
        grouping, ap1, coa1, indicator1 = bundle.objects[1:5]
        ap2, od, _, ip_addr, custom, coa2, indicator2, vuln = bundle.objects[8:16]
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        grouping_uuid = self._extract_uuid(grouping.id)
        self.assertEqual(
            self.parser.misp_event.uuid,
            uuid5(self._UUIDv4, grouping_uuid)
        )
        self.assertIn(
            f'Original UUID was: {grouping_uuid}',
            self.parser.misp_event.comment
        )
        attribute = self.parser.misp_event.attributes[0]
        indicator1_uuid = self._extract_uuid(indicator1.id)
        self.assertEqual(attribute.uuid, uuid5(self._UUIDv4, indicator1_uuid))
        self.assertIn(f'Original UUID was: {indicator1_uuid}', attribute.comment)
        for tag, stix_object in zip(attribute.tags, (ap1, coa1)):
            self.assertIn(stix_object.name, tag.name)
        ap, ip_port1, btc, coa, ip_port2, vulnerability = self.parser.misp_event.objects
        ap_uuid = self._extract_uuid(ap2.id)
        self.assertEqual(ap.uuid, uuid5(self._UUIDv4, ap_uuid))
        self.assertIn(f'Original UUID was: {ap_uuid}', ap.comment)
        ip_port1_uuid = self._extract_uuid(od.id)
        self.assertEqual(ip_port1.uuid, uuid5(self._UUIDv4, ip_port1_uuid))
        self.assertIn(f'Original UUID was: {ip_port1_uuid}', ip_port1.comment)
        ip_dst = ip_port1.attributes[0]
        ip_dst_uuid = self._extract_uuid(ip_addr.id)
        self.assertEqual(ip_dst.uuid, uuid5(self._UUIDv4, ip_dst_uuid))
        self.assertIn(f'Original UUID was: {ip_dst_uuid}', ip_dst.comment)
        btc_uuid = self._extract_uuid(custom.id)
        self.assertEqual(btc.uuid, uuid5(self._UUIDv4, btc_uuid))
        self.assertIn(f'Original UUID was: {btc_uuid}', btc.comment)
        for misp_attribute, custom_attribute in zip(btc.attributes, custom.x_misp_attributes):
            attribute_uuid = custom_attribute['uuid']
            self.assertEqual(
                misp_attribute.uuid,
                uuid5(self._UUIDv4, attribute_uuid)
            )
            self.assertIn(
                f'Original UUID was: {attribute_uuid}',
                misp_attribute.comment
            )
        coa_uuid = self._extract_uuid(coa2.id)
        self.assertEqual(
            coa.uuid,
            uuid5(self._UUIDv4, coa_uuid),
            ip_port2.references[0].referenced_uuid
        )
        self.assertIn(f'Original UUID was: {coa_uuid}', coa.comment)
        indicator2_uuid = self._extract_uuid(indicator2.id)
        self._assert_multiple_equal(
            ip_port2.uuid,
            uuid5(self._UUIDv4, indicator2_uuid),
            ap.references[0].referenced_uuid,
            ip_port1.references[0].referenced_uuid,
            btc.references[0].referenced_uuid,
            vulnerability.references[0].referenced_uuid
        )
        self.assertIn(f'Original UUID was: {indicator2_uuid}', ip_port2.comment)
        vulnerability_uuid = self._extract_uuid(vuln.id)
        self.assertEqual(
            vulnerability.uuid,
            uuid5(self._UUIDv4, vulnerability_uuid),
            coa.references[0].referenced_uuid
        )
        self.assertIn(f'Original UUID was: {vulnerability_uuid}', vulnerability.comment)

    def test_stix21_bundle_with_multiple_reports_as_multiple_events(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_multiple_reports()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        _, grouping1, od1, _, od2, _, grouping2, indicator1, indicator2, malware, relation1, relation2 = bundle.objects
        self._check_events_from_bundle_with_multiple_reports(
            (
                grouping1, od1, od2, grouping2, indicator2, indicator1, malware,
                relation1, relation2
            )
        )

    def test_stix21_bundle_with_multiple_reports_as_single_event(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_multiple_reports()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle(single_event = True)
        _, _, od1, _, od2, _, _, indicator1, indicator2, malware, relation1, relation2 = bundle.objects
        self._check_single_event_from_bundle_with_multiple_reports(
            (od1, od2, indicator2, indicator1, malware, relation1, relation2),
            bundle.id
        )

    def test_stix21_bundle_with_no_report(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_no_report()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        _, od1, _, od2, _, indicator1, indicator2, malware, relation1, relation2 = bundle.objects
        self._check_event_from_bundle_with_no_report(
            (od1, od2, indicator1, indicator2, malware, relation1, relation2),
            bundle.id
        )

    def test_stix21_bundle_with_sightings(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_sightings()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, *stix_objects, identity1, identity2, identity3, identity4 = bundle.objects
        identities = (identity1, identity2, identity3, identity4)
        self.assertEqual(event.uuid, grouping.id.split('--')[1])
        self.assertEqual(len(event.attributes), 2)
        AS, domain  = event.attributes
        observed_data, _, sighting1, sighting2, opinion1, opinion2, indicator, sighting3, opinion3, sighting4, opinion4 = stix_objects
        self.assertEqual(AS.uuid, observed_data.id.split('--')[1])
        self.assertEqual(len(AS.sightings), 4)
        stix_objects = (sighting1, sighting2, opinion1, opinion2)
        for sighting, stix_object, identity in zip(AS.sightings, stix_objects, identities):
            self.assertEqual(sighting.date_sighting, self._timestamp_from_datetime(stix_object.modified))
            self.assertEqual(sighting.type, '0' if stix_object.type == 'sighting' else '1')
            self.assertEqual(sighting.Organisation['uuid'], identity.id.split('--')[1])
            self.assertEqual(sighting.Organisation['name'], identity.name)
        self.assertEqual(domain.uuid, indicator.id.split('--')[1])
        self.assertEqual(len(domain.sightings), 4)
        stix_objects = (sighting3, sighting4, opinion3, opinion4)
        identities = (identity1, identity3, identity2, identity4)
        for sighting, stix_object, identity in zip(domain.sightings, stix_objects, identities):
            self.assertEqual(sighting.date_sighting, self._timestamp_from_datetime(stix_object.modified))
            self.assertEqual(sighting.type, '0' if stix_object.type == 'sighting' else '1')
            self.assertEqual(sighting.Organisation['uuid'], identity.id.split('--')[1])
            self.assertEqual(sighting.Organisation['name'], identity.name)

    def test_stix21_bundle_with_single_report(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_single_report()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        _, grouping, od1, _, od2, _, indicator1, indicator2, malware, relation1, relation2 = bundle.objects
        self._check_event_from_bundle_with_single_report(
            (grouping, od1, od2, indicator1, indicator2, malware, relation1, relation2)
        )

    ################################################################################
    #                          MISP GALAXIES IMPORT TESTS                          #
    ################################################################################

    def test_stix21_bundle_with_attack_pattern_galaxy(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_attack_pattern_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, attack_pattern = bundle.objects
        self._check_misp_event_features_from_grouping(event, grouping)
        self._check_attack_pattern_galaxy(event.galaxies[0], attack_pattern)

    def test_stix21_bundle_with_course_of_action_galaxy(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_course_of_action_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, course_of_action = bundle.objects
        self._check_misp_event_features_from_grouping(event, grouping)
        self._check_course_of_action_galaxy(event.galaxies[0], course_of_action)

    def test_stix21_bundle_with_custom_galaxy(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_custom_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, custom = bundle.objects
        self._check_misp_event_features_from_grouping(event, grouping)
        self._check_custom_galaxy(event.galaxies[0], custom)

    def test_stix21_bundle_with_galaxy_embedded_in_attribute(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_galaxy_embedded_in_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, attack_pattern, course_of_action, _, malware, _, _ = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        for galaxy in attribute.galaxies:
            if galaxy['type'] == 'mitre-attack-pattern':
                self._check_galaxy_fields(
                    galaxy, attack_pattern, 'mitre-attack-pattern',
                    'Attack Pattern'
                )
                self.assertEqual(
                    galaxy.clusters[0].meta['external_id'],
                    attack_pattern.external_references[0].external_id
                )
            elif galaxy['type'] == 'mitre-course-of-action':
                self._check_galaxy_fields(
                    galaxy, course_of_action, 'mitre-course-of-action',
                    'Course of Action'
                )
            else:
                self.fail(f"Wrong MISP Galaxy type: {galaxy['type']}")
        galaxy = event.galaxies[0]
        self._check_galaxy_fields(galaxy, malware, 'mitre-malware', 'Malware')
        meta = galaxy.clusters[0].meta
        self.assertEqual(meta['synonyms'], malware.aliases)
        self.assertEqual(meta['is_family'], malware.is_family)

    def test_stix21_bundle_with_intrusion_set_galaxy(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_intrusion_set_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, intrusion_set = bundle.objects
        self._check_misp_event_features_from_grouping(event, grouping)
        self._check_intrusion_set_galaxy(event.galaxies[0], intrusion_set)

    def test_stix21_bundle_with_location_galaxies(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_location_galaxies()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, location1, location2 = bundle.objects
        self._check_misp_event_features_from_grouping(event, grouping)
        country, region = event.galaxies
        self._check_galaxy_fields(country, location1, 'country', 'Country')
        meta = country.clusters[0].meta
        for field, value in meta.items():
            self.assertEqual(value, getattr(location1, f'x_misp_{field}'))
        cluster = region.clusters[0]
        self._assert_multiple_equal(region.type, cluster.type, 'region')
        self.assertEqual(region.name, 'Regions UN M49')
        galaxy_description, cluster_description = location2.description.split(' | ')
        self.assertEqual(region.description, galaxy_description)
        self.assertEqual(cluster.value, f'154 - {location2.name}')
        self.assertEqual(cluster.description, cluster_description)
        self.assertEqual(
            region.clusters[0].meta['subregion'], location2.x_misp_subregion
        )

    def test_stix21_bundle_with_malware_galaxy(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_malware_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, malware = bundle.objects
        self._check_misp_event_features_from_grouping(event, grouping)
        self._check_malware_galaxy(event.galaxies[0], malware)

    def test_stix21_bundle_with_sector_galaxy(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_sector_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, identity = bundle.objects
        self._check_misp_event_features_from_grouping(event, grouping)
        self._check_sector_galaxy(event.galaxies[0], identity)

    def test_stix21_bundle_with_threat_actor_galaxy(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_threat_actor_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, threat_actor = bundle.objects
        self._check_misp_event_features_from_grouping(event, grouping)
        self._check_threat_actor_galaxy(event.galaxies[0], threat_actor)

    def test_stix21_bundle_with_tool_galaxy(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_tool_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, tool = bundle.objects
        self._check_misp_event_features_from_grouping(event, grouping)
        self._check_tool_galaxy(event.galaxies[0], tool)

    def test_stix21_bundle_with_vulnerability_galaxy(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_vulnerability_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, vulnerability = bundle.objects
        self._check_misp_event_features_from_grouping(event, grouping)
        self._check_vulnerability_galaxy(event.galaxies[0], vulnerability)

    ################################################################################
    #                          MISP OBJECTS IMPORT TESTS.                          #
    ################################################################################

    def test_stix21_bundle_with_account_indicator_objects(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_account_indicator_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, gitlab_indicator, telegram_indicator = bundle.objects
        gitlab, telegram = self._check_misp_event_features_from_grouping(event, grouping)
        gitlab_pattern = self._check_indicator_object(gitlab, gitlab_indicator)
        self._check_gitlab_user_indicator_object(gitlab.attributes, gitlab_pattern)
        self._populate_documentation(
            misp_object = json.loads(gitlab.to_json()),
            indicator = gitlab_indicator
        )
        telegram_pattern = self._check_indicator_object(telegram, telegram_indicator)
        self._check_telegram_account_indicator_object(telegram.attributes, telegram_pattern)
        self._populate_documentation(
            misp_object = json.loads(telegram.to_json()),
            indicator = telegram_indicator
        )

    def test_stix21_bundle_with_account_observable_objects(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_account_observable_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, gitlab_od, gitlab_o, telegram_od, telegram_o = bundle.objects
        gitlab, telegram = self._check_misp_event_features_from_grouping(event, grouping)
        gitlab_ref = self._check_observed_data_object(gitlab, gitlab_od)[0]
        self._assert_multiple_equal(
            gitlab.uuid,
            gitlab_o.id.split('--')[1],
            gitlab_ref.split('--')[1]
        )
        self._check_gitlab_user_observable_object(gitlab.attributes, gitlab_o)
        self._populate_documentation(
            misp_object = json.loads(gitlab.to_json()),
            observed_data = [gitlab_od, gitlab_o]
        )
        telegram_ref = self._check_observed_data_object(telegram, telegram_od)[0]
        self._assert_multiple_equal(
            telegram.uuid,
            telegram_o.id.split('--')[1],
            telegram_ref.split('--')[1]
        )
        self._check_telegram_account_observable_object(telegram.attributes, telegram_o)
        self._populate_documentation(
            misp_object = json.loads(telegram.to_json()),
            observed_data = [telegram_od, telegram_o]
        )

    def test_stix21_bundle_with_account_with_attachment_indicator_objects(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_account_with_attachment_indicator_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, facebook_i, github_i, parler_i, reddit_i, twitter_i, user_i = bundle.objects
        facebook, github, parler, reddit, twitter, user_account = self._check_misp_event_features_from_grouping(event, grouping)
        facebook_pattern = self._check_indicator_object(facebook, facebook_i)
        self._check_facebook_account_indicator_object(facebook.attributes, facebook_pattern)
        self._populate_documentation(
            misp_object = json.loads(facebook.to_json()),
            indicator = facebook_i
        )
        github_pattern = self._check_indicator_object(github, github_i)
        self._check_github_user_indicator_object(github.attributes, github_pattern)
        self._populate_documentation(
            misp_object = json.loads(github.to_json()),
            indicator = github_i
        )
        parler_pattern = self._check_indicator_object(parler, parler_i)
        self._check_parler_account_indicator_object(parler.attributes, parler_pattern)
        self._populate_documentation(
            misp_object = json.loads(parler.to_json()),
            indicator = parler_i
        )
        reddit_pattern = self._check_indicator_object(reddit, reddit_i)
        self._check_reddit_account_indicator_object(reddit.attributes, reddit_pattern)
        self._populate_documentation(
            misp_object = json.loads(reddit.to_json()),
            indicator = reddit_i
        )
        twitter_pattern = self._check_indicator_object(twitter, twitter_i)
        self._check_twitter_account_indicator_object(twitter.attributes, twitter_pattern)
        self._populate_documentation(
            misp_object = json.loads(twitter.to_json()),
            indicator = twitter_i
        )
        user_account_pattern = self._check_indicator_object(user_account, user_i)
        self._check_user_account_indicator_object(
            user_account.attributes,
            user_account_pattern[1:-1].split(' AND ')
        )
        self._populate_documentation(
            misp_object = json.loads(user_account.to_json()),
            indicator = user_i
        )

    def test_stix21_bundle_with_account_with_attachment_observable_objects(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_account_with_attachment_observable_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, facebook_od, facebook_o, github_od, github_o, parler_od, parler_o, reddit_od, reddit_o, twitter_od, twitter_o, user_od, user_o = bundle.objects
        facebook, github, parler, reddit, twitter, user_account = self._check_misp_event_features_from_grouping(event, grouping)
        facebook_ref = self._check_observed_data_object(facebook, facebook_od)[0]
        self._assert_multiple_equal(
            facebook.uuid,
            facebook_o.id.split('--')[1],
            facebook_ref.split('--')[1]
        )
        self._check_facebook_account_observable_object(facebook.attributes, facebook_o)
        self._populate_documentation(
            misp_object = json.loads(facebook.to_json()),
            observed_data = [facebook_od, facebook_o]
        )
        github_ref = self._check_observed_data_object(github, github_od)[0]
        self._assert_multiple_equal(
            github.uuid,
            github_o.id.split('--')[1],
            github_ref.split('--')[1]
        )
        self._check_github_user_observable_object(github.attributes, github_o)
        self._populate_documentation(
            misp_object = json.loads(github.to_json()),
            observed_data = [github_od, github_o]
        )
        parler_ref = self._check_observed_data_object(parler, parler_od)[0]
        self._assert_multiple_equal(
            parler.uuid,
            parler_o.id.split('--')[1],
            parler_ref.split('--')[1]
        )
        self._check_parler_account_observable_object(parler.attributes, parler_o)
        self._populate_documentation(
            misp_object = json.loads(parler.to_json()),
            observed_data = [parler_od, parler_o]
        )
        reddit_ref = self._check_observed_data_object(reddit, reddit_od)[0]
        self._assert_multiple_equal(
            reddit.uuid,
            reddit_o.id.split('--')[1],
            reddit_ref.split('--')[1]
        )
        self._check_reddit_account_observable_object(reddit.attributes, reddit_o)
        self._populate_documentation(
            misp_object = json.loads(reddit.to_json()),
            observed_data = [reddit_od, reddit_o]
        )
        twitter_ref = self._check_observed_data_object(twitter, twitter_od)[0]
        self._assert_multiple_equal(
            twitter.uuid,
            twitter_o.id.split('--')[1],
            twitter_ref.split('--')[1]
        )
        self._check_twitter_account_observable_object(twitter.attributes, twitter_o)
        self._populate_documentation(
            misp_object = json.loads(twitter.to_json()),
            observed_data = [twitter_od, twitter_o]
        )
        user_account_ref = self._check_observed_data_object(user_account, user_od)[0]
        self._assert_multiple_equal(
            user_account.uuid,
            user_o.id.split('--')[1],
            user_account_ref.split('--')[1]
        )
        password, last_changed = self._check_user_account_observable_object(
            user_account.attributes,
            user_o
        )
        self.assertEqual(password.type, 'text')
        self.assertEqual(password.object_relation, 'password')
        self.assertEqual(password.value, user_o.credential)
        self.assertEqual(last_changed.type, 'datetime')
        self.assertEqual(last_changed.object_relation, 'password_last_changed')
        self.assertEqual(last_changed.value, user_o.credential_last_changed)
        self._populate_documentation(
            misp_object = json.loads(user_account.to_json()),
            observed_data = [user_od, user_o]
        )

    def test_stix21_bundle_with_android_app_indicator_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_android_app_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_object(misp_object, indicator)
        self._check_android_app_indicator_object(misp_object.attributes, pattern)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_android_app_observable_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_android_app_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, observable = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        observable_ref = self._check_observed_data_object(misp_object, observed_data)[0]
        self._assert_multiple_equal(
            misp_object.uuid,
            observable.id.split('--')[1],
            observable_ref.split('--')[1]
        )
        self._check_android_app_observable_object(misp_object.attributes, observable)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            observed_data = [observed_data, observable]
        )

    def test_stix21_bundle_with_annotation_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_annotation_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, note, observed_data, _, _, indicator = bundle.objects
        note_object, ip_port_object, attribute = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(note_object.uuid, note.id.split('--')[1])
        self.assertEqual(note_object.name, 'annotation')
        content, attachment, note_type = note_object.attributes
        self.assertEqual(content.type, 'text')
        self.assertEqual(content.object_relation, 'text')
        self.assertEqual(content.value, note.content)
        self.assertEqual(attachment.type, 'attachment')
        self.assertEqual(attachment.object_relation, 'attachment')
        self.assertEqual(attachment.value, note.x_misp_attachment['value'])
        self.assertEqual(
            self._get_data_value(attachment.data),
            note.x_misp_attachment['data']
        )
        self.assertEqual(note_type.type, 'text')
        self.assertEqual(note_type.object_relation, 'type')
        self.assertEqual(note_type.value, note.x_misp_type)
        self.assertEqual(len(note_object.references), 2)
        ip_port_ref, attribute_ref = note_object.references
        self._assert_multiple_equal(
            ip_port_ref.referenced_uuid,
            ip_port_object.uuid,
            observed_data.id.split('--')[1]
        )
        self._assert_multiple_equal(
            attribute_ref.referenced_uuid,
            attribute.uuid,
            indicator.id.split('--')[1]
        )
        self._assert_multiple_equal(
            ip_port_ref.relationship_type,
            attribute_ref.relationship_type,
            'annotates'
        )
        self._populate_documentation(
            misp_object = json.loads(note_object.to_json()),
            note = note
        )

    def test_stix21_bundle_with_asn_indicator_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_asn_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_object(misp_object, indicator)
        self._check_asn_indicator_object(misp_object.attributes, pattern)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_asn_observable_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_asn_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, observable = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        observable_ref = self._check_observed_data_object(misp_object, observed_data)[0]
        self._assert_multiple_equal(
            misp_object.uuid,
            observable.id.split('--')[1],
            observable_ref.split('--')[1]
        )
        self._check_asn_observable_object(misp_object.attributes, observable)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            observed_data = [observed_data, observable]
        )

    def test_stix21_bundle_with_attack_pattern_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_attack_pattern_object()
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
        bundle = TestInternalSTIX21Bundles.get_bundle_with_course_of_action_object()
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

    def test_stix21_bundle_with_cpe_asset_indicator_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_cpe_asset_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_object(misp_object, indicator)
        self._check_cpe_asset_indicator_object(misp_object.attributes, pattern)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_cpe_asset_observable_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_cpe_asset_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, observable = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        observable_ref = self._check_observed_data_object(misp_object, observed_data)[0]
        self._assert_multiple_equal(
            misp_object.uuid,
            observable.id.split('--')[1],
            observable_ref.split('--')[1]
        )
        self._check_cpe_asset_observable_object(misp_object.attributes, observable)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            observed_data = [observed_data, observable]
        )

    def test_stix21_bundle_with_credential_indicator_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_credential_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_object(misp_object, indicator)
        self._check_credential_indicator_object(
            misp_object.attributes,
            pattern[1:-1].split(' AND ')
        )
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_credential_observable_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_credential_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, observable = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        observable_ref = self._check_observed_data_object(misp_object, observed_data)[0]
        self._assert_multiple_equal(
            misp_object.uuid,
            observable.id.split('--')[1],
            observable_ref.split('--')[1]
        )
        password = self._check_credential_observable_object(
            misp_object.attributes,
            observable
        )
        self.assertEqual(password.type, 'text')
        self.assertEqual(password.object_relation, 'password')
        self.assertEqual(password.value, observable.credential)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            observed_data = [observed_data, observable]
        )

    def test_stix21_bundle_with_custom_objects(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_custom_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, *custom_objects = bundle.objects
        misp_objects = self._check_misp_event_features_from_grouping(event, grouping)
        for misp_object, custom_object in zip(misp_objects, custom_objects):
            self._check_custom_object(misp_object, custom_object)

    def test_stix21_bundle_with_domain_ip_indicator_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_domain_ip_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_object(misp_object, indicator)
        self._check_domain_ip_indicator_object(misp_object.attributes, pattern)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_domain_ip_observable_objects(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_domain_ip_observable_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, standard_od, ip1, ip2, domain1, domain2, custom_od, domain3, ip3 = bundle.objects
        standard, custom = self._check_misp_event_features_from_grouping(event, grouping)
        ip1_ref, ip2_ref, domain1_ref, domain2_ref = self._check_observed_data_object(
            standard,
            standard_od
        )
        domain1_a, ip1_a, ip2_a, domain2_a = standard.attributes
        for attribute, observable, ref in zip((domain1_a, domain2_a), (domain1, domain2), (domain1_ref, domain2_ref)):
            self._assert_multiple_equal(
                attribute.uuid,
                observable.id.split('--')[1],
                ref.split('--')[1]
            )
            self.assertEqual(attribute.type, 'domain')
            self.assertEqual(attribute.object_relation, 'domain')
            self.assertEqual(attribute.value, observable.value)
        for attribute, observable, ref in zip((ip1_a, ip2_a), (ip1, ip2), (ip1_ref, ip2_ref)):
            self._assert_multiple_equal(
                attribute.uuid,
                observable.id.split('--')[1],
                ref.split('--')[1]
            )
            self.assertEqual(attribute.type, 'ip-dst')
            self.assertEqual(attribute.object_relation, 'ip')
            self.assertEqual(attribute.value, observable.value)
        self._populate_documentation(
            misp_object = json.loads(standard.to_json()),
            observed_data = [standard_od, ip1, ip2, domain1, domain2],
            name = 'Domain-IP object (standard case)'
        )
        domain_ref, ip_ref = self._check_observed_data_object(custom, custom_od)
        self._assert_multiple_equal(
            custom.uuid,
            domain3.id.split('--')[1],
            domain_ref.split('--')[1]
        )
        domain, hostname, port, ip = custom.attributes
        self.assertEqual(domain.type, 'domain')
        self.assertEqual(domain.object_relation, 'domain')
        self.assertEqual(domain.value, domain3.value)
        self.assertEqual(hostname.type, 'hostname')
        self.assertEqual(hostname.object_relation, 'hostname')
        self.assertEqual(hostname.value, domain3.x_misp_hostname)
        self.assertEqual(port.type, 'port')
        self.assertEqual(port.object_relation, 'port')
        self.assertEqual(port.value, domain3.x_misp_port)
        self._assert_multiple_equal(
            ip.uuid,
            ip3.id.split('--')[1],
            ip_ref.split('--')[1]
        )
        self.assertEqual(ip.type, 'ip-dst')
        self.assertEqual(ip.object_relation, 'ip')
        self.assertEqual(ip.value, ip3.value)
        self._populate_documentation(
            misp_object = json.loads(custom.to_json()),
            observed_data = [custom_od, domain3, ip3],
            name = 'Domain-IP object (custom case)'
        )

    def test_stix21_bundle_with_email_indicator_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_email_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        email_pattern = self._get_parsed_email_pattern(self._check_indicator_object(misp_object, indicator))
        self._check_email_indicator_object(misp_object.attributes, email_pattern)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_email_observable_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_email_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, od, message, addr1, addr2, addr3, addr4, addr5, file1, file2 = bundle.objects
        email = self._check_misp_event_features_from_grouping(event, grouping)[0]
        _from, _from_dn, _to, _to_dn, cc1, cc1_dn, cc2, cc2_dn, bcc, bcc_dn, message_id, subject, boundary, user_agent, reply_to, x_mailer, *attachments = email.attributes
        message_ref, addr1_ref, addr2_ref, addr3_ref, addr4_ref, addr5_ref, file1_ref, file2_ref = self._check_observed_data_object(email, od)
        self._assert_multiple_equal(
            email.uuid,
            od.id.split('--')[1],
            message.id.split('--')[1],
            message_ref.split('--')[1]
        )
        self._assert_multiple_equal(
            _from.uuid,
            addr1.id.split('--')[1],
            addr1_ref.split('--')[1]
        )
        self._assert_multiple_equal(
            _to.uuid,
            addr2.id.split('--')[1],
            addr2_ref.split('--')[1]
        )
        self._assert_multiple_equal(
            cc1.uuid,
            addr3.id.split('--')[1],
            addr3_ref.split('--')[1]
        )
        self._assert_multiple_equal(
            cc2.uuid,
            addr4.id.split('--')[1],
            addr4_ref.split('--')[1]
        )
        self._assert_multiple_equal(
            bcc.uuid,
            addr5.id.split('--')[1],
            addr5_ref.split('--')[1]
        )
        self._assert_multiple_equal(
            attachments[0].uuid,
            file1.id.split('--')[1],
            file1_ref.split('--')[1]
        )
        self._assert_multiple_equal(
            attachments[1].uuid,
            file2.id.split('--')[1],
            file2_ref.split('--')[1]
        )
        message_id = self._check_email_observable_object(
            (
                _from, _from_dn, _to, _to_dn, cc1, cc1_dn, cc2, cc2_dn, bcc, bcc_dn,
                subject, message_id, boundary, user_agent, reply_to, x_mailer,
                *attachments
            ),
            {observable.id: observable for observable in bundle.objects[-8:]}
        )
        self.assertEqual(message_id.type, 'email-message-id')
        self.assertEqual(message_id.object_relation, 'message-id')
        self.assertEqual(message_id.value, message.message_id)
        self._populate_documentation(
            misp_object = json.loads(email.to_json()),
            observed_data = [od, message, addr1, addr2, addr3, addr4, addr5, file1, file2]
        )

    def test_stix21_bundle_with_employee_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_employee_object()
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

    def test_stix21_bundle_with_file_and_pe_indicator_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_file_and_pe_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        file_object, pe_object, section_object = self._check_misp_event_features_from_grouping(event, grouping)
        file_pattern, pe_pattern, section_pattern = self._get_parsed_file_and_pe_pattern(
            self._check_indicator_object(file_object, indicator)
        )
        self.assertEqual(pe_object.name, 'pe')
        self.assertEqual(pe_object.timestamp, indicator.modified)
        self.assertEqual(section_object.name, 'pe-section')
        self.assertEqual(section_object.timestamp, indicator.modified)
        self._check_single_file_indicator_object(file_object.attributes, file_pattern)
        self._check_pe_indicator_object(pe_object.attributes, pe_pattern)
        self._check_pe_section_indicator_object(section_object.attributes, section_pattern)
        self._populate_documentation(
            misp_object = [
                json.loads(file_object.to_json()),
                json.loads(pe_object.to_json()),
                json.loads(section_object.to_json())
            ],
            indicator = indicator,
            name = 'File object with a Windows PE binary extension',
            summary = 'File object with a Windows PE binary extension'
        )

    def test_stix21_bundle_with_file_and_pe_observable_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_file_and_pe_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, observable = bundle.objects
        file_object, pe_object, section_object = self._check_misp_event_features_from_grouping(event, grouping)
        file_ref = self._check_observed_data_object(file_object, observed_data)[0]
        self._assert_multiple_equal(
            file_object.uuid,
            observable.id.split('--')[1],
            file_ref.split('--')[1]
        )
        self.assertEqual(pe_object.name, 'pe')
        self.assertEqual(pe_object.timestamp, observed_data.modified)
        self.assertEqual(section_object.name, 'pe-section')
        self.assertEqual(section_object.timestamp, observed_data.modified)
        self._check_file_and_pe_observable_object(
            file_object.attributes,
            pe_object.attributes,
            section_object.attributes,
            observable
        )
        self._populate_documentation(
            misp_object = [
                json.loads(file_object.to_json()),
                json.loads(pe_object.to_json()),
                json.loads(section_object.to_json())
            ],
            observed_data = [observed_data, observable],
            name = 'File object with a Windows PE binary extension',
            summary = 'File object with a Windows PE binary extension'
        )

    def test_stix21_bundle_with_file_indicator_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_file_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._get_parsed_file_pattern(self._check_indicator_object(misp_object, indicator))
        self._check_file_indicator_object(misp_object.attributes, pattern)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_file_observable_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_file_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, file_object, directory, artifact = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        file_ref, directory_ref, artifact_ref = self._check_observed_data_object(misp_object, observed_data)
        self._assert_multiple_equal(
            misp_object.uuid,
            file_object.id.split('--')[1],
            file_ref.split('--')[1]
        )
        self._assert_multiple_equal(
            misp_object.attributes[-2].uuid,
            directory.id.split('--')[1],
            directory_ref.split('--')[1]
        )
        self._assert_multiple_equal(
            misp_object.attributes[-1].uuid,
            artifact.id.split('--')[1],
            artifact_ref.split('--')[1]
        )
        self._check_file_observable_object(
            misp_object.attributes,
            {
                file_object.id: file_object,
                directory.id: directory,
                artifact.id: artifact
            }
        )
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            observed_data = [observed_data, file_object, directory, artifact]
        )

    def test_stix21_bundle_with_geolocation_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_geolocation_object()
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

    def test_stix21_bundle_with_http_request_indicator_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_http_request_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_object(misp_object, indicator)
        self._check_http_request_indicator_object(misp_object.attributes, pattern)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_http_request_observable_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_http_request_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, network_traffic, address1, address2, domain_name = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        network_traffic_ref, address1_ref, address2_ref, domain_name_ref = self._check_observed_data_object(misp_object, observed_data)
        self._assert_multiple_equal(
            misp_object.uuid,
            network_traffic.id.split('--')[1],
            network_traffic_ref.split('--')[1]
        )
        self._assert_multiple_equal(
            misp_object.attributes[0].uuid,
            address1.id.split('--')[1],
            address1_ref.split('--')[1]
        )
        self._assert_multiple_equal(
            misp_object.attributes[1].uuid,
            address2.id.split('--')[1],
            address2_ref.split('--')[1]
        )
        self._assert_multiple_equal(
            misp_object.attributes[-1].uuid,
            domain_name.id.split('--')[1],
            domain_name_ref.split('--')[1]
        )
        self._check_http_request_observable_object(
            misp_object.attributes,
            {
                network_traffic.id: network_traffic,
                address1.id: address1,
                address2.id: address2,
                domain_name.id: domain_name
            }
        )
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            observed_data = [observed_data, network_traffic, address1, address2, domain_name]
        )

    def test_stix21_bundle_with_image_indicator_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_image_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_object(misp_object, indicator)
        self._check_image_indicator_object(misp_object.attributes, pattern)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_image_observable_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_image_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, file_object, artifact = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        file_ref, artifact_ref = self._check_observed_data_object(misp_object, observed_data)
        self._assert_multiple_equal(
            misp_object.uuid,
            file_object.id.split('--')[1],
            file_ref.split('--')[1]
        )
        self._assert_multiple_equal(
            misp_object.attributes[-2].uuid,
            artifact.id.split('--')[1],
            artifact_ref.split('--')[1]
        )
        self._check_image_observable_object(
            misp_object.attributes,
            {
                file_object.id: file_object,
                artifact.id: artifact
            }
        )
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            observed_data = [observed_data, file_object, artifact]
        )

    def test_stix21_bundle_with_ip_port_indicator_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_ip_port_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_object(misp_object, indicator)
        self._check_ip_port_indicator_object(misp_object.attributes, pattern)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_ip_port_observable_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_ip_port_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, network_traffic, address = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        network_ref, address_ref = self._check_observed_data_object(misp_object, observed_data)
        self._assert_multiple_equal(
            misp_object.uuid,
            network_traffic.id.split('--')[1],
            network_ref.split('--')[1]
        )
        self._assert_multiple_equal(
            misp_object.attributes[0].uuid,
            address.id.split('--')[1],
            address_ref.split('--')[1]
        )
        self._check_ip_port_observable_object(
            misp_object.attributes,
            {
                network_traffic.id: network_traffic,
                address.id: address
            }
        )
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            observed_data = [observed_data, network_traffic, address]
        )

    def test_stix21_bundle_with_legal_entity_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_legal_entity_object()
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

    def test_stix21_bundle_with_lnk_indicator_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_lnk_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        atime, ctime,  mtime, name, dir_ref, MD5, SHA1, SHA256, payload_bin, x_misp_filename, content_md5, _, _, _, size = self._check_indicator_object(misp_object, indicator)[1:-1].split(' AND ')
        access_time, creation_time,  modification_time, filename, path, md5, sha1, sha256, size_in_bytes, malware_sample = misp_object.attributes
        self._check_lnk_indicator_object(
            (
                filename, path, md5, sha1, sha256, size_in_bytes, creation_time,
                modification_time, access_time, malware_sample
            ),
            (
                atime, ctime,  mtime, name, dir_ref, MD5, SHA1, SHA256, payload_bin,
                x_misp_filename, content_md5, size
            )
        )
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_lnk_observable_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_lnk_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, file_object, directory, artifact = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        file_ref, directory_ref, artifact_ref = self._check_observed_data_object(misp_object, observed_data)
        self._assert_multiple_equal(
            misp_object.uuid,
            file_object.id.split('--')[1],
            file_ref.split('--')[1]
        )
        self._assert_multiple_equal(
            misp_object.attributes[-2].uuid,
            directory.id.split('--')[1],
            directory_ref.split('--')[1]
        )
        self._assert_multiple_equal(
            misp_object.attributes[-1].uuid,
            artifact.id.split('--')[1],
            artifact_ref.split('--')[1]
        )
        atime, ctime, mtime = self._check_lnk_observable_object(
            misp_object.attributes,
            {
                file_object.id: file_object,
                directory.id: directory,
                artifact.id: artifact
            }
        )
        self.assertEqual(atime.type, 'datetime')
        self.assertEqual(atime.object_relation, 'lnk-access-time')
        self.assertEqual(atime.value, file_object.atime)
        self.assertEqual(ctime.type, 'datetime')
        self.assertEqual(ctime.object_relation, 'lnk-creation-time')
        self.assertEqual(ctime.value, file_object.ctime)
        self.assertEqual(mtime.type, 'datetime')
        self.assertEqual(mtime.object_relation, 'lnk-modification-time')
        self.assertEqual(mtime.value, file_object.mtime)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            observed_data = [observed_data, file_object, directory, artifact]
        )

    def test_stix21_bundle_with_mutex_indicator_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_mutex_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_object(misp_object, indicator)
        self._check_mutex_indicator_object(misp_object.attributes, pattern)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_mutex_observable_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_mutex_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, mutex = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        mutex_ref = self._check_observed_data_object(misp_object, observed_data)[0]
        self._assert_multiple_equal(
            misp_object.uuid,
            mutex.id.split('--')[1],
            mutex_ref.split('--')[1]
        )
        self._check_mutex_observable_object(misp_object.attributes, mutex)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            observed_data = [observed_data, mutex]
        )

    def test_stix21_bundle_with_netflow_indicator_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_netflow_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_object(misp_object, indicator)
        self._check_netflow_indicator_object(misp_object.attributes, pattern)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_netflow_observable_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_netflow_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, network_traffic, address1, as1, address2, as2 = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        network_traffic_ref, address1_ref, as1_ref, address2_ref, as2_ref = self._check_observed_data_object(misp_object, observed_data)
        self._assert_multiple_equal(
            misp_object.uuid,
            network_traffic.id.split('--')[1],
            network_traffic_ref.split('--')[1]
        )
        self._assert_multiple_equal(
            misp_object.attributes[0].uuid,
            address1.id.split('--')[1],
            address1_ref.split('--')[1]
        )
        self._assert_multiple_equal(
            misp_object.attributes[1].uuid,
            as1.id.split('--')[1],
            as1_ref.split('--')[1]
        )
        self._assert_multiple_equal(
            misp_object.attributes[2].uuid,
            address2.id.split('--')[1],
            address2_ref.split('--')[1]
        )
        self._assert_multiple_equal(
            misp_object.attributes[3].uuid,
            as2.id.split('--')[1],
            as2_ref.split('--')[1]
        )
        self._check_netflow_observable_object(
            misp_object.attributes,
            {
                network_traffic.id: network_traffic,
                address1.id: address1,
                as1.id: as1,
                address2.id: address2,
                as2.id: as2
            }
        )
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            observed_data = [observed_data, network_traffic, address1, as1, address2, as2]
        )

    def test_stix21_bundle_with_network_connection_indicator_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_network_connection_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_object(misp_object, indicator)
        self._check_network_connection_indicator_object(misp_object.attributes, pattern)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_network_connection_observable_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_network_connection_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, network_traffic, address1, address2 = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        network_ref, address1_ref, address2_ref = self._check_observed_data_object(misp_object, observed_data)
        self._assert_multiple_equal(
            misp_object.uuid,
            network_traffic.id.split('--')[1],
            network_ref.split('--')[1]
        )
        self._assert_multiple_equal(
            misp_object.attributes[0].uuid,
            address1.id.split('--')[1],
            address1_ref.split('--')[1]
        )
        self._assert_multiple_equal(
            misp_object.attributes[1].uuid,
            address2.id.split('--')[1],
            address2_ref.split('--')[1]
        )
        self._check_network_connection_observable_object(
            misp_object.attributes,
            {
                network_traffic.id: network_traffic,
                address1.id: address1,
                address2.id: address2
            }
        )
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            observed_data = [observed_data, network_traffic, address1, address2]
        )

    def test_stix21_bundle_with_network_socket_indicator_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_network_socket_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_object(misp_object, indicator)
        _, src_ref, _, dst_ref, _, *patterns = pattern[1:-1].split(' AND ')
        self._check_network_socket_indicator_object(
            misp_object.attributes,
            (src_ref, dst_ref, *patterns)
        )
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_network_socket_observable_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_network_socket_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, network_traffic, address1, address2 = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        network_ref, address1_ref, address2_ref = self._check_observed_data_object(misp_object, observed_data)
        self._assert_multiple_equal(
            misp_object.uuid,
            network_traffic.id.split('--')[1],
            network_ref.split('--')[1]
        )
        self._assert_multiple_equal(
            misp_object.attributes[0].uuid,
            address1.id.split('--')[1],
            address1_ref.split('--')[1]
        )
        self._assert_multiple_equal(
            misp_object.attributes[1].uuid,
            address2.id.split('--')[1],
            address2_ref.split('--')[1]
        )
        ip_src, ip_dst, port_dst, port_src, domain_family, *attributes = misp_object.attributes
        self._check_network_socket_observable_object(
            (ip_src, ip_dst, port_dst, port_src, *attributes),
            {
                network_traffic.id: network_traffic,
                address1.id: address1,
                address2.id: address2
            }
        )
        self.assertEqual(domain_family.type, 'text')
        self.assertEqual(domain_family.object_relation, 'domain-family')
        self.assertEqual(
            domain_family.value,
            network_traffic.x_misp_domain_family
        )
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            observed_data = [observed_data, network_traffic, address1, address2]
        )

    def test_stix21_bundle_with_news_agency_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_news_agency_object()
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

    def test_stix21_bundle_with_object_references(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_object_references()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, *_ = bundle.objects
        attack_pattern, autonomous_system, btc, course_of_action, ip_port, vulnerability = self._check_misp_event_features_from_grouping(event, grouping)
        attack_pattern_references = attack_pattern.references
        self.assertEqual(len(attack_pattern_references), 1)
        self.assertEqual(attack_pattern_references[0].referenced_uuid, ip_port.uuid)
        self.assertEqual(attack_pattern_references[0].relationship_type, 'threatens')
        autonomous_system_references = autonomous_system.references
        self.assertEqual(len(autonomous_system_references), 1)
        self.assertEqual(autonomous_system_references[0].referenced_uuid, ip_port.uuid)
        self.assertEqual(autonomous_system_references[0].relationship_type, 'includes')
        btc_references = btc.references
        self.assertEqual(len(btc_references), 1)
        self.assertEqual(btc_references[0].referenced_uuid, ip_port.uuid)
        self.assertEqual(btc_references[0].relationship_type, 'connected-to')
        course_of_action_references = course_of_action.references
        self.assertEqual(len(course_of_action_references), 1)
        self.assertEqual(course_of_action_references[0].referenced_uuid, vulnerability.uuid)
        self.assertEqual(course_of_action_references[0].relationship_type, 'protects-against')
        ip_port_references = ip_port.references
        self.assertEqual(len(ip_port_references), 1)
        self.assertEqual(ip_port_references[0].referenced_uuid, course_of_action.uuid)
        self.assertEqual(ip_port_references[0].relationship_type, 'protected-with')
        vulnerability_references = vulnerability.references
        self.assertEqual(len(vulnerability_references), 1)
        self.assertEqual(vulnerability_references[0].referenced_uuid, ip_port.uuid)
        self.assertEqual(vulnerability_references[0].relationship_type, 'affects')

    def test_stix21_bundle_with_organization_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_organization_object()
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

    def test_stix21_bundle_with_patterning_language_objects(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_patterning_language_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, sigma_indicator, suricata_indicator, yara_indicator = bundle.objects
        sigma, suricata, yara = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(sigma.name, sigma_indicator.pattern_type)
        self.assertEqual(sigma.uuid, sigma_indicator.id.split('--')[1])
        self._assert_multiple_equal(
            sigma.timestamp,
            sigma_indicator.created,
            sigma_indicator.modified
        )
        self._check_object_labels(sigma, sigma_indicator.labels, True)
        pattern, comment, name, context, reference = sigma.attributes
        self.assertEqual(pattern.value, sigma_indicator.pattern)
        self.assertEqual(pattern.type, sigma_indicator.pattern_type)
        self.assertEqual(comment.value, sigma_indicator.description)
        self.assertEqual(name.value, sigma_indicator.name)
        self.assertEqual(context.value, sigma_indicator.x_misp_context)
        self.assertEqual(reference.value, sigma_indicator.external_references[0].url)
        self._populate_documentation(
            misp_object = json.loads(sigma.to_json()),
            indicator = sigma_indicator
        )
        self.assertEqual(suricata.name, 'suricata')
        self.assertEqual(suricata.uuid, suricata_indicator.id.split('--')[1])
        self._assert_multiple_equal(
            suricata.timestamp,
            suricata_indicator.created,
            suricata_indicator.modified
        )
        self._check_object_labels(suricata, suricata_indicator.labels, True)
        pattern, comment, version, ref = suricata.attributes
        self.assertEqual(pattern.value, suricata_indicator.pattern)
        self.assertEqual(pattern.type, suricata_indicator.pattern_type)
        self.assertEqual(comment.value, suricata_indicator.description)
        self.assertEqual(version.value, suricata_indicator.pattern_version)
        self.assertEqual(ref.value, suricata_indicator.external_references[0].url)
        self._populate_documentation(
            misp_object = json.loads(suricata.to_json()),
            indicator = suricata_indicator
        )
        self.assertEqual(yara.name, yara_indicator.pattern_type)
        self.assertEqual(yara.uuid, yara_indicator.id.split('--')[1])
        self._assert_multiple_equal(
            yara.timestamp,
            yara_indicator.created,
            yara_indicator.modified
        )
        self._check_object_labels(yara, yara_indicator.labels, True)
        pattern, comment, name, version = yara.attributes
        self.assertEqual(pattern.value, yara_indicator.pattern)
        self.assertEqual(pattern.type, yara_indicator.pattern_type)
        self.assertEqual(comment.value, yara_indicator.description)
        self.assertEqual(name.value, yara_indicator.name)
        self.assertEqual(version.value, yara_indicator.pattern_version)
        self._populate_documentation(
            misp_object = json.loads(yara.to_json()),
            indicator = yara_indicator
        )

    def test_stix21_bundle_with_process_indicator_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_process_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_object(misp_object, indicator)
        pid, image, parent_command_line, parent_image, parent_pid, parent_name, child_pid, hidden, name, port = misp_object.attributes
        _pid, _image, _parent_command_line, _parent_image, _parent_pid, _parent_name, _child_pid, is_hidden, _name, _port = pattern[1:-1].split(' AND ')
        self._check_process_indicator_object(
            (
                name, pid, image, parent_command_line, parent_image, parent_pid,
                parent_name, child_pid, hidden, port
            ),
            (
                _name, _pid, _image, _parent_command_line, _parent_image, _parent_pid,
                _parent_name, _child_pid, is_hidden, _port
            )
        )
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_process_observable_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_process_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, process, parent_image, parent_process, child_process, image = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        process_ref, parent_image_ref, parent_ref, child_ref, image_ref = self._check_observed_data_object(misp_object, observed_data)
        self._assert_multiple_equal(
            misp_object.uuid,
            process.id.split('--')[1],
            process_ref.split('--')[1]
        )
        self._assert_multiple_equal(
            misp_object.attributes[-2].uuid,
            parent_process.id.split('--')[1],
            parent_ref.split('--')[1]
        )
        self._assert_multiple_equal(
            misp_object.attributes[-1].uuid,
            parent_image.id.split('--')[1],
            parent_image_ref.split('--')[1]
        )
        self._assert_multiple_equal(
            misp_object.attributes[5].uuid,
            child_process.id.split('--')[1],
            child_ref.split('--')[1]
        )
        self._assert_multiple_equal(
            misp_object.attributes[4].uuid,
            image.id.split('--')[1],
            image_ref.split('--')[1]
        )
        name, parent_process_name = self._check_process_observable_object(
            misp_object.attributes,
            {
                process.id: process,
                parent_process.id: parent_process,
                parent_image.id: parent_image,
                child_process.id: child_process,
                image.id: image
            }
        )
        self.assertEqual(name.type, 'text')
        self.assertEqual(name.object_relation, 'name')
        self.assertEqual(name.value, process.x_misp_name)
        self.assertEqual(parent_process_name.type, 'text')
        self.assertEqual(parent_process_name.object_relation, 'parent-process-name')
        self.assertEqual(parent_process_name.value, parent_process.x_misp_process_name)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            observed_data = [
                observed_data,
                process,
                parent_image,
                parent_process,
                child_process,
                image
            ]
        )

    def test_stix21_bundle_with_registry_key_indicator_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_registry_key_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_object(misp_object, indicator)
        key, last_modified, *attributes = misp_object.attributes
        _key, modified_time, *patterns = pattern[1:-1].split(' AND ')
        self._check_registry_key_indicator_object(
            (key, *attributes, last_modified),
            (_key, *patterns, modified_time)
        )
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_registry_key_observable_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_registry_key_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, registry_key = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        registry_key_ref = self._check_observed_data_object(misp_object, observed_data)[0]
        self._assert_multiple_equal(
            misp_object.uuid,
            registry_key.id.split('--')[1],
            registry_key_ref.split('--')[1]
        )
        modified_time = self._check_registry_key_observable_object(
            misp_object.attributes,
            registry_key
        )
        self.assertEqual(modified_time.type, 'datetime')
        self.assertEqual(modified_time.object_relation, 'last-modified')
        self.assertEqual(modified_time.value, registry_key.modified_time)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            observed_data = [observed_data, registry_key]
        )

    def test_stix21_bundle_with_script_objects(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_script_objects()
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

    def test_stix21_bundle_with_url_indicator_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_url_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_object(misp_object, indicator)
        self._check_url_indicator_object(misp_object.attributes, pattern)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_url_observable_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_url_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, url = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        url_ref = self._check_observed_data_object(misp_object, observed_data)[0]
        self._assert_multiple_equal(
            misp_object.uuid,
            url.id.split('--')[1],
            url_ref.split('--')[1]
        )
        self._check_url_observable_object(misp_object.attributes, url)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            observed_data = [observed_data, url]
        )

    def test_stix21_bundle_with_vulnerability_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_vulnerability_object()
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

    def test_stix21_bundle_with_x509_indicator_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_x509_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        pattern = self._check_indicator_object(misp_object, indicator)
        self._check_x509_indicator_object(misp_object.attributes, pattern)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix21_bundle_with_x509_observable_object(self):
        bundle = TestInternalSTIX21Bundles.get_bundle_with_x509_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, x509 = bundle.objects
        misp_object = self._check_misp_event_features_from_grouping(event, grouping)[0]
        x509_ref = self._check_observed_data_object(misp_object, observed_data)[0]
        self._assert_multiple_equal(
            misp_object.uuid,
            x509.id.split('--')[1],
            x509_ref.split('--')[1]
        )
        self._check_x509_observable_object(misp_object.attributes, x509)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            observed_data = [observed_data, x509]
        )
