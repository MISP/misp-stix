#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
from uuid import uuid5
from .test_internal_stix20_bundles import TestInternalSTIX20Bundles
from ._test_stix import TestSTIX20
from ._test_stix_import import TestInternalSTIX2Import, TestSTIX20Import


class TestInternalSTIX20Import(TestInternalSTIX2Import, TestSTIX20, TestSTIX20Import):

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

    def _check_observed_data_object(self, misp_object, observed_data):
        self.assertEqual(misp_object.uuid, observed_data.id.split('--')[1])
        self._assert_multiple_equal(
            misp_object.timestamp,
            observed_data.created,
            observed_data.modified
        )
        self._check_object_labels(misp_object, observed_data.labels, False)
        return observed_data.objects

    ################################################################################
    #                         MISP ATTRIBUTES IMPORT TESTS                         #
    ################################################################################

    def test_stix20_bundle_with_AS_indicator_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_AS_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'AS')
        self.assertEqual(attribute.value, f'AS{self._get_pattern_value(pattern[1:-1])}')
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_AS_observable_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_AS_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        observable = self._check_observed_data_attribute(attribute, observed_data)['0']
        self.assertEqual(attribute.type, 'AS')
        self.assertEqual(attribute.value, f'AS{observable.number}')
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_attachment_indicator_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_attachment_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
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

    def test_stix20_bundle_with_attachment_observable_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_attachment_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        file_observable, artifact_observable = self._check_observed_data_attribute(
            attribute,
            observed_data
        ).values()
        self.assertEqual(attribute.type, 'attachment')
        self.assertEqual(attribute.value, file_observable.name)
        self.assertEqual(self._get_data_value(attribute.data), artifact_observable.payload_bin)
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_campaign_name_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_campaign_name_attribute()
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

    def test_stix20_bundle_with_custom_attributes(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_custom_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, *custom_attributes = bundle.objects
        attributes = self._check_misp_event_features(event, report)
        self.assertEqual(len(attributes), len(custom_attributes))
        for attribute, custom_attribute in zip(attributes, custom_attributes):
            self._check_custom_attribute(attribute, custom_attribute)

    def test_stix20_bundle_with_domain_ip_indicator_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_domain_ip_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
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

    def test_stix20_bundle_with_domain_ip_observable_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_domain_ip_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        domain, address = self._check_observed_data_attribute(attribute, observed_data).values()
        self.assertEqual(attribute.type, 'domain|ip')
        self.assertEqual(
            attribute.value,
            f'{domain.value}|{address.value}'
        )
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_domain_indicator_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_domain_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'domain')
        self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_domain_observable_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_domain_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        observable = self._check_observed_data_attribute(attribute, observed_data)['0']
        self.assertEqual(attribute.type, 'domain')
        self.assertEqual(attribute.value, observable.value)
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_email_attachment_indicator_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_email_attachment_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'email-attachment')
        self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_email_attachment_observable_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_email_attachment_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        message, file_object = self._check_observed_data_attribute(attribute, observed_data).values()
        self.assertEqual(attribute.type, 'email-attachment')
        self._assert_multiple_equal(
            attribute.value,
            message.body_multipart[0]['content_disposition'].split('=')[1].strip("'"),
            file_object.name
        )
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_email_body_indicator_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_email_body_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'email-body')
        self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_email_body_observable_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_email_body_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        observable = self._check_observed_data_attribute(attribute, observed_data)['0']
        self.assertEqual(attribute.type, 'email-body')
        self.assertEqual(attribute.value, observable.body)
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_email_destination_indicator_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_email_destination_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'email-dst')
        self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_email_destination_observable_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_email_destination_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        observable = self._check_observed_data_attribute(attribute, observed_data)['1']
        self.assertEqual(attribute.type, 'email-dst')
        self.assertEqual(attribute.value, observable.value)
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_email_header_indicator_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_email_header_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'email-header')
        self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_email_header_observable_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_email_header_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        observable = self._check_observed_data_attribute(attribute, observed_data)['0']
        self.assertEqual(attribute.type, 'email-header')
        self.assertEqual(attribute.value, observable.received_lines[0])
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_email_indicator_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_email_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'email')
        self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_email_observable_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_email_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        observable = self._check_observed_data_attribute(attribute, observed_data)['0']
        self.assertEqual(attribute.type, 'email')
        self.assertEqual(attribute.value, observable.value)
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_email_reply_to_indicator_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_email_reply_to_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'email-reply-to')
        self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_email_reply_to_observable_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_email_reply_to_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        observable = self._check_observed_data_attribute(attribute, observed_data)['0']
        self.assertEqual(attribute.type, 'email-reply-to')
        self.assertEqual(attribute.value, observable.additional_header_fields['Reply-To'])
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_email_source_indicator_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_email_source_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'email-src')
        self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_email_source_observable_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_email_source_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        observable = self._check_observed_data_attribute(attribute, observed_data)['1']
        self.assertEqual(attribute.type, 'email-src')
        self.assertEqual(attribute.value, observable.value)
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_email_subject_indicator_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_email_subject_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'email-subject')
        self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_email_subject_observable_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_email_subject_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        observable = self._check_observed_data_attribute(attribute, observed_data)['0']
        self.assertEqual(attribute.type, 'email-subject')
        self.assertEqual(attribute.value, observable.subject)
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_email_x_mailer_indicator_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_email_x_mailer_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'email-x-mailer')
        self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_email_x_mailer_observable_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_email_x_mailer_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        observable = self._check_observed_data_attribute(attribute, observed_data)['0']
        self.assertEqual(attribute.type, 'email-x-mailer')
        self.assertEqual(attribute.value, observable.additional_header_fields['X-Mailer'])
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_filename_indicator_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_filename_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'filename')
        self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_filename_observable_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_filename_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        observable = self._check_observed_data_attribute(attribute, observed_data)['0']
        self.assertEqual(attribute.type, 'filename')
        self.assertEqual(attribute.value, observable.name)
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundl_with_github_username_indicator_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_github_username_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
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

    def test_stix20_bundle_with_hash_composite_indicator_attributes(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_hash_composite_indicator_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, *indicators = bundle.objects
        attributes = self._check_misp_event_features(event, report)
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

    def test_stix20_bundle_with_hash_composite_observable_attributes(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_hash_composite_observable_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, *observables = bundle.objects
        attributes = self._check_misp_event_features(event, report)
        self.assertEqual(len(attributes), 14)
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

    def test_stix20_bundle_with_hash_indicator_attributes(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_hash_indicator_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, *indicators = bundle.objects
        attributes = self._check_misp_event_features(event, report)
        self.assertEqual(len(attributes), 15)
        for attribute, indicator in zip(attributes, indicators):
            pattern = self._check_indicator_attribute(attribute, indicator)
            self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
            self._populate_documentation(
                attribute = json.loads(attribute.to_json()),
                indicator = indicator
            )

    def test_stix20_bundle_with_hash_observable_attributes(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_hash_observable_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, *observables = bundle.objects
        attributes = self._check_misp_event_features(event, report)
        self.assertEqual(len(attributes), 15)
        for attribute, observed_data in zip(attributes, observables):
            observable = self._check_observed_data_attribute(attribute, observed_data)['0']
            hash_type = self.hash_types_mapping(attribute.type)
            self.assertEqual(attribute.value, observable.hashes[hash_type])
            self._populate_documentation(
                attribute = json.loads(attribute.to_json()),
                observed_data = observed_data
            )

    def test_stix20_bundle_with_hostname_indicator_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_hostname_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'hostname')
        self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_hostname_observable_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_hostname_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        observable = self._check_observed_data_attribute(attribute, observed_data)['0']
        self.assertEqual(attribute.type, 'hostname')
        self.assertEqual(attribute.value, observable.value)
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_hostname_port_indicator_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_hostname_port_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
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

    def test_stix20_bundle_with_hostname_port_observable_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_hostname_port_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        domain, network = self._check_observed_data_attribute(attribute, observed_data).values()
        self.assertEqual(attribute.type, 'hostname|port')
        self.assertEqual(attribute.value, f'{domain.value}|{network.dst_port}')
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_http_indicator_attributes(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_http_indicator_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, *indicators = bundle.objects
        attributes = self._check_misp_event_features(event, report)
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

    def test_stix20_bundle_with_ip_indicator_attributes(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_ip_indicator_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, *indicators = bundle.objects
        attributes = self._check_misp_event_features(event, report)
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

    def test_stix20_bundle_with_ip_observable_attributes(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_ip_observable_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, *observables = bundle.objects
        attributes = self._check_misp_event_features(event, report)
        self.assertEqual(len(attributes), 2)
        for attribute, observed_data in zip(attributes, observables):
            network, address = self._check_observed_data_attribute(attribute, observed_data).values()
            feature = attribute.type.split('-')[1]
            self.assertTrue(hasattr(network, f"{feature}_ref"))
            self.assertEqual(attribute.value, address.value)
            self._populate_documentation(
                attribute = json.loads(attribute.to_json()),
                observed_data = observed_data
            )

    def test_stix20_bundle_with_ip_port_indicator_attributes(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_ip_port_indicator_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, *indicators = bundle.objects
        attributes = self._check_misp_event_features(event, report)
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

    def test_stix20_bundle_with_ip_port_observable_attributes(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_ip_port_observable_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, *observables = bundle.objects
        attributes = self._check_misp_event_features(event, report)
        self.assertEqual(len(attributes), 2)
        for attribute, observed_data in zip(attributes, observables):
            network, address = self._check_observed_data_attribute(attribute, observed_data).values()
            feature = attribute.type.split('|')[0].split('-')[1]
            ip_value, port_value = attribute.value.split('|')
            self.assertEqual(ip_value, address.value)
            self.assertEqual(int(port_value), getattr(network, f"{feature}_port"))
            self._populate_documentation(
                attribute = json.loads(attribute.to_json()),
                observed_data = observed_data
            )

    def test_stix20_bundle_with_mac_address_indicator_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_mac_address_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'mac-address')
        self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_mac_address_observable_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_mac_address_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        observable = self._check_observed_data_attribute(attribute, observed_data)['0']
        self.assertEqual(attribute.type, 'mac-address')
        self.assertEqual(attribute.value, observable.value)
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_malware_sample_indicator_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_malware_sample_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'malware-sample')
        filename_pattern, md5_pattern, data_pattern, _ = pattern[1:-1].split(' AND ')
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

    def test_stix20_bundle_with_malware_sample_observable_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_malware_sample_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        file_object, artifact = self._check_observed_data_attribute(attribute, observed_data).values()
        self.assertEqual(attribute.type, 'malware-sample')
        self.assertEqual(attribute.value, f"{file_object.name}|{file_object.hashes['MD5']}")
        self.assertEqual(self._get_data_value(attribute.data), artifact.payload_bin)
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_mutex_indicator_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_mutex_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'mutex')
        self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_mutex_observable_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_mutex_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        observable = self._check_observed_data_attribute(attribute, observed_data)['0']
        self.assertEqual(attribute.type, 'mutex')
        self.assertEqual(attribute.value, observable.name)
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_port_indicator_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_port_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'port')
        self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_regkey_indicator_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_regkey_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'regkey')
        self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_regkey_observable_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_regkey_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        observable = self._check_observed_data_attribute(attribute, observed_data)['0']
        self.assertEqual(attribute.type, 'regkey')
        self.assertEqual(attribute.value, observable.key)
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_regkey_value_indicator_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_regkey_value_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
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

    def test_stix20_bundle_with_regkey_value_observable_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_regkey_value_observable_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        observable = self._check_observed_data_attribute(attribute, observed_data)['0']
        self.assertEqual(attribute.type, 'regkey|value')
        self.assertEqual(attribute.value, f"{observable.key}|{observable['values'][0].data}")
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_size_in_bytes_indicator_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_size_in_bytes_indicator_attribute()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        attribute = self._check_misp_event_features(event, report)[0]
        pattern = self._check_indicator_attribute(attribute, indicator)
        self.assertEqual(attribute.type, 'size-in-bytes')
        self.assertEqual(attribute.value, self._get_pattern_value(pattern[1:-1]))
        self._populate_documentation(
            attribute = json.loads(attribute.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_url_indicator_attributes(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_url_indicator_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, *indicators = bundle.objects
        attributes = self._check_misp_event_features(event, report)
        self.assertEqual(len(attributes), 3)
        for attribute, indicator in zip(attributes, indicators):
            pattern = self._check_indicator_attribute(attribute, indicator)[1:-1]
            self.assertEqual(attribute.value, self._get_pattern_value(pattern))
            self._populate_documentation(
                attribute = json.loads(attribute.to_json()),
                indicator = indicator
            )

    def test_stix20_bundle_with_url_observable_attributes(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_url_observable_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, *observables = bundle.objects
        attributes = self._check_misp_event_features(event, report)
        self.assertEqual(len(attributes), 3)
        for attribute, observed_data in zip(attributes, observables):
            url = self._check_observed_data_attribute(attribute, observed_data)['0']
            self.assertEqual(attribute.value, url.value)
            self._populate_documentation(
                attribute = json.loads(attribute.to_json()),
                observed_data = observed_data
            )

    def test_stix20_bundle_with_vulnerability_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_vulnerability_attribute()
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

    def test_stix20_bundle_with_x509_fingerprint_indicator_attributes(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_x509_fingerprint_indicator_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, *indicators = bundle.objects
        attributes = self._check_misp_event_features(event, report)
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

    def test_stix20_bundle_with_x509_fingerprint_observable_attributes(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_x509_fingerprint_observable_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, *observables = bundle.objects
        attributes = self._check_misp_event_features(event, report)
        self.assertEqual(len(attributes), 3)
        for attribute, observed_data in zip(attributes, observables):
            observable = self._check_observed_data_attribute(attribute, observed_data)['0']
            hash_type = self.hash_types_mapping(attribute.type.split('-')[-1])
            self.assertEqual(attribute.value, observable.hashes[hash_type])
            self._populate_documentation(
                attribute = json.loads(attribute.to_json()),
                observed_data = observed_data
            )

    ################################################################################
    #                           MISP EVENTS IMPORT TESTS                           #
    ################################################################################

    def test_stix20_bundle_with_invalid_uuids(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_invalid_uuids()
        report, ap1, coa1, indicator1 = bundle.objects[1:5]
        ap2, observed_data, custom, coa2, indicator2, vuln = bundle.objects[8:14]
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        report_uuid = self._extract_uuid(report.id)
        self.assertEqual(
            self.parser.misp_event.uuid,
            uuid5(self._UUIDv4, report_uuid)
        )
        self.assertIn(
            f'Original UUID was: {report_uuid}',
            self.parser.misp_event.comment
        )
        attribute = self.parser.misp_event.attributes[0]
        indicator1_uuid = self._extract_uuid(indicator1.id)
        self.assertEqual(attribute.uuid, uuid5(self._UUIDv4, indicator1_uuid))
        self.assertIn(f'Original UUID was: {indicator1_uuid}', attribute.comment)
        for tag, stix_object in zip(attribute.tags, (ap1, coa1)):
            self.assertIn(stix_object.name, tag.name)
        ap, asn, btc, coa, ip_port, vulnerability = self.parser.misp_event.objects
        ap_uuid = self._extract_uuid(ap2.id)
        self.assertEqual(ap.uuid, uuid5(self._UUIDv4, ap_uuid))
        self.assertIn(f'Original UUID was: {ap_uuid}', ap.comment)
        asn_uuid = self._extract_uuid(observed_data.id)
        self.assertEqual(asn.uuid, uuid5(self._UUIDv4, asn_uuid))
        self.assertIn(f'Original UUID was: {asn_uuid}', asn.comment)
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
            ip_port.references[0].referenced_uuid
        )
        self.assertIn(f'Original UUID was: {coa_uuid}', coa.comment)
        indicator2_uuid = self._extract_uuid(indicator2.id)
        self._assert_multiple_equal(
            ip_port.uuid,
            uuid5(self._UUIDv4, indicator2_uuid),
            ap.references[0].referenced_uuid,
            asn.references[0].referenced_uuid,
            btc.references[0].referenced_uuid,
            vulnerability.references[0].referenced_uuid
        )
        self.assertIn(f'Original UUID was: {indicator2_uuid}', ip_port.comment)
        vulnerability_uuid = self._extract_uuid(vuln.id)
        self.assertEqual(
            vulnerability.uuid,
            uuid5(self._UUIDv4, vulnerability_uuid),
            coa.references[0].referenced_uuid
        )
        self.assertIn(f'Original UUID was: {vulnerability_uuid}', vulnerability.comment)

    def test_stix20_bundle_with_multiple_reports_as_multiple_events(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_multiple_reports()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        self._check_events_from_bundle_with_multiple_reports(bundle.objects[1:])

    def test_stix20_bundle_with_multiple_reports_as_single_event(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_multiple_reports()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle(single_event = True)
        _, _, od1, od2, _, indicator1, indicator2, malware, relation1, relation2 = bundle.objects
        self._check_single_event_from_bundle_with_multiple_reports(
            (od1, od2, indicator1, indicator2, malware, relation1, relation2),
            bundle.id
        )

    def test_stix20_bundle_with_no_report(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_no_report()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        self._check_event_from_bundle_with_no_report(bundle.objects[1:], bundle.id)

    def test_stix20_bundle_with_sightings(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_sightings()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, identity1, identity2, identity3, identity4, report, *stix_objects = bundle.objects
        identities = (identity1, identity2, identity3, identity4)
        self.assertEqual(event.uuid, report.id.split('--')[1])
        self.assertEqual(len(event.attributes), 2)
        AS, domain  = event.attributes
        observed_data, sighting1, sighting2, opinion1, opinion2, indicator, sighting3, opinion3, sighting4, opinion4 = stix_objects
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

    def test_stix20_bundle_with_single_report(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_single_report()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        self._check_event_from_bundle_with_single_report(bundle.objects[1:])

    ################################################################################
    #                          MISP GALAXIES IMPORT TESTS                          #
    ################################################################################

    def test_stix20_bundle_with_attack_pattern_galaxy(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_attack_pattern_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, attack_pattern = bundle.objects
        self._check_misp_event_features(event, report)
        self._check_attack_pattern_galaxy(event.galaxies[0], attack_pattern)

    def test_stix20_bundle_with_course_of_action_galaxy(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_course_of_action_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, course_of_action = bundle.objects
        self._check_misp_event_features(event, report)
        self._check_course_of_action_galaxy(event.galaxies[0], course_of_action)

    def test_stix20_bundle_with_custom_galaxy(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_custom_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, custom = bundle.objects
        self._check_misp_event_features(event, report)
        self._check_custom_galaxy(event.galaxies[0], custom)

    def test_stix20_bundle_with_galaxy_embedded_in_attribute(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_galaxy_embedded_in_attribute()
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

    def test_stix20_bundle_with_intrusion_set_galaxy(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_intrusion_set_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, intrusion_set = bundle.objects
        self._check_misp_event_features(event, report)
        self._check_intrusion_set_galaxy(event.galaxies[0], intrusion_set)

    def test_stix20_bundle_with_malware_galaxy(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_malware_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, malware = bundle.objects
        self._check_misp_event_features(event, report)
        self._check_malware_galaxy(event.galaxies[0], malware)

    def test_stix20_bundle_with_sector_galaxy(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_sector_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, identity = bundle.objects
        self._check_misp_event_features(event, report)
        self._check_sector_galaxy(event.galaxies[0], identity)

    def test_stix20_bundle_with_threat_actor_galaxy(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_threat_actor_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, threat_actor = bundle.objects
        self._check_misp_event_features(event, report)
        self._check_threat_actor_galaxy(event.galaxies[0], threat_actor)

    def test_stix20_bundle_with_tool_galaxy(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_tool_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, tool = bundle.objects
        self._check_misp_event_features(event, report)
        self._check_tool_galaxy(event.galaxies[0], tool)

    def test_stix20_bundle_with_vulnerability_galaxy(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_vulnerability_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, vulnerability = bundle.objects
        self._check_misp_event_features(event, report)
        self._check_vulnerability_galaxy(event.galaxies[0], vulnerability)

    ################################################################################
    #                          MISP OBJECTS IMPORT TESTS.                          #
    ################################################################################

    def test_stix20_bundle_with_account_indicator_objects(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_account_indicator_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, gitlab_indicator, telegram_indicator = bundle.objects
        gitlab, telegram = self._check_misp_event_features(event, report)
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

    def test_stix20_bundle_with_account_observable_objects(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_account_observable_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, gitlab_observed_data, telegram_observed_data = bundle.objects
        gitlab, telegram = self._check_misp_event_features(event, report)
        gitlab_observable = self._check_observed_data_object(gitlab, gitlab_observed_data)['0']
        self._check_gitlab_user_observable_object(gitlab.attributes, gitlab_observable)
        self._populate_documentation(
            misp_object = json.loads(gitlab.to_json()),
            observed_data = gitlab_observed_data
        )
        telegram_observable = self._check_observed_data_object(telegram, telegram_observed_data)['0']
        self._check_telegram_account_observable_object(telegram.attributes, telegram_observable)
        self._populate_documentation(
            misp_object = json.loads(telegram.to_json()),
            observed_data = telegram_observed_data
        )

    def test_stix20_bundle_with_account_with_attachment_indicator_objects(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_account_with_attachment_indicator_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, facebook_i, github_i, parler_i, reddit_i, twitter_i, user_i = bundle.objects
        facebook, github, parler, reddit, twitter, user_account = self._check_misp_event_features(event, report)
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
        account_p, display_p, user_id_p, account_login, last_changed_p, groups1, groups2, gid, home_dir_p, password_p, *user_avatar_p = user_account_pattern[1:-1].split(' AND ')
        account_a, display_a, user_id_a, username, last_changed_a, group1, group2, group_id, home_dir_a, password_a, user_avatar = user_account.attributes
        self._check_user_account_indicator_object(
            (
                account_a, display_a, password_a, user_id_a, username, last_changed_a,
                group1, group2, group_id, home_dir_a, user_avatar
            ),
            (
                account_p, display_p, password_p, user_id_p, account_login, last_changed_p,
                groups1, groups2, gid, home_dir_p, *user_avatar_p
            )
        )
        self._populate_documentation(
            misp_object = json.loads(user_account.to_json()),
            indicator = user_i
        )

    def test_stix20_bundle_with_account_with_attachment_observable_objects(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_account_with_attachment_observable_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, facebook_od, github_od, parler_od, reddit_od, twitter_od, user_od = bundle.objects
        facebook, github, parler, reddit, twitter, user_account = self._check_misp_event_features(event, report)
        facebook_observable = self._check_observed_data_object(facebook, facebook_od)['0']
        self._check_facebook_account_observable_object(facebook.attributes, facebook_observable)
        self._populate_documentation(
            misp_object = json.loads(facebook.to_json()),
            observed_data = facebook_od
        )
        github_observable = self._check_observed_data_object(github, github_od)['0']
        self._check_github_user_observable_object(github.attributes, github_observable)
        self._populate_documentation(
            misp_object = json.loads(github.to_json()),
            observed_data = github_od
        )
        parler_observable = self._check_observed_data_object(parler, parler_od)['0']
        self._check_parler_account_observable_object(parler.attributes, parler_observable)
        self._populate_documentation(
            misp_object = json.loads(parler.to_json()),
            observed_data = parler_od
        )
        reddit_observable = self._check_observed_data_object(reddit, reddit_od)['0']
        self._check_reddit_account_observable_object(reddit.attributes, reddit_observable)
        self._populate_documentation(
            misp_object = json.loads(reddit.to_json()),
            observed_data = reddit_od
        )
        twitter_observable = self._check_observed_data_object(twitter, twitter_od)['0']
        self._check_twitter_account_observable_object(twitter.attributes, twitter_observable)
        self._populate_documentation(
            misp_object = json.loads(twitter.to_json()),
            observed_data = twitter_od
        )
        user_account_observable = self._check_observed_data_object(user_account, user_od)['0']
        password, last_changed = self._check_user_account_observable_object(
            user_account.attributes,
            user_account_observable
        )
        self.assertEqual(password.type, 'text')
        self.assertEqual(password.object_relation, 'password')
        self.assertEqual(password.value, user_account_observable.x_misp_password)
        self.assertEqual(last_changed.type, 'datetime')
        self.assertEqual(last_changed.object_relation, 'password_last_changed')
        self.assertEqual(last_changed.value, user_account_observable.password_last_changed)
        self._populate_documentation(
            misp_object = json.loads(user_account.to_json()),
            observed_data = user_od
        )

    def test_stix20_bundle_with_android_app_indicator_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_android_app_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        pattern = self._check_indicator_object(misp_object, indicator)
        self._check_android_app_indicator_object(misp_object.attributes, pattern)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_android_app_observable_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_android_app_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        observable = self._check_observed_data_object(misp_object, observed_data)['0']
        self._check_android_app_observable_object(misp_object.attributes, observable)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_asn_indicator_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_asn_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        pattern = self._check_indicator_object(misp_object, indicator)
        self._check_asn_indicator_object(misp_object.attributes, pattern)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_asn_observable_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_asn_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        observable = self._check_observed_data_object(misp_object, observed_data)['0']
        self._check_asn_observable_object(misp_object.attributes, observable)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_attack_pattern_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_attack_pattern_object()
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
        bundle = TestInternalSTIX20Bundles.get_bundle_with_course_of_action_object()
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

    def test_stix20_bundle_with_cpe_asset_indicator_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_cpe_asset_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        pattern = self._check_indicator_object(misp_object, indicator)
        self._check_cpe_asset_indicator_object(misp_object.attributes, pattern)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_cpe_asset_observable_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_cpe_asset_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        observable = self._check_observed_data_object(misp_object, observed_data)['0']
        self._check_cpe_asset_observable_object(misp_object.attributes, observable)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_credential_indicator_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_credential_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        pattern = self._check_indicator_object(misp_object, indicator)
        user_id, text_pattern, credential, *patterns = pattern[1:-1].split(' AND ')
        username, text, password, *attributes = misp_object.attributes
        self._check_credential_indicator_object(
            [username, password, text, *attributes],
            [user_id, credential, text_pattern, *patterns]
        )
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_credential_observable_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_credential_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        observable = self._check_observed_data_object(misp_object, observed_data)['0']
        password = self._check_credential_observable_object(
            misp_object.attributes,
            observable
        )
        self.assertEqual(password.type, 'text')
        self.assertEqual(password.object_relation, 'password')
        self.assertEqual(password.value, observable.x_misp_password)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_custom_objects(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_custom_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, *custom_objects = bundle.objects
        misp_objects = self._check_misp_event_features(event, report)
        for misp_object, custom_object in zip(misp_objects, custom_objects):
            self._check_custom_object(misp_object, custom_object)

    def test_stix20_bundle_with_domain_ip_indicator_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_domain_ip_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        pattern = self._check_indicator_object(misp_object, indicator)
        self._check_domain_ip_indicator_object(misp_object.attributes, pattern)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_domain_ip_observable_objects(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_domain_ip_observable_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, standard_observed_data, custom_observed_data = bundle.objects
        standard, custom = self._check_misp_event_features(event, report)
        standard_observables = self._check_observed_data_object(standard, standard_observed_data)
        domain1, ip1, ip2, domain2 = standard.attributes
        for attribute, index in zip((domain1, domain2), ('2', '3')):
            self.assertEqual(attribute.type,'domain')
            self.assertEqual(attribute.object_relation, 'domain')
            self.assertEqual(attribute.value, standard_observables[index].value)
        for attribute, index in zip((ip1, ip2), ('0', '1')):
            self.assertEqual(attribute.type, 'ip-dst')
            self.assertEqual(attribute.object_relation, 'ip')
            self.assertEqual(attribute.value, standard_observables[index].value)
        self._populate_documentation(
            misp_object = json.loads(standard.to_json()),
            observed_data = standard_observed_data,
            name = 'Domain-IP object (standard case)'
        )
        custom_observables = self._check_observed_data_object(custom, custom_observed_data)
        domain, hostname, port, ip = custom.attributes
        self.assertEqual(domain.type, 'domain')
        self.assertEqual(domain.object_relation, 'domain')
        self.assertEqual(domain.value, custom_observables['0'].value)
        self.assertEqual(hostname.type, 'hostname')
        self.assertEqual(hostname.object_relation, 'hostname')
        self.assertEqual(hostname.value, custom_observables['0'].x_misp_hostname)
        self.assertEqual(ip.type, 'ip-dst')
        self.assertEqual(ip.object_relation, 'ip')
        self.assertEqual(ip.value, custom_observables['1'].value)
        self.assertEqual(port.type, 'port')
        self.assertEqual(port.object_relation, 'port')
        self.assertEqual(port.value, custom_observables['0'].x_misp_port)
        self._populate_documentation(
            misp_object = json.loads(custom.to_json()),
            observed_data = custom_observed_data,
            name = 'Domain-IP object (custom case)'
        )

    def test_stix20_bundle_with_email_indicator_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_email_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        _to, to_dn, cc1, cc1_dn, cc2, cc2_dn, bcc, bcc_dn, _from, from_dn, reply_to, subject, x_mailer, user_agent, boundary, message_id, *attachments = misp_object.attributes
        email_pattern = self._get_parsed_email_pattern(self._check_indicator_object(misp_object, indicator))
        self._check_email_indicator_object(
            (
                _to, to_dn, cc1, cc1_dn, cc2, cc2_dn, bcc, bcc_dn, _from, from_dn,
                message_id, reply_to, subject, x_mailer, user_agent, boundary,
                *attachments
            ),
            email_pattern
        )
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_email_observable_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_email_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        email = self._check_misp_event_features(event, report)[0]
        observables = self._check_observed_data_object(email, observed_data)
        message_id = self._check_email_observable_object(
            email.attributes,
            observables
        )
        self.assertEqual(message_id.type, 'email-message-id')
        self.assertEqual(message_id.object_relation, 'message-id')
        self.assertEqual(message_id.value, observables['0'].x_misp_message_id)
        self._populate_documentation(
            misp_object = json.loads(email.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_employee_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_employee_object()
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

    def test_stix20_bundle_with_file_and_pe_indicator_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_file_and_pe_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        file_object, pe_object, section_object = self._check_misp_event_features(event, report)
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

    def test_stix20_bundle_with_file_and_pe_observable_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_file_and_pe_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        file_object, pe_object, section_object = self._check_misp_event_features(event, report)
        observable = self._check_observed_data_object(file_object, observed_data)['0']
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
            observed_data = observed_data,
            name = 'File object with a Windows PE binary extension',
            summary = 'File object with a Windows PE binary extension'
        )

    def test_stix20_bundle_with_file_indicator_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_file_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        pattern = self._get_parsed_file_pattern(self._check_indicator_object(misp_object, indicator))
        self._check_file_indicator_object(misp_object.attributes, pattern)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_file_observable_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_file_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        observables = self._check_observed_data_object(misp_object, observed_data)
        self._check_file_observable_object(misp_object.attributes, observables)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_http_request_indicator_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_http_request_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        pattern = self._check_indicator_object(misp_object, indicator)
        self._check_http_request_indicator_object(misp_object.attributes, pattern)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_http_request_observable_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_http_request_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        observables = self._check_observed_data_object(misp_object, observed_data)
        self._check_http_request_observable_object(misp_object.attributes, observables)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_image_indicator_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_image_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        pattern = self._check_indicator_object(misp_object, indicator)
        self._check_image_indicator_object(misp_object.attributes, pattern)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_image_observable_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_image_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        observables = self._check_observed_data_object(misp_object, observed_data)
        self._check_image_observable_object(misp_object.attributes, observables)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_ip_port_indicator_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_ip_port_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        pattern = self._check_indicator_object(misp_object, indicator)
        self._check_ip_port_indicator_object(misp_object.attributes, pattern)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_ip_port_observable_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_ip_port_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        observables = self._check_observed_data_object(misp_object, observed_data)
        self._check_ip_port_observable_object(misp_object.attributes, observables)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_legal_entity_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_legal_entity_object()
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

    def test_stix20_bundle_with_lnk_indicator_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_lnk_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        name, dir_ref, MD5, SHA1, SHA256, payload_bin, x_misp_filename, content_md5, _, size, ctime, mtime, atime = self._check_indicator_object(misp_object, indicator)[1:-1].split(' AND ')
        self._check_lnk_indicator_object(
            misp_object.attributes,
            (
                atime, ctime,  mtime, name, dir_ref, MD5, SHA1, SHA256, payload_bin,
                x_misp_filename, content_md5, size
            )
        )
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_lnk_observable_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_lnk_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        observables = self._check_observed_data_object(misp_object, observed_data)
        atime, ctime, mtime = self._check_lnk_observable_object(misp_object.attributes, observables)
        file_object = observed_data.objects['0']
        self.assertEqual(atime.type, 'datetime')
        self.assertEqual(atime.object_relation, 'lnk-access-time')
        self.assertEqual(atime.value, file_object.accessed)
        self.assertEqual(ctime.type, 'datetime')
        self.assertEqual(ctime.object_relation, 'lnk-creation-time')
        self.assertEqual(ctime.value, file_object.created)
        self.assertEqual(mtime.type, 'datetime')
        self.assertEqual(mtime.object_relation, 'lnk-modification-time')
        self.assertEqual(mtime.value, file_object.modified)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_mutex_indicator_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_mutex_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        pattern = self._check_indicator_object(misp_object, indicator)
        self._check_mutex_indicator_object(misp_object.attributes, pattern)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_mutex_observable_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_mutex_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        mutex = self._check_observed_data_object(misp_object, observed_data)['0']
        self._check_mutex_observable_object(misp_object.attributes, mutex)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_netflow_indicator_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_netflow_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        pattern = self._check_indicator_object(misp_object, indicator)
        self._check_netflow_indicator_object(misp_object.attributes, pattern)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_netflow_observable_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_netflow_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        observables = self._check_observed_data_object(misp_object, observed_data)
        self._check_netflow_observable_object(misp_object.attributes, observables)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_network_connection_indicator_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_network_connection_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        pattern = self._check_indicator_object(misp_object, indicator)
        self._check_network_connection_indicator_object(misp_object.attributes, pattern)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_network_connection_observable_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_network_connection_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        observables = self._check_observed_data_object(misp_object, observed_data)
        self._check_network_connection_observable_object(misp_object.attributes, observables)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_network_socket_indicator_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_network_socket_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        pattern = self._check_indicator_object(misp_object, indicator)
        _, src_ref, _, dst_ref, _, domain_ref, dst_port, src_port, protocols, addressFamily, protocolFamily, socketType, is_listening = pattern[1:-1].split(' AND ')
        ip_src, ip_dst, hostname, port_dst, port_src, protocol, address_family, domain_family, socket_type, listening = misp_object.attributes
        self._check_network_socket_indicator_object(
            (
                ip_src, ip_dst, hostname, port_dst, port_src, protocol, address_family,
                socket_type, listening, domain_family
            ),
            (
                src_ref, dst_ref, domain_ref, dst_port, src_port, protocols, addressFamily,
                socketType, is_listening, protocolFamily
            )
        )
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_network_socket_observable_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_network_socket_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        observables = self._check_observed_data_object(misp_object, observed_data)
        ip_src, ip_dst, port_dst, port_src, hostname, protocol, address_family, domain_family, socket_type, listening = misp_object.attributes
        self._check_network_socket_observable_object(
            (
                ip_src, ip_dst, port_dst, port_src, hostname, protocol, address_family,
                socket_type, listening
            ),
            observables
        )
        self.assertEqual(domain_family.type, 'text')
        self.assertEqual(domain_family.object_relation, 'domain-family')
        self.assertEqual(
            domain_family.value,
            observed_data.objects['0'].extensions['socket-ext'].protocol_family
        )
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_news_agency_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_news_agency_object()
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

    def test_stix20_bundle_with_object_references(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_object_references()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, *_ = bundle.objects
        attack_pattern, autonomous_system, btc, course_of_action, ip_port, vulnerability = self._check_misp_event_features(event, report)
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

    def test_stix20_bundle_with_organization_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_organization_object()
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

    def test_stix20_bundle_with_process_indicator_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_process_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        pattern = self._check_indicator_object(misp_object, indicator)
        self._check_process_indicator_object(misp_object.attributes, pattern[1:-1].split(' AND '))
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_process_observable_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_process_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        observables = self._check_observed_data_object(misp_object, observed_data)
        name, parent_process_name = self._check_process_observable_object(
            misp_object.attributes,
            observables
        )
        self.assertEqual(name.type, 'text')
        self.assertEqual(name.object_relation, 'name')
        self.assertEqual(name.value, observables['0'].name)
        self.assertEqual(parent_process_name.type, 'text')
        self.assertEqual(parent_process_name.object_relation, 'parent-process-name')
        self.assertEqual(parent_process_name.value, observables['1'].name)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_registry_key_indicator_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_registry_key_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        pattern = self._check_indicator_object(misp_object, indicator)
        self._check_registry_key_indicator_object(
            misp_object.attributes,
            pattern[1:-1].split(' AND ')
        )
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_registry_key_observable_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_registry_key_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        observable = self._check_observed_data_object(misp_object, observed_data)['0']
        modified_time = self._check_registry_key_observable_object(misp_object.attributes, observable)
        self.assertEqual(modified_time.type, 'datetime')
        self.assertEqual(modified_time.object_relation, 'last-modified')
        self.assertEqual(modified_time.value, observable.modified)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_script_objects(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_script_objects()
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

    def test_stix20_bundle_with_url_indicator_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_url_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        pattern = self._check_indicator_object(misp_object, indicator)
        self._check_url_indicator_object(misp_object.attributes, pattern)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_url_observable_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_url_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        url = self._check_observed_data_object(misp_object, observed_data)['0']
        self._check_url_observable_object(misp_object.attributes, url)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            observed_data = observed_data
        )

    def test_stix20_bundle_with_vulnerability_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_vulnerability_object()
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

    def test_stix20_bundle_with_x509_indicator_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_x509_indicator_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        pattern = self._check_indicator_object(misp_object, indicator)
        self._check_x509_indicator_object(misp_object.attributes, pattern)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            indicator = indicator
        )

    def test_stix20_bundle_with_x509_observable_object(self):
        bundle = TestInternalSTIX20Bundles.get_bundle_with_x509_observable_object()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        misp_object = self._check_misp_event_features(event, report)[0]
        x509 = self._check_observed_data_object(misp_object, observed_data)['0']
        self._check_x509_observable_object(misp_object.attributes, x509)
        self._populate_documentation(
            misp_object = json.loads(misp_object.to_json()),
            observed_data = observed_data
        )
