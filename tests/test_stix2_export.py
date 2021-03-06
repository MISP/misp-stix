#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import json
import os
import sys
from misp_stix_converter import MISPtoSTIX20Parser, MISPtoSTIX21Parser
from .test_events import *


class TestSTIX2Export(unittest.TestCase):
    _labels = [
        'Threat-Report',
        'misp:tool="MISP-STIX-Converter"'
    ]

    @staticmethod
    def _add_attribute_ids_flag(event):
        for attribute in event['Event']['Attribute']:
            attribute['to_ids'] = True

    def _check_identity_features(self, identity, orgc):
        identity_id = f"identity--{orgc['uuid']}"
        self.assertEqual(identity.type, 'identity')
        self.assertEqual(identity.id, identity_id)
        self.assertEqual(identity.name, orgc['name'])
        self.assertEqual(identity.identity_class, 'organization')
        return identity_id

    def _check_attribute_campaign_features(self, campaign, attribute, identity_id, object_ref):
        uuid = f"campaign--{attribute['uuid']}"
        self.assertEqual(uuid, object_ref)
        self.assertEqual(campaign.id, uuid)
        self.assertEqual(campaign.type, 'campaign')
        self.assertEqual(campaign.created_by_ref, identity_id)
        self._check_attribute_labels(attribute, campaign.labels)
        timestamp = self._datetime_from_timestamp(attribute['timestamp'])
        self.assertEqual(campaign.created, timestamp)
        self.assertEqual(campaign.modified, timestamp)

    def _check_attribute_indicator_features(self, indicator, attribute, identity_id, object_ref):
        uuid = f"indicator--{attribute['uuid']}"
        self.assertEqual(uuid, object_ref)
        self.assertEqual(indicator.id, uuid)
        self.assertEqual(indicator.type, 'indicator')
        self.assertEqual(indicator.created_by_ref, identity_id)
        self._check_killchain(indicator.kill_chain_phases[0], attribute['category'])
        self._check_attribute_labels(attribute, indicator.labels)
        timestamp = self._datetime_from_timestamp(attribute['timestamp'])
        self.assertEqual(indicator.created, timestamp)
        self.assertEqual(indicator.modified, timestamp)
        self.assertEqual(indicator.valid_from, timestamp)

    def _check_attribute_labels(self, attribute, labels):
        if attribute.get('to_ids'):
            type_label, category_label, ids_label = labels
            self.assertEqual(ids_label, f'misp:to_ids="{attribute["to_ids"]}"')
        else:
            type_label, category_label = labels
        self.assertEqual(type_label, f'misp:type="{attribute["type"]}"')
        self.assertEqual(category_label, f'misp:category="{attribute["category"]}"')

    def _check_attribute_vulnerability_features(self, vulnerability, attribute, identity_id, object_ref):
        uuid = f"vulnerability--{attribute['uuid']}"
        self.assertEqual(uuid, object_ref)
        self.assertEqual(vulnerability.id, uuid)
        self.assertEqual(vulnerability.type, 'vulnerability')
        self.assertEqual(vulnerability.created_by_ref, identity_id)
        self._check_attribute_labels(attribute, vulnerability.labels)
        timestamp = self._datetime_from_timestamp(attribute['timestamp'])
        self.assertEqual(vulnerability.created, timestamp)
        self.assertEqual(vulnerability.modified, timestamp)

    def _check_killchain(self, killchain, category):
        self.assertEqual(killchain['kill_chain_name'], 'misp-category')
        self.assertEqual(killchain['phase_name'], category)

    def _check_attribute_observable_features(self, observed_data, attribute, identity_id, object_ref):
        uuid = f"observed-data--{attribute['uuid']}"
        self.assertEqual(uuid, object_ref)
        self.assertEqual(observed_data.id, uuid)
        self.assertEqual(observed_data.type, 'observed-data')
        self.assertEqual(observed_data.created_by_ref, identity_id)
        self.assertEqual(observed_data.number_observed, 1)
        type_label, category_label = observed_data.labels
        self.assertEqual(type_label, f'misp:type="{attribute["type"]}"')
        self.assertEqual(category_label, f'misp:category="{attribute["category"]}"')
        timestamp = self._datetime_from_timestamp(attribute['timestamp'])
        self.assertEqual(observed_data.created, timestamp)
        self.assertEqual(observed_data.modified, timestamp)
        self.assertEqual(observed_data.first_observed, timestamp)
        self.assertEqual(observed_data.last_observed, timestamp)

    def _check_report_features(self, report, event, identity_id, timestamp):
        self.assertEqual(report.type, 'report')
        self.assertEqual(report.id, f"report--{event['uuid']}")
        self.assertEqual(report.created_by_ref, identity_id)
        self.assertEqual(report.labels, self._labels)
        self.assertEqual(report.name, event['info'])
        self.assertEqual(report.created, timestamp)
        self.assertEqual(report.modified, timestamp)
        return report.object_refs

    @staticmethod
    def _datetime_from_timestamp(timestamp):
        return datetime.utcfromtimestamp(int(timestamp))

    @staticmethod
    def _parse_AS_value(value):
        if value.startswith('AS'):
            return int(value[2:])
        return int(value)

    @staticmethod
    def _remove_attribute_ids_flag(event):
        for attribute in event['Event']['Attribute']:
            attribute['to_ids'] = False


class TestSTIX20Export(TestSTIX2Export):
    def setUp(self):
        self.parser = MISPtoSTIX20Parser()

    def _run_indicator_tests(self, event):
        self._add_attribute_ids_flag(event)
        orgc = event['Event']['Orgc']
        attribute = event['Event']['Attribute'][0]
        self.parser.parse_misp_event(event)
        identity, report, indicator = self.parser.stix_objects
        identity_id = self._check_identity_features(identity, orgc)
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        object_ref = self._check_report_features(report, event['Event'], identity_id, timestamp)[0]
        self.assertEqual(report.published, timestamp)
        self._check_attribute_indicator_features(indicator, attribute, identity_id, object_ref)
        return attribute['value'], indicator.pattern

    def _run_indicators_tests(self, event):
        self._add_attribute_ids_flag(event)
        orgc = event['Event']['Orgc']
        attributes = event['Event']['Attribute']
        self.parser.parse_misp_event(event)
        identity, report, *indicators = self.parser.stix_objects
        identity_id = self._check_identity_features(identity, orgc)
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        object_refs = self._check_report_features(report, event['Event'], identity_id, timestamp)
        self.assertEqual(report.published, timestamp)
        for attribute, indicator, object_ref in zip(attributes, indicators, object_refs):
            self._check_attribute_indicator_features(indicator, attribute, identity_id, object_ref)
        attribute_values = (attribute['value'] for attribute in attributes)
        patterns = (indicator.pattern for indicator in indicators)
        return attribute_values, patterns

    def _run_observable_tests(self, event):
        self._remove_attribute_ids_flag(event)
        orgc = event['Event']['Orgc']
        attribute = event['Event']['Attribute'][0]
        self.parser.parse_misp_event(event)
        identity, report, observed_data = self.parser.stix_objects
        identity_id = self._check_identity_features(identity, orgc)
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        args = (
            report,
            event['Event'],
            identity_id,
            timestamp
        )
        object_ref = self._check_report_features(*args)[0]
        self.assertEqual(report.published, timestamp)
        self._check_attribute_observable_features(
            observed_data,
            attribute,
            identity_id,
            object_ref
        )
        return attribute['value'], observed_data['objects']

    def _run_observables_tests(self, event):
        self._remove_attribute_ids_flag(event)
        orgc = event['Event']['Orgc']
        attributes = event['Event']['Attribute']
        self.parser.parse_misp_event(event)
        identity, report, *observed_datas = self.parser.stix_objects
        identity_id = self._check_identity_features(identity, orgc)
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        args = (
            report,
            event['Event'],
            identity_id,
            timestamp
        )
        object_refs = self._check_report_features(*args)
        self.assertEqual(report.published, timestamp)
        for attribute, observed_data, object_ref in zip(attributes, observed_datas, object_refs):
            self._check_attribute_observable_features(
                observed_data,
                attribute,
                identity_id,
                object_ref
            )
        attribute_values = tuple(attribute['value'] for attribute in attributes)
        observable_objects = tuple(observed_data['objects'] for observed_data in observed_datas)
        return attribute_values, observable_objects

    def test_event_with_as_indicator_attribute(self):
        event = get_event_with_as_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        number = self._parse_AS_value(attribute_value)
        self.assertEqual(pattern, f"[autonomous-system:number = '{number}']")

    def test_event_with_as_observable_attribute(self):
        event = get_event_with_as_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        observable = observable_objects['0']
        self.assertEqual(observable.type, 'autonomous-system')
        number = self._parse_AS_value(attribute_value)
        self.assertEqual(observable.number, number)

    def test_event_with_attachment_indicator_attribute(self):
        event = get_event_with_attachment_attribute()
        data = event['Event']['Attribute'][0]['data']
        attribute_value, pattern = self._run_indicator_tests(event)
        file_pattern = f"file:name = '{attribute_value}'"
        data_pattern = f"file:content_ref.payload_bin = '{data}'"
        self.assertEqual(pattern, f"[{file_pattern} AND {data_pattern}]")

    def test_event_with_attachment_observable_attribute(self):
        event = get_event_with_attachment_attribute()
        data = event['Event']['Attribute'][0]['data']
        attribute_value, observable_objects = self._run_observable_tests(event)
        file_object, artifact_object = observable_objects.values()
        self.assertEqual(file_object.type, 'file')
        self.assertEqual(file_object.name, attribute_value)
        self.assertEqual(file_object.content_ref, '1')
        self.assertEqual(artifact_object.type, 'artifact')
        self.assertEqual(artifact_object.payload_bin, data)

    def test_event_with_campaign_name_attribute(self):
        event = get_event_with_campaign_name_attribute()
        self._remove_attribute_ids_flag(event)
        orgc = event['Event']['Orgc']
        attribute = event['Event']['Attribute'][0]
        self.parser.parse_misp_event(event)
        identity, report, campaign = self.parser.stix_objects
        identity_id = self._check_identity_features(identity, orgc)
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        object_ref = self._check_report_features(report, event['Event'], identity_id, timestamp)[0]
        self.assertEqual(report.published, timestamp)
        self._check_attribute_campaign_features(
            campaign,
            attribute,
            identity_id,
            object_ref
        )
        self.assertEqual(campaign.name, attribute['value'])

    def test_event_with_domain_indicator_attribute(self):
        event = get_event_with_domain_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[domain-name:value = '{attribute_value}']")

    def test_event_with_domain_observable_attribute(self):
        event = get_event_with_domain_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        observable = observable_objects['0']
        self.assertEqual(observable.type, 'domain-name')
        self.assertEqual(observable.value, attribute_value)

    def test_event_with_domain_ip_indicator_attribute(self):
        event = get_event_with_domain_ip_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        domain, ip = attribute_value.split('|')
        domain_pattern = f"domain-name:value = '{domain}'"
        ip_pattern = f"domain-name:resolves_to_refs[*].value = '{ip}'"
        self.assertEqual(pattern, f'[{domain_pattern} AND {ip_pattern}]')

    def test_event_with_domain_ip_observable_attribute(self):
        event = get_event_with_domain_ip_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        domain, ip = attribute_value.split('|')
        domain_object, address_object = observable_objects.values()
        self.assertEqual(domain_object.type, 'domain-name')
        self.assertEqual(domain_object.value, domain)
        self.assertEqual(domain_object.resolves_to_refs, ['1'])
        self.assertEqual(address_object.type, 'ipv4-addr')
        self.assertEqual(address_object.value, ip)

    def test_event_with_email_attachment_indicator_attribute(self):
        event = get_event_with_email_attachment_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(
            pattern,
            f"[email-message:body_multipart[*].body_raw_ref.name = '{attribute_value}']"
        )

    def test_event_with_email_attachment_observable_attribute(self):
        event = get_event_with_email_attachment_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        email_object, file_object = observable_objects.values()
        self.assertEqual(email_object.type, 'email-message')
        self.assertEqual(email_object.is_multipart, True)
        body = email_object.body_multipart[0]
        self.assertEqual(body.content_disposition, f"attachment; filename='{attribute_value}'")
        self.assertEqual(body.body_raw_ref, '1')
        self.assertEqual(file_object.type, 'file')
        self.assertEqual(file_object.name, attribute_value)

    def test_event_with_email_body_indicator_attribute(self):
        event = get_event_with_email_body_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(
            pattern,
            f"[email-message:body = '{attribute_value}']"
        )

    def test_event_with_email_body_observable_attribute(self):
        event = get_event_with_email_body_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        email_object = observable_objects['0']
        self.assertEqual(email_object.type, 'email-message')
        self.assertEqual(email_object.is_multipart, False)
        self.assertEqual(email_object.body, attribute_value)

    def test_event_with_email_destination_indicator_attribute(self):
        event = get_event_with_email_destination_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[email-message:to_refs[*].value = '{attribute_value}']")

    def test_event_with_email_destination_observable_attribute(self):
        event = get_event_with_email_destination_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        message, address = observable_objects.values()
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.to_refs, ['1'])
        self.assertEqual(address.type, 'email-addr')
        self.assertEqual(address.value, attribute_value)

    def test_event_with_email_header_indicator_attribute(self):
        event = get_event_with_email_header_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[email-message:received_lines = '{attribute_value}']")

    def test_event_with_email_header_observable_attribute(self):
        event = get_event_with_email_header_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        message_object = observable_objects['0']
        self.assertEqual(message_object.type, 'email-message')
        self.assertEqual(message_object.is_multipart, False)
        self.assertEqual(message_object.received_lines, [attribute_value])

    def test_event_with_email_indicator_attribute(self):
        event = get_event_with_email_address_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[email-addr:value = '{attribute_value}']")

    def test_event_with_email_observable_attribute(self):
        event = get_event_with_email_address_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        address_object = observable_objects['0']
        self.assertEqual(address_object.type, 'email-addr')
        self.assertEqual(address_object.value, attribute_value)

    def test_event_with_email_reply_to_indicator_attribute(self):
        event = get_event_with_email_reply_to_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(
            pattern,
            f"[email-message:additional_header_fields.reply_to = '{attribute_value}']"
        )

    def test_event_with_email_reply_to_observable_attribute(self):
        event = get_event_with_email_reply_to_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        message = observable_objects['0']
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.additional_header_fields['Reply-To'][0], attribute_value)

    def test_event_with_email_source_indicator_attribute(self):
        event = get_event_with_email_source_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[email-message:from_ref.value = '{attribute_value}']")

    def test_event_with_email_source_observable_attribute(self):
        event = get_event_with_email_source_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        message, address = observable_objects.values()
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.from_ref, '1')
        self.assertEqual(address.type, 'email-addr')
        self.assertEqual(address.value, attribute_value)

    def test_event_with_email_subject_indicator_attribute(self):
        event = get_event_with_email_subject_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[email-message:subject = '{attribute_value}']")

    def test_event_with_email_subject_observable_attribute(self):
        event = get_event_with_email_subject_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        message = observable_objects['0']
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.subject, attribute_value)

    def test_event_with_email_x_mailer_indicator_attribute(self):
        event = get_event_with_email_x_mailer_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(
            pattern,
            f"[email-message:additional_header_fields.x_mailer = '{attribute_value}']"
        )

    def test_event_with_email_x_mailer__attribute(self):
        event = get_event_with_email_x_mailer_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        message = observable_objects['0']
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.additional_header_fields['X-Mailer'], attribute_value)

    def test_event_with_filename_indicator_attribute(self):
        event = get_event_with_filename_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[file:name = '{attribute_value}']")

    def test_event_with_filename_observable_attribute(self):
        event = get_event_with_filename_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        observable = observable_objects['0']
        self.assertEqual(observable.type, 'file')
        self.assertEqual(observable.name, attribute_value)

    def test_event_with_hash_composite_indicator_attributes(self):
        event = get_event_with_hash_composite_attributes(
            ('md5', 'sha1', 'sha512/256', 'sha3-256'),
            (
                'filename1|b2a5abfeef9e36964281a31e17b57c97',
                'filename2|2920d5e6c579fce772e5506caf03af65579088bd',
                'filename3|82333533f7f7cb4123bceee76358b36d4110e03c2219b80dced5a4d63424cc93',
                'filename4|39725234628358bcce613d1d1c07c2c3d2d106e3a6ac192016b46e5dddcd03f4'
            ),
            (
                '91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f',
                '518b4bcb-a86b-4783-9457-391d548b605b',
                '34cb1a7c-55ec-412a-8684-ba4a88d83a45',
                '94a2b00f-bec3-4f8a-bea4-e4ccf0de776f'
            )
        )
        attribute_values, patterns = self._run_indicators_tests(event)
        hash_types = ('MD5', 'SHA1', 'SHA256', 'SHA3256')
        for attribute_value, pattern, hash_type in zip(attribute_values, patterns, hash_types):
            filename, hash_value = attribute_value.split('|')
            filename_pattern = f"file:name = '{filename}'"
            hash_pattern = f"file:hashes.{hash_type} = '{hash_value}'"
            self.assertEqual(pattern, f"[{filename_pattern} AND {hash_pattern}]")

    def test_event_with_hash_composite_observable_attributes(self):
        event = get_event_with_hash_composite_attributes(
            ('md5', 'sha1', 'sha512/256', 'sha3-256'),
            (
                'filename1|b2a5abfeef9e36964281a31e17b57c97',
                'filename2|2920d5e6c579fce772e5506caf03af65579088bd',
                'filename3|82333533f7f7cb4123bceee76358b36d4110e03c2219b80dced5a4d63424cc93',
                'filename4|39725234628358bcce613d1d1c07c2c3d2d106e3a6ac192016b46e5dddcd03f4'
            ),
            (
                '91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f',
                '518b4bcb-a86b-4783-9457-391d548b605b',
                '34cb1a7c-55ec-412a-8684-ba4a88d83a45',
                '94a2b00f-bec3-4f8a-bea4-e4ccf0de776f'
            )
        )
        attribute_values, observable_objects = self._run_observables_tests(event)
        hash_types = ('MD5', 'SHA-1', 'SHA-256', 'SHA3-256')
        for attribute_value, observable_object, hash_type in zip(attribute_values, observable_objects, hash_types):
            filename, hash_value = attribute_value.split('|')
            self.assertEqual(observable_object['0'].type, 'file')
            self.assertEqual(observable_object['0'].name, filename)
            self.assertEqual(observable_object['0'].hashes[hash_type], hash_value)

    def test_event_with_hash_indicator_attributes(self):
        event = get_event_with_hash_attributes(
            ('md5', 'sha1', 'sha512/256', 'sha3-256'),
            (
                'b2a5abfeef9e36964281a31e17b57c97',
                '2920d5e6c579fce772e5506caf03af65579088bd',
                '82333533f7f7cb4123bceee76358b36d4110e03c2219b80dced5a4d63424cc93',
                '39725234628358bcce613d1d1c07c2c3d2d106e3a6ac192016b46e5dddcd03f4'
            ),
            (
                '91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f',
                '518b4bcb-a86b-4783-9457-391d548b605b',
                '34cb1a7c-55ec-412a-8684-ba4a88d83a45',
                '94a2b00f-bec3-4f8a-bea4-e4ccf0de776f'
            )
        )
        attribute_values, patterns = self._run_indicators_tests(event)
        md5, sha1, sha2, sha3 = attribute_values
        md5_pattern, sha1_pattern, sha2_pattern, sha3_pattern = patterns
        self.assertEqual(md5_pattern, f"[file:hashes.MD5 = '{md5}']")
        self.assertEqual(sha1_pattern, f"[file:hashes.SHA1 = '{sha1}']")
        self.assertEqual(sha2_pattern, f"[file:hashes.SHA256 = '{sha2}']")
        self.assertEqual(sha3_pattern, f"[file:hashes.SHA3256 = '{sha3}']")

    def test_event_with_hash_observable_attributes(self):
        event = get_event_with_hash_attributes(
            ('md5', 'sha1', 'sha512/256', 'sha3-256'),
            (
                'b2a5abfeef9e36964281a31e17b57c97',
                '2920d5e6c579fce772e5506caf03af65579088bd',
                '82333533f7f7cb4123bceee76358b36d4110e03c2219b80dced5a4d63424cc93',
                '39725234628358bcce613d1d1c07c2c3d2d106e3a6ac192016b46e5dddcd03f4'
            ),
            (
                '91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f',
                '518b4bcb-a86b-4783-9457-391d548b605b',
                '34cb1a7c-55ec-412a-8684-ba4a88d83a45',
                '94a2b00f-bec3-4f8a-bea4-e4ccf0de776f'
            )
        )
        attribute_values, observable_objects = self._run_observables_tests(event)
        md5, sha1, sha2, sha3 = attribute_values
        md5_object, sha1_object, sha2_object, sha3_object = observable_objects
        hash_types = ('MD5', 'SHA-1', 'SHA-256', 'SHA3-256')
        for attribute_value, observable_object, hash_type in zip(attribute_values, observable_objects, hash_types):
            self.assertEqual(observable_object['0'].type, 'file')
            self.assertEqual(observable_object['0'].hashes[hash_type], attribute_value)

    def test_event_with_hostname_indicator_attribute(self):
        event = get_event_with_hostname_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[domain-name:value = '{attribute_value}']")

    def test_event_with_hostname_observable_attribute(self):
        event = get_event_with_hostname_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        observable = observable_objects['0']
        self.assertEqual(observable.type, 'domain-name')
        self.assertEqual(observable.value, attribute_value)

    def test_event_with_hostname_port_indicator_attribute(self):
        event = get_event_with_hostname_port_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        hostname, port = attribute_value.split('|')
        hostname_pattern = f"domain-name:value = '{hostname}'"
        port_pattern = f"network-traffic:dst_port = '{port}'"
        self.assertEqual(pattern, f"[{hostname_pattern} AND {port_pattern}]")

    def test_event_with_hostname_port_observable_attribute(self):
        event = get_event_with_hostname_port_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        hostname, port = attribute_value.split('|')
        domain_object, network_traffic_object = observable_objects.values()
        self.assertEqual(domain_object.type, 'domain-name')
        self.assertEqual(domain_object.value, hostname)
        self.assertEqual(network_traffic_object.type, 'network-traffic')
        self.assertEqual(network_traffic_object.dst_port, int(port))
        self.assertEqual(network_traffic_object.dst_ref, '0')

    def test_event_with_http_indicator_attributes(self):
        event = get_event_with_http_attributes()
        attribute_values, patterns = self._run_indicators_tests(event)
        http_method, user_agent = attribute_values
        http_method_pattern, user_agent_pattern = patterns
        prefix = f"network-traffic:extensions.'http-request-ext'"
        self.assertEqual(
            http_method_pattern,
            f"[{prefix}.request_method = '{http_method}']"
        )
        self.assertEqual(
            user_agent_pattern,
            f"[{prefix}.request_header.'User-Agent' = '{user_agent}']"
        )

    def test_event_with_ip_indicator_attributes(self):
        event = get_event_with_ip_attributes()
        attribute_values, patterns = self._run_indicators_tests(event)
        src, dst = attribute_values
        src_pattern, dst_pattern = patterns
        src_type_pattern = "network-traffic:src_ref.type = 'ipv4-addr'"
        src_value_pattern = f"network-traffic:src_ref.value = '{src}'"
        self.assertEqual(src_pattern, f"[{src_type_pattern} AND {src_value_pattern}]")
        dst_type_pattern = "network-traffic:dst_ref.type = 'ipv4-addr'"
        dst_value_pattern = f"network-traffic:dst_ref.value = '{dst}'"
        self.assertEqual(dst_pattern, f"[{dst_type_pattern} AND {dst_value_pattern}]")

    def test_event_with_ip_observable_attributes(self):
        event = get_event_with_ip_attributes()
        attribute_values, observable_objects = self._run_observables_tests(event)
        src, dst = attribute_values
        src_object, dst_object = observable_objects
        src_network, src_address = src_object.values()
        self.assertEqual(src_network.type, 'network-traffic')
        self.assertEqual(src_network.src_ref, '1')
        self.assertEqual(src_address.type, 'ipv4-addr')
        self.assertEqual(src_address.value, src)
        dst_network, dst_address = dst_object.values()
        self.assertEqual(dst_network.type, 'network-traffic')
        self.assertEqual(dst_network.dst_ref, '1')
        self.assertEqual(dst_address.type, 'ipv4-addr')
        self.assertEqual(dst_address.value, dst)

    def test_event_with_ip_port_indicator_attributes(self):
        event = get_event_with_ip_port_attributes()
        attribute_values, patterns = self._run_indicators_tests(event)
        src, dst = attribute_values
        src_ip_value, src_port_value = src.split('|')
        dst_ip_value, dst_port_value = dst.split('|')
        src_pattern, dst_pattern = patterns
        src_type_pattern = "network-traffic:src_ref.type = 'ipv4-addr'"
        src_value_pattern = f"network-traffic:src_ref.value = '{src_ip_value}'"
        src_port_pattern = f"network-traffic:src_port = '{src_port_value}'"
        self.assertEqual(
            src_pattern,
            f"[{src_type_pattern} AND {src_value_pattern} AND {src_port_pattern}]"
        )
        dst_type_pattern = "network-traffic:dst_ref.type = 'ipv4-addr'"
        dst_value_pattern = f"network-traffic:dst_ref.value = '{dst_ip_value}'"
        dst_port_pattern = f"network-traffic:dst_port = '{dst_port_value}'"
        self.assertEqual(
            dst_pattern,
            f"[{dst_type_pattern} AND {dst_value_pattern} AND {dst_port_pattern}]"
        )

    def test_event_with_ip_port_observable_attributes(self):
        event = get_event_with_ip_port_attributes()
        attribute_values, observable_objects = self._run_observables_tests(event)
        src, dst = attribute_values
        src_ip_value, src_port_value = src.split('|')
        dst_ip_value, dst_port_value = dst.split('|')
        src_object, dst_object = observable_objects
        src_network, src_address = src_object.values()
        self.assertEqual(src_network.type, 'network-traffic')
        self.assertEqual(src_network.src_ref, '1')
        self.assertEqual(src_network.src_port, int(src_port_value))
        self.assertEqual(src_address.type, 'ipv4-addr')
        self.assertEqual(src_address.value, src_ip_value)
        dst_network, dst_address = dst_object.values()
        self.assertEqual(dst_network.type, 'network-traffic')
        self.assertEqual(dst_network.dst_ref, '1')
        self.assertEqual(dst_network.dst_port, int(dst_port_value))
        self.assertEqual(dst_address.type, 'ipv4-addr')
        self.assertEqual(dst_address.value, dst_ip_value)

    def test_event_with_mac_address_indicator_attribute(self):
        event = get_event_with_mac_address_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[mac-addr:value = '{attribute_value}']")

    def test_event_with_mac_address_observable_attribute(self):
        event = get_event_with_mac_address_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        observable = observable_objects['0']
        self.assertEqual(observable.type, 'mac-addr')
        self.assertEqual(observable.value, attribute_value)

    def test_event_with_mutex_indicator_attribute(self):
        event = get_event_with_mutex_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[mutex:name = '{attribute_value}']")

    def test_event_with_mutex_observable_attribute(self):
        event = get_event_with_mutex_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        observable = observable_objects['0']
        self.assertEqual(observable.type, 'mutex')
        self.assertEqual(observable.name, attribute_value)

    def test_event_with_port_indicator_attribute(self):
        event = get_event_with_port_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[network-traffic:dst_port = '{attribute_value}']")

    def test_event_with_regkey_indicator_attribute(self):
        event = get_event_with_regkey_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(
            pattern.replace('\\\\', '\\'),
            f"[windows-registry-key:key = '{attribute_value.strip()}']"
        )

    def test_event_with_regkey_observable_attribute(self):
        event = get_event_with_regkey_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        observable = observable_objects['0']
        self.assertEqual(observable.type, 'windows-registry-key')
        self.assertEqual(observable.key, attribute_value.strip())

    def test_event_with_regkey_value_indicator_attribute(self):
        event = get_event_with_regkey_value_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        key, value = attribute_value.split('|')
        key_pattern = f"windows-registry-key:key = '{key.strip()}'"
        value_pattern = f"windows-registry-key:values.data = '{value.strip()}'"
        self.assertEqual(
            pattern.replace('\\\\', '\\'),
            f"[{key_pattern} AND {value_pattern}]"
        )

    def test_event_with_regkey_value_observable_attribute(self):
        event = get_event_with_regkey_value_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        key, value = attribute_value.split('|')
        observable = observable_objects['0']
        self.assertEqual(observable.type, 'windows-registry-key')
        self.assertEqual(observable.key, key.strip())
        self.assertEqual(observable['values'][0].data, value.strip())

    def test_event_with_size_in_bytes_indicator_attribute(self):
        event = get_event_with_size_in_bytes_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[file:size = '{attribute_value}']")

    def test_event_with_url_indicator_attribute(self):
        event = get_event_with_url_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[url:value = '{attribute_value}']")

    def test_event_with_url_observable_attribute(self):
        event = get_event_with_url_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        observable = observable_objects['0']
        self.assertEqual(observable.type, 'url')
        self.assertEqual(observable.value, attribute_value)

    def test_event_with_vulnerability_attribute(self):
        event = get_event_with_vulnerability_attribute()
        self._add_attribute_ids_flag(event)
        orgc = event['Event']['Orgc']
        attribute = event['Event']['Attribute'][0]
        self.parser.parse_misp_event(event)
        identity, report, vulnerability = self.parser.stix_objects
        identity_id = self._check_identity_features(identity, orgc)
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        object_ref = self._check_report_features(report, event['Event'], identity_id, timestamp)[0]
        self.assertEqual(report.published, timestamp)
        self._check_attribute_vulnerability_features(
            vulnerability,
            attribute,
            identity_id,
            object_ref
        )
        self.assertEqual(vulnerability.name, attribute['value'])
        external_reference = vulnerability.external_references[0]
        self.assertEqual(external_reference.source_name, 'cve')
        self.assertEqual(external_reference.external_id, attribute['value'])

    def test_event_with_x509_fingerprint_indicator_attributes(self):
        event = get_event_with_x509_fingerprint_attributes()
        attribute_values, patterns = self._run_indicators_tests(event)
        md5, sha1, sha256 = attribute_values
        md5_pattern, sha1_pattern, sha256_pattern = patterns
        self.assertEqual(md5_pattern, f"[x509-certificate:hashes.MD5 = '{md5}']")
        self.assertEqual(sha1_pattern, f"[x509-certificate:hashes.SHA1 = '{sha1}']")
        self.assertEqual(sha256_pattern, f"[x509-certificate:hashes.SHA256 = '{sha256}']")

    def test_event_with_x509_fingerprint_observable_attributes(self):
        event = get_event_with_x509_fingerprint_attributes()
        attribute_values, observable_objects = self._run_observables_tests(event)
        hash_types = ('MD5', 'SHA-1', 'SHA-256')
        for attribute_value, observable_object, hash_type in zip(attribute_values, observable_objects, hash_types):
            self.assertEqual(observable_object['0'].type, 'x509-certificate')
            self.assertEqual(observable_object['0'].hashes[hash_type], attribute_value)


class TestSTIX21Export(TestSTIX2Export):
    def setUp(self):
        self.parser = MISPtoSTIX21Parser()

    def _check_grouping_features(self, grouping, event, identity_id):
        timestamp = self._datetime_from_timestamp(event['timestamp'])
        self.assertEqual(grouping.type, 'grouping')
        self.assertEqual(grouping.id, f"grouping--{event['uuid']}")
        self.assertEqual(grouping.created_by_ref, identity_id)
        self.assertEqual(grouping.labels, self._labels)
        self.assertEqual(grouping.name, event['info'])
        self.assertEqual(grouping.created, timestamp)
        self.assertEqual(grouping.modified, timestamp)
        return grouping.object_refs

    def _check_pattern_features(self, indicator):
        self.assertEqual(indicator.pattern_type, 'stix')
        self.assertEqual(indicator.pattern_version, '2.1')

    def _check_spec_versions(self, stix_objects):
        for stix_object in stix_objects:
            self.assertEqual(stix_object.spec_version, '2.1')

    def _run_indicator_tests(self, event):
        self._add_attribute_ids_flag(event)
        orgc = event['Event']['Orgc']
        attribute = event['Event']['Attribute'][0]
        self.parser.parse_misp_event(event)
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, indicator = stix_objects
        identity_id = self._check_identity_features(identity, orgc)
        args = (
            grouping,
            event['Event'],
            identity_id
        )
        object_ref = self._check_grouping_features(*args)[0]
        self._check_attribute_indicator_features(indicator, attribute, identity_id, object_ref)
        self._check_pattern_features(indicator)
        return attribute['value'], indicator.pattern

    def _run_indicators_tests(self, event):
        self._add_attribute_ids_flag(event)
        orgc = event['Event']['Orgc']
        attributes = event['Event']['Attribute']
        self.parser.parse_misp_event(event)
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, *indicators = stix_objects
        identity_id = self._check_identity_features(identity, orgc)
        args = (
            grouping,
            event['Event'],
            identity_id
        )
        object_refs = self._check_grouping_features(*args)
        for attribute, indicator, object_ref in zip(attributes, indicators, object_refs):
            self._check_attribute_indicator_features(indicator, attribute, identity_id, object_ref)
            self._check_pattern_features(indicator)
        attribute_values = (attribute['value'] for attribute in attributes)
        patterns = (indicator.pattern for indicator in indicators)
        return attribute_values, patterns

    def _run_observable_tests(self, event):
        self._remove_attribute_ids_flag(event)
        orgc = event['Event']['Orgc']
        attribute = event['Event']['Attribute'][0]
        self.parser.parse_misp_event(event)
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, observed_data, *observable = stix_objects
        identity_id = self._check_identity_features(identity, orgc)
        observable_id, *ids = self._check_grouping_features(
            grouping,
            event['Event'],
            identity_id
        )
        self._check_attribute_observable_features(observed_data, attribute, identity_id, observable_id)
        return attribute['value'], ids, observed_data['object_refs'], observable

    def _run_observables_tests(self, event, index=2):
        self._remove_attribute_ids_flag(event)
        orgc = event['Event']['Orgc']
        attributes = event['Event']['Attribute']
        self.parser.parse_misp_event(event)
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, *observables = stix_objects
        observed_datas = observables[::index]
        observables = [value for count, value in enumerate(observables) if count % index != 0]
        identity_id = self._check_identity_features(identity, orgc)
        ids = self._check_grouping_features(
            grouping,
            event['Event'],
            identity_id
        )
        observable_ids = ids[::index]
        object_ids = [value for count, value in enumerate(ids) if count % index != 0]
        for attribute, observed_data, observable_id in zip(attributes, observed_datas, observable_ids):
            self._check_attribute_observable_features(
                observed_data,
                attribute,
                identity_id,
                observable_id
            )
        attribute_values = tuple(attribute['value'] for attribute in attributes)
        object_refs = tuple(observed_data['object_refs'][0] for observed_data in observed_datas)
        return attribute_values, object_ids, object_refs, observables

    def test_event_with_as_indicator_attribute(self):
        event = get_event_with_as_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        number = self._parse_AS_value(attribute_value)
        self.assertEqual(pattern, f"[autonomous-system:number = '{number}']")

    def test_event_with_as_observable_attribute(self):
        event = get_event_with_as_attribute()
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        object_ref = object_refs[0]
        AS = observable[0]
        self.assertEqual(object_ref, grouping_refs[0])
        self.assertEqual(AS.id, object_ref)
        self.assertEqual(AS.type, 'autonomous-system')
        number = self._parse_AS_value(attribute_value)
        self.assertEqual(AS.number, number)

    def test_event_with_attachment_indicator_attribute(self):
        event = get_event_with_attachment_attribute()
        data = event['Event']['Attribute'][0]['data']
        attribute_value, pattern = self._run_indicator_tests(event)
        file_pattern = f"file:name = '{attribute_value}'"
        data_pattern = f"file:content_ref.payload_bin = '{data}'"
        self.assertEqual(pattern, f"[{file_pattern} AND {data_pattern}]")

    def test_event_with_attachment_observable_attribute(self):
        event = get_event_with_attachment_attribute()
        data = event['Event']['Attribute'][0]['data']
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        file_id, artifact_id = grouping_refs
        file_ref, artifact_ref = object_refs
        file_object, artifact_object = observable
        self.assertEqual(file_ref, file_id)
        self.assertEqual(file_object.id, file_ref)
        self.assertEqual(file_object.type, 'file')
        self.assertEqual(file_object.name, attribute_value)
        self.assertEqual(file_object.content_ref, artifact_id)
        self.assertEqual(artifact_ref, artifact_id)
        self.assertEqual(artifact_object.id, artifact_ref)
        self.assertEqual(artifact_object.type, 'artifact')
        self.assertEqual(artifact_object.payload_bin, data)

    def test_event_with_campaign_name_attribute(self):
        event = get_event_with_campaign_name_attribute()
        self._remove_attribute_ids_flag(event)
        orgc = event['Event']['Orgc']
        attribute = event['Event']['Attribute'][0]
        self.parser.parse_misp_event(event)
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, campaign = stix_objects
        identity_id = self._check_identity_features(identity, orgc)
        args = (
            grouping,
            event['Event'],
            identity_id
        )
        object_ref = self._check_grouping_features(*args)[0]
        self._check_attribute_campaign_features(
            campaign,
            attribute,
            identity_id,
            object_ref
        )
        self.assertEqual(campaign.name, attribute['value'])

    def test_event_with_domain_indicator_attribute(self):
        event = get_event_with_domain_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[domain-name:value = '{attribute_value}']")

    def test_event_with_domain_observable_attribute(self):
        event = get_event_with_domain_attribute()
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        object_ref = object_refs[0]
        domain = observable[0]
        self.assertEqual(object_ref, grouping_refs[0])
        self.assertEqual(domain.id, object_ref)
        self.assertEqual(domain.type, 'domain-name')
        self.assertEqual(domain.value, attribute_value)

    def test_event_with_domain_ip_indicator_attribute(self):
        event = get_event_with_domain_ip_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        domain, ip = attribute_value.split('|')
        domain_pattern = f"domain-name:value = '{domain}'"
        ip_pattern = f"domain-name:resolves_to_refs[*].value = '{ip}'"
        self.assertEqual(pattern, f'[{domain_pattern} AND {ip_pattern}]')

    def test_event_with_domain_ip_observable_attribute(self):
        event = get_event_with_domain_ip_attribute()
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        domain_value, ip_value = attribute_value.split('|')
        domain_id, address_id = grouping_refs
        domain_ref, address_ref = object_refs
        domain, address = observable
        self.assertEqual(domain_ref, domain_id)
        self.assertEqual(domain.id, domain_ref)
        self.assertEqual(domain.type, 'domain-name')
        self.assertEqual(domain.value, domain_value)
        self.assertEqual(domain.resolves_to_refs, [address_id])
        self.assertEqual(address_ref, address_id)
        self.assertEqual(address.id, address_ref)
        self.assertEqual(address.type, 'ipv4-addr')
        self.assertEqual(address.value, ip_value)

    def test_event_with_email_attachment_indicator_attribute(self):
        event = get_event_with_email_attachment_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[email-message:body_multipart[*].body_raw_ref.name = '{attribute_value}']")

    def test_event_with_email_attachment_observable_attribute(self):
        event = get_event_with_email_attachment_attribute()
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        email_id, file_id = grouping_refs
        email_ref, file_ref = object_refs
        email, file = observable
        self.assertEqual(email_ref, email_id)
        self.assertEqual(email.id, email_ref)
        self.assertEqual(email.type, 'email-message')
        self.assertEqual(email.is_multipart, True)
        body = email.body_multipart[0]
        self.assertEqual(body.content_disposition, f"attachment; filename='{attribute_value}'")
        self.assertEqual(body.body_raw_ref, file_id)
        self.assertEqual(file_ref, file_id)
        self.assertEqual(file.id, file_ref)
        self.assertEqual(file.name, attribute_value)

    def test_event_with_email_body_indicator_attribute(self):
        event = get_event_with_email_body_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(
            pattern,
            f"[email-message:body = '{attribute_value}']"
        )

    def test_event_with_email_body_observable_attribute(self):
        event = get_event_with_email_body_attribute()
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        object_ref = object_refs[0]
        message = observable[0]
        self.assertEqual(object_ref, grouping_refs[0])
        self.assertEqual(message.id, object_ref)
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.body, attribute_value)

    def test_event_with_email_destination_indicator_attribute(self):
        event = get_event_with_email_destination_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[email-message:to_refs[*].value = '{attribute_value}']")

    def test_event_with_email_destination_observable_attribute(self):
        event = get_event_with_email_destination_attribute()
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        message_id, address_id = grouping_refs
        message_ref, address_ref = object_refs
        message, address = observable
        self.assertEqual(message_ref, message_id)
        self.assertEqual(message.id, message_ref)
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.to_refs, [address_id])
        self.assertEqual(address_ref, address_id)
        self.assertEqual(address.id, address_ref)
        self.assertEqual(address.type, 'email-addr')
        self.assertEqual(address.value, attribute_value)

    def test_event_with_email_header_indicator_attribute(self):
        event = get_event_with_email_header_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[email-message:received_lines = '{attribute_value}']")

    def test_event_with_email_header_observable_attribute(self):
        event = get_event_with_email_header_attribute()
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        object_ref = object_refs[0]
        message = observable[0]
        self.assertEqual(object_ref, grouping_refs[0])
        self.assertEqual(message.id, object_ref)
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.received_lines, [attribute_value])

    def test_event_with_email_indicator_attribute(self):
        event = get_event_with_email_address_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[email-addr:value = '{attribute_value}']")

    def test_event_with_email_message_id_indicator_attribute(self):
        event = get_event_with_email_message_id_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[email-message:message_id = '{attribute_value}']")

    def test_event_with_email_message_id_observable_attribute(self):
        event = get_event_with_email_message_id_attribute()
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        object_ref = object_refs[0]
        message = observable[0]
        self.assertEqual(object_ref, grouping_refs[0])
        self.assertEqual(message.id, object_ref)
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.message_id, attribute_value)

    def test_event_with_email_observable_attribute(self):
        event = get_event_with_email_address_attribute()
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        object_ref = object_refs[0]
        address = observable[0]
        self.assertEqual(object_ref, grouping_refs[0])
        self.assertEqual(address.id, object_ref)
        self.assertEqual(address.type, 'email-addr')
        self.assertEqual(address.value, attribute_value)

    def test_event_with_email_reply_to_indicator_attribute(self):
        event = get_event_with_email_reply_to_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(
            pattern,
            f"[email-message:additional_header_fields.reply_to = '{attribute_value}']"
        )

    def test_event_with_email_reply_to_observable_attribute(self):
        event = get_event_with_email_reply_to_attribute()
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        object_ref = object_refs[0]
        message = observable[0]
        self.assertEqual(object_ref, grouping_refs[0])
        self.assertEqual(message.id, object_ref)
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.additional_header_fields['Reply-To'][0], attribute_value)

    def test_event_with_email_source_indicator_attribute(self):
        event = get_event_with_email_source_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[email-message:from_ref.value = '{attribute_value}']")

    def test_event_with_email_source_observable_attribute(self):
        event = get_event_with_email_source_attribute()
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        message_id, address_id = grouping_refs
        message_ref, address_ref = object_refs
        message, address = observable
        self.assertEqual(message_ref, message_id)
        self.assertEqual(message.id, message_ref)
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.from_ref, address_id)
        self.assertEqual(address_ref, address_id)
        self.assertEqual(address.id, address_ref)
        self.assertEqual(address.type, 'email-addr')
        self.assertEqual(address.value, attribute_value)

    def test_event_with_email_subject_indicator_attribute(self):
        event = get_event_with_email_subject_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[email-message:subject = '{attribute_value}']")

    def test_event_with_email_subject_observable_attribute(self):
        event = get_event_with_email_subject_attribute()
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        object_ref = object_refs[0]
        message = observable[0]
        self.assertEqual(object_ref, grouping_refs[0])
        self.assertEqual(message.id, object_ref)
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.subject, attribute_value)

    def test_event_with_email_x_mailer_indicator_attribute(self):
        event = get_event_with_email_x_mailer_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(
            pattern,
            f"[email-message:additional_header_fields.x_mailer = '{attribute_value}']"
        )

    def test_event_with_email_x_mailer_observable_attribute(self):
        event = get_event_with_email_x_mailer_attribute()
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        object_ref = object_refs[0]
        message = observable[0]
        self.assertEqual(object_ref, grouping_refs[0])
        self.assertEqual(message.id, object_ref)
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.additional_header_fields['X-Mailer'], attribute_value)

    def test_event_with_filename_indicator_attribute(self):
        event = get_event_with_filename_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[file:name = '{attribute_value}']")

    def test_event_with_filename_observable_attribute(self):
        event = get_event_with_filename_attribute()
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        object_ref = object_refs[0]
        file = observable[0]
        self.assertEqual(object_ref, grouping_refs[0])
        self.assertEqual(file.id, object_ref)
        self.assertEqual(file.type, 'file')
        self.assertEqual(file.name, attribute_value)

    def test_event_with_hash_composite_indicator_attributes(self):
        event = get_event_with_hash_composite_attributes(
            ('md5', 'sha1', 'sha512/256', 'sha3-256'),
            (
                'filename1|b2a5abfeef9e36964281a31e17b57c97',
                'filename2|2920d5e6c579fce772e5506caf03af65579088bd',
                'filename3|82333533f7f7cb4123bceee76358b36d4110e03c2219b80dced5a4d63424cc93',
                'filename4|39725234628358bcce613d1d1c07c2c3d2d106e3a6ac192016b46e5dddcd03f4'
            ),
            (
                '91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f',
                '518b4bcb-a86b-4783-9457-391d548b605b',
                '34cb1a7c-55ec-412a-8684-ba4a88d83a45',
                '94a2b00f-bec3-4f8a-bea4-e4ccf0de776f'
            )
        )
        attribute_values, patterns = self._run_indicators_tests(event)
        hash_types = ('MD5', 'SHA1', 'SHA256', 'SHA3256')
        for attribute_value, pattern, hash_type in zip(attribute_values, patterns, hash_types):
            filename, hash_value = attribute_value.split('|')
            filename_pattern = f"file:name = '{filename}'"
            hash_pattern = f"file:hashes.{hash_type} = '{hash_value}'"
            self.assertEqual(pattern, f"[{filename_pattern} AND {hash_pattern}]")

    def test_event_with_hash_composite_observable_attributes(self):
        event = get_event_with_hash_composite_attributes(
            ('md5', 'sha1', 'sha512/256', 'sha3-256'),
            (
                'filename1|b2a5abfeef9e36964281a31e17b57c97',
                'filename2|2920d5e6c579fce772e5506caf03af65579088bd',
                'filename3|82333533f7f7cb4123bceee76358b36d4110e03c2219b80dced5a4d63424cc93',
                'filename4|39725234628358bcce613d1d1c07c2c3d2d106e3a6ac192016b46e5dddcd03f4'
            ),
            (
                '91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f',
                '518b4bcb-a86b-4783-9457-391d548b605b',
                '34cb1a7c-55ec-412a-8684-ba4a88d83a45',
                '94a2b00f-bec3-4f8a-bea4-e4ccf0de776f'
            )
        )
        values, grouping_refs, object_refs, observables = self._run_observables_tests(event)
        for grouping_ref, object_ref, observable in zip(grouping_refs, object_refs, observables):
            self.assertEqual(grouping_ref, object_ref)
            self.assertEqual(observable.id, object_ref)
            self.assertEqual(observable.type, 'file')
        hash_types = ('MD5', 'SHA-1', 'SHA-256', 'SHA3-256')
        for value, observable, hash_type in zip(values, observables, hash_types):
            filename, hash_value = value.split('|')
            self.assertEqual(observable.name, filename)
            self.assertEqual(observable.hashes[hash_type], hash_value)

    def test_event_with_hash_indicator_attributes(self):
        event = get_event_with_hash_attributes(
            ('md5', 'sha1', 'sha512/256', 'sha3-256'),
            (
                'b2a5abfeef9e36964281a31e17b57c97',
                '2920d5e6c579fce772e5506caf03af65579088bd',
                '82333533f7f7cb4123bceee76358b36d4110e03c2219b80dced5a4d63424cc93',
                '39725234628358bcce613d1d1c07c2c3d2d106e3a6ac192016b46e5dddcd03f4'
            ),
            (
                '91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f',
                '518b4bcb-a86b-4783-9457-391d548b605b',
                '34cb1a7c-55ec-412a-8684-ba4a88d83a45',
                '94a2b00f-bec3-4f8a-bea4-e4ccf0de776f'
            )
        )
        attribute_values, patterns = self._run_indicators_tests(event)
        md5, sha1, sha2, sha3 = attribute_values
        md5_pattern, sha1_pattern, sha2_pattern, sha3_pattern = patterns
        self.assertEqual(md5_pattern, f"[file:hashes.MD5 = '{md5}']")
        self.assertEqual(sha1_pattern, f"[file:hashes.SHA1 = '{sha1}']")
        self.assertEqual(sha2_pattern, f"[file:hashes.SHA256 = '{sha2}']")
        self.assertEqual(sha3_pattern, f"[file:hashes.SHA3256 = '{sha3}']")

    def test_event_with_hash_observable_attributes(self):
        event = get_event_with_hash_attributes(
            ('md5', 'sha1', 'sha512/256', 'sha3-256'),
            (
                'b2a5abfeef9e36964281a31e17b57c97',
                '2920d5e6c579fce772e5506caf03af65579088bd',
                '82333533f7f7cb4123bceee76358b36d4110e03c2219b80dced5a4d63424cc93',
                '39725234628358bcce613d1d1c07c2c3d2d106e3a6ac192016b46e5dddcd03f4'
            ),
            (
                '91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f',
                '518b4bcb-a86b-4783-9457-391d548b605b',
                '34cb1a7c-55ec-412a-8684-ba4a88d83a45',
                '94a2b00f-bec3-4f8a-bea4-e4ccf0de776f'
            )
        )
        values, grouping_refs, object_refs, observables = self._run_observables_tests(event)
        for grouping_ref, object_ref, observable in zip(grouping_refs, object_refs, observables):
            self.assertEqual(grouping_ref, object_ref)
            self.assertEqual(observable.id, object_ref)
            self.assertEqual(observable.type, 'file')
        md5, sha1, sha2, sha3 = values
        md5_object, sha1_object, sha2_object, sha3_object = observables
        self.assertEqual(md5_object.hashes['MD5'], md5)
        self.assertEqual(sha1_object.hashes['SHA-1'], sha1)
        self.assertEqual(sha2_object.hashes['SHA-256'], sha2)
        self.assertEqual(sha3_object.hashes['SHA3-256'], sha3)

    def test_event_with_hostname_indicator_attribute(self):
        event = get_event_with_hostname_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[domain-name:value = '{attribute_value}']")

    def test_event_with_hostname_observable_attribute(self):
        event = get_event_with_hostname_attribute()
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        object_ref = object_refs[0]
        domain = observable[0]
        self.assertEqual(object_ref, grouping_refs[0])
        self.assertEqual(domain.id, object_ref)
        self.assertEqual(domain.type, 'domain-name')
        self.assertEqual(domain.value, attribute_value)

    def test_event_with_hostname_port_indicator_attribute(self):
        event = get_event_with_hostname_port_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        hostname, port = attribute_value.split('|')
        hostname_pattern = f"domain-name:value = '{hostname}'"
        port_pattern = f"network-traffic:dst_port = '{port}'"
        self.assertEqual(pattern, f"[{hostname_pattern} AND {port_pattern}]")

    def test_event_with_hostname_port_observable_attribute(self):
        event = get_event_with_hostname_port_attribute()
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        hostname, port = attribute_value.split('|')
        domain_id, network_traffic_id = grouping_refs
        hostname_ref, network_traffic_ref = object_refs
        domain, network_traffic = observable
        self.assertEqual(hostname_ref, domain_id)
        self.assertEqual(domain.id, hostname_ref)
        self.assertEqual(domain.type, 'domain-name')
        self.assertEqual(domain.value, hostname)
        self.assertEqual(network_traffic.id, network_traffic_id)
        self.assertEqual(network_traffic.type, 'network-traffic')
        self.assertEqual(network_traffic.dst_port, int(port))
        self.assertEqual(network_traffic.dst_ref, domain_id)

    def test_event_with_http_indicator_attributes(self):
        event = get_event_with_http_attributes()
        attribute_values, patterns = self._run_indicators_tests(event)
        http_method, user_agent = attribute_values
        http_method_pattern, user_agent_pattern = patterns
        prefix = f"network-traffic:extensions.'http-request-ext'"
        self.assertEqual(
            http_method_pattern,
            f"[{prefix}.request_method = '{http_method}']"
        )
        self.assertEqual(
            user_agent_pattern,
            f"[{prefix}.request_header.'User-Agent' = '{user_agent}']"
        )

    def test_event_with_ip_indicator_attributes(self):
        event = get_event_with_ip_attributes()
        attribute_values, patterns = self._run_indicators_tests(event)
        src, dst = attribute_values
        src_pattern, dst_pattern = patterns
        src_type_pattern = "network-traffic:src_ref.type = 'ipv4-addr'"
        src_value_pattern = f"network-traffic:src_ref.value = '{src}'"
        self.assertEqual(src_pattern, f"[{src_type_pattern} AND {src_value_pattern}]")
        dst_type_pattern = "network-traffic:dst_ref.type = 'ipv4-addr'"
        dst_value_pattern = f"network-traffic:dst_ref.value = '{dst}'"
        self.assertEqual(dst_pattern, f"[{dst_type_pattern} AND {dst_value_pattern}]")

    def test_event_with_ip_observable_attributes(self):
        event = get_event_with_ip_attributes()
        values, grouping_refs, object_refs, observables = self._run_observables_tests(
            event,
            index=3
        )
        for grouping_ref, observable in zip(grouping_refs, observables):
            self.assertEqual(grouping_ref, observable.id)
        src, dst = values
        src_network_id, src_address_id, dst_network_id, dst_address_id = grouping_refs
        src_observable_id, dst_observable_id = object_refs
        src_network, src_address, dst_network, dst_address = observables
        self.assertEqual(src_network_id, src_observable_id)
        self.assertEqual(src_network.id, src_network_id)
        self.assertEqual(src_network.type, 'network-traffic')
        self.assertEqual(src_network.src_ref, src_address_id)
        self.assertEqual(src_address.id, src_address_id)
        self.assertEqual(src_address.value, src)
        self.assertEqual(dst_network_id, dst_observable_id)
        self.assertEqual(dst_network.id, dst_network_id)
        self.assertEqual(dst_network.type, 'network-traffic')
        self.assertEqual(dst_network.dst_ref, dst_address_id)
        self.assertEqual(dst_address.id, dst_address_id)
        self.assertEqual(dst_address.value, dst)

    def test_event_with_ip_port_indicator_attributes(self):
        event = get_event_with_ip_port_attributes()
        attribute_values, patterns = self._run_indicators_tests(event)
        src, dst = attribute_values
        src_ip_value, src_port_value = src.split('|')
        dst_ip_value, dst_port_value = dst.split('|')
        src_pattern, dst_pattern = patterns
        src_type_pattern = "network-traffic:src_ref.type = 'ipv4-addr'"
        src_value_pattern = f"network-traffic:src_ref.value = '{src_ip_value}'"
        src_port_pattern = f"network-traffic:src_port = '{src_port_value}'"
        self.assertEqual(
            src_pattern,
            f"[{src_type_pattern} AND {src_value_pattern} AND {src_port_pattern}]"
        )
        dst_type_pattern = "network-traffic:dst_ref.type = 'ipv4-addr'"
        dst_value_pattern = f"network-traffic:dst_ref.value = '{dst_ip_value}'"
        dst_port_pattern = f"network-traffic:dst_port = '{dst_port_value}'"
        self.assertEqual(
            dst_pattern,
            f"[{dst_type_pattern} AND {dst_value_pattern} AND {dst_port_pattern}]"
        )

    def test_event_with_ip_port_observable_attributes(self):
        event = get_event_with_ip_port_attributes()
        values, grouping_refs, object_refs, observables = self._run_observables_tests(
            event,
            index=3
        )
        for grouping_ref, observable in zip(grouping_refs, observables):
            self.assertEqual(grouping_ref, observable.id)
        src, dst = values
        src_network_id, src_address_id, dst_network_id, dst_address_id = grouping_refs
        src_observable_id, dst_observable_id = object_refs
        src_network, src_address, dst_network, dst_address = observables
        src_ip_value, src_port_value = src.split('|')
        self.assertEqual(src_network_id, src_observable_id)
        self.assertEqual(src_network.id, src_network_id)
        self.assertEqual(src_network.type, 'network-traffic')
        self.assertEqual(src_network.src_port, int(src_port_value))
        self.assertEqual(src_network.src_ref, src_address_id)
        self.assertEqual(src_address.id, src_address_id)
        self.assertEqual(src_address.value, src_ip_value)
        dst_ip_value, dst_port_value = dst.split('|')
        self.assertEqual(dst_network_id, dst_observable_id)
        self.assertEqual(dst_network.id, dst_network_id)
        self.assertEqual(dst_network.type, 'network-traffic')
        self.assertEqual(dst_network.dst_port, int(dst_port_value))
        self.assertEqual(dst_network.dst_ref, dst_address_id)
        self.assertEqual(dst_address.id, dst_address_id)
        self.assertEqual(dst_address.value, dst_ip_value)

    def test_event_with_mac_address_indicator_attribute(self):
        event = get_event_with_mac_address_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[mac-addr:value = '{attribute_value}']")

    def test_event_with_mac_address_observable_attribute(self):
        event = get_event_with_mac_address_attribute()
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        object_ref = object_refs[0]
        mac_address = observable[0]
        self.assertEqual(object_ref, grouping_refs[0])
        self.assertEqual(mac_address.id, object_ref)
        self.assertEqual(mac_address.type, 'mac-addr')
        self.assertEqual(mac_address.value, attribute_value)

    def test_event_with_mutex_indicator_attribute(self):
        event = get_event_with_mutex_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[mutex:name = '{attribute_value}']")

    def test_event_with_mutex_observable_attribute(self):
        event = get_event_with_mutex_attribute()
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        object_ref = object_refs[0]
        mutex = observable[0]
        self.assertEqual(object_ref, grouping_refs[0])
        self.assertEqual(mutex.id, object_ref)
        self.assertEqual(mutex.type, 'mutex')
        self.assertEqual(mutex.name, attribute_value)

    def test_event_with_port_indicator_attribute(self):
        event = get_event_with_port_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[network-traffic:dst_port = '{attribute_value}']")

    def test_event_with_regkey_indicator_attribute(self):
        event = get_event_with_regkey_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(
            pattern.replace('\\\\', '\\'),
            f"[windows-registry-key:key = '{attribute_value.strip()}']"
        )

    def test_event_with_regkey_observable_attribute(self):
        event = get_event_with_regkey_attribute()
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        object_ref = object_refs[0]
        registry_key = observable[0]
        self.assertEqual(object_ref, grouping_refs[0])
        self.assertEqual(registry_key.id, object_ref)
        self.assertEqual(registry_key.type, 'windows-registry-key')
        self.assertEqual(registry_key.key, attribute_value.strip())

    def test_event_with_regkey_value_indicator_attribute(self):
        event = get_event_with_regkey_value_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        key, value = attribute_value.split('|')
        key_pattern = f"windows-registry-key:key = '{key.strip()}'"
        value_pattern = f"windows-registry-key:values.data = '{value.strip()}'"
        self.assertEqual(
            pattern.replace('\\\\', '\\'),
            f"[{key_pattern} AND {value_pattern}]"
        )

    def test_event_with_regkey_value_observable_attribute(self):
        event = get_event_with_regkey_value_attribute()
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        key, value = attribute_value.split('|')
        object_ref = object_refs[0]
        registry_key = observable[0]
        self.assertEqual(object_ref, grouping_refs[0])
        self.assertEqual(registry_key.id, object_ref)
        self.assertEqual(registry_key.type, 'windows-registry-key')
        self.assertEqual(registry_key.key, key.strip())
        self.assertEqual(registry_key['values'][0].data, value.strip())

    def test_event_with_size_in_bytes_indicator_attribute(self):
        event = get_event_with_size_in_bytes_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[file:size = '{attribute_value}']")

    def test_event_with_url_indicator_attribute(self):
        event = get_event_with_url_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[url:value = '{attribute_value}']")

    def test_event_with_url_observable_attribute(self):
        event = get_event_with_url_attribute()
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        object_ref = object_refs[0]
        url = observable[0]
        self.assertEqual(object_ref, grouping_refs[0])
        self.assertEqual(url.id, object_ref)
        self.assertEqual(url.type, 'url')
        self.assertEqual(url.value, attribute_value)

    def test_event_with_vulnerability_attribute(self):
        event = get_event_with_vulnerability_attribute()
        self._add_attribute_ids_flag(event)
        orgc = event['Event']['Orgc']
        attribute = event['Event']['Attribute'][0]
        self.parser.parse_misp_event(event)
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, vulnerability = stix_objects
        identity_id = self._check_identity_features(identity, orgc)
        args = (
            grouping,
            event['Event'],
            identity_id
        )
        object_ref = self._check_grouping_features(*args)[0]
        self._check_attribute_vulnerability_features(
            vulnerability,
            attribute,
            identity_id,
            object_ref
        )
        self.assertEqual(vulnerability.name, attribute['value'])
        external_reference = vulnerability.external_references[0]
        self.assertEqual(external_reference.source_name, 'cve')
        self.assertEqual(external_reference.external_id, attribute['value'])

    def test_event_with_x509_fingerprint_indicator_attributes(self):
        event = get_event_with_x509_fingerprint_attributes()
        attribute_values, patterns = self._run_indicators_tests(event)
        md5, sha1, sha256 = attribute_values
        md5_pattern, sha1_pattern, sha256_pattern = patterns
        self.assertEqual(md5_pattern, f"[x509-certificate:hashes.MD5 = '{md5}']")
        self.assertEqual(sha1_pattern, f"[x509-certificate:hashes.SHA1 = '{sha1}']")
        self.assertEqual(sha256_pattern, f"[x509-certificate:hashes.SHA256 = '{sha256}']")

    def test_event_with_x509_fingerprint_observable_attributes(self):
        event = get_event_with_x509_fingerprint_attributes()
        values, grouping_refs, object_refs, observables = self._run_observables_tests(event)
        for grouping_ref, object_ref, observable in zip(grouping_refs, object_refs, observables):
            self.assertEqual(grouping_ref, object_ref)
            self.assertEqual(observable.id, object_ref)
            self.assertEqual(observable.type, 'x509-certificate')
        md5, sha1, sha256 = values
        md5_object, sha1_object, sha256_object = observables
        self.assertEqual(md5_object.hashes['MD5'], md5)
        self.assertEqual(sha1_object.hashes['SHA-1'], sha1)
        self.assertEqual(sha256_object.hashes['SHA-256'], sha256)
