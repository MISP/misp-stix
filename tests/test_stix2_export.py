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

    def _check_attribute_indicator_features(self, indicator, attribute, identity_id, object_ref):
        uuid = f"indicator--{attribute['uuid']}"
        self.assertEqual(uuid, object_ref)
        self.assertEqual(indicator.id, uuid)
        self.assertEqual(indicator.type, 'indicator')
        self.assertEqual(indicator.created_by_ref, identity_id)
        self._check_killchain(indicator.kill_chain_phases[0], attribute['category'])
        type_label, category_label, ids_label = indicator.labels
        self.assertEqual(type_label, f'misp:type="{attribute["type"]}"')
        self.assertEqual(category_label, f'misp:category="{attribute["category"]}"')
        self.assertEqual(ids_label, f'misp:to_ids="{attribute["to_ids"]}"')
        timestamp = self._datetime_from_timestamp(attribute['timestamp'])
        self.assertEqual(indicator.created, timestamp)
        self.assertEqual(indicator.modified, timestamp)
        self.assertEqual(indicator.valid_from, timestamp)

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

    def test_event_with_as_indicator_attribute(self):
        event = get_event_with_as_attribute()
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
        number = self._parse_AS_value(attribute['value'])
        self.assertEqual(indicator.pattern, f"[autonomous-system:number = '{number}']")

    def test_event_with_as_observable_attribute(self):
        event = get_event_with_as_attribute()
        self._remove_attribute_ids_flag(event)
        orgc = event['Event']['Orgc']
        attribute = event['Event']['Attribute'][0]
        self.parser.parse_misp_event(event)
        identity, report, observed_data = self.parser.stix_objects
        identity_id = self._check_identity_features(identity, orgc)
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        object_ref = self._check_report_features(report, event['Event'], identity_id, timestamp)[0]
        self.assertEqual(report.published, timestamp)
        self._check_attribute_observable_features(observed_data, attribute, identity_id, object_ref)
        observable = observed_data['objects']['0']
        self.assertEqual(observable.type, 'autonomous-system')
        number = self._parse_AS_value(attribute['value'])
        self.assertEqual(observable.number, number)

    def test_event_with_domain_indicator_attribute(self):
        event = get_event_with_domain_attribute()
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
        self.assertEqual(indicator.pattern, f"[domain-name:value = '{attribute['value']}']")

    def test_event_with_domain_observable_attribute(self):
        event = get_event_with_domain_attribute()
        self._remove_attribute_ids_flag(event)
        orgc = event['Event']['Orgc']
        attribute = event['Event']['Attribute'][0]
        self.parser.parse_misp_event(event)
        identity, report, observed_data = self.parser.stix_objects
        identity_id = self._check_identity_features(identity, orgc)
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        object_ref = self._check_report_features(report, event['Event'], identity_id, timestamp)[0]
        self.assertEqual(report.published, timestamp)
        self._check_attribute_observable_features(observed_data, attribute, identity_id, object_ref)
        observable = observed_data['objects']['0']
        self.assertEqual(observable.type, 'domain-name')
        self.assertEqual(observable.value, attribute['value'])

    def test_event_with_domain_ip_indicator_attribute(self):
        event = get_event_with_domain_ip_attribute()
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
        domain, ip = attribute['value'].split('|')
        domain_pattern = f"domain-name:value = '{domain}'"
        ip_pattern = f"domain-name:resolves_to_refs[*].value = '{ip}'"
        self.assertEqual(indicator.pattern, f'[{domain_pattern} AND {ip_pattern}]')

    def test_event_with_domain_ip_observable_attribute(self):
        event = get_event_with_domain_ip_attribute()
        self._remove_attribute_ids_flag(event)
        orgc = event['Event']['Orgc']
        attribute = event['Event']['Attribute'][0]
        self.parser.parse_misp_event(event)
        identity, report, observed_data = self.parser.stix_objects
        identity_id = self._check_identity_features(identity, orgc)
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        object_ref = self._check_report_features(report, event['Event'], identity_id, timestamp)[0]
        self.assertEqual(report.published, timestamp)
        self._check_attribute_observable_features(observed_data, attribute, identity_id, object_ref)
        domain, ip = attribute['value'].split('|')
        domain_object, address_object = observed_data['objects'].values()
        self.assertEqual(domain_object.type, 'domain-name')
        self.assertEqual(domain_object.value, domain)
        self.assertEqual(domain_object.resolves_to_refs, ['1'])
        self.assertEqual(address_object.type, 'ipv4-addr')
        self.assertEqual(address_object.value, ip)


class TestSTIX21Export(TestSTIX2Export):
    def setUp(self):
        self.parser = MISPtoSTIX21Parser()

    def _check_grouping_features(self, grouping, event, identity_id, timestamp):
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

    def test_event_with_as_indicator_attribute(self):
        event = get_event_with_as_attribute()
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
            identity_id,
            self._datetime_from_timestamp(attribute['timestamp'])
        )
        object_ref = self._check_grouping_features(*args)[0]
        self._check_attribute_indicator_features(indicator, attribute, identity_id, object_ref)
        self._check_pattern_features(indicator)
        number = self._parse_AS_value(attribute['value'])
        self.assertEqual(indicator.pattern, f"[autonomous-system:number = '{number}']")

    def test_event_with_as_observable_attribute(self):
        event = get_event_with_as_attribute()
        self._remove_attribute_ids_flag(event)
        orgc = event['Event']['Orgc']
        attribute = event['Event']['Attribute'][0]
        self.parser.parse_misp_event(event)
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, observed_data, AS = stix_objects
        identity_id = self._check_identity_features(identity, orgc)
        observable_id, as_id = self._check_grouping_features(
            grouping,
            event['Event'],
            identity_id,
            self._datetime_from_timestamp(event['Event']['timestamp'])
        )
        self._check_attribute_observable_features(observed_data, attribute, identity_id, observable_id)
        object_ref = observed_data['object_refs'][0]
        self.assertEqual(AS.id, object_ref)
        self.assertEqual(AS.type, 'autonomous-system')
        number = self._parse_AS_value(attribute['value'])
        self.assertEqual(AS.number, number)

    def test_event_with_domain_indicator_attribute(self):
        event = get_event_with_domain_attribute()
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
            identity_id,
            self._datetime_from_timestamp(event['Event']['timestamp'])
        )
        object_ref = self._check_grouping_features(*args)[0]
        self._check_attribute_indicator_features(indicator, attribute, identity_id, object_ref)
        self._check_pattern_features(indicator)
        self.assertEqual(indicator.pattern, f"[domain-name:value = '{attribute['value']}']")

    def test_event_with_domain_observable_attribute(self):
        event = get_event_with_domain_attribute()
        self._remove_attribute_ids_flag(event)
        orgc = event['Event']['Orgc']
        attribute = event['Event']['Attribute'][0]
        self.parser.parse_misp_event(event)
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, observed_data, domain = stix_objects
        identity_id = self._check_identity_features(identity, orgc)
        observable_id, domain_id = self._check_grouping_features(
            grouping,
            event['Event'],
            identity_id,
            self._datetime_from_timestamp(event['Event']['timestamp'])
        )
        self._check_attribute_observable_features(observed_data, attribute, identity_id, observable_id)
        object_ref = observed_data['object_refs'][0]
        self.assertEqual(object_ref, domain_id)
        self.assertEqual(domain.id, object_ref)
        self.assertEqual(domain.type, 'domain-name')
        self.assertEqual(domain.value, attribute['value'])

    def test_event_with_domain_ip_indicator_attribute(self):
        event = get_event_with_domain_ip_attribute()
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
            identity_id,
            self._datetime_from_timestamp(event['Event']['timestamp'])
        )
        object_ref = self._check_grouping_features(*args)[0]
        self._check_attribute_indicator_features(indicator, attribute, identity_id, object_ref)
        self._check_pattern_features(indicator)
        domain, ip = attribute['value'].split('|')
        domain_pattern = f"domain-name:value = '{domain}'"
        ip_pattern = f"domain-name:resolves_to_refs[*].value = '{ip}'"
        self.assertEqual(indicator.pattern, f'[{domain_pattern} AND {ip_pattern}]')

    def test_event_with_domain_ip_observable_attribute(self):
        event = get_event_with_domain_ip_attribute()
        self._remove_attribute_ids_flag(event)
        orgc = event['Event']['Orgc']
        attribute = event['Event']['Attribute'][0]
        self.parser.parse_misp_event(event)
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, observed_data, domain, address = stix_objects
        identity_id = self._check_identity_features(identity, orgc)
        observable_id, domain_id, address_id = self._check_grouping_features(
            grouping,
            event['Event'],
            identity_id,
            self._datetime_from_timestamp(event['Event']['timestamp'])
        )
        self._check_attribute_observable_features(observed_data, attribute, identity_id, observable_id)
        domain_value, ip_value = attribute['value'].split('|')
        domain_ref, address_ref = observed_data['object_refs']
        self.assertEqual(domain_ref, domain_id)
        self.assertEqual(domain.id, domain_ref)
        self.assertEqual(domain.type, 'domain-name')
        self.assertEqual(domain.value, domain_value)
        self.assertEqual(domain.resolves_to_refs, [address_id])
        self.assertEqual(address_ref, address_id)
        self.assertEqual(address.id, address_ref)
        self.assertEqual(address.type, 'ipv4-addr')
        self.assertEqual(address.value, ip_value)
