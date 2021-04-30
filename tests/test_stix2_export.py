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

    @staticmethod
    def _add_object_ids_flag(event):
        for misp_object in event['Event']['Object']:
            misp_object['Attribute'][0]['to_ids'] = True

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
        self._check_indicator_features(indicator, identity_id, object_ref, attribute['uuid'])
        self._check_killchain(indicator.kill_chain_phases[0], attribute['category'])
        self._check_attribute_labels(attribute, indicator.labels)
        self._check_indicator_time_features(indicator, attribute['timestamp'])

    def _check_attribute_labels(self, attribute, labels):
        if attribute.get('to_ids'):
            type_label, category_label, ids_label = labels
            self.assertEqual(ids_label, f'misp:to_ids="{attribute["to_ids"]}"')
        else:
            type_label, category_label = labels
        self.assertEqual(type_label, f'misp:type="{attribute["type"]}"')
        self.assertEqual(category_label, f'misp:category="{attribute["category"]}"')

    def _check_attribute_observable_features(self, observed_data, attribute, identity_id, object_ref):
        self._check_observable_features(observed_data, identity_id, object_ref, attribute['uuid'])
        self._check_attribute_labels(attribute, observed_data.labels)
        self._check_observable_time_features(observed_data, attribute['timestamp'])

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

    def _check_external_reference(self, reference, source_name, value):
        self.assertEqual(reference.source_name, source_name)
        self.assertEqual(reference.external_id, value)

    def _check_galaxy_features(self, stix_object, galaxy, timestamp, killchain, synonyms):
        cluster = galaxy['GalaxyCluster'][0]
        self.assertEqual(stix_object.created, timestamp)
        self.assertEqual(stix_object.modified, timestamp)
        self.assertEqual(stix_object.name, cluster['value'])
        self.assertEqual(stix_object.description, f"{galaxy['description']} | {cluster['description']}")
        self.assertEqual(stix_object.labels[0], f'misp:name="{galaxy["name"]}"')
        if killchain:
            self.assertEqual(stix_object.kill_chain_phases[0]['phase_name'], cluster['type'])
        if synonyms:
            self.assertEqual(stix_object.aliases[0], cluster['meta']['synonyms'][0])

    def _check_identity_features(self, identity, orgc, timestamp):
        identity_id = f"identity--{orgc['uuid']}"
        self.assertEqual(identity.type, 'identity')
        self.assertEqual(identity.id, identity_id)
        self.assertEqual(identity.name, orgc['name'])
        self.assertEqual(identity.identity_class, 'organization')
        self.assertEqual(identity.created, timestamp)
        self.assertEqual(identity.modified, timestamp)
        return identity_id

    def _check_indicator_features(self, indicator, identity_id, object_ref, object_uuid):
        uuid = f"indicator--{object_uuid}"
        self.assertEqual(uuid, object_ref)
        self.assertEqual(indicator.id, uuid)
        self.assertEqual(indicator.type, 'indicator')
        self.assertEqual(indicator.created_by_ref, identity_id)

    def _check_indicator_time_features(self, indicator, object_time):
        timestamp = self._datetime_from_timestamp(object_time)
        self.assertEqual(indicator.created, timestamp)
        self.assertEqual(indicator.modified, timestamp)
        self.assertEqual(indicator.valid_from, timestamp)

    def _check_killchain(self, killchain, category):
        self.assertEqual(killchain['kill_chain_name'], 'misp-category')
        self.assertEqual(killchain['phase_name'], category)

    def _check_object_indicator_features(self, indicator, misp_object, identity_id, object_ref):
        self._check_indicator_features(indicator, identity_id, object_ref, misp_object['uuid'])
        self._check_killchain(indicator.kill_chain_phases[0], misp_object['meta-category'])
        self._check_object_labels(misp_object, indicator.labels, to_ids=True)
        self._check_indicator_time_features(indicator, misp_object['timestamp'])

    def _check_object_labels(self, misp_object, labels, to_ids=None):
        if to_ids is not None:
            category_label, name_label, ids_label = labels
            self.assertEqual(ids_label, f'misp:to_ids="{to_ids}"')
        else:
            category_label, name_label = labels
        self.assertEqual(category_label, f'misp:category="{misp_object["meta-category"]}"')
        self.assertEqual(name_label, f'misp:name="{misp_object["name"]}"')

    def _check_object_observable_features(self, observed_data, misp_object, identity_id, object_ref):
        self._check_observable_features(observed_data, identity_id, object_ref, misp_object['uuid'])
        self._check_object_labels(misp_object, observed_data.labels, to_ids=False)
        self._check_observable_time_features(observed_data, misp_object['timestamp'])

    def _check_observable_features(self, observed_data, identity_id, object_ref, object_uuid):
        uuid = f"observed-data--{object_uuid}"
        self.assertEqual(uuid, object_ref)
        self.assertEqual(observed_data.id, uuid)
        self.assertEqual(observed_data.type, 'observed-data')
        self.assertEqual(observed_data.created_by_ref, identity_id)
        self.assertEqual(observed_data.number_observed, 1)

    def _check_observable_time_features(self, observed_data, object_time):
        timestamp = self._datetime_from_timestamp(object_time)
        self.assertEqual(observed_data.created, timestamp)
        self.assertEqual(observed_data.modified, timestamp)
        self.assertEqual(observed_data.first_observed, timestamp)
        self.assertEqual(observed_data.last_observed, timestamp)

    def _check_relationship_features(self, relationship, source_id, target_id, relationship_type, timestamp):
        self.assertEqual(relationship.type, 'relationship')
        self.assertEqual(relationship.source_ref, source_id)
        self.assertEqual(relationship.target_ref, target_id)
        self.assertEqual(relationship.relationship_type, relationship_type)
        self.assertEqual(relationship.created, timestamp)
        self.assertEqual(relationship.modified, timestamp)

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
    def _reassemble_pattern(pattern):
        reassembled = []
        middle = False
        for feature in pattern.split(' AND '):
            if feature.startswith('('):
                pattern_part = [feature]
                middle = True
                continue
            if feature.endswith(')'):
                pattern_part.append(feature)
                reassembled.append(' AND '.join(pattern_part))
                middle = False
                continue
            if middle:
                pattern_part.append(feature)
            else:
                reassembled.append(feature)
        return reassembled

    @staticmethod
    def _remove_attribute_ids_flag(event):
        for attribute in event['Event']['Attribute']:
            attribute['to_ids'] = False

    @staticmethod
    def _remove_object_ids_flags(event):
        for misp_object in event['Event']['Object']:
            for attribute in misp_object['Attribute']:
                attribute['to_ids'] = False


class TestSTIX20Export(TestSTIX2Export):
    def setUp(self):
        self.parser = MISPtoSTIX20Parser()

    ################################################################################
    #                              UTILITY FUNCTIONS.                              #
    ################################################################################

    def _check_bundle_features(self, length):
        bundle = self.parser.bundle
        self.assertEqual(bundle.type, 'bundle')
        self.assertEqual(bundle.spec_version, '2.0')
        self.assertEqual(len(bundle.objects), length)
        return bundle

    def _run_indicator_from_object_tests(self, event):
        self._add_object_ids_flag(event)
        orgc = event['Event']['Orgc']
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event)
        identity, report, indicator = self.parser.stix_objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        args = (report, event['Event'], identity_id, timestamp)
        object_ref = self._check_report_features(*args)[0]
        self.assertEqual(report.published, timestamp)
        self._check_object_indicator_features(indicator, misp_object, identity_id, object_ref)
        return misp_object['Attribute'], indicator.pattern

    def _run_indicator_tests(self, event):
        self._add_attribute_ids_flag(event)
        orgc = event['Event']['Orgc']
        attribute = event['Event']['Attribute'][0]
        self.parser.parse_misp_event(event)
        identity, report, indicator = self.parser.stix_objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
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
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event['Event'], identity_id, timestamp)
        self.assertEqual(report.published, timestamp)
        for attribute, indicator, object_ref in zip(attributes, indicators, object_refs):
            self._check_attribute_indicator_features(indicator, attribute, identity_id, object_ref)
        attribute_values = (attribute['value'] for attribute in attributes)
        patterns = (indicator.pattern for indicator in indicators)
        return attribute_values, patterns

    def _run_galaxy_tests(self, event, timestamp):
        orgc = event['Event']['Orgc']
        self.parser.parse_misp_event(event)
        identity, report, stix_object = self.parser.stix_objects
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event['Event'], identity_id, timestamp)[0]
        self.assertEqual(report.published, timestamp)
        self.assertEqual(stix_object.id, object_ref)
        return stix_object

    def _run_observable_from_object_tests(self, event):
        self._remove_object_ids_flags(event)
        orgc = event['Event']['Orgc']
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event)
        identity, report, observed_data = self.parser.stix_objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        args = (report, event['Event'], identity_id, timestamp)
        object_ref = self._check_report_features(*args)[0]
        self.assertEqual(report.published, timestamp)
        self._check_object_observable_features(
            observed_data,
            misp_object,
            identity_id,
            object_ref
        )
        return misp_object['Attribute'], observed_data['objects']

    def _run_observable_tests(self, event):
        self._remove_attribute_ids_flag(event)
        orgc = event['Event']['Orgc']
        attribute = event['Event']['Attribute'][0]
        self.parser.parse_misp_event(event)
        identity, report, observed_data = self.parser.stix_objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        args = (report, event['Event'], identity_id, timestamp)
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
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        args = (report, event['Event'], identity_id, timestamp)
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

    ################################################################################
    #                              EVENT FIELDS TESTS                              #
    ################################################################################

    def test_base_event(self):
        event = get_base_event()
        orgc = event['Event']['Orgc']
        self.parser.parse_misp_event(event)
        bundle = self._check_bundle_features(3)
        identity, report, custom = bundle.objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event['Event'], identity_id, timestamp)[0]
        self.assertEqual(report.published, timestamp)
        self.assertEqual(custom.type, 'x-misp-event-note')
        self.assertEqual(custom.id, f"x-misp-event-note--{event['Event']['uuid']}")
        self.assertEqual(custom.created_by_ref, identity_id)
        self.assertEqual(custom.created, timestamp)
        self.assertEqual(custom.modified, timestamp)
        self.assertEqual(custom.object_ref, report.id)
        self.assertEqual(
            custom.x_misp_event_note,
            "This MISP Event is empty and contains no attribute, object, galaxy or tag."
        )

    def test_published_event(self):
        event = get_published_event()
        orgc = event['Event']['Orgc']
        self.parser.parse_misp_event(event)
        bundle = self._check_bundle_features(3)
        _, report, _ = bundle.objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        self.assertEqual(report.created, timestamp)
        self.assertEqual(report.modified, timestamp)
        self.assertEqual(
            report.published,
            self._datetime_from_timestamp(event['Event']['publish_timestamp'])
        )

    def test_event_with_tags(self):
        event = get_event_with_tags()
        orgc = event['Event']['Orgc']
        self.parser.parse_misp_event(event)
        bundle = self._check_bundle_features(4)
        _, _, _, marking = bundle.objects
        self.assertEqual(marking.definition_type, 'tlp')
        self.assertEqual(marking.definition['tlp'], 'white')

    ################################################################################
    #                        SINGLE ATTRIBUTES EXPORT TESTS                        #
    ################################################################################

    def test_embedded_indicator_attribute_galaxy(self):
        event = get_embedded_indicator_attribute_galaxy()
        orgc = event['Event']['Orgc']
        attribute = event['Event']['Attribute'][0]
        self.parser.parse_misp_event(event)
        bundle = self._check_bundle_features(8)
        identity, report, attack_pattern, course_of_action, indicator, malware, *relationships = bundle.objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event['Event'], identity_id, timestamp)
        self.assertEqual(report.published, timestamp)
        ap_ref, coa_ref, indicator_ref, malware_ref, apr_ref, coar_ref = object_refs
        ap_relationship, coa_relationship = relationships
        self.assertEqual(attack_pattern.id, ap_ref)
        self.assertEqual(course_of_action.id, coa_ref)
        self.assertEqual(indicator.id, indicator_ref)
        self.assertEqual(malware.id, malware_ref)
        self.assertEqual(ap_relationship.id, apr_ref)
        self.assertEqual(coa_relationship.id, coar_ref)
        timestamp = self._datetime_from_timestamp(attribute['timestamp'])
        self._check_relationship_features(ap_relationship, indicator_ref, ap_ref, 'indicates', timestamp)
        self._check_relationship_features(coa_relationship, indicator_ref, coa_ref, 'has', timestamp)

    def test_embedded_non_indicator_attribute_galaxy(self):
        event = get_embedded_non_indicator_attribute_galaxy()
        orgc = event['Event']['Orgc']
        attribute = event['Event']['Attribute'][0]
        self.parser.parse_misp_event(event)
        bundle = self._check_bundle_features(8)
        identity, report, attack_pattern, course_of_action, vulnerability, malware, *relationships = bundle.objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event['Event'], identity_id, timestamp)
        self.assertEqual(report.published, timestamp)
        ap_ref, coa_ref, vulnerability_ref, malware_ref, apr_ref, coar_ref = object_refs
        ap_relationship, coa_relationship = relationships
        self.assertEqual(attack_pattern.id, ap_ref)
        self.assertEqual(course_of_action.id, coa_ref)
        self.assertEqual(vulnerability.id, vulnerability_ref)
        self.assertEqual(malware.id, malware_ref)
        self.assertEqual(ap_relationship.id, apr_ref)
        self.assertEqual(coa_relationship.id, coar_ref)
        timestamp = self._datetime_from_timestamp(attribute['timestamp'])
        self._check_relationship_features(ap_relationship, vulnerability_ref, ap_ref, 'has', timestamp)
        self._check_relationship_features(coa_relationship, vulnerability_ref, coa_ref, 'has', timestamp)

    def test_embedded_observable_attribute_galaxy(self):
        event = get_embedded_observable_attribute_galaxy()
        orgc = event['Event']['Orgc']
        attribute = event['Event']['Attribute'][0]
        self.parser.parse_misp_event(event)
        bundle = self._check_bundle_features(6)
        identity, report, attack_pattern, observed_data, malware, relationship = bundle.objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event['Event'], identity_id, timestamp)
        self.assertEqual(report.published, timestamp)
        ap_ref, od_ref, malware_ref, relationship_ref = object_refs
        self.assertEqual(attack_pattern.id, ap_ref)
        self.assertEqual(observed_data.id, od_ref)
        self.assertEqual(malware.id, malware_ref)
        self.assertEqual(relationship.id, relationship_ref)
        self._check_relationship_features(
            relationship,
            od_ref,
            ap_ref,
            'has',
            self._datetime_from_timestamp(attribute['timestamp'])
        )

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
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event['Event'], identity_id, timestamp)[0]
        self.assertEqual(report.published, timestamp)
        self._check_attribute_campaign_features(
            campaign,
            attribute,
            identity_id,
            object_ref
        )
        self.assertEqual(campaign.name, attribute['value'])

    def test_event_with_custom_attributes(self):
        event = get_event_with_stix2_custom_attributes()
        orgc = event['Event']['Orgc']
        attributes = event['Event']['Attribute']
        self.parser.parse_misp_event(event)
        identity, report, *custom_objects = self.parser.stix_objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event['Event'], identity_id, timestamp)[0]
        self.assertEqual(report.published, timestamp)
        for attribute, custom_object in zip(attributes, custom_objects):
            attribute_type = attribute['type']
            category = attribute['category']
            custom_type = f"x-misp-attribute"
            self.assertEqual(custom_object.type, custom_type)
            self.assertEqual(custom_object.id, f"{custom_type}--{attribute['uuid']}")
            self.assertEqual(custom_object.created_by_ref, identity_id)
            self.assertEqual(custom_object.labels[0], f'misp:type="{attribute_type}"')
            self.assertEqual(custom_object.labels[1], f'misp:category="{category}"')
            if attribute.get('to_ids', False):
                self.assertEqual(custom_object.labels[2], 'misp:to_ids="True"')
            self.assertEqual(custom_object.x_misp_type, attribute['type'])
            self.assertEqual(custom_object.x_misp_category, category)
            if attribute.get('comment'):
                self.assertEqual(custom_object.x_misp_comment, attribute['comment'])
            self.assertEqual(custom_object.x_misp_value, attribute['value'])

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

    def test_event_with_malware_sample_indicator_attribute(self):
        event = get_event_with_malware_sample_attribute()
        data = event['Event']['Attribute'][0]['data']
        attribute_value, pattern = self._run_indicator_tests(event)
        filename, hash_value = attribute_value.split('|')
        file_pattern = f"file:name = '{filename}'"
        hash_pattern = f"file:hashes.MD5 = '{hash_value}'"
        data_pattern = f"file:content_ref.payload_bin = '{data}'"
        self.assertEqual(pattern, f"[{file_pattern} AND {hash_pattern} AND {data_pattern}]")

    def test_event_with_malware_sample_observable_attribute(self):
        event = get_event_with_malware_sample_attribute()
        data = event['Event']['Attribute'][0]['data']
        attribute_value, observable_objects = self._run_observable_tests(event)
        file_object, artifact_object = observable_objects.values()
        filename, hash_value = attribute_value.split('|')
        self.assertEqual(file_object.type, 'file')
        self.assertEqual(file_object.name, filename)
        self.assertEqual(file_object.hashes['MD5'], hash_value)
        self.assertEqual(file_object.content_ref, '1')
        self.assertEqual(artifact_object.type, 'artifact')
        self.assertEqual(artifact_object.payload_bin, data)

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
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event['Event'], identity_id, timestamp)[0]
        self.assertEqual(report.published, timestamp)
        self._check_attribute_vulnerability_features(
            vulnerability,
            attribute,
            identity_id,
            object_ref
        )
        self.assertEqual(vulnerability.name, attribute['value'])
        self._check_external_reference(
            vulnerability.external_references[0],
            'cve',
            attribute['value']
        )

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

    ################################################################################
    #                          MISP OBJECTS EXPORT TESTS.                          #
    ################################################################################

    def test_event_with_asn_indicator_object(self):
        event = get_event_with_asn_object()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        asn, description, subnet1, subnet2 = (attribute['value'] for attribute in attributes)
        asn_pattern, description_pattern, subnet1_pattern, subnet2_pattern = pattern[1:-1].split(' AND ')
        self.assertEqual(asn_pattern, f"autonomous-system:number = '{int(asn[2:])}'")
        self.assertEqual(description_pattern, f"autonomous-system:name = '{description}'")
        self.assertEqual(
            subnet1_pattern,
            f"autonomous-system:x_misp_subnet_announced = '{subnet1}'"
        )
        self.assertEqual(
            subnet2_pattern,
            f"autonomous-system:x_misp_subnet_announced = '{subnet2}'"
        )

    def test_event_with_asn_observable_object(self):
        event = get_event_with_asn_object()
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        asn, description, subnet1, subnet2 = (attribute['value'] for attribute in attributes)
        self.assertEqual(observable_objects['0'].type, 'autonomous-system')
        self.assertEqual(observable_objects['0'].number, int(asn[2:]))
        self.assertEqual(observable_objects['0'].name, description)
        self.assertEqual(
            observable_objects['0'].x_misp_subnet_announced,
            [subnet1, subnet2]
        )

    def test_event_with_attack_pattern_object(self):
        event = get_event_with_attack_pattern_object()
        orgc = event['Event']['Orgc']
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event)
        identity, report, attack_pattern = self.parser.stix_objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        args = (report, event['Event'], identity_id, timestamp)
        object_ref = self._check_report_features(*args)[0]
        self.assertEqual(report.published, timestamp)
        self.assertEqual(attack_pattern.type, 'attack-pattern')
        self.assertEqual(attack_pattern.id, object_ref)
        self.assertEqual(attack_pattern.created_by_ref, identity_id)
        self._check_killchain(attack_pattern.kill_chain_phases[0], misp_object['meta-category'])
        self._check_object_labels(misp_object, attack_pattern.labels)
        timestamp = self._datetime_from_timestamp(misp_object['timestamp'])
        self.assertEqual(attack_pattern.created, timestamp)
        self.assertEqual(attack_pattern.modified, timestamp)
        id, name, summary = (attribute['value'] for attribute in misp_object['Attribute'])
        self.assertEqual(attack_pattern.name, name)
        self.assertEqual(attack_pattern.description, summary)
        self._check_external_reference(
            attack_pattern.external_references[0],
            'capec',
            f'CAPEC-{id}'
        )

    def test_event_with_course_of_action_object(self):
        event = get_event_with_course_of_action_object()
        orgc = event['Event']['Orgc']
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event)
        identity, report, course_of_action = self.parser.stix_objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        args = (report, event['Event'], identity_id, timestamp)
        object_ref = self._check_report_features(*args)[0]
        self.assertEqual(report.published, timestamp)
        self.assertEqual(course_of_action.type, 'course-of-action')
        self.assertEqual(course_of_action.id, object_ref)
        self.assertEqual(course_of_action.created_by_ref, identity_id)
        self._check_object_labels(misp_object, course_of_action.labels)
        timestamp = self._datetime_from_timestamp(misp_object['timestamp'])
        self.assertEqual(course_of_action.created, timestamp)
        self.assertEqual(course_of_action.modified, timestamp)
        self.assertEqual(course_of_action.name, misp_object['Attribute'][0]['value'])
        for attribute in misp_object['Attribute'][1:]:
            self.assertEqual(
                getattr(
                    course_of_action,
                    f"x_misp_{attribute['object_relation']}"
                ),
                attribute['value']
            )

    def test_event_with_credential_indicator_object(self):
        event = get_event_with_credential_object()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        text, username, password, *attributes = ((attribute['object_relation'], attribute['value']) for attribute in attributes)
        attributes.insert(0, text)
        username_pattern, password_pattern, *pattern = pattern[1:-1].split(' AND ')
        self.assertEqual(username_pattern, f"user-account:user_id = '{username[1]}'")
        self.assertEqual(password_pattern, f"user-account:credential = '{password[1]}'")
        for pattern_part, attribute in zip(pattern, attributes):
            feature, value = attribute
            self.assertEqual(pattern_part, f"user-account:x_misp_{feature} = '{value}'")

    def test_event_with_credential_observable_object(self):
        event = get_event_with_credential_object()
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        user_account = observable_objects['0']
        text, username, password, *attributes = ((attribute['object_relation'], attribute['value']) for attribute in attributes)
        attributes.insert(0, text)
        self.assertEqual(user_account.type, 'user-account')
        self.assertEqual(user_account.user_id, username[1])
        self.assertEqual(user_account.credential, password[1])
        for feature, value in attributes:
            self.assertEqual(getattr(user_account, f'x_misp_{feature}'), value)

    def test_event_with_domain_ip_indicator_object(self):
        event = get_event_with_domain_ip_object()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        domain, ip = (attribute['value'] for attribute in attributes)
        domain_pattern, ip_pattern = pattern[1:-1].split(' AND ')
        self.assertEqual(domain_pattern, f"domain-name:value = '{domain}'")
        self.assertEqual(ip_pattern, f"domain-name:resolves_to_refs[*].value = '{ip}'")

    def test_event_with_domain_ip_observable_object(self):
        event = get_event_with_domain_ip_object()
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        domain, ip = (attribute['value'] for attribute in attributes)
        domain_object = observable_objects['0']
        address_object = observable_objects['1']
        self.assertEqual(domain_object.type, 'domain-name')
        self.assertEqual(domain_object.value, domain)
        self.assertEqual(domain_object.resolves_to_refs, ['1'])
        self.assertEqual(address_object.type, 'ipv4-addr')
        self.assertEqual(address_object.value, ip)

    def test_event_with_email_indicator_object(self):
        event = get_event_with_email_object()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        _from, _to, _cc1, _cc2, _reply_to, _subject, _attachment1, _attachment2, _x_mailer, _user_agent, _boundary = (attribute['value'] for attribute in attributes)
        cc1_, cc2_, from_, reply_to_, subject_, to_, x_mailer_, attachment1_, attachment2_, user_agent_, boundary_ = pattern[1:-1].split(' AND ')
        self.assertEqual(from_, f"email-message:from_ref.value = '{_from}'")
        self.assertEqual(to_, f"email-message:to_refs.value = '{_to}'")
        self.assertEqual(cc1_, f"email-message:cc_refs.value = '{_cc1}'")
        self.assertEqual(cc2_, f"email-message:cc_refs.value = '{_cc2}'")
        self.assertEqual(
            reply_to_,
            f"email-message:additional_header_fields.reply_to = '{_reply_to}'"
        )
        self.assertEqual(subject_, f"email-message:subject = '{_subject}'")
        self.assertEqual(
            attachment1_,
            f"email-message:body_multipart[0].body_raw_ref.name = '{_attachment1}'"
        )
        self.assertEqual(
            attachment2_,
            f"email-message:body_multipart[1].body_raw_ref.name = '{_attachment2}'"
        )
        self.assertEqual(
            x_mailer_,
            f"email-message:additional_header_fields.x_mailer = '{_x_mailer}'"
        )
        self.assertEqual(user_agent_, f"email-message:x_misp_user_agent = '{_user_agent}'")
        self.assertEqual(boundary_, f"email-message:x_misp_mime_boundary = '{_boundary}'")

    def test_event_with_email_observable_object(self):
        event = get_event_with_email_object()
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        _from, _to, _cc1, _cc2, _reply_to, _subject, _attachment1, _attachment2, _x_mailer, _user_agent, _boundary = (attribute['value'] for attribute in attributes)
        message = observable_objects['0']
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, True)
        self.assertEqual(message.subject, _subject)
        additional_header = message.additional_header_fields
        self.assertEqual(additional_header['Reply-To'], _reply_to)
        self.assertEqual(additional_header['X-Mailer'], _x_mailer)
        self.assertEqual(message.x_misp_mime_boundary, _boundary)
        self.assertEqual(message.x_misp_user_agent, _user_agent)
        self.assertEqual(message.from_ref, '1')
        self.assertEqual(message.to_refs, ['2'])
        self.assertEqual(message.cc_refs, ['3', '4'])
        body1, body2 = message.body_multipart
        self.assertEqual(body1['body_raw_ref'], '5')
        self.assertEqual(body1['content_disposition'], f"attachment; filename='{_attachment1}'")
        self.assertEqual(body2['body_raw_ref'], '6')
        self.assertEqual(body2['content_disposition'], f"attachment; filename='{_attachment2}'")
        address1 = observable_objects['1']
        self.assertEqual(address1.type, 'email-addr')
        self.assertEqual(address1.value, _from)
        address2 = observable_objects['2']
        self.assertEqual(address2.type, 'email-addr')
        self.assertEqual(address2.value, _to)
        address3 = observable_objects['3']
        self.assertEqual(address3.type, 'email-addr')
        self.assertEqual(address3.value, _cc1)
        address4 = observable_objects['4']
        self.assertEqual(address4.type, 'email-addr')
        self.assertEqual(address4.value, _cc2)
        file1 = observable_objects['5']
        self.assertEqual(file1.type, 'file')
        self.assertEqual(file1.name, _attachment1)
        file2 = observable_objects['6']
        self.assertEqual(file2.type, 'file')
        self.assertEqual(file2.name, _attachment2)

    def test_event_with_file_indicator_object(self):
        event = get_event_with_file_object_with_artifact()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        _malware_sample, _filename, _md5, _sha1, _sha256, _size, _attachment, _path, _encoding = (attribute['value'] for attribute in attributes)
        md5_, sha1_, sha256_, filename_, encoding_, size_, path_, malware_sample_, attachment_ = self._reassemble_pattern(pattern[1:-1])
        self.assertEqual(md5_, f"file:hashes.MD5 = '{_md5}'")
        self.assertEqual(sha1_, f"file:hashes.SHA1 = '{_sha1}'")
        self.assertEqual(sha256_, f"file:hashes.SHA256 = '{_sha256}'")
        self.assertEqual(filename_, f"file:name = '{_filename}'")
        self.assertEqual(encoding_, f"file:name_enc = '{_encoding}'")
        self.assertEqual(path_, f"file:parent_directory_ref.path = '{_path}'")
        self.assertEqual(size_, f"file:size = '{_size}'")
        ms_data, ms_filename, ms_md5 = malware_sample_.split(' AND ')
        self.assertEqual(ms_data, f"(file:content_ref.payload_bin = '{attributes[0]['data']}'")
        filename, md5 = _malware_sample.split('|')
        self.assertEqual(ms_filename, f"file:content_ref.x_misp_filename = '{filename}'")
        self.assertEqual(ms_md5, f"file:content_ref.hashes.MD5 = '{md5}')")
        a_data, a_filename = attachment_.split(' AND ')
        self.assertEqual(a_data, f"(file:content_ref.payload_bin = '{attributes[6]['data']}'")
        self.assertEqual(a_filename, f"file:content_ref.x_misp_filename = '{_attachment}')")

    def test_event_with_file_observable_object(self):
        event = get_event_with_file_object_with_artifact()
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        _malware_sample, _filename, _md5, _sha1, _sha256, _size, _attachment, _path, _encoding = (attribute['value'] for attribute in attributes)
        file = observable_objects['0']
        self.assertEqual(file.type, 'file')
        self.assertEqual(file.size, int(_size))
        self.assertEqual(file.name, _filename)
        self.assertEqual(file.name_enc, _encoding)
        hashes = file.hashes
        self.assertEqual(hashes['MD5'], _md5)
        self.assertEqual(hashes['SHA-1'], _sha1)
        self.assertEqual(hashes['SHA-256'], _sha256)
        self.assertEqual(file.parent_directory_ref, '1')
        self.assertEqual(file.content_ref, '2')
        directory = observable_objects['1']
        self.assertEqual(directory.type, 'directory')
        self.assertEqual(directory.path, _path)
        artifact1 = observable_objects['2']
        self.assertEqual(artifact1.type, 'artifact')
        self.assertEqual(artifact1.payload_bin, attributes[0]['data'])
        filename, md5 = _malware_sample.split('|')
        self.assertEqual(artifact1.hashes['MD5'], md5)
        self.assertEqual(artifact1.x_misp_filename, filename)
        artifact2 = observable_objects['3']
        self.assertEqual(artifact2.type, 'artifact')
        self.assertEqual(artifact2.payload_bin, attributes[6]['data'])
        self.assertEqual(artifact2.x_misp_filename, _attachment)

    def test_event_with_ip_port_indicator_object(self):
        prefix = 'network-traffic'
        event = get_event_with_ip_port_object()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        ip, port, domain, first_seen = (attribute['value'] for attribute in attributes)
        pattern = pattern[1:-1].split(' AND ')
        self.assertEqual(
            ' AND '.join(pattern[:2]),
            f"({prefix}:dst_ref.type = 'ipv4-addr' AND {prefix}:dst_ref.value = '{ip}')"
        )
        self.assertEqual(
            ' AND '.join(pattern[2:4]),
            f"({prefix}:dst_ref.type = 'domain-name' AND {prefix}:dst_ref.value = '{domain}')"
        )
        self.assertEqual(pattern[4], f"{prefix}:dst_port = '{port}'")
        self.assertEqual(pattern[5], f"{prefix}:start = '{first_seen}'")

    def test_event_with_ip_port_observable_object(self):
        event = get_event_with_ip_port_object()
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        ip, port, domain, first_seen = (attribute['value'] for attribute in attributes)
        network_traffic = observable_objects['0']
        address_object = observable_objects['1']
        self.assertEqual(network_traffic.type, 'network-traffic')
        self.assertEqual(network_traffic.dst_port, int(port))
        self.assertEqual(
            network_traffic.start.strftime('%Y-%m-%dT%H:%M:%SZ'),
            first_seen
        )
        self.assertIn('ipv4', network_traffic.protocols)
        self.assertEqual(network_traffic.dst_ref, '1')
        self.assertEqual(network_traffic.x_misp_domain, domain)
        self.assertEqual(address_object.type, 'ipv4-addr')
        self.assertEqual(address_object.value, ip)

    def test_event_with_network_connection_indicator_object(self):
        event = get_event_with_network_connection_object()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        _ip_src, _ip_dst, _src_port, _dst_port, _hostname, _layer3, _layer4, _layer7 = (attribute['value'] for attribute in attributes)
        ip_src_, ip_dst_, hostname_, dst_port_, src_port_, layer3_, layer4_, layer7_ = self._reassemble_pattern(pattern[1:-1])
        ip_src_type, ip_src_value = ip_src_.split(' AND ')
        self.assertEqual(ip_src_type, "(network-traffic:src_ref.type = 'ipv4-addr'")
        self.assertEqual(ip_src_value, f"network-traffic:src_ref.value = '{_ip_src}')")
        ip_dst_type, ip_dst_value = ip_dst_.split(' AND ')
        self.assertEqual(ip_dst_type, "(network-traffic:dst_ref.type = 'ipv4-addr'")
        self.assertEqual(ip_dst_value, f"network-traffic:dst_ref.value = '{_ip_dst}')")
        hostname_type, hostname_value = hostname_.split(' AND ')
        self.assertEqual(hostname_type, "(network-traffic:dst_ref.type = 'domain-name'")
        self.assertEqual(hostname_value, f"network-traffic:dst_ref.value = '{_hostname}')")
        self.assertEqual(dst_port_, f"network-traffic:dst_port = '{_dst_port}'")
        self.assertEqual(src_port_, f"network-traffic:src_port = '{_src_port}'")
        self.assertEqual(layer3_, f"network-traffic:protocols[0] = '{_layer3}'")
        self.assertEqual(layer4_, f"network-traffic:protocols[1] = '{_layer4}'")
        self.assertEqual(layer7_, f"network-traffic:protocols[2] = '{_layer7}'")

    def test_event_with_network_connection_observable_object(self):
        event = get_event_with_network_connection_object()
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        ip_src, ip_dst, src_port, dst_port, hostname, layer3, layer4, layer7 = (attribute['value'] for attribute in attributes)
        network_traffic = observable_objects['0']
        self.assertEqual(network_traffic.type, 'network-traffic')
        self.assertEqual(network_traffic.src_port, int(src_port))
        self.assertEqual(network_traffic.dst_port, int(dst_port))
        self.assertEqual(network_traffic.protocols, [layer3, layer4, layer7])
        self.assertEqual(network_traffic.src_ref, '1')
        self.assertEqual(network_traffic.dst_ref, '2')
        self.assertEqual(network_traffic.x_misp_hostname_dst, hostname)
        address1 = observable_objects['1']
        self.assertEqual(address1.type, 'ipv4-addr')
        self.assertEqual(address1.value, ip_src)
        address2 = observable_objects['2']
        self.assertEqual(address2.type, 'ipv4-addr')
        self.assertEqual(address2.value, ip_dst)

    ################################################################################
    #                            GALAXIES EXPORT TESTS.                            #
    ################################################################################

    def test_event_with_attack_pattern_galaxy(self):
        event = get_event_with_attack_pattern_galaxy()
        galaxy = event['Event']['Galaxy'][0]
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        attack_pattern = self._run_galaxy_tests(event, timestamp)
        self.assertEqual(attack_pattern.type, 'attack-pattern')
        self._check_galaxy_features(attack_pattern, galaxy, timestamp, True, False)

    def test_event_with_course_of_action_galaxy(self):
        event = get_event_with_course_of_action_galaxy()
        galaxy = event['Event']['Galaxy'][0]
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        course_of_action = self._run_galaxy_tests(event, timestamp)
        self.assertEqual(course_of_action.type, 'course-of-action')
        self._check_galaxy_features(course_of_action, galaxy, timestamp, False, False)

    def test_event_with_malware_galaxy(self):
        event = get_event_with_malware_galaxy()
        galaxy = event['Event']['Galaxy'][0]
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        malware = self._run_galaxy_tests(event, timestamp)
        self.assertEqual(malware.type, 'malware')
        self._check_galaxy_features(malware, galaxy, timestamp, True, False)

    def test_event_with_threat_actor_galaxy(self):
        event = get_event_with_threat_actor_galaxy()
        galaxy = event['Event']['Galaxy'][0]
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        threat_actor = self._run_galaxy_tests(event, timestamp)
        self.assertEqual(threat_actor.type, 'threat-actor')
        self._check_galaxy_features(threat_actor, galaxy, timestamp, False, True)

    def test_event_with_tool_galaxy(self):
        event = get_event_with_tool_galaxy()
        galaxy = event['Event']['Galaxy'][0]
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        tool = self._run_galaxy_tests(event, timestamp)
        self.assertEqual(tool.type, 'tool')
        self._check_galaxy_features(tool, galaxy, timestamp, True, False)

    def test_event_with_vulnerability_galaxy(self):
        event = get_event_with_vulnerability_galaxy()
        galaxy = event['Event']['Galaxy'][0]
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        vulnerability = self._run_galaxy_tests(event, timestamp)
        self.assertEqual(vulnerability.type, 'vulnerability')
        self._check_galaxy_features(vulnerability, galaxy, timestamp, False, False)


class TestSTIX21Export(TestSTIX2Export):
    def setUp(self):
        self.parser = MISPtoSTIX21Parser()

    ################################################################################
    #                              UTILITY FUNCTIONS.                              #
    ################################################################################

    def _check_bundle_features(self, length):
        bundle = self.parser.bundle
        self.assertEqual(bundle.type, 'bundle')
        self.assertEqual(len(bundle.objects), length)
        return bundle.objects

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

    def _run_galaxy_tests(self, event, timestamp):
        orgc = event['Event']['Orgc']
        self.parser.parse_misp_event(event)
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, stix_object = stix_objects
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        args = (grouping, event['Event'], identity_id)
        object_ref = self._check_grouping_features(*args)[0]
        self.assertEqual(stix_object.id, object_ref)
        return stix_object

    def _run_indicator_from_object_tests(self, event):
        self._add_object_ids_flag(event)
        orgc = event['Event']['Orgc']
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event)
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, indicator = stix_objects
        identity_id = self._check_identity_features(
            identity,
            orgc,
            self._datetime_from_timestamp(event['Event']['timestamp'])
        )
        args = (grouping, event['Event'], identity_id)
        object_ref = self._check_grouping_features(*args)[0]
        self._check_object_indicator_features(indicator, misp_object, identity_id, object_ref)
        self._check_pattern_features(indicator)
        return misp_object['Attribute'], indicator.pattern

    def _run_indicator_tests(self, event):
        self._add_attribute_ids_flag(event)
        orgc = event['Event']['Orgc']
        attribute = event['Event']['Attribute'][0]
        self.parser.parse_misp_event(event)
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, indicator = stix_objects
        identity_id = self._check_identity_features(
            identity,
            orgc,
            self._datetime_from_timestamp(event['Event']['timestamp'])
        )
        args = (grouping, event['Event'], identity_id)
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
        identity_id = self._check_identity_features(
            identity,
            orgc,
            self._datetime_from_timestamp(event['Event']['timestamp'])
        )
        args = (grouping, event['Event'], identity_id)
        object_refs = self._check_grouping_features(*args)
        for attribute, indicator, object_ref in zip(attributes, indicators, object_refs):
            self._check_attribute_indicator_features(indicator, attribute, identity_id, object_ref)
            self._check_pattern_features(indicator)
        attribute_values = (attribute['value'] for attribute in attributes)
        patterns = (indicator.pattern for indicator in indicators)
        return attribute_values, patterns

    def _run_observable_from_object_tests(self, event):
        self._remove_object_ids_flags(event)
        orgc = event['Event']['Orgc']
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event)
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, observed_data, *observable = stix_objects
        identity_id = self._check_identity_features(
            identity,
            orgc,
            self._datetime_from_timestamp(event['Event']['timestamp'])
        )
        observable_id, *ids = self._check_grouping_features(
            grouping,
            event['Event'],
            identity_id
        )
        self._check_object_observable_features(
            observed_data,
            misp_object,
            identity_id,
            observable_id
        )
        return misp_object['Attribute'], ids, observed_data['object_refs'], observable

    def _run_observable_tests(self, event):
        self._remove_attribute_ids_flag(event)
        orgc = event['Event']['Orgc']
        attribute = event['Event']['Attribute'][0]
        self.parser.parse_misp_event(event)
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, observed_data, *observable = stix_objects
        identity_id = self._check_identity_features(
            identity,
            orgc,
            self._datetime_from_timestamp(event['Event']['timestamp'])
        )
        observable_id, *ids = self._check_grouping_features(
            grouping,
            event['Event'],
            identity_id
        )
        self._check_attribute_observable_features(
            observed_data,
            attribute,
            identity_id,
            observable_id
        )
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
        identity_id = self._check_identity_features(
            identity,
            orgc,
            self._datetime_from_timestamp(event['Event']['timestamp'])
        )
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

    ################################################################################
    #                              EVENT FIELDS TESTS                              #
    ################################################################################

    def test_base_event(self):
        event = get_base_event()
        orgc = event['Event']['Orgc']
        self.parser.parse_misp_event(event)
        stix_objects = self._check_bundle_features(3)
        self._check_spec_versions(stix_objects)
        identity, grouping, note = stix_objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        args = (
            grouping,
            event['Event'],
            identity_id
        )
        object_ref = self._check_grouping_features(*args)[0]
        self.assertEqual(note.type, 'note')
        self.assertEqual(note.id, f"note--{event['Event']['uuid']}")
        self.assertEqual(note.created_by_ref, identity_id)
        self.assertEqual(note.created, timestamp)
        self.assertEqual(note.modified, timestamp)
        self.assertEqual(
            note.content,
            "This MISP Event is empty and contains no attribute, object, galaxy or tag."
        )
        self.assertEqual(note.object_refs, [grouping.id])

    def test_published_event(self):
        event = get_published_event()
        orgc = event['Event']['Orgc']
        self.parser.parse_misp_event(event)
        stix_objects = self._check_bundle_features(3)
        self._check_spec_versions(stix_objects)
        identity, report, _ = stix_objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        self._check_report_features(report, event['Event'], identity_id, timestamp)
        self.assertEqual(
            report.published,
            self._datetime_from_timestamp(event['Event']['publish_timestamp'])
        )

    def test_event_with_tags(self):
        event = get_event_with_tags()
        orgc = event['Event']['Orgc']
        self.parser.parse_misp_event(event)
        stix_objects = self._check_bundle_features(4)
        self._check_spec_versions(stix_objects)
        _, _, _, marking = stix_objects
        self.assertEqual(marking.definition_type, 'tlp')
        self.assertEqual(marking.definition['tlp'], 'white')

    ################################################################################
    #                        SINGLE ATTRIBUTES EXPORT TESTS                        #
    ################################################################################

    def test_embedded_indicator_attribute_galaxy(self):
        event = get_embedded_indicator_attribute_galaxy()
        orgc = event['Event']['Orgc']
        attribute = event['Event']['Attribute'][0]
        self.parser.parse_misp_event(event)
        stix_objects = self._check_bundle_features(8)
        self._check_spec_versions(stix_objects)
        identity, grouping, attack_pattern, course_of_action, indicator, malware, *relationships = stix_objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        args = (
            grouping,
            event['Event'],
            identity_id
        )
        object_refs = self._check_grouping_features(*args)
        ap_ref, coa_ref, indicator_ref, malware_ref, apr_ref, coar_ref = object_refs
        ap_relationship, coa_relationship = relationships
        self.assertEqual(attack_pattern.id, ap_ref)
        self.assertEqual(course_of_action.id, coa_ref)
        self.assertEqual(indicator.id, indicator_ref)
        self.assertEqual(malware.id, malware_ref)
        self.assertEqual(ap_relationship.id, apr_ref)
        self.assertEqual(coa_relationship.id, coar_ref)
        timestamp = self._datetime_from_timestamp(attribute['timestamp'])
        self._check_relationship_features(ap_relationship, indicator_ref, ap_ref, 'indicates', timestamp)
        self._check_relationship_features(coa_relationship, indicator_ref, coa_ref, 'has', timestamp)

    def test_embedded_non_indicator_attribute_galaxy(self):
        event = get_embedded_non_indicator_attribute_galaxy()
        orgc = event['Event']['Orgc']
        attribute = event['Event']['Attribute'][0]
        self.parser.parse_misp_event(event)
        stix_objects = self._check_bundle_features(8)
        self._check_spec_versions(stix_objects)
        identity, grouping, attack_pattern, course_of_action, vulnerability, malware, *relationships = stix_objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        args = (
            grouping,
            event['Event'],
            identity_id
        )
        object_refs = self._check_grouping_features(*args)
        ap_ref, coa_ref, vulnerability_ref, malware_ref, apr_ref, coar_ref = object_refs
        ap_relationship, coa_relationship = relationships
        self.assertEqual(attack_pattern.id, ap_ref)
        self.assertEqual(course_of_action.id, coa_ref)
        self.assertEqual(vulnerability.id, vulnerability_ref)
        self.assertEqual(malware.id, malware_ref)
        self.assertEqual(ap_relationship.id, apr_ref)
        self.assertEqual(coa_relationship.id, coar_ref)
        timestamp = self._datetime_from_timestamp(attribute['timestamp'])
        self._check_relationship_features(ap_relationship, vulnerability_ref, ap_ref, 'has', timestamp)
        self._check_relationship_features(coa_relationship, vulnerability_ref, coa_ref, 'has', timestamp)

    def test_embedded_observable_attribute_galaxy(self):
        event = get_embedded_observable_attribute_galaxy()
        orgc = event['Event']['Orgc']
        attribute = event['Event']['Attribute'][0]
        galaxy = event['Event']['Galaxy'][0]
        cluster = galaxy['GalaxyCluster'][0]
        self.parser.parse_misp_event(event)
        stix_objects = self._check_bundle_features(7)
        self._check_spec_versions(stix_objects)
        identity, grouping, attack_pattern, observed_data, autonomous_system, malware, relationship = stix_objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        args = (
            grouping,
            event['Event'],
            identity_id
        )
        object_refs = self._check_grouping_features(*args)
        ap_ref, od_ref, as_ref, malware_ref, relationship_ref = object_refs
        self.assertEqual(attack_pattern.id, ap_ref)
        self.assertEqual(observed_data.id, od_ref)
        self.assertEqual(autonomous_system.id, as_ref)
        self.assertEqual(malware.id, malware_ref)
        self.assertEqual(relationship.id, relationship_ref)
        self._check_relationship_features(
            relationship,
            od_ref,
            ap_ref,
            'has',
            self._datetime_from_timestamp(attribute['timestamp'])
        )

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
        identity_id = self._check_identity_features(
            identity,
            orgc,
            self._datetime_from_timestamp(event['Event']['timestamp'])
        )
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

    def test_event_with_custom_attributes(self):
        event = get_event_with_stix2_custom_attributes()
        orgc = event['Event']['Orgc']
        attributes = event['Event']['Attribute']
        self.parser.parse_misp_event(event)
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, *custom_objects = stix_objects
        identity_id = self._check_identity_features(
            identity,
            orgc,
            self._datetime_from_timestamp(event['Event']['timestamp'])
        )
        args = (
            grouping,
            event['Event'],
            identity_id
        )
        object_refs = self._check_grouping_features(*args)
        for attribute, custom_object, object_ref in zip(attributes, custom_objects, object_refs):
            attribute_type = attribute['type']
            category = attribute['category']
            custom_type = f"x-misp-attribute"
            self.assertEqual(custom_object.type, custom_type)
            self.assertEqual(object_ref, f"{custom_type}--{attribute['uuid']}")
            self.assertEqual(custom_object.id, object_ref)
            self.assertEqual(custom_object.created_by_ref, identity_id)
            self.assertEqual(custom_object.labels[0], f'misp:type="{attribute_type}"')
            self.assertEqual(custom_object.labels[1], f'misp:category="{category}"')
            if attribute.get('to_ids', False):
                self.assertEqual(custom_object.labels[2], 'misp:to_ids="True"')
            self.assertEqual(custom_object.x_misp_type, attribute['type'])
            self.assertEqual(custom_object.x_misp_category, category)
            if attribute.get('comment'):
                self.assertEqual(custom_object.x_misp_comment, attribute['comment'])
            self.assertEqual(custom_object.x_misp_value, attribute['value'])

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

    def test_event_with_malware_sample_indicator_attribute(self):
        event = get_event_with_malware_sample_attribute()
        data = event['Event']['Attribute'][0]['data']
        attribute_value, pattern = self._run_indicator_tests(event)
        filename, hash_value = attribute_value.split('|')
        file_pattern = f"file:name = '{filename}'"
        hash_pattern = f"file:hashes.MD5 = '{hash_value}'"
        data_pattern = f"file:content_ref.payload_bin = '{data}'"
        self.assertEqual(pattern, f"[{file_pattern} AND {hash_pattern} AND {data_pattern}]")

    def test_event_with_malware_sample_observable_attribute(self):
        event = get_event_with_malware_sample_attribute()
        data = event['Event']['Attribute'][0]['data']
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        file_id, artifact_id = grouping_refs
        file_ref, artifact_ref = object_refs
        file_object, artifact_object = observable
        filename, hash_value = attribute_value.split('|')
        self.assertEqual(file_ref, file_id)
        self.assertEqual(file_object.id, file_ref)
        self.assertEqual(file_object.type, 'file')
        self.assertEqual(file_object.name, filename)
        self.assertEqual(file_object.hashes['MD5'], hash_value)
        self.assertEqual(file_object.content_ref, artifact_id)
        self.assertEqual(artifact_ref, artifact_id)
        self.assertEqual(artifact_object.id, artifact_ref)
        self.assertEqual(artifact_object.type, 'artifact')
        self.assertEqual(artifact_object.payload_bin, data)

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
        identity_id = self._check_identity_features(
            identity,
            orgc,
            self._datetime_from_timestamp(event['Event']['timestamp'])
        )
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
        self._check_external_reference(
            vulnerability.external_references[0],
            'cve',
            attribute['value']
        )

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

    ################################################################################
    #                          MISP OBJECTS EXPORT TESTS.                          #
    ################################################################################

    def test_event_with_asn_indicator_object(self):
        event = get_event_with_asn_object()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        asn, description, subnet1, subnet2 = (attribute['value'] for attribute in attributes)
        asn_pattern, description_pattern, subnet1_pattern, subnet2_pattern = pattern[1:-1].split(' AND ')
        self.assertEqual(asn_pattern, f"autonomous-system:number = '{int(asn[2:])}'")
        self.assertEqual(description_pattern, f"autonomous-system:name = '{description}'")
        self.assertEqual(
            subnet1_pattern,
            f"autonomous-system:x_misp_subnet_announced = '{subnet1}'"
        )
        self.assertEqual(
            subnet2_pattern,
            f"autonomous-system:x_misp_subnet_announced = '{subnet2}'"
        )

    def test_event_with_asn_observable_object(self):
        event = get_event_with_asn_object()
        attributes, grouping_refs, object_refs, observable = self._run_observable_from_object_tests(event)
        asn, description, subnet1, subnet2 = (attribute['value'] for attribute in attributes)
        object_ref = object_refs[0]
        autonomous_system = observable[0]
        self.assertEqual(object_ref, grouping_refs[0])
        self.assertEqual(autonomous_system.id, object_ref)
        self.assertEqual(autonomous_system.type, 'autonomous-system')
        self.assertEqual(autonomous_system.number, int(asn[2:]))
        self.assertEqual(autonomous_system.name, description)
        self.assertEqual(
            autonomous_system.x_misp_subnet_announced,
            [subnet1, subnet2]
        )

    def test_event_with_attack_pattern_object(self):
        event = get_event_with_attack_pattern_object()
        orgc = event['Event']['Orgc']
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event)
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, attack_pattern = stix_objects
        identity_id = self._check_identity_features(
            identity,
            orgc,
            self._datetime_from_timestamp(event['Event']['timestamp'])
        )
        args = (grouping, event['Event'], identity_id)
        object_ref = self._check_grouping_features(*args)[0]
        self.assertEqual(attack_pattern.type, 'attack-pattern')
        self.assertEqual(attack_pattern.id, object_ref)
        self.assertEqual(attack_pattern.created_by_ref, identity_id)
        self._check_killchain(attack_pattern.kill_chain_phases[0], misp_object['meta-category'])
        self._check_object_labels(misp_object, attack_pattern.labels)
        timestamp = self._datetime_from_timestamp(misp_object['timestamp'])
        self.assertEqual(attack_pattern.created, timestamp)
        self.assertEqual(attack_pattern.modified, timestamp)
        id, name, summary = (attribute['value'] for attribute in misp_object['Attribute'])
        self.assertEqual(attack_pattern.name, name)
        self.assertEqual(attack_pattern.description, summary)
        self._check_external_reference(
            attack_pattern.external_references[0],
            'capec',
            f'CAPEC-{id}'
        )

    def test_event_with_course_of_action_object(self):
        event = get_event_with_course_of_action_object()
        orgc = event['Event']['Orgc']
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event)
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, course_of_action = stix_objects
        identity_id = self._check_identity_features(
            identity,
            orgc,
            self._datetime_from_timestamp(event['Event']['timestamp'])
        )
        args = (grouping, event['Event'], identity_id)
        object_ref = self._check_grouping_features(*args)[0]
        self.assertEqual(course_of_action.type, 'course-of-action')
        self.assertEqual(course_of_action.id, object_ref)
        self.assertEqual(course_of_action.created_by_ref, identity_id)
        self._check_object_labels(misp_object, course_of_action.labels)
        timestamp = self._datetime_from_timestamp(misp_object['timestamp'])
        self.assertEqual(course_of_action.created, timestamp)
        self.assertEqual(course_of_action.modified, timestamp)
        self.assertEqual(course_of_action.name, misp_object['Attribute'][0]['value'])
        for attribute in misp_object['Attribute'][1:]:
            self.assertEqual(
                getattr(
                    course_of_action,
                    f"x_misp_{attribute['object_relation']}"
                ),
                attribute['value']
            )

    def test_event_with_credential_indicator_object(self):
        event = get_event_with_credential_object()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        text, username, password, *attributes = ((attribute['object_relation'], attribute['value']) for attribute in attributes)
        attributes.insert(0, text)
        username_pattern, password_pattern, *pattern = pattern[1:-1].split(' AND ')
        self.assertEqual(username_pattern, f"user-account:user_id = '{username[1]}'")
        self.assertEqual(password_pattern, f"user-account:credential = '{password[1]}'")
        for pattern_part, attribute in zip(pattern, attributes):
            feature, value = attribute
            self.assertEqual(pattern_part, f"user-account:x_misp_{feature} = '{value}'")

    def test_event_with_credential_observable_object(self):
        event = get_event_with_credential_object()
        attributes, grouping_refs, object_refs, observable = self._run_observable_from_object_tests(event)
        text, username, password, *attributes = ((attribute['object_relation'], attribute['value']) for attribute in attributes)
        attributes.insert(0, text)
        object_ref = object_refs[0]
        user_account = observable[0]
        self.assertEqual(object_ref, grouping_refs[0])
        self.assertEqual(user_account.id, object_ref)
        self.assertEqual(user_account.type, 'user-account')
        self.assertEqual(user_account.user_id, username[1])
        self.assertEqual(user_account.credential, password[1])
        for feature, value in attributes:
            self.assertEqual(getattr(user_account, f'x_misp_{feature}'), value)

    def test_event_with_domain_ip_indicator_object(self):
        event = get_event_with_domain_ip_object()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        domain, ip = (attribute['value'] for attribute in attributes)
        domain_pattern, ip_pattern = pattern[1:-1].split(' AND ')
        self.assertEqual(domain_pattern, f"domain-name:value = '{domain}'")
        self.assertEqual(ip_pattern, f"domain-name:resolves_to_refs[*].value = '{ip}'")

    def test_event_with_domain_ip_observable_object(self):
        event = get_event_with_domain_ip_object()
        attributes, grouping_refs, object_refs, observable = self._run_observable_from_object_tests(event)
        domain, ip = (attribute['value'] for attribute in attributes)
        domain_ref, address_ref = object_refs
        domain_object, address_object = observable
        self.assertEqual(domain_ref, grouping_refs[0])
        self.assertEqual(address_ref, grouping_refs[1])
        self.assertEqual(domain_object.id, domain_ref)
        self.assertEqual(domain_object.type, 'domain-name')
        self.assertEqual(domain_object.value, domain)
        self.assertEqual(domain_object.resolves_to_refs, [address_ref])
        self.assertEqual(address_object.id, address_ref)
        self.assertEqual(address_object.value, ip)

    def test_event_with_email_indicator_object(self):
        event = get_event_with_email_object()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        _from, _to, _cc1, _cc2, _reply_to, _subject, _attachment1, _attachment2, _x_mailer, _user_agent, _boundary = (attribute['value'] for attribute in attributes)
        cc1_, cc2_, from_, reply_to_, subject_, to_, x_mailer_, attachment1_, attachment2_, user_agent_, boundary_ = pattern[1:-1].split(' AND ')
        self.assertEqual(from_, f"email-message:from_ref.value = '{_from}'")
        self.assertEqual(to_, f"email-message:to_refs.value = '{_to}'")
        self.assertEqual(cc1_, f"email-message:cc_refs.value = '{_cc1}'")
        self.assertEqual(cc2_, f"email-message:cc_refs.value = '{_cc2}'")
        self.assertEqual(
            reply_to_,
            f"email-message:additional_header_fields.reply_to = '{_reply_to}'"
        )
        self.assertEqual(subject_, f"email-message:subject = '{_subject}'")
        self.assertEqual(
            attachment1_,
            f"email-message:body_multipart[0].body_raw_ref.name = '{_attachment1}'"
        )
        self.assertEqual(
            attachment2_,
            f"email-message:body_multipart[1].body_raw_ref.name = '{_attachment2}'"
        )
        self.assertEqual(
            x_mailer_,
            f"email-message:additional_header_fields.x_mailer = '{_x_mailer}'"
        )
        self.assertEqual(user_agent_, f"email-message:x_misp_user_agent = '{_user_agent}'")
        self.assertEqual(boundary_, f"email-message:x_misp_mime_boundary = '{_boundary}'")

    def test_event_with_email_observable_object(self):
        event = get_event_with_email_object()
        attributes, grouping_refs, object_refs, observables = self._run_observable_from_object_tests(event)
        _from, _to, _cc1, _cc2, _reply_to, _subject, _attachment1, _attachment2, _x_mailer, _user_agent, _boundary = (attribute['value'] for attribute in attributes)
        message, address1, address2, address3, address4, file1, file2 = observables
        for grouping_ref, object_ref in zip(grouping_refs, object_refs):
            self.assertEqual(grouping_ref, object_ref)
        message_ref, address1_ref, address2_ref, address3_ref, address4_ref, file1_ref, file2_ref = grouping_refs
        self.assertEqual(message.id, message_ref)
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, True)
        self.assertEqual(message.subject, _subject)
        additional_header = message.additional_header_fields
        self.assertEqual(additional_header['Reply-To'], _reply_to)
        self.assertEqual(additional_header['X-Mailer'], _x_mailer)
        self.assertEqual(message.x_misp_mime_boundary, _boundary)
        self.assertEqual(message.x_misp_user_agent, _user_agent)
        self.assertEqual(message.from_ref, address1_ref)
        self.assertEqual(message.to_refs, [address2_ref])
        self.assertEqual(message.cc_refs, [address3_ref, address4_ref])
        body1, body2 = message.body_multipart
        self.assertEqual(body1['body_raw_ref'], file1_ref)
        self.assertEqual(body1['content_disposition'], f"attachment; filename='{_attachment1}'")
        self.assertEqual(body2['body_raw_ref'], file2_ref)
        self.assertEqual(body2['content_disposition'], f"attachment; filename='{_attachment2}'")
        self.assertEqual(address1.id, address1_ref)
        self.assertEqual(address1.type, 'email-addr')
        self.assertEqual(address1.value, _from)
        self.assertEqual(address2.id, address2_ref)
        self.assertEqual(address2.type, 'email-addr')
        self.assertEqual(address2.value, _to)
        self.assertEqual(address3.id, address3_ref)
        self.assertEqual(address3.type, 'email-addr')
        self.assertEqual(address3.value, _cc1)
        self.assertEqual(address4.id, address4_ref)
        self.assertEqual(address4.type, 'email-addr')
        self.assertEqual(address4.value, _cc2)
        self.assertEqual(file1.id, file1_ref)
        self.assertEqual(file1.type, 'file')
        self.assertEqual(file1.name, _attachment1)
        self.assertEqual(file2.id, file2_ref)
        self.assertEqual(file2.type, 'file')
        self.assertEqual(file2.name, _attachment2)

    def test_event_with_file_indicator_object(self):
        event = get_event_with_file_object_with_artifact()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        _malware_sample, _filename, _md5, _sha1, _sha256, _size, _attachment, _path, _encoding = (attribute['value'] for attribute in attributes)
        md5_, sha1_, sha256_, filename_, encoding_, size_, path_, malware_sample_, attachment_ = self._reassemble_pattern(pattern[1:-1])
        self.assertEqual(md5_, f"file:hashes.MD5 = '{_md5}'")
        self.assertEqual(sha1_, f"file:hashes.SHA1 = '{_sha1}'")
        self.assertEqual(sha256_, f"file:hashes.SHA256 = '{_sha256}'")
        self.assertEqual(filename_, f"file:name = '{_filename}'")
        self.assertEqual(encoding_, f"file:name_enc = '{_encoding}'")
        self.assertEqual(path_, f"file:parent_directory_ref.path = '{_path}'")
        self.assertEqual(size_, f"file:size = '{_size}'")
        ms_data, ms_filename, ms_md5 = malware_sample_.split(' AND ')
        self.assertEqual(ms_data, f"(file:content_ref.payload_bin = '{attributes[0]['data']}'")
        filename, md5 = _malware_sample.split('|')
        self.assertEqual(ms_filename, f"file:content_ref.x_misp_filename = '{filename}'")
        self.assertEqual(ms_md5, f"file:content_ref.hashes.MD5 = '{md5}')")
        a_data, a_filename = attachment_.split(' AND ')
        self.assertEqual(a_data, f"(file:content_ref.payload_bin = '{attributes[6]['data']}'")
        self.assertEqual(a_filename, f"file:content_ref.x_misp_filename = '{_attachment}')")

    def test_event_with_file_observable_object(self):
        event = get_event_with_file_object_with_artifact()
        attributes, grouping_refs, object_refs, observables = self._run_observable_from_object_tests(event)
        _malware_sample, _filename, _md5, _sha1, _sha256, _size, _attachment, _path, _encoding = (attribute['value'] for attribute in attributes)
        file, directory, artifact1, artifact2 = observables
        for grouping_ref, object_ref in zip(grouping_refs, object_refs):
            self.assertEqual(grouping_ref, object_ref)
        file_ref, directory_ref, artifact1_ref, artifact2_ref = grouping_refs
        self.assertEqual(file.id, file_ref)
        self.assertEqual(file.type, 'file')
        self.assertEqual(file.size, int(_size))
        self.assertEqual(file.name, _filename)
        self.assertEqual(file.name_enc, _encoding)
        hashes = file.hashes
        self.assertEqual(hashes['MD5'], _md5)
        self.assertEqual(hashes['SHA-1'], _sha1)
        self.assertEqual(hashes['SHA-256'], _sha256)
        self.assertEqual(file.parent_directory_ref, directory_ref)
        self.assertEqual(file.content_ref, artifact1_ref)
        self.assertEqual(directory.id, directory_ref)
        self.assertEqual(directory.type, 'directory')
        self.assertEqual(directory.path, _path)
        self.assertEqual(artifact1.id, artifact1_ref)
        self.assertEqual(artifact1.type, 'artifact')
        self.assertEqual(artifact1.payload_bin, attributes[0]['data'])
        filename, md5 = _malware_sample.split('|')
        self.assertEqual(artifact1.hashes['MD5'], md5)
        self.assertEqual(artifact1.x_misp_filename, filename)
        self.assertEqual(artifact2.id, artifact2_ref)
        self.assertEqual(artifact2.type, 'artifact')
        self.assertEqual(artifact2.payload_bin, attributes[6]['data'])
        self.assertEqual(artifact2.x_misp_filename, _attachment)

    def test_event_with_ip_port_indicator_object(self):
        prefix = 'network-traffic'
        event = get_event_with_ip_port_object()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        ip, port, domain, first_seen = (attribute['value'] for attribute in attributes)
        pattern = pattern[1:-1].split(' AND ')
        self.assertEqual(
            ' AND '.join(pattern[:2]),
            f"({prefix}:dst_ref.type = 'ipv4-addr' AND {prefix}:dst_ref.value = '{ip}')"
        )
        self.assertEqual(
            ' AND '.join(pattern[2:4]),
            f"({prefix}:dst_ref.type = 'domain-name' AND {prefix}:dst_ref.value = '{domain}')"
        )
        self.assertEqual(pattern[4], f"{prefix}:dst_port = '{port}'")
        self.assertEqual(pattern[5], f"{prefix}:start = '{first_seen}'")

    def test_event_with_ip_port_observable_object(self):
        event = get_event_with_ip_port_object()
        attributes, grouping_refs, object_refs, observables = self._run_observable_from_object_tests(event)
        ip, port, domain, first_seen = (attribute['value'] for attribute in attributes)
        network_traffic_ref, address_ref = object_refs
        network_traffic, address_object = observables
        self.assertEqual(network_traffic_ref, grouping_refs[0])
        self.assertEqual(address_ref, grouping_refs[1])
        self.assertEqual(network_traffic.id, network_traffic_ref)
        self.assertEqual(network_traffic.type, 'network-traffic')
        self.assertEqual(network_traffic.dst_port, int(port))
        self.assertEqual(
            network_traffic.start.strftime('%Y-%m-%dT%H:%M:%SZ'),
            first_seen
        )
        self.assertIn('ipv4', network_traffic.protocols)
        self.assertEqual(network_traffic.dst_ref, address_ref)
        self.assertEqual(network_traffic.x_misp_domain, domain)
        self.assertEqual(address_object.id, address_ref)
        self.assertEqual(address_object.type, 'ipv4-addr')
        self.assertEqual(address_object.value, ip)

    def test_event_with_network_connection_indicator_object(self):
        event = get_event_with_network_connection_object()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        _ip_src, _ip_dst, _src_port, _dst_port, _hostname, _layer3, _layer4, _layer7 = (attribute['value'] for attribute in attributes)
        ip_src_, ip_dst_, hostname_, dst_port_, src_port_, layer3_, layer4_, layer7_ = self._reassemble_pattern(pattern[1:-1])
        ip_src_type, ip_src_value = ip_src_.split(' AND ')
        self.assertEqual(ip_src_type, "(network-traffic:src_ref.type = 'ipv4-addr'")
        self.assertEqual(ip_src_value, f"network-traffic:src_ref.value = '{_ip_src}')")
        ip_dst_type, ip_dst_value = ip_dst_.split(' AND ')
        self.assertEqual(ip_dst_type, "(network-traffic:dst_ref.type = 'ipv4-addr'")
        self.assertEqual(ip_dst_value, f"network-traffic:dst_ref.value = '{_ip_dst}')")
        hostname_type, hostname_value = hostname_.split(' AND ')
        self.assertEqual(hostname_type, "(network-traffic:dst_ref.type = 'domain-name'")
        self.assertEqual(hostname_value, f"network-traffic:dst_ref.value = '{_hostname}')")
        self.assertEqual(dst_port_, f"network-traffic:dst_port = '{_dst_port}'")
        self.assertEqual(src_port_, f"network-traffic:src_port = '{_src_port}'")
        self.assertEqual(layer3_, f"network-traffic:protocols[0] = '{_layer3}'")
        self.assertEqual(layer4_, f"network-traffic:protocols[1] = '{_layer4}'")
        self.assertEqual(layer7_, f"network-traffic:protocols[2] = '{_layer7}'")

    def test_event_with_network_connection_observable_object(self):
        event = get_event_with_network_connection_object()
        attributes, grouping_refs, object_refs, observables = self._run_observable_from_object_tests(event)
        ip_src, ip_dst, src_port, dst_port, hostname, layer3, layer4, layer7 = (attribute['value'] for attribute in attributes)
        for grouping_ref, object_ref in zip(grouping_refs, object_refs):
            self.assertEqual(grouping_ref, object_ref)
        network_traffic, address1, address2 = observables
        network_traffic_ref, address1_ref, address2_ref = grouping_refs
        self.assertEqual(network_traffic.id, network_traffic_ref)
        self.assertEqual(network_traffic.type, 'network-traffic')
        self.assertEqual(network_traffic.src_port, int(src_port))
        self.assertEqual(network_traffic.dst_port, int(dst_port))
        self.assertEqual(network_traffic.protocols, [layer3, layer4, layer7])
        self.assertEqual(network_traffic.src_ref, address1_ref)
        self.assertEqual(network_traffic.dst_ref, address2_ref)
        self.assertEqual(network_traffic.x_misp_hostname_dst, hostname)
        self.assertEqual(address1.id, address1_ref)
        self.assertEqual(address1.type, 'ipv4-addr')
        self.assertEqual(address1.value, ip_src)
        self.assertEqual(address2.id, address2_ref)
        self.assertEqual(address2.type, 'ipv4-addr')
        self.assertEqual(address2.value, ip_dst)

    ################################################################################
    #                            GALAXIES EXPORT TESTS.                            #
    ################################################################################

    def test_event_with_attack_pattern_galaxy(self):
        event = get_event_with_attack_pattern_galaxy()
        galaxy = event['Event']['Galaxy'][0]
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        attack_pattern = self._run_galaxy_tests(event, timestamp)
        self.assertEqual(attack_pattern.type, 'attack-pattern')
        self._check_galaxy_features(attack_pattern, galaxy, timestamp, True, False)

    def test_event_with_course_of_action_galaxy(self):
        event = get_event_with_course_of_action_galaxy()
        galaxy = event['Event']['Galaxy'][0]
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        course_of_action = self._run_galaxy_tests(event, timestamp)
        self.assertEqual(course_of_action.type, 'course-of-action')
        self._check_galaxy_features(course_of_action, galaxy, timestamp, False, False)

    def test_event_with_malware_galaxy(self):
        event = get_event_with_malware_galaxy()
        galaxy = event['Event']['Galaxy'][0]
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        malware = self._run_galaxy_tests(event, timestamp)
        self.assertEqual(malware.type, 'malware')
        self._check_galaxy_features(malware, galaxy, timestamp, True, True)

    def test_event_with_threat_actor_galaxy(self):
        event = get_event_with_threat_actor_galaxy()
        galaxy = event['Event']['Galaxy'][0]
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        threat_actor = self._run_galaxy_tests(event, timestamp)
        self.assertEqual(threat_actor.type, 'threat-actor')
        self._check_galaxy_features(threat_actor, galaxy, timestamp, False, True)

    def test_event_with_tool_galaxy(self):
        event = get_event_with_tool_galaxy()
        galaxy = event['Event']['Galaxy'][0]
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        tool = self._run_galaxy_tests(event, timestamp)
        self.assertEqual(tool.type, 'tool')
        self._check_galaxy_features(tool, galaxy, timestamp, True, True)

    def test_event_with_vulnerability_galaxy(self):
        event = get_event_with_vulnerability_galaxy()
        galaxy = event['Event']['Galaxy'][0]
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        vulnerability = self._run_galaxy_tests(event, timestamp)
        self.assertEqual(vulnerability.type, 'vulnerability')
        self._check_galaxy_features(vulnerability, galaxy, timestamp, False, False)
