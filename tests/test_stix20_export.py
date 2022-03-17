#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
from collections import defaultdict
from datetime import datetime
from misp_stix_converter import MISPtoSTIX20Parser, misp_collection_to_stix2_0, misp_to_stix2_0
from .test_events import *
from .update_documentation import DocumentationUpdater
from ._test_stix_export import TestCollectionSTIX2Export, TestSTIX2Export


class TestSTIX20Export(TestSTIX2Export):
    __attributes = defaultdict(lambda: defaultdict(dict))
    __objects = defaultdict(lambda: defaultdict(dict))
    def setUp(self):
        self.parser = MISPtoSTIX20Parser()

    @classmethod
    def tearDownClass(self):
        attributes_documentation = DocumentationUpdater('misp_attributes_to_stix20')
        attributes_documentation.check_stix20_mapping(self.__attributes)
        objects_documentation = DocumentationUpdater('misp_objects_to_stix20')
        objects_documentation.check_stix20_mapping(self.__objects)

    ################################################################################
    #                              UTILITY FUNCTIONS.                              #
    ################################################################################

    def _check_bundle_features(self, length):
        bundle = self.parser.bundle
        self.assertEqual(bundle.type, 'bundle')
        self.assertEqual(bundle.spec_version, '2.0')
        self.assertEqual(len(bundle.objects), length)
        return bundle

    def _populate_attributes_documentation(self, attribute, **kwargs):
        attribute_type = attribute['type']
        if 'MISP' not in self.__attributes[attribute_type]:
            self.__attributes[attribute_type]['MISP'] = self._sanitize_documentation(attribute)
        for object_type, stix_object in kwargs.items():
            documented = json.loads(stix_object.serialize())
            feature = object_type.replace('_', ' ').title()
            self.__attributes[attribute_type]['STIX'][feature] = documented

    def _populate_objects_documentation(self, misp_object, name=None, summary=None, **kwargs):
        if name is None:
            name = misp_object['name']
        if 'MISP' not in self.__objects[name]:
            self.__objects[name]['MISP'] = self._sanitize_documentation(misp_object)
        if summary is not None:
            self.__objects['summary'][name] = summary
        for object_type, stix_object in kwargs.items():
            documented = json.loads(stix_object.serialize())
            feature = 'Course of Action' if object_type == 'course_of_action' else object_type.replace('_', ' ').title()
            self.__objects[name]['STIX'][feature] = documented

    def _run_custom_attributes_tests(self, event):
        orgc = event['Event']['Orgc']
        attributes = event['Event']['Attribute']
        self.parser.parse_misp_event(event)
        identity, report, *custom_objects = self.parser.stix_objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event['Event'], identity_id, timestamp)
        self.assertEqual(report.published, timestamp)
        for attribute, custom_object, object_ref in zip(attributes, custom_objects, object_refs):
            self._run_custom_attribute_tests(attribute, custom_object, object_ref, identity_id)

    def _run_galaxy_tests(self, event, timestamp):
        orgc = event['Event']['Orgc']
        self.parser.parse_misp_event(event)
        identity, report, stix_object = self.parser.stix_objects
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event['Event'], identity_id, timestamp)[0]
        self.assertEqual(report.published, timestamp)
        self.assertEqual(stix_object.id, object_ref)
        return stix_object

    def _run_indicators_from_objects_tests(self, event):
        self._add_object_ids_flag(event)
        orgc = event['Event']['Orgc']
        misp_objects = deepcopy(event['Event']['Object'])
        self.parser.parse_misp_event(event)
        identity, report, *indicators = self.parser.stix_objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        args = (report, event['Event'], identity_id, timestamp)
        object_refs = self._check_report_features(*args)
        self.assertEqual(report.published, timestamp)
        for indicator, misp_object, object_ref in zip(indicators, misp_objects, object_refs):
            self._check_object_indicator_features(indicator, misp_object, identity_id, object_ref)
        return misp_objects, tuple(indicator.pattern for indicator in indicators)

    def _run_indicator_from_objects_tests(self, event):
        self._add_object_ids_flag(event)
        orgc = event['Event']['Orgc']
        misp_objects = deepcopy(event['Event']['Object'])
        self.parser.parse_misp_event(event)
        identity, report, indicator = self.parser.stix_objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        args = (report, event['Event'], identity_id, timestamp)
        object_ref = self._check_report_features(*args)[0]
        self.assertEqual(report.published, timestamp)
        self._check_object_indicator_features(indicator, misp_objects[0], identity_id, object_ref)
        return misp_objects, indicator.pattern

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

    def _run_observables_from_objects_tests(self, event):
        self._remove_object_ids_flags(event)
        orgc = event['Event']['Orgc']
        misp_objects = deepcopy(event['Event']['Object'])
        self.parser.parse_misp_event(event)
        identity, report, *observed_datas = self.parser.stix_objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        args = (report, event['Event'], identity_id, timestamp)
        object_refs = self._check_report_features(*args)
        self.assertEqual(report.published, timestamp)
        for observed_data, misp_object, object_ref in zip(observed_datas, misp_objects, object_refs):
            self._check_object_observable_features(
                observed_data,
                misp_object,
                identity_id,
                object_ref
            )
        return misp_objects, tuple(observed_data['objects'] for observed_data in observed_datas)

    def _run_observable_from_objects_tests(self, event):
        self._remove_object_ids_flags(event)
        orgc = event['Event']['Orgc']
        misp_objects = deepcopy(event['Event']['Object'])
        self.parser.parse_misp_event(event)
        identity, report, observed_data = self.parser.stix_objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        args = (report, event['Event'], identity_id, timestamp)
        object_ref = self._check_report_features(*args)[0]
        self.assertEqual(report.published, timestamp)
        self._check_object_observable_features(
            observed_data,
            misp_objects[0],
            identity_id,
            object_ref
        )
        return misp_objects, observed_data['objects']

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
        self.assertEqual(custom.id, object_ref)
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
        identity, report, _ = bundle.objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        self._check_report_features(report, event['Event'], identity_id, timestamp)
        self.assertEqual(report.created, timestamp)
        self.assertEqual(report.modified, timestamp)
        self.assertEqual(
            report.published,
            self._datetime_from_timestamp(event['Event']['publish_timestamp'])
        )

    def test_event_with_escaped_characters(self):
        event = get_event_with_escaped_values_v20()
        self.parser.parse_misp_event(event)
        bundle = self._check_bundle_features(48)
        _, _, *indicators = bundle.objects
        for indicator in indicators:
            self.assertEqual(indicator.type, 'indicator')

    def test_event_with_sightings(self):
        event = get_event_with_sightings()
        orgc = event['Event']['Orgc']
        attribute1, attribute2 = event['Event']['Attribute']
        sightings1 = attribute1['Sighting']
        sightings2 = attribute2['Sighting']
        self.parser.parse_misp_event(event)
        identity, identity1, identity2, identity3, report, *stix_objects = self.parser.stix_objects
        identities = (identity1, identity2, identity3)
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event['Event'], identity_id, timestamp)
        for stix_object, object_ref in zip(stix_objects, object_refs):
            self.assertEqual(stix_object.id, object_ref)
        self._check_identities_from_sighting(
            identities,
            tuple(f"identity--{sighting['Organisation']['uuid']}" for sighting in sightings1[:3]),
            tuple(sighting['Organisation']['name'] for sighting in sightings2[:3])
        )
        identity_ids = tuple(identity.id for identity in identities)
        observed_data, sighting1, opinion1, indicator, sighting2, opinion2 = stix_objects
        self.assertEqual(sighting1.type, 'sighting')
        self.assertEqual(
            sighting1.first_seen,
            self._datetime_from_timestamp(sightings1[0]['date_sighting'])
        )
        self.assertEqual(
            sighting1.last_seen,
            self._datetime_from_timestamp(sightings1[1]['date_sighting'])
        )
        self.assertEqual(sighting1.count, 2)
        self.assertEqual(sighting1.sighting_of_ref, observed_data.id)
        self.assertEqual(len(sighting1.where_sighted_refs), 2)
        for where_sighted_ref in sighting1.where_sighted_refs:
            self.assertIn(where_sighted_ref, identity_ids)
        self.assertEqual(opinion1.type, 'x-misp-opinion')
        self.assertEqual(opinion1.object_ref, observed_data.id)
        self.assertEqual(len(opinion1.x_misp_authors), 2)
        self.assertIn(sightings1[3]['Organisation']['name'], opinion1.x_misp_authors)
        self.assertIn(sightings1[2]['Organisation']['name'], opinion1.x_misp_authors)
        self.assertEqual(opinion1.x_misp_explanation, "False positive Sighting")
        self.assertEqual(opinion1.x_misp_opinion, "strongly-disagree")
        self.assertEqual(sighting2.type, 'sighting')
        self.assertEqual(
            sighting2.first_seen,
            self._datetime_from_timestamp(sightings2[0]['date_sighting'])
        )
        self.assertEqual(
            sighting2.last_seen,
            self._datetime_from_timestamp(sightings2[2]['date_sighting'])
        )
        self.assertEqual(sighting2.count, 2)
        self.assertEqual(sighting2.sighting_of_ref, indicator.id)
        self.assertEqual(len(sighting2.where_sighted_refs), 2)
        for where_sighted_ref in sighting2.where_sighted_refs:
            self.assertIn(where_sighted_ref, identity_ids)
        self.assertEqual(opinion2.type, 'x-misp-opinion')
        self.assertEqual(opinion2.object_ref, indicator.id)
        self.assertEqual(len(opinion2.x_misp_authors), 2)
        self.assertIn(sightings2[1]['Organisation']['name'], opinion2.x_misp_authors)
        self.assertIn(sightings2[3]['Organisation']['name'], opinion2.x_misp_authors)
        self.assertEqual(opinion2.x_misp_explanation, "False positive Sighting")
        self.assertEqual(opinion2.x_misp_opinion, "strongly-disagree")

    def test_event_with_tags(self):
        event = get_event_with_tags()
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
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_as_observable_attribute(self):
        event = get_event_with_as_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        observable = observable_objects['0']
        self.assertEqual(observable.type, 'autonomous-system')
        number = self._parse_AS_value(attribute_value)
        self.assertEqual(observable.number, number)
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_attachment_indicator_attribute(self):
        event = get_event_with_attachment_attribute()
        attribute = event['Event']['Attribute'][0]
        attribute_value, pattern = self._run_indicator_tests(event)
        file_pattern = f"file:name = '{attribute_value}'"
        data_pattern = f"file:content_ref.payload_bin = '{attribute['data']}'"
        self.assertEqual(pattern, f"[{file_pattern} AND {data_pattern}]")
        self._populate_documentation(
            attribute = attribute,
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_attachment_observable_attribute(self):
        event = get_event_with_attachment_attribute()
        attribute = event['Event']['Attribute'][0]
        attribute_value, observable_objects = self._run_observable_tests(event)
        file_object, artifact_object = observable_objects.values()
        self.assertEqual(file_object.type, 'file')
        self.assertEqual(file_object.name, attribute_value)
        self.assertEqual(file_object.content_ref, '1')
        self.assertEqual(artifact_object.type, 'artifact')
        self.assertEqual(artifact_object.payload_bin, attribute['data'])
        self._populate_documentation(
            attribute = attribute,
            observed_data = self.parser.stix_objects[-1]
        )

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
        self._populate_documentation(
            attribute = attribute,
            campaign = campaign
        )

    def test_event_with_custom_attributes(self):
        event = get_event_with_stix2_custom_attributes()
        self._run_custom_attributes_tests(event)

    def test_event_with_domain_indicator_attribute(self):
        event = get_event_with_domain_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[domain-name:value = '{attribute_value}']")
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_domain_observable_attribute(self):
        event = get_event_with_domain_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        observable = observable_objects['0']
        self.assertEqual(observable.type, 'domain-name')
        self.assertEqual(observable.value, attribute_value)
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_domain_ip_indicator_attribute(self):
        event = get_event_with_domain_ip_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        domain, ip = attribute_value.split('|')
        domain_pattern = f"domain-name:value = '{domain}'"
        ip_pattern = f"domain-name:resolves_to_refs[*].value = '{ip}'"
        self.assertEqual(pattern, f'[{domain_pattern} AND {ip_pattern}]')
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

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
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_email_attachment_indicator_attribute(self):
        event = get_event_with_email_attachment_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(
            pattern,
            f"[email-message:body_multipart[*].body_raw_ref.name = '{attribute_value}']"
        )
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
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
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_email_body_indicator_attribute(self):
        event = get_event_with_email_body_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(
            pattern,
            f"[email-message:body = '{attribute_value}']"
        )
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_email_body_observable_attribute(self):
        event = get_event_with_email_body_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        email_object = observable_objects['0']
        self.assertEqual(email_object.type, 'email-message')
        self.assertEqual(email_object.is_multipart, False)
        self.assertEqual(email_object.body, attribute_value)
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_email_destination_indicator_attribute(self):
        event = get_event_with_email_destination_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[email-message:to_refs[*].value = '{attribute_value}']")
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_email_destination_observable_attribute(self):
        event = get_event_with_email_destination_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        message, address = observable_objects.values()
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.to_refs, ['1'])
        self._check_email_address(address, attribute_value)
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_email_header_indicator_attribute(self):
        event = get_event_with_email_header_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[email-message:received_lines = '{attribute_value}']")
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_email_header_observable_attribute(self):
        event = get_event_with_email_header_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        message_object = observable_objects['0']
        self.assertEqual(message_object.type, 'email-message')
        self.assertEqual(message_object.is_multipart, False)
        self.assertEqual(message_object.received_lines, [attribute_value])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_email_indicator_attribute(self):
        event = get_event_with_email_address_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[email-addr:value = '{attribute_value}']")
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_email_observable_attribute(self):
        event = get_event_with_email_address_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        address_object = observable_objects['0']
        self._check_email_address(address_object, attribute_value)
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_email_reply_to_indicator_attribute(self):
        event = get_event_with_email_reply_to_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(
            pattern,
            f"[email-message:additional_header_fields.reply_to = '{attribute_value}']"
        )
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_email_reply_to_observable_attribute(self):
        event = get_event_with_email_reply_to_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        message = observable_objects['0']
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.additional_header_fields['Reply-To'], attribute_value)
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_email_source_indicator_attribute(self):
        event = get_event_with_email_source_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[email-message:from_ref.value = '{attribute_value}']")
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_email_source_observable_attribute(self):
        event = get_event_with_email_source_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        message, address = observable_objects.values()
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.from_ref, '1')
        self._check_email_address(address, attribute_value)
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_email_subject_indicator_attribute(self):
        event = get_event_with_email_subject_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[email-message:subject = '{attribute_value}']")
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_email_subject_observable_attribute(self):
        event = get_event_with_email_subject_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        message = observable_objects['0']
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.subject, attribute_value)
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_email_x_mailer_indicator_attribute(self):
        event = get_event_with_email_x_mailer_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(
            pattern,
            f"[email-message:additional_header_fields.x_mailer = '{attribute_value}']"
        )
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_email_x_mailer_attribute(self):
        event = get_event_with_email_x_mailer_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        message = observable_objects['0']
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.additional_header_fields['X-Mailer'], attribute_value)
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_filename_indicator_attribute(self):
        event = get_event_with_filename_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[file:name = '{attribute_value}']")
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_filename_observable_attribute(self):
        event = get_event_with_filename_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        observable = observable_objects['0']
        self.assertEqual(observable.type, 'file')
        self.assertEqual(observable.name, attribute_value)
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_github_username_indicator_attribute(self):
        event = get_event_with_github_username_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(
            pattern,
            f"[user-account:account_type = 'github' AND user-account:account_login = '{attribute_value}']"
        )
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_github_username_observable_attribute(self):
        event = get_event_with_github_username_attribute()
        self._run_custom_attributes_tests(event)

    def test_event_with_hash_composite_indicator_attributes(self):
        event = get_event_with_hash_composite_attributes()
        attribute_values, patterns = self._run_indicators_tests(event)
        hash_types = ('MD5', 'SHA1', 'SHA224', 'SHA256', 'SHA3256', 'SHA384', 'SSDEEP', 'TLSH')
        for attribute_value, pattern, hash_type in zip(attribute_values, patterns, hash_types):
            filename, hash_value = attribute_value.split('|')
            filename_pattern = f"file:name = '{filename}'"
            hash_pattern = f"file:hashes.{hash_type} = '{hash_value}'"
            self.assertEqual(pattern, f"[{filename_pattern} AND {hash_pattern}]")
        for attribute, indicator in zip(event['Event']['Attribute'], self.parser.stix_objects[-8:]):
            self._populate_documentation(attribute=attribute, indicator=indicator)

    def test_event_with_hash_composite_observable_attributes(self):
        event = get_event_with_hash_composite_attributes()
        attribute_values, observable_objects = self._run_observables_tests(event)
        hash_types = ('MD5', 'SHA-1', 'SHA-224', 'SHA-256', 'SHA3-256', 'SHA-384', 'ssdeep', 'TLSH')
        for attribute_value, observable_object, hash_type in zip(attribute_values, observable_objects, hash_types):
            filename, hash_value = attribute_value.split('|')
            self.assertEqual(observable_object['0'].type, 'file')
            self.assertEqual(observable_object['0'].name, filename)
            self.assertEqual(observable_object['0'].hashes[hash_type], hash_value)
        for attribute, observed_data in zip(event['Event']['Attribute'], self.parser.stix_objects[-8:]):
            self._populate_documentation(attribute=attribute, observed_data=observed_data)

    def test_event_with_hash_indicator_attributes(self):
        event = get_event_with_hash_attributes()
        values, patterns = self._run_indicators_tests(event)
        hash_types = ('MD5', 'SHA1', 'SHA224', 'SHA256', 'SHA3256', 'SHA384', 'SSDEEP', 'TLSH')
        for pattern, hash_type, value in zip(patterns, hash_types, values):
            self.assertEqual(pattern, f"[file:hashes.{hash_type} = '{value}']")
        for attribute, indicator in zip(event['Event']['Attribute'], self.parser.stix_objects[-8:]):
            self._populate_documentation(attribute=attribute, indicator=indicator)

    def test_event_with_hash_observable_attributes(self):
        event = get_event_with_hash_attributes()
        values, observable_objects = self._run_observables_tests(event)
        hash_types = ('MD5', 'SHA-1', 'SHA-224', 'SHA-256', 'SHA3-256', 'SHA-384', 'ssdeep', 'TLSH')
        for value, observable_object, hash_type in zip(values, observable_objects, hash_types):
            self.assertEqual(observable_object['0'].type, 'file')
            self.assertEqual(observable_object['0'].hashes[hash_type], value)
        for attribute, observed_data in zip(event['Event']['Attribute'], self.parser.stix_objects[-8:]):
            self._populate_documentation(attribute=attribute, observed_data=observed_data)

    def test_event_with_hostname_indicator_attribute(self):
        event = get_event_with_hostname_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[domain-name:value = '{attribute_value}']")
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_hostname_observable_attribute(self):
        event = get_event_with_hostname_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        observable = observable_objects['0']
        self.assertEqual(observable.type, 'domain-name')
        self.assertEqual(observable.value, attribute_value)
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_hostname_port_indicator_attribute(self):
        event = get_event_with_hostname_port_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        hostname, port = attribute_value.split('|')
        hostname_pattern = f"domain-name:value = '{hostname}'"
        port_pattern = f"network-traffic:dst_port = '{port}'"
        self.assertEqual(pattern, f"[{hostname_pattern} AND {port_pattern}]")
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

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
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

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
        for attribute, indicator in zip(event['Event']['Attribute'], self.parser.stix_objects[-2:]):
            self._populate_documentation(attribute=attribute, indicator=indicator)

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
        for attribute, indicator in zip(event['Event']['Attribute'], self.parser.stix_objects[-2:]):
            self._populate_documentation(attribute=attribute, indicator=indicator)

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
        for attribute, observed_data in zip(event['Event']['Attribute'], self.parser.stix_objects[-2:]):
            self._populate_documentation(attribute=attribute, observed_data=observed_data)

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
        for attribute, indicator in zip(event['Event']['Attribute'], self.parser.stix_objects[-2:]):
            self._populate_documentation(attribute=attribute, indicator=indicator)

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
        for attribute, observed_data in zip(event['Event']['Attribute'], self.parser.stix_objects[-2:]):
            self._populate_documentation(attribute=attribute, observed_data=observed_data)

    def test_event_with_mac_address_indicator_attribute(self):
        event = get_event_with_mac_address_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[mac-addr:value = '{attribute_value}']")
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_mac_address_observable_attribute(self):
        event = get_event_with_mac_address_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        observable = observable_objects['0']
        self.assertEqual(observable.type, 'mac-addr')
        self.assertEqual(observable.value, attribute_value.lower())
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_malware_sample_indicator_attribute(self):
        event = get_event_with_malware_sample_attribute()
        data = event['Event']['Attribute'][0]['data']
        attribute_value, pattern = self._run_indicator_tests(event)
        filename, hash_value = attribute_value.split('|')
        file_pattern, hash_pattern, data_pattern, mime_type = pattern[1:-1].split(' AND ')
        self.assertEqual(file_pattern, f"file:name = '{filename}'")
        self.assertEqual(hash_pattern, f"file:hashes.MD5 = '{hash_value}'")
        self.assertEqual(data_pattern, f"file:content_ref.payload_bin = '{data}'")
        self.assertEqual(mime_type, f"file:content_ref.mime_type = 'application/zip'")
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

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
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_mutex_indicator_attribute(self):
        event = get_event_with_mutex_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[mutex:name = '{attribute_value}']")
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_mutex_observable_attribute(self):
        event = get_event_with_mutex_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        observable = observable_objects['0']
        self.assertEqual(observable.type, 'mutex')
        self.assertEqual(observable.name, attribute_value)
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_port_indicator_attribute(self):
        event = get_event_with_port_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[network-traffic:dst_port = '{attribute_value}']")
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_regkey_indicator_attribute(self):
        event = get_event_with_regkey_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(
            pattern.replace('\\\\', '\\'),
            f"[windows-registry-key:key = '{attribute_value.strip()}']"
        )
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_regkey_observable_attribute(self):
        event = get_event_with_regkey_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        observable = observable_objects['0']
        self.assertEqual(observable.type, 'windows-registry-key')
        self.assertEqual(observable.key, attribute_value.strip())
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_regkey_value_indicator_attribute(self):
        event = get_event_with_regkey_value_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        key, value = attribute_value.split('|')
        key_pattern = f"windows-registry-key:key = '{self._sanitize_registry_key_value(key)}'"
        value_pattern = f"windows-registry-key:values.data = '{self._sanitize_registry_key_value(value)}'"
        self.assertEqual(pattern, f"[{key_pattern} AND {value_pattern}]")
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_regkey_value_observable_attribute(self):
        event = get_event_with_regkey_value_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        key, value = attribute_value.split('|')
        observable = observable_objects['0']
        self.assertEqual(observable.type, 'windows-registry-key')
        self.assertEqual(observable.key, key.strip())
        self.assertEqual(observable['values'][0].data, value.strip())
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_size_in_bytes_indicator_attribute(self):
        event = get_event_with_size_in_bytes_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[file:size = '{attribute_value}']")
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_url_indicator_attribute(self):
        event = get_event_with_url_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[url:value = '{attribute_value}']")
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_url_observable_attribute(self):
        event = get_event_with_url_attribute()
        attribute_value, observable_objects = self._run_observable_tests(event)
        observable = observable_objects['0']
        self.assertEqual(observable.type, 'url')
        self.assertEqual(observable.value, attribute_value)
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

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
        self._populate_documentation(attribute=attribute, vulnerability=vulnerability)

    def test_event_with_x509_fingerprint_indicator_attributes(self):
        event = get_event_with_x509_fingerprint_attributes()
        attribute_values, patterns = self._run_indicators_tests(event)
        md5, sha1, sha256 = attribute_values
        md5_pattern, sha1_pattern, sha256_pattern = patterns
        self.assertEqual(md5_pattern, f"[x509-certificate:hashes.MD5 = '{md5}']")
        self.assertEqual(sha1_pattern, f"[x509-certificate:hashes.SHA1 = '{sha1}']")
        self.assertEqual(sha256_pattern, f"[x509-certificate:hashes.SHA256 = '{sha256}']")
        for attribute, indicator in zip(event['Event']['Attribute'], self.parser.stix_objects[-3:]):
            self._populate_documentation(attribute=attribute, indicator=indicator)

    def test_event_with_x509_fingerprint_observable_attributes(self):
        event = get_event_with_x509_fingerprint_attributes()
        attribute_values, observable_objects = self._run_observables_tests(event)
        hash_types = ('MD5', 'SHA-1', 'SHA-256')
        for attribute_value, observable_object, hash_type in zip(attribute_values, observable_objects, hash_types):
            self.assertEqual(observable_object['0'].type, 'x509-certificate')
            self.assertEqual(observable_object['0'].hashes[hash_type], attribute_value)
        for attribute, observed_data in zip(event['Event']['Attribute'], self.parser.stix_objects[-3:]):
            self._populate_documentation(attribute=attribute, observed_data=observed_data)

    ################################################################################
    #                          MISP OBJECTS EXPORT TESTS.                          #
    ################################################################################

    def test_embedded_indicator_object_galaxy(self):
        event = get_embedded_indicator_object_galaxy()
        self._add_object_ids_flag(event)
        orgc = event['Event']['Orgc']
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event)
        bundle = self._check_bundle_features(8)
        identity, report, malware, coa, indicator, tool, *relationships = bundle.objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event['Event'], identity_id, timestamp)
        self.assertEqual(report.published, timestamp)
        malware_ref, coa_ref, indicator_ref, tool_ref, mr_ref, coar_ref = object_refs
        malware_relationship, coa_relationship = relationships
        self.assertEqual(malware.id, malware_ref)
        self.assertEqual(coa.id, coa_ref)
        self.assertEqual(indicator.id, indicator_ref)
        self.assertEqual(tool.id, tool_ref)
        self.assertEqual(malware_relationship.id, mr_ref)
        self.assertEqual(coa_relationship.id, coar_ref)
        timestamp = self._datetime_from_timestamp(misp_object['timestamp'])
        self._check_relationship_features(malware_relationship, indicator_ref, malware_ref, 'indicates', timestamp)
        self._check_relationship_features(coa_relationship, indicator_ref, coa_ref, 'has', timestamp)

    def test_embedded_non_indicator_object_galaxy(self):
        event = get_embedded_non_indicator_object_galaxy()
        orgc = event['Event']['Orgc']
        coa_object, vulnerability_object = deepcopy(event['Event']['Object'])
        self.parser.parse_misp_event(event)
        bundle = self._check_bundle_features(12)
        identity, report, ap, g_coa, o_coa, malware, vulnerability, tool, *relationships = bundle.objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event['Event'], identity_id, timestamp)
        self.assertEqual(report.published, timestamp)
        ap_ref, g_coa_ref, o_coa_ref, malware_ref, vulnerability_ref, tool_ref, *relationship_refs = object_refs
        self.assertEqual(ap.id, ap_ref)
        self.assertEqual(g_coa.id, g_coa_ref)
        self.assertEqual(o_coa.id, o_coa_ref)
        self.assertEqual(malware.id, malware_ref)
        self.assertEqual(vulnerability.id, vulnerability_ref)
        self.assertEqual(tool.id, tool_ref)
        relationship1, relationship2, relationship3, relationship4 = relationships
        r_ref1, r_ref2, r_ref3, r_ref4 = relationship_refs
        self.assertEqual(relationship1.id, r_ref1)
        self.assertEqual(relationship2.id, r_ref2)
        self.assertEqual(relationship3.id, r_ref3)
        self.assertEqual(relationship4.id, r_ref4)
        coa_timestamp = self._datetime_from_timestamp(coa_object['timestamp'])
        self._check_relationship_features(relationship1, o_coa_ref, ap_ref, 'mitigates', coa_timestamp)
        self._check_relationship_features(relationship2, o_coa_ref, g_coa_ref, 'has', coa_timestamp)
        vulnerability_timestamp = self._datetime_from_timestamp(vulnerability_object['timestamp'])
        self._check_relationship_features(relationship3, vulnerability_ref, malware_ref, 'has', vulnerability_timestamp)
        self._check_relationship_features(relationship4, vulnerability_ref, g_coa_ref, 'has', vulnerability_timestamp)

    def test_embedded_object_galaxy_with_multiple_clusters(self):
        event = get_embedded_object_galaxy_with_multiple_clusters()
        orgc = event['Event']['Orgc']
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event)
        bundle = self._check_bundle_features(7)
        identity, report, malware1, malware2, observed_data, relationship1, relationship2 = bundle.objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event['Event'], identity_id, timestamp)
        self.assertEqual(report.published, timestamp)
        malware1_ref, malware2_ref, observed_data_ref, relationship1_ref, relationship2_ref = object_refs
        self.assertEqual(malware1.id, malware1_ref)
        self.assertEqual(malware2.id, malware2_ref)
        self.assertEqual(observed_data.id, observed_data_ref)
        self.assertEqual(relationship1.id, relationship1_ref)
        self.assertEqual(relationship2.id, relationship2_ref)
        object_timestamp = self._datetime_from_timestamp(misp_object['timestamp'])
        self._check_relationship_features(relationship1, observed_data_ref, malware1_ref, 'has', object_timestamp)
        self._check_relationship_features(relationship2, observed_data_ref, malware2_ref, 'has', object_timestamp)

    def test_embedded_observable_object_galaxy(self):
        event = get_embedded_observable_object_galaxy()
        orgc = event['Event']['Orgc']
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event)
        bundle = self._check_bundle_features(6)
        identity, report, malware, observed_data, tool, relationship = bundle.objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event['Event'], identity_id, timestamp)
        self.assertEqual(report.published, timestamp)
        malware_ref, observed_data_ref, tool_ref, relationship_ref = object_refs
        self.assertEqual(malware.id, malware_ref)
        self.assertEqual(observed_data.id, observed_data_ref)
        self.assertEqual(tool.id, tool_ref)
        self.assertEqual(relationship.id, relationship_ref)
        self._check_relationship_features(
            relationship,
            observed_data_ref,
            malware_ref,
            'has',
            self._datetime_from_timestamp(misp_object['timestamp'])
        )

    def test_event_with_account_indicator_objects(self):
        event = get_event_with_account_objects()
        misp_objects, patterns = self._run_indicators_from_objects_tests(event)
        facebook_object, gitlab_object, telegram_object, twitter_object = misp_objects
        facebook_pattern, gitlab_pattern, telegram_pattern, twitter_pattern = patterns
        account_id, account_name, link = (attribute['value'] for attribute in facebook_object['Attribute'])
        account_type, user_id, account_login, _link = facebook_pattern[1:-1].split(' AND ')
        self.assertEqual(account_type, f"user-account:account_type = 'facebook'")
        self.assertEqual(user_id, f"user-account:user_id = '{account_id}'")
        self.assertEqual(account_login, f"user-account:account_login = '{account_name}'")
        self.assertEqual(_link, f"user-account:x_misp_link = '{link}'")
        gitlab_id, name, username = (attribute['value'] for attribute in gitlab_object['Attribute'])
        account_type, user_id, display_name, account_login = gitlab_pattern[1:-1].split(' AND ')
        self.assertEqual(account_type, f"user-account:account_type = 'gitlab'")
        self.assertEqual(user_id, f"user-account:user_id = '{gitlab_id}'")
        self.assertEqual(display_name, f"user-account:display_name = '{name}'")
        self.assertEqual(account_login, f"user-account:account_login = '{username}'")
        telegram_id, username, phone1, phone2 = (attribute['value'] for attribute in telegram_object['Attribute'])
        account_type, user_id, login, phone_1, phone_2 = telegram_pattern[1:-1].split(' AND ')
        self.assertEqual(account_type, "user-account:account_type = 'telegram'")
        self.assertEqual(user_id, f"user-account:user_id = '{telegram_id}'")
        self.assertEqual(login, f"user-account:account_login = '{username}'")
        self.assertEqual(phone_1, f"user-account:x_misp_phone = '{phone1}'")
        self.assertEqual(phone_2, f"user-account:x_misp_phone = '{phone2}'")
        _id, name, displayed_name, followers = (attribute['value'] for attribute in twitter_object['Attribute'])
        account_type, display_name, user_id, account_login, _followers = twitter_pattern[1:-1].split(' AND ')
        self.assertEqual(account_type, f"user-account:account_type = 'twitter'")
        self.assertEqual(display_name, f"user-account:display_name = '{displayed_name}'")
        self.assertEqual(user_id, f"user-account:user_id = '{_id}'")
        self.assertEqual(account_login, f"user-account:account_login = '{name}'")
        self.assertEqual(_followers, f"user-account:x_misp_followers = '{followers}'")
        for misp_object, indicator in zip(misp_objects, self.parser.stix_objects[-4:]):
            self._populate_documentation(misp_object=misp_object, indicator=indicator)

    def test_event_with_account_observable_objects(self):
        event = get_event_with_account_objects()
        misp_objects, observable_objects = self._run_observables_from_objects_tests(event)
        facebook_object, gitlab_object, telegram_object, twitter_object = misp_objects
        facebook, gitlab, telegram, twitter = observable_objects
        account_id, account_name, link = (attribute['value'] for attribute in facebook_object['Attribute'])
        facebook = facebook['0']
        self.assertEqual(facebook.type, 'user-account')
        self.assertEqual(facebook.account_type, 'facebook')
        self.assertEqual(facebook.user_id, account_id)
        self.assertEqual(facebook.account_login, account_name)
        self.assertEqual(facebook.x_misp_link, link)
        gitlab_id, name, username = (attribute['value'] for attribute in gitlab_object['Attribute'])
        gitlab = gitlab['0']
        self.assertEqual(gitlab.type, 'user-account')
        self.assertEqual(gitlab.account_type, 'gitlab')
        self.assertEqual(gitlab.user_id, gitlab_id)
        self.assertEqual(gitlab.display_name, name)
        self.assertEqual(gitlab.account_login, username)
        telegram_id, username, phone1, phone2 = (attribute['value'] for attribute in telegram_object['Attribute'])
        telegram = telegram['0']
        self.assertEqual(telegram.type, 'user-account')
        self.assertEqual(telegram.account_type, 'telegram')
        self.assertEqual(telegram.user_id, telegram_id)
        self.assertEqual(telegram.account_login, username)
        self.assertEqual(telegram.x_misp_phone, [phone1, phone2])
        _id, name, displayed_name, followers = (attribute['value'] for attribute in twitter_object['Attribute'])
        twitter = twitter['0']
        self.assertEqual(twitter.type, 'user-account')
        self.assertEqual(twitter.account_type, 'twitter')
        self.assertEqual(twitter.user_id, _id)
        self.assertEqual(twitter.account_login, name)
        self.assertEqual(twitter.display_name, displayed_name)
        self.assertEqual(twitter.x_misp_followers, followers)
        for misp_object, observed_data in zip(misp_objects, self.parser.stix_objects[-4:]):
            self._populate_documentation(misp_object=misp_object, observed_data=observed_data)

    def test_event_with_account_indicator_objects_with_attachment(self):
        event = get_event_with_account_objects_with_attachment()
        misp_objects, patterns = self._run_indicators_from_objects_tests(event)
        github_user, parler_account, reddit_account = misp_objects
        github_pattern, parler_pattern, reddit_pattern = patterns
        github_id, username, fullname, organisation, image = (attribute['value'] for attribute in github_user['Attribute'])
        account_type, user_id, display_name, login, organization, image_data, image_value = github_pattern[1:-1].split(' AND ')
        self.assertEqual(account_type, "user-account:account_type = 'github'")
        self.assertEqual(user_id, f"user-account:user_id = '{github_id}'")
        self.assertEqual(display_name, f"user-account:display_name = '{fullname}'")
        self.assertEqual(login, f"user-account:account_login = '{username}'")
        self.assertEqual(organization, f"user-account:x_misp_organisation = '{organisation}'")
        data = github_user['Attribute'][-1]['data'].replace('\\', '')
        self.assertEqual(image_data, f"user-account:x_misp_profile_image.data = '{data}'")
        self.assertEqual(image_value, f"user-account:x_misp_profile_image.value = '{image}'")
        parler_id, parler_name, human, profile_photo = (attribute['value'] for attribute in parler_account['Attribute'])
        account_type, user_id, login, is_human, image_data, image_value = parler_pattern[1:-1].split(' AND ')
        self.assertEqual(account_type, f"user-account:account_type = 'parler'")
        self.assertEqual(user_id, f"user-account:user_id = '{parler_id}'")
        self.assertEqual(login, f"user-account:account_login = '{parler_name}'")
        self.assertEqual(is_human, f"user-account:x_misp_human = 'False'")
        data = parler_account['Attribute'][-1]['data'].replace('\\', '')
        self.assertEqual(image_data, f"user-account:x_misp_profile_photo.data = '{data}'")
        self.assertEqual(image_value, f"user-account:x_misp_profile_photo.value = '{profile_photo}'")
        reddit_id, reddit_name, description, account_avatar = (attribute['value'] for attribute in reddit_account['Attribute'])
        account_type, user_id, login, description_pattern, image_data, image_value = reddit_pattern[1:-1].split(' AND ')
        self.assertEqual(account_type, f"user-account:account_type = 'reddit'")
        self.assertEqual(user_id, f"user-account:user_id = '{reddit_id}'")
        self.assertEqual(login, f"user-account:account_login = '{reddit_name}'")
        self.assertEqual(description_pattern, f"user-account:x_misp_description = '{description}'")
        data = reddit_account['Attribute'][-1]['data'].replace('\\', '')
        self.assertEqual(image_data, f"user-account:x_misp_account_avatar.data = '{data}'")
        self.assertEqual(image_value, f"user-account:x_misp_account_avatar.value = '{account_avatar}'")
        for misp_object, indicator in zip(misp_objects, self.parser.stix_objects[-4:]):
            self._populate_documentation(misp_object=misp_object, indicator=indicator)

    def test_event_with_account_observable_object_with_attachment(self):
        event = get_event_with_account_objects_with_attachment()
        misp_objects, observable_objects = self._run_observables_from_objects_tests(event)
        github_user, parler_account, reddit_account = misp_objects
        github, parler, reddit = observable_objects
        github_id, username, fullname, organisation, image = (attribute['value'] for attribute in github_user['Attribute'])
        github = github['0']
        self.assertEqual(github.type, 'user-account')
        self.assertEqual(github.account_type, 'github')
        self.assertEqual(github.user_id, github_id)
        self.assertEqual(github.account_login, username)
        self.assertEqual(github.display_name, fullname)
        self.assertEqual(github.x_misp_organisation, organisation)
        self.assertEqual(github.x_misp_profile_image['value'], image)
        self.assertEqual(
            github.x_misp_profile_image['data'],
            github_user['Attribute'][-1]['data'].replace('\\', '')
        )
        parler_id, parler_name, human, profile_photo = (attribute['value'] for attribute in parler_account['Attribute'])
        parler = parler['0']
        self.assertEqual(parler.type, 'user-account')
        self.assertEqual(parler.account_type, 'parler')
        self.assertEqual(parler.user_id, parler_id)
        self.assertEqual(parler.account_login, parler_name)
        self.assertEqual(parler.x_misp_human, human)
        self.assertEqual(parler.x_misp_profile_photo['value'], profile_photo)
        self.assertEqual(
            parler.x_misp_profile_photo['data'],
            parler_account['Attribute'][-1]['data'].replace('\\', '')
        )
        reddit_id, reddit_name, description, account_avatar = (attribute['value'] for attribute in reddit_account['Attribute'])
        reddit = reddit['0']
        self.assertEqual(reddit.type, 'user-account')
        self.assertEqual(reddit.account_type, 'reddit')
        self.assertEqual(reddit.user_id, reddit_id)
        self.assertEqual(reddit.account_login, reddit_name)
        self.assertEqual(reddit.x_misp_description, description)
        self.assertEqual(reddit.x_misp_account_avatar['value'], account_avatar)
        self.assertEqual(
            reddit.x_misp_account_avatar['data'],
            reddit_account['Attribute'][-1]['data'].replace('\\', '')
        )
        for misp_object, observed_data in zip(misp_objects, self.parser.stix_objects[-3:]):
            self._populate_documentation(misp_object=misp_object, observed_data=observed_data)

    def test_event_with_android_app_indicator_object(self):
        event = get_event_with_android_app_object()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        name, certificate, domain = (attribute['value'] for attribute in attributes)
        name_pattern, cert_pattern, domain_pattern = pattern[1:-1].split(' AND ')
        self.assertEqual(name_pattern, f"software:name = '{name}'")
        self.assertEqual(cert_pattern, f"software:x_misp_certificate = '{certificate}'")
        self.assertEqual(domain_pattern, f"software:x_misp_domain = '{domain}'")
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_android_app_observable_object(self):
        event = get_event_with_android_app_object()
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        software = observable_objects['0']
        name, certificate, domain = (attribute['value'] for attribute in attributes)
        self.assertEqual(software.type, 'software')
        self.assertEqual(software.name, name)
        self.assertEqual(software.x_misp_certificate, certificate)
        self.assertEqual(software.x_misp_domain, domain)
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

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
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1]
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
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
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
        self._check_object_labels(misp_object, attack_pattern.labels, to_ids=False)
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
        self._populate_documentation(misp_object=misp_object, attack_pattern=attack_pattern)

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
        self._check_object_labels(misp_object, course_of_action.labels, to_ids=False)
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
        self._populate_documentation(
            misp_object = misp_object,
            course_of_action = course_of_action
        )

    def test_event_with_cpe_asset_indicator_object(self):
        event = get_event_with_cpe_asset_object()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        cpe, language, product, vendor, version, description = (attribute['value'] for attribute in attributes)
        cpe_pattern, language_pattern, name, vendor_pattern, version_pattern, description_pattern = pattern[1:-1].split(' AND ')
        self.assertEqual(cpe_pattern, f"software:cpe = '{cpe}'")
        self.assertEqual(language_pattern, f"software:languages = '{language}'")
        self.assertEqual(name, f"software:name = '{product}'")
        self.assertEqual(vendor_pattern, f"software:vendor = '{vendor}'")
        self.assertEqual(version_pattern, f"software:version = '{version}'")
        self.assertEqual(description_pattern, f"software:x_misp_description = '{description}'")
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_cpe_asset_observable_object(self):
        event = get_event_with_cpe_asset_object()
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        software = observable_objects['0']
        cpe, language, product, vendor, version, description = (attribute['value'] for attribute in attributes)
        self.assertEqual(software.type, 'software')
        self.assertEqual(software.cpe, cpe)
        self.assertEqual(software.name, product)
        self.assertEqual(software.languages, [language])
        self.assertEqual(software.vendor, vendor)
        self.assertEqual(software.version, version)
        self.assertEqual(software.x_misp_description, description)
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_credential_indicator_object(self):
        event = get_event_with_credential_object()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        text, username, *attributes = ((attribute['object_relation'], attribute['value']) for attribute in attributes)
        attributes.insert(0, text)
        username_pattern, *pattern = pattern[1:-1].split(' AND ')
        self.assertEqual(username_pattern, f"user-account:user_id = '{username[1]}'")
        for pattern_part, attribute in zip(pattern, attributes):
            feature, value = attribute
            self.assertEqual(pattern_part, f"user-account:x_misp_{feature} = '{value}'")
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_credential_observable_object(self):
        event = get_event_with_credential_object()
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        user_account = observable_objects['0']
        text, username, password, *attributes = ((attribute['object_relation'], attribute['value']) for attribute in attributes)
        attributes.insert(0, text)
        self.assertEqual(user_account.type, 'user-account')
        self.assertEqual(user_account.user_id, username[1])
        for feature, value in attributes:
            self.assertEqual(getattr(user_account, f'x_misp_{feature}'), value)
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_custom_objects(self):
        event = get_event_with_custom_objects()
        orgc = event['Event']['Orgc']
        misp_objects = deepcopy(event['Event']['Object'])
        self.parser.parse_misp_event(event)
        identity, report, *custom_objects = self.parser.stix_objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event['Event'], identity_id, timestamp)
        self.assertEqual(report.published, timestamp)
        for misp_object, custom_object, object_ref in zip(misp_objects, custom_objects, object_refs):
            self._run_custom_object_tests(misp_object, custom_object, object_ref, identity_id)

    def test_event_with_domain_ip_indicator_object(self):
        event = get_event_with_domain_ip_object_custom()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        _domain, _hostname, _ip, _port = (attribute['value'] for attribute in attributes)
        domain_, hostname_, ip_, port_ = pattern[1:-1].split(' AND ')
        self.assertEqual(domain_, f"domain-name:value = '{_domain}'")
        self.assertEqual(hostname_, f"domain-name:value = '{_hostname}'")
        self.assertEqual(ip_, f"domain-name:resolves_to_refs[*].value = '{_ip}'")
        self.assertEqual(port_, f"domain-name:x_misp_port = '{_port}'")
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_domain_ip_observable_object_custom(self):
        event = get_event_with_domain_ip_object_custom()
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        _domain, hostname, _ip, port = (attribute['value'] for attribute in attributes)
        domain_ = observable_objects['0']
        ip_ = observable_objects['1']
        self.assertEqual(domain_.type, 'domain-name')
        self.assertEqual(domain_.value, _domain)
        self.assertEqual(domain_.x_misp_hostname, hostname)
        self.assertEqual(domain_.x_misp_port, port)
        self.assertEqual(domain_.resolves_to_refs, ['1'])
        self.assertEqual(ip_.type, 'ipv4-addr')
        self.assertEqual(ip_.value, _ip)
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_domain_ip_observable_object_standard(self):
        event = get_event_with_domain_ip_object_standard()
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        _domain1, _domain2, _ip1, _ip2 = (attribute['value'] for attribute in attributes)
        ip1_ = observable_objects['0']
        ip2_ = observable_objects['1']
        domain1_ = observable_objects['2']
        domain2_ = observable_objects['3']
        self.assertEqual(ip1_.type, 'ipv4-addr')
        self.assertEqual(ip1_.value, _ip1)
        self.assertEqual(ip2_.type, 'ipv4-addr')
        self.assertEqual(ip2_.value, _ip2)
        self.assertEqual(domain1_.type, 'domain-name')
        self.assertEqual(domain1_.value, _domain1)
        self.assertEqual(domain1_.resolves_to_refs, ['0', '1'])
        self.assertEqual(domain2_.type, 'domain-name')
        self.assertEqual(domain2_.value, _domain2)
        self.assertEqual(domain2_.resolves_to_refs, ['0', '1'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_email_indicator_object(self):
        event = get_event_with_email_object()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        _from, _to, _cc1, _cc2, _reply_to, _subject, _attachment1, _attachment2, _x_mailer, _user_agent, _boundary, _message_id = (attribute['value'] for attribute in attributes)
        cc1_, cc2_, from_, reply_to_, subject_, to_, x_mailer_, attachment1_, attachment2_, user_agent_, boundary_, message_id_ = pattern[1:-1].split(' AND ')
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
        self.assertEqual(message_id_, f"email-message:x_misp_message_id = '{_message_id}'")
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_email_observable_object(self):
        event = get_event_with_email_object()
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        _from, _to, _cc1, _cc2, _reply_to, _subject, _attachment1, _attachment2, _x_mailer, _user_agent, _boundary, _message_id = (attribute['value'] for attribute in attributes)
        message = observable_objects['0']
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, True)
        self.assertEqual(message.subject, _subject)
        additional_header = message.additional_header_fields
        self.assertEqual(additional_header['Reply-To'], _reply_to)
        self.assertEqual(additional_header['X-Mailer'], _x_mailer)
        self.assertEqual(message.x_misp_message_id, _message_id)
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
        self._check_email_address(address1, _from)
        address2 = observable_objects['2']
        self._check_email_address(address2, _to)
        address3 = observable_objects['3']
        self._check_email_address(address3, _cc1)
        address4 = observable_objects['4']
        self._check_email_address(address4, _cc2)
        file1 = observable_objects['5']
        self.assertEqual(file1.type, 'file')
        self.assertEqual(file1.name, _attachment1)
        file2 = observable_objects['6']
        self.assertEqual(file2.type, 'file')
        self.assertEqual(file2.name, _attachment2)
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_email_indicator_object_with_display_names(self):
        event = get_event_with_email_object_with_display_names()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        _from, _from_name, _to1, _to1_name, _to2, _to2_name, _cc, _cc_name, _bcc, _bcc_name = (attribute['value'] for attribute in attributes)
        bcc_, bcc_name_, cc_, cc_name_, from_, from_name_, to1_, to2_, to1_name_, to2_name_ = pattern[1:-1].split(' AND ')
        self.assertEqual(bcc_, f"email-message:bcc_refs.value = '{_bcc}'")
        self.assertEqual(bcc_name_, f"email-message:bcc_refs.display_name = '{_bcc_name}'")
        self.assertEqual(cc_, f"email-message:cc_refs.value = '{_cc}'")
        self.assertEqual(cc_name_, f"email-message:cc_refs.display_name = '{_cc_name}'")
        self.assertEqual(from_, f"email-message:from_ref.value = '{_from}'")
        self.assertEqual(from_name_, f"email-message:from_ref.display_name = '{_from_name}'")
        self.assertEqual(to1_, f"email-message:to_refs.value = '{_to1}'")
        self.assertEqual(to2_, f"email-message:to_refs.value = '{_to2}'")
        self.assertEqual(to1_name_, f"email-message:to_refs.display_name = '{_to1_name}'")
        self.assertEqual(to2_name_, f"email-message:to_refs.display_name = '{_to2_name}'")
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_email_observable_object_with_display_names(self):
        event = get_event_with_email_object_with_display_names()
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        _from, _from_name, _to1, _to1_name, _to2, _to2_name, _cc, _cc_name, _bcc, _bcc_name = (attribute['value'] for attribute in attributes)
        message = observable_objects['0']
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.from_ref, '1')
        self.assertEqual(message.to_refs, ['2', '3'])
        self.assertEqual(message.cc_refs, ['4'])
        self.assertEqual(message.bcc_refs, ['5'])
        from_ = observable_objects['1']
        self._check_email_address(from_, _from, display_name=_from_name)
        to1_ = observable_objects['2']
        self._check_email_address(to1_, _to1, display_name=_to1_name)
        to2_ = observable_objects['3']
        self._check_email_address(to2_, _to2, display_name=_to2_name)
        cc_ = observable_objects['4']
        self._check_email_address(cc_, _cc, display_name=_cc_name)
        bcc_ = observable_objects['5']
        self._check_email_address(bcc_, _bcc, display_name=_bcc_name)
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_employee_object(self):
        event = get_event_with_employee_object()
        orgc = event['Event']['Orgc']
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event)
        identity, report, employee = self.parser.stix_objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        args = (report, event['Event'], identity_id, timestamp)
        object_ref = self._check_report_features(*args)[0]
        employee_id = f"identity--{misp_object['uuid']}"
        first_name, last_name, description, email, employee_type = (attribute['value'] for attribute in misp_object['Attribute'])
        self.assertEqual(employee.type, 'identity')
        self.assertEqual(object_ref, employee_id)
        self.assertEqual(employee.id, employee_id)
        self.assertEqual(employee.identity_class, 'individual')
        timestamp = self._datetime_from_timestamp(misp_object['timestamp'])
        self.assertEqual(employee.created, timestamp)
        self.assertEqual(employee.modified, timestamp)
        self.assertEqual(employee.name, f"{first_name} {last_name}")
        self.assertEqual(employee.description, description)
        self.assertEqual(employee.contact_information, email)
        self.assertEqual(employee.x_misp_employee_type, employee_type)
        self._populate_documentation(misp_object=misp_object, identity=employee)

    def test_event_with_file_and_pe_indicator_objects(self):
        event = get_event_with_file_and_pe_objects()
        misp_objects, pattern = self._run_indicator_from_objects_tests(event)
        _file, pe, section = misp_objects
        _filename, _md5, _sha1, _sha256, _size, _entropy = (attribute['value'] for attribute in _file['Attribute'])
        pattern = pattern[1:-1].split(' AND ')
        md5_, sha1_, sha256_, name_, size_, entropy_ = pattern[:6]
        self.assertEqual(md5_, f"file:hashes.MD5 = '{_md5}'")
        self.assertEqual(sha1_, f"file:hashes.SHA1 = '{_sha1}'")
        self.assertEqual(sha256_, f"file:hashes.SHA256 = '{_sha256}'")
        self.assertEqual(name_, f"file:name = '{_filename}'")
        self.assertEqual(size_, f"file:size = '{_size}'")
        self.assertEqual(entropy_, f"file:x_misp_entropy = '{_entropy}'")
        self._check_pe_and_section_pattern(pattern[6:], pe, section)
        self._populate_documentation(
            misp_object = misp_objects,
            indicator = self.parser.stix_objects[-1],
            name = 'file with references to pe & pe-section(s)',
            summary = 'File Object with a Windows PE binary extension'
        )

    def test_event_with_file_and_pe_observable_objects(self):
        event = get_event_with_file_and_pe_objects()
        misp_objects, observable_objects = self._run_observable_from_objects_tests(event)
        _file, pe, section = misp_objects
        filename, md5, sha1, sha256, size, entropy = (attribute['value'] for attribute in _file['Attribute'])
        file_object = observable_objects['0']
        self.assertEqual(file_object.type, 'file')
        self.assertEqual(file_object.name, filename)
        hashes = file_object.hashes
        self.assertEqual(hashes['MD5'], md5)
        self.assertEqual(hashes['SHA-1'], sha1)
        self.assertEqual(hashes['SHA-256'], sha256)
        self.assertEqual(file_object.size, int(size))
        self.assertEqual(file_object.x_misp_entropy, entropy)
        self._check_pe_and_section_observable(
            file_object.extensions['windows-pebinary-ext'],
            pe,
            section
        )
        self._populate_documentation(
            misp_object = misp_objects,
            observed_data = self.parser.stix_objects[-1],
            name = 'file with references to pe & pe-section(s)'
        )

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
        ms_data, ms_filename, ms_md5, mime_type = malware_sample_.split(' AND ')
        self.assertEqual(ms_data, f"(file:content_ref.payload_bin = '{attributes[0]['data']}'")
        filename, md5 = _malware_sample.split('|')
        self.assertEqual(ms_filename, f"file:content_ref.x_misp_filename = '{filename}'")
        self.assertEqual(ms_md5, f"file:content_ref.hashes.MD5 = '{md5}'")
        self.assertEqual(mime_type, f"file:content_ref.mime_type = 'application/zip')")
        a_data, a_filename = attachment_.split(' AND ')
        self.assertEqual(a_data, f"(file:content_ref.payload_bin = '{attributes[6]['data']}'")
        self.assertEqual(a_filename, f"file:content_ref.x_misp_filename = '{_attachment}')")
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1],
            summary = 'File Object (potential references to Artifact & Directory Objects)'
        )

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
        self.assertEqual(
            file.x_misp_attachment,
            {
                'value': _attachment,
                'data': attributes[6]['data']
            }
        )
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
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1],
            summary = 'File Object (potential references to Artifact & Directory Objects)'
        )

    def test_event_with_image_indicator_object(self):
        event = get_event_with_image_object()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        attachment, filename, url, text = (attribute['value'] for attribute in attributes)
        name, payload_bin, mime_type, name_ref, url_pattern, text_pattern = pattern[1:-1].split(' AND ')
        self.assertEqual(name, f"file:name = '{filename}'")
        data = attributes[0]['data'].replace('\\', '')
        self.assertEqual(payload_bin, f"file:content_ref.payload_bin = '{data}'")
        self.assertEqual(mime_type, f"file:content_ref.mime_type = 'image/png'")
        self.assertEqual(name_ref, f"file:content_ref.x_misp_filename = '{attachment}'")
        self.assertEqual(url_pattern, f"file:content_ref.url = '{url}'")
        self.assertEqual(text_pattern, f"file:x_misp_image_text = '{text}'")
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_image_observable_object(self):
        event = get_event_with_image_object()
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        attachment, filename, url, text = (attribute['value'] for attribute in attributes)
        file = observable_objects['0']
        self.assertEqual(file.type, 'file')
        self.assertEqual(file.name, filename)
        self.assertEqual(file.content_ref, '1')
        self.assertEqual(file.x_misp_image_text, text)
        artifact = observable_objects['1']
        self.assertEqual(artifact.type, 'artifact')
        self.assertEqual(artifact.payload_bin, attributes[0]['data'].replace('\\', ''))
        self.assertEqual(artifact.mime_type, 'image/png')
        self.assertEqual(artifact.x_misp_url, url)
        self.assertEqual(artifact.x_misp_filename, attachment)
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

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
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1]
        )

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
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_legal_entity_object(self):
        event = get_event_with_legal_entity_object()
        orgc = event['Event']['Orgc']
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event)
        identity, report, legal_entity = self.parser.stix_objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        args = (report, event['Event'], identity_id, timestamp)
        object_ref = self._check_report_features(*args)[0]
        legal_entity_id = f"identity--{misp_object['uuid']}"
        name, description, business, phone, logo = (attribute['value'] for attribute in misp_object['Attribute'])
        self.assertEqual(legal_entity.type, 'identity')
        self.assertEqual(object_ref, legal_entity_id)
        self.assertEqual(legal_entity.id, legal_entity_id)
        self.assertEqual(legal_entity.identity_class, 'organization')
        timestamp = self._datetime_from_timestamp(misp_object['timestamp'])
        self.assertEqual(legal_entity.created, timestamp)
        self.assertEqual(legal_entity.modified, timestamp)
        self.assertEqual(legal_entity.name, name)
        self.assertEqual(legal_entity.description, description)
        self.assertEqual(legal_entity.sectors, [business])
        self.assertEqual(legal_entity.contact_information, f"phone-number: {phone}")
        self.assertEqual(legal_entity.x_misp_logo['value'], logo)
        self.assertEqual(
            legal_entity.x_misp_logo['data'],
            misp_object['Attribute'][-1]['data'].replace('\\', '')
        )
        self._populate_documentation(misp_object=misp_object, identity=legal_entity)

    def test_event_with_lnk_indicator_object(self):
        event = get_event_with_lnk_object()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        filename, fullpath, md5, sha1, sha256, malware_sample, size_in_bytes, creation, modification, access = (attribute['value'] for attribute in attributes)
        name, directory, md5_pattern, sha1_pattern, sha256_pattern, artifact, size, ctime, mtime, atime = self._reassemble_pattern(pattern[1:-1])
        self.assertEqual(name, f"file:name = '{filename}'")
        self.assertEqual(directory, f"file:parent_directory_ref.path = '{fullpath}'")
        self.assertEqual(md5_pattern, f"file:hashes.MD5 = '{md5}'")
        self.assertEqual(sha1_pattern, f"file:hashes.SHA1 = '{sha1}'")
        self.assertEqual(sha256_pattern, f"file:hashes.SHA256 = '{sha256}'")
        ms_data, ms_filename, ms_md5, mime_type = artifact.split(' AND ')
        data = attributes[5]['data'].replace('\\', '')
        self.assertEqual(ms_data, f"(file:content_ref.payload_bin = '{data}'")
        filename, md5 = malware_sample.split('|')
        self.assertEqual(ms_filename, f"file:content_ref.x_misp_filename = '{filename}'")
        self.assertEqual(ms_md5, f"file:content_ref.hashes.MD5 = '{md5}'")
        self.assertEqual(mime_type, f"file:content_ref.mime_type = 'application/zip')")
        self.assertEqual(size, f"file:size = '{size_in_bytes}'")
        self.assertEqual(ctime, f"file:x_misp_lnk_creation_time = '{creation}'")
        self.assertEqual(mtime, f"file:x_misp_lnk_modification_time = '{modification}'")
        self.assertEqual(atime, f"file:x_misp_lnk_access_time = '{access}'")
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_lnk_observable_object(self):
        event = get_event_with_lnk_object()
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        filename, fullpath, md5, sha1, sha256, malware_sample, size_in_bytes, creation, modification, access = (attribute['value'] for attribute in attributes)
        file = observable_objects['0']
        self.assertEqual(file.type, 'file')
        self.assertEqual(file.name, filename)
        self.assertEqual(file.hashes['MD5'], md5)
        self.assertEqual(file.hashes['SHA-1'], sha1)
        self.assertEqual(file.hashes['SHA-256'], sha256)
        self.assertEqual(file.size, int(size_in_bytes))
        directory = observable_objects['1']
        self.assertEqual(directory.type, 'directory')
        self.assertEqual(directory.path, fullpath)
        self.assertEqual(file.parent_directory_ref, '1')
        artifact = observable_objects['2']
        self.assertEqual(artifact.type, 'artifact')
        self.assertEqual(artifact.payload_bin, attributes[5]['data'].replace('\\', ''))
        self.assertEqual(artifact.mime_type, 'application/zip')
        filename, md5 = malware_sample.split('|')
        self.assertEqual(artifact.x_misp_filename, filename)
        self.assertEqual(artifact.hashes['MD5'], md5)
        self.assertEqual(file.content_ref, '2')
        self.assertEqual(file.x_misp_lnk_creation_time, creation)
        self.assertEqual(file.x_misp_lnk_modification_time, modification)
        self.assertEqual(file.x_misp_lnk_access_time, access)
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_mutex_indicator_object(self):
        event = get_event_with_mutex_object()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        _name, _description, _os = (attribute['value'] for attribute in attributes)
        name_, description_, os_ = pattern[1:-1].split(' AND ')
        self.assertEqual(name_, f"mutex:name = '{_name}'")
        self.assertEqual(description_, f"mutex:x_misp_description = '{_description}'")
        self.assertEqual(os_, f"mutex:x_misp_operating_system = '{_os}'")
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_mutex_observable_object(self):
        event = get_event_with_mutex_object()
        attributes, observable_object = self._run_observable_from_object_tests(event)
        name, description, _os = (attribute['value'] for attribute in attributes)
        mutex = observable_object['0']
        self.assertEqual(mutex.type, 'mutex')
        self.assertEqual(mutex.name, name)
        self.assertEqual(mutex.x_misp_description, description)
        self.assertEqual(mutex.x_misp_operating_system, _os)
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

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
        self.assertEqual(layer3_, f"network-traffic:protocols[0] = '{_layer3.lower()}'")
        self.assertEqual(layer4_, f"network-traffic:protocols[1] = '{_layer4.lower()}'")
        self.assertEqual(layer7_, f"network-traffic:protocols[2] = '{_layer7.lower()}'")
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1],
            summary = 'Network Traffic, IPv4/IPv6 Address & Domain Name Objects'
        )

    def test_event_with_network_connection_observable_object(self):
        event = get_event_with_network_connection_object()
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        ip_src, ip_dst, src_port, dst_port, hostname, layer3, layer4, layer7 = (attribute['value'] for attribute in attributes)
        network_traffic = observable_objects['0']
        self.assertEqual(network_traffic.type, 'network-traffic')
        self.assertEqual(network_traffic.src_port, int(src_port))
        self.assertEqual(network_traffic.dst_port, int(dst_port))
        self.assertEqual(network_traffic.protocols, [layer3.lower(), layer4.lower(), layer7.lower()])
        self.assertEqual(network_traffic.src_ref, '1')
        self.assertEqual(network_traffic.dst_ref, '2')
        self.assertEqual(network_traffic.x_misp_hostname_dst, hostname)
        address1 = observable_objects['1']
        self.assertEqual(address1.type, 'ipv4-addr')
        self.assertEqual(address1.value, ip_src)
        address2 = observable_objects['2']
        self.assertEqual(address2.type, 'ipv4-addr')
        self.assertEqual(address2.value, ip_dst)
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_network_socket_indicator_object(self):
        event = get_event_with_network_socket_object()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        _ip_src, _ip_dst, _src_port, _dst_port, _hostname, _address_family, _domain_family, _socket_type, _state, _protocol = (attribute['value'] for attribute in attributes)
        ip_src_, ip_dst_, hostname_, dst_port_, src_port_, protocol_, address_family_, domain_family_, socket_type_, state_ = self._reassemble_pattern(pattern[1:-1])
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
        self.assertEqual(protocol_, f"network-traffic:protocols[0] = '{_protocol.lower()}'")
        self.assertEqual(address_family_, f"network-traffic:extensions.'socket-ext'.address_family = '{_address_family}'")
        self.assertEqual(domain_family_, f"network-traffic:extensions.'socket-ext'.protocol_family = '{_domain_family}'")
        self.assertEqual(socket_type_, f"network-traffic:extensions.'socket-ext'.socket_type = '{_socket_type}'")
        self.assertEqual(state_, f"network-traffic:extensions.'socket-ext'.is_{_state} = true")
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1],
            summary = 'Network Traffic with a socket extension, IPv4/IPv6 Address & Domain Name Objects'
        )

    def test_event_with_network_socket_observable_object(self):
        event = get_event_with_network_socket_object()
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        ip_src, ip_dst, src_port, dst_port, hostname, address_family, domain_family, socket_type, state, protocol = (attribute['value'] for attribute in attributes)
        network_traffic = observable_objects['0']
        self.assertEqual(network_traffic.type, 'network-traffic')
        self.assertEqual(network_traffic.src_port, int(src_port))
        self.assertEqual(network_traffic.dst_port, int(dst_port))
        self.assertEqual(network_traffic.protocols, [protocol.lower()])
        socket_ext = network_traffic.extensions['socket-ext']
        self.assertEqual(socket_ext.address_family, address_family)
        self.assertEqual(socket_ext.protocol_family, domain_family)
        self.assertEqual(socket_ext.socket_type, socket_type)
        self.assertEqual(getattr(socket_ext, f'is_{state}'), True)
        self.assertEqual(network_traffic.x_misp_hostname_dst, hostname)
        self.assertEqual(network_traffic.src_ref, '1')
        self.assertEqual(network_traffic.dst_ref, '2')
        address1 = observable_objects['1']
        self.assertEqual(address1.type, 'ipv4-addr')
        self.assertEqual(address1.value, ip_src)
        address2 = observable_objects['2']
        self.assertEqual(address2.type, 'ipv4-addr')
        self.assertEqual(address2.value, ip_dst)
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_news_agency_object(self):
        event = get_event_with_news_agency_object()
        orgc = event['Event']['Orgc']
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event)
        identity, report, news_agency = self.parser.stix_objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        args = (report, event['Event'], identity_id, timestamp)
        object_ref = self._check_report_features(*args)[0]
        news_agency_id = f"identity--{misp_object['uuid']}"
        name, address1, email1, phone1, address2, email2, phone2, link, attachment = (attribute['value'] for attribute in misp_object['Attribute'])
        self.assertEqual(news_agency.type, 'identity')
        self.assertEqual(object_ref, news_agency_id)
        self.assertEqual(news_agency.id, news_agency_id)
        self.assertEqual(news_agency.identity_class, 'organization')
        timestamp = self._datetime_from_timestamp(misp_object['timestamp'])
        self.assertEqual(news_agency.created, timestamp)
        self.assertEqual(news_agency.modified, timestamp)
        self.assertEqual(news_agency.name, name)
        self.assertEqual(
            news_agency.contact_information,
            f"address: {address1}; {address2} / e-mail: {email1}; {email2} / phone-number: {phone1}; {phone2}"
        )
        self.assertEqual(news_agency.x_misp_link, link)
        self.assertEqual(news_agency.x_misp_attachment['value'], attachment)
        self.assertEqual(
            news_agency.x_misp_attachment['data'],
            misp_object['Attribute'][-1]['data'].replace('\\', '')
        )
        self._populate_documentation(misp_object=misp_object, identity=news_agency)

    def test_event_with_organization_object(self):
        event = get_event_with_organization_object()
        orgc = event['Event']['Orgc']
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event)
        identity, report, organization = self.parser.stix_objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        args = (report, event['Event'], identity_id, timestamp)
        object_ref = self._check_report_features(*args)[0]
        organization_id = f"identity--{misp_object['uuid']}"
        name, description, address, email, phone, role, alias = (attribute['value'] for attribute in misp_object['Attribute'])
        self.assertEqual(organization.type, 'identity')
        self.assertEqual(object_ref, organization_id)
        self.assertEqual(organization.id, organization_id)
        self.assertEqual(organization.identity_class, 'organization')
        timestamp = self._datetime_from_timestamp(misp_object['timestamp'])
        self.assertEqual(organization.created, timestamp)
        self.assertEqual(organization.modified, timestamp)
        self.assertEqual(organization.name, name)
        self.assertEqual(organization.description, description)
        self.assertEqual(
            organization.contact_information,
            f"address: {address} / e-mail: {email} / phone-number: {phone}"
        )
        self.assertEqual(organization.x_misp_role, role)
        self.assertEqual(organization.x_misp_alias, alias)
        self._populate_documentation(misp_object = misp_object, identity=organization)

    def test_event_with_pe_and_section_indicator_objects(self):
        event = get_event_with_pe_objects()
        misp_objects, pattern = self._run_indicator_from_objects_tests(event)
        self._check_pe_and_section_pattern(pattern[1:-1].split(' AND '), *misp_objects)
        self._populate_documentation(
            misp_object = misp_objects,
            indicator = self.parser.stix_objects[-1],
            name = 'pe & pe-sections',
            summary = 'Windows PE binary extension within a File Object'
        )

    def test_event_with_pe_and_section_observable_objects(self):
        event = get_event_with_pe_objects()
        misp_objects, observable_objects = self._run_observable_from_objects_tests(event)
        self._check_pe_and_section_observable(
            observable_objects['0'].extensions['windows-pebinary-ext'],
            *misp_objects
        )
        self._populate_documentation(
            misp_object = misp_objects,
            observed_data = self.parser.stix_objects[-1],
            name = 'pe & pe-sections'
        )

    def test_event_with_process_indicator_object(self):
        event = get_event_with_process_object_v2()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        _pid, _child_pid, _parent_pid, _name, _image, _parent_image, _port, _command_line, _parent_name = (attribute['value'] for attribute in attributes)
        name_, pid_, image_, command_line_, parent_image_, parent_pid_, parent_name_, child_pid_, port_ = pattern[1:-1].split(' AND ')
        self.assertEqual(name_, f"process:name = '{_name}'")
        self.assertEqual(pid_, f"process:pid = '{_pid}'")
        self.assertEqual(image_, f"process:binary_ref.name = '{_image}'")
        self.assertEqual(command_line_, f"process:parent_ref.command_line = '{_command_line}'")
        self.assertEqual(parent_image_, f"process:parent_ref.binary_ref.name = '{_parent_image}'")
        self.assertEqual(parent_pid_, f"process:parent_ref.pid = '{_parent_pid}'")
        self.assertEqual(parent_name_, f"process:parent_ref.name = '{_parent_name}'")
        self.assertEqual(child_pid_, f"process:child_refs[0].pid = '{_child_pid}'")
        self.assertEqual(port_, f"process:x_misp_port = '{_port}'")
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1],
            summary = 'Process Objects (potential reference to File Objects)'
        )

    def test_event_with_process_observable_object(self):
        event = get_event_with_process_object_v2()
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        pid, child_pid, parent_pid, name, image, parent_image, port, command_line, parent_name = (attribute['value'] for attribute in attributes)
        process = observable_objects['0']
        self.assertEqual(process.type, 'process')
        self.assertEqual(process.pid, int(pid))
        self.assertEqual(process.name, name)
        self.assertEqual(process.x_misp_port, port)
        self.assertEqual(process.parent_ref, '1')
        self.assertEqual(process.child_refs, ['3'])
        self.assertEqual(process.binary_ref, '4')
        parent_process = observable_objects['1']
        self.assertEqual(parent_process.type, 'process')
        self.assertEqual(parent_process.pid, int(parent_pid))
        self.assertEqual(parent_process.command_line, command_line)
        self.assertEqual(parent_process.name, parent_name)
        self.assertEqual(parent_process.binary_ref, '2')
        parent_image_object = observable_objects['2']
        self.assertEqual(parent_image_object.type, 'file')
        self.assertEqual(parent_image_object.name, parent_image)
        child_process = observable_objects['3']
        self.assertEqual(child_process.type, 'process')
        self.assertEqual(child_process.pid, int(child_pid))
        image_object = observable_objects['4']
        self.assertEqual(image_object.type, 'file')
        self.assertEqual(image_object.name, image)
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_registry_key_indicator_object(self):
        event = get_event_with_registry_key_object()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        _key, _hive, _name, _data, _data_type, _modified = (attribute['value'] for attribute in attributes)
        key_, data_, data_type_, name_, hive_, modified_ = pattern[1:-1].split(' AND ')
        key = _key.replace('\\', '\\\\')
        self.assertEqual(key_, f"windows-registry-key:key = '{key}'")
        self.assertEqual(data_, f"windows-registry-key:values[0].data = '{self._sanitize_registry_key_value(_data)}'")
        self.assertEqual(data_type_, f"windows-registry-key:values[0].data_type = '{_data_type}'")
        self.assertEqual(name_, f"windows-registry-key:values[0].name = '{_name}'")
        self.assertEqual(hive_, f"windows-registry-key:x_misp_hive = '{_hive}'")
        self.assertEqual(modified_, f"windows-registry-key:x_misp_last_modified = '{_modified}'")
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_registry_key_observable_object(self):
        event = get_event_with_registry_key_object()
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        key, hive, name, data, data_type, modified = (attribute['value'] for attribute in attributes)
        registry_key = observable_objects['0']
        self.assertEqual(registry_key.type, 'windows-registry-key')
        self.assertEqual(registry_key.key, key)
        self.assertEqual(registry_key.x_misp_last_modified, modified)
        self.assertEqual(registry_key.x_misp_hive, hive)
        registry_value = registry_key['values'][0]
        self.assertEqual(registry_value.data, data)
        self.assertEqual(registry_value.data_type, data_type)
        self.assertEqual(registry_value.name, name)
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_url_indicator_object(self):
        event = get_event_with_url_object()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        _url, _domain, _host, _ip, _port = (attribute['value'] for attribute in attributes)
        url_, domain_, host_, ip_, port_ = pattern[1:-1].split(' AND ')
        self.assertEqual(url_, f"url:value = '{_url}'")
        self.assertEqual(domain_, f"url:x_misp_domain = '{_domain}'")
        self.assertEqual(host_, f"url:x_misp_host = '{_host}'")
        self.assertEqual(ip_, f"url:x_misp_ip = '{_ip}'")
        self.assertEqual(port_, f"url:x_misp_port = '{_port}'")
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_url_observable_object(self):
        event = get_event_with_url_object()
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        url, domain, host, ip, port = (attribute['value'] for attribute in attributes)
        url_object = observable_objects['0']
        self.assertEqual(url_object.type, 'url')
        self.assertEqual(url_object.value, url)
        self.assertEqual(url_object.x_misp_domain, domain)
        self.assertEqual(url_object.x_misp_host, host)
        self.assertEqual(url_object.x_misp_ip, ip)
        self.assertEqual(url_object.x_misp_port, port)
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_user_account_indicator_object(self):
        event = get_event_with_user_account_object()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        _username, _userid, _display_name, _passwd, _group1, _group2, _groupid, _home, _account_type, _plc = (attribute['value'] for attribute in attributes)
        account_type_, display_name_, userid_, username_, plc_, group1_, group2_, groupid_, home_, passwd_ = pattern[1:-1].split(' AND ')
        self.assertEqual(account_type_, f"user-account:account_type = '{_account_type}'")
        self.assertEqual(display_name_, f"user-account:display_name = '{_display_name}'")
        self.assertEqual(userid_, f"user-account:user_id = '{_userid}'")
        self.assertEqual(username_, f"user-account:account_login = '{_username}'")
        self.assertEqual(plc_, f"user-account:password_last_changed = '{_plc}'")
        self.assertEqual(group1_, f"user-account:extensions.'unix-account-ext'.groups = '{_group1}'")
        self.assertEqual(group2_, f"user-account:extensions.'unix-account-ext'.groups = '{_group2}'")
        self.assertEqual(groupid_, f"user-account:extensions.'unix-account-ext'.gid = '{_groupid}'")
        self.assertEqual(home_, f"user-account:extensions.'unix-account-ext'.home_dir = '{_home}'")
        self.assertEqual(passwd_, f"user-account:x_misp_password = '{_passwd}'")
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_user_account_observable_object(self):
        event = get_event_with_user_account_object()
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        username, userid, display_name, passwd, group1, group2, groupid, home, account_type, plc = (attribute['value'] for attribute in attributes)
        user_account = observable_objects['0']
        self.assertEqual(user_account.type, 'user-account')
        self.assertEqual(user_account.user_id, userid)
        self.assertEqual(user_account.account_login, username)
        self.assertEqual(user_account.account_type, account_type)
        self.assertEqual(user_account.display_name, display_name)
        extension = user_account.extensions['unix-account-ext']
        self.assertEqual(extension.gid, int(groupid))
        self.assertEqual(extension.groups, [group1, group2])
        self.assertEqual(extension.home_dir, home)
        self.assertEqual(user_account.x_misp_password, passwd)
        self.assertEqual(
            datetime.strftime(user_account.password_last_changed, '%Y-%m-%dT%H:%M:%S'),
            plc
        )
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_vulnerability_object(self):
        event = get_event_with_vulnerability_object()
        orgc = event['Event']['Orgc']
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event)
        identity, report, vulnerability = self.parser.stix_objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        args = (report, event['Event'], identity_id, timestamp)
        object_ref = self._check_report_features(*args)[0]
        self._check_object_vulnerability_features(vulnerability, misp_object, identity_id, object_ref)
        self._populate_documentation(misp_object=misp_object, vulnerability=vulnerability)

    def test_event_with_x509_indicator_object(self):
        event = get_event_with_x509_object()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        _issuer, _pem, _pia, _pie, _pim, _srlnmbr, _signalg, _subject, _vnb, _vna, _version, _md5, _sha1 = (attribute['value'] for attribute in attributes)
        md5_, sha1_, issuer_, pia_, pie_, pim_, srlnmbr_, signalg_, subject_, version_, vna_, vnb_, pem_ = pattern[1:-1].split(' AND ')
        self.assertEqual(md5_, f"x509-certificate:hashes.MD5 = '{_md5}'")
        self.assertEqual(sha1_, f"x509-certificate:hashes.SHA1 = '{_sha1}'")
        self.assertEqual(issuer_, f"x509-certificate:issuer = '{_issuer}'")
        self.assertEqual(pia_, f"x509-certificate:subject_public_key_algorithm = '{_pia}'")
        self.assertEqual(pie_, f"x509-certificate:subject_public_key_exponent = '{_pie}'")
        self.assertEqual(pim_, f"x509-certificate:subject_public_key_modulus = '{_pim}'")
        self.assertEqual(srlnmbr_, f"x509-certificate:serial_number = '{_srlnmbr}'")
        self.assertEqual(signalg_, f"x509-certificate:signature_algorithm = '{_signalg}'")
        self.assertEqual(subject_, f"x509-certificate:subject = '{_subject}'")
        self.assertEqual(version_, f"x509-certificate:version = '{_version}'")
        self.assertEqual(vna_, f"x509-certificate:validity_not_after = '{_vna}'")
        self.assertEqual(vnb_, f"x509-certificate:validity_not_before = '{_vnb}'")
        self.assertEqual(pem_, f"x509-certificate:x_misp_pem = '{_pem}'")
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_x509_observable_object(self):
        event = get_event_with_x509_object()
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        issuer, pem, pia, pie, pim, srlnmbr, signalg, subject, vnb, vna, version, md5, sha1 = (attribute['value'] for attribute in attributes)
        x509 = observable_objects['0']
        self.assertEqual(x509.type, 'x509-certificate')
        hashes = x509.hashes
        self.assertEqual(hashes['MD5'], md5)
        self.assertEqual(hashes['SHA-1'], sha1)
        self.assertEqual(x509.version, version)
        self.assertEqual(x509.serial_number, srlnmbr)
        self.assertEqual(x509.signature_algorithm, signalg)
        self.assertEqual(x509.issuer, issuer)
        self.assertEqual(
            datetime.strftime(x509.validity_not_before, '%Y-%m-%dT%H:%M:%S'),
            vnb
        )
        self.assertEqual(
            datetime.strftime(x509.validity_not_after, '%Y-%m-%dT%H:%M:%S'),
            vna
        )
        self.assertEqual(x509.subject, subject)
        self.assertEqual(x509.subject_public_key_algorithm, pia)
        self.assertEqual(x509.subject_public_key_modulus, pim)
        self.assertEqual(x509.subject_public_key_exponent, int(pie))
        self.assertEqual(x509.x_misp_pem, pem)
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_object_references(self):
        event = get_event_with_object_references()
        orgc = event['Event']['Orgc']
        ap_object, as_object, btc_object, coa_object, ip_object, vuln_object = deepcopy(event['Event']['Object'])
        self.parser.parse_misp_event(event)
        bundle = self._check_bundle_features(14)
        identity, report, attack_pattern, observed_data, custom, coa, indicator, vulnerability, *relationships = bundle.objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event['Event'], identity_id, timestamp)
        self.assertEqual(report.published, timestamp)
        ap_ref, observed_data_ref, custom_ref, coa_ref, indicator_ref, vuln_ref, *relationship_refs = object_refs
        self.assertEqual(attack_pattern.id, ap_ref)
        self.assertEqual(observed_data.id, observed_data_ref)
        self.assertEqual(custom.id, custom_ref)
        self.assertEqual(coa.id, coa_ref)
        self.assertEqual(indicator.id, indicator_ref)
        self.assertEqual(vulnerability.id, vuln_ref)
        for relationship, relationship_ref in zip(relationships, relationship_refs):
            self.assertEqual(relationship.id, relationship_ref)
        relation1, relation2, relation3, relation4, relation5, relation6 = relationships
        self._check_relationship_features(
            relation1,
            ap_ref,
            indicator_ref,
            'threatens',
            self._datetime_from_timestamp(ap_object['timestamp'])
        )
        self._check_relationship_features(
            relation2,
            observed_data_ref,
            indicator_ref,
            'includes',
            self._datetime_from_timestamp(as_object['timestamp'])
        )
        self._check_relationship_features(
            relation3,
            custom_ref,
            indicator_ref,
            'connected-to',
            self._datetime_from_timestamp(btc_object['timestamp'])
        )
        self._check_relationship_features(
            relation4,
            coa_ref,
            vuln_ref,
            'protects-against',
            self._datetime_from_timestamp(coa_object['timestamp'])
        )
        self._check_relationship_features(
            relation5,
            indicator_ref,
            coa_ref,
            'protected-with',
            self._datetime_from_timestamp(ip_object['timestamp'])
        )
        self._check_relationship_features(
            relation6,
            vuln_ref,
            indicator_ref,
            'affects',
            self._datetime_from_timestamp(vuln_object['timestamp'])
        )

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

    def test_event_with_intrusion_set_galaxy(self):
        event = get_event_with_intrusion_set_galaxy()
        galaxy = event['Event']['Galaxy'][0]
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        intrusion_set = self._run_galaxy_tests(event, timestamp)
        self.assertEqual(intrusion_set.type, 'intrusion-set')
        self._check_galaxy_features(intrusion_set, galaxy, timestamp, False, True)

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


class TestSTIX20ExportInteroperability(TestSTIX2Export):
    def setUp(self):
        self.parser = MISPtoSTIX20Parser(interoperability=True)

    def _run_galaxy_tests(self, event, timestamp):
        orgc = event['Event']['Orgc']
        self.parser.parse_misp_event(event)
        mitre_identity, identity, report, stix_object = self.parser.stix_objects
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event['Event'], identity_id, timestamp)[0]
        self.assertEqual(report.published, timestamp)
        self.assertEqual(stix_object.id, object_ref)
        self.assertEqual(stix_object.created_by_ref, mitre_identity.id)
        return stix_object

    def test_attack_pattern(self):
        event = get_event_with_attack_pattern_galaxy()
        galaxy = event['Event']['Galaxy'][0]
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        attack_pattern = self._run_galaxy_tests(event, timestamp)
        self.assertEqual(attack_pattern.type, 'attack-pattern')
        name, reference = galaxy['GalaxyCluster'][0]['value'].split(' - ')
        self.assertEqual(attack_pattern.name, name)
        self.assertEqual(attack_pattern.external_references[0].external_id, reference)

    def test_course_of_action(self):
        event = get_event_with_course_of_action_galaxy()
        galaxy = event['Event']['Galaxy'][0]
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        course_of_action = self._run_galaxy_tests(event, timestamp)
        self.assertEqual(course_of_action.type, 'course-of-action')
        name, reference = galaxy['GalaxyCluster'][0]['value'].split(' - ')
        self.assertEqual(course_of_action.name, name)
        self.assertEqual(course_of_action.external_references[0].external_id, reference)

    def test_intrusion_set(self):
        event = get_event_with_intrusion_set_galaxy()
        galaxy = event['Event']['Galaxy'][0]
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        intrusion_set = self._run_galaxy_tests(event, timestamp)
        self.assertEqual(intrusion_set.type, 'intrusion-set')
        name, reference = galaxy['GalaxyCluster'][0]['value'].split(' - ')
        self.assertEqual(intrusion_set.name, name)
        self.assertEqual(intrusion_set.external_references[0].external_id, reference)

    def test_malware(self):
        event = get_event_with_malware_galaxy()
        galaxy = event['Event']['Galaxy'][0]
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        malware = self._run_galaxy_tests(event, timestamp)
        self.assertEqual(malware.type, 'malware')
        name, reference = galaxy['GalaxyCluster'][0]['value'].split(' - ')
        self.assertEqual(malware.name, name)
        self.assertEqual(malware.external_references[0].external_id, reference)

    def test_tool(self):
        event = get_event_with_tool_galaxy()
        galaxy = event['Event']['Galaxy'][0]
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        tool = self._run_galaxy_tests(event, timestamp)
        self.assertEqual(tool.type, 'tool')
        name, reference = galaxy['GalaxyCluster'][0]['value'].split(' - ')
        self.assertEqual(tool.name, name)
        self.assertEqual(tool.external_references[0].external_id, reference)


class TestCollectionStix20Export(TestCollectionSTIX2Export):
    def test_attributes_collection(self):
        name = 'test_attributes_collection'
        to_test_name = f'{name}.json.out'
        reference_name = f'{name}_stix20.json'
        output_file = self._current_path / to_test_name
        input_files = [self._current_path / f'{name}_{n}.json' for n in (1, 2)]
        self.assertEqual(misp_collection_to_stix2_0(output_file, *input_files), 1)
        self._check_stix2_results_export(to_test_name, reference_name)
        self.assertEqual(misp_collection_to_stix2_0(output_file, *input_files, in_memory=True), 1)
        self._check_stix2_results_export(to_test_name, reference_name)

    def test_events_collection(self):
        name = 'test_events_collection'
        to_test_name = f'{name}.json.out'
        reference_name = f'{name}_stix20.json'
        output_file = self._current_path / to_test_name
        input_files = [self._current_path / f'{name}_{n}.json' for n in (1, 2)]
        self.assertEqual(misp_collection_to_stix2_0(output_file, *input_files), 1)
        self._check_stix2_results_export(to_test_name, reference_name)
        self.assertEqual(misp_collection_to_stix2_0(output_file, *input_files, in_memory=True), 1)
        self._check_stix2_results_export(to_test_name, reference_name)

    def test_event_export(self):
        name = 'test_events_collection_1.json'
        self.assertEqual(misp_to_stix2_0(self._current_path / name), 1)
        self._check_stix2_results_export(f'{name}.out', 'test_event_stix20.json')
