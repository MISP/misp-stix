#!/usr/bin/env python
# -*- coding: utf-8 -*-

from datetime import datetime
from misp_stix_converter import (
    MISPtoSTIX20Mapping, MISPtoSTIX20Parser, misp_collection_to_stix2,
    misp_to_stix2)
from pymisp import MISPAttribute, MISPEvent
from .test_events import *
from .update_documentation import (
    AttributesDocumentationUpdater, GalaxiesDocumentationUpdater,
    ObjectsDocumentationUpdater)
from ._test_stix import TestSTIX20
from ._test_stix_export import TestCollectionSTIX2Export, TestSTIX2Export, TestSTIX20Export


class TestSTIX20GenericExport(TestSTIX20Export, TestSTIX20):
    def setUp(self):
        self.parser = MISPtoSTIX20Parser()

    @classmethod
    def tearDownClass(self):
        attributes_documentation = AttributesDocumentationUpdater(
            'misp_attributes_to_stix20',
            self._attributes_v20,
            'export'
        )
        attributes_documentation.check_export_mapping('stix20')
        objects_documentation = ObjectsDocumentationUpdater(
            'misp_objects_to_stix20',
            self._objects_v20,
            'export'
        )
        objects_documentation.check_export_mapping('stix20')
        galaxies_documentation = GalaxiesDocumentationUpdater(
            'misp_galaxies_to_stix20',
            self._galaxies_v20,
            'export'
        )
        galaxies_documentation.check_export_mapping('stix20')

    def _check_bundle_features(self, length):
        bundle = self.parser.bundle
        self.assertEqual(bundle.type, 'bundle')
        self.assertEqual(bundle.spec_version, '2.0')
        self.assertEqual(len(bundle.objects), length)
        return bundle


class TestSTIX20EventExport(TestSTIX20GenericExport):
    def _check_opinion_features(self, opinion, sighting, object_id):
        self.assertEqual(opinion.type, 'x-misp-opinion')
        self.assertEqual(opinion.id, f"x-misp-opinion--{sighting['uuid']}")
        self._assert_multiple_equal(
            opinion.created,
            opinion.modified,
            self._datetime_from_timestamp(sighting['date_sighting'])
        )
        self.assertEqual(opinion.object_ref, object_id)
        self.assertEqual(opinion.x_misp_author, sighting['Organisation']['name'])
        self.assertEqual(
            opinion.x_misp_author_ref,
            f"identity--{sighting['Organisation']['uuid']}"
        )
        self.assertEqual(opinion.x_misp_explanation, "False positive Sighting")
        self.assertEqual(opinion.x_misp_opinion, "strongly-disagree")

    def _test_base_event(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        bundle = self._check_bundle_features(3)
        identity, report, custom = bundle.objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event, identity_id, timestamp)[0]
        self.assertEqual(report.published, timestamp)
        self.assertEqual(custom.type, 'x-misp-event-note')
        self._assert_multiple_equal(
            custom.id,
            f"x-misp-event-note--{event['uuid']}",
            object_ref
        )
        self.assertEqual(custom.created_by_ref, identity_id)
        self.assertEqual(custom.created, timestamp)
        self.assertEqual(custom.modified, timestamp)
        self.assertEqual(custom.object_ref, report.id)
        self.assertEqual(
            custom.x_misp_event_note,
            "This MISP Event is empty and contains no attribute, object, galaxy or tag."
        )

    def _test_event_with_escaped_characters(self, event):
        attributes = deepcopy(event['Attribute'])
        self.parser.parse_misp_event(event)
        bundle = self._check_bundle_features(48)
        _, _, *indicators = bundle.objects
        self.assertIn(attributes[0]['value'][2:], indicators[0].pattern)
        for attribute, indicator in zip(attributes[1:], indicators[1:]):
            self.assertEqual(indicator.type, 'indicator')
            attribute_value = attribute['value']
            if '|' in attribute_value:
                attribute_value, value = attribute_value.split('|')
                self.assertIn(self._sanitize_pattern_value(value), indicator.pattern)
            self.assertIn(self._sanitize_pattern_value(attribute_value), indicator.pattern)
            if attribute.get('data'):
                data = attribute['data']
                if not isinstance(data, str):
                    data = b64encode(data.getvalue()).decode()
                self.assertIn(self._sanitize_pattern_value(data), indicator.pattern)

    def _test_event_with_sightings(self, event):
        orgc = event['Orgc']
        attribute1, attribute2 = event['Attribute']
        sightings1 = attribute1['Sighting']
        sightings2 = attribute2['Sighting']
        self.parser.parse_misp_event(event)
        identity, identity1, identity2, identity3, identity4, report, *stix_objects = self.parser.stix_objects
        identities = (identity1, identity2, identity3, identity4)
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event, identity_id, timestamp)
        for stix_object, object_ref in zip(stix_objects, object_refs):
            self.assertEqual(stix_object.id, object_ref)
        self._check_identities_from_sighting(
            identities,
            tuple(f"identity--{sighting['Organisation']['uuid']}" for sighting in sightings1),
            tuple(sighting['Organisation']['name'] for sighting in sightings2)
        )
        observed_data, sighting1, sighting2, opinion1, opinion2, indicator, sighting3, opinion3, sighting4, opinion4 = stix_objects
        self._check_sighting_features(
            sighting1,
            sightings1[0],
            observed_data.id,
            identity1.id
        )
        self._check_sighting_features(
            sighting2,
            sightings1[1],
            observed_data.id,
            identity2.id
        )
        self._check_opinion_features(
            opinion1,
            sightings1[2],
            observed_data.id
        )
        self._check_opinion_features(
            opinion2,
            sightings1[3],
            observed_data.id
        )
        self._check_sighting_features(
            sighting3,
            sightings2[0],
            indicator.id,
            identity1.id
        )
        self._check_opinion_features(
            opinion3,
            sightings2[1],
            indicator.id
        )
        self._check_sighting_features(
            sighting4,
            sightings2[2],
            indicator.id,
            identity3.id
        )
        self._check_opinion_features(
            opinion4,
            sightings2[3],
            indicator.id
        )

    def _test_event_with_tags(self, event):
        self.parser.parse_misp_event(event)
        bundle = self._check_bundle_features(4)
        _, _, _, marking = bundle.objects
        self.assertEqual(marking.definition_type, 'tlp')
        self.assertEqual(marking.definition['tlp'], 'white')

    def _test_published_event(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        bundle = self._check_bundle_features(3)
        identity, report, _ = bundle.objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        self._check_report_features(report, event, identity_id, timestamp)
        self.assertEqual(report.created, timestamp)
        self.assertEqual(report.modified, timestamp)
        publish_timestamp = event['publish_timestamp']
        if not isinstance(publish_timestamp, datetime):
            publish_timestamp = self._datetime_from_timestamp(publish_timestamp)
        self.assertEqual(report.published, publish_timestamp)


class TestSTIX20JSONEventExport(TestSTIX20EventExport):
    def test_base_event(self):
        event = get_base_event()
        self._test_base_event(event['Event'])

    def test_event_with_escaped_characters(self):
        event = get_event_with_escaped_values_v20()
        self._test_event_with_escaped_characters(event['Event'])

    def test_event_with_sightings(self):
        event = get_event_with_sightings()
        self._test_event_with_sightings(event['Event'])

    def test_event_with_tags(self):
        event = get_event_with_tags()
        self._test_event_with_tags(event['Event'])

    def test_published_event(self):
        event = get_published_event()
        self._test_published_event(event['Event'])


class TestSTIX20MISPEventExport(TestSTIX20EventExport):
    def test_base_event(self):
        event = get_base_event()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_base_event(misp_event)

    def test_event_with_escaped_characters(self):
        event = get_event_with_escaped_values_v20()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_escaped_characters(misp_event)

    def test_event_with_sightings(self):
        event = get_event_with_sightings()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_sightings(misp_event)

    def test_event_with_tags(self):
        event = get_event_with_tags()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_tags(misp_event)

    def test_published_event(self):
        event = get_published_event()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_published_event(misp_event)


class TestSTIX20AttributesExport(TestSTIX20GenericExport):
    _http_features = ('request_method', "request_header.'User-Agent'")
    _http_prefix = f"network-traffic:extensions.'http-request-ext'"

    def _check_hash_composite_indicator_attribute(self, attribute, indicator):
        filename, hash_value = attribute['value'].split('|')
        hash_type = attribute['type'].split('|')[1]
        if '/' in hash_type:
            hash_type = f"SHA{hash_type.split('/')[1]}"
        filename_pattern = f"file:name = '{filename}'"
        hash_pattern = f"file:hashes.{hash_type.replace('-', '').upper()} = '{hash_value}'"
        self.assertEqual(indicator.pattern, f"[{filename_pattern} AND {hash_pattern}]")

    def _check_hash_composite_observable_attribute(self, attribute, observed_data):
        filename, hash_value = attribute['value'].split('|')
        observable_object = observed_data['objects']['0']
        self.assertEqual(observable_object.type, 'file')
        self.assertEqual(observable_object.name, filename)
        hash_type = self.hash_types_mapping(attribute['type'].split('|')[1])
        self.assertEqual(observable_object.hashes[hash_type], hash_value)

    def _check_hash_indicator_attribute(self, attribute, indicator):
        hash_type = attribute['type']
        if '/' in hash_type:
            hash_type = f"SHA{hash_type.split('/')[1]}"
        self.assertEqual(
            indicator.pattern,
            f"[file:hashes.{hash_type.replace('-', '').upper()} = '{attribute['value']}']"
        )

    def _check_hash_observable_attribute(self, attribute, observed_data):
        hash_type = self.hash_types_mapping(attribute['type'])
        observable_object = observed_data['objects']['0']
        self.assertEqual(observable_object.type, 'file')
        self.assertEqual(observable_object.hashes[hash_type], attribute['value'])

    def _check_ip_indicator_attribute(self, attribute, indicator):
        feature = attribute['type'].split('-')[1]
        type_pattern = f"network-traffic:{feature}_ref.type = 'ipv4-addr'"
        value_pattern = f"network-traffic:{feature}_ref.value = '{attribute['value']}'"
        self.assertEqual(indicator.pattern, f"[{type_pattern} AND {value_pattern}]")

    def _check_ip_observable_attribute(self, attribute, observed_data):
        feature = attribute['type'].split('-')[1]
        network, address = observed_data['objects'].values()
        self.assertEqual(network.type, 'network-traffic')
        self.assertEqual(getattr(network, f'{feature}_ref'), '1')
        self.assertEqual(address.type, 'ipv4-addr')
        self.assertEqual(address.value, attribute['value'])

    def _check_ip_port_indicator_attribute(self, attribute, indicator):
        feature = attribute['type'].split('|')[0].split('-')[1]
        ip_value, port_value = attribute['value'].split('|')
        type_pattern = f"network-traffic:{feature}_ref.type = 'ipv4-addr'"
        ip_pattern = f"network-traffic:{feature}_ref.value = '{ip_value}'"
        port_pattern = f"network-traffic:{feature}_port = '{port_value}'"
        self.assertEqual(indicator.pattern, f"[{type_pattern} AND {ip_pattern} AND {port_pattern}]")

    def _check_ip_port_observable_attribute(self, attribute, observed_data):
        feature = attribute['type'].split('|')[0].split('-')[1]
        ip_value, port_value = attribute['value'].split('|')
        network, address = observed_data['objects'].values()
        self.assertEqual(network.type, 'network-traffic')
        self.assertEqual(getattr(network, f'{feature}_ref'), '1')
        self.assertEqual(getattr(network, f'{feature}_port'), int(port_value))
        self.assertEqual(address.type, 'ipv4-addr')
        self.assertEqual(address.value, ip_value)

    def _check_url_observable_attribute(self, attribute, observed_data):
        observable = observed_data.objects['0']
        self.assertEqual(observable.type, 'url')
        self.assertEqual(observable.value, attribute['value'])

    def _check_x509_fingerprint_observable_attribute(self, attribute, observed_data):
        observable_object = observed_data['objects']['0']
        self.assertEqual(observable_object.type, 'x509-certificate')
        hash_type = self.hash_types_mapping(attribute['type'].split('-')[-1])
        self.assertEqual(observable_object.hashes[hash_type], attribute['value'])

    def _run_indicator_tests(self, event):
        self._add_attribute_ids_flag(event)
        orgc = event['Orgc']
        attribute = event['Attribute'][0]
        self.parser.parse_misp_event(event)
        identity, report, indicator = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event, identity_id, timestamp)[0]
        self.assertEqual(report.published, timestamp)
        self._check_attribute_indicator_features(indicator, attribute, identity_id, object_ref)
        return attribute['value'], indicator.pattern

    def _run_indicators_tests(self, event):
        self._add_attribute_ids_flag(event)
        orgc = event['Orgc']
        attributes = event['Attribute']
        self.parser.parse_misp_event(event)
        identity, report, *indicators = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event, identity_id, timestamp)
        self.assertEqual(report.published, timestamp)
        for attribute, indicator, object_ref in zip(attributes, indicators, object_refs):
            self._check_attribute_indicator_features(indicator, attribute, identity_id, object_ref)
        return attributes, indicators

    def _run_observable_tests(self, event):
        self._remove_attribute_ids_flag(event)
        orgc = event['Orgc']
        attribute = event['Attribute'][0]
        self.parser.parse_misp_event(event)
        identity, report, observed_data = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event, identity_id, timestamp)[0]
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
        orgc = event['Orgc']
        attributes = event['Attribute']
        self.parser.parse_misp_event(event)
        identity, report, *observables = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event, identity_id, timestamp)
        self.assertEqual(report.published, timestamp)
        for attribute, observed_data, object_ref in zip(attributes, observables, object_refs):
            self._check_attribute_observable_features(
                observed_data,
                attribute,
                identity_id,
                object_ref
            )
        return attributes, observables

    def _test_embedded_indicator_attribute_galaxy(self, event):
        orgc = event['Orgc']
        attribute = event['Attribute'][0]
        event_galaxy = deepcopy(event['Galaxy'][0])
        self.parser.parse_misp_event(event)
        bundle = self._check_bundle_features(10)
        identity, report, attack_pattern, course_of_action, custom, indicator, malware, *relationships = bundle.objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event, identity_id, timestamp)
        self.assertEqual(report.published, timestamp)
        ap_ref, coa_ref, custom_ref, indicator_ref, malware_ref, apr_ref, coar_ref, customr_ref = object_refs
        ap_relationship, coa_relationship, custom_relationship = relationships
        ap_galaxy, coa_galaxy, custom_galaxy = attribute['Galaxy']
        self._assert_multiple_equal(
            attack_pattern.id,
            ap_ref,
            f"attack-pattern--{ap_galaxy['GalaxyCluster'][0]['uuid']}"
        )
        self._assert_multiple_equal(
            course_of_action.id,
            coa_ref,
            f"course-of-action--{coa_galaxy['GalaxyCluster'][0]['uuid']}"
        )
        self._assert_multiple_equal(
            custom.id,
            custom_ref,
            f"x-misp-galaxy-cluster--{custom_galaxy['GalaxyCluster'][0]['uuid']}"
        )
        self._assert_multiple_equal(
            indicator.id,
            indicator_ref,
            f"indicator--{attribute['uuid']}"
        )
        self._assert_multiple_equal(
            malware.id,
            malware_ref,
            f"malware--{event_galaxy['GalaxyCluster'][0]['uuid']}"
        )
        self._assert_multiple_equal(ap_relationship.id, apr_ref)
        self._assert_multiple_equal(coa_relationship.id, coar_ref)
        self.assertEqual(custom_relationship.id, customr_ref)
        timestamp = attribute['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self._check_relationship_features(ap_relationship, indicator_ref, ap_ref, 'indicates', timestamp)
        self._check_relationship_features(coa_relationship, indicator_ref, coa_ref, 'related-to', timestamp)
        self._check_relationship_features(custom_relationship, indicator_ref, custom_ref, 'related-to', timestamp)

    def _test_embedded_non_indicator_attribute_galaxy(self, event):
        orgc = event['Orgc']
        attribute = event['Attribute'][0]
        self.parser.parse_misp_event(event)
        bundle = self._check_bundle_features(8)
        identity, report, attack_pattern, course_of_action, vulnerability, malware, *relationships = bundle.objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event, identity_id, timestamp)
        self.assertEqual(report.published, timestamp)
        ap_ref, coa_ref, vulnerability_ref, malware_ref, apr_ref, coar_ref = object_refs
        ap_relationship, coa_relationship = relationships
        self.assertEqual(attack_pattern.id, ap_ref)
        self.assertEqual(course_of_action.id, coa_ref)
        self.assertEqual(vulnerability.id, vulnerability_ref)
        self.assertEqual(malware.id, malware_ref)
        self.assertEqual(ap_relationship.id, apr_ref)
        self.assertEqual(coa_relationship.id, coar_ref)
        timestamp = attribute['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self._check_relationship_features(ap_relationship, vulnerability_ref, ap_ref, 'related-to', timestamp)
        self._check_relationship_features(coa_relationship, vulnerability_ref, coa_ref, 'related-to', timestamp)

    def _test_embedded_observable_attribute_galaxy(self, event):
        orgc = event['Orgc']
        attribute = event['Attribute'][0]
        self.parser.parse_misp_event(event)
        bundle = self._check_bundle_features(6)
        identity, report, attack_pattern, observed_data, malware, relationship = bundle.objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event, identity_id, timestamp)
        self.assertEqual(report.published, timestamp)
        ap_ref, od_ref, malware_ref, relationship_ref = object_refs
        self.assertEqual(attack_pattern.id, ap_ref)
        self.assertEqual(observed_data.id, od_ref)
        self.assertEqual(malware.id, malware_ref)
        self.assertEqual(relationship.id, relationship_ref)
        timestamp = attribute['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self._check_relationship_features(
            relationship, od_ref, ap_ref, 'related-to', timestamp
        )

    def _test_event_with_as_indicator_attribute(self, event):
        attribute_value, pattern = self._run_indicator_tests(event)
        number = self._parse_AS_value(attribute_value)
        self.assertEqual(pattern, f"[autonomous-system:number = '{number}']")

    def _test_event_with_as_observable_attribute(self, event):
        attribute_value, observable_objects = self._run_observable_tests(event)
        observable = observable_objects['0']
        self.assertEqual(observable.type, 'autonomous-system')
        number = self._parse_AS_value(attribute_value)
        self.assertEqual(observable.number, number)

    def _test_event_with_attachment_indicator_attribute(self, event):
        data = event['Attribute'][0]['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        attribute_value, pattern = self._run_indicator_tests(event)
        file_pattern = f"file:name = '{attribute_value}'"
        data_pattern = f"file:content_ref.payload_bin = '{data}'"
        self.assertEqual(pattern, f"[{file_pattern} AND {data_pattern}]")

    def _test_event_with_attachment_observable_attribute(self, event):
        data = event['Attribute'][0]['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        attribute_value, observable_objects = self._run_observable_tests(event)
        file_object, artifact_object = observable_objects.values()
        self.assertEqual(file_object.type, 'file')
        self.assertEqual(file_object.name, attribute_value)
        self.assertEqual(file_object.content_ref, '1')
        self.assertEqual(artifact_object.type, 'artifact')
        self.assertEqual(artifact_object.payload_bin, data)

    def _test_event_with_campaign_name_attribute(self, event):
        self._remove_attribute_ids_flag(event)
        orgc = event['Orgc']
        attribute = event['Attribute'][0]
        self.parser.parse_misp_event(event)
        identity, report, campaign = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event, identity_id, timestamp)[0]
        self.assertEqual(report.published, timestamp)
        self._check_attribute_campaign_features(
            campaign,
            attribute,
            identity_id,
            object_ref
        )
        self.assertEqual(campaign.name, attribute['value'])

    def _test_event_with_custom_attributes(self, event):
        orgc = event['Orgc']
        attributes = event['Attribute']
        self.parser.parse_misp_event(event)
        identity, report, *custom_objects = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event, identity_id, timestamp)
        self.assertEqual(report.published, timestamp)
        for attribute, custom_object, object_ref in zip(attributes, custom_objects, object_refs):
            self._run_custom_attribute_tests(attribute, custom_object, object_ref, identity_id)

    def _test_event_with_domain_indicator_attribute(self, event):
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[domain-name:value = '{attribute_value}']")

    def _test_event_with_domain_observable_attribute(self, event):
        attribute_value, observable_objects = self._run_observable_tests(event)
        observable = observable_objects['0']
        self.assertEqual(observable.type, 'domain-name')
        self.assertEqual(observable.value, attribute_value)

    def _test_event_with_domain_ip_indicator_attribute(self, event):
        attribute_value, pattern = self._run_indicator_tests(event)
        domain, ip = attribute_value.split('|')
        domain_pattern = f"domain-name:value = '{domain}'"
        ip_pattern = f"domain-name:resolves_to_refs[*].value = '{ip}'"
        self.assertEqual(pattern, f'[{domain_pattern} AND {ip_pattern}]')

    def _test_event_with_domain_ip_observable_attribute(self, event):
        attribute_value, observable_objects = self._run_observable_tests(event)
        domain, ip = attribute_value.split('|')
        domain_object, address_object = observable_objects.values()
        self.assertEqual(domain_object.type, 'domain-name')
        self.assertEqual(domain_object.value, domain)
        self.assertEqual(domain_object.resolves_to_refs, ['1'])
        self.assertEqual(address_object.type, 'ipv4-addr')
        self.assertEqual(address_object.value, ip)

    def _test_event_with_email_attachment_indicator_attribute(self, event):
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(
            pattern,
            f"[email-message:body_multipart[*].body_raw_ref.name = '{attribute_value}']"
        )

    def _test_event_with_email_attachment_observable_attribute(self, event):
        attribute_value, observable_objects = self._run_observable_tests(event)
        email_object, file_object = observable_objects.values()
        self.assertEqual(email_object.type, 'email-message')
        self.assertEqual(email_object.is_multipart, True)
        body = email_object.body_multipart[0]
        self.assertEqual(body.content_disposition, f"attachment; filename='{attribute_value}'")
        self.assertEqual(body.body_raw_ref, '1')
        self.assertEqual(file_object.type, 'file')
        self.assertEqual(file_object.name, attribute_value)

    def _test_event_with_email_body_indicator_attribute(self, event):
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(
            pattern,
            f"[email-message:body = '{attribute_value}']"
        )

    def _test_event_with_email_body_observable_attribute(self, event):
        attribute_value, observable_objects = self._run_observable_tests(event)
        email_object = observable_objects['0']
        self.assertEqual(email_object.type, 'email-message')
        self.assertEqual(email_object.is_multipart, False)
        self.assertEqual(email_object.body, attribute_value)

    def _test_event_with_email_destination_indicator_attribute(self, event):
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[email-message:to_refs[*].value = '{attribute_value}']")

    def _test_event_with_email_destination_observable_attribute(self, event):
        attribute_value, observable_objects = self._run_observable_tests(event)
        message, address = observable_objects.values()
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.to_refs, ['1'])
        self._check_email_address(address, attribute_value)

    def _test_event_with_email_header_indicator_attribute(self, event):
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[email-message:received_lines = '{attribute_value}']")

    def _test_event_with_email_header_observable_attribute(self, event):
        attribute_value, observable_objects = self._run_observable_tests(event)
        message_object = observable_objects['0']
        self.assertEqual(message_object.type, 'email-message')
        self.assertEqual(message_object.is_multipart, False)
        self.assertEqual(message_object.received_lines, [attribute_value])

    def _test_event_with_email_indicator_attribute(self, event):
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[email-addr:value = '{attribute_value}']")

    def _test_event_with_email_observable_attribute(self, event):
        attribute_value, observable_objects = self._run_observable_tests(event)
        address_object = observable_objects['0']
        self._check_email_address(address_object, attribute_value)

    def _test_event_with_email_reply_to_indicator_attribute(self, event):
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(
            pattern,
            f"[email-message:additional_header_fields.reply_to = '{attribute_value}']"
        )

    def _test_event_with_email_reply_to_observable_attribute(self, event):
        attribute_value, observable_objects = self._run_observable_tests(event)
        message = observable_objects['0']
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.additional_header_fields['Reply-To'], attribute_value)

    def _test_event_with_email_source_indicator_attribute(self, event):
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[email-message:from_ref.value = '{attribute_value}']")

    def _test_event_with_email_source_observable_attribute(self, event):
        attribute_value, observable_objects = self._run_observable_tests(event)
        message, address = observable_objects.values()
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.from_ref, '1')
        self._check_email_address(address, attribute_value)

    def _test_event_with_email_subject_indicator_attribute(self, event):
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[email-message:subject = '{attribute_value}']")

    def _test_event_with_email_subject_observable_attribute(self, event):
        attribute_value, observable_objects = self._run_observable_tests(event)
        message = observable_objects['0']
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.subject, attribute_value)

    def _test_event_with_email_x_mailer_indicator_attribute(self, event):
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(
            pattern,
            f"[email-message:additional_header_fields.x_mailer = '{attribute_value}']"
        )

    def _test_event_with_email_x_mailer_observable_attribute(self, event):
        attribute_value, observable_objects = self._run_observable_tests(event)
        message = observable_objects['0']
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.additional_header_fields['X-Mailer'], attribute_value)

    def _test_event_with_filename_indicator_attribute(self, event):
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[file:name = '{attribute_value}']")

    def _test_event_with_filename_observable_attribute(self, event):
        attribute_value, observable_objects = self._run_observable_tests(event)
        observable = observable_objects['0']
        self.assertEqual(observable.type, 'file')
        self.assertEqual(observable.name, attribute_value)

    def _test_event_with_github_username_attribute(self, event):
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(
            pattern,
            f"[user-account:account_type = 'github' AND user-account:account_login = '{attribute_value}']"
        )

    def _test_event_with_hostname_indicator_attribute(self, event):
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[domain-name:value = '{attribute_value}']")

    def _test_event_with_hostname_observable_attribute(self, event):
        attribute_value, observable_objects = self._run_observable_tests(event)
        observable = observable_objects['0']
        self.assertEqual(observable.type, 'domain-name')
        self.assertEqual(observable.value, attribute_value)

    def _test_event_with_hostname_port_indicator_attribute(self, event):
        attribute_value, pattern = self._run_indicator_tests(event)
        hostname, port = attribute_value.split('|')
        hostname_pattern = f"domain-name:value = '{hostname}'"
        port_pattern = f"network-traffic:dst_port = '{port}'"
        self.assertEqual(pattern, f"[{hostname_pattern} AND {port_pattern}]")

    def _test_event_with_hostname_port_observable_attribute(self, event):
        attribute_value, observable_objects = self._run_observable_tests(event)
        hostname, port = attribute_value.split('|')
        domain_object, network_traffic_object = observable_objects.values()
        self.assertEqual(domain_object.type, 'domain-name')
        self.assertEqual(domain_object.value, hostname)
        self.assertEqual(network_traffic_object.type, 'network-traffic')
        self.assertEqual(network_traffic_object.dst_port, int(port))
        self.assertEqual(network_traffic_object.dst_ref, '0')

    def _test_event_with_mac_address_indicator_attribute(self, event):
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[mac-addr:value = '{attribute_value}']")

    def _test_event_with_mac_address_observable_attribute(self, event):
        attribute_value, observable_objects = self._run_observable_tests(event)
        observable = observable_objects['0']
        self.assertEqual(observable.type, 'mac-addr')
        self.assertEqual(observable.value, attribute_value.lower())

    def _test_event_with_malware_sample_indicator_attribute(self, event):
        data = event['Attribute'][0]['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        attribute_value, pattern = self._run_indicator_tests(event)
        filename, hash_value = attribute_value.split('|')
        data_pattern, file_pattern, hash_pattern, mime_type = pattern[1:-1].split(' AND ')
        self.assertEqual(data_pattern, f"file:content_ref.payload_bin = '{data}'")
        self.assertEqual(file_pattern, f"file:name = '{filename}'")
        self.assertEqual(hash_pattern, f"file:hashes.MD5 = '{hash_value}'")
        self.assertEqual(mime_type, f"file:content_ref.mime_type = 'application/zip'")

    def _test_event_with_malware_sample_observable_attribute(self, event):
        data = event['Attribute'][0]['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        attribute_value, observable_objects = self._run_observable_tests(event)
        file_object, artifact_object = observable_objects.values()
        filename, hash_value = attribute_value.split('|')
        self.assertEqual(file_object.type, 'file')
        self.assertEqual(file_object.name, filename)
        self.assertEqual(file_object.hashes['MD5'], hash_value)
        self.assertEqual(file_object.content_ref, '1')
        self.assertEqual(artifact_object.type, 'artifact')
        self.assertEqual(artifact_object.payload_bin, data)

    def _test_event_with_mutex_indicator_attribute(self, event):
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[mutex:name = '{attribute_value}']")

    def _test_event_with_mutex_observable_attribute(self, event):
        attribute_value, observable_objects = self._run_observable_tests(event)
        observable = observable_objects['0']
        self.assertEqual(observable.type, 'mutex')
        self.assertEqual(observable.name, attribute_value)

    def _test_event_with_port_indicator_attribute(self, event):
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[network-traffic:dst_port = '{attribute_value}']")

    def _test_event_with_regkey_indicator_attribute(self, event):
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(
            pattern.replace('\\\\', '\\'),
            f"[windows-registry-key:key = '{attribute_value.strip()}']"
        )

    def _test_event_with_regkey_observable_attribute(self, event):
        attribute_value, observable_objects = self._run_observable_tests(event)
        observable = observable_objects['0']
        self.assertEqual(observable.type, 'windows-registry-key')
        self.assertEqual(observable.key, attribute_value.strip())

    def _test_event_with_regkey_value_indicator_attribute(self, event):
        attribute_value, pattern = self._run_indicator_tests(event)
        key, value = attribute_value.split('|')
        key_pattern = f"windows-registry-key:key = '{self._sanitize_registry_key_value(key)}'"
        value_pattern = f"windows-registry-key:values.data = '{self._sanitize_registry_key_value(value)}'"
        self.assertEqual(pattern, f"[{key_pattern} AND {value_pattern}]")

    def _test_event_with_regkey_value_observable_attribute(self, event):
        attribute_value, observable_objects = self._run_observable_tests(event)
        key, value = attribute_value.split('|')
        observable = observable_objects['0']
        self.assertEqual(observable.type, 'windows-registry-key')
        self.assertEqual(observable.key, key.strip())
        self.assertEqual(observable['values'][0].data, value.strip())

    def _test_event_with_size_in_bytes_indicator_attribute(self, event):
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[file:size = '{attribute_value}']")

    def _test_event_with_vulnerability_attribute(self, event):
        self._add_attribute_ids_flag(event)
        orgc = event['Orgc']
        attribute = event['Attribute'][0]
        self.parser.parse_misp_event(event)
        identity, report, vulnerability = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event, identity_id, timestamp)[0]
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


class TestSTIX20JSONAttributesExport(TestSTIX20AttributesExport):
    def test_embedded_indicator_attribute_galaxy(self):
        event = get_embedded_indicator_attribute_galaxy()
        self._test_embedded_indicator_attribute_galaxy(event['Event'])

    def test_embedded_non_indicator_attribute_galaxy(self):
        event = get_embedded_non_indicator_attribute_galaxy()
        self._test_embedded_non_indicator_attribute_galaxy(event['Event'])

    def test_embedded_observable_attribute_galaxy(self):
        event = get_embedded_observable_attribute_galaxy()
        self._test_embedded_observable_attribute_galaxy(event['Event'])

    def test_event_with_as_indicator_attribute(self):
        event = get_event_with_as_attribute()
        self._test_event_with_as_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_as_observable_attribute(self):
        event = get_event_with_as_attribute()
        self._test_event_with_as_observable_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_attachment_indicator_attribute(self):
        event = get_event_with_attachment_attribute()
        self._test_event_with_attachment_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_attachment_observable_attribute(self):
        event = get_event_with_attachment_attribute()
        self._test_event_with_attachment_observable_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_campaign_name_attribute(self):
        event = get_event_with_campaign_name_attribute()
        self._test_event_with_campaign_name_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            campaign = self.parser.stix_objects[-1]
        )

    def test_event_with_custom_attributes(self):
        event = get_event_with_stix2_custom_attributes()
        self._test_event_with_custom_attributes(event['Event'])

    def test_event_with_domain_indicator_attribute(self):
        event = get_event_with_domain_attribute()
        self._test_event_with_domain_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_domain_observable_attribute(self):
        event = get_event_with_domain_attribute()
        self._test_event_with_domain_observable_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_domain_ip_indicator_attribute(self):
        event = get_event_with_domain_ip_attribute()
        self._test_event_with_domain_ip_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_domain_ip_observable_attribute(self):
        event = get_event_with_domain_ip_attribute()
        self._test_event_with_domain_ip_observable_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_email_attachment_indicator_attribute(self):
        event = get_event_with_email_attachment_attribute()
        self._test_event_with_email_attachment_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_email_attachment_observable_attribute(self):
        event = get_event_with_email_attachment_attribute()
        self._test_event_with_email_attachment_observable_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_email_body_indicator_attribute(self):
        event = get_event_with_email_body_attribute()
        self._test_event_with_email_body_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_email_body_observable_attribute(self):
        event = get_event_with_email_body_attribute()
        self._test_event_with_email_body_observable_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_email_destination_indicator_attribute(self):
        event = get_event_with_email_destination_attribute()
        self._test_event_with_email_destination_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_email_destination_observable_attribute(self):
        event = get_event_with_email_destination_attribute()
        self._test_event_with_email_destination_observable_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_email_header_indicator_attribute(self):
        event = get_event_with_email_header_attribute()
        self._test_event_with_email_header_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_email_header_observable_attribute(self):
        event = get_event_with_email_header_attribute()
        self._test_event_with_email_header_observable_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_email_indicator_attribute(self):
        event = get_event_with_email_address_attribute()
        self._test_event_with_email_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_email_observable_attribute(self):
        event = get_event_with_email_address_attribute()
        self._test_event_with_email_observable_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_email_reply_to_indicator_attribute(self):
        event = get_event_with_email_reply_to_attribute()
        self._test_event_with_email_reply_to_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_email_reply_to_observable_attribute(self):
        event = get_event_with_email_reply_to_attribute()
        self._test_event_with_email_reply_to_observable_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_email_source_indicator_attribute(self):
        event = get_event_with_email_source_attribute()
        self._test_event_with_email_source_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_email_source_observable_attribute(self):
        event = get_event_with_email_source_attribute()
        self._test_event_with_email_source_observable_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_email_subject_indicator_attribute(self):
        event = get_event_with_email_subject_attribute()
        self._test_event_with_email_subject_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_email_subject_observable_attribute(self):
        event = get_event_with_email_subject_attribute()
        self._test_event_with_email_subject_observable_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_email_x_mailer_indicator_attribute(self):
        event = get_event_with_email_x_mailer_attribute()
        self._test_event_with_email_x_mailer_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_email_x_mailer_attribute(self):
        event = get_event_with_email_x_mailer_attribute()
        self._test_event_with_email_x_mailer_observable_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_filename_indicator_attribute(self):
        event = get_event_with_filename_attribute()
        self._test_event_with_filename_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_filename_observable_attribute(self):
        event = get_event_with_filename_attribute()
        self._test_event_with_filename_observable_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_github_username_indicator_attribute(self):
        event = get_event_with_github_username_attribute()
        self._test_event_with_github_username_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_github_username_observable_attribute(self):
        event = get_event_with_github_username_attribute()
        self._test_event_with_custom_attributes(event['Event'])

    def test_event_with_hash_composite_indicator_attributes(self):
        event = get_event_with_hash_composite_attributes()
        attributes, indicators = self._run_indicators_tests(event['Event'])
        for attribute, indicator, in zip(attributes, indicators):
            self._check_hash_composite_indicator_attribute(attribute, indicator)
            self._populate_documentation(attribute=attribute, indicator=indicator)

    def test_event_with_hash_composite_observable_attributes(self):
        event = get_event_with_hash_composite_attributes()
        attributes, observables = self._run_observables_tests(event['Event'])
        for attribute, observed_data in zip(attributes, observables):
            self._check_hash_composite_observable_attribute(attribute, observed_data)
            self._populate_documentation(attribute=attribute, observed_data=observed_data)

    def test_event_with_hash_indicator_attributes(self):
        event = get_event_with_hash_attributes()
        attributes, indicators = self._run_indicators_tests(event['Event'])
        for attribute, indicator in zip(attributes, indicators):
            self._check_hash_indicator_attribute(attribute, indicator)
            self._populate_documentation(attribute=attribute, indicator=indicator)

    def test_event_with_hash_observable_attributes(self):
        event = get_event_with_hash_attributes()
        attributes, observables = self._run_observables_tests(event['Event'])
        for attribute, observed_data in zip(attributes, observables):
            self._check_hash_observable_attribute(attribute, observed_data)
            self._populate_documentation(attribute=attribute, observed_data=observed_data)

    def test_event_with_hostname_indicator_attribute(self):
        event = get_event_with_hostname_attribute()
        self._test_event_with_hostname_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_hostname_observable_attribute(self):
        event = get_event_with_hostname_attribute()
        self._test_event_with_hostname_observable_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_hostname_port_indicator_attribute(self):
        event = get_event_with_hostname_port_attribute()
        self._test_event_with_hostname_port_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_hostname_port_observable_attribute(self):
        event = get_event_with_hostname_port_attribute()
        self._test_event_with_hostname_port_observable_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_http_indicator_attributes(self):
        event = get_event_with_http_attributes()
        attributes, indicators = self._run_indicators_tests(event['Event'])
        for attribute, indicator, feature in zip(attributes, indicators, self._http_features):
            self.assertEqual(
                indicator.pattern,
                f"[{self._http_prefix}.{feature} = '{attribute['value']}']"
            )
            self._populate_documentation(attribute=attribute, indicator=indicator)

    def test_event_with_ip_indicator_attributes(self):
        event = get_event_with_ip_attributes()
        attributes, indicators = self._run_indicators_tests(event['Event'])
        for attribute, indicator in zip(attributes, indicators):
            self._check_ip_indicator_attribute(attribute, indicator)
            self._populate_documentation(attribute=attribute, indicator=indicator)

    def test_event_with_ip_observable_attributes(self):
        event = get_event_with_ip_attributes()
        attributes, observables = self._run_observables_tests(event['Event'])
        for attribute, observed_data in zip(attributes, observables):
            self._check_ip_observable_attribute(attribute, observed_data)
            self._populate_documentation(attribute=attribute, observed_data=observed_data)

    def test_event_with_ip_port_indicator_attributes(self):
        event = get_event_with_ip_port_attributes()
        attributes, indicators = self._run_indicators_tests(event['Event'])
        for attribute, indicator in zip(attributes, indicators):
            self._check_ip_port_indicator_attribute(attribute, indicator)
            self._populate_documentation(attribute=attribute, indicator=indicator)

    def test_event_with_ip_port_observable_attributes(self):
        event = get_event_with_ip_port_attributes()
        attributes, observables = self._run_observables_tests(event['Event'])
        for attribute, observed_data in zip(attributes, observables):
            self._check_ip_port_observable_attribute(attribute, observed_data)
            self._populate_documentation(attribute=attribute, observed_data=observed_data)

    def test_event_with_mac_address_indicator_attribute(self):
        event = get_event_with_mac_address_attribute()
        self._test_event_with_mac_address_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_mac_address_observable_attribute(self):
        event = get_event_with_mac_address_attribute()
        self._test_event_with_mac_address_observable_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_malware_sample_indicator_attribute(self):
        event = get_event_with_malware_sample_attribute()
        self._test_event_with_malware_sample_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_malware_sample_observable_attribute(self):
        event = get_event_with_malware_sample_attribute()
        self._test_event_with_malware_sample_observable_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_mutex_indicator_attribute(self):
        event = get_event_with_mutex_attribute()
        self._test_event_with_mutex_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_mutex_observable_attribute(self):
        event = get_event_with_mutex_attribute()
        self._test_event_with_mutex_observable_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_port_indicator_attribute(self):
        event = get_event_with_port_attribute()
        self._test_event_with_port_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_regkey_indicator_attribute(self):
        event = get_event_with_regkey_attribute()
        self._test_event_with_regkey_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_regkey_observable_attribute(self):
        event = get_event_with_regkey_attribute()
        self._test_event_with_regkey_observable_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_regkey_value_indicator_attribute(self):
        event = get_event_with_regkey_value_attribute()
        self._test_event_with_regkey_value_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_regkey_value_observable_attribute(self):
        event = get_event_with_regkey_value_attribute()
        self._test_event_with_regkey_value_observable_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_size_in_bytes_indicator_attribute(self):
        event = get_event_with_size_in_bytes_attribute()
        self._test_event_with_size_in_bytes_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_url_indicator_attributes(self):
        event = get_event_with_url_attributes()
        attributes, indicators = self._run_indicators_tests(event['Event'])
        for attribute, indicator in zip(attributes, indicators):
            self.assertEqual(indicator.pattern, f"[url:value = '{attribute['value']}']")
            self._populate_documentation(attribute=attribute, indicator=indicator)

    def test_event_with_url_observable_attributes(self):
        event = get_event_with_url_attributes()
        attributes, observables = self._run_observables_tests(event['Event'])
        for attribute, observed_data in zip(attributes, observables):
            self._check_url_observable_attribute(attribute, observed_data)
            self._populate_documentation(attribute=attribute, observed_data=observed_data)

    def test_event_with_vulnerability_attribute(self):
        event = get_event_with_vulnerability_attribute()
        self._test_event_with_vulnerability_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            vulnerability = self.parser.stix_objects[-1]
        )

    def test_event_with_x509_fingerprint_indicator_attributes(self):
        event = get_event_with_x509_fingerprint_attributes()
        attributes, indicators = self._run_indicators_tests(event['Event'])
        for attribute, indicator in zip(attributes, indicators):
            hash_type = attribute['type'].split('-')[-1].upper()
            self.assertEqual(
                indicator.pattern,
                f"[x509-certificate:hashes.{hash_type} = '{attribute['value']}']"
            )
            self._populate_documentation(attribute=attribute, indicator=indicator)

    def test_event_with_x509_fingerprint_observable_attributes(self):
        event = get_event_with_x509_fingerprint_attributes()
        attributes, observables = self._run_observables_tests(event['Event'])
        for attribute, observed_data in zip(attributes, observables):
            self._check_x509_fingerprint_observable_attribute(attribute, observed_data)
            self._populate_documentation(attribute=attribute, observed_data=observed_data)


class TestSTIX20MISPAttributesExport(TestSTIX20AttributesExport):
    def test_embedded_indicator_attribute_galaxy(self):
        event = get_embedded_indicator_attribute_galaxy()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_embedded_indicator_attribute_galaxy(misp_event)

    def test_embedded_non_indicator_attribute_galaxy(self):
        event = get_embedded_non_indicator_attribute_galaxy()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_embedded_non_indicator_attribute_galaxy(misp_event)

    def test_embedded_observable_attribute_galaxy(self):
        event = get_embedded_observable_attribute_galaxy()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_embedded_observable_attribute_galaxy(misp_event)

    def test_event_with_as_indicator_attribute(self):
        event = get_event_with_as_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_as_indicator_attribute(misp_event)

    def test_event_with_as_observable_attribute(self):
        event = get_event_with_as_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_as_observable_attribute(misp_event)

    def test_event_with_attachment_indicator_attribute(self):
        event = get_event_with_attachment_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_attachment_indicator_attribute(misp_event)

    def test_event_with_attachment_observable_attribute(self):
        event = get_event_with_attachment_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_attachment_observable_attribute(misp_event)

    def test_event_with_campaign_name_attribute(self):
        event = get_event_with_campaign_name_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_campaign_name_attribute(misp_event)

    def test_event_with_custom_attributes(self):
        event = get_event_with_stix2_custom_attributes()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_custom_attributes(misp_event)

    def test_event_with_domain_indicator_attribute(self):
        event = get_event_with_domain_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_domain_indicator_attribute(misp_event)

    def test_event_with_domain_observable_attribute(self):
        event = get_event_with_domain_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_domain_observable_attribute(misp_event)

    def test_event_with_domain_ip_indicator_attribute(self):
        event = get_event_with_domain_ip_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_domain_ip_indicator_attribute(misp_event)

    def test_event_with_domain_ip_observable_attribute(self):
        event = get_event_with_domain_ip_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_domain_ip_observable_attribute(misp_event)

    def test_event_with_email_attachment_indicator_attribute(self):
        event = get_event_with_email_attachment_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_email_attachment_indicator_attribute(misp_event)

    def test_event_with_email_attachment_observable_attribute(self):
        event = get_event_with_email_attachment_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_email_attachment_observable_attribute(misp_event)

    def test_event_with_email_body_indicator_attribute(self):
        event = get_event_with_email_body_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_email_body_indicator_attribute(misp_event)

    def test_event_with_email_body_observable_attribute(self):
        event = get_event_with_email_body_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_email_body_observable_attribute(misp_event)

    def test_event_with_email_destination_indicator_attribute(self):
        event = get_event_with_email_destination_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_email_destination_indicator_attribute(misp_event)

    def test_event_with_email_destination_observable_attribute(self):
        event = get_event_with_email_destination_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_email_destination_observable_attribute(misp_event)

    def test_event_with_email_header_indicator_attribute(self):
        event = get_event_with_email_header_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_email_header_indicator_attribute(misp_event)

    def test_event_with_email_header_observable_attribute(self):
        event = get_event_with_email_header_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_email_header_observable_attribute(misp_event)

    def test_event_with_email_indicator_attribute(self):
        event = get_event_with_email_address_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_email_indicator_attribute(misp_event)

    def test_event_with_email_observable_attribute(self):
        event = get_event_with_email_address_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_email_observable_attribute(misp_event)

    def test_event_with_email_reply_to_indicator_attribute(self):
        event = get_event_with_email_reply_to_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_email_reply_to_indicator_attribute(misp_event)

    def test_event_with_email_reply_to_observable_attribute(self):
        event = get_event_with_email_reply_to_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_email_reply_to_observable_attribute(misp_event)

    def test_event_with_email_source_indicator_attribute(self):
        event = get_event_with_email_source_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_email_source_indicator_attribute(misp_event)

    def test_event_with_email_source_observable_attribute(self):
        event = get_event_with_email_source_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_email_source_observable_attribute(misp_event)

    def test_event_with_email_subject_indicator_attribute(self):
        event = get_event_with_email_subject_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_email_subject_indicator_attribute(misp_event)

    def test_event_with_email_subject_observable_attribute(self):
        event = get_event_with_email_subject_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_email_subject_observable_attribute(misp_event)

    def test_event_with_email_x_mailer_indicator_attribute(self):
        event = get_event_with_email_x_mailer_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_email_x_mailer_indicator_attribute(misp_event)

    def test_event_with_email_x_mailer_attribute(self):
        event = get_event_with_email_x_mailer_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_email_x_mailer_observable_attribute(misp_event)

    def test_event_with_filename_indicator_attribute(self):
        event = get_event_with_filename_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_filename_indicator_attribute(misp_event)

    def test_event_with_filename_observable_attribute(self):
        event = get_event_with_filename_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_filename_observable_attribute(misp_event)

    def test_event_with_github_username_indicator_attribute(self):
        event = get_event_with_github_username_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_github_username_attribute(misp_event)

    def test_event_with_github_username_observable_attribute(self):
        event = get_event_with_github_username_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_custom_attributes(misp_event)

    def test_event_with_hash_composite_indicator_attributes(self):
        event = get_event_with_hash_composite_attributes()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        attributes, indicators = self._run_indicators_tests(misp_event)
        for attribute, indicator, in zip(attributes, indicators):
            self._check_hash_composite_indicator_attribute(attribute, indicator)

    def test_event_with_hash_composite_observable_attributes(self):
        event = get_event_with_hash_composite_attributes()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        attributes, observables = self._run_observables_tests(misp_event)
        for attribute, observed_data in zip(attributes, observables):
            self._check_hash_composite_observable_attribute(attribute, observed_data)

    def test_event_with_hash_indicator_attributes(self):
        event = get_event_with_hash_attributes()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        attributes, indicators = self._run_indicators_tests(misp_event)
        for attribute, indicator in zip(attributes, indicators):
            self._check_hash_indicator_attribute(attribute, indicator)

    def test_event_with_hash_observable_attributes(self):
        event = get_event_with_hash_attributes()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        attributes, observables = self._run_observables_tests(misp_event)
        for attribute, observed_data in zip(attributes, observables):
            self._check_hash_observable_attribute(attribute, observed_data)

    def test_event_with_hostname_indicator_attribute(self):
        event = get_event_with_hostname_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_hostname_indicator_attribute(misp_event)

    def test_event_with_hostname_observable_attribute(self):
        event = get_event_with_hostname_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_hostname_observable_attribute(misp_event)

    def test_event_with_hostname_port_indicator_attribute(self):
        event = get_event_with_hostname_port_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_hostname_port_indicator_attribute(misp_event)

    def test_event_with_hostname_port_observable_attribute(self):
        event = get_event_with_hostname_port_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_hostname_port_observable_attribute(misp_event)

    def test_event_with_http_indicator_attributes(self):
        event = get_event_with_http_attributes()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        attributes, indicators = self._run_indicators_tests(misp_event)
        for attribute, indicator, feature in zip(attributes, indicators, self._http_features):
            self.assertEqual(
                indicator.pattern,
                f"[{self._http_prefix}.{feature} = '{attribute['value']}']"
            )

    def test_event_with_ip_indicator_attributes(self):
        event = get_event_with_ip_attributes()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        attributes, indicators = self._run_indicators_tests(misp_event)
        for attribute, indicator in zip(attributes, indicators):
            self._check_ip_indicator_attribute(attribute, indicator)

    def test_event_with_ip_observable_attributes(self):
        event = get_event_with_ip_attributes()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        attributes, observables = self._run_observables_tests(misp_event)
        for attribute, observed_data in zip(attributes, observables):
            self._check_ip_observable_attribute(attribute, observed_data)

    def test_event_with_ip_port_indicator_attributes(self):
        event = get_event_with_ip_port_attributes()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        attributes, indicators = self._run_indicators_tests(misp_event)
        for attribute, indicator in zip(attributes, indicators):
            self._check_ip_port_indicator_attribute(attribute, indicator)

    def test_event_with_ip_port_observable_attributes(self):
        event = get_event_with_ip_port_attributes()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        attributes, observables = self._run_observables_tests(misp_event)
        for attribute, observed_data in zip(attributes, observables):
            self._check_ip_port_observable_attribute(attribute, observed_data)

    def test_event_with_mac_address_indicator_attribute(self):
        event = get_event_with_mac_address_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_mac_address_indicator_attribute(misp_event)

    def test_event_with_mac_address_observable_attribute(self):
        event = get_event_with_mac_address_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_mac_address_observable_attribute(misp_event)

    def test_event_with_malware_sample_indicator_attribute(self):
        event = get_event_with_malware_sample_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_malware_sample_indicator_attribute(misp_event)

    def test_event_with_malware_sample_observable_attribute(self):
        event = get_event_with_malware_sample_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_malware_sample_observable_attribute(misp_event)

    def test_event_with_mutex_indicator_attribute(self):
        event = get_event_with_mutex_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_mutex_indicator_attribute(misp_event)

    def test_event_with_mutex_observable_attribute(self):
        event = get_event_with_mutex_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_mutex_observable_attribute(misp_event)

    def test_event_with_port_indicator_attribute(self):
        event = get_event_with_port_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_port_indicator_attribute(misp_event)

    def test_event_with_regkey_indicator_attribute(self):
        event = get_event_with_regkey_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_regkey_indicator_attribute(misp_event)

    def test_event_with_regkey_observable_attribute(self):
        event = get_event_with_regkey_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_regkey_observable_attribute(misp_event)

    def test_event_with_regkey_value_indicator_attribute(self):
        event = get_event_with_regkey_value_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_regkey_value_indicator_attribute(misp_event)

    def test_event_with_regkey_value_observable_attribute(self):
        event = get_event_with_regkey_value_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_regkey_value_observable_attribute(misp_event)

    def test_event_with_size_in_bytes_indicator_attribute(self):
        event = get_event_with_size_in_bytes_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_size_in_bytes_indicator_attribute(misp_event)

    def test_event_with_url_indicator_attributes(self):
        event = get_event_with_url_attributes()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        attributes, indicators = self._run_indicators_tests(misp_event)
        for attribute, indicator in zip(attributes, indicators):
            self.assertEqual(indicator.pattern, f"[url:value = '{attribute['value']}']")

    def test_event_with_url_observable_attributes(self):
        event = get_event_with_url_attributes()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        attributes, observables = self._run_observables_tests(misp_event)
        for attribute, observed_data in zip(attributes, observables):
            self._check_url_observable_attribute(attribute, observed_data)

    def test_event_with_vulnerability_attribute(self):
        event = get_event_with_vulnerability_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_vulnerability_attribute(misp_event)

    def test_event_with_x509_fingerprint_indicator_attributes(self):
        event = get_event_with_x509_fingerprint_attributes()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        attributes, indicators = self._run_indicators_tests(misp_event)
        for attribute, indicator in zip(attributes, indicators):
            hash_type = attribute['type'].split('-')[-1].upper()
            self.assertEqual(
                indicator.pattern,
                f"[x509-certificate:hashes.{hash_type} = '{attribute['value']}']"
            )

    def test_event_with_x509_fingerprint_observable_attributes(self):
        event = get_event_with_x509_fingerprint_attributes()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        attributes, observables = self._run_observables_tests(misp_event)
        for attribute, observed_data in zip(attributes, observables):
            self._check_x509_fingerprint_observable_attribute(attribute, observed_data)


class TestSTIX20ObjectsExport(TestSTIX20GenericExport):
    def _check_account_indicator_objects(self, misp_objects, patterns):
        gitlab_object, telegram_object = misp_objects
        gitlab_pattern, telegram_pattern = patterns
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

    def _check_account_observable_objects(self, misp_objects, observable_objects):
        gitlab_object, telegram_object = misp_objects
        gitlab, telegram = observable_objects
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

    def _check_account_with_attachment_indicator_objects(self, misp_objects, patterns):
        facebook_account, github_user, parler_account, reddit_account, twitter_account = misp_objects
        facebook_pattern, github_pattern, parler_pattern, reddit_pattern, twitter_pattern = patterns
        github_id, username, fullname, organisation, image = (attribute['value'] for attribute in github_user['Attribute'])
        account_id, account_name, link, avatar = facebook_account['Attribute']
        account_type, user_id, account_login, _link, avatar_data, avatar_value = facebook_pattern[1:-1].split(' AND ')
        self.assertEqual(account_type, f"user-account:account_type = 'facebook'")
        self.assertEqual(user_id, f"user-account:user_id = '{account_id['value']}'")
        self.assertEqual(
            account_login,
            f"user-account:account_login = '{account_name['value']}'"
        )
        self.assertEqual(_link, f"user-account:x_misp_link = '{link['value']}'")
        data = avatar['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(
            avatar_data,
            f"user-account:x_misp_user_avatar.data = '{data}'"
        )
        self.assertEqual(
            avatar_value,
            f"user-account:x_misp_user_avatar.value = '{avatar['value']}'"
        )
        account_type, user_id, display_name, login, organization, image_data, image_value = github_pattern[1:-1].split(' AND ')
        self.assertEqual(account_type, "user-account:account_type = 'github'")
        self.assertEqual(user_id, f"user-account:user_id = '{github_id}'")
        self.assertEqual(display_name, f"user-account:display_name = '{fullname}'")
        self.assertEqual(login, f"user-account:account_login = '{username}'")
        self.assertEqual(organization, f"user-account:x_misp_organisation = '{organisation}'")
        data = github_user['Attribute'][-1]['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(image_data, f"user-account:x_misp_profile_image.data = '{data}'")
        self.assertEqual(image_value, f"user-account:x_misp_profile_image.value = '{image}'")
        parler_id, parler_name, _, profile_photo = (attribute['value'] for attribute in parler_account['Attribute'])
        account_type, user_id, login, is_human, image_data, image_value = parler_pattern[1:-1].split(' AND ')
        self.assertEqual(account_type, f"user-account:account_type = 'parler'")
        self.assertEqual(user_id, f"user-account:user_id = '{parler_id}'")
        self.assertEqual(login, f"user-account:account_login = '{parler_name}'")
        self.assertEqual(is_human, f"user-account:x_misp_human = 'False'")
        data = parler_account['Attribute'][-1]['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(image_data, f"user-account:x_misp_profile_photo.data = '{data}'")
        self.assertEqual(image_value, f"user-account:x_misp_profile_photo.value = '{profile_photo}'")
        reddit_id, reddit_name, description, account_avatar = (attribute['value'] for attribute in reddit_account['Attribute'])
        account_type, user_id, login, description_pattern, image_data, image_value = reddit_pattern[1:-1].split(' AND ')
        self.assertEqual(account_type, f"user-account:account_type = 'reddit'")
        self.assertEqual(user_id, f"user-account:user_id = '{reddit_id}'")
        self.assertEqual(login, f"user-account:account_login = '{reddit_name}'")
        self.assertEqual(description_pattern, f"user-account:x_misp_description = '{description}'")
        data = reddit_account['Attribute'][-1]['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(image_data, f"user-account:x_misp_account_avatar.data = '{data}'")
        self.assertEqual(image_value, f"user-account:x_misp_account_avatar.value = '{account_avatar}'")
        _id, name, displayed_name, followers, profile_image = twitter_account['Attribute']
        account_type, display_name, user_id, account_login, _followers, image_data, image_value = twitter_pattern[1:-1].split(' AND ')
        self.assertEqual(account_type, f"user-account:account_type = 'twitter'")
        self.assertEqual(
            display_name,
            f"user-account:display_name = '{displayed_name['value']}'"
        )
        self.assertEqual(user_id, f"user-account:user_id = '{_id['value']}'")
        self.assertEqual(account_login, f"user-account:account_login = '{name['value']}'")
        self.assertEqual(_followers, f"user-account:x_misp_followers = '{followers['value']}'")
        data = profile_image['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(
            image_data,
            f"user-account:x_misp_profile_image.data = '{data}'"
        )
        self.assertEqual(
            image_value,
            f"user-account:x_misp_profile_image.value = '{profile_image['value']}'"
        )

    def _check_account_with_attachment_observable_objects(self, misp_objects, observable_objects):
        facebook_account, github_user, parler_account, reddit_account, twitter_account = misp_objects
        facebook, github, parler, reddit, twitter = observable_objects
        account_id, account_name, link, avatar = facebook_account['Attribute']
        facebook = facebook['0']
        self.assertEqual(facebook.type, 'user-account')
        self.assertEqual(facebook.account_type, 'facebook')
        self.assertEqual(facebook.user_id, account_id['value'])
        self.assertEqual(facebook.account_login, account_name['value'])
        self.assertEqual(facebook.x_misp_link, link['value'])
        self.assertEqual(facebook.x_misp_user_avatar['value'], avatar['value'])
        data = avatar['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(facebook.x_misp_user_avatar['data'], data)
        github_id, username, fullname, organisation, image = (attribute['value'] for attribute in github_user['Attribute'])
        github = github['0']
        self.assertEqual(github.type, 'user-account')
        self.assertEqual(github.account_type, 'github')
        self.assertEqual(github.user_id, github_id)
        self.assertEqual(github.account_login, username)
        self.assertEqual(github.display_name, fullname)
        self.assertEqual(github.x_misp_organisation, organisation)
        self.assertEqual(github.x_misp_profile_image['value'], image)
        data = github_user['Attribute'][-1]['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(github.x_misp_profile_image['data'], data)
        parler_id, parler_name, human, profile_photo = (attribute['value'] for attribute in parler_account['Attribute'])
        parler = parler['0']
        self.assertEqual(parler.type, 'user-account')
        self.assertEqual(parler.account_type, 'parler')
        self.assertEqual(parler.user_id, parler_id)
        self.assertEqual(parler.account_login, parler_name)
        self.assertEqual(parler.x_misp_human, human)
        self.assertEqual(parler.x_misp_profile_photo['value'], profile_photo)
        data = parler_account['Attribute'][-1]['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(parler.x_misp_profile_photo['data'], data)
        reddit_id, reddit_name, description, account_avatar = (attribute['value'] for attribute in reddit_account['Attribute'])
        reddit = reddit['0']
        self.assertEqual(reddit.type, 'user-account')
        self.assertEqual(reddit.account_type, 'reddit')
        self.assertEqual(reddit.user_id, reddit_id)
        self.assertEqual(reddit.account_login, reddit_name)
        self.assertEqual(reddit.x_misp_description, description)
        self.assertEqual(reddit.x_misp_account_avatar['value'], account_avatar)
        data = reddit_account['Attribute'][-1]['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(reddit.x_misp_account_avatar['data'], data)
        _id, name, displayed_name, followers, profile_image = twitter_account['Attribute']
        twitter = twitter['0']
        self.assertEqual(twitter.type, 'user-account')
        self.assertEqual(twitter.account_type, 'twitter')
        self.assertEqual(twitter.user_id, _id['value'])
        self.assertEqual(twitter.account_login, name['value'])
        self.assertEqual(twitter.display_name, displayed_name['value'])
        self.assertEqual(twitter.x_misp_followers, followers['value'])
        self.assertEqual(twitter.x_misp_profile_image['value'], profile_image['value'])
        data = profile_image['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(twitter.x_misp_profile_image['data'], data)

    def _run_indicators_from_objects_tests(self, event):
        self._add_object_ids_flag(event)
        orgc = event['Orgc']
        misp_objects = deepcopy(event['Object'])
        self.parser.parse_misp_event(event)
        identity, report, *indicators = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event, identity_id, timestamp)
        self.assertEqual(report.published, timestamp)
        for indicator, misp_object, object_ref in zip(indicators, misp_objects, object_refs):
            self._check_object_indicator_features(indicator, misp_object, identity_id, object_ref)
        return misp_objects, tuple(indicator.pattern for indicator in indicators)

    def _run_indicator_from_objects_tests(self, event):
        self._add_object_ids_flag(event)
        orgc = event['Orgc']
        misp_objects = deepcopy(event['Object'])
        self.parser.parse_misp_event(event)
        identity, report, indicator = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event, identity_id, timestamp)[0]
        self.assertEqual(report.published, timestamp)
        self._check_object_indicator_features(indicator, misp_objects[0], identity_id, object_ref)
        return misp_objects, indicator.pattern

    def _run_indicator_from_object_tests(self, event):
        self._add_object_ids_flag(event)
        orgc = event['Orgc']
        misp_object = deepcopy(event['Object'][0])
        self.parser.parse_misp_event(event)
        identity, report, indicator = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event, identity_id, timestamp)[0]
        self.assertEqual(report.published, timestamp)
        self._check_object_indicator_features(indicator, misp_object, identity_id, object_ref)
        return misp_object['Attribute'], indicator.pattern

    def _run_observables_from_objects_tests(self, event):
        self._remove_object_ids_flags(event)
        orgc = event['Orgc']
        misp_objects = deepcopy(event['Object'])
        self.parser.parse_misp_event(event)
        identity, report, *observed_datas = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event, identity_id, timestamp)
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
        orgc = event['Orgc']
        misp_objects = deepcopy(event['Object'])
        self.parser.parse_misp_event(event)
        identity, report, observed_data = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event, identity_id, timestamp)[0]
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
        orgc = event['Orgc']
        misp_object = deepcopy(event['Object'][0])
        self.parser.parse_misp_event(event)
        identity, report, observed_data = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event, identity_id, timestamp)[0]
        self.assertEqual(report.published, timestamp)
        self._check_object_observable_features(
            observed_data,
            misp_object,
            identity_id,
            object_ref
        )
        return misp_object['Attribute'], observed_data['objects']

    def _test_embedded_indicator_object_galaxy(self, event):
        self._add_object_ids_flag(event)
        orgc = event['Orgc']
        misp_object = deepcopy(event['Object'][0])
        tool_galaxy, event_coa_galaxy, event_custom_galaxy = deepcopy(event['Galaxy'])
        self.parser.parse_misp_event(event)
        bundle = self._check_bundle_features(10)
        identity, report, malware, coa, custom, indicator, tool, *relationships = bundle.objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event, identity_id, timestamp)
        self.assertEqual(report.published, timestamp)
        malware_ref, coa_ref, custom_ref, indicator_ref, tool_ref, mr_ref, coar_ref, customr_ref = object_refs
        malware_relationship, coa_relationship, custom_relationship = relationships
        malware_galaxy = misp_object['Attribute'][0]['Galaxy'][0]
        coa_galaxy = misp_object['Attribute'][1]['Galaxy'][0]
        custom_galaxy = misp_object['Attribute'][2]['Galaxy'][0]
        self._assert_multiple_equal(
            malware.id,
            malware_ref,
            f"malware--{malware_galaxy['GalaxyCluster'][0]['uuid']}"
        )
        self._assert_multiple_equal(
            coa.id,
            coa_ref,
            f"course-of-action--{event_coa_galaxy['GalaxyCluster'][0]['uuid']}",
            f"course-of-action--{coa_galaxy['GalaxyCluster'][0]['uuid']}"
        )
        self._assert_multiple_equal(
            custom.id,
            custom_ref,
            f"x-misp-galaxy-cluster--{event_custom_galaxy['GalaxyCluster'][0]['uuid']}",
            f"x-misp-galaxy-cluster--{custom_galaxy['GalaxyCluster'][0]['uuid']}"
        )
        self._assert_multiple_equal(
            indicator.id,
            indicator_ref,
            f"indicator--{misp_object['uuid']}"
        )
        self._assert_multiple_equal(
            tool.id,
            tool_ref,
            f"tool--{tool_galaxy['GalaxyCluster'][0]['uuid']}"
        )
        self.assertEqual(malware_relationship.id, mr_ref)
        self.assertEqual(coa_relationship.id, coar_ref)
        self.assertEqual(custom_relationship.id, customr_ref)
        timestamp = misp_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self._check_relationship_features(malware_relationship, indicator_ref, malware_ref, 'indicates', timestamp)
        self._check_relationship_features(coa_relationship, indicator_ref, coa_ref, 'related-to', timestamp)
        self._check_relationship_features(custom_relationship, indicator_ref, custom_ref, 'related-to', timestamp)

    def _test_embedded_non_indicator_object_galaxy(self, event):
        orgc = event['Orgc']
        coa_object, vulnerability_object = deepcopy(event['Object'])
        self.parser.parse_misp_event(event)
        bundle = self._check_bundle_features(12)
        identity, report, ap, g_coa, o_coa, malware, vulnerability, tool, *relationships = bundle.objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event, identity_id, timestamp)
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
        coa_timestamp = coa_object['timestamp']
        if not isinstance(coa_timestamp, datetime):
            coa_timestamp = self._datetime_from_timestamp(coa_timestamp)
        self._check_relationship_features(relationship1, o_coa_ref, ap_ref, 'mitigates', coa_timestamp)
        self._check_relationship_features(relationship2, o_coa_ref, g_coa_ref, 'related-to', coa_timestamp)
        vulnerability_timestamp = vulnerability_object['timestamp']
        if not isinstance(vulnerability_timestamp, datetime):
            vulnerability_timestamp = self._datetime_from_timestamp(vulnerability_timestamp)
        self._check_relationship_features(relationship3, vulnerability_ref, malware_ref, 'related-to', vulnerability_timestamp)
        self._check_relationship_features(relationship4, vulnerability_ref, g_coa_ref, 'related-to', vulnerability_timestamp)

    def _test_embedded_object_galaxy_with_multiple_clusters(self, event):
        orgc = event['Orgc']
        misp_object = deepcopy(event['Object'][0])
        self.parser.parse_misp_event(event)
        bundle = self._check_bundle_features(7)
        identity, report, malware1, malware2, observed_data, relationship1, relationship2 = bundle.objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event, identity_id, timestamp)
        self.assertEqual(report.published, timestamp)
        malware1_ref, malware2_ref, observed_data_ref, relationship1_ref, relationship2_ref = object_refs
        self.assertEqual(malware1.id, malware1_ref)
        self.assertEqual(malware2.id, malware2_ref)
        self.assertEqual(observed_data.id, observed_data_ref)
        self.assertEqual(relationship1.id, relationship1_ref)
        self.assertEqual(relationship2.id, relationship2_ref)
        object_timestamp = misp_object['timestamp']
        if not isinstance(object_timestamp, datetime):
            object_timestamp = self._datetime_from_timestamp(object_timestamp)
        self._check_relationship_features(relationship1, observed_data_ref, malware1_ref, 'related-to', object_timestamp)
        self._check_relationship_features(relationship2, observed_data_ref, malware2_ref, 'related-to', object_timestamp)

    def _test_embedded_observable_object_galaxy(self, event):
        orgc = event['Orgc']
        misp_object = deepcopy(event['Object'][0])
        self.parser.parse_misp_event(event)
        bundle = self._check_bundle_features(6)
        identity, report, malware, observed_data, tool, relationship = bundle.objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event, identity_id, timestamp)
        self.assertEqual(report.published, timestamp)
        malware_ref, observed_data_ref, tool_ref, relationship_ref = object_refs
        self.assertEqual(malware.id, malware_ref)
        self.assertEqual(observed_data.id, observed_data_ref)
        self.assertEqual(tool.id, tool_ref)
        self.assertEqual(relationship.id, relationship_ref)
        timestamp = misp_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self._check_relationship_features(
            relationship, observed_data_ref, malware_ref, 'related-to', timestamp
        )

    def _test_event_with_android_app_indicator_objet(self, event):
        attributes, pattern = self._run_indicator_from_object_tests(event)
        name, certificate, domain = (attribute['value'] for attribute in attributes)
        name_pattern, cert_pattern, domain_pattern = pattern[1:-1].split(' AND ')
        self.assertEqual(name_pattern, f"software:name = '{name}'")
        self.assertEqual(cert_pattern, f"software:x_misp_certificate = '{certificate}'")
        self.assertEqual(domain_pattern, f"software:x_misp_domain = '{domain}'")

    def _test_event_with_android_app_observable_objet(self, event):
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        software = observable_objects['0']
        name, certificate, domain = (attribute['value'] for attribute in attributes)
        self.assertEqual(software.type, 'software')
        self.assertEqual(software.name, name)
        self.assertEqual(software.x_misp_certificate, certificate)
        self.assertEqual(software.x_misp_domain, domain)

    def _test_event_with_asn_indicator_objet(self, event):
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

    def _test_event_with_asn_observable_objet(self, event):
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        asn, description, subnet1, subnet2 = (attribute['value'] for attribute in attributes)
        self.assertEqual(observable_objects['0'].type, 'autonomous-system')
        self.assertEqual(observable_objects['0'].number, int(asn[2:]))
        self.assertEqual(observable_objects['0'].name, description)
        self.assertEqual(
            observable_objects['0'].x_misp_subnet_announced,
            [subnet1, subnet2]
        )

    def _test_event_with_attack_pattern_objet(self, event):
        orgc = event['Orgc']
        misp_object = deepcopy(event['Object'][0])
        self.parser.parse_misp_event(event)
        identity, report, attack_pattern = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event, identity_id, timestamp)[0]
        self.assertEqual(report.published, timestamp)
        self._assert_multiple_equal(
            attack_pattern.id,
            f"attack-pattern--{misp_object['uuid']}",
            object_ref
        )
        self._check_attack_pattern_object(attack_pattern, misp_object, identity_id)

    def _test_event_with_course_of_action_object(self, event):
        orgc = event['Orgc']
        misp_object = deepcopy(event['Object'][0])
        self.parser.parse_misp_event(event)
        identity, report, course_of_action = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event, identity_id, timestamp)[0]
        self.assertEqual(report.published, timestamp)
        self._assert_multiple_equal(
            course_of_action.id,
            f"course-of-action--{misp_object['uuid']}",
            object_ref
        )
        self._check_course_of_action_object(course_of_action, misp_object, identity_id)

    def _test_event_with_cpe_asset_indicator_object(self, event):
        attributes, pattern = self._run_indicator_from_object_tests(event)
        cpe, language, product, vendor, version, description = (attribute['value'] for attribute in attributes)
        cpe_pattern, language_pattern, name, vendor_pattern, version_pattern, description_pattern = pattern[1:-1].split(' AND ')
        self.assertEqual(cpe_pattern, f"software:cpe = '{cpe}'")
        self.assertEqual(language_pattern, f"software:languages = '{language}'")
        self.assertEqual(name, f"software:name = '{product}'")
        self.assertEqual(vendor_pattern, f"software:vendor = '{vendor}'")
        self.assertEqual(version_pattern, f"software:version = '{version}'")
        self.assertEqual(description_pattern, f"software:x_misp_description = '{description}'")

    def _test_event_with_cpe_asset_observable_object(self, event):
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

    def _test_event_with_credential_indicator_object(self, event):
        attributes, pattern = self._run_indicator_from_object_tests(event)
        text, username, *attributes = ((attribute['object_relation'], attribute['value']) for attribute in attributes)
        attributes.insert(0, text)
        username_pattern, *pattern = pattern[1:-1].split(' AND ')
        self.assertEqual(username_pattern, f"user-account:user_id = '{username[1]}'")
        for pattern_part, attribute in zip(pattern, attributes):
            feature, value = attribute
            self.assertEqual(pattern_part, f"user-account:x_misp_{feature} = '{value}'")

    def _test_event_with_credential_observable_object(self, event):
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        user_account = observable_objects['0']
        text, username, *attributes = ((attribute['object_relation'], attribute['value']) for attribute in attributes)
        attributes.insert(0, text)
        self.assertEqual(user_account.type, 'user-account')
        self.assertEqual(user_account.user_id, username[1])
        for feature, value in attributes:
            self.assertEqual(getattr(user_account, f'x_misp_{feature}'), value)

    def _test_event_with_custom_objects(self, event):
        orgc = event['Orgc']
        misp_objects = deepcopy(event['Object'])
        self.parser.parse_misp_event(event)
        identity, report, *custom_objects = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event, identity_id, timestamp)
        self.assertEqual(report.published, timestamp)
        for misp_object, custom_object, object_ref in zip(misp_objects, custom_objects, object_refs):
            self._run_custom_object_tests(misp_object, custom_object, object_ref, identity_id)

    def _test_event_with_domain_ip_indicator_object(self, event):
        attributes, pattern = self._run_indicator_from_object_tests(event)
        _domain, _hostname, _ip, _port = (attribute['value'] for attribute in attributes)
        domain_, hostname_, ip_, port_ = pattern[1:-1].split(' AND ')
        self.assertEqual(domain_, f"domain-name:value = '{_domain}'")
        self.assertEqual(hostname_, f"domain-name:x_misp_hostname = '{_hostname}'")
        self.assertEqual(ip_, f"domain-name:resolves_to_refs[*].value = '{_ip}'")
        self.assertEqual(port_, f"domain-name:x_misp_port = '{_port}'")

    def _test_event_with_domain_ip_observable_object_custom(self, event):
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

    def _test_event_with_domain_ip_observable_object_standard(self, event):
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

    def _test_event_with_email_indicator_object(self, event):
        attributes, pattern = self._run_indicator_from_object_tests(event)
        _from, _from_dn, _to, _to_dn, _cc1, _cc1_dn, _cc2, _cc2_dn, _bcc, _bcc_dn, _reply_to, _subject, _attachment1, _attachment2, _x_mailer, _user_agent, _boundary, _message_id = (attribute['value'] for attribute in attributes)
        to_, to_dn, cc1_, cc1_dn, cc2_, cc2_dn, bcc_, bcc_dn, from_, from_dn, reply_to_, subject_, x_mailer_, attachment1_, content1, attachment2_, content2, user_agent_, boundary_, message_id_ = pattern[1:-1].split(' AND ')
        self.assertEqual(from_, f"email-message:from_ref.value = '{_from}'")
        self.assertEqual(from_dn, f"email-message:from_ref.display_name = '{_from_dn}'")
        self.assertEqual(to_, f"email-message:to_refs[0].value = '{_to}'")
        self.assertEqual(to_dn, f"email-message:to_refs[0].display_name = '{_to_dn}'")
        self.assertEqual(cc1_, f"email-message:cc_refs[0].value = '{_cc1}'")
        self.assertEqual(cc1_dn, f"email-message:cc_refs[0].display_name = '{_cc1_dn}'")
        self.assertEqual(cc2_, f"email-message:cc_refs[1].value = '{_cc2}'")
        self.assertEqual(cc2_dn, f"email-message:cc_refs[1].display_name = '{_cc2_dn}'")
        self.assertEqual(bcc_, f"email-message:bcc_refs[0].value = '{_bcc}'")
        self.assertEqual(bcc_dn, f"email-message:bcc_refs[0].display_name = '{_bcc_dn}'")
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
            content1,
            f"email-message:body_multipart[0].content_disposition = 'attachment'"
        )
        self.assertEqual(
            attachment2_,
            f"email-message:body_multipart[1].body_raw_ref.name = '{_attachment2}'"
        )
        self.assertEqual(
            content2,
            f"email-message:body_multipart[1].content_disposition = 'attachment'"
        )
        self.assertEqual(
            x_mailer_,
            f"email-message:additional_header_fields.x_mailer = '{_x_mailer}'"
        )
        self.assertEqual(user_agent_, f"email-message:x_misp_user_agent = '{_user_agent}'")
        self.assertEqual(boundary_, f"email-message:x_misp_mime_boundary = '{_boundary}'")
        self.assertEqual(message_id_, f"email-message:x_misp_message_id = '{_message_id}'")

    def _test_event_with_email_observable_object(self, event):
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        _from, _from_dn, _to, _to_dn, _cc1, _cc1_dn, _cc2, _cc2_dn, _bcc, _bcc_dn, _reply_to, _subject, _attachment1, _attachment2, _x_mailer, _user_agent, _boundary, _message_id = (attribute['value'] for attribute in attributes)
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
        self.assertEqual(message.bcc_refs, ['5'])
        body1, body2 = message.body_multipart
        self.assertEqual(body1['body_raw_ref'], '6')
        self.assertEqual(body1['content_disposition'], f"attachment; filename='{_attachment1}'")
        self.assertEqual(body2['body_raw_ref'], '7')
        self.assertEqual(body2['content_disposition'], f"attachment; filename='{_attachment2}'")
        self._check_email_address(observable_objects['1'], _from, display_name=_from_dn)
        self._check_email_address(observable_objects['2'], _to, display_name=_to_dn)
        self._check_email_address(observable_objects['3'], _cc1, display_name=_cc1_dn)
        self._check_email_address(observable_objects['4'], _cc2, display_name=_cc2_dn)
        self._check_email_address(observable_objects['5'], _bcc, display_name=_bcc_dn)
        file1 = observable_objects['6']
        self.assertEqual(file1.type, 'file')
        self.assertEqual(file1.name, _attachment1)
        file2 = observable_objects['7']
        self.assertEqual(file2.type, 'file')
        self.assertEqual(file2.name, _attachment2)

    def _test_event_with_email_indicator_object_with_display_names(self, event):
        attributes, pattern = self._run_indicator_from_object_tests(event)
        _from, _from_name, _to, _to_name, _cc1, _cc2_name, _bcc, _bcc_name = (attribute['value'] for attribute in attributes)
        to_, to_name_, cc1_, cc2_name_, bcc_, bcc_name_, from_, from_name_ = pattern[1:-1].split(' AND ')
        self.assertEqual(to_, f"email-message:to_refs[0].value = '{_to}'")
        self.assertEqual(to_name_, f"email-message:to_refs[0].display_name = '{_to_name}'")
        self.assertEqual(cc1_, f"email-message:cc_refs[0].value = '{_cc1}'")
        self.assertEqual(cc2_name_, f"email-message:cc_refs[1].display_name = '{_cc2_name}'")
        self.assertEqual(bcc_, f"email-message:bcc_refs[0].value = '{_bcc}'")
        self.assertEqual(bcc_name_, f"email-message:bcc_refs[0].display_name = '{_bcc_name}'")
        self.assertEqual(from_, f"email-message:from_ref.value = '{_from}'")
        self.assertEqual(from_name_, f"email-message:from_ref.display_name = '{_from_name}'")

    def _test_event_with_email_observable_object_with_display_names(self, event):
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        _from, _from_name, _to, _to_name, _cc1, _cc2_name, _bcc, _bcc_name = (attribute['value'] for attribute in attributes)
        message = observable_objects['0']
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.from_ref, '1')
        self.assertEqual(message.to_refs, ['2'])
        self.assertEqual(message.cc_refs, ['3'])
        self.assertEqual(message.bcc_refs, ['4'])
        self._check_email_address(observable_objects['1'], _from, display_name=_from_name)
        self._check_email_address(observable_objects['2'], _to, display_name=_to_name)
        self._check_email_address(observable_objects['3'], _cc1)
        self.assertEqual(message.x_misp_cc_display_name, _cc2_name)
        self._check_email_address(observable_objects['4'], _bcc, display_name=_bcc_name)

    def _test_event_with_employee_object(self, event):
        orgc = event['Orgc']
        misp_object = deepcopy(event['Object'][0])
        self.parser.parse_misp_event(event)
        identity, report, employee = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event, identity_id, timestamp)[0]
        employee_type = self._check_employee_object(
            employee,
            misp_object,
            object_ref,
            identity_id
        )
        self.assertEqual(employee.x_misp_employee_type, employee_type)

    def _test_event_with_file_and_pe_indicator_objects(self, event):
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

    def _test_event_with_file_and_pe_observable_objects(self, event):
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

    def _test_event_with_file_indicator_object(self, event):
        attributes, pattern = self._run_indicator_from_object_tests(event)
        _malware_sample, _filename, _md5, _sha1, _sha256, _size, _attachment, _path, _encoding, creation, modification = (attribute['value'] for attribute in attributes)
        md5_, sha1_, sha256_, filename_, encoding_, size_, ctime, mtime, path_, malware_sample_, attachment_ = self._reassemble_pattern(pattern[1:-1])
        self.assertEqual(md5_, f"file:hashes.MD5 = '{_md5}'")
        self.assertEqual(sha1_, f"file:hashes.SHA1 = '{_sha1}'")
        self.assertEqual(sha256_, f"file:hashes.SHA256 = '{_sha256}'")
        self.assertEqual(filename_, f"file:name = '{_filename}'")
        self.assertEqual(encoding_, f"file:name_enc = '{_encoding}'")
        self.assertEqual(path_, f"file:parent_directory_ref.path = '{_path}'")
        self.assertEqual(size_, f"file:size = '{_size}'")
        self.assertEqual(ctime, f"file:created = '{creation}'")
        self.assertEqual(mtime, f"file:modified = '{modification}'")
        ms_data, ms_filename, ms_md5, mime_type = malware_sample_.split(' AND ')
        data = attributes[0]['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(ms_data, f"(file:content_ref.payload_bin = '{data}'")
        filename, md5 = _malware_sample.split('|')
        self.assertEqual(ms_filename, f"file:content_ref.x_misp_filename = '{filename}'")
        self.assertEqual(ms_md5, f"file:content_ref.hashes.MD5 = '{md5}'")
        self.assertEqual(mime_type, f"file:content_ref.mime_type = 'application/zip')")
        a_data, a_filename = attachment_.split(' AND ')
        data = attributes[6]['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(a_data, f"(file:content_ref.payload_bin = '{data}'")
        self.assertEqual(a_filename, f"file:content_ref.x_misp_filename = '{_attachment}')")

    def _test_event_with_file_observable_object(self, event):
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        _malware_sample, _filename, _md5, _sha1, _sha256, _size, _attachment, _path, _encoding, ctime, mtime = (attribute['value'] for attribute in attributes)
        _file = observable_objects['0']
        self.assertEqual(_file.type, 'file')
        self.assertEqual(_file.size, int(_size))
        self.assertEqual(_file.name, _filename)
        self.assertEqual(_file.name_enc, _encoding)
        if isinstance(ctime, str):
            ctime = self._datetime_from_str(ctime)
        self.assertEqual(_file.created, ctime)
        if isinstance(mtime, str):
            mtime = self._datetime_from_str(mtime)
        self.assertEqual(_file.modified, mtime)
        hashes = _file.hashes
        self.assertEqual(hashes['MD5'], _md5)
        self.assertEqual(hashes['SHA-1'], _sha1)
        self.assertEqual(hashes['SHA-256'], _sha256)
        self.assertEqual(_file.x_misp_attachment['value'], _attachment)
        data = attributes[6]['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(_file.x_misp_attachment['data'], data)
        self.assertEqual(_file.parent_directory_ref, '1')
        self.assertEqual(_file.content_ref, '2')
        directory = observable_objects['1']
        self.assertEqual(directory.type, 'directory')
        self.assertEqual(directory.path, _path)
        artifact = observable_objects['2']
        self.assertEqual(artifact.type, 'artifact')
        data = attributes[0]['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(artifact.payload_bin, data)
        filename, md5 = _malware_sample.split('|')
        self.assertEqual(artifact.hashes['MD5'], md5)
        self.assertEqual(artifact.x_misp_filename, filename)

    def _test_event_with_http_request_indicator_object(self, event):
        attributes, pattern = self._run_indicator_from_object_tests(event)
        ip_src, ip_dst, host, http_method, agent, uri, url, content = (attribute['value'] for attribute in attributes)
        src_type, src_value, dst_type, dst_value, host_type, host_value, method, req_value1, req_value2, content_type, user_agent = pattern[1:-1].split(' AND ')
        prefix = 'network-traffic'
        self.assertEqual(src_type, f"({prefix}:src_ref.type = 'ipv4-addr'")
        self.assertEqual(src_value, f"{prefix}:src_ref.value = '{ip_src}')")
        self.assertEqual(dst_type, f"({prefix}:dst_ref.type = 'ipv4-addr'")
        self.assertEqual(dst_value, f"{prefix}:dst_ref.value = '{ip_dst}')")
        self.assertEqual(host_type, f"({prefix}:dst_ref.type = 'domain-name'")
        self.assertEqual(host_value, f"{prefix}:dst_ref.value = '{host}')")
        feature = "extensions.'http-request-ext'"
        self.assertEqual(method, f"{prefix}:{feature}.request_method = '{http_method}'")
        self.assertEqual(req_value1, f"{prefix}:{feature}.request_value = '{uri}'")
        self.assertEqual(req_value2, f"{prefix}:{feature}.request_value = '{url}'")
        self.assertEqual(
            content_type,
            f"{prefix}:{feature}.request_header.'Content-Type' = '{content}'"
        )
        self.assertEqual(
            user_agent,
            f"{prefix}:{feature}.request_header.'User-Agent' = '{agent}'"
        )

    def _test_event_with_http_request_observable_object(self, event):
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        ip_src, ip_dst, host, method, user_agent, uri, url, content = (attribute['value'] for attribute in attributes)
        network_traffic = observable_objects['0']
        src_address = observable_objects['1']
        dst_address = observable_objects['2']
        domain_name = observable_objects['3']
        self.assertEqual(network_traffic.type, 'network-traffic')
        extension = network_traffic.extensions['http-request-ext']
        self.assertEqual(extension.request_method, method)
        self.assertEqual(extension.request_value, uri)
        self.assertEqual(extension.request_header['Content-Type'], content)
        self.assertEqual(extension.request_header['User-Agent'], user_agent)
        self.assertEqual(network_traffic.x_misp_url, url)
        self.assertEqual(network_traffic.src_ref, '1')
        self.assertEqual(network_traffic.dst_ref, '2')
        self.assertEqual(src_address.type, 'ipv4-addr')
        self.assertEqual(src_address.value, ip_src)
        self.assertEqual(dst_address.type, 'ipv4-addr')
        self.assertEqual(dst_address.value, ip_dst)
        self.assertEqual(domain_name.type, 'domain-name')
        self.assertEqual(domain_name.value, host)
        self.assertEqual(domain_name.resolves_to_refs, ['2'])

    def _test_event_with_identity_object(self, event):
        orgc = event['Orgc']
        misp_object = deepcopy(event['Object'][0])
        self.parser.parse_misp_event(event)
        created_by_ref_identity, report, identity = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(created_by_ref_identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event, identity_id, timestamp)[0]
        self.assertEqual(identity.type, 'identity')
        self._assert_multiple_equal(
            identity.id,
            object_ref,
            f"identity--{misp_object['uuid']}"
        )
        self.assertEqual(identity.created_by_ref, identity_id)
        name, contact_information, description, identity_class, roles = (attribute['value'] for attribute in misp_object['Attribute'])
        self.assertEqual(identity.name, name)
        self.assertEqual(identity.contact_information, contact_information)
        self.assertEqual(identity.description, description)
        self.assertEqual(identity.identity_class, identity_class)
        self.assertEqual(identity.x_misp_roles, roles)

    def _test_event_with_image_indicator_object(self, event):
        attributes, pattern = self._run_indicator_from_object_tests(event)
        attachment, filename, url, text = (attribute['value'] for attribute in attributes)
        name, payload_bin, mime_type, name_ref, url_pattern, text_pattern = pattern[1:-1].split(' AND ')
        self.assertEqual(name, f"file:name = '{filename}'")
        data = attributes[0]['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(payload_bin, f"file:content_ref.payload_bin = '{data}'")
        self.assertEqual(mime_type, f"file:content_ref.mime_type = 'image/png'")
        self.assertEqual(name_ref, f"file:content_ref.x_misp_filename = '{attachment}'")
        self.assertEqual(url_pattern, f"file:content_ref.url = '{url}'")
        self.assertEqual(text_pattern, f"file:x_misp_image_text = '{text}'")

    def _test_event_with_image_observable_object(self, event):
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        attachment, filename, url, text = (attribute['value'] for attribute in attributes)
        file = observable_objects['0']
        self.assertEqual(file.type, 'file')
        self.assertEqual(file.name, filename)
        self.assertEqual(file.content_ref, '1')
        self.assertEqual(file.x_misp_image_text, text)
        artifact = observable_objects['1']
        self.assertEqual(artifact.type, 'artifact')
        data = attributes[0]['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(artifact.payload_bin, data)
        self.assertEqual(artifact.mime_type, 'image/png')
        self.assertEqual(artifact.x_misp_url, url)
        self.assertEqual(artifact.x_misp_filename, attachment)

    def _test_event_with_ip_port_indicator_object(self, event):
        prefix = 'network-traffic'
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

    def _test_event_with_ip_port_observable_object(self, event):
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        ip, port, domain, first_seen = (attribute['value'] for attribute in attributes)
        network_traffic = observable_objects['0']
        address_object = observable_objects['1']
        self.assertEqual(network_traffic.type, 'network-traffic')
        self.assertEqual(network_traffic.dst_port, int(port))
        timestamp = first_seen
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_str(timestamp)
        self.assertEqual(network_traffic.start, timestamp)
        self.assertIn('ipv4', network_traffic.protocols)
        self.assertEqual(network_traffic.dst_ref, '1')
        self.assertEqual(network_traffic.x_misp_domain, domain)
        self.assertEqual(address_object.type, 'ipv4-addr')
        self.assertEqual(address_object.value, ip)

    def _test_event_with_legal_entity_object(self, event):
        orgc = event['Orgc']
        misp_object = deepcopy(event['Object'][0])
        self.parser.parse_misp_event(event)
        identity, report, legal_entity = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event, identity_id, timestamp)[0]
        self._check_legal_entity_object_features(
            legal_entity,
            misp_object,
            object_ref,
            identity_id
        )

    def _test_event_with_lnk_indicator_object(self, event):
        attributes, pattern = self._run_indicator_from_object_tests(event)
        filename, fullpath, md5, sha1, sha256, malware_sample, size_in_bytes, creation, modification, access = (attribute['value'] for attribute in attributes)
        accessed, created, modified, name, directory, md5_pattern, sha1_pattern, sha256_pattern, artifact, size = self._reassemble_pattern(pattern[1:-1])
        self.assertEqual(accessed, f"file:accessed = '{access}'")
        self.assertEqual(created, f"file:created = '{creation}'")
        self.assertEqual(modified, f"file:modified = '{modification}'")
        self.assertEqual(name, f"file:name = '{filename}'")
        self.assertEqual(directory, f"file:parent_directory_ref.path = '{fullpath}'")
        self.assertEqual(md5_pattern, f"file:hashes.MD5 = '{md5}'")
        self.assertEqual(sha1_pattern, f"file:hashes.SHA1 = '{sha1}'")
        self.assertEqual(sha256_pattern, f"file:hashes.SHA256 = '{sha256}'")
        ms_data, ms_filename, ms_md5, mime_type = artifact.split(' AND ')
        data = attributes[5]['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(ms_data, f"(file:content_ref.payload_bin = '{data}'")
        filename, md5 = malware_sample.split('|')
        self.assertEqual(ms_filename, f"file:content_ref.x_misp_filename = '{filename}'")
        self.assertEqual(ms_md5, f"file:content_ref.hashes.MD5 = '{md5}'")
        self.assertEqual(mime_type, f"file:content_ref.mime_type = 'application/zip')")
        self.assertEqual(size, f"file:size = '{size_in_bytes}'")

    def _test_event_with_lnk_observable_object(self, event):
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
        data = attributes[5]['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(artifact.payload_bin, data)
        self.assertEqual(artifact.mime_type, 'application/zip')
        filename, md5 = malware_sample.split('|')
        self.assertEqual(artifact.x_misp_filename, filename)
        self.assertEqual(artifact.hashes['MD5'], md5)
        self.assertEqual(file.content_ref, '2')
        if isinstance(creation, str):
            creation = self._datetime_from_str(creation)
        self.assertEqual(file.created, creation)
        if isinstance(modification, str):
            modification = self._datetime_from_str(modification)
        self.assertEqual(file.modified, modification)
        if isinstance(access, str):
            access = self._datetime_from_str(access)
        self.assertEqual(file.accessed, access)

    def _test_event_with_mutex_indicator_object(self, event):
        attributes, pattern = self._run_indicator_from_object_tests(event)
        _name, _description, _os = (attribute['value'] for attribute in attributes)
        name_, description_, os_ = pattern[1:-1].split(' AND ')
        self.assertEqual(name_, f"mutex:name = '{_name}'")
        self.assertEqual(description_, f"mutex:x_misp_description = '{_description}'")
        self.assertEqual(os_, f"mutex:x_misp_operating_system = '{_os}'")

    def _test_event_with_mutex_observable_object(self, event):
        attributes, observable_object = self._run_observable_from_object_tests(event)
        name, description, _os = (attribute['value'] for attribute in attributes)
        mutex = observable_object['0']
        self.assertEqual(mutex.type, 'mutex')
        self.assertEqual(mutex.name, name)
        self.assertEqual(mutex.x_misp_description, description)
        self.assertEqual(mutex.x_misp_operating_system, _os)

    def _test_event_with_netflow_indicator_object(self, event):
        attributes, pattern = self._run_indicator_from_object_tests(event)
        ip_src, ip_dst, src_as, dst_as, src_port, dst_port, protocol, first_seen, tcp_flags = (attribute['value'] for attribute in attributes)
        src_type, src_value, _src_as, dst_type, dst_value, _dst_as, _protocol, _src_port, _dst_port, start, tcp_ext = pattern[1:-1].split(' AND ')
        prefix = 'network-traffic'
        self.assertEqual(src_type, f"({prefix}:src_ref.type = 'ipv4-addr'")
        self.assertEqual(src_value, f"{prefix}:src_ref.value = '{ip_src}'")
        self.assertEqual(_src_as, f"{prefix}:src_ref.belongs_to_refs[0].number = '{self._parse_AS_value(src_as)}')")
        self.assertEqual(dst_type, f"({prefix}:dst_ref.type = 'ipv4-addr'")
        self.assertEqual(dst_value, f"{prefix}:dst_ref.value = '{ip_dst}'")
        self.assertEqual(_dst_as, f"{prefix}:dst_ref.belongs_to_refs[0].number = '{self._parse_AS_value(dst_as)}')")
        self.assertEqual(_protocol, f"{prefix}:protocols[0] = '{protocol.lower()}'")
        self.assertEqual(_src_port, f"{prefix}:src_port = '{src_port}'")
        self.assertEqual(_dst_port, f"{prefix}:dst_port = '{dst_port}'")
        self.assertEqual(start, f"{prefix}:start = '{first_seen}'")
        self.assertEqual(tcp_ext, f"{prefix}:extensions.'tcp-ext'.src_flags_hex = '{tcp_flags}'")

    def _test_event_with_netflow_observable_object(self, event):
        attributes, observable_object = self._run_observable_from_object_tests(event)
        ip_src, ip_dst, src_as, dst_as, src_port, dst_port, protocol, first_seen, tcp_flags = (attribute['value'] for attribute in attributes)
        network_traffic = observable_object['0']
        src_address = observable_object['1']
        src_autonomous_system = observable_object['2']
        dst_address = observable_object['3']
        dst_autonomous_system = observable_object['4']
        self.assertEqual(network_traffic.type, 'network-traffic')
        timestamp = first_seen
        if isinstance(timestamp, str):
            timestamp = self._datetime_from_str(timestamp)
        self.assertEqual(network_traffic.start, timestamp)
        self.assertEqual(network_traffic.src_port, int(src_port))
        self.assertEqual(network_traffic.dst_port, int(dst_port))
        self.assertEqual(set(network_traffic.protocols), {protocol.lower(), 'tcp'})
        self.assertEqual(network_traffic.extensions['tcp-ext'].src_flags_hex, tcp_flags)
        self.assertEqual(network_traffic.src_ref, '1')
        self.assertEqual(network_traffic.dst_ref, '3')
        self._assert_multiple_equal(
            src_address.type,
            dst_address.type,
            'ipv4-addr'
        )
        self._assert_multiple_equal(
            src_autonomous_system.type,
            dst_autonomous_system.type,
            'autonomous-system'
        )
        self.assertEqual(src_address.value, ip_src)
        self.assertEqual(src_address.belongs_to_refs, ['2'])
        self.assertEqual(src_autonomous_system.number, self._parse_AS_value(src_as))
        self.assertEqual(dst_address.value, ip_dst)
        self.assertEqual(dst_address.belongs_to_refs, ['4'])
        self.assertEqual(dst_autonomous_system.number, self._parse_AS_value(dst_as))

    def _test_event_with_network_connection_indicator_object(self, event):
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

    def _test_event_with_network_connection_observable_object(self, event):
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

    def _test_event_with_network_socket_indicator_object(self, event):
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

    def _test_event_with_network_socket_observable_object(self, event):
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

    def _test_event_with_news_agency_object(self, event):
        orgc = event['Orgc']
        misp_object = deepcopy(event['Object'][0])
        self.parser.parse_misp_event(event)
        identity, report, news_agency = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event, identity_id, timestamp)[0]
        news_agency_id = f"identity--{misp_object['uuid']}"
        name, address1, email1, phone1, address2, email2, phone2, link, attachment = (attribute['value'] for attribute in misp_object['Attribute'])
        self.assertEqual(news_agency.type, 'identity')
        self._assert_multiple_equal(
            news_agency.id,
            news_agency_id,
            object_ref
        )
        self.assertEqual(news_agency.identity_class, 'organization')
        timestamp = misp_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self.assertEqual(news_agency.created, timestamp)
        self.assertEqual(news_agency.modified, timestamp)
        self.assertEqual(news_agency.name, name)
        self.assertEqual(
            news_agency.contact_information,
            f"address: {address1}; {address2} / e-mail: {email1}; {email2} / phone-number: {phone1}; {phone2} / link: {link}"
        )
        self.assertEqual(news_agency.x_misp_attachment['value'], attachment)
        data = misp_object['Attribute'][-1]['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(news_agency.x_misp_attachment['data'], data)

    def _test_event_with_organization_object(self, event):
        orgc = event['Orgc']
        misp_object = deepcopy(event['Object'][0])
        self.parser.parse_misp_event(event)
        identity, report, organization = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event, identity_id, timestamp)[0]
        organization_id = f"identity--{misp_object['uuid']}"
        name, description, address, email, phone, role, alias = (attribute['value'] for attribute in misp_object['Attribute'])
        self.assertEqual(organization.type, 'identity')
        self._assert_multiple_equal(
            organization.id,
            organization_id,
            object_ref
        )
        self.assertEqual(organization.identity_class, 'organization')
        timestamp = misp_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
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

    def _test_event_with_pe_and_section_indicator_objects(self, event):
        misp_objects, pattern = self._run_indicator_from_objects_tests(event)
        self._check_pe_and_section_pattern(pattern[1:-1].split(' AND '), *misp_objects)

    def _test_event_with_pe_and_section_observable_objects(self, event):
        misp_objects, observable_objects = self._run_observable_from_objects_tests(event)
        self._check_pe_and_section_observable(
            observable_objects['0'].extensions['windows-pebinary-ext'],
            *misp_objects
        )

    def _test_event_with_person_object(self, event):
        orgc = event['Orgc']
        misp_object = deepcopy(event['Object'][0])
        self.parser.parse_misp_event(event)
        identity, report, person = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event, identity_id, timestamp)[0]
        role = self._check_person_object(
            person,
            misp_object,
            object_ref,
            identity_id
        )
        self.assertEqual(person.x_misp_role, role)

    def _test_event_with_process_indicator_object(self, event):
        attributes, pattern = self._run_indicator_from_object_tests(event)
        _pid, _child_pid, _parent_pid, _name, _image, _parent_image, _port, _hidden, _command_line, _parent_name = (attribute['value'] for attribute in attributes)
        hidden_, name_, pid_, image_, command_line_, parent_image_, parent_pid_, parent_name_, child_pid_, port_ = pattern[1:-1].split(' AND ')
        self.assertEqual(name_, f"process:name = '{_name}'")
        self.assertEqual(pid_, f"process:pid = '{_pid}'")
        self.assertEqual(image_, f"process:binary_ref.name = '{_image}'")
        self.assertEqual(command_line_, f"process:parent_ref.command_line = '{_command_line}'")
        self.assertEqual(parent_image_, f"process:parent_ref.binary_ref.name = '{_parent_image}'")
        self.assertEqual(parent_pid_, f"process:parent_ref.pid = '{_parent_pid}'")
        self.assertEqual(parent_name_, f"process:parent_ref.name = '{_parent_name}'")
        self.assertEqual(child_pid_, f"process:child_refs[0].pid = '{_child_pid}'")
        self.assertEqual(port_, f"process:x_misp_port = '{_port}'")
        self.assertEqual(hidden_, f"process:is_hidden = '{_hidden}'")

    def _test_event_with_process_observable_object(self, event):
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        pid, child_pid, parent_pid, name, image, parent_image, port, _, command_line, parent_name = (attribute['value'] for attribute in attributes)
        process = observable_objects['0']
        self.assertEqual(process.type, 'process')
        self.assertEqual(process.pid, int(pid))
        self.assertEqual(process.name, name)
        self.assertEqual(process.is_hidden, True)
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

    def _test_event_with_registry_key_indicator_object(self, event):
        attributes, pattern = self._run_indicator_from_object_tests(event)
        _key, _hive, _name, _data, _data_type, _modified = (attribute['value'] for attribute in attributes)
        key_, modified_, data_, data_type_, name_, hive_ = pattern[1:-1].split(' AND ')
        key = _key.replace('\\', '\\\\')
        self.assertEqual(key_, f"windows-registry-key:key = '{key}'")
        self.assertEqual(modified_, f"windows-registry-key:modified = '{_modified}'")
        self.assertEqual(data_, f"windows-registry-key:values[0].data = '{self._sanitize_registry_key_value(_data)}'")
        self.assertEqual(data_type_, f"windows-registry-key:values[0].data_type = '{_data_type}'")
        self.assertEqual(name_, f"windows-registry-key:values[0].name = '{_name}'")
        self.assertEqual(hive_, f"windows-registry-key:x_misp_hive = '{_hive}'")

    def _test_event_with_registry_key_observable_object(self, event):
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        key, hive, name, data, data_type, last_modified = (attribute['value'] for attribute in attributes)
        registry_key = observable_objects['0']
        self.assertEqual(registry_key.type, 'windows-registry-key')
        self.assertEqual(registry_key.key, key)
        if not isinstance(last_modified, datetime):
            last_modified = self._datetime_from_str(last_modified)
        self.assertEqual(
            registry_key.modified.timestamp(),
            last_modified.timestamp()
        )
        self.assertEqual(registry_key.x_misp_hive, hive)
        registry_value = registry_key['values'][0]
        self.assertEqual(registry_value.data, data)
        self.assertEqual(registry_value.data_type, data_type)
        self.assertEqual(registry_value.name, name)

    def _test_event_with_script_objects(self, event):
        orgc = event['Orgc']
        malware_script, tool_script = deepcopy(event['Object'])
        self.parser.parse_misp_event(event)
        identity, report, malware, tool = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        malware_ref, tool_ref = self._check_report_features(report, event, identity_id, timestamp)
        language, comment, name, script, script_attachment, state = malware_script['Attribute']
        self._assert_multiple_equal(
            malware.id,
            f"malware--{malware_script['uuid']}",
            malware_ref
        )
        self.assertEqual(malware.type, 'malware')
        self.assertEqual(malware.implementation_languages, [language['value']])
        self.assertEqual(malware.name, name['value'])
        self.assertEqual(malware.description, comment['value'])
        self.assertEqual(malware.x_misp_script, script['value'])
        self.assertEqual(
            malware.x_misp_script_as_attachment['value'],
            script_attachment['value']
        )
        data = script_attachment['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(malware.x_misp_script_as_attachment['data'], data)
        self.assertEqual(malware.x_misp_state, state['value'])
        language, comment, name, script, script_attachment, state = tool_script['Attribute']
        self._assert_multiple_equal(
            tool.id,
            f"tool--{tool_script['uuid']}",
            tool_ref
        )
        self.assertEqual(tool.type, 'tool')
        self.assertEqual(tool.name, name['value'])
        self.assertEqual(tool.description, comment['value'])
        self.assertEqual(tool.x_misp_language, language['value'])
        self.assertEqual(tool.x_misp_script, script['value'])
        self.assertEqual(
            tool.x_misp_script_as_attachment['value'],
            script_attachment['value']
        )
        data = script_attachment['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(tool.x_misp_script_as_attachment['data'], data)
        self.assertEqual(tool.x_misp_state, state['value'])

    def _test_event_with_url_indicator_object(self, event):
        attributes, pattern = self._run_indicator_from_object_tests(event)
        _url, _domain, _host, _ip, _port = (attribute['value'] for attribute in attributes)
        url_, domain_, host_, ip_, port_ = pattern[1:-1].split(' AND ')
        self.assertEqual(url_, f"url:value = '{_url}'")
        self.assertEqual(domain_, f"url:x_misp_domain = '{_domain}'")
        self.assertEqual(host_, f"url:x_misp_host = '{_host}'")
        self.assertEqual(ip_, f"url:x_misp_ip = '{_ip}'")
        self.assertEqual(port_, f"url:x_misp_port = '{_port}'")

    def _test_event_with_url_observable_object(self, event):
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        url, domain, host, ip, port = (attribute['value'] for attribute in attributes)
        url_object = observable_objects['0']
        self.assertEqual(url_object.type, 'url')
        self.assertEqual(url_object.value, url)
        self.assertEqual(url_object.x_misp_domain, domain)
        self.assertEqual(url_object.x_misp_host, host)
        self.assertEqual(url_object.x_misp_ip, ip)
        self.assertEqual(url_object.x_misp_port, port)

    def _test_event_with_user_account_indicator_object(self, event):
        attributes, pattern = self._run_indicator_from_object_tests(event)
        _username, _userid, _display_name, _passwd, _group1, _group2, _groupid, _home, user_avatar, _account_type, _plc = attributes
        account_type_, display_name_, userid_, username_, plc_, group1_, group2_, groupid_, home_, passwd_, avatar_data, avatar_value = pattern[1:-1].split(' AND ')
        self.assertEqual(
            account_type_,
            f"user-account:account_type = '{_account_type['value']}'"
        )
        self.assertEqual(
            display_name_,
            f"user-account:display_name = '{_display_name['value']}'"
        )
        self.assertEqual(userid_, f"user-account:user_id = '{_userid['value']}'")
        self.assertEqual(username_, f"user-account:account_login = '{_username['value']}'")
        self.assertEqual(plc_, f"user-account:password_last_changed = '{_plc['value']}'")
        self.assertEqual(
            group1_,
            f"user-account:extensions.'unix-account-ext'.groups = '{_group1['value']}'"
        )
        self.assertEqual(
            group2_,
            f"user-account:extensions.'unix-account-ext'.groups = '{_group2['value']}'"
        )
        self.assertEqual(
            groupid_,
            f"user-account:extensions.'unix-account-ext'.gid = '{_groupid['value']}'"
        )
        self.assertEqual(
            home_,
            f"user-account:extensions.'unix-account-ext'.home_dir = '{_home['value']}'"
        )
        self.assertEqual(passwd_, f"user-account:x_misp_password = '{_passwd['value']}'")
        data = user_avatar['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(
            avatar_data,
            f"user-account:x_misp_user_avatar.data = '{data}'"
        )
        self.assertEqual(
            avatar_value,
            f"user-account:x_misp_user_avatar.value = '{user_avatar['value']}'"
        )

    def _test_event_with_user_account_observable_object(self, event):
        attributes, observable_objects = self._run_observable_from_object_tests(event)
        username, userid, display_name, passwd, group1, group2, groupid, home, user_avatar, account_type, plc = attributes
        user_account = observable_objects['0']
        self.assertEqual(user_account.type, 'user-account')
        self.assertEqual(user_account.user_id, userid['value'])
        self.assertEqual(user_account.account_login, username['value'])
        self.assertEqual(user_account.account_type, account_type['value'])
        self.assertEqual(user_account.display_name, display_name['value'])
        extension = user_account.extensions['unix-account-ext']
        self.assertEqual(extension.gid, int(groupid['value']))
        self.assertEqual(extension.groups, [group1['value'], group2['value']])
        self.assertEqual(extension.home_dir, home['value'])
        self.assertEqual(user_account.x_misp_password, passwd['value'])
        password_last_changed = plc['value']
        if not isinstance(password_last_changed, datetime):
            password_last_changed = self._datetime_from_str(password_last_changed)
        self.assertEqual(
            user_account.password_last_changed.timestamp(),
            password_last_changed.timestamp()
        )
        self.assertEqual(user_account.x_misp_user_avatar['value'], user_avatar['value'])
        data = user_avatar['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(user_account.x_misp_user_avatar['data'], data)

    def _test_event_with_vulnerability_object(self, event):
        orgc = event['Orgc']
        misp_object = deepcopy(event['Object'][0])
        self.parser.parse_misp_event(event)
        identity, report, vulnerability = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event, identity_id, timestamp)[0]
        self._check_object_vulnerability_features(vulnerability, misp_object, identity_id, object_ref)

    def _test_event_with_x509_indicator_object(self, event):
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

    def _test_event_with_x509_observable_object(self, event):
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
        if not isinstance(vnb, datetime):
            vnb = self._datetime_from_str(vnb)
        self.assertEqual(
            x509.validity_not_before.timestamp(),
            vnb.timestamp()
        )
        if not isinstance(vna, datetime):
            vna = self._datetime_from_str(vna)
        self.assertEqual(
            x509.validity_not_after.timestamp(),
            vna.timestamp()
        )
        self.assertEqual(x509.subject, subject)
        self.assertEqual(x509.subject_public_key_algorithm, pia)
        self.assertEqual(x509.subject_public_key_modulus, pim)
        self.assertEqual(x509.subject_public_key_exponent, int(pie))
        self.assertEqual(x509.x_misp_pem, pem)

    def _test_object_references(self, event):
        orgc = event['Orgc']
        ap_object, as_object, btc_object, coa_object, ip_object, person_object, vuln_object = deepcopy(event['Object'])
        self.parser.parse_misp_event(event)
        bundle = self._check_bundle_features(16)
        identity, report, attack_pattern, observed_data, custom, coa, indicator, person, vulnerability, *relationships = bundle.objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event, identity_id, timestamp)
        self.assertEqual(report.published, timestamp)
        ap_ref, observed_data_ref, custom_ref, coa_ref, indicator_ref, person_ref, vuln_ref, *relationship_refs = object_refs
        self._assert_multiple_equal(
            attack_pattern.id,
            ap_ref,
            f"attack-pattern--{ap_object['uuid']}"
        )
        self._assert_multiple_equal(
            observed_data.id,
            observed_data_ref,
            f"observed-data--{as_object['uuid']}"
        )
        self._assert_multiple_equal(
            custom.id,
            custom_ref,
            f"x-misp-object--{btc_object['uuid']}"
        )
        self._assert_multiple_equal(
            coa.id,
            coa_ref,
            f"course-of-action--{coa_object['uuid']}"
        )
        self._assert_multiple_equal(
            indicator.id,
            indicator_ref,
            f"indicator--{ip_object['uuid']}"
        )
        self._assert_multiple_equal(
            person.id,
            person_ref,
            f"identity--{person_object['uuid']}"
        )
        self._assert_multiple_equal(
            vulnerability.id,
            vuln_ref,
            f"vulnerability--{vuln_object['uuid']}"
        )
        for relationship, relationship_ref in zip(relationships, relationship_refs):
            self.assertEqual(relationship.id, relationship_ref)
        relation1, relation2, relation3, relation4, relation5, relation6, relation7 = relationships
        timestamp = ap_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self._check_relationship_features(
            relation1,
            ap_ref,
            indicator_ref,
            'threatens',
            timestamp
        )
        timestamp = as_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self._check_relationship_features(
            relation2,
            observed_data_ref,
            indicator_ref,
            'includes',
            timestamp
        )
        timestamp = btc_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self._check_relationship_features(
            relation3,
            custom_ref,
            indicator_ref,
            'connected-to',
            timestamp
        )
        timestamp = coa_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self._check_relationship_features(
            relation4,
            coa_ref,
            vuln_ref,
            'protects-against',
            timestamp
        )
        timestamp = ip_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self._check_relationship_features(
            relation5,
            indicator_ref,
            coa_ref,
            'protected-with',
            timestamp
        )
        timestamp = person_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self._check_relationship_features(
            relation6,
            person_ref,
            indicator_ref,
            'owns',
            timestamp
        )
        timestamp = vuln_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self._check_relationship_features(
            relation7,
            vuln_ref,
            indicator_ref,
            'affects',
            timestamp
        )


class TestSTIX20JSONObjectsExport(TestSTIX20ObjectsExport):
    def test_embedded_indicator_object_galaxy(self):
        event = get_embedded_indicator_object_galaxy()
        self._test_embedded_indicator_object_galaxy(event['Event'])

    def test_embedded_non_indicator_object_galaxy(self):
        event = get_embedded_non_indicator_object_galaxy()
        self._test_embedded_non_indicator_object_galaxy(event['Event'])

    def test_embedded_object_galaxy_with_multiple_clusters(self):
        event = get_embedded_object_galaxy_with_multiple_clusters()
        self._test_embedded_object_galaxy_with_multiple_clusters(event['Event'])

    def test_embedded_observable_object_galaxy(self):
        event = get_embedded_observable_object_galaxy()
        self._test_embedded_observable_object_galaxy(event['Event'])

    def test_event_with_account_indicator_objects(self):
        event = get_event_with_account_objects()
        misp_objects, patterns = self._run_indicators_from_objects_tests(event['Event'])
        self._check_account_indicator_objects(misp_objects, patterns)
        for misp_object, indicator in zip(misp_objects, self.parser.stix_objects[-2:]):
            self._populate_documentation(misp_object=misp_object, indicator=indicator)

    def test_event_with_account_observable_objects(self):
        event = get_event_with_account_objects()
        misp_objects, observable_objects = self._run_observables_from_objects_tests(event['Event'])
        self._check_account_observable_objects(misp_objects, observable_objects)
        for misp_object, observed_data in zip(misp_objects, self.parser.stix_objects[-2:]):
            self._populate_documentation(misp_object=misp_object, observed_data=observed_data)

    def test_event_with_account_indicator_objects_with_attachment(self):
        event = get_event_with_account_objects_with_attachment()
        misp_objects, patterns = self._run_indicators_from_objects_tests(event['Event'])
        self._check_account_with_attachment_indicator_objects(misp_objects, patterns)
        for misp_object, indicator in zip(misp_objects, self.parser.stix_objects[-5:]):
            self._populate_documentation(misp_object=misp_object, indicator=indicator)

    def test_event_with_account_observable_object_with_attachment(self):
        event = get_event_with_account_objects_with_attachment()
        misp_objects, observable_objects = self._run_observables_from_objects_tests(event['Event'])
        self._check_account_with_attachment_observable_objects(misp_objects, observable_objects)
        for misp_object, observed_data in zip(misp_objects, self.parser.stix_objects[-5:]):
            self._populate_documentation(misp_object=misp_object, observed_data=observed_data)

    def test_event_with_android_app_indicator_object(self):
        event = get_event_with_android_app_object()
        self._test_event_with_android_app_indicator_objet(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_android_app_observable_object(self):
        event = get_event_with_android_app_object()
        self._test_event_with_android_app_observable_objet(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_asn_indicator_object(self):
        event = get_event_with_asn_object()
        self._test_event_with_asn_indicator_objet(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_asn_observable_object(self):
        event = get_event_with_asn_object()
        self._test_event_with_asn_observable_objet(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_attack_pattern_object(self):
        event = get_event_with_attack_pattern_object()
        self._test_event_with_attack_pattern_objet(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            attack_pattern = self.parser.stix_objects[-1]
        )

    def test_event_with_course_of_action_object(self):
        event = get_event_with_course_of_action_object()
        self._test_event_with_course_of_action_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            course_of_action = self.parser.stix_objects[-1]
        )

    def test_event_with_cpe_asset_indicator_object(self):
        event = get_event_with_cpe_asset_object()
        self._test_event_with_cpe_asset_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_cpe_asset_observable_object(self):
        event = get_event_with_cpe_asset_object()
        self._test_event_with_cpe_asset_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_credential_indicator_object(self):
        event = get_event_with_credential_object()
        self._test_event_with_credential_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_credential_observable_object(self):
        event = get_event_with_credential_object()
        self._test_event_with_credential_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_custom_objects(self):
        event = get_event_with_custom_objects()
        self._test_event_with_custom_objects(event['Event'])

    def test_event_with_domain_ip_indicator_object(self):
        event = get_event_with_domain_ip_object_custom()
        self._test_event_with_domain_ip_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_domain_ip_observable_object_custom(self):
        event = get_event_with_domain_ip_object_custom()
        self._test_event_with_domain_ip_observable_object_custom(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_domain_ip_observable_object_standard(self):
        event = get_event_with_domain_ip_object_standard()
        self._test_event_with_domain_ip_observable_object_standard(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_email_indicator_object(self):
        event = get_event_with_email_object()
        self._test_event_with_email_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_email_observable_object(self):
        event = get_event_with_email_object()
        self._test_event_with_email_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_email_indicator_object_with_display_names(self):
        event = get_event_with_email_object_with_display_names()
        self._test_event_with_email_indicator_object_with_display_names(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1],
            name = 'email with display names'
        )

    def test_event_with_email_observable_object_with_display_names(self):
        event = get_event_with_email_object_with_display_names()
        self._test_event_with_email_observable_object_with_display_names(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1],
            name = 'email with display names'
        )

    def test_event_with_employee_object(self):
        event = get_event_with_employee_object()
        self._test_event_with_employee_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            identity = self.parser.stix_objects[-1]
        )

    def test_event_with_file_and_pe_indicator_objects(self):
        event = get_event_with_file_and_pe_objects()
        self._test_event_with_file_and_pe_indicator_objects(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'],
            indicator = self.parser.stix_objects[-1],
            name = 'file with references to pe & pe-section(s)',
            summary = 'File Object with a Windows PE binary extension'
        )

    def test_event_with_file_and_pe_observable_objects(self):
        event = get_event_with_file_and_pe_objects()
        self._test_event_with_file_and_pe_observable_objects(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'],
            observed_data = self.parser.stix_objects[-1],
            name = 'file with references to pe & pe-section(s)'
        )

    def test_event_with_file_indicator_object(self):
        event = get_event_with_file_object_with_artifact()
        self._test_event_with_file_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1],
            summary = 'File Object (potential references to Artifact & Directory Objects)'
        )

    def test_event_with_file_observable_object(self):
        event = get_event_with_file_object_with_artifact()
        self._test_event_with_file_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1],
            summary = 'File Object (potential references to Artifact & Directory Objects)'
        )

    def test_event_with_http_request_indicator_object(self):
        event = get_event_with_http_request_object()
        self._test_event_with_http_request_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_http_request_observable_object(self):
        event = get_event_with_http_request_object()
        self._test_event_with_http_request_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_identity_object(self):
        event = get_event_with_identity_object()
        self._test_event_with_identity_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            identity = self.parser.stix_objects[-1]
        )

    def test_event_with_image_indicator_object(self):
        event = get_event_with_image_object()
        self._test_event_with_image_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_image_observable_object(self):
        event = get_event_with_image_object()
        self._test_event_with_image_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_ip_port_indicator_object(self):
        event = get_event_with_ip_port_object()
        self._test_event_with_ip_port_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_ip_port_observable_object(self):
        event = get_event_with_ip_port_object()
        self._test_event_with_ip_port_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_legal_entity_object(self):
        event = get_event_with_legal_entity_object()
        self._test_event_with_legal_entity_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            identity = self.parser.stix_objects[-1]
        )

    def test_event_with_lnk_indicator_object(self):
        event = get_event_with_lnk_object()
        self._test_event_with_lnk_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_lnk_observable_object(self):
        event = get_event_with_lnk_object()
        self._test_event_with_lnk_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_mutex_indicator_object(self):
        event = get_event_with_mutex_object()
        self._test_event_with_mutex_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_mutex_observable_object(self):
        event = get_event_with_mutex_object()
        self._test_event_with_mutex_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_netflow_indicator_object(self):
        event = get_event_with_netflow_object()
        self._test_event_with_netflow_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_netflow_observable_object(self):
        event = get_event_with_netflow_object()
        self._test_event_with_netflow_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_network_connection_indicator_object(self):
        event = get_event_with_network_connection_object()
        self._test_event_with_network_connection_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1],
            summary = 'Network Traffic, IPv4/IPv6 Address & Domain Name Objects'
        )

    def test_event_with_network_connection_observable_object(self):
        event = get_event_with_network_connection_object()
        self._test_event_with_network_connection_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_network_socket_indicator_object(self):
        event = get_event_with_network_socket_object()
        self._test_event_with_network_socket_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1],
            summary = 'Network Traffic with a socket extension, IPv4/IPv6 Address & Domain Name Objects'
        )

    def test_event_with_network_socket_observable_object(self):
        event = get_event_with_network_socket_object()
        self._test_event_with_network_socket_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_news_agency_object(self):
        event = get_event_with_news_agency_object()
        self._test_event_with_news_agency_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            identity = self.parser.stix_objects[-1]
        )

    def test_event_with_organization_object(self):
        event = get_event_with_organization_object()
        self._test_event_with_organization_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            identity = self.parser.stix_objects[-1]
        )

    def test_event_with_pe_and_section_indicator_objects(self):
        event = get_event_with_pe_objects()
        self._test_event_with_pe_and_section_indicator_objects(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'],
            indicator = self.parser.stix_objects[-1],
            name = 'pe & pe-sections',
            summary = 'Windows PE binary extension within a File Object'
        )

    def test_event_with_pe_and_section_observable_objects(self):
        event = get_event_with_pe_objects()
        self._test_event_with_pe_and_section_observable_objects(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'],
            observed_data = self.parser.stix_objects[-1],
            name = 'pe & pe-sections'
        )

    def test_event_with_person_object(self):
        event = get_event_with_person_object()
        self._test_event_with_person_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            identity = self.parser.stix_objects[-1]
        )

    def test_event_with_process_indicator_object(self):
        event = get_event_with_process_object_v2()
        self._test_event_with_process_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1],
            summary = 'Process Objects (potential reference to File Objects)'
        )

    def test_event_with_process_observable_object(self):
        event = get_event_with_process_object_v2()
        self._test_event_with_process_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_registry_key_indicator_object(self):
        event = get_event_with_registry_key_object()
        self._test_event_with_registry_key_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_registry_key_observable_object(self):
        event = get_event_with_registry_key_object()
        self._test_event_with_registry_key_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_script_objects(self):
        event = get_event_with_script_objects()
        self._test_event_with_script_objects(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            malware = self.parser.stix_objects[-2],
            name = 'Script object where state is "Malicious"'
        )
        self._populate_documentation(
            misp_object = event['Event']['Object'][1],
            tool = self.parser.stix_objects[-1],
            name = 'Script object where state is not "Malicious"'
        )

    def test_event_with_url_indicator_object(self):
        event = get_event_with_url_object()
        self._test_event_with_url_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_url_observable_object(self):
        event = get_event_with_url_object()
        self._test_event_with_url_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_user_account_indicator_object(self):
        event = get_event_with_user_account_object()
        self._test_event_with_user_account_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_user_account_observable_object(self):
        event = get_event_with_user_account_object()
        self._test_event_with_user_account_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_event_with_vulnerability_object(self):
        event = get_event_with_vulnerability_object()
        self._test_event_with_vulnerability_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            vulnerability = self.parser.stix_objects[-1]
        )

    def test_event_with_x509_indicator_object(self):
        event = get_event_with_x509_object()
        self._test_event_with_x509_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_x509_observable_object(self):
        event = get_event_with_x509_object()
        self._test_event_with_x509_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = event['Event']['Object'][0],
            observed_data = self.parser.stix_objects[-1]
        )

    def test_object_references(self):
        event = get_event_with_object_references()
        self._test_object_references(event['Event'])


class TestSTIX20MISPObjectsExport(TestSTIX20ObjectsExport):
    def test_embedded_indicator_object_galaxy(self):
        event = get_embedded_indicator_object_galaxy()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_embedded_indicator_object_galaxy(misp_event)

    def test_embedded_non_indicator_object_galaxy(self):
        event = get_embedded_non_indicator_object_galaxy()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_embedded_non_indicator_object_galaxy(misp_event)

    def test_embedded_object_galaxy_with_multiple_clusters(self):
        event = get_embedded_object_galaxy_with_multiple_clusters()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_embedded_object_galaxy_with_multiple_clusters(misp_event)

    def test_embedded_observable_object_galaxy(self):
        event = get_embedded_observable_object_galaxy()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_embedded_observable_object_galaxy(misp_event)

    def test_event_with_account_indicator_objects(self):
        event = get_event_with_account_objects()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        misp_objects, patterns = self._run_indicators_from_objects_tests(misp_event)
        self._check_account_indicator_objects(misp_objects, patterns)

    def test_event_with_account_observable_objects(self):
        event = get_event_with_account_objects()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        misp_objects, observable_objects = self._run_observables_from_objects_tests(misp_event)
        self._check_account_observable_objects(misp_objects, observable_objects)

    def test_event_with_account_indicator_objects_with_attachment(self):
        event = get_event_with_account_objects_with_attachment()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        misp_objects, patterns = self._run_indicators_from_objects_tests(misp_event)
        self._check_account_with_attachment_indicator_objects(misp_objects, patterns)

    def test_event_with_account_observable_object_with_attachment(self):
        event = get_event_with_account_objects_with_attachment()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        misp_objects, observable_objects = self._run_observables_from_objects_tests(misp_event)
        self._check_account_with_attachment_observable_objects(misp_objects, observable_objects)

    def test_event_with_android_app_indicator_object(self):
        event = get_event_with_android_app_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_android_app_indicator_objet(misp_event)

    def test_event_with_android_app_observable_object(self):
        event = get_event_with_android_app_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_android_app_observable_objet(misp_event)

    def test_event_with_asn_indicator_object(self):
        event = get_event_with_asn_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_asn_indicator_objet(misp_event)

    def test_event_with_asn_observable_object(self):
        event = get_event_with_asn_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_asn_observable_objet(misp_event)

    def test_event_with_attack_pattern_object(self):
        event = get_event_with_attack_pattern_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_attack_pattern_objet(misp_event)

    def test_event_with_course_of_action_object(self):
        event = get_event_with_course_of_action_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_course_of_action_object(misp_event)

    def test_event_with_cpe_asset_indicator_object(self):
        event = get_event_with_cpe_asset_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_cpe_asset_indicator_object(misp_event)

    def test_event_with_cpe_asset_observable_object(self):
        event = get_event_with_cpe_asset_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_cpe_asset_observable_object(misp_event)

    def test_event_with_credential_indicator_object(self):
        event = get_event_with_credential_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_credential_indicator_object(misp_event)

    def test_event_with_credential_observable_object(self):
        event = get_event_with_credential_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_credential_observable_object(misp_event)

    def test_event_with_custom_objects(self):
        event = get_event_with_custom_objects()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_custom_objects(misp_event)

    def test_event_with_domain_ip_indicator_object(self):
        event = get_event_with_domain_ip_object_custom()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_domain_ip_indicator_object(misp_event)

    def test_event_with_domain_ip_observable_object_custom(self):
        event = get_event_with_domain_ip_object_custom()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_domain_ip_observable_object_custom(misp_event)

    def test_event_with_domain_ip_observable_object_standard(self):
        event = get_event_with_domain_ip_object_standard()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_domain_ip_observable_object_standard(misp_event)

    def test_event_with_email_indicator_object(self):
        event = get_event_with_email_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_email_indicator_object(misp_event)

    def test_event_with_email_observable_object(self):
        event = get_event_with_email_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_email_observable_object(misp_event)

    def test_event_with_email_indicator_object_with_display_names(self):
        event = get_event_with_email_object_with_display_names()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_email_indicator_object_with_display_names(misp_event)

    def test_event_with_email_observable_object_with_display_names(self):
        event = get_event_with_email_object_with_display_names()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_email_observable_object_with_display_names(misp_event)

    def test_event_with_employee_object(self):
        event = get_event_with_employee_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_employee_object(misp_event)

    def test_event_with_file_and_pe_indicator_objects(self):
        event = get_event_with_file_and_pe_objects()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_file_and_pe_indicator_objects(misp_event)

    def test_event_with_file_and_pe_observable_objects(self):
        event = get_event_with_file_and_pe_objects()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_file_and_pe_observable_objects(misp_event)

    def test_event_with_file_indicator_object(self):
        event = get_event_with_file_object_with_artifact()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_file_indicator_object(misp_event)

    def test_event_with_file_observable_object(self):
        event = get_event_with_file_object_with_artifact()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_file_observable_object(misp_event)

    def test_event_with_http_request_indicator_object(self):
        event = get_event_with_http_request_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_http_request_indicator_object(misp_event)

    def test_event_with_http_request_observable_object(self):
        event = get_event_with_http_request_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_http_request_observable_object(misp_event)

    def test_event_with_identity_object(self):
        event = get_event_with_identity_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_identity_object(misp_event)

    def test_event_with_image_indicator_object(self):
        event = get_event_with_image_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_image_indicator_object(misp_event)

    def test_event_with_image_observable_object(self):
        event = get_event_with_image_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_image_observable_object(misp_event)

    def test_event_with_ip_port_indicator_object(self):
        event = get_event_with_ip_port_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_ip_port_indicator_object(misp_event)

    def test_event_with_ip_port_observable_object(self):
        event = get_event_with_ip_port_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_ip_port_observable_object(misp_event)

    def test_event_with_legal_entity_object(self):
        event = get_event_with_legal_entity_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_legal_entity_object(misp_event)

    def test_event_with_lnk_indicator_object(self):
        event = get_event_with_lnk_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_lnk_indicator_object(misp_event)

    def test_event_with_lnk_observable_object(self):
        event = get_event_with_lnk_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_lnk_observable_object(misp_event)

    def test_event_with_mutex_indicator_object(self):
        event = get_event_with_mutex_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_mutex_indicator_object(misp_event)

    def test_event_with_mutex_observable_object(self):
        event = get_event_with_mutex_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_mutex_observable_object(misp_event)

    def test_event_with_netflow_indicator_object(self):
        event = get_event_with_netflow_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_netflow_indicator_object(misp_event)

    def test_event_with_netflow_observable_object(self):
        event = get_event_with_netflow_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_netflow_observable_object(misp_event)

    def test_event_with_network_connection_indicator_object(self):
        event = get_event_with_network_connection_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_network_connection_indicator_object(misp_event)

    def test_event_with_network_connection_observable_object(self):
        event = get_event_with_network_connection_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_network_connection_observable_object(misp_event)

    def test_event_with_network_socket_indicator_object(self):
        event = get_event_with_network_socket_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_network_socket_indicator_object(misp_event)

    def test_event_with_network_socket_observable_object(self):
        event = get_event_with_network_socket_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_network_socket_observable_object(misp_event)

    def test_event_with_news_agency_object(self):
        event = get_event_with_news_agency_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_news_agency_object(misp_event)

    def test_event_with_organization_object(self):
        event = get_event_with_organization_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_organization_object(misp_event)

    def test_event_with_pe_and_section_indicator_objects(self):
        event = get_event_with_pe_objects()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_pe_and_section_indicator_objects(misp_event)

    def test_event_with_pe_and_section_observable_objects(self):
        event = get_event_with_pe_objects()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_pe_and_section_observable_objects(misp_event)

    def test_event_with_person_object(self):
        event = get_event_with_person_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_person_object(misp_event)

    def test_event_with_process_indicator_object(self):
        event = get_event_with_process_object_v2()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_process_indicator_object(misp_event)

    def test_event_with_process_observable_object(self):
        event = get_event_with_process_object_v2()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_process_observable_object(misp_event)

    def test_event_with_registry_key_indicator_object(self):
        event = get_event_with_registry_key_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_registry_key_indicator_object(misp_event)

    def test_event_with_registry_key_observable_object(self):
        event = get_event_with_registry_key_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_registry_key_observable_object(misp_event)

    def test_event_with_script_objects(self):
        event = get_event_with_script_objects()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_script_objects(misp_event)

    def test_event_with_url_indicator_object(self):
        event = get_event_with_url_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_url_indicator_object(misp_event)

    def test_event_with_url_observable_object(self):
        event = get_event_with_url_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_url_observable_object(misp_event)

    def test_event_with_user_account_indicator_object(self):
        event = get_event_with_user_account_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_user_account_indicator_object(misp_event)

    def test_event_with_user_account_observable_object(self):
        event = get_event_with_user_account_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_user_account_observable_object(misp_event)

    def test_event_with_vulnerability_object(self):
        event = get_event_with_vulnerability_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_vulnerability_object(misp_event)

    def test_event_with_x509_indicator_object(self):
        event = get_event_with_x509_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_x509_indicator_object(misp_event)

    def test_event_with_x509_observable_object(self):
        event = get_event_with_x509_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_x509_observable_object(misp_event)

    def test_object_references(self):
        event = get_event_with_object_references()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_object_references(misp_event)


class TestSTIX20GalaxiesExport(TestSTIX20GenericExport):
    def _run_galaxy_tests(self, event, timestamp):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        identity, report, stix_object = self.parser.stix_objects
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event, identity_id, timestamp)[0]
        self.assertEqual(report.published, timestamp)
        self.assertEqual(stix_object.id, object_ref)
        return stix_object

    def _test_event_with_attack_pattern_galaxy(self, event):
        galaxy = event['Galaxy'][0]
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        attack_pattern = self._run_galaxy_tests(event, timestamp)
        self.assertEqual(attack_pattern.type, 'attack-pattern')
        self._check_galaxy_features(attack_pattern, galaxy, timestamp)

    def _test_event_with_course_of_action_galaxy(self, event):
        galaxy = event['Galaxy'][0]
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        course_of_action = self._run_galaxy_tests(event, timestamp)
        self.assertEqual(course_of_action.type, 'course-of-action')
        self._check_galaxy_features(course_of_action, galaxy, timestamp)

    def _test_event_with_custom_galaxy(self, event):
        galaxy = event['Galaxy'][0]
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        custom_galaxy = self._run_galaxy_tests(event, timestamp)
        self._check_custom_galaxy_features(custom_galaxy, galaxy, timestamp)

    def _test_event_with_intrusion_set_galaxy(self, event):
        galaxy = event['Galaxy'][0]
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        intrusion_set = self._run_galaxy_tests(event, timestamp)
        self.assertEqual(intrusion_set.type, 'intrusion-set')
        self._check_galaxy_features(intrusion_set, galaxy, timestamp)

    def _test_event_with_malware_galaxy(self, event):
        galaxy = event['Galaxy'][0]
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        malware = self._run_galaxy_tests(event, timestamp)
        self.assertEqual(malware.type, 'malware')
        self._check_galaxy_features(malware, galaxy, timestamp)

    def _test_event_with_sector_galaxy(self, event):
        galaxy = event['Galaxy'][0]
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity = self._run_galaxy_tests(event, timestamp)
        self.assertEqual(identity.type, 'identity')
        self.assertEqual(identity.identity_class, 'class')
        self._check_galaxy_features(identity, galaxy, timestamp)

    def _test_event_with_threat_actor_galaxy(self, event):
        galaxy = event['Galaxy'][0]
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        threat_actor = self._run_galaxy_tests(event, timestamp)
        self.assertEqual(threat_actor.type, 'threat-actor')
        self._check_galaxy_features(threat_actor, galaxy, timestamp)

    def _test_event_with_tool_galaxy(self, event):
        galaxy = event['Galaxy'][0]
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        tool = self._run_galaxy_tests(event, timestamp)
        self.assertEqual(tool.type, 'tool')
        self._check_galaxy_features(tool, galaxy, timestamp)

    def _test_event_with_vulnerability_galaxy(self, event):
        galaxy = event['Galaxy'][0]
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        vulnerability = self._run_galaxy_tests(event, timestamp)
        self.assertEqual(vulnerability.type, 'vulnerability')
        self._check_galaxy_features(vulnerability, galaxy, timestamp)


class TestSTIX20JSONGalaxiesExport(TestSTIX20GalaxiesExport):
    _mapping_types = MISPtoSTIX20Mapping

    def test_event_with_attack_pattern_galaxy(self):
        event = get_event_with_attack_pattern_galaxy()
        self._test_event_with_attack_pattern_galaxy(event['Event'])
        self._populate_documentation(
            galaxy = event['Event']['Galaxy'][0],
            attack_pattern = self.parser.stix_objects[-1],
            summary = ', '.join(
                sorted(self._mapping_types.attack_pattern_types())
            )
        )

    def test_event_with_course_of_action_galaxy(self):
        event = get_event_with_course_of_action_galaxy()
        self._test_event_with_course_of_action_galaxy(event['Event'])
        self._populate_documentation(
            galaxy = event['Event']['Galaxy'][0],
            course_of_action = self.parser.stix_objects[-1],
            summary = ', '.join(
                sorted(self._mapping_types.course_of_action_types())
            )
        )

    def test_event_with_custom_galaxy(self):
        event = get_event_with_custom_galaxy()
        self._test_event_with_custom_galaxy(event['Event'])

    def test_event_with_intrusion_set_galaxy(self):
        event = get_event_with_intrusion_set_galaxy()
        self._test_event_with_intrusion_set_galaxy(event['Event'])
        self._populate_documentation(
            galaxy = event['Event']['Galaxy'][0],
            intrusion_set = self.parser.stix_objects[-1],
            summary = ', '.join(
                sorted(self._mapping_types.intrusion_set_types())
            )
        )

    def test_event_with_malware_galaxy(self):
        event = get_event_with_malware_galaxy()
        self._test_event_with_malware_galaxy(event['Event'])
        self._populate_documentation(
            galaxy = event['Event']['Galaxy'][0],
            malware = self.parser.stix_objects[-1],
            summary = ', '.join(sorted(self._mapping_types.malware_types()))
        )

    def test_event_with_sector_galaxy(self):
        event = get_event_with_sector_galaxy()
        self._test_event_with_sector_galaxy(event['Event'])
        self._populate_documentation(
            galaxy = event['Event']['Galaxy'][0],
            identity = self.parser.stix_objects[-1]
        )

    def test_event_with_threat_actor_galaxy(self):
        event = get_event_with_threat_actor_galaxy()
        self._test_event_with_threat_actor_galaxy(event['Event'])
        self._populate_documentation(
            galaxy = event['Event']['Galaxy'][0],
            threat_actor = self.parser.stix_objects[-1],
            summary = ', '.join(sorted(self._mapping_types.threat_actor_types()))
        )

    def test_event_with_tool_galaxy(self):
        event = get_event_with_tool_galaxy()
        self._test_event_with_tool_galaxy(event['Event'])
        self._populate_documentation(
            galaxy = event['Event']['Galaxy'][0],
            tool = self.parser.stix_objects[-1],
            summary = ', '.join(sorted(self._mapping_types.tool_types()))
        )

    def test_event_with_vulnerability_galaxy(self):
        event = get_event_with_vulnerability_galaxy()
        self._test_event_with_vulnerability_galaxy(event['Event'])
        self._populate_documentation(
            galaxy = event['Event']['Galaxy'][0],
            vulnerability = self.parser.stix_objects[-1],
            summary = ', '.join(sorted(self._mapping_types.vulnerability_types()))
        )


class TestSTIX20MISPGalaxiesExport(TestSTIX20GalaxiesExport):
    def test_event_with_attack_pattern_galaxy(self):
        event = get_event_with_attack_pattern_galaxy()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_attack_pattern_galaxy(misp_event)

    def test_event_with_course_of_action_galaxy(self):
        event = get_event_with_course_of_action_galaxy()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_course_of_action_galaxy(misp_event)

    def test_event_with_custom_galaxy(self):
        event = get_event_with_custom_galaxy()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_custom_galaxy(misp_event)

    def test_event_with_intrusion_set_galaxy(self):
        event = get_event_with_intrusion_set_galaxy()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_intrusion_set_galaxy(misp_event)

    def test_event_with_malware_galaxy(self):
        event = get_event_with_malware_galaxy()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_malware_galaxy(misp_event)

    def test_event_with_threat_actor_galaxy(self):
        event = get_event_with_threat_actor_galaxy()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_threat_actor_galaxy(misp_event)

    def test_event_with_sector_galaxy(self):
        event = get_event_with_sector_galaxy()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_sector_galaxy(misp_event)

    def test_event_with_tool_galaxy(self):
        event = get_event_with_tool_galaxy()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_tool_galaxy(misp_event)

    def test_event_with_vulnerability_galaxy(self):
        event = get_event_with_vulnerability_galaxy()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_vulnerability_galaxy(misp_event)

    def test_attribute_with_attack_pattern_galaxy(self):
        attribute = get_indicator_attribute_with_galaxy()
        misp_attribute = MISPAttribute()
        misp_attribute.from_dict(**attribute)
        self.parser.parse_misp_attributes([misp_attribute])
        self.assertIsNotNone(self.parser.bundle)


class TestSTIX20ExportInteroperability(TestSTIX2Export):
    def setUp(self):
        self.parser = MISPtoSTIX20Parser(interoperability=True)

    def _check_galaxy_object(self, stix_object, name, cluster_value):
        self.assertEqual(stix_object.type, name)
        name, reference = cluster_value.split(' - ')
        self.assertEqual(stix_object.name, name)
        try:
            self.assertEqual(
                stix_object.external_references[0].external_id, reference
            )
        except AssertionError:
            self.assertEqual(stix_object.x_mitre_old_attack_id, reference)

    def _run_galaxy_tests(self, event):
        orgc = event['Orgc']
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self.parser.parse_misp_event(event)
        mitre_identity, identity, report, stix_object = self.parser.stix_objects
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event, identity_id, timestamp)[0]
        self.assertEqual(report.published, timestamp)
        self.assertEqual(stix_object.id, object_ref)
        self.assertEqual(stix_object.created_by_ref, mitre_identity.id)
        return stix_object


class TestSTIX20JSONExportInteroperability(TestSTIX20ExportInteroperability):
    def test_attack_pattern(self):
        event = get_event_with_attack_pattern_galaxy()['Event']
        cluster_value = event['Galaxy'][0]['GalaxyCluster'][0]['value']
        attack_pattern = self._run_galaxy_tests(event)
        self._check_galaxy_object(attack_pattern, 'attack-pattern', cluster_value)

    def test_course_of_action(self):
        event = get_event_with_course_of_action_galaxy()['Event']
        cluster_value = event['Galaxy'][0]['GalaxyCluster'][0]['value']
        course_of_action = self._run_galaxy_tests(event)
        self._check_galaxy_object(course_of_action, 'course-of-action', cluster_value)

    def test_intrusion_set(self):
        event = get_event_with_intrusion_set_galaxy()['Event']
        cluster_value = event['Galaxy'][0]['GalaxyCluster'][0]['value']
        intrusion_set = self._run_galaxy_tests(event)
        self._check_galaxy_object(intrusion_set, 'intrusion-set', cluster_value)

    def test_malware(self):
        event = get_event_with_malware_galaxy()['Event']
        cluster_value = event['Galaxy'][0]['GalaxyCluster'][0]['value']
        malware = self._run_galaxy_tests(event)
        self._check_galaxy_object(malware, 'malware', cluster_value)

    def test_tool(self):
        event = get_event_with_tool_galaxy()['Event']
        cluster_value = event['Galaxy'][0]['GalaxyCluster'][0]['value']
        tool = self._run_galaxy_tests(event)
        self._check_galaxy_object(tool, 'tool', cluster_value)


class TestSTIX20MISPExportInteroperability(TestSTIX20ExportInteroperability):
    def test_attack_pattern(self):
        event = get_event_with_attack_pattern_galaxy()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        attack_pattern = self._run_galaxy_tests(misp_event)
        self._check_galaxy_object(
            attack_pattern,
            'attack-pattern',
            misp_event.galaxies[0]['GalaxyCluster'][0]['value']
        )

    def test_course_of_action(self):
        event = get_event_with_course_of_action_galaxy()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        course_of_action = self._run_galaxy_tests(misp_event)
        self._check_galaxy_object(
            course_of_action,
            'course-of-action',
            misp_event.galaxies[0]['GalaxyCluster'][0]['value']
        )

    def test_intrusion_set(self):
        event = get_event_with_intrusion_set_galaxy()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        intrusion_set = self._run_galaxy_tests(misp_event)
        self._check_galaxy_object(
            intrusion_set,
            'intrusion-set',
            misp_event.galaxies[0]['GalaxyCluster'][0]['value']
        )

    def test_malware(self):
        event = get_event_with_malware_galaxy()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        malware = self._run_galaxy_tests(misp_event)
        self._check_galaxy_object(
            malware,
            'malware',
            misp_event.galaxies[0]['GalaxyCluster'][0]['value']
        )

    def test_tool(self):
        event = get_event_with_tool_galaxy()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        tool = self._run_galaxy_tests(misp_event)
        self._check_galaxy_object(
            tool,
            'tool',
            misp_event.galaxies[0]['GalaxyCluster'][0]['value']
        )


class TestCollectionSTIX20Export(TestCollectionSTIX2Export):
    def test_attributes_collection(self):
        name = 'test_attributes_collection'
        output_file = self._current_path / f'{name}.json.out'
        reference_file = self._current_path / f'{name}_stix20.json'
        input_files = [self._current_path / f'{name}_{n}.json' for n in (1, 2)]
        self.assertEqual(
            misp_collection_to_stix2(
                *input_files, version='2.0', single_output=True,
                output_name=output_file
            ),
            {'success': 1, 'results': [output_file]}
        )
        self._check_stix2_results_export(output_file, reference_file)
        self.assertEqual(
            misp_collection_to_stix2(
                *input_files, version='2.0', in_memory=True,
                single_output=True, output_name=output_file
            ),
            {'success': 1, 'results': [output_file]}
        )
        self._check_stix2_results_export(output_file, reference_file)

    def test_events_collection(self):
        name = 'test_events_collection'
        output_file = self._current_path / f'{name}.json.out'
        reference_file = self._current_path / f'{name}_stix20.json'
        input_files = [self._current_path / f'{name}_{n}.json' for n in (1, 2)]
        self.assertEqual(
            misp_collection_to_stix2(
                *input_files, version='2.0', single_output=True,
                output_name=output_file
            ),
            {'success': 1, 'results': [output_file]}
        )
        self._check_stix2_results_export(output_file, reference_file)
        self.assertEqual(
            misp_collection_to_stix2(
                *input_files, version='2.0', in_memory=True,
                single_output=True, output_name=output_file
            ),
            {'success': 1, 'results': [output_file]}
        )
        self._check_stix2_results_export(output_file, reference_file)
        self.assertEqual(
            misp_collection_to_stix2(*input_files, version='2.0'),
            {
                'success': 1,
                'results': [
                    self._current_path / f'{name}_{n}.json.out' for n in (1, 2)
                ]
            }
        )
        for n in (1, 2):
            self._check_stix2_results_export(
                self._current_path / f'{name}_{n}.json.out',
                self._current_path / f'test_event{n}_stix20.json'
            )


    def test_event_export(self):
        name = 'test_events_collection_1.json'
        filename = self._current_path / name
        output_file = self._current_path / f'{name}.out'
        reference_file = self._current_path / 'test_event1_stix20.json'
        self.assertEqual(
            misp_to_stix2(filename, version='2.0'),
            {'success': 1, 'results': [output_file]}
        )
        self._check_stix2_results_export(output_file, reference_file)
        self.assertEqual(
            misp_collection_to_stix2(
                filename, version='2.0'
            ),
            {'success': 1, 'results': [output_file]}
        )
        self._check_stix2_results_export(output_file, reference_file)


class TestFeedSTIX20Export(TestSTIX2Export):
    def setUp(self):
        self.parser = MISPtoSTIX20Parser()


class TestFeedSTIX20JSONExport(TestFeedSTIX20Export):
    def test_attributes_feed(self):
        attributes = get_attributes_feed()
        for attribute in attributes[:2]:
            self.parser.parse_misp_attribute(attribute)
        bundle = self.parser.bundle
        self.assertEqual(len(bundle.objects), 3)
        identity1, indicator1, indicator2 = bundle.objects
        for attribute in attributes[2:]:
            self.parser.parse_misp_attribute(attribute)
        bundle = self.parser.bundle
        self.assertEqual(len(bundle.objects), 3)
        identity2, indicator3, indicator4 = bundle.objects
        self._assert_multiple_equal(
            f"identity--{attributes[0]['Event']['Orgc']['uuid']}",
            identity1.id,
            identity2.id
        )
        self._assert_multiple_equal(
            attributes[1]['Event']['Orgc']['name'],
            identity1.name,
            identity2.name
        )
        indicators = (indicator1, indicator2, indicator3, indicator4)
        for attribute, indicator in zip(attributes, indicators):
            self.assertEqual(indicator.id, f"indicator--{attribute['Attribute']['uuid']}")


class TestFeedSTIX20MISPExport(TestFeedSTIX20Export):
    def test_attributes_feed(self):
        attributes = get_attributes_feed()
        for attribute in attributes[:2]:
            misp_attribute = MISPAttribute()
            misp_attribute.from_dict(**attribute)
            self.parser.parse_misp_attribute(misp_attribute)
        bundle = self.parser.bundle
        self.assertEqual(len(bundle.objects), 3)
        identity1, indicator1, indicator2 = bundle.objects
        for attribute in attributes[2:]:
            misp_attribute = MISPAttribute()
            misp_attribute.from_dict(**attribute)
            self.parser.parse_misp_attribute(misp_attribute)
        bundle = self.parser.bundle
        self.assertEqual(len(bundle.objects), 3)
        identity2, indicator3, indicator4 = bundle.objects
        self._assert_multiple_equal(
            self.parser._mapping.misp_identity_args()['id'],
            identity1.id,
            identity2.id
        )
        self._assert_multiple_equal(
            self.parser._mapping.misp_identity_args()['name'],
            identity1.name,
            identity2.name
        )
        indicators = (indicator1, indicator2, indicator3, indicator4)
        for attribute, indicator in zip(attributes, indicators):
            self.assertEqual(indicator.id, f"indicator--{attribute['Attribute']['uuid']}")
