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

    def _check_bundle_features(self, length):
        bundle = self.parser.bundle
        self.assertEqual(bundle.type, 'bundle')
        self.assertEqual(bundle.spec_version, '2.0')
        self.assertEqual(len(bundle.objects), length)
        return bundle


class TestSTIX20EventExport(TestSTIX20GenericExport):
    def _check_analyst_note(self, stix_object, misp_layer):
        self.assertEqual(
            stix_object.id, f"x-misp-analyst-note--{misp_layer['uuid']}"
        )
        self.assertEqual(stix_object.x_misp_note, misp_layer['note'])
        self.assertEqual(stix_object.x_misp_author, misp_layer['authors'])
        self.assertEqual(stix_object.x_misp_language, misp_layer['language'])
        self.assertEqual(stix_object.created, misp_layer.created)
        self.assertEqual(
            stix_object.modified,
            self._datetime_from_str(misp_layer['modified'])
        )

    def _check_analyst_opinion(self, stix_object, misp_layer):
        self.assertEqual(
            stix_object.id, f"x-misp-analyst-opinion--{misp_layer['uuid']}"
        )
        self.assertEqual(stix_object.x_misp_opinion, int(misp_layer['opinion']))
        self.assertEqual(stix_object.x_misp_author, misp_layer['authors'])
        self.assertEqual(stix_object.x_misp_comment, misp_layer['comment'])
        self.assertEqual(stix_object.created, misp_layer.created)
        self.assertEqual(
            stix_object.modified,
            self._datetime_from_str(misp_layer['modified'])
        )

    def _check_opinion_features(self, opinion, sighting, *object_ids):
        self.assertEqual(opinion.type, 'x-misp-opinion')
        self.assertEqual(opinion.id, f"x-misp-opinion--{sighting['uuid']}")
        self._assert_multiple_equal(
            opinion.created, opinion.modified,
            self._datetime_from_timestamp(sighting['date_sighting'])
        )
        self.assertEqual(opinion.object_refs, list(object_ids))
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

    def _test_event_with_analyst_data(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        src_attribute, dst_attribute = self.parser._misp_event.attributes
        misp_object = self.parser._misp_event.objects[0]
        event_report = self.parser._misp_event.event_reports[0]
        note = self.parser._misp_event.notes[0]
        bundle = self._check_bundle_features(17)
        identity, report, *stix_objects = bundle.objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event, identity_id, timestamp)
        self.assertEqual(report.published, timestamp)
        for stix_object, object_ref in zip(stix_objects, object_refs):
            self.assertEqual(stix_object.id, object_ref)
        (attr_observed_data, attr_indicator, attr_opinion, observed_data,
         observed_data_note, obj_observed_data, obj_indicator, obj_opinion,
         obj_attr_note, report, report_opinion, attr_relationship,
         relationship, obj_relationship, event_note) = stix_objects
        attr_opinion_od_ref, attr_opinion_ind_ref = attr_opinion.object_refs
        self._assert_multiple_equal(
            attr_observed_data.id, attr_relationship.target_ref,
            relationship.target_ref, attr_opinion_od_ref,
            f'observed-data--{src_attribute.uuid}'
        )
        self._assert_multiple_equal(
            attr_indicator.id, attr_relationship.source_ref,
            attr_opinion_ind_ref, f'indicator--{src_attribute.uuid}'
        )
        self._assert_multiple_equal(
            attr_opinion.type, obj_opinion.type, report_opinion.type,
            'x-misp-analyst-opinion'
        )
        attribute_opinion = src_attribute['Opinion'][0]
        self._check_analyst_opinion(attr_opinion, attribute_opinion)
        self._assert_multiple_equal(
            observed_data.id, observed_data_note.object_refs[0],
            f'observed-data--{dst_attribute.uuid}'
        )
        self._assert_multiple_equal(
            observed_data_note.type, obj_attr_note.type, event_note.type,
            'x-misp-analyst-note'
        )
        attribute_note = dst_attribute['Note'][0]
        self._check_analyst_note(observed_data_note, attribute_note)
        obj_attr_note_od_ref, obj_attr_note_ind_ref = obj_attr_note.object_refs
        obj_opinion_od_ref, obj_opinion_ind_ref = obj_opinion.object_refs
        self._assert_multiple_equal(
            obj_observed_data.id, obj_relationship.target_ref,
            obj_attr_note_od_ref, relationship.source_ref,
            obj_opinion_od_ref, f'observed-data--{misp_object.uuid}'
        )
        self._assert_multiple_equal(
            obj_indicator.id, obj_opinion_ind_ref, obj_attr_note_ind_ref,
            obj_relationship.source_ref, f"indicator--{misp_object['uuid']}"
        )
        object_opinion = misp_object['Opinion'][0]
        self._check_analyst_opinion(obj_opinion, object_opinion)
        object_attribute_note = misp_object['Attribute'][0]['Note'][0]
        self._check_analyst_note(obj_attr_note, object_attribute_note)
        self._assert_multiple_equal(
            report.id, report_opinion.object_refs[0],
            f"x-misp-event-report--{event_report.uuid}"
        )
        self.assertEqual(report.type, 'x-misp-event-report')
        event_report_opinion = event_report.opinions[0]
        self._check_analyst_opinion(report_opinion, event_report_opinion)
        self.assertEqual(relationship.relationship_type, 'downloaded-from')
        self._check_analyst_note(event_note, note)

    def _test_event_with_escaped_characters(self, event):
        initial_attributes = deepcopy(event['Attribute'])
        misp_objects = deepcopy(event['Object'])
        self.parser.parse_misp_event(event)
        attributes = self.parser._misp_event.attributes
        bundle = self._check_bundle_features(98)
        indicators = [obj for obj in bundle.objects if obj.type == 'indicator']
        self._check_event_with_escaped_characters(
            indicators, initial_attributes, attributes, misp_objects
        )

    def _test_event_with_event_report(self, event):
        orgc = event['Orgc']
        event_report = event['EventReport'][0]
        self.parser.parse_misp_event(event)
        bundle = self._check_bundle_features(10)
        identity, report, *stix_objects = bundle.objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event, identity_id, timestamp)
        self.assertEqual(report.published, timestamp)
        for stix_object, object_ref in zip(stix_objects, object_refs):
            self.assertEqual(stix_object.id, object_ref)
        *stix_objects, note, _, _ = stix_objects
        self.assertEqual(note.id, f"x-misp-event-report--{event_report['uuid']}")
        timestamp = event_report['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self._assert_multiple_equal(note.created, note.modified, timestamp)
        self.assertEqual(note.x_misp_content, event_report['content'])
        self.assertEqual(note.x_misp_name, event_report['name'])
        object_refs = note.object_refs
        self.assertEqual(len(object_refs), 5)
        object_ids = {stix_object.id for stix_object in stix_objects}
        self.assertEqual(set(object_refs), object_ids)

    def _test_event_with_sightings(self, event):
        orgc = event['Orgc']
        attribute1, attribute2 = event['Attribute']
        sightings1 = attribute1['Sighting']
        sightings2 = attribute2['Sighting']
        self.parser.parse_misp_event(event)
        (identity, identity1, identity2, identity3, identity4,
         report, *stix_objects) = self.parser.stix_objects
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
        (observed_data1, sighting1, sighting2, opinion1, opinion2,
         observed_data2, indicator, sighting3, opinion3, sighting4,
         opinion4, relationship) = stix_objects
        self._check_sighting_features(
            sighting1, sightings1[0], observed_data1.id, identity1.id
        )
        self._check_sighting_features(
            sighting2, sightings1[1], observed_data1.id, identity2.id
        )
        self._check_opinion_features(opinion1, sightings1[2], observed_data1.id)
        self._check_opinion_features(opinion2, sightings1[3], observed_data1.id
        )
        self._check_sighting_features(
            sighting3, sightings2[0], indicator.id, identity1.id, observed_data2.id
        )
        self._check_opinion_features(opinion3, sightings2[1], observed_data2.id, indicator.id)
        self._check_sighting_features(
            sighting4, sightings2[2], indicator.id, identity3.id, observed_data2.id
        )
        self._check_opinion_features(opinion4, sightings2[3], observed_data2.id, indicator.id)
        self._check_relationship_features(
            relationship, indicator.id, observed_data2.id, 'based-on', timestamp
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

    def test_event_with_analyst_data(self):
        event = get_event_with_analyst_data()
        self._test_event_with_analyst_data(event['Event'])

    def test_event_with_escaped_characters(self):
        event = get_event_with_escaped_values_v20()
        self._test_event_with_escaped_characters(event['Event'])

    def test_event_with_event_report(self):
        event = get_event_with_event_report()
        self._test_event_with_event_report(event['Event'])

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

    def test_event_with_analyst_data(self):
        event = get_event_with_analyst_data()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_analyst_data(misp_event)

    def test_event_with_escaped_characters(self):
        event = get_event_with_escaped_values_v20()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_escaped_characters(misp_event)

    def test_event_with_event_report(self):
        event = get_event_with_event_report()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_event_report(misp_event)

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

    def _check_as_observable_attribute(self, attribute, observed_data):
        observable = observed_data.objects['0']
        self.assertEqual(observable.type, 'autonomous-system')
        self.assertEqual(observable.number, int(attribute.value))

    def _check_attachment_observable_attribute(self, attribute, observed_data):
        file_object, artifact_object = observed_data.objects.values()
        self.assertEqual(file_object.type, 'file')
        self.assertEqual(file_object.name, attribute.value)
        self.assertEqual(file_object.content_ref, '1')
        self.assertEqual(artifact_object.type, 'artifact')
        data = b64encode(attribute.data.getvalue()).decode()
        self.assertEqual(artifact_object.payload_bin, data)

    def _check_domain_ip_observable_attribute(self, attribute, observed_data):
        domain, ip = attribute.value.split('|')
        domain_object, address_object = observed_data.objects.values()
        self.assertEqual(domain_object.type, 'domain-name')
        self.assertEqual(domain_object.value, domain)
        self.assertEqual(domain_object.resolves_to_refs, ['1'])
        self.assertEqual(address_object.type, 'ipv4-addr')
        self.assertEqual(address_object.value, ip)

    def _check_domain_observable_attribute(self, attribute, observed_data):
        observable = observed_data.objects['0']
        self.assertEqual(observable.type, 'domain-name')
        self.assertEqual(observable.value, attribute.value)

    def _check_email_attachment_observable_attribute(self, attribute, observed_data):
        email_object, file_object = observed_data.objects.values()
        self.assertEqual(email_object.type, 'email-message')
        self.assertEqual(email_object.is_multipart, True)
        body = email_object.body_multipart[0]
        self.assertEqual(body.content_disposition, f"attachment; filename='{attribute.value}'")
        self.assertEqual(body.body_raw_ref, '1')
        self.assertEqual(file_object.type, 'file')
        self.assertEqual(file_object.name, attribute.value)

    def _check_email_body_observable_attribute(self, attribute, observed_data):
        email_object = observed_data.objects['0']
        self.assertEqual(email_object.type, 'email-message')
        self.assertEqual(email_object.is_multipart, False)
        self.assertEqual(email_object.body, attribute.value)

    def _check_email_destination_observable_attribute(self, attribute, observed_data):
        message, address = observed_data.objects.values()
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.to_refs, ['1'])
        self._check_email_address(address, attribute.value)

    def _check_email_header_observable_attribute(self, attribute, observed_data):
        message_object = observed_data.objects['0']
        self.assertEqual(message_object.type, 'email-message')
        self.assertEqual(message_object.is_multipart, False)
        self.assertEqual(message_object.received_lines, [attribute.value])

    def _check_email_reply_to_observable_attribute(self, attribute, observed_data):
        message = observed_data.objects['0']
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.additional_header_fields['Reply-To'], attribute.value)

    def _check_email_source_observable_attribute(self, attribute, observed_data):
        message, address = observed_data.objects.values()
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.from_ref, '1')
        self._check_email_address(address, attribute.value)

    def _check_email_subject_observable_attribute(self, attribute, observed_data):
        message = observed_data.objects['0']
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.subject, attribute.value)


    def _check_email_x_mailer_observable_attribute(self, attribute, observed_data):
        message = observed_data.objects['0']
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.additional_header_fields['X-Mailer'], attribute.value)

    def _check_filename_observable_attribute(self, attribute, observed_data):
        observable = observed_data.objects['0']
        self.assertEqual(observable.type, 'file')
        self.assertEqual(observable.name, attribute.value)

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

    def _check_hostname_observable_attribute(self, attribute, observed_data):
        observable = observed_data.objects['0']
        self.assertEqual(observable.type, 'domain-name')
        self.assertEqual(observable.value, attribute.value)

    def _check_hostname_port_observable_attribute(self, attribute, observed_data):
        hostname, port = attribute.value.split('|')
        domain_object, network_traffic_object = observed_data.objects.values()
        self.assertEqual(domain_object.type, 'domain-name')
        self.assertEqual(domain_object.value, hostname)
        self.assertEqual(network_traffic_object.type, 'network-traffic')
        self.assertEqual(network_traffic_object.dst_port, int(port))
        self.assertEqual(network_traffic_object.dst_ref, '0')

    def _check_mac_address_observable_attribute(self, attribute, observed_data):
        observable = observed_data.objects['0']
        self.assertEqual(observable.type, 'mac-addr')
        self.assertEqual(observable.value, attribute.value.lower())

    def _check_malware_sample_observable_attribute(self, attribute, observed_data):
        file_object, artifact_object = observed_data.objects.values()
        filename, hash_value = attribute.value.split('|')
        self.assertEqual(file_object.type, 'file')
        self.assertEqual(file_object.name, filename)
        self.assertEqual(file_object.hashes['MD5'], hash_value)
        self.assertEqual(file_object.content_ref, '1')
        self.assertEqual(artifact_object.type, 'artifact')
        data = b64encode(attribute.data.getvalue()).decode()
        self.assertEqual(artifact_object.payload_bin, data)

    def _check_mutex_observable_attribute(self, attribute, observed_data):
        observable = observed_data.objects['0']
        self.assertEqual(observable.type, 'mutex')
        self.assertEqual(observable.name, attribute.value)

    def _check_regkey_observable_attribute(self, attribute, observed_data):
        observable = observed_data.objects['0']
        self.assertEqual(observable.type, 'windows-registry-key')
        self.assertEqual(observable.key, attribute.value.strip())

    def _check_regkey_value_observable_attribute(self, attribute, observed_data):
        key, value = attribute.value.split('|')
        observable = observed_data.objects['0']
        self.assertEqual(observable.type, 'windows-registry-key')
        self.assertEqual(observable.key, key.strip())
        self.assertEqual(observable['values'][0].data, value.strip())

    def _check_url_observable_attribute(self, attribute, observed_data):
        observable = observed_data.objects['0']
        self.assertEqual(observable.type, 'url')
        self.assertEqual(observable.value, attribute['value'])

    def _check_x509_fingerprint_observable_attribute(self, attribute, observed_data):
        observable_object = observed_data['objects']['0']
        self.assertEqual(observable_object.type, 'x509-certificate')
        hash_type = self.hash_types_mapping(attribute['type'].split('-')[-1])
        self.assertEqual(observable_object.hashes[hash_type], attribute['value'])

    def _run_indicator_tests(self, event, indicator_only=False):
        self._add_attribute_ids_flag(event)
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        attribute = self.parser._misp_event.attributes[0]
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        if indicator_only:
            identity, report, indicator = self.parser.stix_objects
            identity_id = self._check_identity_features(identity, orgc, timestamp)
            object_ref = self._check_report_features(report, event, identity_id, timestamp)[0]
            self._check_attribute_indicator_features(indicator, attribute, identity_id, object_ref)
            return attribute, indicator.pattern
        identity, report, observed_data, indicator, relationship = self.parser.stix_objects
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event, identity_id, timestamp)
        observed_data_ref, indicator_ref, relationship_ref = object_refs
        self.assertEqual(report.published, timestamp)
        self._check_attribute_observable_features(observed_data, attribute, identity_id, observed_data_ref)
        self._check_attribute_indicator_features(indicator, attribute, identity_id, indicator_ref)
        self.assertEqual(relationship.id, relationship_ref)
        self.assertEqual(relationship.relationship_type, 'based-on')
        self.assertEqual(relationship.source_ref, indicator_ref)
        self.assertEqual(relationship.target_ref, observed_data_ref)
        return attribute, observed_data, indicator.pattern

    def _run_indicators_tests(self, event, indicator_only=False):
        self._add_attribute_ids_flag(event)
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        attributes = self.parser._misp_event.attributes
        n_attributes = len(attributes)
        self.assertTrue(n_attributes > 0)
        identity, report, *SDOs = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event, identity_id, timestamp)
        self.assertEqual(report.published, timestamp)
        if indicator_only:
            for attribute, indicator, object_ref in zip(attributes, SDOs, object_refs):
                self._check_attribute_indicator_features(
                    indicator, attribute, identity_id, object_ref
                )
            return attributes, SDOs
        relationships = SDOs[-n_attributes:]
        brol = SDOs[:-n_attributes]
        object_chunks = []
        ref_chunks = []
        indicator_indexes = (i for i, obj in enumerate(brol) if obj['type'] == 'indicator')
        index = 0
        for indicator_index in indicator_indexes:
            object_chunks.append(brol[index:indicator_index + 1])
            ref_chunks.append(object_refs[index:indicator_index + 1])
            index = indicator_index + 1
        for attribute, chunk, object_ref, relationship in zip(attributes, object_chunks, ref_chunks, relationships):
            observed_data, indicator = chunk
            observed_data_ref, indicator_ref = object_ref
            self._check_attribute_indicator_features(indicator, attribute, identity_id, indicator_ref)
            self._check_attribute_observable_features(observed_data, attribute, identity_id, observed_data_ref)
            self.assertEqual(relationship.relationship_type, 'based-on')
            self.assertEqual(relationship.source_ref, indicator_ref)
            self.assertEqual(relationship.target_ref, observed_data_ref)
        return attributes, object_chunks, relationships

    def _run_observable_tests(self, event):
        self._remove_attribute_ids_flag(event)
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        attribute = self.parser._misp_event.attributes[0]
        identity, report, observed_data = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event, identity_id, timestamp)[0]
        self.assertEqual(report.published, timestamp)
        self._check_attribute_observable_features(
            observed_data, attribute, identity_id, object_ref
        )
        return attribute, observed_data

    def _run_observables_tests(self, event):
        self._remove_attribute_ids_flag(event)
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        attributes = self.parser._misp_event.attributes
        identity, report, *observables = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event, identity_id, timestamp)
        self.assertEqual(report.published, timestamp)
        for attribute, observed_data, object_ref in zip(attributes, observables, object_refs):
            self._check_attribute_observable_features(
                observed_data, attribute, identity_id, object_ref
            )
        return attributes, observables

    def _test_embedded_indicator_attribute_galaxy(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        attribute = self.parser._misp_event.attributes[0]
        event_galaxy = self.parser._misp_event.galaxies[0]
        bundle = self._check_bundle_features(12)
        (identity, report, attack_pattern, course_of_action, custom,
         observed_data, indicator, malware, *relationships) = bundle.objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event, identity_id, timestamp)
        self.assertEqual(report.published, timestamp)
        (ap_ref, coa_ref, custom_ref, observed_data_ref, indicator_ref,
         malware_ref, apr_ref, coar_ref, customr_ref, indr_ref) = object_refs
        ap_relationship, coa_relationship, custom_relationship, ind_relationship = relationships
        ap_galaxy, coa_galaxy, custom_galaxy = attribute['Galaxy']
        self._assert_multiple_equal(
            attack_pattern.id, ap_ref,
            f"attack-pattern--{ap_galaxy['GalaxyCluster'][0]['uuid']}"
        )
        self._assert_multiple_equal(
            course_of_action.id, coa_ref,
            f"course-of-action--{coa_galaxy['GalaxyCluster'][0]['uuid']}"
        )
        self._assert_multiple_equal(
            custom.id, custom_ref,
            f"x-misp-galaxy-cluster--{custom_galaxy['GalaxyCluster'][0]['uuid']}"
        )
        self._assert_multiple_equal(
            observed_data.id, observed_data_ref, f'observed-data--{attribute.uuid}'
        )
        self._assert_multiple_equal(
            indicator.id, indicator_ref, f"indicator--{attribute.uuid}"
        )
        self._assert_multiple_equal(
            malware.id, malware_ref,
            f"malware--{event_galaxy['GalaxyCluster'][0]['uuid']}"
        )
        self._assert_multiple_equal(ap_relationship.id, apr_ref)
        self._assert_multiple_equal(coa_relationship.id, coar_ref)
        self.assertEqual(custom_relationship.id, customr_ref)
        self.assertEqual(ind_relationship.id, indr_ref)
        timestamp = attribute['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self._check_relationship_features(
            ap_relationship, observed_data_ref, ap_ref, 'related-to', timestamp
        )
        self._check_relationship_features(
            coa_relationship, observed_data_ref, coa_ref, 'related-to', timestamp
        )
        self._check_relationship_features(
            custom_relationship, observed_data_ref, custom_ref, 'related-to', timestamp
        )
        self._check_relationship_features(
            ind_relationship, indicator_ref, observed_data_ref, 'based-on', timestamp
        )

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
        attribute, observed_data, pattern = self._run_indicator_tests(event)
        self._check_as_observable_attribute(attribute, observed_data)
        self.assertEqual(pattern, f"[autonomous-system:number = '{attribute.value}']")

    def _test_event_with_as_observable_attribute(self, event):
        attribute, observed_data = self._run_observable_tests(event)
        self._check_as_observable_attribute(attribute, observed_data)

    def _test_event_with_attachment_indicator_attribute(self, event):
        attribute, observed_data, pattern = self._run_indicator_tests(event)
        self._check_attachment_observable_attribute(attribute, observed_data)
        file_pattern = f"file:name = '{attribute.value}'"
        data = b64encode(attribute.data.getvalue()).decode()
        data_pattern = f"file:content_ref.payload_bin = '{data}'"
        self.assertEqual(pattern, f"[{file_pattern} AND {data_pattern}]")

    def _test_event_with_attachment_observable_attribute(self, event):
        attribute, observed_data = self._run_observable_tests(event)
        self._check_attachment_observable_attribute(attribute, observed_data)

    def _test_event_with_campaign_name_attribute(self, event):
        self._remove_attribute_ids_flag(event)
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        attribute = self.parser._misp_event.attributes[0]
        identity, report, campaign = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event, identity_id, timestamp)[0]
        self.assertEqual(report.published, timestamp)
        self._check_attribute_campaign_features(
            campaign, attribute, identity_id, object_ref
        )
        self.assertEqual(campaign.name, attribute['value'])

    def _test_event_with_custom_attributes(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        attributes = self.parser._misp_event.attributes
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
        attribute, observed_data, pattern = self._run_indicator_tests(event)
        self._check_domain_observable_attribute(attribute, observed_data)
        self.assertEqual(pattern, f"[domain-name:value = '{attribute.value}']")

    def _test_event_with_domain_ip_indicator_attribute(self, event):
        attribute, observed_data, pattern = self._run_indicator_tests(event)
        self._check_domain_ip_observable_attribute(attribute, observed_data)
        domain, ip = attribute.value.split('|')
        domain_pattern = f"domain-name:value = '{domain}'"
        ip_pattern = f"domain-name:resolves_to_refs[*].value = '{ip}'"
        self.assertEqual(pattern, f'[{domain_pattern} AND {ip_pattern}]')

    def _test_event_with_domain_ip_observable_attribute(self, event):
        attribute, observed_data = self._run_observable_tests(event)
        self._check_domain_ip_observable_attribute(attribute, observed_data)

    def _test_event_with_domain_observable_attribute(self, event):
        attribute, observed_data = self._run_observable_tests(event)
        self._check_domain_observable_attribute(attribute, observed_data)

    def _test_event_with_email_attachment_indicator_attribute(self, event):
        attribute, observed_data, pattern = self._run_indicator_tests(event)
        self._check_email_attachment_observable_attribute(attribute, observed_data)
        self.assertEqual(
            pattern,
            f"[email-message:body_multipart[*].body_raw_ref.name = '{attribute.value}']"
        )

    def _test_event_with_email_attachment_observable_attribute(self, event):
        attribute, observed_data = self._run_observable_tests(event)
        self._check_email_attachment_observable_attribute(attribute, observed_data)

    def _test_event_with_email_body_indicator_attribute(self, event):
        attribute, observed_data, pattern = self._run_indicator_tests(event)
        self._check_email_body_observable_attribute(attribute, observed_data)
        self.assertEqual(
            pattern,
            f"[email-message:body = '{attribute.value}']"
        )

    def _test_event_with_email_body_observable_attribute(self, event):
        attribute, observed_data = self._run_observable_tests(event)
        self._check_email_body_observable_attribute(attribute, observed_data)

    def _test_event_with_email_destination_indicator_attribute(self, event):
        attribute, observed_data, pattern = self._run_indicator_tests(event)
        self._check_email_destination_observable_attribute(attribute, observed_data)
        self.assertEqual(pattern, f"[email-message:to_refs[*].value = '{attribute.value}']")

    def _test_event_with_email_destination_observable_attribute(self, event):
        attribute, observed_data = self._run_observable_tests(event)
        self._check_email_destination_observable_attribute(attribute, observed_data)

    def _test_event_with_email_header_indicator_attribute(self, event):
        attribute, observed_data, pattern = self._run_indicator_tests(event)
        self._check_email_header_observable_attribute(attribute, observed_data)
        self.assertEqual(pattern, f"[email-message:received_lines = '{attribute.value}']")

    def _test_event_with_email_header_observable_attribute(self, event):
        attribute, observed_data = self._run_observable_tests(event)
        self._check_email_header_observable_attribute(attribute, observed_data)

    def _test_event_with_email_indicator_attribute(self, event):
        attribute, observed_data, pattern = self._run_indicator_tests(event)
        self._check_email_address(observed_data.objects['0'], attribute.value)
        self.assertEqual(pattern, f"[email-addr:value = '{attribute.value}']")

    def _test_event_with_email_observable_attribute(self, event):
        attribute, observed_data = self._run_observable_tests(event)
        self._check_email_address(observed_data.objects['0'], attribute.value)

    def _test_event_with_email_reply_to_indicator_attribute(self, event):
        attribute, observed_data, pattern = self._run_indicator_tests(event)
        self._check_email_reply_to_observable_attribute(attribute, observed_data)
        self.assertEqual(
            pattern,
            f"[email-message:additional_header_fields.reply_to = '{attribute.value}']"
        )

    def _test_event_with_email_reply_to_observable_attribute(self, event):
        attribute, observed_data = self._run_observable_tests(event)
        self._check_email_reply_to_observable_attribute(attribute, observed_data)

    def _test_event_with_email_source_indicator_attribute(self, event):
        attribute, observed_data, pattern = self._run_indicator_tests(event)
        self._check_email_source_observable_attribute(attribute, observed_data)
        self.assertEqual(pattern, f"[email-message:from_ref.value = '{attribute.value}']")

    def _test_event_with_email_source_observable_attribute(self, event):
        attribute, observed_data = self._run_observable_tests(event)
        self._check_email_source_observable_attribute(attribute, observed_data)

    def _test_event_with_email_subject_indicator_attribute(self, event):
        attribute, observed_data, pattern = self._run_indicator_tests(event)
        self._check_email_subject_observable_attribute(attribute, observed_data)
        self.assertEqual(pattern, f"[email-message:subject = '{attribute.value}']")

    def _test_event_with_email_subject_observable_attribute(self, event):
        attribute, observed_data = self._run_observable_tests(event)
        self._check_email_subject_observable_attribute(attribute, observed_data)

    def _test_event_with_email_x_mailer_indicator_attribute(self, event):
        attribute, observed_data, pattern = self._run_indicator_tests(event)
        self._check_email_x_mailer_observable_attribute(attribute, observed_data)
        self.assertEqual(
            pattern,
            f"[email-message:additional_header_fields.x_mailer = '{attribute.value}']"
        )

    def _test_event_with_email_x_mailer_observable_attribute(self, event):
        attribute, observed_data = self._run_observable_tests(event)
        self._check_email_x_mailer_observable_attribute(attribute, observed_data)

    def _test_event_with_filename_indicator_attribute(self, event):
        attribute, observed_data, pattern = self._run_indicator_tests(event)
        self._check_filename_observable_attribute(attribute, observed_data)
        self.assertEqual(pattern, f"[file:name = '{attribute.value}']")

    def _test_event_with_filename_observable_attribute(self, event):
        attribute, observed_data = self._run_observable_tests(event)
        self._check_filename_observable_attribute(attribute, observed_data)

    def _test_event_with_github_username_attribute(self, event):
        attribute, pattern = self._run_indicator_tests(event, indicator_only=True)
        self.assertEqual(
            pattern,
            f"[user-account:account_type = 'github' AND user-account:account_login = '{attribute.value}']"
        )

    def _test_event_with_hostname_indicator_attribute(self, event):
        attribute, observed_data, pattern = self._run_indicator_tests(event)
        self._check_hostname_observable_attribute(attribute, observed_data)
        self.assertEqual(pattern, f"[domain-name:value = '{attribute.value}']")

    def _test_event_with_hostname_observable_attribute(self, event):
        attribute, observed_data = self._run_observable_tests(event)
        self._check_hostname_observable_attribute(attribute, observed_data)

    def _test_event_with_hostname_port_indicator_attribute(self, event):
        attribute, observed_data, pattern = self._run_indicator_tests(event)
        self._check_hostname_port_observable_attribute(attribute, observed_data)
        hostname, port = attribute.value.split('|')
        hostname_pattern = f"domain-name:value = '{hostname}'"
        port_pattern = f"network-traffic:dst_port = '{port}'"
        self.assertEqual(pattern, f"[{hostname_pattern} AND {port_pattern}]")

    def _test_event_with_hostname_port_observable_attribute(self, event):
        attribute, observed_data = self._run_observable_tests(event)
        self._check_hostname_port_observable_attribute(attribute, observed_data)

    def _test_event_with_mac_address_indicator_attribute(self, event):
        attribute, observed_data, pattern = self._run_indicator_tests(event)
        self._check_mac_address_observable_attribute(attribute, observed_data)
        self.assertEqual(pattern, f"[mac-addr:value = '{attribute.value}']")

    def _test_event_with_mac_address_observable_attribute(self, event):
        attribute, observed_data = self._run_observable_tests(event)
        self._check_mac_address_observable_attribute(attribute, observed_data)

    def _test_event_with_malware_sample_indicator_attribute(self, event):
        attribute, observed_data, pattern = self._run_indicator_tests(event)
        self._check_malware_sample_observable_attribute(attribute, observed_data)
        filename, hash_value = attribute.value.split('|')
        data_pattern, file_pattern, hash_pattern, mime_type = pattern[1:-1].split(' AND ')
        data = b64encode(attribute.data.getvalue()).decode()
        self.assertEqual(data_pattern, f"file:content_ref.payload_bin = '{data}'")
        self.assertEqual(file_pattern, f"file:name = '{filename}'")
        self.assertEqual(hash_pattern, f"file:hashes.MD5 = '{hash_value}'")
        self.assertEqual(mime_type, f"file:content_ref.mime_type = 'application/zip'")

    def _test_event_with_malware_sample_observable_attribute(self, event):
        attribute, observed_data = self._run_observable_tests(event)
        self._check_malware_sample_observable_attribute(attribute, observed_data)

    def _test_event_with_mutex_indicator_attribute(self, event):
        attribute, observed_data, pattern = self._run_indicator_tests(event)
        self._check_mutex_observable_attribute(attribute, observed_data)
        self.assertEqual(pattern, f"[mutex:name = '{attribute.value}']")

    def _test_event_with_mutex_observable_attribute(self, event):
        attribute, observed_data = self._run_observable_tests(event)
        self._check_mutex_observable_attribute(attribute, observed_data)

    def _test_event_with_port_indicator_attribute(self, event):
        attribute, pattern = self._run_indicator_tests(event, indicator_only=True)
        self.assertEqual(pattern, f"[network-traffic:dst_port = '{attribute.value}']")

    def _test_event_with_regkey_indicator_attribute(self, event):
        attribute, observed_data, pattern = self._run_indicator_tests(event)
        self._check_regkey_observable_attribute(attribute, observed_data)
        self.assertEqual(
            pattern.replace('\\\\', '\\'),
            f"[windows-registry-key:key = '{attribute.value.strip()}']"
        )

    def _test_event_with_regkey_observable_attribute(self, event):
        attribute, observed_data = self._run_observable_tests(event)
        self._check_regkey_observable_attribute(attribute, observed_data)

    def _test_event_with_regkey_value_indicator_attribute(self, event):
        attribute, observed_data, pattern = self._run_indicator_tests(event)
        self._check_regkey_value_observable_attribute(attribute, observed_data)
        key, value = attribute.value.split('|')
        key_pattern = f"windows-registry-key:key = '{self._sanitise_registry_key_value(key)}'"
        value_pattern = f"windows-registry-key:values.data = '{self._sanitise_registry_key_value(value)}'"
        self.assertEqual(pattern, f"[{key_pattern} AND {value_pattern}]")

    def _test_event_with_regkey_value_observable_attribute(self, event):
        attribute, observed_data = self._run_observable_tests(event)
        self._check_regkey_value_observable_attribute(attribute, observed_data)

    def _test_event_with_size_in_bytes_indicator_attribute(self, event):
        attribute, pattern = self._run_indicator_tests(event, indicator_only=True)
        self.assertEqual(pattern, f"[file:size = '{attribute.value}']")

    def _test_event_with_vulnerability_attribute(self, event):
        self._add_attribute_ids_flag(event)
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        attribute = self.parser._misp_event.attributes[0]
        identity, report, vulnerability = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event, identity_id, timestamp)[0]
        self.assertEqual(report.published, timestamp)
        self._check_attribute_vulnerability_features(
            vulnerability, attribute, identity_id, object_ref
        )
        self.assertEqual(vulnerability.name, attribute['value'])
        self._check_external_reference(
            vulnerability.external_references[0], 'cve', attribute['value']
        )


class TestSTIX20JSONAttributesExport(TestSTIX20AttributesExport):
    @classmethod
    def tearDownClass(self):
        attributes_documentation = AttributesDocumentationUpdater(
            'misp_attributes_to_stix20',
            self._attributes_v20,
            'export'
        )
        attributes_documentation.check_export_mapping()

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
            attribute=self.parser._misp_event.attributes[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_as_observable_attribute(self):
        event = get_event_with_as_attribute()
        self._test_event_with_as_observable_attribute(event['Event'])

    def test_event_with_attachment_indicator_attribute(self):
        event = get_event_with_attachment_attribute()
        self._test_event_with_attachment_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute=self.parser._misp_event.attributes[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_attachment_observable_attribute(self):
        event = get_event_with_attachment_attribute()
        self._test_event_with_attachment_observable_attribute(event['Event'])

    def test_event_with_campaign_name_attribute(self):
        event = get_event_with_campaign_name_attribute()
        self._test_event_with_campaign_name_attribute(event['Event'])
        self._populate_documentation(
            attribute=self.parser._misp_event.attributes[0],
            stix=self.parser.stix_objects[-1]
        )

    def test_event_with_custom_attributes(self):
        event = get_event_with_stix2_custom_attributes()
        self._test_event_with_custom_attributes(event['Event'])

    def test_event_with_domain_indicator_attribute(self):
        event = get_event_with_domain_attribute()
        self._test_event_with_domain_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute=self.parser._misp_event.attributes[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_domain_observable_attribute(self):
        event = get_event_with_domain_attribute()
        self._test_event_with_domain_observable_attribute(event['Event'])

    def test_event_with_domain_ip_indicator_attribute(self):
        event = get_event_with_domain_ip_attribute()
        self._test_event_with_domain_ip_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute=self.parser._misp_event.attributes[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_domain_ip_observable_attribute(self):
        event = get_event_with_domain_ip_attribute()
        self._test_event_with_domain_ip_observable_attribute(event['Event'])

    def test_event_with_email_attachment_indicator_attribute(self):
        event = get_event_with_email_attachment_attribute()
        self._test_event_with_email_attachment_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute=self.parser._misp_event.attributes[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_email_attachment_observable_attribute(self):
        event = get_event_with_email_attachment_attribute()
        self._test_event_with_email_attachment_observable_attribute(event['Event'])

    def test_event_with_email_body_indicator_attribute(self):
        event = get_event_with_email_body_attribute()
        self._test_event_with_email_body_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute=self.parser._misp_event.attributes[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_email_body_observable_attribute(self):
        event = get_event_with_email_body_attribute()
        self._test_event_with_email_body_observable_attribute(event['Event'])

    def test_event_with_email_destination_indicator_attribute(self):
        event = get_event_with_email_destination_attribute()
        self._test_event_with_email_destination_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute=self.parser._misp_event.attributes[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_email_destination_observable_attribute(self):
        event = get_event_with_email_destination_attribute()
        self._test_event_with_email_destination_observable_attribute(event['Event'])

    def test_event_with_email_header_indicator_attribute(self):
        event = get_event_with_email_header_attribute()
        self._test_event_with_email_header_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute=self.parser._misp_event.attributes[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_email_header_observable_attribute(self):
        event = get_event_with_email_header_attribute()
        self._test_event_with_email_header_observable_attribute(event['Event'])

    def test_event_with_email_indicator_attribute(self):
        event = get_event_with_email_address_attribute()
        self._test_event_with_email_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute=self.parser._misp_event.attributes[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_email_observable_attribute(self):
        event = get_event_with_email_address_attribute()
        self._test_event_with_email_observable_attribute(event['Event'])

    def test_event_with_email_reply_to_indicator_attribute(self):
        event = get_event_with_email_reply_to_attribute()
        self._test_event_with_email_reply_to_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute=self.parser._misp_event.attributes[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_email_reply_to_observable_attribute(self):
        event = get_event_with_email_reply_to_attribute()
        self._test_event_with_email_reply_to_observable_attribute(event['Event'])

    def test_event_with_email_source_indicator_attribute(self):
        event = get_event_with_email_source_attribute()
        self._test_event_with_email_source_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute=self.parser._misp_event.attributes[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_email_source_observable_attribute(self):
        event = get_event_with_email_source_attribute()
        self._test_event_with_email_source_observable_attribute(event['Event'])

    def test_event_with_email_subject_indicator_attribute(self):
        event = get_event_with_email_subject_attribute()
        self._test_event_with_email_subject_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute=self.parser._misp_event.attributes[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_email_subject_observable_attribute(self):
        event = get_event_with_email_subject_attribute()
        self._test_event_with_email_subject_observable_attribute(event['Event'])

    def test_event_with_email_x_mailer_indicator_attribute(self):
        event = get_event_with_email_x_mailer_attribute()
        self._test_event_with_email_x_mailer_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute=self.parser._misp_event.attributes[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_email_x_mailer_attribute(self):
        event = get_event_with_email_x_mailer_attribute()
        self._test_event_with_email_x_mailer_observable_attribute(event['Event'])

    def test_event_with_filename_indicator_attribute(self):
        event = get_event_with_filename_attribute()
        self._test_event_with_filename_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute=self.parser._misp_event.attributes[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_filename_observable_attribute(self):
        event = get_event_with_filename_attribute()
        self._test_event_with_filename_observable_attribute(event['Event'])

    def test_event_with_github_username_indicator_attribute(self):
        event = get_event_with_github_username_attribute()
        self._test_event_with_github_username_attribute(event['Event'])
        self._populate_documentation(
            attribute=self.parser._misp_event.attributes[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_github_username_observable_attribute(self):
        event = get_event_with_github_username_attribute()
        self._test_event_with_custom_attributes(event['Event'])

    def test_event_with_hash_composite_indicator_attributes(self):
        event = get_event_with_hash_composite_attributes()
        stix_objects = self._run_indicators_tests(event['Event'])
        for attribute, objects, relationship in zip(*stix_objects):
            observed_data, indicator = objects
            self._check_hash_composite_indicator_attribute(attribute, indicator)
            self._check_hash_composite_observable_attribute(attribute, observed_data)
            self._populate_documentation(
                attribute=attribute, stix=[*objects, relationship]
            )

    def test_event_with_hash_composite_observable_attributes(self):
        event = get_event_with_hash_composite_attributes()
        attributes, observables = self._run_observables_tests(event['Event'])
        for attribute, observed_data in zip(attributes, observables):
            self._check_hash_composite_observable_attribute(attribute, observed_data)

    def test_event_with_hash_indicator_attributes(self):
        event = get_event_with_hash_attributes()
        stix_objects = self._run_indicators_tests(event['Event'])
        for attribute, objects, relationship in zip(*stix_objects):
            observed_data, indicator = objects
            self._check_hash_indicator_attribute(attribute, indicator)
            self._check_hash_observable_attribute(attribute, observed_data)
            self._populate_documentation(
                attribute=attribute, stix=[*objects, relationship]
            )

    def test_event_with_hash_observable_attributes(self):
        event = get_event_with_hash_attributes()
        attributes, observables = self._run_observables_tests(event['Event'])
        for attribute, observed_data in zip(attributes, observables):
            self._check_hash_observable_attribute(attribute, observed_data)

    def test_event_with_hostname_indicator_attribute(self):
        event = get_event_with_hostname_attribute()
        self._test_event_with_hostname_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute=self.parser._misp_event.attributes[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_hostname_observable_attribute(self):
        event = get_event_with_hostname_attribute()
        self._test_event_with_hostname_observable_attribute(event['Event'])

    def test_event_with_hostname_port_indicator_attribute(self):
        event = get_event_with_hostname_port_attribute()
        self._test_event_with_hostname_port_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute=self.parser._misp_event.attributes[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_hostname_port_observable_attribute(self):
        event = get_event_with_hostname_port_attribute()
        self._test_event_with_hostname_port_observable_attribute(event['Event'])

    def test_event_with_http_indicator_attributes(self):
        event = get_event_with_http_attributes()
        attributes, indicators = self._run_indicators_tests(event['Event'], indicator_only=True)
        for attribute, indicator, feature in zip(attributes, indicators, self._http_features):
            self.assertEqual(
                indicator.pattern,
                f"[{self._http_prefix}.{feature} = '{attribute['value']}']"
            )
            self._populate_documentation(attribute=attribute, stix=indicator)

    def test_event_with_ip_indicator_attributes(self):
        event = get_event_with_ip_attributes()
        stix_objects = self._run_indicators_tests(event['Event'])
        for attribute, objects, relationship in zip(*stix_objects):
            observed_data, indicator = objects
            self._check_ip_indicator_attribute(attribute, indicator)
            self._check_ip_observable_attribute(attribute, observed_data)
            self._populate_documentation(
                attribute=attribute, stix=[*objects, relationship]
            )

    def test_event_with_ip_observable_attributes(self):
        event = get_event_with_ip_attributes()
        attributes, observables = self._run_observables_tests(event['Event'])
        for attribute, observed_data in zip(attributes, observables):
            self._check_ip_observable_attribute(attribute, observed_data)

    def test_event_with_ip_port_indicator_attributes(self):
        event = get_event_with_ip_port_attributes()
        stix_objects = self._run_indicators_tests(event['Event'])
        for attribute, objects, relationship in zip(*stix_objects):
            observed_data, indicator = objects
            self._check_ip_port_indicator_attribute(attribute, indicator)
            self._check_ip_port_observable_attribute(attribute, observed_data)
            self._populate_documentation(
                attribute=attribute, stix=[*objects, relationship]
            )

    def test_event_with_ip_port_observable_attributes(self):
        event = get_event_with_ip_port_attributes()
        attributes, observables = self._run_observables_tests(event['Event'])
        for attribute, observed_data in zip(attributes, observables):
            self._check_ip_port_observable_attribute(attribute, observed_data)

    def test_event_with_mac_address_indicator_attribute(self):
        event = get_event_with_mac_address_attribute()
        self._test_event_with_mac_address_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute=self.parser._misp_event.attributes[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_mac_address_observable_attribute(self):
        event = get_event_with_mac_address_attribute()
        self._test_event_with_mac_address_observable_attribute(event['Event'])

    def test_event_with_malware_sample_indicator_attribute(self):
        event = get_event_with_malware_sample_attribute()
        self._test_event_with_malware_sample_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute=self.parser._misp_event.attributes[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_malware_sample_observable_attribute(self):
        event = get_event_with_malware_sample_attribute()
        self._test_event_with_malware_sample_observable_attribute(event['Event'])

    def test_event_with_mutex_indicator_attribute(self):
        event = get_event_with_mutex_attribute()
        self._test_event_with_mutex_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute=self.parser._misp_event.attributes[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_mutex_observable_attribute(self):
        event = get_event_with_mutex_attribute()
        self._test_event_with_mutex_observable_attribute(event['Event'])

    def test_event_with_port_indicator_attribute(self):
        event = get_event_with_port_attribute()
        self._test_event_with_port_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute=self.parser._misp_event.attributes[0],
            stix=self.parser.stix_objects[-1]
        )

    def test_event_with_regkey_indicator_attribute(self):
        event = get_event_with_regkey_attribute()
        self._test_event_with_regkey_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute=self.parser._misp_event.attributes[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_regkey_observable_attribute(self):
        event = get_event_with_regkey_attribute()
        self._test_event_with_regkey_observable_attribute(event['Event'])

    def test_event_with_regkey_value_indicator_attribute(self):
        event = get_event_with_regkey_value_attribute()
        self._test_event_with_regkey_value_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute=self.parser._misp_event.attributes[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_regkey_value_observable_attribute(self):
        event = get_event_with_regkey_value_attribute()
        self._test_event_with_regkey_value_observable_attribute(event['Event'])

    def test_event_with_size_in_bytes_indicator_attribute(self):
        event = get_event_with_size_in_bytes_attribute()
        self._test_event_with_size_in_bytes_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute=self.parser._misp_event.attributes[0],
            stix=self.parser.stix_objects[-1]
        )

    def test_event_with_url_indicator_attributes(self):
        event = get_event_with_url_attributes()
        stix_objects = self._run_indicators_tests(event['Event'])
        for attribute, objects, relationship in zip(*stix_objects):
            observed_data, indicator = objects
            self.assertEqual(indicator.pattern, f"[url:value = '{attribute['value']}']")
            self._check_url_observable_attribute(attribute, observed_data)
            self._populate_documentation(
                attribute=attribute, stix=[*objects, relationship]
            )

    def test_event_with_url_observable_attributes(self):
        event = get_event_with_url_attributes()
        attributes, observables = self._run_observables_tests(event['Event'])
        for attribute, observed_data in zip(attributes, observables):
            self._check_url_observable_attribute(attribute, observed_data)

    def test_event_with_vulnerability_attribute(self):
        event = get_event_with_vulnerability_attribute()
        self._test_event_with_vulnerability_attribute(event['Event'])
        self._populate_documentation(
            attribute=self.parser._misp_event.attributes[0],
            stix=self.parser.stix_objects[-1]
        )

    def test_event_with_x509_fingerprint_indicator_attributes(self):
        event = get_event_with_x509_fingerprint_attributes()
        stix_objects = self._run_indicators_tests(event['Event'])
        for attribute, objects, relationshp in zip(*stix_objects):
            observed_data, indicator = objects
            hash_type = attribute['type'].split('-')[-1].upper()
            self.assertEqual(
                indicator.pattern,
                f"[x509-certificate:hashes.{hash_type} = '{attribute['value']}']"
            )
            self._check_x509_fingerprint_observable_attribute(attribute, observed_data)
            self._populate_documentation(
                attribute=attribute, stix=[*objects, relationshp]
            )

    def test_event_with_x509_fingerprint_observable_attributes(self):
        event = get_event_with_x509_fingerprint_attributes()
        attributes, observables = self._run_observables_tests(event['Event'])
        for attribute, observed_data in zip(attributes, observables):
            self._check_x509_fingerprint_observable_attribute(attribute, observed_data)


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
        stix_objects = self._run_indicators_tests(misp_event)
        for attribute, objects, _ in zip(*stix_objects):
            observed_data, indicator = objects
            self._check_hash_composite_observable_attribute(attribute, observed_data)
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
        stix_objects = self._run_indicators_tests(misp_event)
        for attribute, objects, _ in zip(*stix_objects):
            observed_data, indicator = objects
            self._check_hash_observable_attribute(attribute, observed_data)
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
        attributes, indicators = self._run_indicators_tests(misp_event, indicator_only=True)
        for attribute, indicator, feature in zip(attributes, indicators, self._http_features):
            self.assertEqual(
                indicator.pattern,
                f"[{self._http_prefix}.{feature} = '{attribute['value']}']"
            )

    def test_event_with_ip_indicator_attributes(self):
        event = get_event_with_ip_attributes()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        stix_objects = self._run_indicators_tests(misp_event)
        for attribute, objects, _ in zip(*stix_objects):
            observed_data, indicator = objects
            self._check_ip_observable_attribute(attribute, observed_data)
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
        stix_objects = self._run_indicators_tests(misp_event)
        for attribute, objects, _ in zip(*stix_objects):
            observed_data, indicator = objects
            self._check_ip_port_observable_attribute(attribute, observed_data)
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
        stix_objects = self._run_indicators_tests(misp_event)
        for attribute, objects, _ in zip(*stix_objects):
            observed_data, indicator = objects
            self._check_url_observable_attribute(attribute, observed_data)
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
        stix_objects = self._run_indicators_tests(misp_event)
        for attribute, objects, _ in zip(*stix_objects):
            observed_data, indicator = objects
            hash_type = attribute['type'].split('-')[-1].upper()
            self._check_x509_fingerprint_observable_attribute(attribute, observed_data)
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
    def _check_account_observable_objects(self, misp_objects, observable_objects):
        gitlab_object, telegram_object = misp_objects
        gitlab, telegram = observable_objects
        gitlab_id, name, username = (attribute['value'] for attribute in gitlab_object['Attribute'])
        gitlab = gitlab.objects['0']
        self.assertEqual(gitlab.type, 'user-account')
        self.assertEqual(gitlab.account_type, 'gitlab')
        self.assertEqual(gitlab.user_id, gitlab_id)
        self.assertEqual(gitlab.display_name, name)
        self.assertEqual(gitlab.account_login, username)
        telegram_id, username, phone1, phone2 = (attribute['value'] for attribute in telegram_object['Attribute'])
        telegram = telegram.objects['0']
        self.assertEqual(telegram.type, 'user-account')
        self.assertEqual(telegram.account_type, 'telegram')
        self.assertEqual(telegram.user_id, telegram_id)
        self.assertEqual(telegram.account_login, username)
        self.assertEqual(telegram.x_misp_phone, [phone1, phone2])

    def _check_account_with_attachment_observable_objects(self, misp_objects, observable_objects):
        facebook_account, github_user, parler_account, reddit_account, twitter_account = misp_objects
        facebook, github, parler, reddit, twitter = observable_objects
        account_id, account_name, link, avatar = facebook_account['Attribute']
        facebook = facebook.objects['0']
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
        github = github.objects['0']
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
        parler = parler.objects['0']
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
        reddit = reddit.objects['0']
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
        twitter = twitter.objects['0']
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

    def _check_android_app_observable_object(self, misp_object, observed_data):
        software = observed_data.objects['0']
        name, certificate, domain = (attribute.value for attribute in misp_object.attributes)
        self.assertEqual(software.type, 'software')
        self.assertEqual(software.name, name)
        self.assertEqual(software.x_misp_certificate, certificate)
        self.assertEqual(software.x_misp_domain, domain)

    def _check_asn_observable_object(self, misp_object, observed_data):
        asn, description, subnet1, subnet2 = (
            attribute.value for attribute in misp_object.attributes
        )
        autonomous_system = observed_data.objects['0']
        self.assertEqual(autonomous_system.type, 'autonomous-system')
        self.assertEqual(autonomous_system.number, int(asn))
        self.assertEqual(autonomous_system.name, description)
        self.assertEqual(
            autonomous_system.x_misp_subnet_announced, [subnet1, subnet2]
        )

    def _check_cpe_asset_observable_object(self, misp_object, observed_data):
        software = observed_data.objects['0']
        cpe, language, product, vendor, version, description = (
            attribute.value for attribute in misp_object.attributes
        )
        self.assertEqual(software.type, 'software')
        self.assertEqual(software.cpe, cpe)
        self.assertEqual(software.name, product)
        self.assertEqual(software.languages, [language])
        self.assertEqual(software.vendor, vendor)
        self.assertEqual(software.version, version)
        self.assertEqual(software.x_misp_description, description)

    def _check_credential_observable_object(self, misp_object, observed_data):
        user_account = observed_data.objects['0']
        text, username, *attributes = misp_object.attributes
        attributes.insert(0, text)
        self.assertEqual(user_account.type, 'user-account')
        self.assertEqual(user_account.user_id, username.value)
        for attribute in attributes:
            self.assertEqual(
                getattr(user_account, f'x_misp_{attribute.object_relation}'),
                attribute.value
            )

    def _check_domain_ip_observable_object(self, misp_object, observed_data):
        _domain, hostname, _ip, port = (
            attribute.value for attribute in misp_object.attributes
        )
        domain_ = observed_data.objects['0']
        self.assertEqual(domain_.type, 'domain-name')
        self.assertEqual(domain_.value, _domain)
        self.assertEqual(domain_.x_misp_hostname, hostname)
        self.assertEqual(domain_.x_misp_port, port)
        self.assertEqual(domain_.resolves_to_refs, ['1'])
        ip_ = observed_data.objects['1']
        self.assertEqual(ip_.type, 'ipv4-addr')
        self.assertEqual(ip_.value, _ip)

    def _check_email_observable_object(self, misp_object, observed_data):
        (_from, _from_dn, _to, _to_dn, _cc1, _cc1_dn, _cc2, _cc2_dn, _bcc,
         _bcc_dn, _reply_to, _subject, _attachment1, _attachment2, _x_mailer,
         _user_agent, _boundary, _message_id) = (
            attribute.value for attribute in misp_object.attributes
        )
        message = observed_data.objects['0']
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
        self._check_email_address(observed_data.objects['1'], _from, display_name=_from_dn)
        self._check_email_address(observed_data.objects['2'], _to, display_name=_to_dn)
        self._check_email_address(observed_data.objects['3'], _cc1, display_name=_cc1_dn)
        self._check_email_address(observed_data.objects['4'], _cc2, display_name=_cc2_dn)
        self._check_email_address(observed_data.objects['5'], _bcc, display_name=_bcc_dn)
        file1 = observed_data.objects['6']
        self.assertEqual(file1.type, 'file')
        self.assertEqual(file1.name, _attachment1)
        file2 = observed_data.objects['7']
        self.assertEqual(file2.type, 'file')
        self.assertEqual(file2.name, _attachment2)

    def _check_email_with_display_names_observable_object(self, misp_object, observed_data):
        _from, _from_name, _to, _to_name, _cc1, _cc2_name, _bcc, _bcc_name = (
            attribute.value for attribute in misp_object.attributes
        )
        message = observed_data.objects['0']
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.from_ref, '1')
        self.assertEqual(message.to_refs, ['2'])
        self.assertEqual(message.cc_refs, ['3'])
        self.assertEqual(message.bcc_refs, ['4'])
        self._check_email_address(observed_data.objects['1'], _from, display_name=_from_name)
        self._check_email_address(observed_data.objects['2'], _to, display_name=_to_name)
        self._check_email_address(observed_data.objects['3'], _cc1)
        self.assertEqual(message.x_misp_cc_display_name, _cc2_name)
        self._check_email_address(observed_data.objects['4'], _bcc, display_name=_bcc_name)

    def _check_file_and_pe_observable_objects(self, observed_data, *misp_objects):
        _file, pe, section = misp_objects
        filename, md5, sha1, sha256, size, entropy = (
            attribute.value for attribute in _file.attributes
        )
        file_object = observed_data.objects['0']
        self.assertEqual(file_object.type, 'file')
        self.assertEqual(file_object.name, filename)
        hashes = file_object.hashes
        self.assertEqual(hashes['MD5'], md5)
        self.assertEqual(hashes['SHA-1'], sha1)
        self.assertEqual(hashes['SHA-256'], sha256)
        self.assertEqual(file_object.size, int(size))
        self.assertEqual(file_object.x_misp_entropy, entropy)
        self._check_pe_and_section_observable(
            file_object.extensions['windows-pebinary-ext'], pe, section
        )

    def _check_file_observable_object(self, misp_object, observed_data):
        (_malware_sample, _filename, _md5, _sha1, _sha256, _size, _attachment,
         _path, _encoding, ctime, mtime) = misp_object.attributes
        _file = observed_data.objects['0']
        self.assertEqual(_file.type, 'file')
        self.assertEqual(_file.size, int(_size.value))
        self.assertEqual(_file.name, _filename.value)
        self.assertEqual(_file.name_enc, _encoding.value)
        creation = ctime.value
        if isinstance(creation, str):
            creation = self._datetime_from_str(creation)
        self.assertEqual(_file.created, creation)
        modification = mtime.value
        if isinstance(modification, str):
            modification = self._datetime_from_str(modification)
        self.assertEqual(_file.modified, modification)
        hashes = _file.hashes
        self.assertEqual(hashes['MD5'], _md5.value)
        self.assertEqual(hashes['SHA-1'], _sha1.value)
        self.assertEqual(hashes['SHA-256'], _sha256.value)
        self.assertEqual(_file.x_misp_attachment['value'], _attachment.value)
        data = _attachment.data
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(_file.x_misp_attachment['data'], data)
        self.assertEqual(_file.parent_directory_ref, '1')
        self.assertEqual(_file.content_ref, '2')
        directory = observed_data.objects['1']
        self.assertEqual(directory.type, 'directory')
        self.assertEqual(directory.path, _path.value)
        artifact = observed_data.objects['2']
        self.assertEqual(artifact.type, 'artifact')
        data = _malware_sample.data
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(artifact.payload_bin, data)
        filename, md5 = _malware_sample.value.split('|')
        self.assertEqual(artifact.hashes['MD5'], md5)
        self.assertEqual(artifact.x_misp_filename, filename)

    def _check_http_request_observable_object(self, misp_object, observed_data):
        ip_src, ip_dst, host, method, user_agent, uri, url, content = (
            attribute.value for attribute in misp_object.attributes
        )
        network_traffic = observed_data.objects['0']
        self.assertEqual(network_traffic.type, 'network-traffic')
        extension = network_traffic.extensions['http-request-ext']
        self.assertEqual(extension.request_method, method)
        self.assertEqual(extension.request_value, uri)
        self.assertEqual(extension.request_header['Content-Type'], content)
        self.assertEqual(extension.request_header['User-Agent'], user_agent)
        self.assertEqual(network_traffic.x_misp_url, url)
        self.assertEqual(network_traffic.src_ref, '1')
        self.assertEqual(network_traffic.dst_ref, '2')
        src_address = observed_data.objects['1']
        self.assertEqual(src_address.type, 'ipv4-addr')
        self.assertEqual(src_address.value, ip_src)
        dst_address = observed_data.objects['2']
        self.assertEqual(dst_address.type, 'ipv4-addr')
        self.assertEqual(dst_address.value, ip_dst)
        domain_name = observed_data.objects['3']
        self.assertEqual(domain_name.type, 'domain-name')
        self.assertEqual(domain_name.value, host)
        self.assertEqual(domain_name.resolves_to_refs, ['2'])

    def _check_image_observable_object(self, misp_object, observed_data):
        attachment, filename, url, text = misp_object.attributes
        _file = observed_data.objects['0']
        self.assertEqual(_file.type, 'file')
        self.assertEqual(_file.name, filename.value)
        self.assertEqual(_file.content_ref, '1')
        self.assertEqual(_file.x_misp_image_text, text.value)
        artifact = observed_data.objects['1']
        self.assertEqual(artifact.type, 'artifact')
        data = attachment.data
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(artifact.payload_bin, data)
        self.assertEqual(artifact.mime_type, 'image/png')
        self.assertEqual(artifact.x_misp_url, url.value)
        self.assertEqual(artifact.x_misp_filename, attachment.value)

    def _check_ip_port_observable_object(self, misp_object, observed_data):
        ip, port, domain, first_seen = (
            attribute.value for attribute in misp_object.attributes
        )
        network_traffic = observed_data.objects['0']
        self.assertEqual(network_traffic.type, 'network-traffic')
        self.assertEqual(network_traffic.dst_port, int(port))
        timestamp = first_seen
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_str(timestamp)
        self.assertEqual(network_traffic.start, timestamp)
        self.assertIn('ipv4', network_traffic.protocols)
        self.assertEqual(network_traffic.dst_ref, '1')
        self.assertEqual(network_traffic.x_misp_domain, domain)
        address_object = observed_data.objects['1']
        self.assertEqual(address_object.type, 'ipv4-addr')
        self.assertEqual(address_object.value, ip)

    def _check_lnk_observable_object(self, misp_object, observed_data):
        (filename, fullpath, md5, sha1, sha256, malware_sample, size_in_bytes,
         creation, modification, access) = misp_object.attributes
        file = observed_data.objects['0']
        self.assertEqual(file.type, 'file')
        self.assertEqual(file.name, filename.value)
        self.assertEqual(file.hashes['MD5'], md5.value)
        self.assertEqual(file.hashes['SHA-1'], sha1.value)
        self.assertEqual(file.hashes['SHA-256'], sha256.value)
        self.assertEqual(file.size, int(size_in_bytes.value))
        directory = observed_data.objects['1']
        self.assertEqual(directory.type, 'directory')
        self.assertEqual(directory.path, fullpath.value)
        self.assertEqual(file.parent_directory_ref, '1')
        artifact = observed_data.objects['2']
        self.assertEqual(artifact.type, 'artifact')
        data = malware_sample.data
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(artifact.payload_bin, data)
        self.assertEqual(artifact.mime_type, 'application/zip')
        filename, md5 = malware_sample.value.split('|')
        self.assertEqual(artifact.x_misp_filename, filename)
        self.assertEqual(artifact.hashes['MD5'], md5)
        self.assertEqual(file.content_ref, '2')
        creation_value = creation.value
        if isinstance(creation_value, str):
            creation_value = self._datetime_from_str(creation_value)
        self.assertEqual(file.created, creation_value)
        modification_value = modification.value
        if isinstance(modification_value, str):
            modification_value = self._datetime_from_str(modification_value)
        self.assertEqual(file.modified, modification_value)
        access_value = access.value
        if isinstance(access_value, str):
            access_value = self._datetime_from_str(access_value)
        self.assertEqual(file.accessed, access_value)

    def _check_mutex_observable_object(self, misp_object, observed_data):
        name, description, _os = (attribute['value'] for attribute in misp_object.attributes)
        mutex = observed_data.objects['0']
        self.assertEqual(mutex.type, 'mutex')
        self.assertEqual(mutex.name, name)
        self.assertEqual(mutex.x_misp_description, description)
        self.assertEqual(mutex.x_misp_operating_system, _os)

    def _check_netflow_observable_object(self, misp_object, observed_data):
        (ip_src, ip_dst, src_as, dst_as, src_port, dst_port, protocol, first_seen,
         tcp_flags) = (attribute['value'] for attribute in misp_object.attributes)
        network_traffic = observed_data.objects['0']
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
        src_address = observed_data.objects['1']
        dst_address = observed_data.objects['3']
        self._assert_multiple_equal(src_address.type, dst_address.type, 'ipv4-addr')
        src_autonomous_system = observed_data.objects['2']
        dst_autonomous_system = observed_data.objects['4']
        self._assert_multiple_equal(
            src_autonomous_system.type, dst_autonomous_system.type, 'autonomous-system'
        )
        self.assertEqual(src_address.value, ip_src)
        self.assertEqual(src_address.belongs_to_refs, ['2'])
        self.assertEqual(src_autonomous_system.number, self._parse_AS_value(src_as))
        self.assertEqual(dst_address.value, ip_dst)
        self.assertEqual(dst_address.belongs_to_refs, ['4'])
        self.assertEqual(dst_autonomous_system.number, self._parse_AS_value(dst_as))

    def _check_network_connection_observable_object(self, misp_object, observed_data):
        (ip_src, ip_dst, src_port, dst_port, hostname, layer3, layer4,
         layer7) = (attribute['value'] for attribute in misp_object.attributes)
        network_traffic = observed_data.objects['0']
        self.assertEqual(network_traffic.type, 'network-traffic')
        self.assertEqual(network_traffic.src_port, int(src_port))
        self.assertEqual(network_traffic.dst_port, int(dst_port))
        self.assertEqual(
            network_traffic.protocols,
            [layer3.lower(), layer4.lower(), layer7.lower()]
        )
        self.assertEqual(network_traffic.src_ref, '1')
        self.assertEqual(network_traffic.dst_ref, '2')
        self.assertEqual(network_traffic.x_misp_hostname_dst, hostname)
        address1 = observed_data.objects['1']
        self.assertEqual(address1.type, 'ipv4-addr')
        self.assertEqual(address1.value, ip_src)
        address2 = observed_data.objects['2']
        self.assertEqual(address2.type, 'ipv4-addr')
        self.assertEqual(address2.value, ip_dst)

    def _check_network_socket_observable_object(self, misp_object, observed_data):
        (ip_src, ip_dst, src_port, dst_port, hostname, address_family,
         domain_family, socket_type, state, protocol) = (
            attribute['value'] for attribute in misp_object.attributes
        )
        network_traffic = observed_data.objects['0']
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
        address1 = observed_data.objects['1']
        self.assertEqual(address1.type, 'ipv4-addr')
        self.assertEqual(address1.value, ip_src)
        address2 = observed_data.objects['2']
        self.assertEqual(address2.type, 'ipv4-addr')
        self.assertEqual(address2.value, ip_dst)

    def _check_process_observable_object(self, misp_object, observed_data):
        (pid, child_pid, parent_pid, name, image, parent_image, port, _, command_line,
         parent_name) = (attribute['value'] for attribute in misp_object.attributes)
        process = observed_data.objects['0']
        self.assertEqual(process.type, 'process')
        self.assertEqual(process.pid, int(pid))
        self.assertEqual(process.name, name)
        self.assertEqual(process.is_hidden, True)
        self.assertEqual(process.x_misp_port, port)
        self.assertEqual(process.parent_ref, '1')
        self.assertEqual(process.child_refs, ['3'])
        self.assertEqual(process.binary_ref, '4')
        parent_process = observed_data.objects['1']
        self.assertEqual(parent_process.type, 'process')
        self.assertEqual(parent_process.pid, int(parent_pid))
        self.assertEqual(parent_process.command_line, command_line)
        self.assertEqual(parent_process.name, parent_name)
        self.assertEqual(parent_process.binary_ref, '2')
        parent_image_object = observed_data.objects['2']
        self.assertEqual(parent_image_object.type, 'file')
        self.assertEqual(parent_image_object.name, parent_image)
        child_process = observed_data.objects['3']
        self.assertEqual(child_process.type, 'process')
        self.assertEqual(child_process.pid, int(child_pid))
        image_object = observed_data.objects['4']
        self.assertEqual(image_object.type, 'file')
        self.assertEqual(image_object.name, image)

    def _check_registry_key_observable_object(self, misp_object, observed_data):
        key, hive, name, data, data_type, last_modified = (
            attribute['value'] for attribute in misp_object.attributes
        )
        registry_key = observed_data.objects['0']
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

    def _check_url_observable_object(self, misp_object, observed_data):
        url, domain, host, ip, port = (attribute['value'] for attribute in misp_object.attributes)
        url_object = observed_data.objects['0']
        self.assertEqual(url_object.type, 'url')
        self.assertEqual(url_object.value, url)
        self.assertEqual(url_object.x_misp_domain, domain)
        self.assertEqual(url_object.x_misp_host, host)
        self.assertEqual(url_object.x_misp_ip, ip)
        self.assertEqual(url_object.x_misp_port, port)

    def _check_user_account_observable_object(self, misp_object, observed_data):
        (username, userid, display_name, passwd, group1, group2, groupid, home,
         user_avatar, account_type, plc) = misp_object.attributes
        user_account = observed_data.objects['0']
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

    def _check_x509_observable_object(self, misp_object, observed_data):
        (issuer, pem, pia, pie, pim, srlnmbr, signalg, subject, vnb, vna, version,
         md5, sha1) = (attribute['value'] for attribute in misp_object.attributes)
        x509 = observed_data.objects['0']
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
        self.assertEqual(x509.validity_not_before.timestamp(), vnb.timestamp())
        if not isinstance(vna, datetime):
            vna = self._datetime_from_str(vna)
        self.assertEqual(x509.validity_not_after.timestamp(), vna.timestamp())
        self.assertEqual(x509.subject, subject)
        self.assertEqual(x509.subject_public_key_algorithm, pia)
        self.assertEqual(x509.subject_public_key_modulus, pim)
        self.assertEqual(x509.subject_public_key_exponent, int(pie))
        self.assertEqual(x509.x_misp_pem, pem)

    def _run_indicators_from_objects_tests(self, event):
        self._add_object_ids_flag(event)
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_objects = self.parser._misp_event.objects
        n_objects = len(misp_objects)
        identity, report, *SDOs = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event, identity_id, timestamp)
        self.assertEqual(report.published, timestamp)
        relationships = SDOs[-n_objects:]
        brol = SDOs[:-n_objects]
        object_chunks = []
        ref_chunks = []
        indicator_indexes = (i for i, obj in enumerate(brol) if obj['type'] == 'indicator')
        index = 0
        for indicator_index in indicator_indexes:
            object_chunks.append(brol[index:indicator_index + 1])
            ref_chunks.append(object_refs[index:indicator_index + 1])
            index = indicator_index + 1
        for misp_object, chunk, object_ref, relationship in zip(misp_objects, object_chunks, ref_chunks, relationships):
            observed_data, indicator = chunk
            observed_data_ref, indicator_ref = object_ref
            self._check_object_indicator_features(indicator, misp_object, identity_id, indicator_ref)
            self._check_object_observable_features(
                observed_data, misp_object, identity_id, observed_data_ref
            )
            self.assertEqual(relationship.relationship_type, 'based-on')
            self.assertEqual(relationship.source_ref, indicator_ref)
            self.assertEqual(relationship.target_ref, observed_data_ref)
        return misp_objects, object_chunks, relationships

    def _run_indicator_from_objects_tests(self, event):
        self._add_object_ids_flag(event)
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_objects = self.parser._misp_event.objects
        identity, report, observed_data, indicator, relationship = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event, identity_id, timestamp)
        observed_data_ref, indicator_ref, relationship_ref = object_refs
        self.assertEqual(report.published, timestamp)
        self._check_object_observable_features(
            observed_data, misp_objects[0], identity_id, observed_data_ref
        )
        self._check_object_indicator_features(
            indicator, misp_objects[0], identity_id, indicator_ref
        )
        self.assertEqual(relationship.id, relationship_ref)
        self.assertEqual(relationship.relationship_type, 'based-on')
        self.assertEqual(relationship.source_ref, indicator_ref)
        self.assertEqual(relationship.target_ref, observed_data_ref)
        return misp_objects, observed_data, indicator.pattern

    def _run_indicator_from_object_tests(self, event):
        self._add_object_ids_flag(event)
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_object = self.parser._misp_event.objects[0]
        identity, report, observed_data, indicator, relationship = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event, identity_id, timestamp)
        observed_data_ref, indicator_ref, relationship_ref = object_refs
        self.assertEqual(report.published, timestamp)
        self._check_object_observable_features(
            observed_data, misp_object, identity_id, observed_data_ref
        )
        self._check_object_indicator_features(
            indicator, misp_object, identity_id, indicator_ref
        )
        self.assertEqual(relationship.id, relationship_ref)
        self.assertEqual(relationship.relationship_type, 'based-on')
        self.assertEqual(relationship.source_ref, indicator_ref)
        self.assertEqual(relationship.target_ref, observed_data_ref)
        return misp_object, observed_data, indicator.pattern

    def _run_observables_from_objects_tests(self, event):
        self._remove_object_ids_flags(event)
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_objects = self.parser._misp_event.objects
        identity, report, *od_objects = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event, identity_id, timestamp)
        self.assertEqual(report.published, timestamp)
        for observed_data, misp_object, object_ref in zip(od_objects, misp_objects, object_refs):
            self._check_object_observable_features(
                observed_data, misp_object, identity_id, object_ref
            )
        return misp_objects, od_objects

    def _run_observable_from_objects_tests(self, event):
        self._remove_object_ids_flags(event)
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_objects = self.parser._misp_event.objects
        identity, report, observed_data = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event, identity_id, timestamp)[0]
        self.assertEqual(report.published, timestamp)
        self._check_object_observable_features(
            observed_data, misp_objects[0], identity_id, object_ref
        )
        return misp_objects, observed_data

    def _run_observable_from_object_tests(self, event):
        self._remove_object_ids_flags(event)
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_object = self.parser._misp_event.objects[0]
        identity, report, observed_data = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event, identity_id, timestamp)[0]
        self.assertEqual(report.published, timestamp)
        self._check_object_observable_features(
            observed_data, misp_object, identity_id, object_ref
        )
        return misp_object, observed_data

    def _test_embedded_indicator_object_galaxy(self, event):
        self._add_object_ids_flag(event)
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_object = self.parser._misp_event.objects[0]
        tool_galaxy, event_coa_galaxy, event_custom_galaxy = self.parser._misp_event.galaxies
        bundle = self._check_bundle_features(12)
        identity, report, malware, coa, custom, observed_data, indicator, tool, *relationships = bundle.objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event, identity_id, timestamp)
        self.assertEqual(report.published, timestamp)
        (malware_ref, coa_ref, custom_ref, observed_data_ref, indicator_ref,
         tool_ref, mr_ref, coar_ref, customr_ref, indr_ref) = object_refs
        malware_relationship, coa_relationship, custom_relationship, indicator_relationship = relationships
        malware_galaxy = misp_object['Attribute'][0]['Galaxy'][0]
        coa_galaxy = misp_object['Attribute'][1]['Galaxy'][0]
        custom_galaxy = misp_object['Attribute'][2]['Galaxy'][0]
        self._assert_multiple_equal(
            malware.id, malware_ref,
            f"malware--{malware_galaxy['GalaxyCluster'][0]['uuid']}"
        )
        self._assert_multiple_equal(
            coa.id, coa_ref,
            f"course-of-action--{event_coa_galaxy['GalaxyCluster'][0]['uuid']}",
            f"course-of-action--{coa_galaxy['GalaxyCluster'][0]['uuid']}"
        )
        self._assert_multiple_equal(
            custom.id, custom_ref,
            f"x-misp-galaxy-cluster--{event_custom_galaxy['GalaxyCluster'][0]['uuid']}",
            f"x-misp-galaxy-cluster--{custom_galaxy['GalaxyCluster'][0]['uuid']}"
        )
        self._assert_multiple_equal(
            indicator.id, indicator_ref, f"indicator--{misp_object['uuid']}"
        )
        self._assert_multiple_equal(
            tool.id, tool_ref, f"tool--{tool_galaxy['GalaxyCluster'][0]['uuid']}"
        )
        self.assertEqual(malware_relationship.id, mr_ref)
        self.assertEqual(coa_relationship.id, coar_ref)
        self.assertEqual(custom_relationship.id, customr_ref)
        self.assertEqual(indicator_relationship.id, indr_ref)
        timestamp = misp_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self._check_relationship_features(malware_relationship, observed_data_ref, malware_ref, 'related-to', timestamp)
        self._check_relationship_features(coa_relationship, observed_data_ref, coa_ref, 'related-to', timestamp)
        self._check_relationship_features(custom_relationship, observed_data_ref, custom_ref, 'related-to', timestamp)
        self._check_relationship_features(indicator_relationship, indicator_ref, observed_data_ref, 'based-on', timestamp)

    def _test_embedded_non_indicator_object_galaxy(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        coa_object, vulnerability_object = self.parser._misp_event.objects
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
        self.parser.parse_misp_event(event)
        misp_object = self.parser._misp_event.objects[0]
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
        self.parser.parse_misp_event(event)
        misp_object = self.parser._misp_event.objects[0]
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
        misp_object, observed_data, pattern = self._run_indicator_from_object_tests(event)
        self._check_android_app_observable_object(misp_object, observed_data)
        name, certificate, domain = (attribute.value for attribute in misp_object.attributes)
        name_pattern, cert_pattern, domain_pattern = pattern[1:-1].split(' AND ')
        self.assertEqual(name_pattern, f"software:name = '{name}'")
        self.assertEqual(cert_pattern, f"software:x_misp_certificate = '{certificate}'")
        self.assertEqual(domain_pattern, f"software:x_misp_domain = '{domain}'")

    def _test_event_with_android_app_observable_objet(self, event):
        misp_object, observed_data = self._run_observable_from_object_tests(event)
        self._check_android_app_observable_object(misp_object, observed_data)

    def _test_event_with_asn_indicator_objet(self, event):
        misp_object, observed_data, pattern = self._run_indicator_from_object_tests(event)
        self._check_asn_observable_object(misp_object, observed_data)
        asn = misp_object.attributes[0].value
        asn_pattern = pattern[1:-1]
        self.assertEqual(asn_pattern, f"autonomous-system:number = '{int(asn)}'")

    def _test_event_with_asn_observable_objet(self, event):
        misp_object, observed_data = self._run_observable_from_object_tests(event)
        self._check_asn_observable_object(misp_object, observed_data)

    def _test_event_with_attack_pattern_objet(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_object = self.parser._misp_event.objects[0]
        identity, report, attack_pattern = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event, identity_id, timestamp)[0]
        self.assertEqual(report.published, timestamp)
        self._assert_multiple_equal(
            attack_pattern.id, object_ref, f"attack-pattern--{misp_object['uuid']}",
        )
        self._check_attack_pattern_object(attack_pattern, misp_object, identity_id)

    def _test_event_with_course_of_action_object(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_object = self.parser._misp_event.objects[0]
        identity, report, course_of_action = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event, identity_id, timestamp)[0]
        self.assertEqual(report.published, timestamp)
        self._assert_multiple_equal(
            course_of_action.id, object_ref, f"course-of-action--{misp_object['uuid']}",
        )
        self._check_course_of_action_object(course_of_action, misp_object, identity_id)

    def _test_event_with_cpe_asset_indicator_object(self, event):
        misp_object, observed_data, pattern = self._run_indicator_from_object_tests(event)
        self._check_cpe_asset_observable_object(misp_object, observed_data)
        cpe = misp_object.attributes[0].value
        cpe_pattern = pattern[1:-1]
        self.assertEqual(cpe_pattern, f"software:cpe = '{cpe}'")

    def _test_event_with_cpe_asset_observable_object(self, event):
        misp_object, observed_data = self._run_observable_from_object_tests(event)
        self._check_cpe_asset_observable_object(misp_object, observed_data)

    def _test_event_with_credential_indicator_object(self, event):
        misp_object, observed_data, pattern = self._run_indicator_from_object_tests(event)
        self._check_credential_observable_object(misp_object, observed_data)
        text = misp_object.attributes[0]
        text_pattern = pattern[1:-1]
        self.assertEqual(
            text_pattern,
            f"user-account:x_misp_{text.object_relation} = '{text.value}'"
        )

    def _test_event_with_credential_observable_object(self, event):
        misp_object, observed_data = self._run_observable_from_object_tests(event)
        self._check_credential_observable_object(misp_object, observed_data)

    def _test_event_with_custom_objects(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_objects = self.parser._misp_event.objects
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
        misp_object, observed_data, pattern = self._run_indicator_from_object_tests(event)
        self._check_domain_ip_observable_object(misp_object, observed_data)
        _domain, _hostname, _ip, _ = (attribute.value for attribute in misp_object.attributes)
        domain_, hostname_, ip_ = pattern[1:-1].split(' AND ')
        self.assertEqual(domain_, f"domain-name:value = '{_domain}'")
        self.assertEqual(hostname_, f"domain-name:x_misp_hostname = '{_hostname}'")
        self.assertEqual(ip_, f"domain-name:resolves_to_refs[*].value = '{_ip}'")

    def _test_event_with_domain_ip_observable_object_custom(self, event):
        misp_object, observed_data = self._run_observable_from_object_tests(event)
        self._check_domain_ip_observable_object(misp_object, observed_data)

    def _test_event_with_domain_ip_observable_object_standard(self, event):
        misp_object, observed_data = self._run_observable_from_object_tests(event)
        _domain1, _domain2, _ip1, _ip2 = (
            attribute.value for attribute in misp_object.attributes
        )
        ip1_ = observed_data.objects['0']
        self.assertEqual(ip1_.type, 'ipv4-addr')
        self.assertEqual(ip1_.value, _ip1)
        ip2_ = observed_data.objects['1']
        self.assertEqual(ip2_.type, 'ipv4-addr')
        self.assertEqual(ip2_.value, _ip2)
        domain1_ = observed_data.objects['2']
        self.assertEqual(domain1_.type, 'domain-name')
        self.assertEqual(domain1_.value, _domain1)
        self.assertEqual(domain1_.resolves_to_refs, ['0', '1'])
        domain2_ = observed_data.objects['3']
        self.assertEqual(domain2_.type, 'domain-name')
        self.assertEqual(domain2_.value, _domain2)
        self.assertEqual(domain2_.resolves_to_refs, ['0', '1'])

    def _test_event_with_email_indicator_object(self, event):
        misp_object, observed_data, pattern = self._run_indicator_from_object_tests(event)
        self._check_email_observable_object(misp_object, observed_data)
        (_from, _, _to, _, _cc1, _, _cc2, _, _bcc, _, _, _, _attachment1,
         _attachment2, *_) = (attribute.value for attribute in misp_object.attributes)
        (to_, cc1_, cc2_, bcc_, from_, attachment1_, content1,
         attachment2_, content2) = pattern[1:-1].split(' AND ')
        self.assertEqual(from_, f"email-message:from_ref.value = '{_from}'")
        self.assertEqual(to_, f"email-message:to_refs[0].value = '{_to}'")
        self.assertEqual(cc1_, f"email-message:cc_refs[0].value = '{_cc1}'")
        self.assertEqual(cc2_, f"email-message:cc_refs[1].value = '{_cc2}'")
        self.assertEqual(bcc_, f"email-message:bcc_refs[0].value = '{_bcc}'")
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

    def _test_event_with_email_observable_object(self, event):
        misp_object, observed_data = self._run_observable_from_object_tests(event)
        self._check_email_observable_object(misp_object, observed_data)

    def _test_event_with_email_with_display_names_indicator_object(self, event):
        misp_object, observed_data, pattern = self._run_indicator_from_object_tests(event)
        self._check_email_with_display_names_observable_object(misp_object, observed_data)
        _from, _, _to, _, _cc, _, _bcc, _ = (
            attribute.value for attribute in misp_object.attributes
        )
        to_, cc_, bcc_, from_ = pattern[1:-1].split(' AND ')
        self.assertEqual(to_, f"email-message:to_refs[0].value = '{_to}'")
        self.assertEqual(cc_, f"email-message:cc_refs[0].value = '{_cc}'")
        self.assertEqual(bcc_, f"email-message:bcc_refs[0].value = '{_bcc}'")
        self.assertEqual(from_, f"email-message:from_ref.value = '{_from}'")

    def _test_event_with_email_with_display_names_observable_object(self, event):
        misp_object, observed_data = self._run_observable_from_object_tests(event)
        self._check_email_with_display_names_observable_object(misp_object, observed_data)

    def _test_event_with_employee_object(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_object = self.parser._misp_event.objects[0]
        identity, report, employee = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event, identity_id, timestamp)[0]
        employee_type = self._check_employee_object(
            employee, misp_object, object_ref, identity_id
        )
        self.assertEqual(employee.x_misp_employee_type, employee_type)

    def _test_event_with_file_and_pe_indicator_objects(self, event):
        misp_objects, observed_data, pattern = self._run_indicator_from_objects_tests(event)
        self._check_file_and_pe_observable_objects(observed_data, *misp_objects)
        _file, pe, section = misp_objects
        _filename, _md5, _sha1, _sha256, *_ = (
            attribute.value for attribute in _file.attributes
        )
        pattern = pattern[1:-1].split(' AND ')
        md5_, sha1_, sha256_, name_ = pattern[:4]
        self.assertEqual(md5_, f"file:hashes.MD5 = '{_md5}'")
        self.assertEqual(sha1_, f"file:hashes.SHA1 = '{_sha1}'")
        self.assertEqual(sha256_, f"file:hashes.SHA256 = '{_sha256}'")
        self.assertEqual(name_, f"file:name = '{_filename}'")
        self._check_pe_and_section_pattern(pattern[4:], pe, section)

    def _test_event_with_file_and_pe_observable_objects(self, event):
        misp_objects, observed_data = self._run_observable_from_objects_tests(event)
        self._check_file_and_pe_observable_objects(observed_data, *misp_objects)

    def _test_event_with_file_indicator_object(self, event):
        misp_object, observed_data, pattern = self._run_indicator_from_object_tests(event)
        self._check_file_observable_object(misp_object, observed_data)
        _malware_sample, _filename, _md5, _sha1, _sha256, *_ = misp_object.attributes
        md5_, sha1_, sha256_, filename_, malware_sample_ = self._reassemble_pattern(pattern[1:-1])
        self.assertEqual(md5_, f"file:hashes.MD5 = '{_md5.value}'")
        self.assertEqual(sha1_, f"file:hashes.SHA1 = '{_sha1.value}'")
        self.assertEqual(sha256_, f"file:hashes.SHA256 = '{_sha256.value}'")
        self.assertEqual(filename_, f"file:name = '{_filename.value}'")
        ms_data, ms_filename, ms_md5, mime_type = malware_sample_.split(' AND ')
        data = _malware_sample.data
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(ms_data, f"(file:content_ref.payload_bin = '{data}'")
        filename, md5 = _malware_sample.value.split('|')
        self.assertEqual(ms_filename, f"file:content_ref.x_misp_filename = '{filename}'")
        self.assertEqual(ms_md5, f"file:content_ref.hashes.MD5 = '{md5}'")
        self.assertEqual(mime_type, f"file:content_ref.mime_type = 'application/zip')")

    def _test_event_with_file_observable_object(self, event):
        misp_object, observed_data = self._run_observable_from_object_tests(event)
        self._check_file_observable_object(misp_object, observed_data)

    def _test_event_with_http_request_indicator_object(self, event):
        misp_object, observed_data, pattern = self._run_indicator_from_object_tests(event)
        self._check_http_request_observable_object(misp_object, observed_data)
        ip_src, ip_dst, host, _, _, uri, url, _ = (
            attribute.value for attribute in misp_object.attributes
        )
        (src_type, src_value, dst_type, dst_value, host_type, host_value,
         req_value1, req_value2, *_) = pattern[1:-1].split(' AND ')
        prefix = 'network-traffic'
        self.assertEqual(src_type, f"({prefix}:src_ref.type = 'ipv4-addr'")
        self.assertEqual(src_value, f"{prefix}:src_ref.value = '{ip_src}')")
        self.assertEqual(dst_type, f"({prefix}:dst_ref.type = 'ipv4-addr'")
        self.assertEqual(dst_value, f"{prefix}:dst_ref.value = '{ip_dst}')")
        self.assertEqual(host_type, f"({prefix}:dst_ref.type = 'domain-name'")
        self.assertEqual(host_value, f"{prefix}:dst_ref.value = '{host}')")
        feature = "extensions.'http-request-ext'"
        self.assertEqual(req_value1, f"{prefix}:{feature}.request_value = '{uri}'")
        self.assertEqual(req_value2, f"{prefix}:{feature}.request_value = '{url}'")

    def _test_event_with_http_request_observable_object(self, event):
        misp_object, observed_data = self._run_observable_from_object_tests(event)
        self._check_http_request_observable_object(misp_object, observed_data)

    def _test_event_with_identity_object(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_object = self.parser._misp_event.objects[0]
        created_by_ref_identity, report, identity = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(created_by_ref_identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event, identity_id, timestamp)[0]
        self.assertEqual(identity.type, 'identity')
        self._assert_multiple_equal(
            identity.id, object_ref, f"identity--{misp_object['uuid']}"
        )
        self.assertEqual(identity.created_by_ref, identity_id)
        name, contact_information, description, identity_class, roles = (
            attribute.value for attribute in misp_object.attributes
        )
        self.assertEqual(identity.name, name)
        self.assertEqual(identity.contact_information, contact_information)
        self.assertEqual(identity.description, description)
        self.assertEqual(identity.identity_class, identity_class)
        self.assertEqual(identity.x_misp_roles, roles)

    def _test_event_with_image_indicator_object(self, event):
        misp_object, observed_data, pattern = self._run_indicator_from_object_tests(event)
        self._check_image_observable_object(misp_object, observed_data)
        attachment, filename, url, _ = misp_object.attributes
        name, payload_bin, mime_type, name_ref, url_pattern = pattern[1:-1].split(' AND ')
        self.assertEqual(name, f"file:name = '{filename.value}'")
        data = attachment.data
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(payload_bin, f"file:content_ref.payload_bin = '{data}'")
        self.assertEqual(mime_type, f"file:content_ref.mime_type = 'image/png'")
        self.assertEqual(name_ref, f"file:content_ref.x_misp_filename = '{attachment.value}'")
        self.assertEqual(url_pattern, f"file:content_ref.url = '{url.value}'")

    def _test_event_with_image_observable_object(self, event):
        misp_object, observed_data = self._run_observable_from_object_tests(event)
        self._check_image_observable_object(misp_object, observed_data)

    def _test_event_with_intrusion_set_object(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_object = self.parser._misp_event.objects[0]
        identity, report, intrusion_set = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event, identity_id, timestamp)[0]
        self.assertEqual(report.published, timestamp)
        self._assert_multiple_equal(
            intrusion_set.id, object_ref, f"intrusion-set--{misp_object['uuid']}"
        )
        self._check_intrusion_set_object(intrusion_set, misp_object, identity_id)

    def _test_event_with_ip_port_indicator_object(self, event):
        misp_object, observed_data, pattern = self._run_indicator_from_object_tests(event)
        self._check_ip_port_observable_object(misp_object, observed_data)
        ip, _, domain, _ = (attribute['value'] for attribute in misp_object['Attribute'])
        ip_type, ip_value, domain_type, domain_value = pattern[1:-1].split(' AND ')
        prefix = 'network-traffic'
        self.assertEqual(ip_type, f"({prefix}:dst_ref.type = 'ipv4-addr'")
        self.assertEqual(ip_value, f"{prefix}:dst_ref.value = '{ip}')")
        self.assertEqual(domain_type, f"({prefix}:dst_ref.type = 'domain-name'")
        self.assertEqual(domain_value, f"{prefix}:dst_ref.value = '{domain}')")

    def _test_event_with_ip_port_observable_object(self, event):
        misp_object, observed_data = self._run_observable_from_object_tests(event)
        self._check_ip_port_observable_object(misp_object, observed_data)

    def _test_event_with_legal_entity_object(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_object = self.parser._misp_event.objects[0]
        identity, report, legal_entity = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event, identity_id, timestamp)[0]
        self._check_legal_entity_object_features(
            legal_entity, misp_object, object_ref, identity_id
        )

    def _test_event_with_lnk_indicator_object(self, event):
        misp_object, observed_data, pattern = self._run_indicator_from_object_tests(event)
        self._check_lnk_observable_object(misp_object, observed_data)
        filename, _, md5, sha1, sha256, malware_sample, *_ = misp_object.attributes
        name, md5_pattern, sha1_pattern, sha256_pattern, artifact = self._reassemble_pattern(pattern[1:-1])
        self.assertEqual(name, f"file:name = '{filename.value}'")
        self.assertEqual(md5_pattern, f"file:hashes.MD5 = '{md5.value}'")
        self.assertEqual(sha1_pattern, f"file:hashes.SHA1 = '{sha1.value}'")
        self.assertEqual(sha256_pattern, f"file:hashes.SHA256 = '{sha256.value}'")
        ms_data, ms_filename, ms_md5, mime_type = artifact.split(' AND ')
        data = malware_sample.data
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(ms_data, f"(file:content_ref.payload_bin = '{data}'")
        filename, md5 = malware_sample.value.split('|')
        self.assertEqual(ms_filename, f"file:content_ref.x_misp_filename = '{filename}'")
        self.assertEqual(ms_md5, f"file:content_ref.hashes.MD5 = '{md5}'")
        self.assertEqual(mime_type, f"file:content_ref.mime_type = 'application/zip')")

    def _test_event_with_lnk_observable_object(self, event):
        misp_object, observed_data = self._run_observable_from_object_tests(event)
        self._check_lnk_observable_object(misp_object, observed_data)

    def _test_event_with_mutex_indicator_object(self, event):
        misp_object, observed_data, pattern = self._run_indicator_from_object_tests(event)
        self._check_mutex_observable_object(misp_object, observed_data)
        _name = misp_object.attributes[0]['value']
        name_ = pattern[1:-1]
        self.assertEqual(name_, f"mutex:name = '{_name}'")

    def _test_event_with_mutex_observable_object(self, event):
        misp_object, observed_data = self._run_observable_from_object_tests(event)
        self._check_mutex_observable_object(misp_object, observed_data)

    def _test_event_with_netflow_indicator_object(self, event):
        misp_object, observed_data, pattern = self._run_indicator_from_object_tests(event)
        self._check_netflow_observable_object(misp_object, observed_data)
        ip_src, ip_dst, *_ = (attribute['value'] for attribute in misp_object.attributes)
        src_type, src_value, dst_type, dst_value = pattern[1:-1].split(' AND ')
        prefix = 'network-traffic'
        self.assertEqual(src_type, f"({prefix}:src_ref.type = 'ipv4-addr'")
        self.assertEqual(src_value, f"{prefix}:src_ref.value = '{ip_src}')")
        self.assertEqual(dst_type, f"({prefix}:dst_ref.type = 'ipv4-addr'")
        self.assertEqual(dst_value, f"{prefix}:dst_ref.value = '{ip_dst}')")

    def _test_event_with_netflow_observable_object(self, event):
       misp_object, observed_data = self._run_observable_from_object_tests(event)
       self._check_netflow_observable_object(misp_object, observed_data)

    def _test_event_with_network_connection_indicator_object(self, event):
        misp_object, observed_data, pattern = self._run_indicator_from_object_tests(event)
        self._check_network_connection_observable_object(misp_object, observed_data)
        _ip_src, _ip_dst, _, _, _hostname, *_ = (
            attribute['value'] for attribute in misp_object['Attribute']
        )
        ip_src_, ip_dst_, hostname_ = self._reassemble_pattern(pattern[1:-1])
        ip_src_type, ip_src_value = ip_src_.split(' AND ')
        self.assertEqual(ip_src_type, "(network-traffic:src_ref.type = 'ipv4-addr'")
        self.assertEqual(ip_src_value, f"network-traffic:src_ref.value = '{_ip_src}')")
        ip_dst_type, ip_dst_value = ip_dst_.split(' AND ')
        self.assertEqual(ip_dst_type, "(network-traffic:dst_ref.type = 'ipv4-addr'")
        self.assertEqual(ip_dst_value, f"network-traffic:dst_ref.value = '{_ip_dst}')")
        hostname_type, hostname_value = hostname_.split(' AND ')
        self.assertEqual(hostname_type, "(network-traffic:dst_ref.type = 'domain-name'")
        self.assertEqual(hostname_value, f"network-traffic:dst_ref.value = '{_hostname}')")

    def _test_event_with_network_connection_observable_object(self, event):
        misp_object, observed_data = self._run_observable_from_object_tests(event)
        self._check_network_connection_observable_object(misp_object, observed_data)

    def _test_event_with_network_socket_indicator_object(self, event):
        misp_object, observed_data, pattern = self._run_indicator_from_object_tests(event)
        self._check_network_socket_observable_object(misp_object, observed_data)
        _ip_src, _ip_dst, _, _, _hostname, *_ = (
            attribute['value'] for attribute in misp_object['Attribute']
        )
        ip_src_, ip_dst_, hostname_ = self._reassemble_pattern(pattern[1:-1])
        ip_src_type, ip_src_value = ip_src_.split(' AND ')
        self.assertEqual(ip_src_type, "(network-traffic:src_ref.type = 'ipv4-addr'")
        self.assertEqual(ip_src_value, f"network-traffic:src_ref.value = '{_ip_src}')")
        ip_dst_type, ip_dst_value = ip_dst_.split(' AND ')
        self.assertEqual(ip_dst_type, "(network-traffic:dst_ref.type = 'ipv4-addr'")
        self.assertEqual(ip_dst_value, f"network-traffic:dst_ref.value = '{_ip_dst}')")
        hostname_type, hostname_value = hostname_.split(' AND ')
        self.assertEqual(hostname_type, "(network-traffic:dst_ref.type = 'domain-name'")
        self.assertEqual(hostname_value, f"network-traffic:dst_ref.value = '{_hostname}')")

    def _test_event_with_network_socket_observable_object(self, event):
        misp_object, observed_data = self._run_observable_from_object_tests(event)
        self._check_network_socket_observable_object(misp_object, observed_data)

    def _test_event_with_news_agency_object(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_object = self.parser._misp_event.objects[0]
        identity, report, news_agency = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event, identity_id, timestamp)[0]
        news_agency_id = f"identity--{misp_object['uuid']}"
        name, address1, email1, phone1, address2, email2, phone2, link, attachment = (attribute['value'] for attribute in misp_object['Attribute'])
        self.assertEqual(news_agency.type, 'identity')
        self._assert_multiple_equal(news_agency.id, news_agency_id, object_ref)
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
        self.parser.parse_misp_event(event)
        misp_object = self.parser._misp_event.objects[0]
        identity, report, organization = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event, identity_id, timestamp)[0]
        organization_id = f"identity--{misp_object['uuid']}"
        name, description, address, email, phone, role, alias = (attribute['value'] for attribute in misp_object['Attribute'])
        self.assertEqual(organization.type, 'identity')
        self._assert_multiple_equal(organization.id, organization_id, object_ref)
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
        misp_objects, observed_data, pattern = self._run_indicator_from_objects_tests(event)
        self._check_pe_and_section_observable(
            observed_data.objects['0'].extensions['windows-pebinary-ext'],
            *misp_objects
        )
        self._check_pe_and_section_pattern(pattern[1:-1].split(' AND '), *misp_objects)

    def _test_event_with_pe_and_section_observable_objects(self, event):
        misp_objects, observed_data = self._run_observable_from_objects_tests(event)
        self._check_pe_and_section_observable(
            observed_data.objects['0'].extensions['windows-pebinary-ext'],
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
        role = self._check_person_object(person, misp_object, object_ref, identity_id)
        self.assertEqual(person.x_misp_role, role)

    def _test_event_with_process_indicator_object(self, event):
        misp_object, observed_data, pattern = self._run_indicator_from_object_tests(event)
        self._check_process_observable_object(misp_object, observed_data)
        _pid, _, _, _, _image, _parent_image, *_ = (
            attribute['value'] for attribute in misp_object.attributes
        )
        pid_, image_, parent_image_ = pattern[1:-1].split(' AND ')
        self.assertEqual(pid_, f"process:pid = '{_pid}'")
        self.assertEqual(image_, f"process:binary_ref.name = '{_image}'")
        self.assertEqual(parent_image_, f"process:parent_ref.binary_ref.name = '{_parent_image}'")

    def _test_event_with_process_observable_object(self, event):
        misp_object, observed_data = self._run_observable_from_object_tests(event)
        self._check_process_observable_object(misp_object, observed_data)

    def _test_event_with_registry_key_indicator_object(self, event):
        misp_object, observed_data, pattern = self._run_indicator_from_object_tests(event)
        self._check_registry_key_observable_object(misp_object, observed_data)
        _key = misp_object.attributes[0]['value'].replace('\\', '\\\\')
        key_ = pattern[1:-1]
        self.assertEqual(key_, f"windows-registry-key:key = '{_key}'")

    def _test_event_with_registry_key_observable_object(self, event):
        misp_object, observed_data = self._run_observable_from_object_tests(event)
        self._check_registry_key_observable_object(misp_object, observed_data)

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
        misp_object, observed_data, pattern = self._run_indicator_from_object_tests(event)
        self._check_url_observable_object(misp_object, observed_data)
        _url, _domain, _host, _ip, _ = (attribute['value'] for attribute in misp_object.attributes)
        url_, domain_, host_, ip_ = pattern[1:-1].split(' AND ')
        self.assertEqual(url_, f"url:value = '{_url}'")
        self.assertEqual(domain_, f"url:x_misp_domain = '{_domain}'")
        self.assertEqual(host_, f"url:x_misp_host = '{_host}'")
        self.assertEqual(ip_, f"url:x_misp_ip = '{_ip}'")

    def _test_event_with_url_observable_object(self, event):
        misp_object, observed_data = self._run_observable_from_object_tests(event)
        self._check_url_observable_object(misp_object, observed_data)

    def _test_event_with_user_account_indicator_object(self, event):
        misp_object, observed_data, pattern = self._run_indicator_from_object_tests(event)
        self._check_user_account_observable_object(misp_object, observed_data)
        _username = misp_object.attributes[0]['value']
        username_ = pattern[1:-1]
        self.assertEqual(username_, f"user-account:account_login = '{_username}'")

    def _test_event_with_user_account_observable_object(self, event):
        misp_object, observed_data = self._run_observable_from_object_tests(event)
        self._check_user_account_observable_object(misp_object, observed_data)

    def _test_event_with_vulnerability_object(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_object = self.parser._misp_event.objects[0]
        identity, report, vulnerability = self.parser.stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_report_features(report, event, identity_id, timestamp)[0]
        self._check_object_vulnerability_features(vulnerability, misp_object, identity_id, object_ref)

    def _test_event_with_x509_indicator_object(self, event):
        misp_object, observed_data, pattern = self._run_indicator_from_object_tests(event)
        self._check_x509_observable_object(misp_object, observed_data)
        _issuer, *_, _md5, _sha1 = (attribute['value'] for attribute in misp_object.attributes)
        md5_, sha1_, issuer_ = pattern[1:-1].split(' AND ')
        self.assertEqual(md5_, f"x509-certificate:hashes.MD5 = '{_md5}'")
        self.assertEqual(sha1_, f"x509-certificate:hashes.SHA1 = '{_sha1}'")
        self.assertEqual(issuer_, f"x509-certificate:issuer = '{_issuer}'")

    def _test_event_with_x509_observable_object(self, event):
        misp_object, observed_data = self._run_observable_from_object_tests(event)
        self._check_x509_observable_object(misp_object, observed_data)

    def _test_object_references(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        (ap_object, as_object, btc_object, coa_object, ip_object,
         person_object, vuln_object) = self.parser._misp_event.objects
        bundle = self._check_bundle_features(18)
        (identity, report, attack_pattern, as_od, custom, coa, ip_od, ip_ind,
         person, vulnerability, *relationships) = bundle.objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_report_features(report, event, identity_id, timestamp)
        self.assertEqual(report.published, timestamp)
        (ap_ref, as_od_ref, custom_ref, coa_ref, ip_od_ref, ip_ind_ref,
         person_ref, vuln_ref, *relationship_refs) = object_refs
        self._assert_multiple_equal(
            attack_pattern.id, ap_ref, f"attack-pattern--{ap_object['uuid']}"
        )
        self._assert_multiple_equal(
            as_od.id, as_od_ref, f"observed-data--{as_object['uuid']}"
        )
        self._assert_multiple_equal(
            custom.id, custom_ref, f"x-misp-object--{btc_object['uuid']}"
        )
        self._assert_multiple_equal(
            coa.id, coa_ref, f"course-of-action--{coa_object['uuid']}"
        )
        self._assert_multiple_equal(
            ip_od.id, ip_od_ref, f"observed-data--{ip_object['uuid']}"
        )
        self._assert_multiple_equal(
            ip_ind.id, ip_ind_ref, f"indicator--{ip_object['uuid']}"
        )
        self._assert_multiple_equal(
            person.id, person_ref, f"identity--{person_object['uuid']}"
        )
        self._assert_multiple_equal(
            vulnerability.id, vuln_ref, f"vulnerability--{vuln_object['uuid']}"
        )
        for relationship, relationship_ref in zip(relationships, relationship_refs):
            self.assertEqual(relationship.id, relationship_ref)
        (ap_od_relation, od_od_relation, custom_od_relation, coa_vuln_relation,
         od_coa_relation, ind_od_relation, id_od_relation, vuln_ind_relation) = relationships
        timestamp = ap_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self._check_relationship_features(
            ap_od_relation, ap_ref, ip_od_ref, 'threatens', timestamp
        )
        timestamp = as_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self._check_relationship_features(
            od_od_relation, as_od_ref, ip_od_ref, 'includes', timestamp
        )
        timestamp = btc_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self._check_relationship_features(
            custom_od_relation, custom_ref, ip_od_ref, 'connected-to', timestamp
        )
        timestamp = coa_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self._check_relationship_features(
            coa_vuln_relation, coa_ref, vuln_ref, 'protects-against', timestamp
        )
        timestamp = ip_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self._check_relationship_features(
            od_coa_relation, ip_od_ref, coa_ref, 'protected-with', timestamp
        )
        self._check_relationship_features(
            ind_od_relation, ip_ind_ref, ip_od_ref, 'based-on', timestamp
        )
        timestamp = person_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self._check_relationship_features(
            id_od_relation, person_ref, ip_od_ref, 'owns', timestamp
        )
        timestamp = vuln_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self._check_relationship_features(
            vuln_ind_relation, vuln_ref, ip_od_ref, 'affects', timestamp
        )


class TestSTIX20JSONObjectsExport(TestSTIX20ObjectsExport):
    @classmethod
    def tearDownClass(self):
        objects_documentation = ObjectsDocumentationUpdater(
            'misp_objects_to_stix20',
            self._objects_v20,
            'export'
        )
        objects_documentation.check_export_mapping()

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
        misp_objects, stix_objects, relationships = self._run_indicators_from_objects_tests(event['Event'])
        self._check_account_observable_objects(
            misp_objects, (stix_object[0] for stix_object in stix_objects)
        )
        self._check_account_indicator_objects(
            misp_objects, (stix_object[-1].pattern for stix_object in stix_objects)
        )
        for misp_object, objects, relationship in zip(misp_objects, stix_objects, relationships):
            self._populate_documentation(misp_object=misp_object, stix=[*objects, relationship])

    def test_event_with_account_observable_objects(self):
        event = get_event_with_account_objects()
        misp_objects, observable_objects = self._run_observables_from_objects_tests(event['Event'])
        self._check_account_observable_objects(misp_objects, observable_objects)

    def test_event_with_account_with_attachment_indicator_objects(self):
        event = get_event_with_account_objects_with_attachment()
        misp_objects, stix_objects, relationships = self._run_indicators_from_objects_tests(event['Event'])
        self._check_account_with_attachment_observable_objects(
            misp_objects, (stix_object[0] for stix_object in stix_objects)
        )
        self._check_account_with_attachment_indicator_objects(
            misp_objects, (stix_object[-1].pattern for stix_object in stix_objects)
        )
        for misp_object, objects, relationship in zip(misp_objects, stix_objects, relationships):
            self._populate_documentation(misp_object=misp_object, stix=[*objects, relationship])

    def test_event_with_account_with_attachment_observable_object(self):
        event = get_event_with_account_objects_with_attachment()
        misp_objects, observable_objects = self._run_observables_from_objects_tests(event['Event'])
        self._check_account_with_attachment_observable_objects(misp_objects, observable_objects)

    def test_event_with_android_app_indicator_object(self):
        event = get_event_with_android_app_object()
        self._test_event_with_android_app_indicator_objet(event['Event'])
        self._populate_documentation(
            misp_object=self.parser._misp_event.objects[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_android_app_observable_object(self):
        event = get_event_with_android_app_object()
        self._test_event_with_android_app_observable_objet(event['Event'])

    def test_event_with_asn_indicator_object(self):
        event = get_event_with_asn_object()
        self._test_event_with_asn_indicator_objet(event['Event'])
        self._populate_documentation(
            misp_object=self.parser._misp_event.objects[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_asn_observable_object(self):
        event = get_event_with_asn_object()
        self._test_event_with_asn_observable_objet(event['Event'])

    def test_event_with_attack_pattern_object(self):
        event = get_event_with_attack_pattern_object()
        self._test_event_with_attack_pattern_objet(event['Event'])
        self._populate_documentation(
            misp_object=self.parser._misp_event.objects[0],
            stix=self.parser.stix_objects[-1]
        )

    def test_event_with_course_of_action_object(self):
        event = get_event_with_course_of_action_object()
        self._test_event_with_course_of_action_object(event['Event'])
        self._populate_documentation(
            misp_object=self.parser._misp_event.objects[0],
            stix=self.parser.stix_objects[-1]
        )

    def test_event_with_cpe_asset_indicator_object(self):
        event = get_event_with_cpe_asset_object()
        self._test_event_with_cpe_asset_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object=self.parser._misp_event.objects[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_cpe_asset_observable_object(self):
        event = get_event_with_cpe_asset_object()
        self._test_event_with_cpe_asset_observable_object(event['Event'])

    def test_event_with_credential_indicator_object(self):
        event = get_event_with_credential_object()
        self._test_event_with_credential_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object=self.parser._misp_event.objects[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_credential_observable_object(self):
        event = get_event_with_credential_object()
        self._test_event_with_credential_observable_object(event['Event'])

    def test_event_with_custom_objects(self):
        event = get_event_with_custom_objects()
        self._test_event_with_custom_objects(event['Event'])

    def test_event_with_domain_ip_indicator_object(self):
        event = get_event_with_domain_ip_object_custom()
        self._test_event_with_domain_ip_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object=self.parser._misp_event.objects[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_domain_ip_observable_object_custom(self):
        event = get_event_with_domain_ip_object_custom()
        self._test_event_with_domain_ip_observable_object_custom(event['Event'])

    def test_event_with_domain_ip_observable_object_standard(self):
        event = get_event_with_domain_ip_object_standard()
        self._test_event_with_domain_ip_observable_object_standard(event['Event'])

    def test_event_with_email_indicator_object(self):
        event = get_event_with_email_object()
        self._test_event_with_email_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object=self.parser._misp_event.objects[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_email_observable_object(self):
        event = get_event_with_email_object()
        self._test_event_with_email_observable_object(event['Event'])

    def test_event_with_email_with_display_names_indicator_object(self):
        event = get_event_with_email_with_display_names_object()
        self._test_event_with_email_with_display_names_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object=self.parser._misp_event.objects[0],
            stix=self.parser.stix_objects[2:], name='email with display names'
        )

    def test_event_with_email_with_display_names_observable_object(self):
        event = get_event_with_email_with_display_names_object()
        self._test_event_with_email_with_display_names_observable_object(event['Event'])

    def test_event_with_employee_object(self):
        event = get_event_with_employee_object()
        self._test_event_with_employee_object(event['Event'])
        self._populate_documentation(
            misp_object=self.parser._misp_event.objects[0],
            stix=self.parser.stix_objects[-1]
        )

    def test_event_with_file_and_pe_indicator_objects(self):
        event = get_event_with_file_and_pe_objects()
        self._test_event_with_file_and_pe_indicator_objects(event['Event'])
        self._populate_documentation(
            misp_object=self.parser._misp_event.objects,
            stix=self.parser.stix_objects[2:],
            name='file with references to pe & pe-section(s)',
            summary='File Object with a Windows PE binary extension'
        )

    def test_event_with_file_and_pe_observable_objects(self):
        event = get_event_with_file_and_pe_objects()
        self._test_event_with_file_and_pe_observable_objects(event['Event'])

    def test_event_with_file_indicator_object(self):
        event = get_event_with_file_object_with_artifact()
        self._test_event_with_file_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object=self.parser._misp_event.objects[0],
            stix=self.parser.stix_objects[2:],
            summary='File Object (potential references to Artifact & Directory Objects)'
        )

    def test_event_with_file_observable_object(self):
        event = get_event_with_file_object_with_artifact()
        self._test_event_with_file_observable_object(event['Event'])

    def test_event_with_http_request_indicator_object(self):
        event = get_event_with_http_request_object()
        self._test_event_with_http_request_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object=self.parser._misp_event.objects[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_http_request_observable_object(self):
        event = get_event_with_http_request_object()
        self._test_event_with_http_request_observable_object(event['Event'])

    def test_event_with_identity_object(self):
        event = get_event_with_identity_object()
        self._test_event_with_identity_object(event['Event'])
        self._populate_documentation(
            misp_object=self.parser._misp_event.objects[0],
            stix=self.parser.stix_objects[-1]
        )

    def test_event_with_image_indicator_object(self):
        event = get_event_with_image_object()
        self._test_event_with_image_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object=self.parser._misp_event.objects[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_image_observable_object(self):
        event = get_event_with_image_object()
        self._test_event_with_image_observable_object(event['Event'])

    def test_event_with_intrusion_set_object(self):
        event = get_event_with_intrusion_set_object()
        self._test_event_with_intrusion_set_object(event['Event'])
        self._populate_documentation(
            misp_object=self.parser._misp_event.objects[0],
            stix=self.parser.stix_objects[-1]
        )

    def test_event_with_ip_port_indicator_object(self):
        event = get_event_with_ip_port_object()
        self._test_event_with_ip_port_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object=self.parser._misp_event.objects[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_ip_port_observable_object(self):
        event = get_event_with_ip_port_object()
        self._test_event_with_ip_port_observable_object(event['Event'])

    def test_event_with_legal_entity_object(self):
        event = get_event_with_legal_entity_object()
        self._test_event_with_legal_entity_object(event['Event'])
        self._populate_documentation(
            misp_object=self.parser._misp_event.objects[0],
            stix=self.parser.stix_objects[-1]
        )

    def test_event_with_lnk_indicator_object(self):
        event = get_event_with_lnk_object()
        self._test_event_with_lnk_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object=self.parser._misp_event.objects[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_lnk_observable_object(self):
        event = get_event_with_lnk_object()
        self._test_event_with_lnk_observable_object(event['Event'])

    def test_event_with_mutex_indicator_object(self):
        event = get_event_with_mutex_object()
        self._test_event_with_mutex_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object=self.parser._misp_event.objects[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_mutex_observable_object(self):
        event = get_event_with_mutex_object()
        self._test_event_with_mutex_observable_object(event['Event'])

    def test_event_with_netflow_indicator_object(self):
        event = get_event_with_netflow_object()
        self._test_event_with_netflow_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object=self.parser._misp_event.objects[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_netflow_observable_object(self):
        event = get_event_with_netflow_object()
        self._test_event_with_netflow_observable_object(event['Event'])

    def test_event_with_network_connection_indicator_object(self):
        event = get_event_with_network_connection_object()
        self._test_event_with_network_connection_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object=self.parser._misp_event.objects[0],
            stix=self.parser.stix_objects[2:],
            summary='Network Traffic, IPv4/IPv6 Address & Domain Name Objects'
        )

    def test_event_with_network_connection_observable_object(self):
        event = get_event_with_network_connection_object()
        self._test_event_with_network_connection_observable_object(event['Event'])

    def test_event_with_network_socket_indicator_object(self):
        event = get_event_with_network_socket_object()
        self._test_event_with_network_socket_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object=self.parser._misp_event.objects[0],
            stix=self.parser.stix_objects[2:],
            summary='Network Traffic with a socket extension, IPv4/IPv6 Address & Domain Name Objects'
        )

    def test_event_with_network_socket_observable_object(self):
        event = get_event_with_network_socket_object()
        self._test_event_with_network_socket_observable_object(event['Event'])

    def test_event_with_news_agency_object(self):
        event = get_event_with_news_agency_object()
        self._test_event_with_news_agency_object(event['Event'])
        self._populate_documentation(
            misp_object=self.parser._misp_event.objects[0],
            stix=self.parser.stix_objects[-1]
        )

    def test_event_with_organization_object(self):
        event = get_event_with_organization_object()
        self._test_event_with_organization_object(event['Event'])
        self._populate_documentation(
            misp_object=self.parser._misp_event.objects[0],
            stix=self.parser.stix_objects[-1]
        )

    def test_event_with_pe_and_section_indicator_objects(self):
        event = get_event_with_pe_objects()
        self._test_event_with_pe_and_section_indicator_objects(event['Event'])
        self._populate_documentation(
            misp_object=self.parser._misp_event.objects[0],
            stix=self.parser.stix_objects[-1], name='pe & pe-sections',
            summary='Windows PE binary extension within a File Object'
        )

    def test_event_with_pe_and_section_observable_objects(self):
        event = get_event_with_pe_objects()
        self._test_event_with_pe_and_section_observable_objects(event['Event'])

    def test_event_with_person_object(self):
        event = get_event_with_person_object()
        self._test_event_with_person_object(event['Event'])
        self._populate_documentation(
            misp_object=self.parser._misp_event.objects[0],
            stix=self.parser.stix_objects[-1]
        )

    def test_event_with_process_indicator_object(self):
        event = get_event_with_process_object_v2()
        self._test_event_with_process_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object=self.parser._misp_event.objects[0],
            stix=self.parser.stix_objects[2:],
            summary='Process Objects (potential reference to File Objects)'
        )

    def test_event_with_process_observable_object(self):
        event = get_event_with_process_object_v2()
        self._test_event_with_process_observable_object(event['Event'])

    def test_event_with_registry_key_indicator_object(self):
        event = get_event_with_registry_key_object()
        self._test_event_with_registry_key_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object=self.parser._misp_event.objects[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_registry_key_observable_object(self):
        event = get_event_with_registry_key_object()
        self._test_event_with_registry_key_observable_object(event['Event'])

    def test_event_with_script_objects(self):
        event = get_event_with_script_objects()
        self._test_event_with_script_objects(event['Event'])
        misp_objects = self.parser._misp_event.objects
        self._populate_documentation(
            misp_object=misp_objects[0], stix=self.parser.stix_objects[-2],
            name='Script object where state is "Malicious"'
        )
        self._populate_documentation(
            misp_object=misp_objects[1], stix=self.parser.stix_objects[-1],
            name='Script object where state is not "Malicious"'
        )

    def test_event_with_url_indicator_object(self):
        event = get_event_with_url_object()
        self._test_event_with_url_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object=self.parser._misp_event.objects[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_url_observable_object(self):
        event = get_event_with_url_object()
        self._test_event_with_url_observable_object(event['Event'])

    def test_event_with_user_account_indicator_object(self):
        event = get_event_with_user_account_object()
        self._test_event_with_user_account_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object=self.parser._misp_event.objects[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_user_account_observable_object(self):
        event = get_event_with_user_account_object()
        self._test_event_with_user_account_observable_object(event['Event'])

    def test_event_with_vulnerability_object(self):
        event = get_event_with_vulnerability_object()
        self._test_event_with_vulnerability_object(event['Event'])
        self._populate_documentation(
            misp_object=self.parser._misp_event.objects[0],
            stix=self.parser.stix_objects[-1]
        )

    def test_event_with_x509_indicator_object(self):
        event = get_event_with_x509_object()
        self._test_event_with_x509_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object=self.parser._misp_event.objects[0],
            stix=self.parser.stix_objects[2:]
        )

    def test_event_with_x509_observable_object(self):
        event = get_event_with_x509_object()
        self._test_event_with_x509_observable_object(event['Event'])

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
        misp_objects, stix_objects, _ = self._run_indicators_from_objects_tests(misp_event)
        self._check_account_observable_objects(
            misp_objects, (stix_object[0] for stix_object in stix_objects)
        )
        self._check_account_indicator_objects(
            misp_objects, (stix_object[-1].pattern for stix_object in stix_objects)
        )

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
        misp_objects, stix_objects, _ = self._run_indicators_from_objects_tests(misp_event)
        self._check_account_with_attachment_observable_objects(
            misp_objects, (stix_object[0] for stix_object in stix_objects)
        )
        self._check_account_with_attachment_indicator_objects(
            misp_objects, (stix_object[-1].pattern for stix_object in stix_objects)
        )

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

    def test_event_with_email_with_display_names_indicator_object_with_display_names(self):
        event = get_event_with_email_with_display_names_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_email_with_display_names_indicator_object(misp_event)

    def test_event_with_email_with_display_names_observable_object_with_display_names(self):
        event = get_event_with_email_with_display_names_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_email_with_display_names_observable_object(misp_event)

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

    def test_event_with_intrusion_set_object(self):
        event = get_event_with_intrusion_set_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_intrusion_set_object(misp_event)

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
    def _check_attack_pattern_meta_fields(self, stix_object, meta):
        super()._check_attack_pattern_meta_fields(stix_object, meta)
        if meta.get('synonyms') is not None:
            self.assertEqual(stix_object.x_misp_synonyms, meta['synonyms'])

    def _check_malware_meta_fields(self, stix_object, meta):
        super()._check_malware_meta_fields(stix_object, meta)
        # Custom Malware Galaxy Cluster fields
        if meta.get('architecture_execution_env') is not None:
            self.assertEqual(
                stix_object.x_misp_architecture_execution_env,
                meta['architecture_execution_env']
            )
        if meta.get('capabilities') is not None:
            self.assertEqual(
                stix_object.x_misp_capabilities, meta['capabilities']
            )
        if meta.get('implementation_languages') is not None:
            self.assertEqual(
                stix_object.x_misp_implementation_languages,
                meta['implementation_languages']
            )
        if meta.get('is_family') is not None:
            self.assertEqual(stix_object.x_misp_is_family, meta['is_family'])
        if meta.get('labels') is not None:
            for label in meta['labels']:
                self.assertIn(label, stix_object.labels)
        elif meta.get('malware_types') is not None:
            for malware_type in meta['malware_types']:
                self.assertIn(malware_type, stix_object.labels)

    def _check_threat_actor_meta_fields(self, stix_object, meta):
        super()._check_threat_actor_meta_fields(stix_object, meta)
        if meta.get('labels') is not None:
            for label in meta['labels']:
                self.assertIn(label, stix_object.labels)
        elif meta.get('threat_actor_types') is not None:
            for label in meta['threat_actor_types']:
                self.assertIn(label, stix_object.labels)

    def _check_tool_meta_fields(self, stix_object, meta):
        super()._check_tool_meta_fields(stix_object, meta)
        if meta.get('labels') is not None:
            for label in meta['labels']:
                self.assertIn(label, stix_object.labels)
        elif meta.get('tool_types') is not None:
            for label in meta['tool_types']:
                self.assertIn(label, stix_object.labels)

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

    def _test_event_with_campaign_galaxy(self, event):
        galaxy = event['Galaxy'][0]
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        campaign = self._run_galaxy_tests(event, timestamp)
        self.assertEqual(campaign.type, 'campaign')
        self._check_galaxy_features(campaign, galaxy, timestamp)

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

    @classmethod
    def tearDownClass(self):
        galaxies_documentation = GalaxiesDocumentationUpdater(
            'misp_galaxies_to_stix20',
            self._galaxies_v20,
            'export'
        )
        galaxies_documentation.check_export_mapping()

    def test_event_with_attack_pattern_galaxy(self):
        event = get_event_with_attack_pattern_galaxy()
        self._test_event_with_attack_pattern_galaxy(event['Event'])
        self._populate_documentation(
            galaxy=self.parser._misp_event.galaxies[0],
            stix=self.parser.stix_objects[-1],
            summary=', '.join(sorted(self._mapping_types.attack_pattern_types()))
        )

    def test_event_with_course_of_action_galaxy(self):
        event = get_event_with_course_of_action_galaxy()
        self._test_event_with_course_of_action_galaxy(event['Event'])
        self._populate_documentation(
            galaxy=self.parser._misp_event.galaxies[0],
            stix=self.parser.stix_objects[-1],
            summary=', '.join(sorted(self._mapping_types.course_of_action_types()))
        )

    def test_event_with_custom_attack_pattern_20_galaxy(self):
        event = get_event_with_custom_attack_pattern_galaxy('2.0')
        self._test_event_with_attack_pattern_galaxy(event['Event'])
        self._populate_documentation(
            galaxy=self.parser._misp_event.galaxies[0],
            stix=self.parser.stix_objects[-1]
        )

    def test_event_with_custom_attack_pattern_21_galaxy(self):
        event = get_event_with_custom_attack_pattern_galaxy('2.1')
        self._test_event_with_attack_pattern_galaxy(event['Event'])
        self._populate_documentation(
            galaxy=self.parser._misp_event.galaxies[0],
            stix=self.parser.stix_objects[-1]
        )

    def test_event_with_custom_campaign_20_galaxy(self):
        event = get_event_with_custom_campaign_galaxy('2.0')
        self._test_event_with_campaign_galaxy(event['Event'])
        self._populate_documentation(
            galaxy=self.parser._misp_event.galaxies[0],
            stix=self.parser.stix_objects[-1]
        )

    def test_event_with_custom_campaign_21_galaxy(self):
        event = get_event_with_custom_campaign_galaxy('2.1')
        self._test_event_with_campaign_galaxy(event['Event'])
        self._populate_documentation(
            galaxy=self.parser._misp_event.galaxies[0],
            stix=self.parser.stix_objects[-1]
        )

    def test_event_with_custom_course_of_action_20_galaxy(self):
        event = get_event_with_custom_course_of_action_galaxy('2.0')
        self._test_event_with_course_of_action_galaxy(event['Event'])
        self._populate_documentation(
            galaxy=self.parser._misp_event.galaxies[0],
            stix=self.parser.stix_objects[-1]
        )

    def test_event_with_custom_course_of_action_21_galaxy(self):
        event = get_event_with_custom_course_of_action_galaxy('2.1')
        self._test_event_with_course_of_action_galaxy(event['Event'])
        self._populate_documentation(
            galaxy=self.parser._misp_event.galaxies[0],
            stix=self.parser.stix_objects[-1]
        )

    def test_event_with_custom_galaxy(self):
        event = get_event_with_custom_galaxy()
        self._test_event_with_custom_galaxy(event['Event'])

    def test_event_with_custom_intrusion_set_20_galaxy(self):
        event = get_event_with_custom_intrusion_set_galaxy('2.0')
        self._test_event_with_intrusion_set_galaxy(event['Event'])
        self._populate_documentation(
            galaxy=self.parser._misp_event.galaxies[0],
            stix=self.parser.stix_objects[-1]
        )

    def test_event_with_custom_intrusion_set_21_galaxy(self):
        event = get_event_with_custom_intrusion_set_galaxy('2.1')
        self._test_event_with_intrusion_set_galaxy(event['Event'])
        self._populate_documentation(
            galaxy=self.parser._misp_event.galaxies[0],
            stix=self.parser.stix_objects[-1]
        )

    def test_event_with_custom_malware_20_galaxy(self):
        event = get_event_with_custom_malware_galaxy('2.0')
        self._test_event_with_malware_galaxy(event['Event'])
        self._populate_documentation(
            galaxy=self.parser._misp_event.galaxies[0],
            stix=self.parser.stix_objects[-1]
        )

    def test_event_with_custom_malware_21_galaxy(self):
        event = get_event_with_custom_malware_galaxy('2.1')
        self._test_event_with_malware_galaxy(event['Event'])
        self._populate_documentation(
            galaxy=self.parser._misp_event.galaxies[0],
            stix=self.parser.stix_objects[-1]
        )

    def test_event_with_custom_threat_actor_20_galaxy(self):
        event = get_event_with_custom_threat_actor_galaxy('2.0')
        self._test_event_with_threat_actor_galaxy(event['Event'])
        self._populate_documentation(
            galaxy=self.parser._misp_event.galaxies[0],
            stix=self.parser.stix_objects[-1]
        )

    def test_event_with_custom_threat_actor_21_galaxy(self):
        event = get_event_with_custom_threat_actor_galaxy('2.1')
        self._test_event_with_threat_actor_galaxy(event['Event'])
        self._populate_documentation(
            galaxy=self.parser._misp_event.galaxies[0],
            stix=self.parser.stix_objects[-1]
        )

    def test_event_with_custom_tool_20_galaxy(self):
        event = get_event_with_custom_tool_galaxy('2.0')
        self._test_event_with_tool_galaxy(event['Event'])
        self._populate_documentation(
            galaxy=self.parser._misp_event.galaxies[0],
            stix=self.parser.stix_objects[-1]
        )

    def test_event_with_custom_tool_21_galaxy(self):
        event = get_event_with_custom_tool_galaxy('2.1')
        self._test_event_with_tool_galaxy(event['Event'])
        self._populate_documentation(
            galaxy=self.parser._misp_event.galaxies[0],
            stix=self.parser.stix_objects[-1]
        )

    def test_event_with_custom_vulnerability_20_galaxy(self):
        event = get_event_with_custom_vulnerability_galaxy('2.0')
        self._test_event_with_vulnerability_galaxy(event['Event'])
        self._populate_documentation(
            galaxy=self.parser._misp_event.galaxies[0],
            stix=self.parser.stix_objects[-1]
        )

    def test_event_with_custom_vulnerability_21_galaxy(self):
        event = get_event_with_custom_vulnerability_galaxy('2.1')
        self._test_event_with_vulnerability_galaxy(event['Event'])
        self._populate_documentation(
            galaxy=self.parser._misp_event.galaxies[0],
            stix=self.parser.stix_objects[-1]
        )

    def test_event_with_intrusion_set_galaxy(self):
        event = get_event_with_intrusion_set_galaxy()
        self._test_event_with_intrusion_set_galaxy(event['Event'])
        self._populate_documentation(
            galaxy=self.parser._misp_event.galaxies[0],
            stix=self.parser.stix_objects[-1],
            summary=', '.join(sorted(self._mapping_types.intrusion_set_types()))
        )

    def test_event_with_malware_galaxy(self):
        event = get_event_with_malware_galaxy()
        self._test_event_with_malware_galaxy(event['Event'])
        self._populate_documentation(
            galaxy=self.parser._misp_event.galaxies[0],
            stix=self.parser.stix_objects[-1],
            summary=', '.join(sorted(self._mapping_types.malware_types()))
        )

    def test_event_with_sector_galaxy(self):
        event = get_event_with_sector_galaxy()
        self._test_event_with_sector_galaxy(event['Event'])
        self._populate_documentation(
            galaxy=self.parser._misp_event.galaxies[0],
            stix=self.parser.stix_objects[-1]
        )

    def test_event_with_threat_actor_galaxy(self):
        event = get_event_with_threat_actor_galaxy()
        self._test_event_with_threat_actor_galaxy(event['Event'])
        self._populate_documentation(
            galaxy=self.parser._misp_event.galaxies[0],
            stix=self.parser.stix_objects[-1],
            summary=', '.join(sorted(self._mapping_types.threat_actor_types()))
        )

    def test_event_with_tool_galaxy(self):
        event = get_event_with_tool_galaxy()
        self._test_event_with_tool_galaxy(event['Event'])
        self._populate_documentation(
            galaxy=self.parser._misp_event.galaxies[0],
            stix=self.parser.stix_objects[-1],
            summary=', '.join(sorted(self._mapping_types.tool_types()))
        )

    def test_event_with_vulnerability_galaxy(self):
        event = get_event_with_vulnerability_galaxy()
        self._test_event_with_vulnerability_galaxy(event['Event'])
        self._populate_documentation(
            galaxy=self.parser._misp_event.galaxies[0],
            stix=self.parser.stix_objects[-1],
            summary=', '.join(sorted(self._mapping_types.vulnerability_types()))
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

    def test_event_with_custom_attack_pattern_20_galaxy(self):
        event = get_event_with_custom_attack_pattern_galaxy('2.0')
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_attack_pattern_galaxy(misp_event)

    def test_event_with_custom_attack_pattern_21_galaxy(self):
        event = get_event_with_custom_attack_pattern_galaxy('2.1')
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_attack_pattern_galaxy(misp_event)

    def test_event_with_custom_campaign_20_galaxy(self):
        event = get_event_with_custom_campaign_galaxy('2.0')
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_campaign_galaxy(misp_event)

    def test_event_with_custom_campaign_21_galaxy(self):
        event = get_event_with_custom_campaign_galaxy('2.1')
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_campaign_galaxy(misp_event)

    def test_event_with_custom_course_of_action_20_galaxy(self):
        event = get_event_with_custom_course_of_action_galaxy('2.0')
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_course_of_action_galaxy(misp_event)

    def test_event_with_custom_course_of_action_21_galaxy(self):
        event = get_event_with_custom_course_of_action_galaxy('2.1')
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_course_of_action_galaxy(misp_event)

    def test_event_with_custom_galaxy(self):
        event = get_event_with_custom_galaxy()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_custom_galaxy(misp_event)

    def test_event_with_custom_intrusion_set_20_galaxy(self):
        event = get_event_with_custom_intrusion_set_galaxy('2.0')
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_intrusion_set_galaxy(misp_event)

    def test_event_with_custom_intrusion_set_21_galaxy(self):
        event = get_event_with_custom_intrusion_set_galaxy('2.1')
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_intrusion_set_galaxy(misp_event)

    def test_event_with_custom_malware_20_galaxy(self):
        event = get_event_with_custom_malware_galaxy('2.0')
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_malware_galaxy(misp_event)

    def test_event_with_custom_malware_21_galaxy(self):
        event = get_event_with_custom_malware_galaxy('2.1')
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_malware_galaxy(misp_event)

    def test_event_with_custom_threat_actor_20_galaxy(self):
        event = get_event_with_custom_threat_actor_galaxy('2.0')
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_threat_actor_galaxy(misp_event)

    def test_event_with_custom_threat_actor_21_galaxy(self):
        event = get_event_with_custom_threat_actor_galaxy('2.1')
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_threat_actor_galaxy(misp_event)

    def test_event_with_custom_tool_20_galaxy(self):
        event = get_event_with_custom_tool_galaxy('2.0')
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_tool_galaxy(misp_event)

    def test_event_with_custom_tool_21_galaxy(self):
        event = get_event_with_custom_tool_galaxy('2.1')
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_tool_galaxy(misp_event)

    def test_event_with_custom_vulnerability_20_galaxy(self):
        event = get_event_with_custom_vulnerability_galaxy('2.0')
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_vulnerability_galaxy(misp_event)

    def test_event_with_custom_vulnerability_21_galaxy(self):
        event = get_event_with_custom_vulnerability_galaxy('2.1')
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_vulnerability_galaxy(misp_event)

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

    def _check_attributes_feed(
            self, indicators, od_objects, relationships, attributes):
        for index, attribute in enumerate(attributes):
            if 'Attribute' in attribute:
                attribute = attribute['Attribute']
            attribute_uuid = attribute['uuid']
            indicator = indicators[index]
            observed_data = od_objects[index]
            relationship = relationships[index]
            self._assert_multiple_equal(
                indicator.id, relationship.source_ref,
                f'indicator--{attribute_uuid}'
            )
            self._assert_multiple_equal(
                observed_data.id, relationship.target_ref,
                f'observed-data--{attribute_uuid}'
            )

    def _test_attributes_feed(self, attributes):
        (identity1, od1, indicator1, relationship1, od2, indicator2,
         relationship2, od3, indicator3, relationship3, od4, indicator4,
         relationship4) = self.parser.bundle.objects
        self.assertEqual(identity1.id, 'identity--a0c22599-9e58-4da4-96ac-7051603fa951')
        self.assertEqual(identity1.name, 'MISP-Project')
        indicators = (indicator1, indicator2, indicator3, indicator4)
        observed_data_objects = (od1, od2, od3, od4)
        relationships = (relationship1, relationship2, relationship3, relationship4)
        self._check_attributes_feed(
            indicators, observed_data_objects, relationships, attributes
        )

    def _test_split_attributes_feed(self, bundle1, bundle2, attributes):
        (identity1, od1, indicator1, relationship1,
         od2, indicator2, relationship2) = bundle1.objects
        (identity2, od3, indicator3, relationship3,
         od4, indicator4, relationship4) = bundle2.objects
        self._assert_multiple_equal(
            'identity--a0c22599-9e58-4da4-96ac-7051603fa951',
            identity1.id, identity2.id
        )
        self._assert_multiple_equal(
            'MISP-Project', identity1.name, identity2.name
        )
        indicators = (indicator1, indicator2, indicator3, indicator4)
        observed_data_objects = (od1, od2, od3, od4)
        relationships = (relationship1, relationship2, relationship3, relationship4)
        self._check_attributes_feed(
            indicators, observed_data_objects, relationships, attributes
        )


class TestFeedSTIX21JSONExport(TestFeedSTIX20Export):
    def test_attributes_feed(self):
        attributes = get_attributes_feed()
        for attribute in attributes:
            self.parser.parse_misp_attribute(attribute)
        self._test_attributes_feed(attributes)

    def test_split_attributes_feed(self):
        attributes = get_attributes_feed()
        for attribute in attributes[:2]:
            self.parser.parse_misp_attribute(attribute)
        bundle1 = self.parser.bundle
        for attribute in attributes[2:]:
            self.parser.parse_misp_attribute(attribute)
        bundle2 = self.parser.bundle
        self._test_split_attributes_feed(bundle1, bundle2, attributes)


class TestFeedSTIX21MISPExport(TestFeedSTIX20Export):
    def test_attributes_feed(self):
        attributes = get_attributes_feed()
        for attribute in attributes:
            attribute['Attribute']['Event'] = attribute['Event']
            misp_attribute = MISPAttribute()
            misp_attribute.from_dict(**attribute)
            self.parser.parse_misp_attribute(misp_attribute)
        self._test_attributes_feed(attributes)

    def test_split_attributes_feed(self):
        attributes = get_attributes_feed()
        for attribute in attributes[:2]:
            attribute['Attribute']['Event'] = attribute['Event']
            misp_attribute = MISPAttribute()
            misp_attribute.from_dict(**attribute)
            self.parser.parse_misp_attribute(misp_attribute)
        bundle1 = self.parser.bundle
        for attribute in attributes[2:]:
            attribute['Attribute']['Event'] = attribute['Event']
            misp_attribute = MISPAttribute()
            misp_attribute.from_dict(**attribute)
            self.parser.parse_misp_attribute(misp_attribute)
        bundle2 = self.parser.bundle
        self._test_split_attributes_feed(bundle1, bundle2, attributes)
