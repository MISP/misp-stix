#!/usr/bin/env python
# -*- coding: utf-8 -*-

from datetime import datetime
from misp_stix_converter import (
    MISPtoSTIX21Mapping, MISPtoSTIX21Parser, misp_collection_to_stix2,
    misp_to_stix2)
from pymisp import MISPAttribute, MISPEvent
from .test_events import *
from .update_documentation import (
    AttributesDocumentationUpdater, GalaxiesDocumentationUpdater,
    ObjectsDocumentationUpdater)
from ._test_stix import TestSTIX21
from ._test_stix_export import TestCollectionSTIX2Export, TestSTIX2Export, TestSTIX21Export


class TestSTIX21GenericExport(TestSTIX21Export, TestSTIX21):
    def setUp(self):
        self.parser = MISPtoSTIX21Parser()

    def _check_bundle_features(self, length):
        bundle = self.parser.bundle
        self.assertEqual(bundle.type, 'bundle')
        self.assertEqual(len(bundle.objects), length)
        return bundle.objects

    def _check_pattern_features(self, indicator):
        self.assertEqual(indicator.pattern_type, 'stix')
        self.assertEqual(indicator.pattern_version, '2.1')

    def _check_spec_versions(self, stix_objects):
        for stix_object in stix_objects:
            self.assertEqual(stix_object.spec_version, '2.1')


class TestSTIX21EventExport(TestSTIX21GenericExport):
    def _check_analyst_note(self, stix_object, misp_layer):
        self.assertEqual(
            stix_object.id, f"note--{misp_layer['uuid']}"
        )
        self.assertEqual(stix_object.content, misp_layer['note'])
        self.assertEqual(stix_object.lang, misp_layer['language'])
        self.assertEqual(
            stix_object.authors, [misp_layer['authors']]
        )
        self.assertEqual(
            stix_object.created,
            self._datetime_from_str(misp_layer['created'])
        )
        self.assertEqual(
            stix_object.modified,
            self._datetime_from_str(misp_layer['modified'])
        )
        self.assertEqual(
            stix_object.labels, ['misp:context-layer="Analyst Note"']
        )

    def _check_analyst_opinion(self, stix_object, misp_layer, opinion):
        self.assertEqual(
            stix_object.id, f"opinion--{misp_layer['uuid']}"
        )
        self.assertEqual(stix_object.opinion, opinion)
        self.assertEqual(
            stix_object.x_misp_opinion, int(misp_layer['opinion'])
        )
        self.assertEqual(stix_object.explanation, misp_layer['comment'])
        self.assertEqual(stix_object.authors, [misp_layer['authors']])
        self.assertEqual(
            stix_object.created,
            self._datetime_from_str(misp_layer['created'])
        )
        self.assertEqual(
            stix_object.modified,
            self._datetime_from_str(misp_layer['modified'])
        )
        self.assertEqual(
            stix_object.labels, ['misp:context-layer="Analyst Opinion"']
        )

    def _check_attribute_confidence_tags(self, stix_object, attribute):
        self.assertEqual(
            stix_object.confidence,
            self.parser._mapping.confidence_tags(
                attribute['Tag'][-1]['name']
            )
        )
        self.assertEqual(stix_object.labels[-2:], [tag['name'] for tag in attribute['Tag'][1:]])

    def _check_object_confidence_tags(self, stix_object, misp_object):
        self.assertEqual(
            stix_object.confidence,
            self.parser._mapping.confidence_tags(
                misp_object['Attribute'][2]['Tag'][0]['name']
            )
        )
        self.assertEqual(
            set(stix_object.labels[-2:]),
            set(attribute['Tag'][0]['name'] for attribute in misp_object['Attribute'][1:3])
        )

    def _check_opinion_features(self, opinion, sighting, *object_ids):
        self.assertEqual(opinion.type, 'opinion')
        self.assertEqual(opinion.id, f"opinion--{sighting['uuid']}")
        timestamp = sighting['date_sighting']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self._assert_multiple_equal(opinion.created, opinion.modified, timestamp)
        self.assertEqual(opinion.object_refs, list(object_ids))
        self.assertEqual(opinion.authors, [sighting['Organisation']['name']])
        self.assertEqual(opinion.explanation, "False positive Sighting")
        self.assertEqual(opinion.opinion, "strongly-disagree")
        self.assertEqual(
            opinion.x_misp_author_ref,
            f"identity--{sighting['Organisation']['uuid']}"
        )

    def _test_base_event(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        stix_objects = self._check_bundle_features(3)
        self._check_spec_versions(stix_objects)
        identity, grouping, note = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_grouping_features(grouping, identity_id)[0]
        self.assertEqual(note.type, 'note')
        self._assert_multiple_equal(note.id, object_ref, f"note--{event['uuid']}")
        self.assertEqual(note.created_by_ref, identity_id)
        self.assertEqual(note.created, timestamp)
        self.assertEqual(note.modified, timestamp)
        self.assertEqual(
            note.content,
            "This MISP Event is empty and contains no attribute, object, galaxy or tag."
        )
        self.assertEqual(note.object_refs, [grouping.id])

    def _test_event_with_analyst_data(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        src_attribute, dst_attribute = self.parser._misp_event.attributes
        misp_object = self.parser._misp_event.objects[0]
        stix_objects = self._check_bundle_features(22)
        self._check_spec_versions(stix_objects)
        identity, grouping, *stix_objects = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_grouping_features(grouping, identity_id)
        for stix_object, object_ref in zip(stix_objects, object_refs):
            self.assertEqual(stix_object.id, object_ref)
        (attr_od, _, _, attr_indicator, attr_opinion, observed_data, _,
         _, obs_data_note, obj_od, _, obj_indicator, obj_opinion, obj_attr_note,
         report, report_opinion, attr_relationship, relationship,
         obj_relationship, event_note) = stix_objects
        self.assertEqual(attr_opinion.object_refs, [attr_od.id, attr_indicator.id])
        self._assert_multiple_equal(
            attr_od.id, relationship.target_ref, attr_relationship.target_ref,
            f"observed-data--{src_attribute['uuid']}"
        )
        attribute_opinion = src_attribute['Opinion'][0]
        self._check_analyst_opinion(attr_opinion, attribute_opinion, 'strongly-agree')
        self._assert_multiple_equal(
            observed_data.id,
            obs_data_note.object_refs[0],
            f"observed-data--{dst_attribute['uuid']}"
        )
        attribute_note = dst_attribute['Note'][0]
        self._check_analyst_note(obs_data_note, attribute_note)
        self._assert_multiple_equal(
            obj_opinion.object_refs, obj_attr_note.object_refs,
            [obj_od.id, obj_indicator.id]
        )
        self._assert_multiple_equal(
            obj_od.id, relationship.source_ref, obj_relationship.target_ref,
            f"observed-data--{misp_object['uuid']}"
        )
        object_opinion = misp_object['Opinion'][0]
        self._check_analyst_opinion(obj_opinion, object_opinion, 'neutral')
        object_attribute_note = misp_object['Attribute'][0]['Note'][0]
        self._check_analyst_note(obj_attr_note, object_attribute_note)
        event_report = self.parser._misp_event.event_reports[0]
        self._assert_multiple_equal(
            report.id,
            report_opinion.object_refs[0],
            f"note--{event_report['uuid']}"
        )
        self.assertEqual(report.labels, ['misp:data-layer="Event Report"'])
        event_report_opinion = event_report['Opinion'][0]
        self._check_analyst_opinion(report_opinion, event_report_opinion, 'agree')
        self.assertEqual(relationship.relationship_type, 'downloaded-from')
        self.assertEqual(attr_relationship.source_ref, attr_indicator.id)
        self.assertEqual(obj_relationship.source_ref, obj_indicator.id)
        self._assert_multiple_equal(
            attr_relationship.relationship_type,
            obj_relationship.relationship_type,
            'based-on'
        )
        self._check_analyst_note(event_note, self.parser._misp_event.notes[0])

    def _test_event_with_attribute_confidence_tags(self, event):
        tlp_tag, *confidence_tags = event['Tag']
        domain, campaign_name, vulnerability_attribute, AS = event['Attribute']
        self.parser.parse_misp_event(event)
        stix_objects = self._check_bundle_features(11)
        self._check_spec_versions(stix_objects)
        (_, grouping, observed_data1, _, indicator, campaign, vulnerability,
         observed_data2, _, relationship, marking) = stix_objects
        self.assertEqual(
            grouping.confidence,
            self.parser._mapping.confidence_tags(confidence_tags[1]['name'])
        )
        self.assertEqual(grouping.labels[-2:], [tag['name'] for tag in confidence_tags])
        self._assert_multiple_equal(
            [marking.id], grouping.object_marking_refs,
            observed_data1.object_marking_refs, campaign.object_marking_refs,
            vulnerability.object_marking_refs, observed_data2.object_marking_refs
        )
        self.assertEqual(
            f'{marking.definition_type}:{marking.definition[marking.definition_type]}',
            tlp_tag['name']
        )
        self._check_attribute_confidence_tags(observed_data1, domain)
        self._check_attribute_confidence_tags(campaign, campaign_name)
        self._check_attribute_confidence_tags(vulnerability, vulnerability_attribute)
        self._check_attribute_confidence_tags(observed_data2, AS)
        self.assertEqual(relationship.relationship_type, 'based-on')
        self.assertEqual(relationship.source_ref, indicator.id)
        self.assertEqual(relationship.target_ref, observed_data1.id)

    def _test_event_with_escaped_characters(self, event):
        attributes = deepcopy(event['Attribute'])
        self.parser.parse_misp_event(event)
        stix_objects = self._check_bundle_features(49)
        self._check_spec_versions(stix_objects)
        _, _, *indicators = stix_objects
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

    def _test_event_with_event_report(self, event):
        orgc = event['Orgc']
        event_report = event['EventReport'][0]
        self.parser.parse_misp_event(event)
        stix_objects = self._check_bundle_features(16)
        self._check_spec_versions(stix_objects)
        identity, grouping, *stix_objects = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_grouping_features(grouping, identity_id)
        for stix_object, object_ref in zip(stix_objects, object_refs):
            self.assertEqual(stix_object.id, object_ref)
        (observed_data1, _, _, indicator1, observed_data2, _, _,
         observed_data3, _, _, indicator2, note, *_) = stix_objects
        self.assertEqual(note.id, f"note--{event_report['uuid']}")
        self.assertEqual(note.abstract, event_report['name'])
        timestamp = event_report['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self._assert_multiple_equal(note.created, note.modified, timestamp)
        self.assertEqual(note.content, event_report['content'])
        object_refs = note.object_refs
        self.assertEqual(len(object_refs), 5)
        object_ids = {
            observed_data1.id, indicator1.id, observed_data2.id,
            observed_data3.id, indicator2.id
        }
        self.assertEqual(set(object_refs), object_ids)

    def _test_event_with_object_confidence_tags(self, event):
        tlp_tag, *confidence_tags = event['Tag']
        self.parser.parse_misp_event(event)
        ip_port, course_of_action, asn = self.parser._misp_event.objects
        stix_objects = self._check_bundle_features(11)
        self._check_spec_versions(stix_objects)
        _, grouping, observed_data1, *_, coa, observed_data2, _, _, marking = stix_objects
        self._assert_multiple_equal(
            grouping.confidence,
            self.parser._mapping.confidence_tags(confidence_tags[1]['name'])
        )
        self.assertEqual(grouping.labels[-2:], [tag['name'] for tag in confidence_tags])
        self._assert_multiple_equal(
            [marking.id], grouping.object_marking_refs,
            observed_data1.object_marking_refs, coa.object_marking_refs,
            observed_data2.object_marking_refs
        )
        self.assertEqual(
            f'{marking.definition_type}:{marking.definition[marking.definition_type]}',
            tlp_tag['name']
        )
        self._check_object_confidence_tags(observed_data1, ip_port)
        self._check_object_confidence_tags(coa, course_of_action)
        self._check_object_confidence_tags(observed_data2, asn)

    def _test_event_with_sightings(self, event):
        orgc = event['Orgc']
        attribute1, attribute2 = event['Attribute']
        sightings1 = attribute1['Sighting']
        sightings2 = attribute2['Sighting']
        self.parser.parse_misp_event(event)
        stix_objects = self._check_bundle_features(20)
        self._check_spec_versions(stix_objects)
        identity, identity1, identity2, identity3, identity4, grouping, *stix_objects = stix_objects
        identities = (identity1, identity2, identity3, identity4)
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_grouping_features(grouping, identity_id)
        for stix_object, object_ref in zip(stix_objects, object_refs):
            self.assertEqual(stix_object.id, object_ref)
        self._check_identities_from_sighting(
            identities,
            tuple(f"identity--{sighting['Organisation']['uuid']}" for sighting in sightings1),
            tuple(sighting['Organisation']['name'] for sighting in sightings2)
        )
        (observed_data1, _, sighting1, sighting2, opinion1, opinion2,
         observed_data2, _, indicator, sighting3, opinion3, sighting4,
         opinion4, _) = stix_objects
        self._check_sighting_features(
            sighting1, sightings1[0], observed_data1.id, identity1.id
        )
        self._check_sighting_features(
            sighting2, sightings1[1], observed_data1.id, identity2.id
        )
        self._check_opinion_features(
            opinion1, sightings1[2], observed_data1.id
        )
        self._check_opinion_features(
            opinion2, sightings1[3], observed_data1.id
        )
        self._check_sighting_features(
            sighting3, sightings2[0], indicator.id, identity1.id, observed_data2.id
        )
        self._check_opinion_features(
            opinion3, sightings2[1], observed_data2.id, indicator.id
        )
        self._check_sighting_features(
            sighting4, sightings2[2], indicator.id, identity3.id, observed_data2.id
        )
        self._check_opinion_features(
            opinion4, sightings2[3], observed_data2.id, indicator.id
        )

    def _test_event_with_tags(self, event):
        self.parser.parse_misp_event(event)
        stix_objects = self._check_bundle_features(4)
        self._check_spec_versions(stix_objects)
        _, _, _, marking = stix_objects
        self.assertEqual(marking.definition_type, 'tlp')
        self.assertEqual(marking.definition['tlp'], 'white')

    def _test_published_event(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        stix_objects = self._check_bundle_features(3)
        self._check_spec_versions(stix_objects)
        identity, report, _ = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        self._check_report_features(report, event, identity_id, timestamp)
        publish_timestamp = event['publish_timestamp']
        if not isinstance(publish_timestamp, datetime):
            publish_timestamp = self._datetime_from_timestamp(publish_timestamp)
        self.assertEqual(report.published, publish_timestamp)


class TestSTIX21JSONEventExport(TestSTIX21EventExport):
    def test_base_event(self):
        event = get_base_event()
        self._test_base_event(event['Event'])

    def test_event_with_analyst_data(self):
        event = get_event_with_analyst_data()
        self._test_event_with_analyst_data(event['Event'])

    def test_event_with_attribute_confidence_tags(self):
        event = get_event_with_attribute_confidence_tags()
        self._test_event_with_attribute_confidence_tags(event['Event'])

    def test_event_with_escaped_characters(self):
        event = get_event_with_escaped_values_v21()
        self._test_event_with_escaped_characters(event['Event'])

    def test_event_with_event_report(self):
        event = get_event_with_event_report()
        self._test_event_with_event_report(event['Event'])

    def test_event_with_object_confidence_tags(self):
        event = get_event_with_object_confidence_tags()
        self._test_event_with_object_confidence_tags(event['Event'])

    def test_event_with_sightings(self):
        event = get_event_with_sightings()
        self._test_event_with_sightings(event['Event'])

    def test_event_with_tags(self):
        event = get_event_with_tags()
        self._test_event_with_tags(event['Event'])

    def test_published_event(self):
        event = get_published_event()
        self._test_published_event(event['Event'])


class TestSTIX21MISPEventExport(TestSTIX21EventExport):
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

    def test_event_with_attribute_confidence_tags(self):
        event = get_event_with_attribute_confidence_tags()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_attribute_confidence_tags(misp_event)

    def test_event_with_escaped_characters(self):
        event = get_event_with_escaped_values_v21()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_escaped_characters(misp_event)

    def test_event_with_event_report(self):
        event = get_event_with_event_report()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_event_report(misp_event)

    def test_event_with_object_confidence_tags(self):
        event = get_event_with_object_confidence_tags()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_object_confidence_tags(misp_event)

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


class TestSTIX21AttributesExport(TestSTIX21GenericExport):
    _http_features = ('request_method', "request_header.'User-Agent'")
    _http_prefix = f"network-traffic:extensions.'http-request-ext'"

    def _check_as_observable_attribute(self, attribute, autonomous_system, object_ref):
        self._assert_multiple_equal(
            autonomous_system.id, object_ref,
            f"autonomous-system--{attribute['uuid']}"
        )
        self.assertEqual(autonomous_system.type, 'autonomous-system')
        number = self._parse_AS_value(attribute['value'])
        self.assertEqual(autonomous_system.number, number)

    def _check_attachment_observable_attribute(self, attribute, observables, object_refs):
        file_object, artifact_object = observables
        file_ref, artifact_ref = object_refs
        self._assert_multiple_equal(
            file_object.id, file_ref, f"file--{attribute['uuid']}"
        )
        self.assertEqual(file_object.type, 'file')
        self.assertEqual(file_object.name, attribute['value'])
        self._assert_multiple_equal(
            file_object.content_ref, artifact_object.id,
            artifact_ref, f"artifact--{attribute['uuid']}"
        )
        self.assertEqual(artifact_object.type, 'artifact')
        data = attribute['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(artifact_object.payload_bin, data)

    def _check_domain_observable_attribute(self, attribute, domain, object_ref):
        self._assert_multiple_equal(
            domain.id, object_ref, f"domain-name--{attribute['uuid']}"
        )
        self.assertEqual(domain.type, 'domain-name')
        self.assertEqual(domain.value, attribute['value'])

    def _check_domain_ip_observable_attribute(self, attribute, observables, object_refs):
        domain_value, ip_value = attribute['value'].split('|')
        domain, address = observables
        domain_ref, address_ref = object_refs
        self._assert_multiple_equal(
            domain.id, domain_ref, f"domain-name--{attribute['uuid']}"
        )
        self.assertEqual(domain.type, 'domain-name')
        self.assertEqual(domain.value, domain_value)
        self._assert_multiple_equal(
            domain.resolves_to_refs[0], address.id,
            address_ref, f"ipv4-addr--{attribute['uuid']}"
        )
        self.assertEqual(address.type, 'ipv4-addr')
        self.assertEqual(address.value, ip_value)

    def _check_email_attachment_observable_attribute(self, attribute, observables, object_refs):
        email_ref, file_ref = object_refs
        email, _file = observables
        self._assert_multiple_equal(
            email.id, email_ref, f"email-message--{attribute['uuid']}"
        )
        self.assertEqual(email.type, 'email-message')
        self.assertEqual(email.is_multipart, True)
        body = email.body_multipart[0]
        self.assertEqual(
            body.content_disposition,
            f"attachment; filename='{attribute['value']}'"
        )
        self._assert_multiple_equal(
            body.body_raw_ref, _file.id, file_ref, f"file--{attribute['uuid']}"
        )
        self.assertEqual(_file.name, attribute['value'])

    def _check_email_body_observable_attribute(self, attribute, email_message, object_ref):
        self._assert_multiple_equal(
            email_message.id, object_ref, f"email-message--{attribute['uuid']}"
        )
        self.assertEqual(email_message.type, 'email-message')
        self.assertEqual(email_message.is_multipart, False)
        self.assertEqual(email_message.body, attribute['value'])

    def _check_email_destination_observable_attribute(self, attribute, observables, object_refs):
        message, address = observables
        message_ref, address_ref = object_refs
        self._assert_multiple_equal(
            message.id, message_ref, f"email-message--{attribute['uuid']}"
        )
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self._assert_multiple_equal(
            message.to_refs[0], address.id, address_ref,
            f"email-addr--{attribute['uuid']}"
        )
        self._check_email_address(address, attribute['value'])

    def _check_email_header_observable_attribute(self, attribute, email_message, object_ref):
        self._assert_multiple_equal(
            email_message.id, object_ref, f"email-message--{attribute['uuid']}"
        )
        self.assertEqual(email_message.type, 'email-message')
        self.assertEqual(email_message.is_multipart, False)
        self.assertEqual(email_message.received_lines, [attribute['value']])

    def _check_email_message_id_observable_attribute(self, attribute, email_message, object_ref):
        self._assert_multiple_equal(
            email_message.id, object_ref, f"email-message--{attribute['uuid']}"
        )
        self.assertEqual(email_message.type, 'email-message')
        self.assertEqual(email_message.is_multipart, False)
        self.assertEqual(email_message.message_id, attribute['value'])

    def _check_email_observable_attribute(self, attribute, email_address, object_ref):
        self._assert_multiple_equal(
            email_address.id, object_ref, f"email-addr--{attribute['uuid']}"
        )
        self._check_email_address(email_address, attribute['value'])

    def _check_email_reply_to_observable_attribute(self, attribute, email_message, object_ref):
        self._assert_multiple_equal(
            email_message.id, object_ref, f"email-message--{attribute['uuid']}"
        )
        self.assertEqual(email_message.type, 'email-message')
        self.assertEqual(email_message.is_multipart, False)
        self.assertEqual(
            email_message.additional_header_fields['Reply-To'], attribute['value']
        )

    def _check_email_source_observable_attribute(self, attribute, observables, object_refs):
        message, address = observables
        message_ref, address_ref = object_refs
        self._assert_multiple_equal(
            message.id, message_ref, f"email-message--{attribute['uuid']}"
        )
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self._assert_multiple_equal(
            message.from_ref, address.id, address_ref,
            f"email-addr--{attribute['uuid']}"
        )
        self._check_email_address(address, attribute['value'])

    def _check_email_subject_observable_attribute(self, attribute, email_message, object_ref):
        self._assert_multiple_equal(
            email_message.id, object_ref, f"email-message--{attribute['uuid']}"
        )
        self.assertEqual(email_message.type, 'email-message')
        self.assertEqual(email_message.is_multipart, False)
        self.assertEqual(email_message.subject, attribute['value'])

    def _check_email_x_mailer_observable_attribute(self, attribute, email_message, object_ref):
        self._assert_multiple_equal(
            email_message.id, object_ref, f"email-message--{attribute['uuid']}"
        )
        self.assertEqual(email_message.type, 'email-message')
        self.assertEqual(email_message.is_multipart, False)
        self.assertEqual(
            email_message.additional_header_fields['X-Mailer'], attribute['value']
        )

    def _check_filename_observable_attribute(self, attribute, file_object, object_ref):
        self._assert_multiple_equal(
            file_object.id, object_ref, f"file--{attribute['uuid']}"
        )
        self.assertEqual(file_object.type, 'file')
        self.assertEqual(file_object.name, attribute['value'])

    def _check_github_username_observable_attribute(self, attribute, account, object_ref):
        self._assert_multiple_equal(
            account.id, object_ref, f"user-account--{attribute['uuid']}"
        )
        self.assertEqual(account.type, 'user-account')
        self.assertEqual(account.account_type, 'github')
        self.assertEqual(account.account_login, attribute['value'])

    def _check_hash_composite_indicator_attribute(self, attribute, indicator):
        filename, hash_value = attribute['value'].split('|')
        hash_type = attribute['type'].split('|')[1]
        if '/' in hash_type:
            hash_type = f"SHA{hash_type.split('/')[1]}"
        filename_pattern = f"file:name = '{filename}'"
        hash_pattern = f"file:hashes.{hash_type.replace('-', '').upper()} = '{hash_value}'"
        self.assertEqual(indicator.pattern, f"[{filename_pattern} AND {hash_pattern}]")

    def _check_hash_composite_observable_attribute(self, grouping_ref, observed_data, observable, attribute):
        self._assert_multiple_equal(
            observable.id,
            grouping_ref,
            observed_data['object_refs'][0],
            f"file--{attribute['uuid']}"
        )
        self.assertEqual(observable.type, 'file')
        filename, hash_value = attribute['value'].split('|')
        self.assertEqual(observable.name, filename)
        hash_type = self.hash_types_mapping(attribute['type'].split('|')[1])
        self.assertEqual(observable.hashes[hash_type], hash_value)

    def _check_hash_indicator_attribute(self, attribute, indicator):
        hash_type = attribute['type']
        if '/' in hash_type:
            hash_type = f"SHA{hash_type.split('/')[1]}"
        self.assertEqual(
            indicator.pattern,
            f"[file:hashes.{hash_type.replace('-', '').upper()} = '{attribute['value']}']"
        )

    def _check_hash_observable_attribute(self, grouping_ref, observed_data, observable, attribute):
        self._assert_multiple_equal(
            observable.id,
            grouping_ref,
            observed_data['object_refs'][0],
            f"file--{attribute['uuid']}"
        )
        self.assertEqual(observable.type, 'file')
        hash_type = self.hash_types_mapping(attribute['type'])
        self.assertEqual(observable.hashes[hash_type], attribute['value'])

    def _check_hostname_observable_attribute(self, attribute, domain, object_ref):
        self._assert_multiple_equal(
            domain.id, object_ref, f"domain-name--{attribute['uuid']}"
        )
        self.assertEqual(domain.type, 'domain-name')
        self.assertEqual(domain.value, attribute['value'])

    def _check_hostname_port_observable_attribute(self, attribute, observables, object_refs):
        domain, network_traffic = observables
        hostname_ref, network_traffic_ref = object_refs
        self._assert_multiple_equal(
            domain.id, hostname_ref, network_traffic.dst_ref,
            f"domain-name--{attribute['uuid']}"
        )
        self.assertEqual(domain.type, 'domain-name')
        hostname, port = attribute['value'].split('|')
        self.assertEqual(domain.value, hostname)
        self._assert_multiple_equal(
            network_traffic.id, network_traffic_ref,
            f"network-traffic--{attribute['uuid']}"
        )
        self.assertEqual(network_traffic.type, 'network-traffic')
        self.assertEqual(network_traffic.dst_port, int(port))

    def _check_ip_indicator_attribute(self, attribute, indicator):
        feature = attribute['type'].split('-')[1]
        type_pattern = f"network-traffic:{feature}_ref.type = 'ipv4-addr'"
        value_pattern = f"network-traffic:{feature}_ref.value = '{attribute['value']}'"
        self.assertEqual(indicator.pattern, f"[{type_pattern} AND {value_pattern}]")

    def _check_ip_observable_attribute(self, attribute, grouping_ref, observed_data, observable):
        network_id, address_id = grouping_ref
        network, address = observable
        network_ref, address_ref = observed_data['object_refs']
        self._assert_multiple_equal(
            network.id,
            network_id,
            network_ref,
            f"network-traffic--{attribute['uuid']}"
        )
        self.assertEqual(network.type, 'network-traffic')
        feature = attribute['type'].split('-')[1]
        self._assert_multiple_equal(
            address.id,
            address_id,
            address_ref,
            getattr(network, f"{feature}_ref"),
            f"ipv4-addr--{attribute['uuid']}"
        )
        self.assertEqual(address.type, 'ipv4-addr')
        self.assertEqual(address.value, attribute['value'])

    def _check_ip_port_indicator_attribute(self, attribute, indicator):
        feature = attribute['type'].split('|')[0].split('-')[1]
        ip_value, port_value = attribute['value'].split('|')
        type_pattern = f"network-traffic:{feature}_ref.type = 'ipv4-addr'"
        value_pattern = f"network-traffic:{feature}_ref.value = '{ip_value}'"
        port_pattern = f"network-traffic:{feature}_port = '{port_value}'"
        self.assertEqual(indicator.pattern, f"[{type_pattern} AND {value_pattern} AND {port_pattern}]")

    def _check_ip_port_observable_attribute(
            self, attribute, grouping_ref, observed_data, observable):
        network_id, address_id = grouping_ref
        network, address = observable
        network_ref, address_ref = observed_data['object_refs']
        ip_value, port_value = attribute['value'].split('|')
        feature = attribute['type'].split('|')[0].split('-')[1]
        self._assert_multiple_equal(
            network.id, network_id, network_ref,
            f"network-traffic--{attribute['uuid']}"
        )
        self.assertEqual(network.type, 'network-traffic')
        self.assertEqual(getattr(network, f"{feature}_port"), int(port_value))
        self._assert_multiple_equal(
            address.id, address_id, address_ref,
            getattr(network, f"{feature}_ref"),
            f"ipv4-addr--{attribute['uuid']}"
        )
        self.assertEqual(address.type, 'ipv4-addr')
        self.assertEqual(address.value, ip_value)

    def _check_mac_address_observable_attribute(self, attribute, mac_address, object_ref):
        self._assert_multiple_equal(
            mac_address.id, object_ref, f"mac-addr--{attribute['uuid']}"
        )
        self.assertEqual(mac_address.type, 'mac-addr')
        self.assertEqual(mac_address.value, attribute['value'].lower())

    def _check_malware_sample_observable_attribute(self, attribute, observables, object_refs):
        file_object, artifact_object = observables
        file_ref, artifact_ref = object_refs
        filename, hash_value = attribute['value'].split('|')
        self._assert_multiple_equal(
            file_object.id, file_ref, f"file--{attribute['uuid']}"
        )
        self.assertEqual(file_object.type, 'file')
        self.assertEqual(file_object.name, filename)
        self.assertEqual(file_object.hashes['MD5'], hash_value)
        self._assert_multiple_equal(
            artifact_object.id, artifact_ref, file_object.content_ref,
            f"artifact--{attribute['uuid']}"
        )
        self.assertEqual(artifact_object.type, 'artifact')
        data = attribute['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(artifact_object.payload_bin, data)

    def _check_mutex_observable_attribute(self, attribute, mutex, object_ref):
        self._assert_multiple_equal(
            mutex.id, object_ref, f"mutex--{attribute['uuid']}"
        )
        self.assertEqual(mutex.type, 'mutex')
        self.assertEqual(mutex.name, attribute['value'])

    def _check_patterning_language_attribute(self, attribute, indicator, object_ref, identity_id):
        self._check_attribute_indicator_features(indicator, attribute, identity_id, object_ref)
        self.assertEqual(indicator.pattern_type, attribute['type'])
        self.assertEqual(indicator.pattern, f"[{attribute['value']}]")

    def _check_regkey_observable_attribute(self, attribute, registry_key, object_ref):
        self._assert_multiple_equal(
            registry_key.id, object_ref,
            f"windows-registry-key--{attribute['uuid']}"
        )
        self.assertEqual(registry_key.type, 'windows-registry-key')
        self.assertEqual(registry_key.key, attribute['value'].strip())

    def _check_regkey_value_observable_attribute(self, attribute, registry_key, object_ref):
        key, value = attribute['value'].split('|')
        self._assert_multiple_equal(
            registry_key.id, object_ref,
            f"windows-registry-key--{attribute['uuid']}"
        )
        self.assertEqual(registry_key.type, 'windows-registry-key')
        self.assertEqual(registry_key.key, key.strip())
        self.assertEqual(registry_key['values'][0].data, value.strip())

    def _check_url_observable_attribute(self, grouping_ref, observed_data, observable, attribute):
        self._assert_multiple_equal(
            observable.id,
            grouping_ref,
            observed_data.object_refs[0],
            f"url--{attribute['uuid']}"
        )
        self.assertEqual(observable.type, 'url')
        self.assertEqual(observable.value, attribute['value'])

    def _check_x509_fingerprint_observable_attribute(self, grouping_ref, observed_data, observable, attribute):
        self._assert_multiple_equal(
            observable.id,
            grouping_ref,
            observed_data['object_refs'][0],
            f"x509-certificate--{attribute['uuid']}"
        )
        self.assertEqual(observable.type, 'x509-certificate')
        hash_type = self.hash_types_mapping(attribute['type'].split('-')[-1])
        self.assertEqual(observable.hashes[hash_type], attribute['value'])

    @staticmethod
    def _group_list_elements(list_to_group, index):
        grouped_list = []
        tmp = []
        for count, stix_id in enumerate(list_to_group):
            if count % index != 0:
                tmp.append(stix_id)
            else:
                if tmp:
                    grouped_list.append(tmp)
                    tmp = []
        grouped_list.append(tmp)
        return grouped_list

    def _run_indicator_tests(self, event, indicator_only=False):
        self._add_attribute_ids_flag(event)
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        attribute = self.parser._misp_event.attributes[0]
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        if indicator_only:
            identity, grouping, indicator = stix_objects
            identity_id = self._check_identity_features(identity, orgc, timestamp)
            object_ref = self._check_grouping_features(grouping, identity_id)[0]
            self._check_attribute_indicator_features(indicator, attribute, identity_id, object_ref)
            self._check_pattern_features(indicator)
            return attribute['value'], indicator.pattern
        identity, grouping, observed_data, *observables, indicator, relationship = stix_objects
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_grouping_features(grouping, identity_id)
        od_ref, *observable_refs, indicator_ref, relationship_ref = object_refs
        self._check_attribute_observable_features(observed_data, attribute, identity_id, od_ref)
        self.assertEqual(observable_refs, observed_data.object_refs)
        self._check_attribute_indicator_features(indicator, attribute, identity_id, indicator_ref)
        self._check_pattern_features(indicator)
        self.assertEqual(relationship.id, relationship_ref)
        self.assertEqual(relationship.relationship_type, 'based-on')
        self.assertEqual(relationship.source_ref, indicator_ref)
        self.assertEqual(relationship.target_ref, od_ref)
        return attribute, observables, observable_refs, indicator.pattern

    def _run_indicators_tests(self, event, indicator_only=False):
        self._add_attribute_ids_flag(event)
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        attributes = self.parser._misp_event.attributes
        n_attributes = len(attributes)
        self.assertTrue(n_attributes > 0)
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, *SDOs = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_grouping_features(grouping, identity_id)
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
            observed_data, *_, indicator = chunk
            od_ref, *_, indicator_ref = object_ref
            self._check_attribute_indicator_features(indicator, attribute, identity_id, indicator_ref)
            self._check_pattern_features(indicator)
            self._check_attribute_observable_features(observed_data, attribute, identity_id, od_ref)
            self.assertEqual(relationship.relationship_type, 'based-on')
            self.assertEqual(relationship.source_ref, indicator_ref)
            self.assertEqual(relationship.target_ref, od_ref)
        return attributes, object_chunks, ref_chunks, relationships

    def _run_observable_tests(self, event):
        self._remove_attribute_ids_flag(event)
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        attribute = self.parser._misp_event.attributes[0]
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, observed_data, *observable = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        observed_data_id, *observable_refs = self._check_grouping_features(
            grouping, identity_id
        )
        self._check_attribute_observable_features(
            observed_data, attribute, identity_id, observed_data_id
        )
        self.assertEqual(observable_refs, observed_data.object_refs)
        return attribute, observable, observable_refs

    def _run_observables_tests(self, event, index=2):
        self._remove_attribute_ids_flag(event)
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        attributes = self.parser._misp_event.attributes
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, *observables = stix_objects
        observed_datas = observables[::index]
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        ids = self._check_grouping_features(grouping, identity_id)
        observable_ids = ids[::index]
        for attribute, observed_data, observable_id in zip(attributes, observed_datas, observable_ids):
            self._check_attribute_observable_features(
                observed_data, attribute, identity_id, observable_id
            )
        if index == 2:
            return (
                attributes,
                [value for count, value in enumerate(ids) if count % index != 0],
                observed_datas,
                [value for count, value in enumerate(observables) if count % index != 0]
            )
        return (
            attributes,
            self._group_list_elements(ids, index),
            observed_datas,
            self._group_list_elements(observables, index)
        )

    def _test_embedded_indicator_attribute_galaxy(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        attribute = self.parser._misp_event.attributes[0]
        event_galaxy = self.parser._misp_event.galaxies[0]
        stix_objects = self._check_bundle_features(13)
        self._check_spec_versions(stix_objects)
        (identity, grouping, attack_pattern, course_of_action, custom,
         observed_data, domain, indicator, malware, *relationships) = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_grouping_features(grouping, identity_id)
        (ap_ref, coa_ref, custom_ref, od_ref, domain_ref, indicator_ref,
         malware_ref, *relationship_refs) = object_refs
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
            observed_data.id, od_ref, f"observed-data--{attribute['uuid']}"
        )
        self._assert_multiple_equal(
            domain.id, domain_ref, f"domain-name--{attribute['uuid']}"
        )
        self._assert_multiple_equal(
            indicator.id, indicator_ref, f"indicator--{attribute['uuid']}"
        )
        self._assert_multiple_equal(
            malware.id, malware_ref,
            f"malware--{event_galaxy['GalaxyCluster'][0]['uuid']}"
        )
        for relationship, relationship_ref in zip(relationships, relationship_refs):
            self.assertEqual(relationship.id, relationship_ref)
        timestamp = attribute['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(attribute['timestamp'])
        od_ap_rel, od_coa_rel, od_custom_rel, ind_od_rel = relationships
        self._check_relationship_features(
            od_ap_rel, od_ref, ap_ref, 'related-to', timestamp,
        )
        self._check_relationship_features(
            od_coa_rel, od_ref, coa_ref, 'related-to', timestamp
        )
        self._check_relationship_features(
            od_custom_rel, od_ref, custom_ref, 'related-to', timestamp
        )
        self._check_relationship_features(
            ind_od_rel, indicator_ref, od_ref, 'based-on', timestamp
        )

    def _test_embedded_non_indicator_attribute_galaxy(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        attribute = self.parser._misp_event.attributes[0]
        event_coa_galaxy, malware_galaxy = self.parser._misp_event.galaxies
        stix_objects = self._check_bundle_features(8)
        self._check_spec_versions(stix_objects)
        identity, grouping, attack_pattern, course_of_action, vulnerability, malware, *relationships = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_grouping_features(grouping, identity_id)
        ap_ref, coa_ref, vulnerability_ref, malware_ref, apr_ref, coar_ref = object_refs
        ap_relationship, coa_relationship = relationships
        ap_galaxy, coa_galaxy = attribute['Galaxy']
        self._assert_multiple_equal(
            attack_pattern.id,
            ap_ref,
            f"attack-pattern--{ap_galaxy['GalaxyCluster'][0]['uuid']}"
        )
        self._assert_multiple_equal(
            course_of_action.id,
            coa_ref,
            f"course-of-action--{event_coa_galaxy['GalaxyCluster'][0]['uuid']}",
            f"course-of-action--{coa_galaxy['GalaxyCluster'][0]['uuid']}"
        )
        self._assert_multiple_equal(
            vulnerability.id,
            vulnerability_ref,
            f"vulnerability--{attribute['uuid']}"
        )
        self._assert_multiple_equal(
            malware.id,
            malware_ref,
            f"malware--{malware_galaxy['GalaxyCluster'][0]['uuid']}"
        )
        self.assertEqual(ap_relationship.id, apr_ref)
        self.assertEqual(coa_relationship.id, coar_ref)
        timestamp = attribute['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self._check_relationship_features(ap_relationship, vulnerability_ref, ap_ref, 'related-to', timestamp)
        self._check_relationship_features(coa_relationship, vulnerability_ref, coa_ref, 'related-to', timestamp)

    def _test_embedded_observable_attribute_galaxy(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        attribute = self.parser._misp_event.attributes[0]
        event_galaxy = self.parser._misp_event.galaxies[0]
        stix_objects = self._check_bundle_features(7)
        self._check_spec_versions(stix_objects)
        identity, grouping, attack_pattern, observed_data, autonomous_system, malware, relationship = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_grouping_features(grouping, identity_id)
        ap_ref, od_ref, as_ref, malware_ref, relationship_ref = object_refs
        self._assert_multiple_equal(
            attack_pattern.id,
            ap_ref,
            f"attack-pattern--{attribute['Galaxy'][0]['GalaxyCluster'][0]['uuid']}"
        )
        self._assert_multiple_equal(
            observed_data.id,
            od_ref,
            f"observed-data--{attribute['uuid']}"
        )
        self._assert_multiple_equal(
            autonomous_system.id,
            as_ref,
            f"autonomous-system--{attribute['uuid']}"
        )
        self._assert_multiple_equal(
            malware.id,
            malware_ref,
            f"malware--{event_galaxy['GalaxyCluster'][0]['uuid']}"
        )
        self.assertEqual(relationship.id, relationship_ref)
        timestamp = attribute['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self._check_relationship_features(
            relationship, od_ref, ap_ref, 'related-to', timestamp
        )

    def _test_event_with_as_indicator_attribute(self, event):
        attribute, observable, object_refs, pattern = self._run_indicator_tests(event)
        self._assert_multiple_equal(len(observable), len(object_refs), 1)
        self._check_as_observable_attribute(attribute, observable[0], object_refs[0])
        number = self._parse_AS_value(attribute['value'])
        self.assertEqual(pattern, f"[autonomous-system:number = '{number}']")

    def _test_event_with_as_observable_attribute(self, event):
        attribute, observable, object_refs = self._run_observable_tests(event)
        self._assert_multiple_equal(len(observable), len(object_refs), 1)
        self._check_as_observable_attribute(attribute, observable[0], object_refs[0])

    def _test_event_with_attachment_indicator_attribute(self, event):
        attribute, observables, object_refs, pattern = self._run_indicator_tests(event)
        self._check_attachment_observable_attribute(attribute, observables, object_refs)
        file_pattern = f"file:name = '{attribute['value']}'"
        data = attribute['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        data_pattern = f"file:content_ref.payload_bin = '{data}'"
        self.assertEqual(pattern, f"[{file_pattern} AND {data_pattern}]")

    def _test_event_with_attachment_observable_attribute(self, event):
        attribute, observables, object_refs = self._run_observable_tests(event)
        self._check_attachment_observable_attribute(attribute, observables, object_refs)

    def _test_event_with_campaign_name_attribute(self, event):
        self._remove_attribute_ids_flag(event)
        orgc = event['Orgc']
        attribute = event['Attribute'][0]
        self.parser.parse_misp_event(event)
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, campaign = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_grouping_features(grouping, identity_id)[0]
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
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, *custom_objects = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_grouping_features(grouping, identity_id)
        for attribute, custom_object, object_ref in zip(attributes, custom_objects, object_refs):
            self._run_custom_attribute_tests(attribute, custom_object, object_ref, identity_id)

    def _test_event_with_domain_indicator_attribute(self, event):
        attribute, observable, object_refs, pattern = self._run_indicator_tests(event)
        self._assert_multiple_equal(len(observable), len(object_refs), 1)
        self._check_domain_observable_attribute(attribute, observable[0], object_refs[0])
        self.assertEqual(pattern, f"[domain-name:value = '{attribute['value']}']")

    def _test_event_with_domain_observable_attribute(self, event):
        attribute, observable, object_refs = self._run_observable_tests(event)
        self._assert_multiple_equal(len(observable), len(object_refs), 1)
        self._check_domain_observable_attribute(attribute, observable[0], object_refs[0])

    def _test_event_with_domain_ip_indicator_attribute(self, event):
        attribute, observables, object_refs, pattern = self._run_indicator_tests(event)
        self._check_domain_ip_observable_attribute(attribute, observables, object_refs)
        domain, ip = attribute['value'].split('|')
        domain_pattern = f"domain-name:value = '{domain}'"
        ip_pattern = f"domain-name:resolves_to_refs[*].value = '{ip}'"
        self.assertEqual(pattern, f'[{domain_pattern} AND {ip_pattern}]')

    def _test_event_with_domain_ip_observable_attribute(self, event):
        attribute, observables, object_refs = self._run_observable_tests(event)
        self._check_domain_ip_observable_attribute(attribute, observables, object_refs)

    def _test_event_with_email_attachment_indicator_attribute(self, event):
        attribute, observables, object_refs, pattern = self._run_indicator_tests(event)
        self._check_email_attachment_observable_attribute(attribute, observables, object_refs)
        self.assertEqual(
            pattern,
            f"[email-message:body_multipart[*].body_raw_ref.name = '{attribute['value']}']"
        )

    def _test_event_with_email_attachment_observable_attribute(self, event):
        attribute, observables, object_refs = self._run_observable_tests(event)
        self._check_email_attachment_observable_attribute(attribute, observables, object_refs)

    def _test_event_with_email_body_indicator_attribute(self, event):
        attribute, observables, object_refs, pattern = self._run_indicator_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_email_body_observable_attribute(attribute, observables[0], object_refs[0])
        self.assertEqual(
            pattern, f"[email-message:body = '{attribute['value']}']"
        )

    def _test_event_with_email_body_observable_attribute(self, event):
        attribute, observables, object_refs = self._run_observable_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_email_body_observable_attribute(attribute, observables[0], object_refs[0])

    def _test_event_with_email_destination_indicator_attribute(self, event):
        attribute, observables, object_refs, pattern = self._run_indicator_tests(event)
        self._check_email_destination_observable_attribute(attribute, observables, object_refs)
        self.assertEqual(pattern, f"[email-message:to_refs[*].value = '{attribute['value']}']")

    def _test_event_with_email_destination_observable_attribute(self, event):
        attribute, observables, object_refs = self._run_observable_tests(event)
        self._check_email_destination_observable_attribute(attribute, observables, object_refs)

    def _test_event_with_email_header_indicator_attribute(self, event):
        attribute, observables, object_refs, pattern = self._run_indicator_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_email_header_observable_attribute(attribute, observables[0], object_refs[0])
        self.assertEqual(pattern, f"[email-message:received_lines = '{attribute['value']}']")

    def _test_event_with_email_header_observable_attribute(self, event):
        attribute, observables, object_refs = self._run_observable_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_email_header_observable_attribute(attribute, observables[0], object_refs[0])

    def _test_event_with_email_indicator_attribute(self, event):
        attribute, observables, object_refs, pattern = self._run_indicator_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_email_observable_attribute(attribute, observables[0], object_refs[0])
        self.assertEqual(pattern, f"[email-addr:value = '{attribute['value']}']")

    def _test_event_with_email_message_id_indicator_attribute(self, event):
        attribute, observables, object_refs, pattern = self._run_indicator_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_email_message_id_observable_attribute(attribute, observables[0], object_refs[0])
        self.assertEqual(pattern, f"[email-message:message_id = '{attribute['value']}']")

    def _test_event_with_email_message_id_observable_attribute(self, event):
        attribute, observables, object_refs = self._run_observable_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_email_message_id_observable_attribute(attribute, observables[0], object_refs[0])

    def _test_event_with_email_observable_attribute(self, event):
        attribute, observables, object_refs = self._run_observable_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_email_observable_attribute(attribute, observables[0], object_refs[0])

    def _test_event_with_email_reply_to_indicator_attribute(self, event):
        attribute, observables, object_refs, pattern = self._run_indicator_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_email_reply_to_observable_attribute(attribute, observables[0], object_refs[0])
        self.assertEqual(
            pattern,
            f"[email-message:additional_header_fields.reply_to = '{attribute['value']}']"
        )

    def _test_event_with_email_reply_to_observable_attribute(self, event):
        attribute, observables, object_refs = self._run_observable_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_email_reply_to_observable_attribute(attribute, observables[0], object_refs[0])

    def _test_event_with_email_source_indicator_attribute(self, event):
        attribute, observables, object_refs, pattern = self._run_indicator_tests(event)
        self._check_email_source_observable_attribute(attribute, observables, object_refs)
        self.assertEqual(pattern, f"[email-message:from_ref.value = '{attribute['value']}']")

    def _test_event_with_email_source_observable_attribute(self, event):
        attribute, observables, object_refs = self._run_observable_tests(event)
        self._check_email_source_observable_attribute(attribute, observables, object_refs)

    def _test_event_with_email_subject_indicator_attribute(self, event):
        attribute, observables, object_refs, pattern = self._run_indicator_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_email_subject_observable_attribute(attribute, observables[0], object_refs[0])
        self.assertEqual(pattern, f"[email-message:subject = '{attribute['value']}']")

    def _test_event_with_email_subject_observable_attribute(self, event):
        attribute, observables, object_refs = self._run_observable_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_email_subject_observable_attribute(attribute, observables[0], object_refs[0])

    def _test_event_with_email_x_mailer_indicator_attribute(self, event):
        attribute, observables, object_refs, pattern = self._run_indicator_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_email_x_mailer_observable_attribute(attribute, observables[0], object_refs[0])
        self.assertEqual(
            pattern,
            f"[email-message:additional_header_fields.x_mailer = '{attribute['value']}']"
        )

    def _test_event_with_email_x_mailer_observable_attribute(self, event):
        attribute, observables, object_refs = self._run_observable_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_email_x_mailer_observable_attribute(attribute, observables[0], object_refs[0])

    def _test_event_with_filename_indicator_attribute(self, event):
        attribute, observables, object_refs, pattern = self._run_indicator_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_filename_observable_attribute(attribute, observables[0], object_refs[0])
        self.assertEqual(pattern, f"[file:name = '{attribute['value']}']")

    def _test_event_with_filename_observable_attribute(self, event):
        attribute, observables, object_refs = self._run_observable_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_filename_observable_attribute(attribute, observables[0], object_refs[0])

    def _test_event_with_github_username_indicator_attribute(self, event):
        attribute, observables, object_refs, pattern = self._run_indicator_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_github_username_observable_attribute(attribute, observables[0], object_refs[0])
        self.assertEqual(
            pattern,
            f"[user-account:account_type = 'github' AND user-account:account_login = '{attribute['value']}']"
        )

    def _test_event_with_github_username_observable_attribute(self, event):
        attribute, observables, object_refs = self._run_observable_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_github_username_observable_attribute(attribute, observables[0], object_refs[0])

    def _test_event_with_hostname_indicator_attribute(self, event):
        attribute, observables, object_refs, pattern = self._run_indicator_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_hostname_observable_attribute(attribute, observables[0], object_refs[0])
        self.assertEqual(pattern, f"[domain-name:value = '{attribute['value']}']")

    def _test_event_with_hostname_observable_attribute(self, event):
        attribute, observables, object_refs = self._run_observable_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_hostname_observable_attribute(attribute, observables[0], object_refs[0])

    def _test_event_with_hostname_port_indicator_attribute(self, event):
        attribute, observables, object_refs, pattern = self._run_indicator_tests(event)
        self._check_hostname_port_observable_attribute(attribute, observables, object_refs)
        hostname, port = attribute['value'].split('|')
        hostname_pattern = f"domain-name:value = '{hostname}'"
        port_pattern = f"network-traffic:dst_port = '{port}'"
        self.assertEqual(pattern, f"[{hostname_pattern} AND {port_pattern}]")

    def _test_event_with_hostname_port_observable_attribute(self, event):
        attribute, observables, object_refs = self._run_observable_tests(event)
        self._check_hostname_port_observable_attribute(attribute, observables, object_refs)

    def _test_event_with_mac_address_indicator_attribute(self, event):
        attribute, observables, object_refs, pattern = self._run_indicator_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_mac_address_observable_attribute(attribute, observables[0], object_refs[0])
        self.assertEqual(pattern, f"[mac-addr:value = '{attribute['value']}']")

    def _test_event_with_mac_address_observable_attribute(self, event):
        attribute, observables, object_refs = self._run_observable_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_mac_address_observable_attribute(attribute, observables[0], object_refs[0])

    def _test_event_with_malware_sample_indicator_attribute(self, event):
        attribute, observables, object_refs, pattern = self._run_indicator_tests(event)
        self._check_malware_sample_observable_attribute(attribute, observables, object_refs)
        data = attribute['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        filename, hash_value = attribute['value'].split('|')
        data_pattern, file_pattern, hash_pattern, mime_type, encryption, decryption = pattern[1:-1].split(' AND ')
        self.assertEqual(data_pattern, f"file:content_ref.payload_bin = '{data}'")
        self.assertEqual(file_pattern, f"file:name = '{filename}'")
        self.assertEqual(hash_pattern, f"file:hashes.MD5 = '{hash_value}'")
        self.assertEqual(mime_type, f"file:content_ref.mime_type = 'application/zip'")
        self.assertEqual(encryption, f"file:content_ref.encryption_algorithm = 'mime-type-indicated'")
        self.assertEqual(decryption, f"file:content_ref.decryption_key = 'infected'")

    def _test_event_with_malware_sample_observable_attribute(self, event):
        attribute, observables, object_refs = self._run_observable_tests(event)
        self._check_malware_sample_observable_attribute(attribute, observables, object_refs)

    def _test_event_with_mutex_indicator_attribute(self, event):
        attribute, observables, object_refs, pattern = self._run_indicator_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_mutex_observable_attribute(attribute, observables[0], object_refs[0])
        self.assertEqual(pattern, f"[mutex:name = '{attribute['value']}']")

    def _test_event_with_mutex_observable_attribute(self, event):
        attribute, observables, object_refs = self._run_observable_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_mutex_observable_attribute(attribute, observables[0], object_refs[0])

    def _test_event_with_port_indicator_attribute(self, event):
        attribute_value, pattern = self._run_indicator_tests(event, indicator_only=True)
        self.assertEqual(pattern, f"[network-traffic:dst_port = '{attribute_value}']")

    def _test_event_with_regkey_indicator_attribute(self, event):
        attribute, observables, object_ref, pattern = self._run_indicator_tests(event)
        self._assert_multiple_equal(len(observables), len(object_ref), 1)
        self._check_regkey_observable_attribute(attribute, observables[0], object_ref[0])
        self.assertEqual(
            pattern.replace('\\\\', '\\'),
            f"[windows-registry-key:key = '{attribute['value'].strip()}']"
        )

    def _test_event_with_regkey_observable_attribute(self, event):
        attribute, observables, object_ref = self._run_observable_tests(event)
        self._assert_multiple_equal(len(observables), len(object_ref), 1)
        self._check_regkey_observable_attribute(attribute, observables[0], object_ref[0])

    def _test_event_with_regkey_value_indicator_attribute(self, event):
        attribute, observables, object_refs, pattern = self._run_indicator_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_regkey_value_observable_attribute(attribute, observables[0], object_refs[0])
        key, value = attribute['value'].split('|')
        key_pattern = f"windows-registry-key:key = '{self._sanitise_registry_key_value(key)}'"
        value_pattern = f"windows-registry-key:values.data = '{self._sanitise_registry_key_value(value)}'"
        self.assertEqual(pattern, f"[{key_pattern} AND {value_pattern}]")

    def _test_event_with_regkey_value_observable_attribute(self, event):
        attribute, observables, object_refs = self._run_observable_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_regkey_value_observable_attribute(attribute, observables[0], object_refs[0])

    def _test_event_with_size_in_bytes_indicator_attribute(self, event):
        attribute_value, pattern = self._run_indicator_tests(event, indicator_only=True)
        self.assertEqual(pattern, f"[file:size = '{attribute_value}']")

    def _test_event_with_vulnerability_attribute(self, event):
        self._add_attribute_ids_flag(event)
        orgc = event['Orgc']
        attribute = event['Attribute'][0]
        self.parser.parse_misp_event(event)
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, vulnerability = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_grouping_features(grouping, identity_id)[0]
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


class TestSTIX21JSONAttributesExport(TestSTIX21AttributesExport):
    @classmethod
    def tearDownClass(self):
        attributes_documentation = AttributesDocumentationUpdater(
            'misp_attributes_to_stix21',
            self._attributes_v21,
            'export'
        )
        attributes_documentation.check_export_mapping('stix21')

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
            observed_data = self.parser.stix_objects[-2:]
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
            observed_data = self.parser.stix_objects[-3:]
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
            observed_data = self.parser.stix_objects[-2:]
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
            observed_data = self.parser.stix_objects[-3:]
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
            observed_data = self.parser.stix_objects[-3:]
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
            observed_data = self.parser.stix_objects[-2:]
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
            observed_data = self.parser.stix_objects[-3:]
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
            observed_data = self.parser.stix_objects[-2:]
        )

    def test_event_with_email_indicator_attribute(self):
        event = get_event_with_email_address_attribute()
        self._test_event_with_email_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_email_message_id_indicator_attribute(self):
        event = get_event_with_email_message_id_attribute()
        self._test_event_with_email_message_id_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_email_message_id_observable_attribute(self):
        event = get_event_with_email_message_id_attribute()
        self._test_event_with_email_message_id_observable_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-2:]
        )

    def test_event_with_email_observable_attribute(self):
        event = get_event_with_email_address_attribute()
        self._test_event_with_email_observable_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-2:]
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
            observed_data = self.parser.stix_objects[-2:]
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
            observed_data = self.parser.stix_objects[-3:]
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
            observed_data = self.parser.stix_objects[-2:]
        )

    def test_event_with_email_x_mailer_indicator_attribute(self):
        event = get_event_with_email_x_mailer_attribute()
        self._test_event_with_email_x_mailer_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_email_x_mailer_observable_attribute(self):
        event = get_event_with_email_x_mailer_attribute()
        self._test_event_with_email_x_mailer_observable_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-2:]
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
            observed_data = self.parser.stix_objects[-2:]
        )

    def test_event_with_github_username_indicator_attribute(self):
        event = get_event_with_github_username_attribute()
        self._test_event_with_github_username_indicator_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_github_username_observable_attribute(self):
        event = get_event_with_github_username_attribute()
        self._test_event_with_github_username_observable_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            observed_data = self.parser.stix_objects[-2:]
        )

    def test_event_with_hash_composite_indicator_attributes(self):
        event = get_event_with_hash_composite_attributes()
        stix_objects = self._run_indicators_tests(event['Event'])
        for attribute, objects, object_refs, relationship in zip(*stix_objects):
            observed_data, observable, indicator = objects
            _, observable_ref, _ = object_refs
            self._check_hash_composite_indicator_attribute(attribute, indicator)
            self._check_hash_composite_observable_attribute(
                observable_ref, observed_data, observable, attribute
            )
            self._populate_documentation(
                attribute=attribute, indicator=indicator,
                observed_data=[observed_data, observable],
                relationship=relationship
            )

    def test_event_with_hash_composite_observable_attributes(self):
        event = get_event_with_hash_composite_attributes()
        attributes, grouping_refs, observed_datas, observables = self._run_observables_tests(event['Event'])
        for grouping_ref, observed_data, observable, attribute in zip(grouping_refs, observed_datas, observables, attributes):
            self._check_hash_composite_observable_attribute(grouping_ref, observed_data, observable, attribute)
            self._populate_documentation(attribute=attribute, observed_data=[observed_data, observable])

    def test_event_with_hash_indicator_attributes(self):
        event = get_event_with_hash_attributes()
        stix_objects = self._run_indicators_tests(event['Event'])
        for attribute, objects, object_refs, relationship in zip(*stix_objects):
            observed_data, observable, indicator = objects
            _, observable_ref, _ = object_refs
            self._check_hash_indicator_attribute(attribute, indicator)
            self._check_hash_observable_attribute(
                observable_ref, observed_data, observable, attribute
            )
            self._populate_documentation(
                attribute=attribute, indicator=indicator,
                observed_data=[observed_data, observable],
                relationship=relationship
            )

    def test_event_with_hash_observable_attributes(self):
        event = get_event_with_hash_attributes()
        attributes, grouping_refs, observed_datas, observables = self._run_observables_tests(event['Event'])
        for grouping_ref, observed_data, observable, attribute in zip(grouping_refs, observed_datas, observables, attributes):
            self._check_hash_observable_attribute(grouping_ref, observed_data, observable, attribute)
            self._populate_documentation(attribute=attribute, observed_data=[observed_data, observable])

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
            observed_data = self.parser.stix_objects[-2:]
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
            observed_data = self.parser.stix_objects[-3:]
        )

    def test_event_with_http_indicator_attributes(self):
        event = get_event_with_http_attributes()
        attributes, indicators = self._run_indicators_tests(event['Event'], indicator_only=True)
        for attribute, indicator, feature in zip(attributes, indicators, self._http_features):
            self.assertEqual(
                indicator.pattern,
                f"[{self._http_prefix}.{feature} = '{attribute['value']}']"
            )
            self._populate_documentation(attribute=attribute, indicator=indicator)

    def test_event_with_ip_indicator_attributes(self):
        event = get_event_with_ip_attributes()
        stix_objects = self._run_indicators_tests(event['Event'])
        for attribute, objects, object_refs, relationship in zip(*stix_objects):
            observed_data, *observables, indicator = objects
            _, *observable_refs, _ = object_refs
            self._check_ip_indicator_attribute(attribute, indicator)
            self._check_ip_observable_attribute(
                attribute, observable_refs, observed_data, observables
            )
            self._populate_documentation(
                attribute=attribute, indicator=indicator,
                observed_data=[observed_data, *observables],
                relationship=relationship
            )

    def test_event_with_ip_observable_attributes(self):
        event = get_event_with_ip_attributes()
        attributes, grouping_refs, observed_datas, observables = self._run_observables_tests(event['Event'], index=3)
        for attribute, grouping_ref, observed_data, observable in zip(attributes, grouping_refs, observed_datas, observables):
            self._check_ip_observable_attribute(attribute, grouping_ref, observed_data, observable)
            self._populate_documentation(attribute=attribute, observed_data=[observed_data, *observable])

    def test_event_with_ip_port_indicator_attributes(self):
        event = get_event_with_ip_port_attributes()
        stix_objects = self._run_indicators_tests(event['Event'])
        for attribute, objects, object_refs, relationship in zip(*stix_objects):
            observed_data, *observables, indicator = objects
            _, *observable_refs, _ = object_refs
            self._check_ip_port_indicator_attribute(attribute, indicator)
            self._check_ip_port_observable_attribute(
                attribute, observable_refs, observed_data, observables
            )
            self._populate_documentation(
                attribute=attribute, indicator=indicator,
                observed_data=[observed_data, *observables],
                relationship=relationship
            )

    def test_event_with_ip_port_observable_attributes(self):
        event = get_event_with_ip_port_attributes()
        attributes, grouping_refs, observed_datas, observables = self._run_observables_tests(event['Event'], index=3)
        for attribute, grouping_ref, observed_data, observable in zip(attributes, grouping_refs, observed_datas, observables):
            self._check_ip_port_observable_attribute(attribute, grouping_ref, observed_data, observable)
            self._populate_documentation(attribute=attribute, observed_data=[observed_data, *observable])

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
            observed_data = self.parser.stix_objects[-2:]
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
            observed_data = self.parser.stix_objects[-3:]
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
            observed_data = self.parser.stix_objects[-2:]
        )

    def test_event_with_patterning_language_attributes(self):
        event = get_event_with_patterning_language_attributes()
        orgc = event['Event']['Orgc']
        self.parser.parse_misp_event(event)
        attributes = self.parser._misp_event.attributes
        timestamp = self.parser._misp_event.timestamp
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, *indicators = stix_objects
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_grouping_features(grouping, identity_id)
        for attribute, indicator, object_ref in zip(attributes, indicators, object_refs):
            self._check_patterning_language_attribute(attribute, indicator, object_ref, identity_id)
            self._populate_documentation(attribute=attribute, indicator=indicator)

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
            observed_data = self.parser.stix_objects[-2:]
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
            observed_data = self.parser.stix_objects[-2:]
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
        stix_objects = self._run_indicators_tests(event['Event'])
        for attribute, objects, object_refs, relationship in zip(*stix_objects):
            observed_data, observable, indicator = objects
            _, observable_ref, _ = object_refs
            self._check_url_observable_attribute(
                observable_ref, observed_data, observable, attribute
            )
            self.assertEqual(indicator.pattern, f"[url:value = '{attribute['value']}']")
            self._populate_documentation(
                attribute=attribute, indicator=indicator,
                observed_data=[observed_data, observable],
                relationship=relationship
            )

    def test_event_with_url_observable_attributes(self):
        event = get_event_with_url_attributes()
        attributes, grouping_refs, observed_datas, observables = self._run_observables_tests(event['Event'])
        for grouping_ref, observed_data, observable, attribute in zip(grouping_refs, observed_datas, observables, attributes):
            self._check_url_observable_attribute(grouping_ref, observed_data, observable, attribute)
            self._populate_documentation(attribute=attribute, observed_data=[observed_data, observable])

    def test_event_with_vulnerability_attribute(self):
        event = get_event_with_vulnerability_attribute()
        self._test_event_with_vulnerability_attribute(event['Event'])
        self._populate_documentation(
            attribute = event['Event']['Attribute'][0],
            vulnerability = self.parser.stix_objects[-1]
        )

    def test_event_with_x509_fingerprint_indicator_attributes(self):
        event = get_event_with_x509_fingerprint_attributes()
        stix_objects = self._run_indicators_tests(event['Event'])
        for attribute, objects, object_refs, relationship in zip(*stix_objects):
            observed_data, observable, indicator = objects
            _, observable_ref, _ = object_refs
            self._check_x509_fingerprint_observable_attribute(
                observable_ref, observed_data, observable, attribute
            )
            hash_type = attribute['type'].split('-')[-1].upper()
            self.assertEqual(
                indicator.pattern,
                f"[x509-certificate:hashes.{hash_type} = '{attribute['value']}']"
            )
            self._populate_documentation(
                attribute=attribute, indicator=indicator,
                observed_data=[observed_data, observable],
                relationship=relationship
            )

    def test_event_with_x509_fingerprint_observable_attributes(self):
        event = get_event_with_x509_fingerprint_attributes()
        attributes, grouping_refs, observed_datas, observables = self._run_observables_tests(event['Event'])
        for grouping_ref, observed_data, observable, attribute in zip(grouping_refs, observed_datas, observables, attributes):
            self._check_x509_fingerprint_observable_attribute(grouping_ref, observed_data, observable, attribute)
            self._populate_documentation(attribute=attribute, observed_data=[observed_data, observable])


class TestSTIX21MISPAttributesExport(TestSTIX21AttributesExport):
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

    def test_event_with_email_message_id_indicator_attribute(self):
        event = get_event_with_email_message_id_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_email_message_id_indicator_attribute(misp_event)

    def test_event_with_email_message_id_observable_attribute(self):
        event = get_event_with_email_message_id_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_email_message_id_observable_attribute(misp_event)

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

    def test_event_with_email_x_mailer_observable_attribute(self):
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
        self._test_event_with_github_username_indicator_attribute(misp_event)

    def test_event_with_github_username_observable_attribute(self):
        event = get_event_with_github_username_attribute()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_github_username_observable_attribute(misp_event)

    def test_event_with_hash_composite_indicator_attributes(self):
        event = get_event_with_hash_composite_attributes()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        stix_objects = self._run_indicators_tests(misp_event)
        for attribute, stix_objects, object_refs, _ in zip(*stix_objects):
            observed_data, observable, indicator = stix_objects
            _, observable_ref, _ = object_refs
            self._check_hash_composite_indicator_attribute(attribute, indicator)
            self._check_hash_composite_observable_attribute(
                observable_ref, observed_data, observable, attribute
            )

    def test_event_with_hash_composite_observable_attributes(self):
        event = get_event_with_hash_composite_attributes()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        attributes, grouping_refs, observed_datas, observables = self._run_observables_tests(misp_event)
        for grouping_ref, observed_data, observable, attribute in zip(grouping_refs, observed_datas, observables, attributes):
            self._check_hash_composite_observable_attribute(grouping_ref, observed_data, observable, attribute)

    def test_event_with_hash_indicator_attributes(self):
        event = get_event_with_hash_attributes()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        stix_objects = self._run_indicators_tests(misp_event)
        for attribute, objects, object_refs, _ in zip(*stix_objects):
            observed_data, observable, indicator = objects
            _, observable_ref, _ = object_refs
            self._check_hash_indicator_attribute(attribute, indicator)
            self._check_hash_observable_attribute(
                observable_ref, observed_data, observable, attribute
            )

    def test_event_with_hash_observable_attributes(self):
        event = get_event_with_hash_attributes()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        attributes, grouping_refs, observed_datas, observables = self._run_observables_tests(misp_event)
        for grouping_ref, observed_data, observable, attribute in zip(grouping_refs, observed_datas, observables, attributes):
            self._check_hash_observable_attribute(grouping_ref, observed_data, observable, attribute)

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
        for attribute, objects, object_refs, _ in zip(*stix_objects):
            observed_data, *observables, indicator = objects
            _, *observable_refs, _ = object_refs
            self._check_ip_indicator_attribute(attribute, indicator)
            self._check_ip_observable_attribute(
                attribute, observable_refs, observed_data, observables
            )

    def test_event_with_ip_observable_attributes(self):
        event = get_event_with_ip_attributes()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        attributes, grouping_refs, observed_datas, observables = self._run_observables_tests(misp_event, index=3)
        for attribute, grouping_ref, observed_data, observable in zip(attributes, grouping_refs, observed_datas, observables):
            self._check_ip_observable_attribute(attribute, grouping_ref, observed_data, observable)

    def test_event_with_ip_port_indicator_attributes(self):
        event = get_event_with_ip_port_attributes()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        stix_objects = self._run_indicators_tests(misp_event)
        for attribute, objects, object_refs, _ in zip(*stix_objects):
            observed_data, *observables, indicator = objects
            _, *observable_refs, _ = object_refs
            self._check_ip_port_indicator_attribute(attribute, indicator)
            self._check_ip_port_observable_attribute(
                attribute, observable_refs, observed_data, observables
            )

    def test_event_with_ip_port_observable_attributes(self):
        event = get_event_with_ip_port_attributes()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        attributes, grouping_refs, observed_datas, observables = self._run_observables_tests(misp_event, index=3)
        for attribute, grouping_ref, observed_data, observable in zip(attributes, grouping_refs, observed_datas, observables):
            self._check_ip_port_observable_attribute(attribute, grouping_ref, observed_data, observable)

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

    def test_event_with_patterning_language_attributes(self):
        event = get_event_with_patterning_language_attributes()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self.parser.parse_misp_event(misp_event)
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, *indicators = stix_objects
        identity_id = self._check_identity_features(identity, misp_event.orgc, misp_event.timestamp)
        object_refs = self._check_grouping_features(grouping, identity_id)
        for attribute, indicator, object_ref in zip(misp_event.attributes, indicators, object_refs):
            self._check_patterning_language_attribute(attribute, indicator, object_ref, identity_id)

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
        for attribute, objects, object_refs, _ in zip(*stix_objects):
            observed_data, observable, indicator = objects
            _, observable_ref, _ = object_refs
            self._check_url_observable_attribute(
                observable_ref, observed_data, observable, attribute
            )
            self.assertEqual(indicator.pattern, f"[url:value = '{attribute['value']}']")

    def test_event_with_url_observable_attributes(self):
        event = get_event_with_url_attributes()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        attributes, grouping_refs, observed_datas, observables = self._run_observables_tests(misp_event)
        for grouping_ref, observed_data, observable, attribute in zip(grouping_refs, observed_datas, observables, attributes):
            self._check_url_observable_attribute(grouping_ref, observed_data, observable, attribute)

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
        for attribute, objects, object_refs, _ in zip(*stix_objects):
            observed_data, observable, indicator = objects
            _, observable_ref, _ = object_refs
            self._check_x509_fingerprint_observable_attribute(
                observable_ref, observed_data, observable, attribute
            )
            hash_type = attribute['type'].split('-')[-1].upper()
            self.assertEqual(
                indicator.pattern,
                f"[x509-certificate:hashes.{hash_type} = '{attribute['value']}']"
            )

    def test_event_with_x509_fingerprint_observable_attributes(self):
        event = get_event_with_x509_fingerprint_attributes()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        attributes, grouping_refs, observed_datas, observables = self._run_observables_tests(misp_event)
        for grouping_ref, observed_data, observable, attribute in zip(grouping_refs, observed_datas, observables, attributes):
            self._check_x509_fingerprint_observable_attribute(grouping_ref, observed_data, observable, attribute)


class TestSTIX21ObjectsExport(TestSTIX21GenericExport):
    def _check_account_indicator_objects(self, misp_objects, patterns):
        gitlab_object, telegram_object = misp_objects
        gitlab_pattern, telegram_pattern = patterns
        gitlab_id = gitlab_object['Attribute'][0]['value']
        account_type, user_id = gitlab_pattern[1:-1].split(' AND ')
        self.assertEqual(account_type, f"user-account:account_type = 'gitlab'")
        self.assertEqual(user_id, f"user-account:user_id = '{gitlab_id}'")
        telegram_id = telegram_object['Attribute'][0]['value']
        account_type, user_id = telegram_pattern[1:-1].split(' AND ')
        self.assertEqual(account_type, "user-account:account_type = 'telegram'")
        self.assertEqual(user_id, f"user-account:user_id = '{telegram_id}'")

    def _check_account_observable_objects(self, misp_objects, observables, object_refs):
        for object_ref, observable, misp_object in zip(object_refs, observables, misp_objects):
            self._assert_multiple_equal(
                observable[1].id, object_ref[1],
                f"user-account--{misp_object['uuid']}"
            )
        gitlab_object, telegram_object = misp_objects
        gitlab, telegram = observables
        gitlab_id, name, username = (attribute['value'] for attribute in gitlab_object['Attribute'])
        gitlab = gitlab[1]
        self.assertEqual(gitlab.type, 'user-account')
        self.assertEqual(gitlab.account_type, 'gitlab')
        self.assertEqual(gitlab.user_id, gitlab_id)
        self.assertEqual(gitlab.display_name, name)
        self.assertEqual(gitlab.account_login, username)
        telegram_id, username, phone1, phone2 = (attribute['value'] for attribute in telegram_object['Attribute'])
        telegram = telegram[1]
        self.assertEqual(telegram.type, 'user-account')
        self.assertEqual(telegram.account_type, 'telegram')
        self.assertEqual(telegram.user_id, telegram_id)
        self.assertEqual(telegram.account_login, username)
        self.assertEqual(telegram.x_misp_phone, [phone1, phone2])

    def _check_account_with_attachment_indicator_objects(self, misp_objects, patterns):
        facebook_account, github_user, parler_account, reddit_account, twitter_account = misp_objects
        facebook_pattern, github_pattern, parler_pattern, reddit_pattern, twitter_pattern = patterns
        account_id = facebook_account['Attribute'][0]['value']
        account_type, user_id = facebook_pattern[1:-1].split(' AND ')
        self.assertEqual(account_type, f"user-account:account_type = 'facebook'")
        self.assertEqual(user_id, f"user-account:user_id = '{account_id}'")
        github_id = github_user['Attribute'][0]['value']
        account_type, user_id = github_pattern[1:-1].split(' AND ')
        self.assertEqual(account_type, "user-account:account_type = 'github'")
        self.assertEqual(user_id, f"user-account:user_id = '{github_id}'")
        parler_id = parler_account['Attribute'][0]['value']
        account_type, user_id = parler_pattern[1:-1].split(' AND ')
        self.assertEqual(account_type, f"user-account:account_type = 'parler'")
        self.assertEqual(user_id, f"user-account:user_id = '{parler_id}'")
        reddit_id = reddit_account['Attribute'][0]['value']
        account_type, user_id = reddit_pattern[1:-1].split(' AND ')
        self.assertEqual(account_type, f"user-account:account_type = 'reddit'")
        self.assertEqual(user_id, f"user-account:user_id = '{reddit_id}'")
        _id = twitter_account['Attribute'][0]['value']
        account_type, user_id = twitter_pattern[1:-1].split(' AND ')
        self.assertEqual(account_type, f"user-account:account_type = 'twitter'")
        self.assertEqual(user_id, f"user-account:user_id = '{_id}'")

    def _check_account_with_attachment_observable_objects(self, misp_objects, observables, object_refs):
        for object_ref, observable, misp_object in zip(object_refs, observables, misp_objects):
            self._assert_multiple_equal(
                observable[1].id, object_ref[1],
                f"user-account--{misp_object['uuid']}"
            )
        facebook_account, github_user, parler_account, reddit_account, twitter_account = misp_objects
        facebook, github, parler, reddit, twitter = observables
        account_id, account_name, link, user_avatar = facebook_account['Attribute']
        facebook = facebook[1]
        self.assertEqual(facebook.type, 'user-account')
        self.assertEqual(facebook.account_type, 'facebook')
        self.assertEqual(facebook.user_id, account_id['value'])
        self.assertEqual(facebook.account_login, account_name['value'])
        self.assertEqual(facebook.x_misp_link, link['value'])
        self.assertEqual(facebook.x_misp_user_avatar['value'], user_avatar['value'])
        data = user_avatar['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(facebook.x_misp_user_avatar['data'], data)
        github_id, username, fullname, organisation, image = (attribute['value'] for attribute in github_user['Attribute'])
        github = github[1]
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
        parler = parler[1]
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
        reddit = reddit[1]
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
        twitter = twitter[1]
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

    def _check_android_app_observable_object(self, misp_object, software, object_ref):
        name, certificate, domain = (
            attribute['value'] for attribute in misp_object['Attribute']
        )
        self.assertEqual(software.type, 'software')
        self._assert_multiple_equal(
            software.id, object_ref, f"software--{misp_object['uuid']}"
        )
        self.assertEqual(software.name, name)
        self.assertEqual(software.x_misp_certificate, certificate)
        self.assertEqual(software.x_misp_domain, domain)

    def _check_asn_observable_object(self, misp_object, autonomous_system, object_ref):
        asn, description, subnet1, subnet2 = (
            attribute['value'] for attribute in misp_object['Attribute']
        )
        self._assert_multiple_equal(
            autonomous_system.id, object_ref,
            f"autonomous-system--{misp_object['uuid']}"
        )
        self.assertEqual(autonomous_system.type, 'autonomous-system')
        self.assertEqual(autonomous_system.number, int(asn[2:]))
        self.assertEqual(autonomous_system.name, description)
        self.assertEqual(
            autonomous_system.x_misp_subnet_announced,
            [subnet1, subnet2]
        )

    def _check_cpe_asset_observable_object(self, misp_object, software, object_ref):
        cpe, language, product, vendor, version, description = (
            attribute['value'] for attribute in misp_object['Attribute']
        )
        self._assert_multiple_equal(
            software.id, object_ref, f"software--{misp_object['uuid']}"
        )
        self.assertEqual(software.type, 'software')
        self.assertEqual(software.cpe, cpe)
        self.assertEqual(software.name, product)
        self.assertEqual(software.languages, [language])
        self.assertEqual(software.vendor, vendor)
        self.assertEqual(software.version, version)
        self.assertEqual(software.x_misp_description, description)

    def _check_credential_observable_object(self, misp_object, user_account, object_ref):
        text, username, password, *attributes = misp_object['Attribute']
        self._assert_multiple_equal(
            user_account.id, object_ref,
            f"user-account--{misp_object['uuid']}"
        )
        self.assertEqual(user_account.type, 'user-account')
        self.assertEqual(user_account.user_id, username['value'])
        self.assertEqual(user_account.credential, password['value'])
        for attribute in (text, *attributes):
            self.assertEqual(
                getattr(user_account, f"x_misp_{attribute['object_relation']}"),
                attribute['value']
            )

    def _check_domain_ip_observable_object(self, misp_object, observables, object_refs):
        _domain, hostname, _ip, port = misp_object['Attribute']
        domain_ref, ip_ref = object_refs
        domain_, address = observables
        self._assert_multiple_equal(
            domain_.id, domain_ref, f"domain-name--{misp_object['uuid']}"
        )
        self.assertEqual(domain_.type, 'domain-name')
        self.assertEqual(domain_.value, _domain['value'])
        self.assertEqual(domain_.x_misp_hostname, hostname['value'])
        self.assertEqual(domain_.x_misp_port, port['value'])
        self._assert_multiple_equal(
            address.id, domain_.resolves_to_refs[0], ip_ref,
            f"ipv4-addr--{_ip['uuid']}"
        )
        self.assertEqual(address.type, 'ipv4-addr')
        self.assertEqual(address.value, _ip['value'])

    def _check_email_observable_object(self, misp_object, observables, object_refs):
        (_from, _from_dn, _to, _to_dn, _cc1, _cc1_dn, _cc2, _cc2_dn, _bcc,
         _bcc_dn, _reply_to, _subject, _attachment1, _attachment2, _x_mailer,
         _user_agent, _boundary, _message_id) = misp_object['Attribute']
        (message, address1, address2, address3,
         address4, address5, file1, file2) = observables
        (message_ref, address1_ref, address2_ref, address3_ref,
         address4_ref, address5_ref, file1_ref, file2_ref) = object_refs
        self._assert_multiple_equal(
            message.id, message_ref, f"email-message--{misp_object['uuid']}"
        )
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, True)
        self.assertEqual(message.subject, _subject['value'])
        self.assertEqual(message.message_id, _message_id['value'])
        additional_header = message.additional_header_fields
        self.assertEqual(additional_header['Reply-To'], _reply_to['value'])
        self.assertEqual(additional_header['X-Mailer'], _x_mailer['value'])
        self.assertEqual(message.x_misp_mime_boundary, _boundary['value'])
        self.assertEqual(message.x_misp_user_agent, _user_agent['value'])
        self.assertEqual(message.from_ref, address1_ref)
        self.assertEqual(message.to_refs, [address2_ref])
        self.assertEqual(message.cc_refs, [address3_ref, address4_ref])
        self.assertEqual(message.bcc_refs, [address5_ref])
        self._assert_multiple_equal(
            message.from_ref, address1.id, address1_ref,
            f"email-addr--{_from['uuid']}"
        )
        self._check_email_address(address1, _from['value'], display_name=_from_dn['value'])
        self._assert_multiple_equal(
            message.to_refs[0], address2.id, address2_ref,
            f"email-addr--{_to['uuid']}"
        )
        self._check_email_address(address2, _to['value'], display_name=_to_dn['value'])
        self._assert_multiple_equal(
            message.cc_refs[0], address3.id, address3_ref,
            f"email-addr--{_cc1['uuid']}"
        )
        self._check_email_address(address3, _cc1['value'], display_name=_cc1_dn['value'])
        self._assert_multiple_equal(
            message.cc_refs[1], address4.id, address4_ref,
            f"email-addr--{_cc2['uuid']}"
        )
        self._check_email_address(address4, _cc2['value'], display_name=_cc2_dn['value'])
        self._assert_multiple_equal(
            message.bcc_refs[0], address5.id, address5_ref,
            f"email-addr--{_bcc['uuid']}"
        )
        self._check_email_address(address5, _bcc['value'], display_name=_bcc_dn['value'])
        body1, body2 = message.body_multipart
        self.assertEqual(
            body1['content_disposition'],
            f"attachment; filename='{_attachment1['value']}'"
        )
        self.assertEqual(
            body2['content_disposition'],
            f"attachment; filename='{_attachment2['value']}'"
        )
        self._assert_multiple_equal(
            body1['body_raw_ref'], file1.id, file1_ref,
            f"file--{_attachment1['uuid']}"
        )
        self.assertEqual(file1.type, 'file')
        self.assertEqual(file1.name, _attachment1['value'])
        self._assert_multiple_equal(
            body2['body_raw_ref'], file2.id, file2_ref,
            f"file--{_attachment2['uuid']}"
        )
        self.assertEqual(file2.type, 'file')
        self.assertEqual(file2.name, _attachment2['value'])

    def _check_email_with_display_names_observable_object(self, misp_object, observables, object_refs):
        _from, _from_name, _to, _to_name, _cc1, _cc2_name, _bcc, _bcc_name = misp_object['Attribute']
        message, from_, to_, cc_, bcc_ = observables
        message_ref, from_ref, to_ref, cc_ref, bcc_ref = object_refs
        self._assert_multiple_equal(
            message.id, message_ref, f"email-message--{misp_object['uuid']}"
        )
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self._assert_multiple_equal(
            message.from_ref, from_.id, from_ref, f"email-addr--{_from['uuid']}"
        )
        self._check_email_address(from_, _from['value'], display_name=_from_name['value'])
        self._assert_multiple_equal(
            message.to_refs[0], to_.id, to_ref, f"email-addr--{_to['uuid']}"
        )
        self._check_email_address(to_, _to['value'], display_name=_to_name['value'])
        self._assert_multiple_equal(
            message.cc_refs[0], cc_.id, cc_ref, f"email-addr--{_cc1['uuid']}"
        )
        self._check_email_address(cc_, _cc1['value'])
        self.assertEqual(message.x_misp_cc_display_name, _cc2_name['value'])
        self._assert_multiple_equal(
            message.bcc_refs[0], bcc_.id, bcc_ref, f"email-addr--{_bcc['uuid']}"
        )
        self._check_email_address(bcc_, _bcc['value'], display_name=_bcc_name['value'])

    def _check_file_and_pe_observable_object(self, _file, file_object, pe, section):
        filename, md5, sha1, sha256, size, entropy = (
            attribute['value'] for attribute in file_object['Attribute']
        )
        self.assertEqual(_file.type, 'file')
        self.assertEqual(_file.name, filename)
        hashes = _file.hashes
        self.assertEqual(hashes['MD5'], md5)
        self.assertEqual(hashes['SHA-1'], sha1)
        self.assertEqual(hashes['SHA-256'], sha256)
        self.assertEqual(_file.size, int(size))
        self.assertEqual(_file.x_misp_entropy, entropy)
        self._check_pe_and_section_observable(
            _file.extensions['windows-pebinary-ext'], pe, section
        )

    def _check_file_observable_object(self, misp_object, observables, object_refs):
        (_malware_sample, _filename, _md5, _sha1, _sha256, _size, _attachment,
         _path, _encoding, ctime, mtime) = misp_object['Attribute']
        _file, directory, artifact = observables
        file_ref, directory_ref, artifact_ref = object_refs
        self._assert_multiple_equal(
            _file.id, file_ref, f"file--{misp_object['uuid']}"
        )
        self.assertEqual(_file.type, 'file')
        self.assertEqual(_file.size, int(_size['value']))
        self.assertEqual(_file.name, _filename['value'])
        self.assertEqual(_file.name_enc, _encoding['value'])
        creation_time = ctime['value']
        if not isinstance(creation_time, datetime):
            creation_time = self._datetime_from_str(creation_time)
        self.assertEqual(_file.ctime, creation_time)
        modification_time = mtime['value']
        if not isinstance(modification_time, datetime):
            modification_time = self._datetime_from_str(modification_time)
        self.assertEqual(_file.mtime, modification_time)
        hashes = _file.hashes
        self.assertEqual(hashes['MD5'], _md5['value'])
        self.assertEqual(hashes['SHA-1'], _sha1['value'])
        self.assertEqual(hashes['SHA-256'], _sha256['value'])
        self.assertEqual(_file.x_misp_attachment['value'], _attachment['value'])
        data = _attachment['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(_file.x_misp_attachment['data'], data)
        self.assertEqual(_file.content_ref, artifact_ref)
        self._assert_multiple_equal(
            _file.parent_directory_ref, directory.id, directory_ref,
            f"directory--{_path['uuid']}"
        )
        self.assertEqual(directory.type, 'directory')
        self.assertEqual(directory.path, _path['value'])
        self._assert_multiple_equal(
            _file.content_ref, artifact.id, artifact_ref,
            f"artifact--{_malware_sample['uuid']}"
        )
        self.assertEqual(artifact.type, 'artifact')
        data = _malware_sample['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(artifact.payload_bin, data)
        filename, md5 = _malware_sample['value'].split('|')
        self.assertEqual(artifact.hashes['MD5'], md5)
        self.assertEqual(artifact.x_misp_filename, filename)

    def _check_http_request_observable_object(self, misp_object, observables, object_refs):
        ip_src, ip_dst, host, method, user_agent, uri, url, content = misp_object['Attribute']
        network_traffic, src_address, dst_address, domain_name = observables
        network_traffic_ref, src_address_ref, dst_address_ref, domain_name_ref = object_refs
        self.assertEqual(network_traffic.type, 'network-traffic')
        self._assert_multiple_equal(
            network_traffic.id, network_traffic_ref,
            f"network-traffic--{misp_object['uuid']}"
        )
        extension = network_traffic.extensions['http-request-ext']
        self.assertEqual(extension.request_method, method['value'])
        self.assertEqual(extension.request_value, uri['value'])
        self.assertEqual(extension.request_header['Content-Type'], content['value'])
        self.assertEqual(extension.request_header['User-Agent'], user_agent['value'])
        self.assertEqual(network_traffic.x_misp_url, url['value'])
        self.assertEqual(src_address.type, 'ipv4-addr')
        self._assert_multiple_equal(
            src_address.id, src_address_ref, network_traffic.src_ref,
            f"ipv4-addr--{ip_src['uuid']}"
        )
        self.assertEqual(src_address.value, ip_src['value'])
        self.assertEqual(dst_address.type, 'ipv4-addr')
        self._assert_multiple_equal(
            dst_address.id, dst_address_ref, network_traffic.dst_ref,
            domain_name.resolves_to_refs[0], f"ipv4-addr--{ip_dst['uuid']}"
        )
        self.assertEqual(dst_address.value, ip_dst['value'])
        self.assertEqual(domain_name.type, 'domain-name')
        self._assert_multiple_equal(
            domain_name.id, domain_name_ref, f"domain-name--{host['uuid']}"
        )
        self.assertEqual(domain_name.value, host['value'])

    def _check_image_observable_object(self, misp_object, observables, object_refs):
        attachment, filename, url, text = misp_object['Attribute']
        _file, artifact = observables
        file_ref, artifact_ref = object_refs
        self.assertEqual(_file.type, 'file')
        self._assert_multiple_equal(
            _file.id, file_ref, f"file--{misp_object['uuid']}"
        )
        self.assertEqual(_file.name, filename['value'])
        self._assert_multiple_equal(
            _file.content_ref, artifact.id, artifact_ref,
            f"artifact--{attachment['uuid']}"
        )
        self.assertEqual(artifact.type, 'artifact')
        data = attachment['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(artifact.payload_bin, data)
        self.assertEqual(artifact.mime_type, 'image/png')
        self.assertEqual(artifact.x_misp_url, url['value'])
        self.assertEqual(artifact.x_misp_filename, attachment['value'])
        self.assertEqual(_file.x_misp_image_text, text['value'])

    def _check_ip_port_observable_object(self, misp_object, observables, object_refs):
        ip, port, domain, first_seen = misp_object['Attribute']
        network_traffic_ref, address_ref = object_refs
        network_traffic, address_object = observables
        self._assert_multiple_equal(
            network_traffic.id, network_traffic_ref,
            f"network-traffic--{misp_object['uuid']}"
        )
        self.assertEqual(network_traffic.type, 'network-traffic')
        self.assertEqual(network_traffic.dst_port, int(port['value']))
        timestamp = first_seen['value']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_str(timestamp)
        self.assertEqual(network_traffic.start, timestamp)
        self.assertIn('ipv4', network_traffic.protocols)
        self.assertEqual(network_traffic.x_misp_domain, domain['value'])
        self._assert_multiple_equal(
            network_traffic.dst_ref, address_object.id, address_ref,
            f"ipv4-addr--{ip['uuid']}"
        )
        self.assertEqual(address_object.type, 'ipv4-addr')
        self.assertEqual(address_object.value, ip['value'])

    def _check_lnk_observable_object(self, misp_object, observables, object_refs):
        (filename, fullpath, md5, sha1, sha256, malware_sample, size_in_bytes,
         creation, modification, access) = misp_object['Attribute']
        file_ref, directory_ref, artifact_ref = object_refs
        _file, directory, artifact = observables
        self.assertEqual(_file.type, 'file')
        self._assert_multiple_equal(
            _file.id, file_ref, f"file--{misp_object['uuid']}"
        )
        self.assertEqual(_file.name, filename['value'])
        self.assertEqual(_file.hashes['MD5'], md5['value'])
        self.assertEqual(_file.hashes['SHA-1'], sha1['value'])
        self.assertEqual(_file.hashes['SHA-256'], sha256['value'])
        self.assertEqual(_file.size, int(size_in_bytes['value']))
        creation_time = creation['value']
        if not isinstance(creation_time, datetime):
            creation_time = self._datetime_from_str(creation_time)
        self.assertEqual(_file.ctime, creation_time)
        modification_time = modification['value']
        if not isinstance(modification_time, datetime):
            modification_time = self._datetime_from_str(modification_time)
        self.assertEqual(_file.mtime, modification_time)
        access_time = access['value']
        if not isinstance(access_time, datetime):
            access_time = self._datetime_from_str(access_time)
        self.assertEqual(_file.atime, access_time)
        self.assertEqual(directory.type, 'directory')
        self._assert_multiple_equal(
            _file.parent_directory_ref, directory.id, directory_ref,
            f"directory--{fullpath['uuid']}"
        )
        self.assertEqual(directory.path, fullpath['value'])
        self.assertEqual(artifact.type, 'artifact')
        self._assert_multiple_equal(
            _file.content_ref, artifact.id, artifact_ref,
            f"artifact--{malware_sample['uuid']}"
        )
        data = malware_sample['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(artifact.payload_bin, data)
        self.assertEqual(artifact.mime_type, 'application/zip')
        filename, md5 = malware_sample['value'].split('|')
        self.assertEqual(artifact.x_misp_filename, filename)
        self.assertEqual(artifact.hashes['MD5'], md5)

    def _check_mutex_observable_object(self, misp_object, mutex, object_ref):
        name, description, _os = (
            attribute['value'] for attribute in misp_object['Attribute']
        )
        self._assert_multiple_equal(
            mutex.id,object_ref, f"mutex--{misp_object['uuid']}"
        )
        self.assertEqual(mutex.type, 'mutex')
        self.assertEqual(mutex.name, name)
        self.assertEqual(mutex.x_misp_description, description)
        self.assertEqual(mutex.x_misp_operating_system, _os)

    def _check_netflow_observable_object(self, misp_object, observables, object_refs):
        (ip_src, ip_dst, src_as, dst_as, src_port, dst_port,
         protocol, first_seen, tcp_flags) = misp_object['Attribute']
        network_traffic, src_address, src_autonomous_system, dst_address, dst_autonomous_system = observables
        network_traffic_ref, src_address_ref, src_autonomous_system_ref, dst_address_ref, dst_autonomous_system_ref = object_refs
        self.assertEqual(network_traffic.type, 'network-traffic')
        self._assert_multiple_equal(
            network_traffic.id, network_traffic_ref,
            f"network-traffic--{misp_object['uuid']}"
        )
        timestamp = first_seen['value']
        if isinstance(timestamp, str):
            timestamp = self._datetime_from_str(timestamp)
        self.assertEqual(network_traffic.start, timestamp)
        self.assertEqual(network_traffic.src_port, int(src_port['value']))
        self.assertEqual(network_traffic.dst_port, int(dst_port['value']))
        self.assertEqual(set(network_traffic.protocols), {protocol['value'].lower(), 'tcp'})
        self.assertEqual(network_traffic.extensions['tcp-ext'].src_flags_hex, tcp_flags['value'])
        self._assert_multiple_equal(
            src_address.type, dst_address.type, 'ipv4-addr'
        )
        self._assert_multiple_equal(
            src_autonomous_system.type, dst_autonomous_system.type,
            'autonomous-system'
        )
        self._assert_multiple_equal(
            network_traffic.src_ref, src_address.id, src_address_ref,
            f"ipv4-addr--{ip_src['uuid']}"
        )
        self.assertEqual(src_address.value, ip_src['value'])
        self._assert_multiple_equal(
            src_address.belongs_to_refs[0], src_autonomous_system.id,
            src_autonomous_system_ref, f"autonomous-system--{src_as['uuid']}"
        )
        self.assertEqual(src_autonomous_system.number, self._parse_AS_value(src_as['value']))
        self._assert_multiple_equal(
            network_traffic.dst_ref, dst_address.id, dst_address_ref,
            f"ipv4-addr--{ip_dst['uuid']}"
        )
        self.assertEqual(dst_address.value, ip_dst['value'])
        self._assert_multiple_equal(
            dst_address.belongs_to_refs[0], dst_autonomous_system.id,
            dst_autonomous_system_ref, f"autonomous-system--{dst_as['uuid']}"
        )
        self.assertEqual(dst_autonomous_system.number, self._parse_AS_value(dst_as['value']))

    def _check_network_connection_observable_object(self, misp_object, observables, object_refs):
        ip_src, ip_dst, src_port, dst_port, hostname, layer3, layer4, layer7 = (
            attribute['value'] for attribute in misp_object['Attribute']
        )
        network_traffic, address1, address2 = observables
        network_traffic_ref, address1_ref, address2_ref = object_refs
        self._assert_multiple_equal(
            network_traffic.id, network_traffic_ref,
            f"network-traffic--{misp_object['uuid']}"
        )
        self.assertEqual(network_traffic.type, 'network-traffic')
        self.assertEqual(network_traffic.src_port, int(src_port))
        self.assertEqual(network_traffic.dst_port, int(dst_port))
        self.assertEqual(
            network_traffic.protocols,
            [layer3.lower(), layer4.lower(), layer7.lower()]
        )
        self.assertEqual(network_traffic.x_misp_hostname_dst, hostname)
        self._assert_multiple_equal(
            network_traffic.src_ref, address1.id, address1_ref
        )
        self.assertEqual(address1.type, 'ipv4-addr')
        self.assertEqual(address1.value, ip_src)
        self._assert_multiple_equal(
            network_traffic.dst_ref, address2.id, address2_ref
        )
        self.assertEqual(address2.type, 'ipv4-addr')
        self.assertEqual(address2.value, ip_dst)

    def _check_network_socket_observable_object(self, misp_object, observables, object_refs):
        (ip_src, ip_dst, src_port, dst_port, hostname, address_family,
         domain_family, socket_type, state, protocol) = misp_object['Attribute']
        network_traffic, address1, address2 = observables
        network_traffic_ref, address1_ref, address2_ref = object_refs
        self._assert_multiple_equal(
            network_traffic.id, network_traffic_ref,
            f"network-traffic--{misp_object['uuid']}"
        )
        self.assertEqual(network_traffic.type, 'network-traffic')
        self.assertEqual(network_traffic.src_port, int(src_port['value']))
        self.assertEqual(network_traffic.dst_port, int(dst_port['value']))
        self.assertEqual(network_traffic.protocols, [protocol['value'].lower()])
        socket_ext = network_traffic.extensions['socket-ext']
        self.assertEqual(socket_ext.address_family, address_family['value'])
        self.assertEqual(socket_ext.socket_type, socket_type['value'])
        self.assertEqual(getattr(socket_ext, f"is_{state['value']}"), True)
        self.assertEqual(network_traffic.x_misp_domain_family, domain_family['value'])
        self.assertEqual(network_traffic.x_misp_hostname_dst, hostname['value'])
        self._assert_multiple_equal(
            network_traffic.src_ref, address1.id, address1_ref,
            f"ipv4-addr--{ip_src['uuid']}"
        )
        self.assertEqual(address1.type, 'ipv4-addr')
        self.assertEqual(address1.value, ip_src['value'])
        self._assert_multiple_equal(
            network_traffic.dst_ref, address2.id, address2_ref,
            f"ipv4-addr--{ip_dst['uuid']}"
        )
        self.assertEqual(address2.type, 'ipv4-addr')
        self.assertEqual(address2.value, ip_dst['value'])

    def _check_process_observable_object(self, misp_object, observables, object_refs):
        (pid, child_pid, parent_pid, name, image, parent_image, port,
         _, command_line, parent_name) = misp_object['Attribute']
        process, parent_image_object, parent_process, child_process, image_object = observables
        process_ref, parent_image_ref, parent_ref, child_ref, image_ref = object_refs
        self._assert_multiple_equal(
            process.id, process_ref, f"process--{misp_object['uuid']}"
        )
        self.assertEqual(process.type, 'process')
        self.assertEqual(process.pid, int(pid['value']))
        self.assertEqual(process.is_hidden, True)
        self.assertEqual(process.x_misp_name, name['value'])
        self.assertEqual(process.x_misp_port, port['value'])
        self._assert_multiple_equal(
            parent_process.image_ref, parent_image_object.id,
            parent_image_ref, f"file--{parent_image['uuid']}"
        )
        self.assertEqual(parent_image_object.type, 'file')
        self.assertEqual(parent_image_object.name, parent_image['value'])
        self._assert_multiple_equal(
            process.parent_ref, parent_process.id, parent_ref,
            f"process--{parent_pid['uuid']}"
        )
        self.assertEqual(parent_process.type, 'process')
        self.assertEqual(parent_process.pid, int(parent_pid['value']))
        self.assertEqual(parent_process.command_line, command_line['value'])
        self.assertEqual(parent_process.x_misp_process_name, parent_name['value'])
        self._assert_multiple_equal(
            process.child_refs[0], child_process.id, child_ref,
            f"process--{child_pid['uuid']}"
        )
        self.assertEqual(child_process.type, 'process')
        self.assertEqual(child_process.pid, int(child_pid['value']))
        self._assert_multiple_equal(
            process.image_ref, image_object.id, image_ref,
            f"file--{image['uuid']}"
        )
        self.assertEqual(image_object.type, 'file')
        self.assertEqual(image_object.name, image['value'])

    def _check_registry_key_observable_object(self, misp_object, registry_key, object_ref):
        key, hive, name, data, data_type, modified = (
            attribute['value'] for attribute in misp_object['Attribute']
        )
        self._assert_multiple_equal(
            registry_key.id, object_ref,
            f"windows-registry-key--{misp_object['uuid']}"
        )
        self.assertEqual(registry_key.type, 'windows-registry-key')
        self.assertEqual(registry_key.key, key)
        if not isinstance(modified, datetime):
            modified = self._datetime_from_str(modified)
        self.assertEqual(
            registry_key.modified_time.timestamp(),
            modified.timestamp()
        )
        self.assertEqual(registry_key.x_misp_hive, hive)
        registry_value = registry_key['values'][0]
        self.assertEqual(registry_value.data, data)
        self.assertEqual(registry_value.data_type, data_type)
        self.assertEqual(registry_value.name, name)

    def _check_SCO(self, observable_object, attribute, reference, feature):
        self.assertEqual(observable_object.id, reference)
        self.assertEqual(observable_object.type, feature)
        self.assertEqual(observable_object.id, f"{feature}--{attribute['uuid']}")
        self.assertEqual(observable_object.value, attribute['value'])

    def _check_url_observable_object(self, misp_object, url_object, object_ref):
        url, domain, host, ip, port = (
            attribute['value'] for attribute in misp_object['Attribute']
        )
        self._assert_multiple_equal(
            url_object.id, object_ref, f"url--{misp_object['uuid']}"
        )
        self.assertEqual(url_object.type, 'url')
        self.assertEqual(url_object.value, url)
        self.assertEqual(url_object.x_misp_domain, domain)
        self.assertEqual(url_object.x_misp_host, host)
        self.assertEqual(url_object.x_misp_ip, ip)
        self.assertEqual(url_object.x_misp_port, port)

    def _check_user_account_observable_object(self, misp_object, user_account, object_ref):
        (username, userid, display_name, passwd, group1, group2, groupid, home,
         user_avatar, account_type, plc) = misp_object['Attribute']
        self._assert_multiple_equal(
            user_account.id, object_ref, f"user-account--{misp_object['uuid']}"
        )
        self.assertEqual(user_account.type, 'user-account')
        self.assertEqual(user_account.user_id, userid['value'])
        self.assertEqual(user_account.credential, passwd['value'])
        self.assertEqual(user_account.account_login, username['value'])
        self.assertEqual(user_account.account_type, account_type['value'])
        self.assertEqual(user_account.display_name, display_name['value'])
        extension = user_account.extensions['unix-account-ext']
        self.assertEqual(extension.gid, int(groupid['value']))
        self.assertEqual(extension.groups, [group1['value'], group2['value']])
        self.assertEqual(extension.home_dir, home['value'])
        password_last_changed = plc['value']
        if not isinstance(password_last_changed, datetime):
            password_last_changed = self._datetime_from_str(password_last_changed)
        self.assertEqual(
            user_account.credential_last_changed.timestamp(),
            password_last_changed.timestamp()
        )
        self.assertEqual(user_account.x_misp_user_avatar['value'], user_avatar['value'])
        data = user_avatar['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(user_account.x_misp_user_avatar['data'], data)

    def _check_x509_observable_object(self, misp_object, x509, object_ref):
        (issuer, pem, pia, pie, pim, srlnmbr, signalg, subject, vnb, vna, version,
         md5, sha1) = (attribute['value'] for attribute in misp_object['Attribute'])
        self._assert_multiple_equal(
            x509.id, object_ref, f"x509-certificate--{misp_object['uuid']}"
        )
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

    @staticmethod
    def _reorder_observable_objects(observables, ids):
        ordered_observables = []
        ordered_ids = []
        tmp_observable = [observables.pop(0)]
        tmp_id = [ids.pop(0)]
        for observable, _id in zip(observables, ids):
            if observable.type == 'observed-data':
                ordered_observables.append(tmp_observable)
                ordered_ids.append(tmp_id)
                tmp_observable = [observable]
                tmp_id = [_id]
            else:
                tmp_observable.append(observable)
                tmp_id.append(_id)
        ordered_observables.append(tmp_observable)
        ordered_ids.append(tmp_id)
        return ordered_observables, ordered_ids

    def _run_indicators_from_objects_tests(self, event):
        self._add_object_ids_flag(event)
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_objects = self.parser._misp_event.objects
        n_objects = len(misp_objects)
        self.assertTrue(n_objects > 1)
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, *SDOs = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_grouping_features(grouping, identity_id)
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
        for data_layer, chunk, object_ref, relationship in zip(misp_objects, object_chunks, ref_chunks, relationships):
            observed_data, *_, indicator = chunk
            od_ref, *_, indicator_ref = object_ref
            self._check_object_indicator_features(indicator, data_layer, identity_id, indicator_ref)
            self._check_pattern_features(indicator)
            self._check_object_observable_features(observed_data, data_layer, identity_id, od_ref)
            self.assertEqual(relationship.relationship_type, 'based-on')
            self.assertEqual(relationship.source_ref, indicator_ref)
            self.assertEqual(relationship.target_ref, od_ref)
        return misp_objects, object_chunks, ref_chunks, relationships

    def _run_indicator_from_objects_tests(self, event):
        self._add_object_ids_flag(event)
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_objects = self.parser._misp_event.objects
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, observed_data, observable, indicator, relationship = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_grouping_features(grouping, identity_id)
        od_ref, observable_ref, indicator_ref, relationship_ref = object_refs
        self._check_object_observable_features(
            observed_data, misp_objects[0], identity_id, od_ref
        )
        self.assertEqual(len(observed_data.object_refs), 1)
        self._assert_multiple_equal(
            observed_data.object_refs[0], observable.id, observable_ref,
            f"file--{misp_objects[0]['uuid']}"
        )
        self._check_object_indicator_features(
            indicator, misp_objects[0], identity_id, indicator_ref
        )
        self._check_pattern_features(indicator)
        self.assertEqual(relationship.id, relationship_ref)
        self.assertEqual(relationship.relationship_type, 'based-on')
        self.assertEqual(relationship.source_ref, indicator_ref)
        self.assertEqual(relationship.target_ref, od_ref)
        return misp_objects, observable, indicator.pattern

    def _run_indicator_from_object_tests(self, event):
        self._add_object_ids_flag(event)
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_object = self.parser._misp_event.objects[0]
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, observed_data, *observables, indicator, relationship = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_grouping_features(grouping, identity_id)
        od_ref, *observable_refs, indicator_ref, relationship_ref = object_refs
        self._check_object_observable_features(
            observed_data, misp_object, identity_id, od_ref
        )
        self.assertEqual(observable_refs, observed_data.object_refs)
        self._check_object_indicator_features(
            indicator, misp_object, identity_id, indicator_ref
        )
        self._check_pattern_features(indicator)
        self.assertEqual(relationship.id, relationship_ref)
        self.assertEqual(relationship.relationship_type, 'based-on')
        self.assertEqual(relationship.source_ref, indicator_ref)
        self.assertEqual(relationship.target_ref, od_ref)
        return misp_object, observables, observable_refs, indicator.pattern

    def _run_observables_from_objects_tests(self, event):
        self._remove_object_ids_flags(event)
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_objects = self.parser._misp_event.objects
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, *observables = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        ids = self._check_grouping_features(grouping, identity_id)
        observables, ids = self._reorder_observable_objects(observables, ids)
        for observable, misp_object, observable_id in zip(observables, misp_objects, ids):
            observed_data, _ = observable
            od_id, *observable_ids = observable_id
            self._check_object_observable_features(
                observed_data, misp_object, identity_id, od_id
            )
            self.assertEqual(observable_ids, observed_data.object_refs)
        return misp_objects, observables, ids

    def _run_observable_from_objects_tests(self, event):
        self._remove_object_ids_flags(event)
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_objects = self.parser._misp_event.objects
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, observed_data, observable = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        observed_data_id, object_ref = self._check_grouping_features(
            grouping, identity_id
        )
        self.assertEqual(len(observed_data.object_refs), 1)
        self._assert_multiple_equal(
            observed_data.object_refs[0], object_ref, observable.id,
            f"file--{misp_objects[0]['uuid']}"
        )
        self._check_object_observable_features(
            observed_data, misp_objects[0], identity_id, observed_data_id
        )
        return misp_objects, observable

    def _run_observable_from_object_tests(self, event):
        self._remove_object_ids_flags(event)
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_object = self.parser._misp_event.objects[0]
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, observed_data, *observables = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        observed_data_id, *object_refs = self._check_grouping_features(
            grouping, identity_id
        )
        self.assertEqual(object_refs, observed_data.object_refs)
        self._check_object_observable_features(
            observed_data, misp_object, identity_id, observed_data_id
        )
        return misp_object, observables, object_refs

    def _test_embedded_indicator_object_galaxy(self, event):
        self._add_object_ids_flag(event)
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_object = self.parser._misp_event.objects[0]
        tool_galaxy, event_coa_galaxy, event_custom_galaxy = self.parser._misp_event.galaxies
        stix_objects = self._check_bundle_features(13)
        self._check_spec_versions(stix_objects)
        (identity, grouping, malware, coa, custom, observed_data,
         autonomous_system, indicator, tool, *relationships) = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_grouping_features(grouping, identity_id)
        (malware_ref, coa_ref, custom_ref, observed_data_ref, as_ref, indicator_ref,
         tool_ref, mr_ref, coar_ref, customr_ref, indr_ref) = object_refs
        (malware_relationship, coa_relationship, custom_relationship,
         indicator_relationship) = relationships
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
            observed_data.id, observed_data_ref,
            f"observed-data--{misp_object['uuid']}"
        )
        self._assert_multiple_equal(
            autonomous_system.id, as_ref,
            f"autonomous-system--{misp_object['uuid']}"
        )
        self._assert_multiple_equal(
            indicator.id, indicator_ref,
            f"indicator--{misp_object['uuid']}"
        )
        self._assert_multiple_equal(
            tool.id, tool_ref,
            f"tool--{tool_galaxy['GalaxyCluster'][0]['uuid']}"
        )
        self.assertEqual(malware_relationship.id, mr_ref)
        self.assertEqual(coa_relationship.id, coar_ref)
        self.assertEqual(custom_relationship.id, customr_ref)
        self.assertEqual(indicator_relationship.id, indr_ref)
        timestamp = misp_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self._check_relationship_features(
            malware_relationship, observed_data_ref, malware_ref, 'related-to', timestamp
        )
        self._check_relationship_features(
            coa_relationship, observed_data_ref, coa_ref, 'related-to', timestamp
        )
        self._check_relationship_features(
            custom_relationship, observed_data_ref, custom_ref, 'related-to', timestamp
        )
        self._check_relationship_features(
            indicator_relationship, indicator_ref, observed_data_ref, 'based-on', timestamp
        )

    def _test_embedded_non_indicator_object_galaxy(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        coa_object, vulnerability_object = self.parser._misp_event.objects
        event_coa_galaxy, tool_galaxy = self.parser._misp_event.galaxies
        stix_objects = self._check_bundle_features(12)
        self._check_spec_versions(stix_objects)
        identity, grouping, ap, g_coa, o_coa, malware, vulnerability, tool, *relationships = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_grouping_features(grouping, identity_id)
        ap_ref, g_coa_ref, o_coa_ref, malware_ref, vulnerability_ref, tool_ref, *relationship_refs = object_refs
        ap_galaxy = coa_object['Attribute'][0]['Galaxy'][0]
        coa_coa_galaxy = coa_object['Attribute'][1]['Galaxy'][0]
        malware_galaxy = vulnerability_object['Attribute'][0]['Galaxy'][0]
        vulnerability_coa_galaxy = vulnerability_object['Attribute'][1]['Galaxy'][0]
        self._assert_multiple_equal(
            ap.id,
            ap_ref,
            f"attack-pattern--{ap_galaxy['GalaxyCluster'][0]['uuid']}"
        )
        self._assert_multiple_equal(
            g_coa.id,
            g_coa_ref,
            f"course-of-action--{event_coa_galaxy['GalaxyCluster'][0]['uuid']}",
            f"course-of-action--{coa_coa_galaxy['GalaxyCluster'][0]['uuid']}",
            f"course-of-action--{vulnerability_coa_galaxy['GalaxyCluster'][0]['uuid']}"
        )
        self._assert_multiple_equal(
            o_coa.id,
            o_coa_ref,
            f"course-of-action--{coa_object['uuid']}"
        )
        self._assert_multiple_equal(
            malware.id,
            malware_ref,
            f"malware--{malware_galaxy['GalaxyCluster'][0]['uuid']}"
        )
        self._assert_multiple_equal(
            vulnerability.id,
            vulnerability_ref,
            f"vulnerability--{vulnerability_object['uuid']}"
        )
        self._assert_multiple_equal(
            tool.id,
            tool_ref,
            f"tool--{tool_galaxy['GalaxyCluster'][0]['uuid']}"
        )
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
        stix_objects = self._check_bundle_features(8)
        self._check_spec_versions(stix_objects)
        identity, grouping, malware1, malware2, observed_data, autonomous_system, relationship1, relationship2 = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_grouping_features(grouping, identity_id)
        malware1_ref, malware2_ref, observed_data_ref, as_ref, relationship1_ref, relationship2_ref = object_refs
        malware_galaxy1 = misp_object['Attribute'][0]['Galaxy'][0]
        malware_galaxy2 = misp_object['Attribute'][1]['Galaxy'][0]
        self._assert_multiple_equal(
            malware1.id,
            malware1_ref,
            f"malware--{malware_galaxy1['GalaxyCluster'][0]['uuid']}"
        )
        self._assert_multiple_equal(
            malware2.id,
            malware2_ref,
            f"malware--{malware_galaxy2['GalaxyCluster'][0]['uuid']}"
        )
        self._assert_multiple_equal(
            observed_data.id,
            observed_data_ref,
            f"observed-data--{misp_object['uuid']}"
        )
        self._assert_multiple_equal(
            autonomous_system.id,
            as_ref,
            f"autonomous-system--{misp_object['uuid']}"
        )
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
        tool_galaxy = self.parser._misp_event.galaxies[0]
        stix_objects = self._check_bundle_features(7)
        self._check_spec_versions(stix_objects)
        identity, grouping, malware, observed_data, autonomous_system, tool, relationship = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_grouping_features(grouping, identity_id)
        malware_ref, observed_data_ref, as_ref, tool_ref, relationship_ref = object_refs
        malware_galaxy = misp_object['Attribute'][0]['Galaxy'][0]
        self._assert_multiple_equal(
            malware.id,
            malware_ref,
            f"malware--{malware_galaxy['GalaxyCluster'][0]['uuid']}"
        )
        self._assert_multiple_equal(
            observed_data.id,
            observed_data_ref,
            f"observed-data--{misp_object['uuid']}"
        )
        self._assert_multiple_equal(
            autonomous_system.id,
            as_ref,
            f"autonomous-system--{misp_object['uuid']}"
        )
        self._assert_multiple_equal(
            tool.id,
            tool_ref,
            f"tool--{tool_galaxy['GalaxyCluster'][0]['uuid']}"
        )
        self.assertEqual(relationship.id, relationship_ref)
        timestamp = misp_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self._check_relationship_features(
            relationship, observed_data_ref, malware_ref, 'related-to', timestamp
        )

    def _test_event_with_annotation_object(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_object = self.parser._misp_event.objects[0]
        attribute = self.parser._misp_event.attributes[0]
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        (identity, grouping, observed_data, network_traffic, ip_address,
         indicator, note, relationship) = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        od_ref, nt_ref, ip_ref, indicator_ref, note_ref, relationship_ref = self._check_grouping_features(grouping, identity_id)
        self._check_attribute_indicator_features(indicator, attribute, identity_id, indicator_ref)
        self._check_pattern_features(indicator)
        type_pattern = "network-traffic:dst_ref.type = 'ipv4-addr'"
        value_pattern = f"network-traffic:dst_ref.value = '{attribute['value']}'"
        self.assertEqual(indicator.pattern, f"[{type_pattern} AND {value_pattern}]")
        text, annotation_type, attachment = (attribute['value'] for attribute in misp_object['Attribute'])
        self.assertEqual(note.type, 'note')
        self._assert_multiple_equal(
            note.id,
            note_ref,
            f"note--{misp_object['uuid']}"
        )
        timestamp = misp_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self.assertEqual(note.created, timestamp)
        self.assertEqual(note.modified, timestamp)
        self.assertEqual(note.labels[0], f'misp:name="{misp_object["name"]}"')
        self.assertEqual(note.labels[1], f'misp:meta-category="{misp_object["meta-category"]}"')
        self.assertEqual(note.labels[2], f'misp:to_ids="False"')
        self.assertEqual(note.content, text)
        self.assertEqual(set(note.object_refs), {indicator.id, observed_data.id})
        self.assertEqual(note.x_misp_type, annotation_type)
        self.assertEqual(note.x_misp_attachment['value'], attachment)
        data = misp_object['Attribute'][-1]['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(note.x_misp_attachment['data'], data)

    def _test_event_with_android_app_indicator_object(self, event):
        misp_object, observables, object_refs, pattern = self._run_indicator_from_object_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_android_app_observable_object(misp_object, observables[0], object_refs[0])
        name, certificate, domain = (attribute['value'] for attribute in misp_object['Attribute'])
        name_pattern, cert_pattern, domain_pattern = pattern[1:-1].split(' AND ')
        self.assertEqual(name_pattern, f"software:name = '{name}'")
        self.assertEqual(cert_pattern, f"software:x_misp_certificate = '{certificate}'")
        self.assertEqual(domain_pattern, f"software:x_misp_domain = '{domain}'")

    def _test_event_with_android_app_observable_object(self, event):
        misp_object, observables, object_refs = self._run_observable_from_object_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_android_app_observable_object(misp_object, observables[0], object_refs[0])

    def _test_event_with_asn_indicator_object(self, event):
        misp_object, observables, object_refs, pattern = self._run_indicator_from_object_tests(event)
        self.assertEqual(len(observables), len(object_refs), 1)
        self._check_asn_observable_object(misp_object, observables[0], object_refs[0])
        asn = misp_object['Attribute'][0]
        asn_pattern = pattern[1:-1]
        self.assertEqual(asn_pattern, f"autonomous-system:number = '{int(asn['value'][2:])}'")

    def _test_event_with_asn_observable_object(self, event):
        misp_object, observables, object_refs = self._run_observable_from_object_tests(event)
        self.assertEqual(len(observables), len(object_refs), 1)
        self._check_asn_observable_object(misp_object, observables[0], object_refs[0])

    def _test_event_with_attack_pattern_object(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_object = self.parser._misp_event.objects[0]
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, attack_pattern = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_grouping_features(grouping, identity_id)[0]
        self._assert_multiple_equal(
            attack_pattern.id,
            grouping['object_refs'][0],
            object_ref,
            f"attack-pattern--{misp_object['uuid']}"
        )
        self._check_attack_pattern_object(attack_pattern, misp_object, identity_id)

    def _test_event_with_course_of_action_object(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_object = self.parser._misp_event.objects[0]
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, course_of_action = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_grouping_features(grouping, identity_id)[0]
        self._assert_multiple_equal(
            course_of_action.id,
            grouping['object_refs'][0],
            object_ref,
            f"course-of-action--{misp_object['uuid']}"
        )
        self._check_course_of_action_object(course_of_action, misp_object, identity_id)

    def _test_event_with_cpe_asset_indicator_object(self, event):
        misp_object, observables, object_refs, pattern = self._run_indicator_from_object_tests(event)
        self.assertEqual(len(observables), len(object_refs), 1)
        self._check_cpe_asset_observable_object(misp_object, observables[0], object_refs[0])
        cpe = misp_object['Attribute'][0]
        cpe_pattern = pattern[1:-1]
        self.assertEqual(cpe_pattern, f"software:cpe = '{cpe['value']}'")

    def _test_event_with_cpe_asset_observable_object(self, event):
        misp_object, observables, object_refs = self._run_observable_from_object_tests(event)
        self.assertEqual(len(observables), len(object_refs), 1)
        self._check_cpe_asset_observable_object(misp_object, observables[0], object_refs[0])

    def _test_event_with_credential_indicator_object(self, event):
        misp_object, observables, object_refs, pattern = self._run_indicator_from_object_tests(event)
        self.assertEqual(len(observables), len(object_refs), 1)
        self._check_credential_observable_object(misp_object, observables[0], object_refs[0])
        text = misp_object['Attribute'][0]
        text_pattern = pattern[1:-1]
        self.assertEqual(
            text_pattern,
            f"user-account:x_misp_{text['object_relation']} = '{text['value']}'"
        )

    def _test_event_with_credential_observable_object(self, event):
        misp_object, observables, object_refs = self._run_observable_from_object_tests(event)
        self.assertEqual(len(observables), len(object_refs), 1)
        self._check_credential_observable_object(misp_object, observables[0], object_refs[0])

    def _test_event_with_custom_object(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_objects = self.parser._misp_event.objects
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, *custom_objects = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_refs = self._check_grouping_features(grouping, identity_id)
        for misp_object, custom_object, object_ref in zip(misp_objects, custom_objects, object_refs):
            self._run_custom_object_tests(misp_object, custom_object, object_ref, identity_id)

    def _test_event_with_domain_ip_indicator_object(self, event):
        misp_object, observables, object_refs, pattern = self._run_indicator_from_object_tests(event)
        self._check_domain_ip_observable_object(misp_object, observables, object_refs)
        _domain, _hostname, _ip, _ = (attribute['value'] for attribute in misp_object['Attribute'])
        domain_, hostname_, ip_ = pattern[1:-1].split(' AND ')
        self.assertEqual(domain_, f"domain-name:value = '{_domain}'")
        self.assertEqual(hostname_, f"domain-name:x_misp_hostname = '{_hostname}'")
        self.assertEqual(ip_, f"domain-name:resolves_to_refs[*].value = '{_ip}'")

    def _test_event_with_domain_ip_observable_object_custom(self, event):
        misp_object, observables, object_refs = self._run_observable_from_object_tests(event)
        self._check_domain_ip_observable_object(misp_object, observables, object_refs)

    def _test_event_with_domain_ip_observable_object_standard(self, event):
        misp_object, observables, object_refs = self._run_observable_from_object_tests(event)
        _domain1, _domain2, _ip1, _ip2 = misp_object['Attribute']
        ip1_, ip2_, domain1_, domain2_ = observables
        ip1_ref, ip2_ref, domain1_ref, domain2_ref = object_refs
        self._check_SCO(domain1_, _domain1, domain1_ref, 'domain-name')
        self.assertEqual(domain1_.resolves_to_refs, [ip1_ref, ip2_ref])
        self._check_SCO(domain2_, _domain2, domain2_ref, 'domain-name')
        self.assertEqual(domain2_.resolves_to_refs, [ip1_ref, ip2_ref])
        self._check_SCO(ip1_, _ip1, ip1_ref, 'ipv4-addr')
        self._check_SCO(ip2_, _ip2, ip2_ref, 'ipv4-addr')

    def _test_event_with_email_indicator_object(self, event):
        misp_object, observables, object_refs, pattern = self._run_indicator_from_object_tests(event)
        self._check_email_observable_object(misp_object, observables, object_refs)
        (_from, _, _to, _, _cc1, _, _cc2, _, _bcc, _, _, _, _attachment1,
         _attachment2, *_) = (attribute['value'] for attribute in misp_object['Attribute'])
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
        misp_object, observables, object_refs = self._run_observable_from_object_tests(event)
        self._check_email_observable_object(misp_object, observables, object_refs)

    def _test_event_with_email_with_display_names_indicator_object(self, event):
        misp_object, observables, object_refs, pattern = self._run_indicator_from_object_tests(event)
        self._check_email_with_display_names_observable_object(
            misp_object, observables, object_refs
        )
        _from, _, _to, _, _cc, _, _bcc, _ = (
            attribute['value'] for attribute in misp_object['Attribute']
        )
        to_, cc_, bcc_, from_ = pattern[1:-1].split(' AND ')
        self.assertEqual(to_, f"email-message:to_refs[0].value = '{_to}'")
        self.assertEqual(cc_, f"email-message:cc_refs[0].value = '{_cc}'")
        self.assertEqual(bcc_, f"email-message:bcc_refs[0].value = '{_bcc}'")
        self.assertEqual(from_, f"email-message:from_ref.value = '{_from}'")

    def _test_event_with_email_with_display_names_observable_object(self, event):
        misp_object, observables, object_refs = self._run_observable_from_object_tests(event)
        self._check_email_with_display_names_observable_object(
            misp_object, observables, object_refs
        )

    def _test_event_with_employee_object(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_object = self.parser._misp_event.objects[0]
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, employee = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        employee_ref = self._check_grouping_features(grouping, identity_id)[0]
        employee_type = self._check_employee_object(
            employee,
            misp_object,
            employee_ref,
            identity_id
        )
        self.assertEqual(employee.roles, [employee_type])

    def _test_event_with_file_and_pe_indicator_objects(self, event):
        misp_objects, observable, pattern = self._run_indicator_from_objects_tests(event)
        self._check_file_and_pe_observable_object(observable, *misp_objects)
        _file, pe, section = misp_objects
        _filename, _md5, _sha1, _sha256, *_ = (
            attribute['value'] for attribute in _file['Attribute']
        )
        pattern = pattern[1:-1].split(' AND ')
        md5_, sha1_, sha256_, name_ = pattern[:4]
        self.assertEqual(md5_, f"file:hashes.MD5 = '{_md5}'")
        self.assertEqual(sha1_, f"file:hashes.SHA1 = '{_sha1}'")
        self.assertEqual(sha256_, f"file:hashes.SHA256 = '{_sha256}'")
        self.assertEqual(name_, f"file:name = '{_filename}'")
        self._check_pe_and_section_pattern(pattern[4:], pe, section)

    def _test_event_with_file_and_pe_observable_objects(self, event):
        misp_objects, observable = self._run_observable_from_objects_tests(event)
        self._check_file_and_pe_observable_object(observable, *misp_objects)

    def _test_event_with_file_indicator_object(self, event):
        misp_object, observables, object_refs, pattern = self._run_indicator_from_object_tests(event)
        self._check_file_observable_object(misp_object, observables, object_refs)
        _malware_sample, _filename, _md5, _sha1, _sha256, *_ = misp_object['Attribute']
        md5_, sha1_, sha256_, filename_, malware_sample_ = self._reassemble_pattern(pattern[1:-1])
        self.assertEqual(md5_, f"file:hashes.MD5 = '{_md5['value']}'")
        self.assertEqual(sha1_, f"file:hashes.SHA1 = '{_sha1['value']}'")
        self.assertEqual(sha256_, f"file:hashes.SHA256 = '{_sha256['value']}'")
        self.assertEqual(filename_, f"file:name = '{_filename['value']}'")
        ms_data, ms_filename, ms_md5, mime_type, encryption, decryption = malware_sample_.split(' AND ')
        data = _malware_sample['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(ms_data, f"(file:content_ref.payload_bin = '{data}'")
        filename, md5 = _malware_sample['value'].split('|')
        self.assertEqual(ms_filename, f"file:content_ref.x_misp_filename = '{filename}'")
        self.assertEqual(ms_md5, f"file:content_ref.hashes.MD5 = '{md5}'")
        self.assertEqual(mime_type, f"file:content_ref.mime_type = 'application/zip'")
        self.assertEqual(encryption, f"file:content_ref.encryption_algorithm = 'mime-type-indicated'")
        self.assertEqual(decryption, f"file:content_ref.decryption_key = 'infected')")

    def _test_event_with_file_observable_object(self, event):
        misp_object, observables, object_refs = self._run_observable_from_object_tests(event)
        self._check_file_observable_object(misp_object, observables, object_refs)

    def _test_event_with_geolocation_object(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_object = self.parser._misp_event.objects[0]
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, location = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_grouping_features(grouping, identity_id)[0]
        address, zipcode, city, country, countrycode, region, latitude, longitude, accuracy, altitude = (attribute['value'] for attribute in misp_object['Attribute'])
        self.assertEqual(location.type, 'location')
        self._assert_multiple_equal(
            location.id,
            object_ref,
            f"location--{misp_object['uuid']}"
        )
        timestamp = misp_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self.assertEqual(location.created, timestamp)
        self.assertEqual(location.modified, timestamp)
        self.assertEqual(location.labels[0], f'misp:name="{misp_object["name"]}"')
        self.assertEqual(location.labels[1], f'misp:meta-category="{misp_object["meta-category"]}"')
        self.assertEqual(location.labels[2], f'misp:to_ids="False"')
        self.assertEqual(location.street_address, address)
        self.assertEqual(location.postal_code, zipcode)
        self.assertEqual(location.city, city)
        self.assertEqual(location.country, countrycode)
        self.assertEqual(location.region, region)
        self.assertEqual(location.latitude, float(latitude))
        self.assertEqual(location.longitude, float(longitude))
        self.assertEqual(location.precision, float(accuracy) * 1000)
        self.assertEqual(location.x_misp_country, country)
        self.assertEqual(location.x_misp_altitude, altitude)

    def _test_event_with_http_request_indicator_object(self, event):
        misp_object, observables, object_refs, pattern = self._run_indicator_from_object_tests(event)
        self._check_http_request_observable_object(misp_object, observables, object_refs)
        ip_src, ip_dst, host, _, _, uri, url, _ = (
            attribute['value'] for attribute in misp_object['Attribute']
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
        misp_object, observables, object_refs = self._run_observable_from_object_tests(event)
        self._check_http_request_observable_object(misp_object, observables, object_refs)

    def _test_event_with_identity_object(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_object = self.parser._misp_event.objects[0]
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        created_by_ref_identity, grouping, identity = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(created_by_ref_identity, orgc, timestamp)
        object_ref = self._check_grouping_features(grouping, identity_id)[0]
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
        self.assertEqual(identity.roles, [roles])

    def _test_event_with_intrusion_set_object(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_object = self.parser._misp_event.objects[0]
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, intrusion_set = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_grouping_features(grouping, identity_id)[0]
        self._assert_multiple_equal(
            intrusion_set.id,
            grouping['object_refs'][0],
            f"intrusion-set--{misp_object['uuid']}",
            object_ref
        )
        self._check_intrusion_set_object(intrusion_set, misp_object, identity_id)

    def _test_event_with_image_indicator_object(self, event):
        misp_object, observables, object_refs, pattern = self._run_indicator_from_object_tests(event)
        self._check_image_observable_object(misp_object, observables, object_refs)
        attachment, filename, url, _ = (attribute for attribute in misp_object['Attribute'])
        name, payload_bin, mime_type, name_ref, url_pattern = pattern[1:-1].split(' AND ')
        self.assertEqual(name, f"file:name = '{filename['value']}'")
        data = attachment['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(payload_bin, f"file:content_ref.payload_bin = '{data}'")
        self.assertEqual(mime_type, f"file:content_ref.mime_type = 'image/png'")
        self.assertEqual(name_ref, f"file:content_ref.x_misp_filename = '{attachment['value']}'")
        self.assertEqual(url_pattern, f"file:content_ref.url = '{url['value']}'")

    def _test_event_with_image_observable_object(self, event):
        misp_object, observables, object_refs = self._run_observable_from_object_tests(event)
        self._check_image_observable_object(misp_object, observables, object_refs)

    def _test_event_with_ip_port_indicator_object(self, event):
        prefix = 'network-traffic'
        misp_object, observables, object_refs, pattern = self._run_indicator_from_object_tests(event)
        self._check_ip_port_observable_object(misp_object, observables, object_refs)
        ip, _, domain, _ = (attribute['value'] for attribute in misp_object['Attribute'])
        ip_type, ip_value, domain_type, domain_value = pattern[1:-1].split(' AND ')
        self.assertEqual(ip_type, f"({prefix}:dst_ref.type = 'ipv4-addr'")
        self.assertEqual(ip_value, f"{prefix}:dst_ref.value = '{ip}')")
        self.assertEqual(domain_type, f"({prefix}:dst_ref.type = 'domain-name'")
        self.assertEqual(domain_value, f"{prefix}:dst_ref.value = '{domain}')")

    def _test_event_with_ip_port_observable_object(self, event):
        misp_object, observables, object_refs = self._run_observable_from_object_tests(event)
        self._check_ip_port_observable_object(misp_object, observables, object_refs)

    def _test_event_with_legal_entity_object(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_object = self.parser._misp_event.objects[0]
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, legal_entity = stix_objects
        timestamp = misp_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        legal_entity_ref = self._check_grouping_features(grouping, identity_id)[0]
        self._check_legal_entity_object_features(
            legal_entity,
            misp_object,
            legal_entity_ref,
            identity_id
        )

    def _test_event_with_lnk_indicator_object(self, event):
        misp_object, observables, object_refs, pattern = self._run_indicator_from_object_tests(event)
        self._check_lnk_observable_object(misp_object, observables, object_refs)
        filename, _, md5, sha1, sha256, malware_sample, *_ = (
            attribute for attribute in misp_object['Attribute']
        )
        name, md5_pattern, sha1_pattern, sha256_pattern, artifact = self._reassemble_pattern(pattern[1:-1])
        self.assertEqual(name, f"file:name = '{filename['value']}'")
        self.assertEqual(md5_pattern, f"file:hashes.MD5 = '{md5['value']}'")
        self.assertEqual(sha1_pattern, f"file:hashes.SHA1 = '{sha1['value']}'")
        self.assertEqual(sha256_pattern, f"file:hashes.SHA256 = '{sha256['value']}'")
        ms_data, ms_filename, ms_md5, mime_type, encryption, decryption = artifact.split(' AND ')
        data = malware_sample['data']
        if not isinstance(data, str):
            data = b64encode(data.getvalue()).decode()
        self.assertEqual(ms_data, f"(file:content_ref.payload_bin = '{data}'")
        filename, md5 = malware_sample['value'].split('|')
        self.assertEqual(ms_filename, f"file:content_ref.x_misp_filename = '{filename}'")
        self.assertEqual(ms_md5, f"file:content_ref.hashes.MD5 = '{md5}'")
        self.assertEqual(mime_type, f"file:content_ref.mime_type = 'application/zip'")
        self.assertEqual(encryption, f"file:content_ref.encryption_algorithm = 'mime-type-indicated'")
        self.assertEqual(decryption, f"file:content_ref.decryption_key = 'infected')")

    def _test_event_with_lnk_observable_object(self, event):
        misp_object, observables, object_refs = self._run_observable_from_object_tests(event)
        self._check_lnk_observable_object(misp_object, observables, object_refs)

    def _test_event_with_mutex_indicator_object(self, event):
        misp_object, observables, object_refs, pattern = self._run_indicator_from_object_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_mutex_observable_object(misp_object, observables[0], object_refs[0])
        _name = misp_object['Attribute'][0]['value']
        name_ = pattern[1:-1]
        self.assertEqual(name_, f"mutex:name = '{_name}'")

    def _test_event_with_mutex_observable_object(self, event):
        misp_object, observables, object_refs = self._run_observable_from_object_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_mutex_observable_object(misp_object, observables[0], object_refs[0])

    def _test_event_with_netflow_indicator_object(self, event):
        misp_object, observables, object_refs, pattern = self._run_indicator_from_object_tests(event)
        self._check_netflow_observable_object(misp_object, observables, object_refs)
        ip_src, ip_dst, *_ = (attribute['value'] for attribute in misp_object['Attribute'])
        src_type, src_value, dst_type, dst_value = pattern[1:-1].split(' AND ')
        prefix = 'network-traffic'
        self.assertEqual(src_type, f"({prefix}:src_ref.type = 'ipv4-addr'")
        self.assertEqual(src_value, f"{prefix}:src_ref.value = '{ip_src}')")
        self.assertEqual(dst_type, f"({prefix}:dst_ref.type = 'ipv4-addr'")
        self.assertEqual(dst_value, f"{prefix}:dst_ref.value = '{ip_dst}')")

    def _test_event_with_netflow_observable_object(self, event):
        misp_object, observables, object_refs = self._run_observable_from_object_tests(event)
        self._check_netflow_observable_object(misp_object, observables, object_refs)

    def _test_event_with_network_connection_indicator_object(self, event):
        misp_object, observables, object_refs, pattern = self._run_indicator_from_object_tests(event)
        self._check_network_connection_observable_object(misp_object, observables, object_refs)
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
        misp_object, observables, object_refs = self._run_observable_from_object_tests(event)
        self._check_network_connection_observable_object(misp_object, observables, object_refs)

    def _test_event_with_network_socket_indicator_object(self, event):
        misp_object, observables, object_refs, pattern = self._run_indicator_from_object_tests(event)
        self._check_network_socket_observable_object(misp_object, observables, object_refs)
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
        misp_object, observables, object_refs = self._run_observable_from_object_tests(event)
        self._check_network_socket_observable_object(misp_object, observables, object_refs)

    def _test_event_with_news_agency_object(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_object = self.parser._misp_event.objects[0]
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, news_agency = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        news_agency_ref = self._check_grouping_features(grouping, identity_id)[0]
        name, address1, email1, phone1, address2, email2, phone2, link, attachment = (attribute['value'] for attribute in misp_object['Attribute'])
        self.assertEqual(news_agency.type, 'identity')
        self._assert_multiple_equal(
            news_agency.id,
            news_agency_ref,
            f"identity--{misp_object['uuid']}"
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

    def _test_event_with_organisation_object(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_object = self.parser._misp_event.objects[0]
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, organization = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        organization_ref = self._check_grouping_features(grouping, identity_id)[0]
        name, description, address, email, phone, role, alias = (attribute['value'] for attribute in misp_object['Attribute'])
        self.assertEqual(organization.type, 'identity')
        self._assert_multiple_equal(
            organization.id,
            organization_ref,
            f"identity--{misp_object['uuid']}"
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
        self.assertEqual(organization.roles, [role])
        self.assertEqual(organization.x_misp_alias, alias)

    def _test_event_with_patterning_language_objects(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        sigma, suricata, yara = self.parser._misp_event.objects
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, sigma_indicator, suricata_indicator, yara_indicator = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        sigma_ref, suricata_ref, yara_ref = self._check_grouping_features(grouping, event, identity_id)
        self._check_object_indicator_features(sigma_indicator, sigma, identity_id, sigma_ref)
        rule, context, reference, name, comment = sigma['Attribute']
        self.assertEqual(sigma_indicator.pattern, rule['value'].replace("'", "\\'"))
        self.assertEqual(sigma_indicator.pattern_type, rule['type'])
        self.assertEqual(sigma_indicator.external_references[0].url, reference['value'])
        self.assertEqual(sigma_indicator.x_misp_context, context['value'])
        self._check_object_indicator_features(suricata_indicator, suricata, identity_id, suricata_ref)
        rule, version, comment, ref = suricata['Attribute']
        self.assertEqual(suricata_indicator.pattern, rule['value'].replace('"', '\\\\"'))
        self.assertEqual(suricata_indicator.pattern_type, rule['type'])
        self.assertEqual(suricata_indicator.pattern_version, version['value'])
        self.assertEqual(suricata_indicator.description, comment['value'])
        self.assertEqual(suricata_indicator.external_references[0].url, ref['value'])
        self._check_object_indicator_features(yara_indicator, yara, identity_id, yara_ref)
        rule, version, comment, name = yara['Attribute']
        self.assertEqual(yara_indicator.pattern, rule['value'].replace('"', '\\\\"'))
        self.assertEqual(yara_indicator.pattern_type, rule['type'])
        self.assertEqual(yara_indicator.pattern_version, version['value'])
        self.assertEqual(yara_indicator.description, comment['value'])
        self.assertEqual(yara_indicator.name, name['value'])

    def _test_event_with_pe_and_section_indicator_object(self, event):
        misp_objects, observable, pattern = self._run_indicator_from_objects_tests(event)
        self._check_pe_and_section_observable(
            observable.extensions['windows-pebinary-ext'], *misp_objects
        )
        self._check_pe_and_section_pattern(pattern[1:-1].split(' AND '), *misp_objects)

    def _test_event_with_pe_and_section_observable_object(self, event):
        misp_objects, observable = self._run_observable_from_objects_tests(event)
        self._check_pe_and_section_observable(
            observable.extensions['windows-pebinary-ext'], *misp_objects
        )

    def _test_event_with_person_object(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_object = self.parser._misp_event.objects[0]
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, person = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        person_ref = self._check_grouping_features(grouping, identity_id)[0]
        role = self._check_person_object(
            person, misp_object, person_ref, identity_id
        )
        self.assertEqual(person.roles, [role])

    def _test_event_with_process_indicator_object(self, event):
        misp_object, observables, object_refs, pattern = self._run_indicator_from_object_tests(event)
        self._check_process_observable_object(misp_object, observables, object_refs)
        _pid, _, _, _, _image, _parent_image, *_ = (
            attribute['value'] for attribute in misp_object['Attribute']
        )
        pid_, image_, parent_image_ = pattern[1:-1].split(' AND ')
        self.assertEqual(pid_, f"process:pid = '{_pid}'")
        self.assertEqual(image_, f"process:image_ref.name = '{_image}'")
        self.assertEqual(parent_image_, f"process:parent_ref.image_ref.name = '{_parent_image}'")

    def _test_event_with_process_observable_object(self, event):
        misp_object, observables, object_refs = self._run_observable_from_object_tests(event)
        self._check_process_observable_object(misp_object, observables, object_refs)

    def _test_event_with_registry_key_indicator_object(self, event):
        misp_object, observables, object_refs, pattern = self._run_indicator_from_object_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_registry_key_observable_object(misp_object, observables[0], object_refs[0])
        key = misp_object['Attribute'][0]['value'].replace('\\', '\\\\')
        key_ = pattern[1:-1]
        self.assertEqual(key_, f"windows-registry-key:key = '{key}'")

    def _test_event_with_registry_key_observable_object(self, event):
        misp_object, observables, object_refs = self._run_observable_from_object_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_registry_key_observable_object(misp_object, observables[0], object_refs[0])

    def _test_event_with_script_objects(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        malware_script, tool_script = self.parser._misp_event.objects
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, malware, tool = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        malware_ref, tool_ref = self._check_grouping_features(grouping, identity_id)
        language, comment, name, script, script_attachment, state = malware_script['Attribute']
        self._assert_multiple_equal(malware.id, malware_ref, f"malware--{malware_script['uuid']}")
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
        self.assertEqual(malware.is_family, False)
        language, comment, name, script, script_attachment, state = tool_script['Attribute']
        self._assert_multiple_equal(tool.id, tool_ref, f"tool--{tool_script['uuid']}")
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
        misp_object, observables, object_refs, pattern = self._run_indicator_from_object_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_url_observable_object(misp_object, observables[0], object_refs[0])
        _url, _domain, _host, _ip, _ = (
            attribute['value'] for attribute in misp_object['Attribute']
        )
        url_, domain_, host_, ip_ = pattern[1:-1].split(' AND ')
        self.assertEqual(url_, f"url:value = '{_url}'")
        self.assertEqual(domain_, f"url:x_misp_domain = '{_domain}'")
        self.assertEqual(host_, f"url:x_misp_host = '{_host}'")
        self.assertEqual(ip_, f"url:x_misp_ip = '{_ip}'")

    def _test_event_with_url_observable_object(self, event):
        misp_object, observables, object_refs = self._run_observable_from_object_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_url_observable_object(misp_object, observables[0], object_refs[0])

    def _test_event_with_user_account_indicator_object(self, event):
        misp_object, observables, object_refs, pattern = self._run_indicator_from_object_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_user_account_observable_object(misp_object, observables[0], object_refs[0])
        _username = misp_object['Attribute'][0]['value']
        username_ = pattern[1:-1]
        self.assertEqual(username_, f"user-account:account_login = '{_username}'")

    def _test_event_with_user_account_observable_object(self, event):
        misp_object, observables, object_refs = self._run_observable_from_object_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_user_account_observable_object(misp_object, observables[0], object_refs[0])

    def _test_event_with_vulnerability_object(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        misp_object = self.parser._misp_event.objects[0]
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, vulnerability = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_grouping_features(grouping, identity_id)[0]
        self._check_object_vulnerability_features(vulnerability, misp_object, identity_id, object_ref)

    def _test_event_with_x509_indicator_object(self, event):
        misp_object, observables, object_refs, pattern = self._run_indicator_from_object_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_x509_observable_object(misp_object, observables[0], object_refs[0])
        _issuer, *_, _md5, _sha1 = (attribute['value'] for attribute in misp_object['Attribute'])
        md5_, sha1_, issuer_ = pattern[1:-1].split(' AND ')
        self.assertEqual(md5_, f"x509-certificate:hashes.MD5 = '{_md5}'")
        self.assertEqual(sha1_, f"x509-certificate:hashes.SHA1 = '{_sha1}'")
        self.assertEqual(issuer_, f"x509-certificate:issuer = '{_issuer}'")

    def _test_event_with_x509_observable_object(self, event):
        misp_object, observables, object_refs = self._run_observable_from_object_tests(event)
        self._assert_multiple_equal(len(observables), len(object_refs), 1)
        self._check_x509_observable_object(
            misp_object, observables[0], object_refs[0]
        )

    def _test_object_references(self, event):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        (ap_object, as_object, btc_object, coa_object, ip_object,
         person_object, vuln_object) = self.parser._misp_event.objects
        stix_objects = self._check_bundle_features(21)
        self._check_spec_versions(stix_objects)
        (identity, grouping, attack_pattern, observed_data1, autonomous_system,
         custom, coa, observed_data2, network_traffic, _, indicator,
         person, vulnerability, *relationships) = stix_objects
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        grouping_refs = self._check_grouping_features(grouping, identity_id)
        (ap_ref, observed_data1_ref, as_ref, custom_ref, coa_ref,
         observed_data2_ref, nt_ref, _, indicator_ref, person_ref,
         vuln_ref, *relationship_refs) = grouping_refs
        self._assert_multiple_equal(
            attack_pattern.id, ap_ref, f"attack-pattern--{ap_object['uuid']}"
        )
        self._assert_multiple_equal(
            observed_data1.id, observed_data1_ref, f"observed-data--{as_object['uuid']}"
        )
        self._assert_multiple_equal(
            autonomous_system.id, as_ref, f"autonomous-system--{as_object['uuid']}"
        )
        self._assert_multiple_equal(
            custom.id, custom_ref, f"x-misp-object--{btc_object['uuid']}"
        )
        self._assert_multiple_equal(
            coa.id, coa_ref, f"course-of-action--{coa_object['uuid']}"
        )
        self._assert_multiple_equal(
            observed_data2.id, observed_data2_ref, f"observed-data--{ip_object['uuid']}"
        )
        self._assert_multiple_equal(
            network_traffic.id, nt_ref, f"network-traffic--{ip_object['uuid']}"
        )
        self._assert_multiple_equal(
            indicator.id, indicator_ref, f"indicator--{ip_object['uuid']}"
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
            ap_od_relation, ap_ref, observed_data2_ref, 'threatens', timestamp
        )
        timestamp = as_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self._check_relationship_features(
            od_od_relation, observed_data1_ref, observed_data2_ref, 'includes', timestamp
        )
        timestamp = btc_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self._check_relationship_features(
            custom_od_relation, custom_ref, observed_data2_ref, 'connected-to', timestamp
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
            od_coa_relation, observed_data2_ref, coa_ref, 'protected-with', timestamp
        )
        self._check_relationship_features(
            ind_od_relation, indicator_ref, observed_data2_ref, 'based-on', timestamp
        )
        timestamp = person_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self._check_relationship_features(
            id_od_relation, person_ref, observed_data2_ref, 'owns', timestamp
        )
        timestamp = vuln_object['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        self._check_relationship_features(
            vuln_ind_relation, vuln_ref, observed_data2_ref, 'affects', timestamp
        )


class TestSTIX21JSONObjectsExport(TestSTIX21ObjectsExport):
    @classmethod
    def tearDownClass(self):
        objects_documentation = ObjectsDocumentationUpdater(
            'misp_objects_to_stix21',
            self._objects_v21,
            'export'
        )
        objects_documentation.check_export_mapping('stix21')

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
        misp_objects, stix_objects, object_refs, relationships = self._run_indicators_from_objects_tests(event['Event'])
        self._check_account_observable_objects(misp_objects, stix_objects, object_refs)
        self._check_account_indicator_objects(
            misp_objects,
            (stix_object[-1].pattern for stix_object in stix_objects)
        )
        for misp_object, objects, relationship in zip(misp_objects, stix_objects, relationships):
            *observables, indicator = objects
            self._populate_documentation(
                misp_object=misp_object, indicator=indicator,
                observed_data=observables, relationship=relationship
            )

    def test_event_with_account_observable_objects(self):
        event = get_event_with_account_objects()
        misp_objects, stix_objects, object_refs = self._run_observables_from_objects_tests(event['Event'])
        self._check_account_observable_objects(misp_objects, stix_objects, object_refs)
        for misp_object, observables in zip(misp_objects, stix_objects):
            self._populate_documentation(
                misp_object = misp_object, observed_data = observables
            )

    def test_event_with_account_indicator_objects_with_attachment(self):
        event = get_event_with_account_objects_with_attachment()
        misp_objects, stix_objects, object_refs, relationships = self._run_indicators_from_objects_tests(event['Event'])
        self._check_account_with_attachment_observable_objects(misp_objects, stix_objects, object_refs)
        self._check_account_with_attachment_indicator_objects(
            misp_objects,
            (stix_object[-1].pattern for stix_object in stix_objects)
        )
        for misp_object, objects, relationship in zip(misp_objects, stix_objects, relationships):
            *observables, indicator = objects
            self._populate_documentation(
                misp_object=misp_object, indicator=indicator,
                observed_data=observables, relationship=relationship
            )

    def test_event_with_account_observable_object_with_attachment(self):
        event = get_event_with_account_objects_with_attachment()
        misp_objects, stix_objects, object_refs = self._run_observables_from_objects_tests(event['Event'])
        self._check_account_with_attachment_observable_objects(misp_objects, stix_objects, object_refs)
        for misp_object, observables in zip(misp_objects, stix_objects):
            self._populate_documentation(
                misp_object = misp_object, observed_data = observables
            )

    def test_event_with_annotation_object(self):
        event = get_event_with_annotation_object()
        self._test_event_with_annotation_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            note = self.parser.stix_objects[-1]
        )

    def test_event_with_android_app_indicator_object(self):
        event = get_event_with_android_app_object()
        self._test_event_with_android_app_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_android_app_observable_object(self):
        event = get_event_with_android_app_object()
        self._test_event_with_android_app_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            observed_data = self.parser.stix_objects[-2:]
        )

    def test_event_with_asn_indicator_object(self):
        event = get_event_with_asn_object()
        self._test_event_with_asn_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_asn_observable_object(self):
        event = get_event_with_asn_object()
        self._test_event_with_asn_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            observed_data = self.parser.stix_objects[-2:]
        )

    def test_event_with_attack_pattern_object(self):
        event = get_event_with_attack_pattern_object()
        self._test_event_with_attack_pattern_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            attack_pattern = self.parser.stix_objects[-1]
        )

    def test_event_with_course_of_action_object(self):
        event = get_event_with_course_of_action_object()
        self._test_event_with_course_of_action_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            course_of_action = self.parser.stix_objects[-1]
        )

    def test_event_with_cpe_asset_indicator_object(self):
        event = get_event_with_cpe_asset_object()
        self._test_event_with_cpe_asset_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_cpe_asset_observable_object(self):
        event = get_event_with_cpe_asset_object()
        self._test_event_with_cpe_asset_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            observed_data = self.parser.stix_objects[-2:]
        )

    def test_event_with_credential_indicator_object(self):
        event = get_event_with_credential_object()
        self._test_event_with_credential_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_credential_observable_object(self):
        event = get_event_with_credential_object()
        self._test_event_with_credential_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            observed_data = self.parser.stix_objects[-2:]
        )

    def test_event_with_custom_objects(self):
        event = get_event_with_custom_objects()
        self._test_event_with_custom_object(event['Event'])

    def test_event_with_domain_ip_indicator_object(self):
        event = get_event_with_domain_ip_object_custom()
        self._test_event_with_domain_ip_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_domain_ip_observable_object_custom(self):
        event = get_event_with_domain_ip_object_custom()
        self._test_event_with_domain_ip_observable_object_custom(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            observed_data = self.parser.stix_objects[-3:]
        )

    def test_event_with_domain_ip_observable_object_standard(self):
        event = get_event_with_domain_ip_object_standard()
        self._test_event_with_domain_ip_observable_object_standard(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            observed_data = self.parser.stix_objects[-5:],
            name = 'domain-ip with the perfect domain & ip matching',
            summary = 'A tuple of IPv4/IPv6 Address & Network Objects for each associated domain & ip'
        )

    def test_event_with_email_indicator_object(self):
        event = get_event_with_email_object()
        self._test_event_with_email_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_email_observable_object(self):
        event = get_event_with_email_object()
        self._test_event_with_email_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            observed_data = self.parser.stix_objects[-9:]
        )

    def test_event_with_email_with_display_names_indicator_object(self):
        event = get_event_with_email_object_with_display_names()
        self._test_event_with_email_with_display_names_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            indicator = self.parser.stix_objects[-1],
            name = 'email with display names'
        )

    def test_event_with_email_with_display_names_observable_object(self):
        event = get_event_with_email_object_with_display_names()
        self._test_event_with_email_with_display_names_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            observed_data = self.parser.stix_objects[-7:],
            name = 'email with display names'
        )

    def test_event_with_employee_object(self):
        event = get_event_with_employee_object()
        self._test_event_with_employee_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            identity = self.parser.stix_objects[-1]
        )

    def test_event_with_file_and_pe_indicator_objects(self):
        event = get_event_with_file_and_pe_objects()
        self._test_event_with_file_and_pe_indicator_objects(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects,
            indicator = self.parser.stix_objects[-1],
            name = 'file with references to pe & pe-section(s)',
            summary = 'File Object with a Windows PE binary extension'
        )

    def test_event_with_file_and_pe_observable_objects(self):
        event = get_event_with_file_and_pe_objects()
        self._test_event_with_file_and_pe_observable_objects(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects,
            observed_data = self.parser.stix_objects[-2:],
            name = 'file with references to pe & pe-section(s)'
        )

    def test_event_with_file_indicator_object(self):
        event = get_event_with_file_object_with_artifact()
        self._test_event_with_file_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            indicator = self.parser.stix_objects[-1],
            summary = 'File Object (potential references to Artifact & Directory Objects)'
        )

    def test_event_with_file_observable_object(self):
        event = get_event_with_file_object_with_artifact()
        self._test_event_with_file_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            observed_data = self.parser.stix_objects[-4:]
        )

    def test_event_with_geolocation_object(self):
        event = get_event_with_geolocation_object()
        self._test_event_with_geolocation_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            location = self.parser.stix_objects[-1]
        )

    def test_event_with_http_request_indicator_object(self):
        event = get_event_with_http_request_object()
        self._test_event_with_http_request_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_http_request_observable_object(self):
        event = get_event_with_http_request_object()
        self._test_event_with_http_request_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            observed_data = self.parser.stix_objects[-5:]
        )

    def test_event_with_identity_object(self):
        event = get_event_with_identity_object()
        self._test_event_with_identity_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            identity = self.parser.stix_objects[-1]
        )

    def test_event_with_image_indicator_object(self):
        event = get_event_with_image_object()
        self._test_event_with_image_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_image_observable_object(self):
        event = get_event_with_image_object()
        self._test_event_with_image_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            observed_data = self.parser.stix_objects[-3:]
        )

    def test_event_with_intrusion_set_object(self):
        event = get_event_with_intrusion_set_object()
        self._test_event_with_intrusion_set_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            intrusion_set = self.parser.stix_objects[-1]
        )

    def test_event_with_ip_port_indicator_object(self):
        event = get_event_with_ip_port_object()
        self._test_event_with_ip_port_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_ip_port_observable_object(self):
        event = get_event_with_ip_port_object()
        self._test_event_with_ip_port_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            observed_data = self.parser.stix_objects[-3:]
        )

    def test_event_with_legal_entity_object(self):
        event = get_event_with_legal_entity_object()
        self._test_event_with_legal_entity_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            identity = self.parser.stix_objects[-1]
        )

    def test_event_with_lnk_indicator_object(self):
        event = get_event_with_lnk_object()
        self._test_event_with_lnk_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_lnk_observable_object(self):
        event = get_event_with_lnk_object()
        self._test_event_with_lnk_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            observed_data = self.parser.stix_objects[-4:]
        )

    def test_event_with_mutex_indicator_object(self):
        event = get_event_with_mutex_object()
        self._test_event_with_mutex_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_mutex_observable_object(self):
        event = get_event_with_mutex_object()
        self._test_event_with_mutex_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            observed_data = self.parser.stix_objects[-2:]
        )

    def test_event_with_netflow_indicator_object(self):
        event = get_event_with_netflow_object()
        self._test_event_with_netflow_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_netflow_observable_object(self):
        event = get_event_with_netflow_object()
        self._test_event_with_netflow_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            observed_data = self.parser.stix_objects[-6:]
        )

    def test_event_with_network_connection_indicator_object(self):
        event = get_event_with_network_connection_object()
        self._test_event_with_network_connection_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            indicator = self.parser.stix_objects[-1],
            summary = 'Network Traffic, IPv4/IPv6 Address & Domain Name Objects'
        )

    def test_event_with_network_connection_observable_object(self):
        event = get_event_with_network_connection_object()
        self._test_event_with_network_connection_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            observed_data = self.parser.stix_objects[-4:]
        )

    def test_event_with_network_socket_indicator_object(self):
        event = get_event_with_network_socket_object()
        self._test_event_with_network_socket_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            indicator = self.parser.stix_objects[-1],
            summary = 'Network Traffic with a socket extension, IPv4/IPv6 Address & Domain Name Objects'
        )

    def test_event_with_network_socket_observable_object(self):
        event = get_event_with_network_socket_object()
        self._test_event_with_network_socket_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            observed_data = self.parser.stix_objects[-4:]
        )

    def test_event_with_news_agency_object(self):
        event = get_event_with_news_agency_object()
        self._test_event_with_news_agency_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            identity = self.parser.stix_objects[-1]
        )

    def test_event_with_organisation_object(self):
        event = get_event_with_organization_object()
        self._test_event_with_organisation_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            identity = self.parser.stix_objects[-1]
        )

    def test_event_with_patterning_language_objects(self):
        event = get_event_with_patterning_language_objects()
        self._test_event_with_patterning_language_objects(event['Event'])
        for misp_object, indicator in zip(self.parser._misp_event.objects, self.parser.stix_objects[-3:]):
            self._populate_documentation(misp_object=misp_object, indicator=indicator)

    def test_event_with_pe_and_section_indicator_objects(self):
        event = get_event_with_pe_objects()
        self._test_event_with_pe_and_section_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects,
            indicator = self.parser.stix_objects[-1],
            name = 'pe & pe-sections',
            summary = 'Windows PE binary extension within a File Object'
        )

    def test_event_with_pe_and_section_observable_objects(self):
        event = get_event_with_pe_objects()
        self._test_event_with_pe_and_section_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects,
            observed_data = self.parser.stix_objects[-2:],
            name = 'pe & pe-sections'
        )

    def test_event_with_person_object(self):
        event = get_event_with_person_object()
        self._test_event_with_person_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            identity = self.parser.stix_objects[-1]
        )

    def test_event_with_process_indicator_object(self):
        event = get_event_with_process_object_v2()
        self._test_event_with_process_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            indicator = self.parser.stix_objects[-1],
            summary = 'Process Objects (potential reference to File Objects)'
        )

    def test_event_with_process_observable_object(self):
        event = get_event_with_process_object_v2()
        self._test_event_with_process_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            observed_data = self.parser.stix_objects[-6:]
        )

    def test_event_with_registry_key_indicator_object(self):
        event = get_event_with_registry_key_object()
        self._test_event_with_registry_key_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_registry_key_observable_object(self):
        event = get_event_with_registry_key_object()
        self._test_event_with_registry_key_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            observed_data = self.parser.stix_objects[-2:]
        )

    def test_event_with_script_objects(self):
        event = get_event_with_script_objects()
        self._test_event_with_script_objects(event['Event'])
        misp_objects = self.parser._misp_event.objects
        self._populate_documentation(
            misp_object = misp_objects[0],
            malware = self.parser.stix_objects[-2],
            name = 'Script object where state is "Malicious"'
        )
        self._populate_documentation(
            misp_object = misp_objects[1],
            tool = self.parser.stix_objects[-1],
            name = 'Script object where state is not "Malicious"'
        )

    def test_event_with_url_indicator_object(self):
        event = get_event_with_url_object()
        self._test_event_with_url_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_url_observable_object(self):
        event = get_event_with_url_object()
        self._test_event_with_url_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            observed_data = self.parser.stix_objects[-2:]
        )

    def test_event_with_user_account_indicator_object(self):
        event = get_event_with_user_account_object()
        self._test_event_with_user_account_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_user_account_observable_object(self):
        event = get_event_with_user_account_object()
        self._test_event_with_user_account_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            observed_data = self.parser.stix_objects[-2:]
        )

    def test_event_with_vulnerability_object(self):
        event = get_event_with_vulnerability_object()
        self._test_event_with_vulnerability_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            vulnerability = self.parser.stix_objects[-1]
        )

    def test_event_with_x509_indicator_object(self):
        event = get_event_with_x509_object()
        self._test_event_with_x509_indicator_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            indicator = self.parser.stix_objects[-1]
        )

    def test_event_with_x509_observable_object(self):
        event = get_event_with_x509_object()
        self._test_event_with_x509_observable_object(event['Event'])
        self._populate_documentation(
            misp_object = self.parser._misp_event.objects[0],
            observed_data = self.parser.stix_objects[-2:]
        )

    def test_object_references(self):
        event = get_event_with_object_references()
        self._test_object_references(event['Event'])


class TestSTIX21MISPObjectsExport(TestSTIX21ObjectsExport):
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
        misp_objects, stix_objects, object_refs, _ = self._run_indicators_from_objects_tests(misp_event)
        self._check_account_observable_objects(misp_objects, stix_objects, object_refs)
        self._check_account_indicator_objects(
            misp_objects,
            (stix_object[-1].pattern for stix_object in stix_objects)
        )

    def test_event_with_account_observable_objects(self):
        event = get_event_with_account_objects()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        misp_objects, observables, object_refs = self._run_observables_from_objects_tests(misp_event)
        self._check_account_observable_objects(misp_objects, observables, object_refs)

    def test_event_with_account_indicator_objects_with_attachment(self):
        event = get_event_with_account_objects_with_attachment()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        misp_objects, stix_objects, object_refs, _ = self._run_indicators_from_objects_tests(misp_event)
        self._check_account_with_attachment_observable_objects(misp_objects, stix_objects, object_refs)
        self._check_account_with_attachment_indicator_objects(
            misp_objects,
            (stix_object[-1].pattern for stix_object in stix_objects)
        )

    def test_event_with_account_observable_object_with_attachment(self):
        event = get_event_with_account_objects_with_attachment()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        misp_objects, observables, object_refs = self._run_observables_from_objects_tests(misp_event)
        self._check_account_with_attachment_observable_objects(misp_objects, observables, object_refs)

    def test_event_with_annotation_object(self):
        event = get_event_with_annotation_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_annotation_object(misp_event)

    def test_event_with_android_app_indicator_object(self):
        event = get_event_with_android_app_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_android_app_indicator_object(misp_event)

    def test_event_with_android_app_observable_object(self):
        event = get_event_with_android_app_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_android_app_observable_object(misp_event)

    def test_event_with_asn_indicator_object(self):
        event = get_event_with_asn_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_asn_indicator_object(misp_event)

    def test_event_with_asn_observable_object(self):
        event = get_event_with_asn_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_asn_observable_object(misp_event)

    def test_event_with_attack_pattern_object(self):
        event = get_event_with_attack_pattern_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_attack_pattern_object(misp_event)

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
        self._test_event_with_custom_object(misp_event)

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

    def test_event_with_email_with_display_names_indicator_object(self):
        event = get_event_with_email_object_with_display_names()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_email_with_display_names_indicator_object(misp_event)

    def test_event_with_email_with_display_names_observable_object(self):
        event = get_event_with_email_object_with_display_names()
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

    def test_event_with_geolocation_object(self):
        event = get_event_with_geolocation_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_geolocation_object(misp_event)

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

    def test_event_with_organisation_object(self):
        event = get_event_with_organization_object()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_organisation_object(misp_event)

    def test_event_with_patterning_language_objects(self):
        event = get_event_with_patterning_language_objects()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_patterning_language_objects(misp_event)

    def test_event_with_pe_and_section_indicator_objects(self):
        event = get_event_with_pe_objects()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_pe_and_section_indicator_object(misp_event)

    def test_event_with_pe_and_section_observable_objects(self):
        event = get_event_with_pe_objects()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_pe_and_section_observable_object(misp_event)

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


class TestSTIX21GalaxiesExport(TestSTIX21GenericExport):
    def _check_attack_pattern_meta_fields(self, stix_object, meta):
        super()._check_attack_pattern_meta_fields(stix_object, meta)
        if meta.get('synonyms') is not None:
            self.assertEqual(stix_object.aliases, meta['synonyms'])

    def _check_location_meta_fields(self, stix_object, meta):
        for key, value in meta.items():
            self.assertEqual(getattr(stix_object, key), value)

    def _check_malware_meta_fields(self, stix_object, meta):
        super()._check_malware_meta_fields(stix_object, meta)
        # Custom Malware Galaxy Cluster fields
        if meta.get('architecture_execution_env') is not None:
            self.assertEqual(
                stix_object.architecture_execution_env,
                meta['architecture_execution_env']
            )
        if meta.get('capabilities') is not None:
            self.assertEqual(
                stix_object.capabilities, meta['capabilities']
            )
        if meta.get('implementation_languages') is not None:
            self.assertEqual(
                stix_object.implementation_languages,
                meta['implementation_languages']
            )
        if meta.get('is_family') is not None:
            self.assertEqual(stix_object.is_family, meta['is_family'])
        if meta.get('malware_types') is not None:
            self.assertEqual(stix_object.malware_types, meta['malware_types'])
        elif meta.get('labels') is not None:
            self.assertEqual(stix_object.malware_types, meta['labels'])

    def _check_threat_actor_meta_fields(self, stix_object, meta):
        super()._check_threat_actor_meta_fields(stix_object, meta)
        if meta.get('threat_actor_types') is not None:
            self.assertEqual(
                stix_object.threat_actor_types, meta['threat_actor_types']
            )
        elif meta.get('labels') is not None:
            self.assertEqual(stix_object.threat_actor_types, meta['labels'])

    def _check_tool_meta_fields(self, stix_object, meta):
        super()._check_tool_meta_fields(stix_object, meta)
        if meta.get('tool_types') is not None:
            self.assertEqual(stix_object.tool_types, meta['tool_types'])
        elif meta.get('labels') is not None:
            self.assertEqual(stix_object.tool_types, meta['labels'])

    def _run_galaxy_tests(self, event, timestamp):
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, stix_object = stix_objects
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_grouping_features(grouping, identity_id)[0]
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

    def _test_event_with_location_galaxies(self, event):
        country, region = event['Galaxy']
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        orgc = event['Orgc']
        self.parser.parse_misp_event(event)
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, location1, location2 = stix_objects
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        location1_ref, location2_ref = self._check_grouping_features(
            grouping, identity_id
        )
        self.assertEqual(location1.id, location1_ref)
        self.assertEqual(location2.id, location2_ref)
        self._assert_multiple_equal(
            location1.type,
            location2.type,
            'location'
        )
        cluster = country['GalaxyCluster'][0]
        self.assertEqual(location1.id, f"{location1.type}--{cluster['uuid']}")
        self.assertEqual(location1.created, timestamp)
        self.assertEqual(location1.modified, timestamp)
        self.assertEqual(location1.name, cluster['description'])
        self.assertEqual(
            location1.description,
            f"{country['description']} | {cluster['value']}"
        )
        self.assertEqual(location1.labels[0], f'misp:galaxy-name="{country["name"]}"')
        self.assertEqual(location1.labels[1], f'misp:galaxy-type="{country["type"]}"')
        for key, values in cluster['meta'].items():
            self.assertEqual(getattr(location1, f'x_misp_{key}'), values)
        cluster = region['GalaxyCluster'][0]
        self.assertEqual(location2.id, f"{location2.type}--{cluster['uuid']}")
        self.assertEqual(location2.created, timestamp)
        self.assertEqual(location2.modified, timestamp)
        region_value = cluster['value'].split(' - ')[-1]
        self.assertEqual(location2.name, region_value)
        self.assertEqual(
            location2.description, f"{region['description']} | {cluster['description']}"
        )
        self.assertEqual(location2.labels[0], f'misp:galaxy-name="{region["name"]}"')
        self.assertEqual(location2.labels[1], f'misp:galaxy-type="{region["type"]}"')
        for key, values in cluster['meta'].items():
            self.assertEqual(getattr(location2, f'x_misp_{key}'), values)
        self.assertEqual(location2.region, region_value.lower().replace(' ', '-'))

    def _test_event_with_location_galaxy(self, event):
        galaxy = event['Galaxy'][0]
        timestamp = event['timestamp']
        if not isinstance(timestamp, datetime):
            timestamp = self._datetime_from_timestamp(timestamp)
        location = self._run_galaxy_tests(event, timestamp)
        self.assertEqual(location.type, 'location')
        self._check_galaxy_features(location, galaxy, timestamp)

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


class TestSTIX21JSONGalaxiesExport(TestSTIX21GalaxiesExport):
    _mapping_types = MISPtoSTIX21Mapping

    @classmethod
    def tearDownClass(self):
        galaxies_documentation = GalaxiesDocumentationUpdater(
            'misp_galaxies_to_stix21',
            self._galaxies_v21,
            'export'
        )
        galaxies_documentation.check_export_mapping('stix21')

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

    def test_event_with_custom_attack_pattern_20_galaxy(self):
        event = get_event_with_custom_attack_pattern_galaxy('2.0')
        self._test_event_with_attack_pattern_galaxy(event['Event'])
        self._populate_documentation(
            galaxy = event['Event']['Galaxy'][0],
            attack_pattern = self.parser.stix_objects[-1]
        )

    def test_event_with_custom_attack_pattern_21_galaxy(self):
        event = get_event_with_custom_attack_pattern_galaxy('2.1')
        self._test_event_with_attack_pattern_galaxy(event['Event'])
        self._populate_documentation(
            galaxy = event['Event']['Galaxy'][0],
            attack_pattern = self.parser.stix_objects[-1]
        )

    def test_event_with_custom_campaign_20_galaxy(self):
        event = get_event_with_custom_campaign_galaxy('2.0')
        self._test_event_with_campaign_galaxy(event['Event'])
        self._populate_documentation(
            galaxy = event['Event']['Galaxy'][0],
            campaign = self.parser.stix_objects[-1]
        )

    def test_event_with_custom_campaign_21_galaxy(self):
        event = get_event_with_custom_campaign_galaxy('2.1')
        self._test_event_with_campaign_galaxy(event['Event'])
        self._populate_documentation(
            galaxy = event['Event']['Galaxy'][0],
            campaign = self.parser.stix_objects[-1]
        )

    def test_event_with_custom_course_of_action_20_galaxy(self):
        event = get_event_with_custom_course_of_action_galaxy('2.0')
        self._test_event_with_course_of_action_galaxy(event['Event'])
        self._populate_documentation(
            galaxy = event['Event']['Galaxy'][0],
            course_of_action = self.parser.stix_objects[-1]
        )

    def test_event_with_custom_course_of_action_21_galaxy(self):
        event = get_event_with_custom_course_of_action_galaxy('2.1')
        self._test_event_with_course_of_action_galaxy(event['Event'])
        self._populate_documentation(
            galaxy = event['Event']['Galaxy'][0],
            course_of_action = self.parser.stix_objects[-1]
        )

    def test_event_with_custom_galaxy(self):
        event = get_event_with_custom_galaxy()
        self._test_event_with_custom_galaxy(event['Event'])

    def test_event_with_custom_intrusion_set_20_galaxy(self):
        event = get_event_with_custom_intrusion_set_galaxy('2.0')
        self._test_event_with_intrusion_set_galaxy(event['Event'])
        self._populate_documentation(
            galaxy = event['Event']['Galaxy'][0],
            intrusion_set = self.parser.stix_objects[-1],
        )

    def test_event_with_custom_intrusion_set_21_galaxy(self):
        event = get_event_with_custom_intrusion_set_galaxy('2.1')
        self._test_event_with_intrusion_set_galaxy(event['Event'])
        self._populate_documentation(
            galaxy = event['Event']['Galaxy'][0],
            intrusion_set = self.parser.stix_objects[-1],
        )

    def test_event_with_custom_location_galaxy(self):
        event = get_event_with_custom_location_galaxy()
        self._test_event_with_location_galaxy(event['Event'])
        self._populate_documentation(
            galaxy = event['Event']['Galaxy'][0],
            location = self.parser.stix_objects[-1]
        )

    def test_event_with_custom_malware_20_galaxy(self):
        event = get_event_with_custom_malware_galaxy('2.0')
        self._test_event_with_malware_galaxy(event['Event'])
        self._populate_documentation(
            galaxy = event['Event']['Galaxy'][0],
            malware = self.parser.stix_objects[-1]
        )

    def test_event_with_custom_malware_21_galaxy(self):
        event = get_event_with_custom_malware_galaxy('2.1')
        self._test_event_with_malware_galaxy(event['Event'])
        self._populate_documentation(
            galaxy = event['Event']['Galaxy'][0],
            malware = self.parser.stix_objects[-1]
        )

    def test_event_with_custom_threat_actor_20_galaxy(self):
        event = get_event_with_custom_threat_actor_galaxy('2.0')
        self._test_event_with_threat_actor_galaxy(event['Event'])
        self._populate_documentation(
            galaxy = event['Event']['Galaxy'][0],
            threat_actor = self.parser.stix_objects[-1]
        )

    def test_event_with_custom_threat_actor_21_galaxy(self):
        event = get_event_with_custom_threat_actor_galaxy('2.1')
        self._test_event_with_threat_actor_galaxy(event['Event'])
        self._populate_documentation(
            galaxy = event['Event']['Galaxy'][0],
            threat_actor = self.parser.stix_objects[-1]
        )

    def test_event_with_custom_tool_20_galaxy(self):
        event = get_event_with_custom_tool_galaxy('2.0')
        self._test_event_with_tool_galaxy(event['Event'])
        self._populate_documentation(
            galaxy = event['Event']['Galaxy'][0],
            tool = self.parser.stix_objects[-1]
        )

    def test_event_with_custom_tool_21_galaxy(self):
        event = get_event_with_custom_tool_galaxy('2.1')
        self._test_event_with_tool_galaxy(event['Event'])
        self._populate_documentation(
            galaxy = event['Event']['Galaxy'][0],
            tool = self.parser.stix_objects[-1]
        )

    def test_event_with_custom_vulnerability_20_galaxy(self):
        event = get_event_with_custom_vulnerability_galaxy('2.0')
        self._test_event_with_vulnerability_galaxy(event['Event'])
        self._populate_documentation(
            galaxy = event['Event']['Galaxy'][0],
            vulnerability = self.parser.stix_objects[-1]
        )

    def test_event_with_custom_vulnerability_21_galaxy(self):
        event = get_event_with_custom_vulnerability_galaxy('2.1')
        self._test_event_with_vulnerability_galaxy(event['Event'])
        self._populate_documentation(
            galaxy = event['Event']['Galaxy'][0],
            vulnerability = self.parser.stix_objects[-1]
        )

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

    def test_event_with_location_galaxies(self):
        event = get_event_with_location_galaxies()
        self._test_event_with_location_galaxies(event['Event'])
        for galaxy, location in zip(event['Event']['Galaxy'], self.parser.stix_objects[-2:]):
            self._populate_documentation(
                galaxy=galaxy,
                location=location
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

    def test_attribute_with_attack_pattern_galaxy(self):
        attribute = get_indicator_attribute_with_galaxy()
        misp_attribute = {"Attribute": [attribute]}
        self.parser.parse_misp_attributes(misp_attribute)
        self.assertIsNotNone(self.parser.bundle)


class TestSTIX21MISPGalaxiesExport(TestSTIX21GalaxiesExport):
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

    def test_event_with_custom_location_galaxy(self):
        event = get_event_with_custom_location_galaxy()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_location_galaxy(misp_event)

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

    def test_event_with_location_galaxies(self):
        event = get_event_with_location_galaxies()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_location_galaxies(misp_event)

    def test_event_with_malware_galaxy(self):
        event = get_event_with_malware_galaxy()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_malware_galaxy(misp_event)

    def test_event_with_sector_galaxy(self):
        event = get_event_with_sector_galaxy()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_sector_galaxy(misp_event)

    def test_event_with_threat_actor_galaxy(self):
        event = get_event_with_threat_actor_galaxy()
        misp_event = MISPEvent()
        misp_event.from_dict(**event)
        self._test_event_with_threat_actor_galaxy(misp_event)

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


class TestSTIX21ExportInteroperability(TestSTIX2Export, TestSTIX21):
    def setUp(self):
        self.parser = MISPtoSTIX21Parser(interoperability=True)

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
        stix_objects = self.parser.stix_objects
        for stix_object in stix_objects:
            self.assertEqual(stix_object.spec_version, '2.1')
        mitre_identity, identity, grouping, stix_object = stix_objects
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        object_ref = self._check_grouping_features(grouping, identity_id)[0]
        self.assertEqual(stix_object.id, object_ref)
        self.assertEqual(stix_object.created_by_ref, mitre_identity.id)
        return stix_object


class TestSTIX21JSONExportInteroperability(TestSTIX21ExportInteroperability):
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


class TestSTIX21MISPExportInteroperability(TestSTIX21ExportInteroperability):
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


class TestCollectionSTIX21Export(TestCollectionSTIX2Export):
    def test_attributes_collection(self):
        name = 'test_attributes_collection'
        output_file = self._current_path / f'{name}.json.out'
        reference_file = self._current_path / f'{name}_stix21.json'
        input_files = [self._current_path / f'{name}_{n}.json' for n in (1, 2)]
        self.assertEqual(
            misp_collection_to_stix2(
                *input_files, version='2.1', single_output=True,
                output_name=output_file
            ),
            {'success': 1, 'results': [output_file]}
        )
        self._check_stix2_results_export(output_file, reference_file)
        self.assertEqual(
            misp_collection_to_stix2(
                *input_files, version='2.1', in_memory=True,
                single_output=True, output_name=output_file
            ),
            {'success': 1, 'results': [output_file]}
        )
        self._check_stix2_results_export(output_file, reference_file)
        self.assertEqual(
            misp_collection_to_stix2(*input_files, version='2.1'),
            {
                'success': 1,
                'results': [
                    self._current_path / f'{name}_{n}.json.out' for n in (1, 2)
                ]
            }
        )

    def test_events_collection(self):
        name = 'test_events_collection'
        output_file = self._current_path / f'{name}.json.out'
        reference_file = self._current_path / f'{name}_stix21.json'
        input_files = [self._current_path / f'{name}_{n}.json' for n in (1, 2)]
        self.assertEqual(
            misp_collection_to_stix2(
                *input_files, version='2.1', single_output=True,
                output_name=output_file
            ),
            {'success': 1, 'results': [output_file]}
        )
        self._check_stix2_results_export(output_file, reference_file)
        self.assertEqual(
            misp_collection_to_stix2(
                *input_files, version='2.1', in_memory=True,
                single_output=True, output_name=output_file
            ),
            {'success': 1, 'results': [output_file]}
        )
        self._check_stix2_results_export(output_file, reference_file)
        self.assertEqual(
            misp_collection_to_stix2(*input_files, version='2.1'),
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
                self._current_path / f'test_event{n}_stix21.json'
            )


    def test_event_export(self):
        name = 'test_events_collection_1.json'
        filename = self._current_path / name
        output_file = self._current_path / f'{name}.out'
        reference_file = self._current_path / 'test_event1_stix21.json'
        self.assertEqual(
            misp_to_stix2(filename, version='2.1'),
            {'success': 1, 'results': [output_file]}
        )
        self._check_stix2_results_export(output_file, reference_file)
        self.assertEqual(
            misp_collection_to_stix2(
                filename, version='2.1'
            ),
            {'success': 1, 'results': [output_file]}
        )
        self._check_stix2_results_export(output_file, reference_file)


class TestFeedSTIX21Export(TestSTIX2Export):
    def setUp(self):
        self.parser = MISPtoSTIX21Parser()


class TestFeedSTIX21JSONExport(TestFeedSTIX21Export):
    def test_attributes_feed(self):
        attributes = get_attributes_feed()
        for attribute in attributes[:2]:
            self.parser.parse_misp_attribute(attribute)
        bundle = self.parser.bundle
        (identity1, od1, nt1, ip1, indicator1, relationship1,
         od2, nt2, ip2, indicator2, relationship2) = bundle.objects
        for attribute in attributes[2:]:
            self.parser.parse_misp_attribute(attribute)
        bundle = self.parser.bundle
        (identity2, od3, nt3, ip3, indicator3, relationship3,
         od4, nt4, ip4, indicator4, relationship4) = bundle.objects
        self._assert_multiple_equal(
            f"identity--{attributes[2]['Event']['Orgc']['uuid']}",
            identity1.id,
            identity2.id
        )
        self._assert_multiple_equal(
            attributes[3]['Event']['Orgc']['name'],
            identity1.name,
            identity2.name
        )
        indicators = (indicator1, indicator2, indicator3, indicator4)
        observed_data_objects = (od1, od2, od3, od4)
        relationships = (relationship1, relationship2, relationship3, relationship4)
        network_traffic_observables = (nt1, nt2, nt3, nt4)
        ip_address_observables = (ip1, ip2, ip3, ip4)
        for index, attribute in enumerate(attributes):
            attribute_uuid = attribute['Attribute']['uuid']
            indicator = indicators[index]
            observed_data = observed_data_objects[index]
            relationship = relationships[index]
            network_traffic = network_traffic_observables[index]
            ip_address = ip_address_observables[index]
            self._assert_multiple_equal(
                indicator.id, relationship.source_ref,
                f'indicator--{attribute_uuid}'
            )
            self._assert_multiple_equal(
                observed_data.id, relationship.target_ref,
                f'observed-data--{attribute_uuid}'
            )
            self.assertEqual(network_traffic.id, f'network-traffic--{attribute_uuid}')
            self.assertEqual(ip_address.id, f'ipv4-addr--{attribute_uuid}')


class TestFeedSTIX21MISPExport(TestFeedSTIX21Export):
    def test_attributes_feed(self):
        attributes = get_attributes_feed()
        for attribute in attributes[:2]:
            misp_attribute = MISPAttribute()
            misp_attribute.from_dict(**attribute)
            self.parser.parse_misp_attribute(misp_attribute)
        bundle = self.parser.bundle
        (identity1, od1, nt1, ip1, indicator1, relationship1,
         od2, nt2, ip2, indicator2, relationship2) = bundle.objects
        for attribute in attributes[2:]:
            misp_attribute = MISPAttribute()
            misp_attribute.from_dict(**attribute)
            self.parser.parse_misp_attribute(misp_attribute)
        bundle = self.parser.bundle
        (identity2, od3, nt3, ip3, indicator3, relationship3,
         od4, nt4, ip4, indicator4, relationship4) = bundle.objects
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
        observed_data_objects = (od1, od2, od3, od4)
        relationships = (relationship1, relationship2, relationship3, relationship4)
        network_traffic_observables = (nt1, nt2, nt3, nt4)
        ip_address_observables = (ip1, ip2, ip3, ip4)
        for index, attribute in enumerate(attributes):
            attribute_uuid = attribute['Attribute']['uuid']
            indicator = indicators[index]
            observed_data = observed_data_objects[index]
            relationship = relationships[index]
            network_traffic = network_traffic_observables[index]
            ip_address = ip_address_observables[index]
            self._assert_multiple_equal(
                indicator.id, relationship.source_ref,
                f'indicator--{attribute_uuid}'
            )
            self._assert_multiple_equal(
                observed_data.id, relationship.target_ref,
                f'observed-data--{attribute_uuid}'
            )
            self.assertEqual(network_traffic.id, f'network-traffic--{attribute_uuid}')
            self.assertEqual(ip_address.id, f'ipv4-addr--{attribute_uuid}')
