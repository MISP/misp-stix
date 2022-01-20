#!/usr/bin/env python
# -*- coding: utf-8 -*-

from datetime import datetime
from misp_stix_converter import MISPtoSTIX21Parser, misp_collection_to_stix2_1, misp_to_stix2_1
from .test_events import *
from ._test_stix_export import TestCollectionSTIX2Export, TestSTIX2Export


class TestSTIX21Export(TestSTIX2Export):
    def setUp(self):
        self.parser = MISPtoSTIX21Parser()

    ################################################################################
    #                              UTILITY FUNCTIONS.                              #
    ################################################################################

    def _assert_multiple_equal(self, reference, *elements):
        for element in elements:
            self.assertEqual(reference, element)

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

    def _check_SCO(self, observable_object, attribute, reference, feature):
        value, uuid = attribute
        self.assertEqual(observable_object.id, reference)
        self.assertEqual(observable_object.type, feature)
        self.assertEqual(observable_object.id, f'{feature}--{uuid}')
        self.assertEqual(observable_object.value, value)

    def _check_spec_versions(self, stix_objects):
        for stix_object in stix_objects:
            self.assertEqual(stix_object.spec_version, '2.1')

    @staticmethod
    def _datetime_from_str(timestamp: str) -> datetime:
        regex = '%Y-%m-%dT%H:%M:%S'
        if '.' in timestamp:
            regex = f'{regex}.%f'
        return datetime.strptime(timestamp.split('+')[0], regex)

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

    def _run_indicators_from_objects_tests(self, event):
        self._add_object_ids_flag(event)
        orgc = event['Event']['Orgc']
        misp_objects = deepcopy(event['Event']['Object'])
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
        for indicator, misp_object, object_ref in zip(indicators, misp_objects, object_refs):
            self._check_object_indicator_features(indicator, misp_object, identity_id, object_ref)
            self._check_pattern_features(indicator)
        return misp_objects, tuple(indicator.pattern for indicator in indicators)

    def _run_indicator_from_objects_tests(self, event):
        self._add_object_ids_flag(event)
        orgc = event['Event']['Orgc']
        misp_objects = deepcopy(event['Event']['Object'])
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
        self._check_object_indicator_features(indicator, misp_objects[0], identity_id, object_ref)
        self._check_pattern_features(indicator)
        return misp_objects, indicator.pattern

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

    def _run_observables_from_objects_tests(self, event):
        self._remove_object_ids_flags(event)
        orgc = event['Event']['Orgc']
        misp_objects = deepcopy(event['Event']['Object'])
        self.parser.parse_misp_event(event)
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, *observables = stix_objects
        identity_id = self._check_identity_features(
            identity,
            orgc,
            self._datetime_from_timestamp(event['Event']['timestamp'])
        )
        ids = self._check_grouping_features(grouping, event['Event'], identity_id)
        observables, ids = self._reorder_observable_objects(observables, ids)
        object_refs = []
        for observable, misp_object, observable_id in zip(observables, misp_objects, ids):
            observed_data = observable.pop(0)
            object_refs.append(observed_data['object_refs'])
            self._check_object_observable_features(
                observed_data,
                misp_object,
                identity_id,
                observable_id.pop(0)
            )
        return misp_objects, ids, object_refs, observables

    def _run_observable_from_objects_tests(self, event):
        self._remove_object_ids_flags(event)
        orgc = event['Event']['Orgc']
        misp_objects = deepcopy(event['Event']['Object'])
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
            misp_objects[0],
            identity_id,
            observable_id
        )
        return misp_objects, ids, observed_data['object_refs'], observable

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
        object_refs = tuple(object_ref for observed_data in observed_datas for object_ref in observed_data['object_refs'])
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

    def test_event_with_escaped_characters(self):
        event = get_event_with_escaped_values_v21()
        self.parser.parse_misp_event(event)
        stix_objects = self._check_bundle_features(49)
        self._check_spec_versions(stix_objects)
        _, _, *indicators = stix_objects
        for indicator in indicators:
            self.assertEqual(indicator.type, 'indicator')

    def test_event_with_event_report(self):
        event = get_event_with_event_report()
        orgc = event['Event']['Orgc']
        event_report = event['Event']['EventReport'][0]
        self.parser.parse_misp_event(event)
        stix_objects = self._check_bundle_features(8)
        self._check_spec_versions(stix_objects)
        identity, grouping, *stix_objects = stix_objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        args = (
            grouping,
            event['Event'],
            identity_id
        )
        for stix_object, object_ref in zip(stix_objects, self._check_grouping_features(*args)):
            self.assertEqual(stix_object.id, object_ref)
        ip_src, observed_data, _, _, domain_ip, note = stix_objects
        self.assertEqual(note.id, f"note--{event_report['uuid']}")
        self.assertEqual(note.abstract, event_report['name'])
        self.assertEqual(note.created, self._datetime_from_timestamp(event_report['timestamp']))
        self.assertEqual(note.content, event_report['content'])
        object_refs = note.object_refs
        self.assertEqual(len(object_refs), 3)
        object_ids = {ip_src.id, observed_data.id, domain_ip.id}
        self.assertEqual(set(object_refs), object_ids)

    def test_event_with_sightings(self):
        event = get_event_with_sightings()
        orgc = event['Event']['Orgc']
        attribute1, attribute2 = event['Event']['Attribute']
        sightings1 = attribute1['Sighting']
        sightings2 = attribute2['Sighting']
        self.parser.parse_misp_event(event)
        stix_objects = self._check_bundle_features(12)
        self._check_spec_versions(stix_objects)
        identity, identity1, identity2, identity3, grouping, *stix_objects = stix_objects
        identities = (identity1, identity2, identity3)
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        args = (
            grouping,
            event['Event'],
            identity_id
        )
        for stix_object, object_ref in zip(stix_objects, self._check_grouping_features(*args)):
            self.assertEqual(stix_object.id, object_ref)
        self._check_identities_from_sighting(
            identities,
            tuple(f"identity--{sighting['Organisation']['uuid']}" for sighting in sightings1[:3]),
            tuple(sighting['Organisation']['name'] for sighting in sightings2[:3])
        )
        identity_ids = tuple(identity.id for identity in identities)
        observed_data, _, sighting1, opinion1, indicator, sighting2, opinion2 = stix_objects
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
        self.assertEqual(opinion1.type, 'opinion')
        self.assertEqual(opinion1.object_refs, [observed_data.id])
        self.assertEqual(len(opinion1.authors), 2)
        self.assertIn(sightings1[3]['Organisation']['name'], opinion1.authors)
        self.assertIn(sightings1[2]['Organisation']['name'], opinion1.authors)
        self.assertEqual(opinion1.explanation, "False positive Sighting")
        self.assertEqual(opinion1.opinion, "strongly-disagree")
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
        self.assertEqual(opinion2.type, 'opinion')
        self.assertEqual(opinion2.object_refs, [indicator.id])
        self.assertEqual(len(opinion2.authors), 2)
        self.assertIn(sightings2[1]['Organisation']['name'], opinion2.authors)
        self.assertIn(sightings2[3]['Organisation']['name'], opinion2.authors)
        self.assertEqual(opinion2.explanation, "False positive Sighting")
        self.assertEqual(opinion2.opinion, "strongly-disagree")

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
        attribute = deepcopy(event['Event']['Attribute'][0])
        event_galaxy = deepcopy(event['Event']['Galaxy'][0])
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
        ap_galaxy, coa_galaxy = attribute['Galaxy']
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
            indicator.id,
            indicator_ref,
            f"indicator--{attribute['uuid']}"
        )
        self._assert_multiple_equal(
            malware.id,
            malware_ref,
            f"malware--{event_galaxy['GalaxyCluster'][0]['uuid']}"
        )
        self.assertEqual(ap_relationship.id, apr_ref)
        self.assertEqual(coa_relationship.id, coar_ref)
        timestamp = self._datetime_from_timestamp(attribute['timestamp'])
        self._check_relationship_features(ap_relationship, indicator_ref, ap_ref, 'indicates', timestamp)
        self._check_relationship_features(coa_relationship, indicator_ref, coa_ref, 'has', timestamp)

    def test_embedded_non_indicator_attribute_galaxy(self):
        event = get_embedded_non_indicator_attribute_galaxy()
        orgc = event['Event']['Orgc']
        attribute = deepcopy(event['Event']['Attribute'][0])
        event_coa_galaxy, malware_galaxy = deepcopy(event['Event']['Galaxy'])
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
        timestamp = self._datetime_from_timestamp(attribute['timestamp'])
        self._check_relationship_features(ap_relationship, vulnerability_ref, ap_ref, 'has', timestamp)
        self._check_relationship_features(coa_relationship, vulnerability_ref, coa_ref, 'has', timestamp)

    def test_embedded_observable_attribute_galaxy(self):
        event = get_embedded_observable_attribute_galaxy()
        orgc = event['Event']['Orgc']
        attribute = deepcopy(event['Event']['Attribute'][0])
        event_galaxy = deepcopy(event['Event']['Galaxy'][0])
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
        attribute = deepcopy(event['Event']['Attribute'][0])
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        object_ref = object_refs[0]
        AS = observable[0]
        self.assertEqual(object_ref, grouping_refs[0])
        self._assert_multiple_equal(
            AS.id,
            object_ref,
            f"autonomous-system--{attribute['uuid']}"
        )
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
        attribute = deepcopy(event['Event']['Attribute'][0])
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        file_id, artifact_id = grouping_refs
        file_ref, artifact_ref = object_refs
        file_object, artifact_object = observable
        self._assert_multiple_equal(
            file_object.id,
            file_ref,
            file_id,
            f"file--{attribute['uuid']}"
        )
        self.assertEqual(file_object.type, 'file')
        self.assertEqual(file_object.name, attribute_value)
        self._assert_multiple_equal(
            file_object.content_ref,
            artifact_object.id,
            artifact_id,
            artifact_ref,
            f"artifact--{attribute['uuid']}"
        )
        self.assertEqual(artifact_object.type, 'artifact')
        self.assertEqual(artifact_object.payload_bin, attribute['data'])

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
            self._run_custom_attribute_tests(attribute, custom_object, object_ref, identity_id)

    def test_event_with_domain_indicator_attribute(self):
        event = get_event_with_domain_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[domain-name:value = '{attribute_value}']")

    def test_event_with_domain_observable_attribute(self):
        event = get_event_with_domain_attribute()
        attribute = deepcopy(event['Event']['Attribute'][0])
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        domain = observable[0]
        self._assert_multiple_equal(
            domain.id,
            grouping_refs[0],
            object_refs[0],
            f"domain-name--{attribute['uuid']}"
        )
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
        attribute = deepcopy(event['Event']['Attribute'][0])
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        domain_value, ip_value = attribute_value.split('|')
        domain_id, address_id = grouping_refs
        domain_ref, address_ref = object_refs
        domain, address = observable
        self._assert_multiple_equal(
            domain.id,
            domain_id,
            domain_ref,
            f"domain-name--{attribute['uuid']}"
        )
        self.assertEqual(domain.type, 'domain-name')
        self.assertEqual(domain.value, domain_value)
        self._assert_multiple_equal(
            domain.resolves_to_refs[0],
            address.id,
            address_id,
            address_ref,
            f"ipv4-addr--{attribute['uuid']}"
        )
        self.assertEqual(address.type, 'ipv4-addr')
        self.assertEqual(address.value, ip_value)

    def test_event_with_email_attachment_indicator_attribute(self):
        event = get_event_with_email_attachment_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[email-message:body_multipart[*].body_raw_ref.name = '{attribute_value}']")

    def test_event_with_email_attachment_observable_attribute(self):
        event = get_event_with_email_attachment_attribute()
        attribute = deepcopy(event['Event']['Attribute'][0])
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        email_id, file_id = grouping_refs
        email_ref, file_ref = object_refs
        email, file = observable
        self._assert_multiple_equal(
            email.id,
            email_id,
            email_ref,
            f"email-message--{attribute['uuid']}"
        )
        self.assertEqual(email.type, 'email-message')
        self.assertEqual(email.is_multipart, True)
        body = email.body_multipart[0]
        self.assertEqual(body.content_disposition, f"attachment; filename='{attribute_value}'")
        self._assert_multiple_equal(
            body.body_raw_ref,
            file.id,
            file_id,
            file_ref,
            f"file--{attribute['uuid']}"
        )
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
        attribute = deepcopy(event['Event']['Attribute'][0])
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        message = observable[0]
        self._assert_multiple_equal(
            message.id,
            grouping_refs[0],
            object_refs[0],
            f"email-message--{attribute['uuid']}"
        )
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.body, attribute_value)

    def test_event_with_email_destination_indicator_attribute(self):
        event = get_event_with_email_destination_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[email-message:to_refs[*].value = '{attribute_value}']")

    def test_event_with_email_destination_observable_attribute(self):
        event = get_event_with_email_destination_attribute()
        attribute = deepcopy(event['Event']['Attribute'][0])
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        message_id, address_id = grouping_refs
        message_ref, address_ref = object_refs
        message, address = observable
        self._assert_multiple_equal(
            message.id,
            message_id,
            message_ref,
            f"email-message--{attribute['uuid']}"
        )
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self._assert_multiple_equal(
            message.to_refs[0],
            address.id,
            address_id,
            address_ref,
            f"email-addr--{attribute['uuid']}"
        )
        self._check_email_address(address, attribute_value)

    def test_event_with_email_header_indicator_attribute(self):
        event = get_event_with_email_header_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[email-message:received_lines = '{attribute_value}']")

    def test_event_with_email_header_observable_attribute(self):
        event = get_event_with_email_header_attribute()
        attribute = deepcopy(event['Event']['Attribute'][0])
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        message = observable[0]
        self._assert_multiple_equal(
            message.id,
            grouping_refs[0],
            object_refs[0],
            f"email-message--{attribute['uuid']}"
        )
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
        attribute = deepcopy(event['Event']['Attribute'][0])
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        message = observable[0]
        self._assert_multiple_equal(
            message.id,
            grouping_refs[0],
            object_refs[0],
            f"email-message--{attribute['uuid']}"
        )
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.message_id, attribute_value)

    def test_event_with_email_observable_attribute(self):
        event = get_event_with_email_address_attribute()
        attribute = deepcopy(event['Event']['Attribute'][0])
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        address = observable[0]
        self._assert_multiple_equal(
            address.id,
            grouping_refs[0],
            object_refs[0],
            f"email-addr--{attribute['uuid']}"
        )
        self._check_email_address(address, attribute_value)

    def test_event_with_email_reply_to_indicator_attribute(self):
        event = get_event_with_email_reply_to_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(
            pattern,
            f"[email-message:additional_header_fields.reply_to = '{attribute_value}']"
        )

    def test_event_with_email_reply_to_observable_attribute(self):
        event = get_event_with_email_reply_to_attribute()
        attribute = deepcopy(event['Event']['Attribute'][0])
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        message = observable[0]
        self._assert_multiple_equal(
            message.id,
            grouping_refs[0],
            object_refs[0],
            f"email-message--{attribute['uuid']}"
        )
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.additional_header_fields['Reply-To'], attribute_value)

    def test_event_with_email_source_indicator_attribute(self):
        event = get_event_with_email_source_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[email-message:from_ref.value = '{attribute_value}']")

    def test_event_with_email_source_observable_attribute(self):
        event = get_event_with_email_source_attribute()
        attribute = deepcopy(event['Event']['Attribute'][0])
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        message_id, address_id = grouping_refs
        message_ref, address_ref = object_refs
        message, address = observable
        self._assert_multiple_equal(
            message.id,
            message_id,
            message_ref,
            f"email-message--{attribute['uuid']}"
        )
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self._assert_multiple_equal(
            message.from_ref,
            address.id,
            address_id,
            address_ref,
            f"email-addr--{attribute['uuid']}"
        )
        self._check_email_address(address, attribute_value)

    def test_event_with_email_subject_indicator_attribute(self):
        event = get_event_with_email_subject_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[email-message:subject = '{attribute_value}']")

    def test_event_with_email_subject_observable_attribute(self):
        event = get_event_with_email_subject_attribute()
        attribute = deepcopy(event['Event']['Attribute'][0])
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        message = observable[0]
        self._assert_multiple_equal(
            message.id,
            grouping_refs[0],
            object_refs[0],
            f"email-message--{attribute['uuid']}"
        )
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
        attribute = deepcopy(event['Event']['Attribute'][0])
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        message = observable[0]
        self._assert_multiple_equal(
            message.id,
            grouping_refs[0],
            object_refs[0],
            f"email-message--{attribute['uuid']}"
        )
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.additional_header_fields['X-Mailer'], attribute_value)

    def test_event_with_filename_indicator_attribute(self):
        event = get_event_with_filename_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[file:name = '{attribute_value}']")

    def test_event_with_filename_observable_attribute(self):
        event = get_event_with_filename_attribute()
        attribute = deepcopy(event['Event']['Attribute'][0])
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        file = observable[0]
        self._assert_multiple_equal(
            file.id,
            grouping_refs[0],
            object_refs[0],
            f"file--{attribute['uuid']}"
        )
        self.assertEqual(file.type, 'file')
        self.assertEqual(file.name, attribute_value)

    def test_event_with_github_username_indicator_attribute(self):
        event = get_event_with_github_username_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(
            pattern,
            f"[user-account:account_type = 'github' AND user-account:account_login = '{attribute_value}']"
        )

    def test_event_with_github_username_observable_attribute(self):
        event = get_event_with_github_username_attribute()
        attribute = deepcopy(event['Event']['Attribute'][0])
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        account = observable[0]
        self._assert_multiple_equal(
            account.id,
            grouping_refs[0],
            object_refs[0],
            f"user-account--{attribute['uuid']}"
        )
        self.assertEqual(account.type, 'user-account')
        self.assertEqual(account.account_type, 'github')
        self.assertEqual(account.account_login, attribute_value)

    def test_event_with_hash_composite_indicator_attributes(self):
        event = get_event_with_hash_composite_attributes()
        attribute_values, patterns = self._run_indicators_tests(event)
        hash_types = ('MD5', 'SHA1', 'SHA224', 'SHA256', 'SHA3256', 'SHA384', 'SSDEEP', 'TLSH')
        for attribute_value, pattern, hash_type in zip(attribute_values, patterns, hash_types):
            filename, hash_value = attribute_value.split('|')
            filename_pattern = f"file:name = '{filename}'"
            hash_pattern = f"file:hashes.{hash_type} = '{hash_value}'"
            self.assertEqual(pattern, f"[{filename_pattern} AND {hash_pattern}]")

    def test_event_with_hash_composite_observable_attributes(self):
        event = get_event_with_hash_composite_attributes()
        attributes = deepcopy(event['Event']['Attribute'])
        values, grouping_refs, object_refs, observables = self._run_observables_tests(event)
        for grouping_ref, object_ref, observable, attribute in zip(grouping_refs, object_refs, observables, attributes):
            self._assert_multiple_equal(
                observable.id,
                grouping_ref,
                object_ref,
                f"file--{attribute['uuid']}"
            )
            self.assertEqual(observable.type, 'file')
        hash_types = ('MD5', 'SHA-1', 'SHA224', 'SHA-256', 'SHA3-256', 'SHA384', 'SSDEEP', 'TLSH')
        for value, observable, hash_type in zip(values, observables, hash_types):
            filename, hash_value = value.split('|')
            self.assertEqual(observable.name, filename)
            self.assertEqual(observable.hashes[hash_type], hash_value)

    def test_event_with_hash_indicator_attributes(self):
        event = get_event_with_hash_attributes()
        values, patterns = self._run_indicators_tests(event)
        hash_types = ('MD5', 'SHA1', 'SHA224', 'SHA256', 'SHA3256', 'SHA384', 'SSDEEP', 'TLSH')
        for pattern, hash_type, value in zip(patterns, hash_types, values):
            self.assertEqual(pattern, f"[file:hashes.{hash_type} = '{value}']")

    def test_event_with_hash_observable_attributes(self):
        event = get_event_with_hash_attributes()
        attributes = deepcopy(event['Event']['Attribute'])
        values, grouping_refs, object_refs, observables = self._run_observables_tests(event)
        for grouping_ref, object_ref, observable, attribute in zip(grouping_refs, object_refs, observables, attributes):
            self._assert_multiple_equal(
                observable.id,
                grouping_ref,
                object_ref,
                f"file--{attribute['uuid']}"
            )
            self.assertEqual(observable.type, 'file')
        hash_types = ('MD5', 'SHA-1', 'SHA224', 'SHA-256', 'SHA3-256', 'SHA384', 'SSDEEP', 'TLSH')
        for observable, hash_type, value in zip(observables, hash_types, values):
            self.assertEqual(observable.hashes[hash_type], value)

    def test_event_with_hostname_indicator_attribute(self):
        event = get_event_with_hostname_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[domain-name:value = '{attribute_value}']")

    def test_event_with_hostname_observable_attribute(self):
        event = get_event_with_hostname_attribute()
        attribute = deepcopy(event['Event']['Attribute'][0])
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        domain = observable[0]
        self._assert_multiple_equal(
            domain.id,
            grouping_refs[0],
            object_refs[0],
            f"domain-name--{attribute['uuid']}"
        )
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
        attribute = deepcopy(event['Event']['Attribute'][0])
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        hostname, port = attribute_value.split('|')
        hostname_id, network_traffic_id = grouping_refs
        hostname_ref, network_traffic_ref = object_refs
        domain, network_traffic = observable
        self._assert_multiple_equal(
            domain.id,
            hostname_id,
            hostname_ref,
            network_traffic.dst_ref,
            f"domain-name--{attribute['uuid']}"
        )
        self.assertEqual(domain.type, 'domain-name')
        self.assertEqual(domain.value, hostname)
        self._assert_multiple_equal(
            network_traffic.id,
            network_traffic_id,
            network_traffic_ref,
            f"network-traffic--{attribute['uuid']}"
        )
        self.assertEqual(network_traffic.type, 'network-traffic')
        self.assertEqual(network_traffic.dst_port, int(port))

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
        src_attribute, dst_attribute = deepcopy(event['Event']['Attribute'])
        values, grouping_refs, object_refs, observables = self._run_observables_tests(
            event,
            index=3
        )
        src, dst = values
        src_network_id, src_address_id, dst_network_id, dst_address_id = grouping_refs
        src_network_ref, src_address_ref, dst_network_ref, dst_address_ref = object_refs
        src_network, src_address, dst_network, dst_address = observables
        self._assert_multiple_equal(
            src_network.id,
            src_network_id,
            src_network_ref,
            f"network-traffic--{src_attribute['uuid']}"
        )
        self.assertEqual(src_network.type, 'network-traffic')
        self._assert_multiple_equal(
            src_address.id,
            src_address_id,
            src_address_ref,
            src_network.src_ref,
            f"ipv4-addr--{src_attribute['uuid']}"
        )
        self.assertEqual(src_address.type, 'ipv4-addr')
        self.assertEqual(src_address.value, src)
        self._assert_multiple_equal(
            dst_network.id,
            dst_network_id,
            dst_network_ref,
            f"network-traffic--{dst_attribute['uuid']}"
        )
        self.assertEqual(dst_network.type, 'network-traffic')
        self._assert_multiple_equal(
            dst_address.id,
            dst_address_id,
            dst_address_ref,
            dst_network.dst_ref,
            f"ipv4-addr--{dst_attribute['uuid']}"
        )
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
        src_attribute, dst_attribute = deepcopy(event['Event']['Attribute'])
        values, grouping_refs, object_refs, observables = self._run_observables_tests(
            event,
            index=3
        )
        src, dst = values
        src_network_id, src_address_id, dst_network_id, dst_address_id = grouping_refs
        src_network_ref, src_address_ref, dst_network_ref, dst_address_ref = object_refs
        src_network, src_address, dst_network, dst_address = observables
        src_ip_value, src_port_value = src.split('|')
        self._assert_multiple_equal(
            src_network.id,
            src_network_id,
            src_network_ref,
            f"network-traffic--{src_attribute['uuid']}"
        )
        self.assertEqual(src_network.type, 'network-traffic')
        self.assertEqual(src_network.src_port, int(src_port_value))
        self._assert_multiple_equal(
            src_address.id,
            src_address_id,
            src_address_ref,
            src_network.src_ref,
            f"ipv4-addr--{src_attribute['uuid']}"
        )
        self.assertEqual(src_address.type, 'ipv4-addr')
        self.assertEqual(src_address.value, src_ip_value)
        dst_ip_value, dst_port_value = dst.split('|')
        self._assert_multiple_equal(
            dst_network.id,
            dst_network_id,
            dst_network_ref,
            f"network-traffic--{dst_attribute['uuid']}"
        )
        self.assertEqual(dst_network.type, 'network-traffic')
        self.assertEqual(dst_network.dst_port, int(dst_port_value))
        self._assert_multiple_equal(
            dst_address.id,
            dst_address_id,
            dst_address_ref,
            dst_network.dst_ref,
            f"ipv4-addr--{dst_attribute['uuid']}"
        )
        self.assertEqual(dst_address.type, 'ipv4-addr')
        self.assertEqual(dst_address.value, dst_ip_value)

    def test_event_with_mac_address_indicator_attribute(self):
        event = get_event_with_mac_address_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[mac-addr:value = '{attribute_value}']")

    def test_event_with_mac_address_observable_attribute(self):
        event = get_event_with_mac_address_attribute()
        attribute = deepcopy(event['Event']['Attribute'][0])
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        mac_address = observable[0]
        self._assert_multiple_equal(
            mac_address.id,
            grouping_refs[0],
            object_refs[0],
            f"mac-addr--{attribute['uuid']}"
        )
        self.assertEqual(mac_address.type, 'mac-addr')
        self.assertEqual(mac_address.value, attribute_value.lower())

    def test_event_with_malware_sample_indicator_attribute(self):
        event = get_event_with_malware_sample_attribute()
        data = event['Event']['Attribute'][0]['data']
        attribute_value, pattern = self._run_indicator_tests(event)
        filename, hash_value = attribute_value.split('|')
        file_pattern, hash_pattern, data_pattern, mime_type, encryption, decryption = pattern[1:-1].split(' AND ')
        self.assertEqual(file_pattern, f"file:name = '{filename}'")
        self.assertEqual(hash_pattern, f"file:hashes.MD5 = '{hash_value}'")
        self.assertEqual(data_pattern, f"file:content_ref.payload_bin = '{data}'")
        self.assertEqual(mime_type, f"file:content_ref.mime_type = 'application/zip'")
        self.assertEqual(encryption, f"file:content_ref.encryption_algorithm = 'mime-type-indicated'")
        self.assertEqual(decryption, f"file:content_ref.decryption_key = 'infected'")

    def test_event_with_malware_sample_observable_attribute(self):
        event = get_event_with_malware_sample_attribute()
        attribute = deepcopy(event['Event']['Attribute'][0])
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        file_id, artifact_id = grouping_refs
        file_ref, artifact_ref = object_refs
        file_object, artifact_object = observable
        filename, hash_value = attribute_value.split('|')
        self._assert_multiple_equal(
            file_object.id,
            file_id,
            file_ref,
            f"file--{attribute['uuid']}"
        )
        self.assertEqual(file_object.type, 'file')
        self.assertEqual(file_object.name, filename)
        self.assertEqual(file_object.hashes['MD5'], hash_value)
        self._assert_multiple_equal(
            artifact_object.id,
            artifact_id,
            artifact_ref,
            file_object.content_ref,
            f"artifact--{attribute['uuid']}"
        )
        self.assertEqual(artifact_object.type, 'artifact')
        self.assertEqual(artifact_object.payload_bin, attribute['data'])

    def test_event_with_mutex_indicator_attribute(self):
        event = get_event_with_mutex_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        self.assertEqual(pattern, f"[mutex:name = '{attribute_value}']")

    def test_event_with_mutex_observable_attribute(self):
        event = get_event_with_mutex_attribute()
        attribute = deepcopy(event['Event']['Attribute'][0])
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        mutex = observable[0]
        self._assert_multiple_equal(
            mutex.id,
            grouping_refs[0],
            object_refs[0],
            f"mutex--{attribute['uuid']}"
        )
        self.assertEqual(mutex.type, 'mutex')
        self.assertEqual(mutex.name, attribute_value)

    def test_event_with_patterning_language_attributes(self):
        event = get_event_with_patterning_language_attributes()
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
        object_refs = self._check_grouping_features(grouping, event['Event'], identity_id)
        for attribute, indicator, object_ref in zip(attributes, indicators, object_refs):
            self._check_attribute_indicator_features(indicator, attribute, identity_id, object_ref)
            self.assertEqual(indicator.pattern_type, attribute['type'])
            self.assertEqual(indicator.pattern, f"[{attribute['value']}]")

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
        attribute = deepcopy(event['Event']['Attribute'][0])
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        registry_key = observable[0]
        self._assert_multiple_equal(
            registry_key.id,
            grouping_refs[0],
            object_refs[0],
            f"windows-registry-key--{attribute['uuid']}"
        )
        self.assertEqual(registry_key.type, 'windows-registry-key')
        self.assertEqual(registry_key.key, attribute_value.strip())

    def test_event_with_regkey_value_indicator_attribute(self):
        event = get_event_with_regkey_value_attribute()
        attribute_value, pattern = self._run_indicator_tests(event)
        key, value = attribute_value.split('|')
        key_pattern = f"windows-registry-key:key = '{self._sanitize_registry_key_value(key)}'"
        value_pattern = f"windows-registry-key:values.data = '{self._sanitize_registry_key_value(value)}'"
        self.assertEqual(pattern, f"[{key_pattern} AND {value_pattern}]")

    def test_event_with_regkey_value_observable_attribute(self):
        event = get_event_with_regkey_value_attribute()
        attribute = deepcopy(event['Event']['Attribute'][0])
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        key, value = attribute_value.split('|')
        registry_key = observable[0]
        self._assert_multiple_equal(
            registry_key.id,
            grouping_refs[0],
            object_refs[0],
            f"windows-registry-key--{attribute['uuid']}"
        )
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
        attribute = deepcopy(event['Event']['Attribute'][0])
        attribute_value, grouping_refs, object_refs, observable = self._run_observable_tests(event)
        url = observable[0]
        self._assert_multiple_equal(
            url.id,
            grouping_refs[0],
            object_refs[0],
            f"url--{attribute['uuid']}"
        )
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
        attributes = deepcopy(event['Event']['Attribute'])
        values, grouping_refs, object_refs, observables = self._run_observables_tests(event)
        for grouping_ref, object_ref, observable, attribute in zip(grouping_refs, object_refs, observables, attributes):
            self._assert_multiple_equal(
                observable.id,
                grouping_ref,
                object_ref,
                f"x509-certificate--{attribute['uuid']}"
            )
            self.assertEqual(observable.type, 'x509-certificate')
        md5, sha1, sha256 = values
        md5_object, sha1_object, sha256_object = observables
        self.assertEqual(md5_object.hashes['MD5'], md5)
        self.assertEqual(sha1_object.hashes['SHA-1'], sha1)
        self.assertEqual(sha256_object.hashes['SHA-256'], sha256)

    ################################################################################
    #                          MISP OBJECTS EXPORT TESTS.                          #
    ################################################################################

    def test_embedded_indicator_object_galaxy(self):
        event = get_embedded_indicator_object_galaxy()
        self._add_object_ids_flag(event)
        orgc = event['Event']['Orgc']
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event)
        stix_objects = self._check_bundle_features(8)
        self._check_spec_versions(stix_objects)
        identity, grouping, malware, coa, indicator, tool, *relationships = stix_objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        args = (
            grouping,
            event['Event'],
            identity_id
        )
        object_refs = self._check_grouping_features(*args)
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
        stix_objects = self._check_bundle_features(12)
        self._check_spec_versions(stix_objects)
        identity, grouping, ap, g_coa, o_coa, malware, vulnerability, tool, *relationships = stix_objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        args = (
            grouping,
            event['Event'],
            identity_id
        )
        object_refs = self._check_grouping_features(*args)
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
        stix_objects = self._check_bundle_features(8)
        self._check_spec_versions(stix_objects)
        identity, grouping, malware1, malware2, observed_data, autonomous_system, relationship1, relationship2 = stix_objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        args = (
            grouping,
            event['Event'],
            identity_id
        )
        object_refs = self._check_grouping_features(*args)
        malware1_ref, malware2_ref, observed_data_ref, as_ref, relationship1_ref, relationship2_ref = object_refs
        self.assertEqual(malware1.id, malware1_ref)
        self.assertEqual(malware2.id, malware2_ref)
        self.assertEqual(observed_data.id, observed_data_ref)
        self.assertEqual(autonomous_system.id, as_ref)
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
        stix_objects = self._check_bundle_features(7)
        self._check_spec_versions(stix_objects)
        identity, grouping, malware, observed_data, autonomous_system, tool, relationship = stix_objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        args = (
            grouping,
            event['Event'],
            identity_id
        )
        object_refs = self._check_grouping_features(*args)
        malware_ref, observed_data_ref, as_ref, tool_ref, relationship_ref = object_refs
        self.assertEqual(malware.id, malware_ref)
        self.assertEqual(observed_data.id, observed_data_ref)
        self.assertEqual(autonomous_system.id, as_ref)
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

    def test_event_with_account_observable_objects(self):
        event = get_event_with_account_objects()
        misp_objects, grouping_refs, object_refs, observables = self._run_observables_from_objects_tests(event)
        for grouping_ref, object_ref, observable in zip(grouping_refs, object_refs, observables):
            for grp_ref, obj_ref, obs in zip(grouping_ref, object_ref, observable):
                self.assertTrue(grp_ref == obj_ref == obs.id)
        facebook_object, gitlab_object, telegram_object, twitter_object = misp_objects
        facebook, gitlab, telegram, twitter = observables
        account_id, account_name, link = (attribute['value'] for attribute in facebook_object['Attribute'])
        facebook = facebook[0]
        self.assertEqual(facebook.type, 'user-account')
        self.assertEqual(facebook.account_type, 'facebook')
        self.assertEqual(facebook.user_id, account_id)
        self.assertEqual(facebook.account_login, account_name)
        self.assertEqual(facebook.x_misp_link, link)
        gitlab_id, name, username = (attribute['value'] for attribute in gitlab_object['Attribute'])
        gitlab = gitlab[0]
        self.assertEqual(gitlab.type, 'user-account')
        self.assertEqual(gitlab.account_type, 'gitlab')
        self.assertEqual(gitlab.user_id, gitlab_id)
        self.assertEqual(gitlab.display_name, name)
        self.assertEqual(gitlab.account_login, username)
        telegram_id, username, phone1, phone2 = (attribute['value'] for attribute in telegram_object['Attribute'])
        telegram = telegram[0]
        self.assertEqual(telegram.type, 'user-account')
        self.assertEqual(telegram.account_type, 'telegram')
        self.assertEqual(telegram.user_id, telegram_id)
        self.assertEqual(telegram.account_login, username)
        self.assertEqual(telegram.x_misp_phone, [phone1, phone2])
        _id, name, displayed_name, followers = (attribute['value'] for attribute in twitter_object['Attribute'])
        twitter = twitter[0]
        self.assertEqual(twitter.type, 'user-account')
        self.assertEqual(twitter.account_type, 'twitter')
        self.assertEqual(twitter.user_id, _id)
        self.assertEqual(twitter.account_login, name)
        self.assertEqual(twitter.display_name, displayed_name)
        self.assertEqual(twitter.x_misp_followers, followers)

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

    def test_event_with_account_observable_object_with_attachment(self):
        event = get_event_with_account_objects_with_attachment()
        misp_objects, grouping_refs, object_refs, observables = self._run_observables_from_objects_tests(event)
        for grouping_ref, object_ref, observable in zip(grouping_refs, object_refs, observables):
            for grp_ref, obj_ref, obs in zip(grouping_ref, object_ref, observable):
                self.assertTrue(grp_ref == obj_ref == obs.id)
        github_user, parler_account, reddit_account = misp_objects
        github, parler, reddit = observables
        github_id, username, fullname, organisation, image = (attribute['value'] for attribute in github_user['Attribute'])
        github = github[0]
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
        parler = parler[0]
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
        reddit = reddit[0]
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

    def test_object_with_annotation_object(self):
        event = get_event_with_annotation_object()
        orgc = event['Event']['Orgc']
        misp_object = deepcopy(event['Event']['Object'][0])
        attribute = deepcopy(event['Event']['Attribute'][0])
        self.parser.parse_misp_event(event)
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, indicator, note = stix_objects
        identity_id = self._check_identity_features(
            identity,
            orgc,
            self._datetime_from_timestamp(event['Event']['timestamp'])
        )
        indicator_ref, note_ref = self._check_grouping_features(grouping, event['Event'], identity_id)
        self._check_attribute_indicator_features(indicator, attribute, identity_id, indicator_ref)
        self._check_pattern_features(indicator)
        type_pattern = "network-traffic:dst_ref.type = 'ipv4-addr'"
        value_pattern = f"network-traffic:dst_ref.value = '{attribute['value']}'"
        self.assertEqual(indicator.pattern, f"[{type_pattern} AND {value_pattern}]")
        text, annotation_type, attachment = (attribute['value'] for attribute in misp_object['Attribute'])
        self.assertEqual(note.type, 'note')
        note_id = f"note--{misp_object['uuid']}"
        self.assertEqual(note_ref, note_id)
        self.assertEqual(note.id, note_id)
        timestamp = self._datetime_from_timestamp(misp_object['timestamp'])
        self.assertEqual(note.created, timestamp)
        self.assertEqual(note.modified, timestamp)
        self.assertEqual(note.labels[0], f'misp:category="{misp_object["meta-category"]}"')
        self.assertEqual(note.labels[1], f'misp:name="{misp_object["name"]}"')
        self.assertEqual(note.labels[2], f'misp:to_ids="False"')
        self.assertEqual(note.content, text)
        self.assertEqual(note.object_refs, [indicator.id])
        self.assertEqual(note.x_misp_type, annotation_type)
        self.assertEqual(note.x_misp_attachment['value'], attachment)
        self.assertEqual(note.x_misp_attachment['data'], misp_object['Attribute'][-1]['data'])

    def test_event_with_android_app_indicator_object(self):
        event = get_event_with_android_app_object()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        name, certificate, domain = (attribute['value'] for attribute in attributes)
        name_pattern, cert_pattern, domain_pattern = pattern[1:-1].split(' AND ')
        self.assertEqual(name_pattern, f"software:name = '{name}'")
        self.assertEqual(cert_pattern, f"software:x_misp_certificate = '{certificate}'")
        self.assertEqual(domain_pattern, f"software:x_misp_domain = '{domain}'")

    def test_event_with_android_app_observable_object(self):
        event = get_event_with_android_app_object()
        misp_object = deepcopy(event['Event']['Object'][0])
        attributes, grouping_refs, object_refs, observable = self._run_observable_from_object_tests(event)
        software = observable[0]
        object_ref = object_refs[0]
        name, certificate, domain = (attribute['value'] for attribute in attributes)
        self.assertEqual(object_ref, grouping_refs[0])
        self.assertEqual(software.type, 'software')
        software_id = f"software--{misp_object['uuid']}"
        self.assertEqual(software_id, object_ref)
        self.assertEqual(software.id, software_id)
        self.assertEqual(software.name, name)
        self.assertEqual(software.x_misp_certificate, certificate)
        self.assertEqual(software.x_misp_domain, domain)

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

    def test_event_with_cpe_asset_observable_object(self):
        event = get_event_with_cpe_asset_object()
        attributes, grouping_refs, object_refs, observable = self._run_observable_from_object_tests(event)
        cpe, language, product, vendor, version, description = (attribute['value'] for attribute in attributes)
        object_ref = object_refs[0]
        software = observable[0]
        self.assertEqual(object_ref, grouping_refs[0])
        self.assertEqual(software.id, object_ref)
        self.assertEqual(software.type, 'software')
        self.assertEqual(software.cpe, cpe)
        self.assertEqual(software.name, product)
        self.assertEqual(software.languages, [language])
        self.assertEqual(software.vendor, vendor)
        self.assertEqual(software.version, version)
        self.assertEqual(software.x_misp_description, description)

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

    def test_event_with_custom_objects(self):
        event = get_event_with_custom_objects()
        orgc = event['Event']['Orgc']
        misp_objects = deepcopy(event['Event']['Object'])
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

    def test_event_with_domain_ip_observable_object_custom(self):
        event = get_event_with_domain_ip_object_custom()
        attributes, grouping_refs, object_refs, observable = self._run_observable_from_object_tests(event)
        _domain, hostname, _ip, port = (attribute['value'] for attribute in attributes)
        for grouping_ref, object_ref in zip(grouping_refs, object_refs):
            self.assertEqual(grouping_ref, object_ref)
        domain_ref, ip_ref = object_refs
        domain_, ip_ = observable
        self.assertEqual(domain_.id, domain_ref)
        self.assertEqual(domain_.type, 'domain-name')
        self.assertEqual(domain_.value, _domain)
        self.assertEqual(domain_.x_misp_hostname, hostname)
        self.assertEqual(domain_.x_misp_port, port)
        self.assertEqual(domain_.resolves_to_refs, [ip_ref])
        self.assertEqual(ip_.id, ip_ref)
        self.assertEqual(ip_.type, 'ipv4-addr')
        self.assertEqual(ip_.value, _ip)

    def test_event_with_domain_ip_observable_object_standard(self):
        event = get_event_with_domain_ip_object_standard()
        attributes, grouping_refs, object_refs, observable = self._run_observable_from_object_tests(event)
        _domain1, _domain2, _ip1, _ip2 = ((attribute['value'], attribute['uuid']) for attribute in attributes)
        for grouping_ref, object_ref in zip(grouping_refs, object_refs):
            self.assertEqual(grouping_ref, object_ref)
        ip1_ref, ip2_ref, domain1_ref, domain2_ref = object_refs
        ip1_, ip2_, domain1_, domain2_ = observable
        self._check_SCO(domain1_, _domain1, domain1_ref, 'domain-name')
        self.assertEqual(domain1_.resolves_to_refs, [ip1_ref, ip2_ref])
        self._check_SCO(domain2_, _domain2, domain2_ref, 'domain-name')
        self.assertEqual(domain2_.resolves_to_refs, [ip1_ref, ip2_ref])
        self._check_SCO(ip1_, _ip1, ip1_ref, 'ipv4-addr')
        self._check_SCO(ip2_, _ip2, ip2_ref, 'ipv4-addr')

    def test_event_with_email_indicator_object(self):
        event = get_event_with_email_object()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        _from, _to, _cc1, _cc2, _reply_to, _subject, _attachment1, _attachment2, _x_mailer, _user_agent, _boundary, _message_id = (attribute['value'] for attribute in attributes)
        cc1_, cc2_, from_, message_id_, reply_to_, subject_, to_, x_mailer_, attachment1_, attachment2_, user_agent_, boundary_ = pattern[1:-1].split(' AND ')
        self.assertEqual(from_, f"email-message:from_ref.value = '{_from}'")
        self.assertEqual(to_, f"email-message:to_refs.value = '{_to}'")
        self.assertEqual(cc1_, f"email-message:cc_refs.value = '{_cc1}'")
        self.assertEqual(cc2_, f"email-message:cc_refs.value = '{_cc2}'")
        self.assertEqual(message_id_, f"email-message:message_id = '{_message_id}'")
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
        _from, _to, _cc1, _cc2, _reply_to, _subject, _attachment1, _attachment2, _x_mailer, _user_agent, _boundary, _message_id = (attribute['value'] for attribute in attributes)
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
        self._check_email_address(address1, _from)
        self.assertEqual(address2.id, address2_ref)
        self._check_email_address(address2, _to)
        self.assertEqual(address3.id, address3_ref)
        self._check_email_address(address3, _cc1)
        self.assertEqual(address4.id, address4_ref)
        self._check_email_address(address4, _cc2)
        self.assertEqual(file1.id, file1_ref)
        self.assertEqual(file1.type, 'file')
        self.assertEqual(file1.name, _attachment1)
        self.assertEqual(file2.id, file2_ref)
        self.assertEqual(file2.type, 'file')
        self.assertEqual(file2.name, _attachment2)

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

    def test_event_with_email_observable_object_with_display_names(self):
        event = get_event_with_email_object_with_display_names()
        attributes, grouping_refs, object_refs, observables = self._run_observable_from_object_tests(event)
        _from, _from_name, _to1, _to1_name, _to2, _to2_name, _cc, _cc_name, _bcc, _bcc_name = (attribute['value'] for attribute in attributes)
        message, from_, to1_, to2_, cc_, bcc_ = observables
        for grouping_ref, object_ref in zip(grouping_refs, object_refs):
            self.assertEqual(grouping_ref, object_ref)
        message_ref, from_ref, to1_ref, to2_ref, cc_ref, bcc_ref = grouping_refs
        self.assertEqual(message.id, message_ref)
        self.assertEqual(message.type, 'email-message')
        self.assertEqual(message.is_multipart, False)
        self.assertEqual(message.from_ref, from_ref)
        self.assertEqual(message.to_refs, [to1_ref, to2_ref])
        self.assertEqual(from_.id, from_ref)
        self._check_email_address(from_, _from, display_name=_from_name)
        self.assertEqual(to1_.id, to1_ref)
        self._check_email_address(to1_, _to1, display_name=_to1_name)
        self.assertEqual(to2_.id, to2_ref)
        self._check_email_address(to2_, _to2, display_name=_to2_name)
        self.assertEqual(cc_.id, cc_ref)
        self._check_email_address(cc_, _cc, display_name=_cc_name)
        self.assertEqual(bcc_.id, bcc_ref)
        self._check_email_address(bcc_, _bcc, display_name=_bcc_name)

    def test_event_with_employee_object(self):
        event = get_event_with_employee_object()
        orgc = event['Event']['Orgc']
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event)
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, employee = stix_objects
        identity_id = self._check_identity_features(
            identity,
            orgc,
            self._datetime_from_timestamp(event['Event']['timestamp'])
        )
        employee_ref = self._check_grouping_features(grouping, event['Event'], identity_id)[0]
        employee_id = f"identity--{misp_object['uuid']}"
        first_name, last_name, description, email, employee_type = (attribute['value'] for attribute in misp_object['Attribute'])
        self.assertEqual(employee.type, 'identity')
        self.assertEqual(employee_ref, employee_id)
        self.assertEqual(employee.id, employee_id)
        self.assertEqual(employee.identity_class, 'individual')
        timestamp = self._datetime_from_timestamp(misp_object['timestamp'])
        self.assertEqual(employee.created, timestamp)
        self.assertEqual(employee.modified, timestamp)
        self.assertEqual(employee.name, f"{first_name} {last_name}")
        self.assertEqual(employee.description, description)
        self.assertEqual(employee.contact_information, email)
        self.assertEqual(employee.roles, [employee_type])

    def test_event_with_file_and_pe_indicator_objects(self):
        event = get_event_with_file_and_pe_objects()
        misp_objects, pattern = self._run_indicator_from_objects_tests(event)
        file, pe, section = misp_objects
        _filename, _md5, _sha1, _sha256, _size, _entropy = (attribute['value'] for attribute in file['Attribute'])
        pattern = pattern[1:-1].split(' AND ')
        md5_, sha1_, sha256_, name_, size_, entropy_ = pattern[:6]
        self.assertEqual(md5_, f"file:hashes.MD5 = '{_md5}'")
        self.assertEqual(sha1_, f"file:hashes.SHA1 = '{_sha1}'")
        self.assertEqual(sha256_, f"file:hashes.SHA256 = '{_sha256}'")
        self.assertEqual(name_, f"file:name = '{_filename}'")
        self.assertEqual(size_, f"file:size = '{_size}'")
        self.assertEqual(entropy_, f"file:x_misp_entropy = '{_entropy}'")
        self._check_pe_and_section_pattern(pattern[6:], pe, section)

    def test_event_with_file_and_pe_observable_objects(self):
        event = get_event_with_file_and_pe_objects()
        misp_objects, grouping_refs, object_refs, observables = self._run_observable_from_objects_tests(event)
        _file, pe, section = misp_objects
        self.assertEqual(grouping_refs[0], object_refs[0])
        filename, md5, sha1, sha256, size, entropy = (attribute['value'] for attribute in _file['Attribute'])
        file_object = observables[0]
        self.assertEqual(file_object.id, object_refs[0])
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
        ms_data, ms_filename, ms_md5, mime_type, encryption, decryption = malware_sample_.split(' AND ')
        self.assertEqual(ms_data, f"(file:content_ref.payload_bin = '{attributes[0]['data']}'")
        filename, md5 = _malware_sample.split('|')
        self.assertEqual(ms_filename, f"file:content_ref.x_misp_filename = '{filename}'")
        self.assertEqual(ms_md5, f"file:content_ref.hashes.MD5 = '{md5}'")
        self.assertEqual(mime_type, f"file:content_ref.mime_type = 'application/zip'")
        self.assertEqual(encryption, f"file:content_ref.encryption_algorithm = 'mime-type-indicated'")
        self.assertEqual(decryption, f"file:content_ref.decryption_key = 'infected')")
        a_data, a_filename = attachment_.split(' AND ')
        self.assertEqual(a_data, f"(file:content_ref.payload_bin = '{attributes[6]['data']}'")
        self.assertEqual(a_filename, f"file:content_ref.x_misp_filename = '{_attachment}')")

    def test_event_with_file_observable_object(self):
        event = get_event_with_file_object_with_artifact()
        attributes, grouping_refs, object_refs, observables = self._run_observable_from_object_tests(event)
        _malware_sample, _filename, _md5, _sha1, _sha256, _size, _attachment, _path, _encoding = (attribute['value'] for attribute in attributes)
        file, directory, artifact1 = observables
        for grouping_ref, object_ref in zip(grouping_refs, object_refs):
            self.assertEqual(grouping_ref, object_ref)
        file_ref, directory_ref, artifact1_ref = grouping_refs
        self.assertEqual(file.id, file_ref)
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

    def test_event_with_geolocation_object(self):
        event = get_event_with_geolocation_object()
        orgc = event['Event']['Orgc']
        misp_object = deepcopy(event['Event']['Object'])[0]
        self.parser.parse_misp_event(event)
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, location = stix_objects
        identity_id = self._check_identity_features(
            identity,
            orgc,
            self._datetime_from_timestamp(event['Event']['timestamp'])
        )
        args = (grouping, event['Event'], identity_id)
        object_ref = self._check_grouping_features(*args)[0]
        address, zipcode, city, country, region, latitude, longitude, altitude = (attribute['value'] for attribute in misp_object['Attribute'])
        self.assertEqual(location.type, 'location')
        location_id = f"location--{misp_object['uuid']}"
        self.assertEqual(object_ref, location_id)
        self.assertEqual(location.id, location_id)
        timestamp = self._datetime_from_timestamp(misp_object['timestamp'])
        self.assertEqual(location.created, timestamp)
        self.assertEqual(location.modified, timestamp)
        self.assertEqual(location.labels[0], f'misp:category="{misp_object["meta-category"]}"')
        self.assertEqual(location.labels[1], f'misp:name="{misp_object["name"]}"')
        self.assertEqual(location.labels[2], f'misp:to_ids="False"')
        self.assertEqual(location.street_address, address)
        self.assertEqual(location.postal_code, zipcode)
        self.assertEqual(location.city, city)
        self.assertEqual(location.country, country)
        self.assertEqual(location.region, region)
        self.assertEqual(location.latitude, float(latitude))
        self.assertEqual(location.longitude, float(longitude))
        self.assertEqual(location.x_misp_altitude, altitude)

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

    def test_event_with_image_observable_object(self):
        event = get_event_with_image_object()
        misp_object = deepcopy(event['Event']['Object'][0])
        attributes, grouping_refs, object_refs, observables = self._run_observable_from_object_tests(event)
        attachment, filename, url, text = (attribute['value'] for attribute in attributes)
        for grouping_ref, object_ref, observable in zip(grouping_refs, object_refs, observables):
            self.assertTrue(grouping_ref == object_ref == observable.id)
        file, artifact = observables
        self.assertEqual(file.type, 'file')
        self.assertEqual(file.id, f"file--{misp_object['uuid']}")
        self.assertEqual(file.name, filename)
        artifact_id = f"artifact--{misp_object['uuid']}"
        self.assertEqual(file.content_ref, artifact_id)
        self.assertEqual(artifact.type, 'artifact')
        self.assertEqual(artifact.id, artifact_id)
        self.assertEqual(artifact.payload_bin, attributes[0]['data'].replace('\\', ''))
        self.assertEqual(artifact.mime_type, 'image/png')
        self.assertEqual(artifact.x_misp_url, url)
        self.assertEqual(artifact.x_misp_filename, attachment)

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

    def test_event_with_legal_entity_object(self):
        event = get_event_with_legal_entity_object()
        orgc = event['Event']['Orgc']
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event)
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, legal_entity = stix_objects
        identity_id = self._check_identity_features(
            identity,
            orgc,
            self._datetime_from_timestamp(event['Event']['timestamp'])
        )
        legal_entity_ref = self._check_grouping_features(grouping, event['Event'], identity_id)[0]
        legal_entity_id = f"identity--{misp_object['uuid']}"
        name, description, business, phone, logo = (attribute['value'] for attribute in misp_object['Attribute'])
        self.assertEqual(legal_entity.type, 'identity')
        self.assertEqual(legal_entity_ref, legal_entity_id)
        self.assertEqual(legal_entity.id, legal_entity_id)
        self.assertEqual(legal_entity.identity_class, 'organization')
        timestamp = self._datetime_from_timestamp(misp_object['timestamp'])
        self.assertEqual(legal_entity.created, timestamp)
        self.assertEqual(legal_entity.modified, timestamp)
        self.assertEqual(legal_entity.name, name)
        self.assertEqual(legal_entity.sectors, [business])
        self.assertEqual(legal_entity.contact_information, f"phone-number: {phone}")
        self.assertEqual(legal_entity.x_misp_logo['value'], logo)
        self.assertEqual(
            legal_entity.x_misp_logo['data'],
            misp_object['Attribute'][-1]['data'].replace('\\', '')
        )

    def test_event_with_lnk_indicator_object(self):
        event = get_event_with_lnk_object()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        filename, fullpath, md5, sha1, sha256, malware_sample, size_in_bytes, creation, modification, access = (attribute['value'] for attribute in attributes)
        atime, ctime, mtime, name, directory, md5_pattern, sha1_pattern, sha256_pattern, artifact, size= self._reassemble_pattern(pattern[1:-1])
        self.assertEqual(name, f"file:name = '{filename}'")
        self.assertEqual(directory, f"file:parent_directory_ref.path = '{fullpath}'")
        self.assertEqual(md5_pattern, f"file:hashes.MD5 = '{md5}'")
        self.assertEqual(sha1_pattern, f"file:hashes.SHA1 = '{sha1}'")
        self.assertEqual(sha256_pattern, f"file:hashes.SHA256 = '{sha256}'")
        ms_data, ms_filename, ms_md5, mime_type, encryption, decryption = artifact.split(' AND ')
        data = attributes[5]['data'].replace('\\', '')
        self.assertEqual(ms_data, f"(file:content_ref.payload_bin = '{data}'")
        filename, md5 = malware_sample.split('|')
        self.assertEqual(ms_filename, f"file:content_ref.x_misp_filename = '{filename}'")
        self.assertEqual(ms_md5, f"file:content_ref.hashes.MD5 = '{md5}'")
        self.assertEqual(mime_type, f"file:content_ref.mime_type = 'application/zip'")
        self.assertEqual(encryption, f"file:content_ref.encryption_algorithm = 'mime-type-indicated'")
        self.assertEqual(decryption, f"file:content_ref.decryption_key = 'infected')")
        self.assertEqual(size, f"file:size = '{size_in_bytes}'")
        self.assertEqual(ctime, f"file:ctime = '{creation}'")
        self.assertEqual(mtime, f"file:mtime = '{modification}'")
        self.assertEqual(atime, f"file:atime = '{access}'")

    def test_event_with_lnk_observable_object(self):
        event = get_event_with_lnk_object()
        misp_object = deepcopy(event['Event']['Object'][0])
        attributes, grouping_refs, object_refs, observables = self._run_observable_from_object_tests(event)
        filename, fullpath, md5, sha1, sha256, malware_sample, size_in_bytes, creation, modification, access = attributes
        for grouping_ref, object_ref, observable in zip(grouping_refs, object_refs, observables):
            self.assertTrue(grouping_ref == object_ref == observable.id)
        file, directory, artifact = observables
        self.assertEqual(file.type, 'file')
        self.assertEqual(file.id, f"file--{misp_object['uuid']}")
        self.assertEqual(file.name, filename['value'])
        self.assertEqual(file.hashes['MD5'], md5['value'])
        self.assertEqual(file.hashes['SHA-1'], sha1['value'])
        self.assertEqual(file.hashes['SHA-256'], sha256['value'])
        self.assertEqual(file.size, int(size_in_bytes['value']))
        self.assertEqual(
            file.ctime,
            self._datetime_from_str(creation['value'])
        )
        self.assertEqual(
            file.mtime,
            self._datetime_from_str(modification['value'])
        )
        self.assertEqual(
            file.atime,
            self._datetime_from_str(access['value'])
        )
        self.assertEqual(directory.type, 'directory')
        directory_id = f"directory--{fullpath['uuid']}"
        self.assertEqual(directory.id, directory_id)
        self.assertEqual(directory.path, fullpath['value'])
        self.assertEqual(file.parent_directory_ref, directory_id)
        artifact_id = f"artifact--{malware_sample['uuid']}"
        self.assertEqual(artifact.type, 'artifact')
        self.assertEqual(artifact.id, artifact_id)
        self.assertEqual(artifact.payload_bin, malware_sample['data'])
        self.assertEqual(artifact.mime_type, 'application/zip')
        filename, md5 = malware_sample['value'].split('|')
        self.assertEqual(artifact.x_misp_filename, filename)
        self.assertEqual(artifact.hashes['MD5'], md5)
        self.assertEqual(file.content_ref, artifact_id)

    def test_event_with_mutex_indicator_object(self):
        event = get_event_with_mutex_object()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        _name, _description, _os = (attribute['value'] for attribute in attributes)
        name_, description_, os_ = pattern[1:-1].split(' AND ')
        self.assertEqual(name_, f"mutex:name = '{_name}'")
        self.assertEqual(description_, f"mutex:x_misp_description = '{_description}'")
        self.assertEqual(os_, f"mutex:x_misp_operating_system = '{_os}'")

    def test_event_with_mutex_observable_object(self):
        event = get_event_with_mutex_object()
        attributes, grouping_refs, object_refs, observables = self._run_observable_from_object_tests(event)
        name, description, _os = (attribute['value'] for attribute in attributes)
        self.assertEqual(grouping_refs[0], object_refs[0])
        mutex = observables[0]
        self.assertEqual(mutex.id, grouping_refs[0])
        self.assertEqual(mutex.type, 'mutex')
        self.assertEqual(mutex.name, name)
        self.assertEqual(mutex.x_misp_description, description)
        self.assertEqual(mutex.x_misp_operating_system, _os)

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
        self.assertEqual(network_traffic.protocols, [layer3.lower(), layer4.lower(), layer7.lower()])
        self.assertEqual(network_traffic.src_ref, address1_ref)
        self.assertEqual(network_traffic.dst_ref, address2_ref)
        self.assertEqual(network_traffic.x_misp_hostname_dst, hostname)
        self.assertEqual(address1.id, address1_ref)
        self.assertEqual(address1.type, 'ipv4-addr')
        self.assertEqual(address1.value, ip_src)
        self.assertEqual(address2.id, address2_ref)
        self.assertEqual(address2.type, 'ipv4-addr')
        self.assertEqual(address2.value, ip_dst)

    def test_event_with_network_socket_indicator_object(self):
        event = get_event_with_network_socket_object()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        _ip_src, _ip_dst, _src_port, _dst_port, _hostname, _address_family, _domain_family, _socket_type, _state, _protocol = (attribute['value'] for attribute in attributes)
        ip_src_, ip_dst_, hostname_, dst_port_, src_port_, protocol_, address_family_, socket_type_, state_, domain_family_ = self._reassemble_pattern(pattern[1:-1])
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
        self.assertEqual(socket_type_, f"network-traffic:extensions.'socket-ext'.socket_type = '{_socket_type}'")
        self.assertEqual(state_, f"network-traffic:extensions.'socket-ext'.is_{_state} = true")
        self.assertEqual(domain_family_, f"network-traffic:x_misp_domain_family = '{_domain_family}'")

    def test_event_with_network_socket_observable_object(self):
        event = get_event_with_network_socket_object()
        attributes, grouping_refs, object_refs, observables = self._run_observable_from_object_tests(event)
        ip_src, ip_dst, src_port, dst_port, hostname, address_family, domain_family, socket_type, state, protocol = (attribute['value'] for attribute in attributes)
        for grouping_ref, object_ref in zip(grouping_refs, object_refs):
            self.assertEqual(grouping_ref, object_ref)
        network_traffic, address1, address2 = observables
        network_traffic_ref, address1_ref, address2_ref = grouping_refs
        self.assertEqual(network_traffic.id, network_traffic_ref)
        self.assertEqual(network_traffic.type, 'network-traffic')
        self.assertEqual(network_traffic.src_port, int(src_port))
        self.assertEqual(network_traffic.dst_port, int(dst_port))
        self.assertEqual(network_traffic.protocols, [protocol.lower()])
        self.assertEqual(network_traffic.src_ref, address1_ref)
        self.assertEqual(network_traffic.dst_ref, address2_ref)
        socket_ext = network_traffic.extensions['socket-ext']
        self.assertEqual(socket_ext.address_family, address_family)
        self.assertEqual(socket_ext.socket_type, socket_type)
        self.assertEqual(getattr(socket_ext, f'is_{state}'), True)
        self.assertEqual(network_traffic.x_misp_domain_family, domain_family)
        self.assertEqual(network_traffic.x_misp_hostname_dst, hostname)
        self.assertEqual(address1.id, address1_ref)
        self.assertEqual(address1.type, 'ipv4-addr')
        self.assertEqual(address1.value, ip_src)
        self.assertEqual(address2.id, address2_ref)
        self.assertEqual(address2.type, 'ipv4-addr')
        self.assertEqual(address2.value, ip_dst)

    def test_event_with_news_agency_object(self):
        event = get_event_with_news_agency_object()
        orgc = event['Event']['Orgc']
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event)
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, news_agency = stix_objects
        identity_id = self._check_identity_features(
            identity,
            orgc,
            self._datetime_from_timestamp(event['Event']['timestamp'])
        )
        news_agency_ref = self._check_grouping_features(grouping, event['Event'], identity_id)[0]
        news_agency_id = f"identity--{misp_object['uuid']}"
        name, address1, email1, phone1, address2, email2, phone2, link, attachment = (attribute['value'] for attribute in misp_object['Attribute'])
        self.assertEqual(news_agency.type, 'identity')
        self.assertEqual(news_agency_ref, news_agency_id)
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

    def test_event_with_organization_object(self):
        event = get_event_with_organization_object()
        orgc = event['Event']['Orgc']
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event)
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, organization = stix_objects
        identity_id = self._check_identity_features(
            identity,
            orgc,
            self._datetime_from_timestamp(event['Event']['timestamp'])
        )
        organization_ref = self._check_grouping_features(grouping, event['Event'], identity_id)[0]
        organization_id = f"identity--{misp_object['uuid']}"
        name, description, address, email, phone, role, alias = (attribute['value'] for attribute in misp_object['Attribute'])
        self.assertEqual(organization.type, 'identity')
        self.assertEqual(organization_ref, organization_id)
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
        self.assertEqual(organization.roles, [role])
        self.assertEqual(organization.x_misp_alias, alias)

    def test_event_with_pe_and_section_indicator_objects(self):
        event = get_event_with_pe_objects()
        misp_objects, pattern = self._run_indicator_from_objects_tests(event)
        self._check_pe_and_section_pattern(pattern[1:-1].split(' AND '), *misp_objects)

    def test_event_with_pe_and_section_observable_objects(self):
        event = get_event_with_pe_objects()
        misp_objects, grouping_refs, object_refs, observables = self._run_observable_from_objects_tests(event)
        self.assertEqual(grouping_refs[0], object_refs[0])
        self._check_pe_and_section_observable(
            observables[0].extensions['windows-pebinary-ext'],
            *misp_objects
        )

    def test_event_with_process_indicator_object(self):
        event = get_event_with_process_object_v2()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        _pid, _child_pid, _parent_pid, _name, _image, _parent_image, _port, _command_line, _parent_name = (attribute['value'] for attribute in attributes)
        pid_, image_, command_line_, parent_image_, parent_pid_, parent_name_, child_pid_, name_, port_ = pattern[1:-1].split(' AND ')
        self.assertEqual(pid_, f"process:pid = '{_pid}'")
        self.assertEqual(image_, f"process:image_ref.name = '{_image}'")
        self.assertEqual(command_line_, f"process:parent_ref.command_line = '{_command_line}'")
        self.assertEqual(parent_image_, f"process:parent_ref.image_ref.name = '{_parent_image}'")
        self.assertEqual(parent_pid_, f"process:parent_ref.pid = '{_parent_pid}'")
        self.assertEqual(parent_name_, f"process:parent_ref.x_misp_process_name = '{_parent_name}'")
        self.assertEqual(child_pid_, f"process:child_refs[0].pid = '{_child_pid}'")
        self.assertEqual(name_, f"process:x_misp_name = '{_name}'")
        self.assertEqual(port_, f"process:x_misp_port = '{_port}'")

    def test_event_with_process_observable_object(self):
        event = get_event_with_process_object_v2()
        attributes, grouping_refs, object_refs, observables = self._run_observable_from_object_tests(event)
        pid, child_pid, parent_pid, name, image, parent_image, port, command_line, parent_name = (attribute['value'] for attribute in attributes)
        for grouping_ref, object_ref in zip(grouping_refs, object_refs):
            self.assertEqual(grouping_ref, object_ref)
        process, parent_image_object, parent_process, child_process, image_object = observables
        process_ref, parent_image_ref, parent_ref, child_ref, image_ref = grouping_refs
        self.assertEqual(process.id, process_ref)
        self.assertEqual(process.type, 'process')
        self.assertEqual(process.pid, int(pid))
        self.assertEqual(process.x_misp_name, name)
        self.assertEqual(process.x_misp_port, port)
        self.assertEqual(process.parent_ref, parent_ref)
        self.assertEqual(process.child_refs, [child_ref])
        self.assertEqual(process.image_ref, image_ref)
        self.assertEqual(parent_image_object.id, parent_image_ref)
        self.assertEqual(parent_image_object.type, 'file')
        self.assertEqual(parent_image_object.name, parent_image)
        self.assertEqual(parent_process.id, parent_ref)
        self.assertEqual(parent_process.type, 'process')
        self.assertEqual(parent_process.pid, int(parent_pid))
        self.assertEqual(parent_process.command_line, command_line)
        self.assertEqual(parent_process.x_misp_process_name, parent_name)
        self.assertEqual(parent_process.image_ref, parent_image_ref)
        self.assertEqual(child_process.id, child_ref)
        self.assertEqual(child_process.type, 'process')
        self.assertEqual(child_process.pid, int(child_pid))
        self.assertEqual(image_object.id, image_ref)
        self.assertEqual(image_object.type, 'file')
        self.assertEqual(image_object.name, image)

    def test_event_with_registry_key_indicator_object(self):
        event = get_event_with_registry_key_object()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        _key, _hive, _name, _data, _data_type, _modified = (attribute['value'] for attribute in attributes)
        key_, modified_, data_, data_type_, name_, hive_ = pattern[1:-1].split(' AND ')
        key = _key.replace('\\', '\\\\')
        self.assertEqual(key_, f"windows-registry-key:key = '{key}'")
        self.assertEqual(modified_, f"windows-registry-key:modified_time = '{_modified}'")
        self.assertEqual(data_, f"windows-registry-key:values[0].data = '{self._sanitize_registry_key_value(_data)}'")
        self.assertEqual(data_type_, f"windows-registry-key:values[0].data_type = '{_data_type}'")
        self.assertEqual(name_, f"windows-registry-key:values[0].name = '{_name}'")
        self.assertEqual(hive_, f"windows-registry-key:x_misp_hive = '{_hive}'")

    def test_event_with_registry_key_observable_object(self):
        event = get_event_with_registry_key_object()
        attributes, grouping_refs, object_refs, observables = self._run_observable_from_object_tests(event)
        key, hive, name, data, data_type, modified = (attribute['value'] for attribute in attributes)
        self.assertEqual(grouping_refs[0], object_refs[0])
        registry_key = observables[0]
        self.assertEqual(registry_key.id, object_refs[0])
        self.assertEqual(registry_key.type, 'windows-registry-key')
        self.assertEqual(registry_key.key, key)
        self.assertEqual(
            datetime.strftime(registry_key.modified_time, '%Y-%m-%dT%H:%M:%S'),
            modified
        )
        self.assertEqual(registry_key.x_misp_hive, hive)
        registry_value = registry_key['values'][0]
        self.assertEqual(registry_value.data, data)
        self.assertEqual(registry_value.data_type, data_type)
        self.assertEqual(registry_value.name, name)

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

    def test_event_with_url_observable_object(self):
        event = get_event_with_url_object()
        attributes, grouping_refs, object_refs, observables = self._run_observable_from_object_tests(event)
        url, domain, host, ip, port = (attribute['value'] for attribute in attributes)
        self.assertEqual(grouping_refs[0], object_refs[0])
        url_object = observables[0]
        self.assertEqual(url_object.id, object_refs[0])
        self.assertEqual(url_object.type, 'url')
        self.assertEqual(url_object.value, url)
        self.assertEqual(url_object.x_misp_domain, domain)
        self.assertEqual(url_object.x_misp_host, host)
        self.assertEqual(url_object.x_misp_ip, ip)
        self.assertEqual(url_object.x_misp_port, port)

    def test_event_with_user_account_indicator_object(self):
        event = get_event_with_user_account_object()
        attributes, pattern = self._run_indicator_from_object_tests(event)
        _username, _userid, _display_name, _passwd, _group1, _group2, _groupid, _home, _account_type, _plc = (attribute['value'] for attribute in attributes)
        account_type_, display_name_, passwd_, userid_, username_, plc_, group1_, group2_, groupid_, home_ = pattern[1:-1].split(' AND ')
        self.assertEqual(account_type_, f"user-account:account_type = '{_account_type}'")
        self.assertEqual(display_name_, f"user-account:display_name = '{_display_name}'")
        self.assertEqual(passwd_, f"user-account:credential = '{_passwd}'")
        self.assertEqual(userid_, f"user-account:user_id = '{_userid}'")
        self.assertEqual(username_, f"user-account:account_login = '{_username}'")
        self.assertEqual(plc_, f"user-account:credential_last_changed = '{_plc}'")
        self.assertEqual(group1_, f"user-account:extensions.'unix-account-ext'.groups = '{_group1}'")
        self.assertEqual(group2_, f"user-account:extensions.'unix-account-ext'.groups = '{_group2}'")
        self.assertEqual(groupid_, f"user-account:extensions.'unix-account-ext'.gid = '{_groupid}'")
        self.assertEqual(home_, f"user-account:extensions.'unix-account-ext'.home_dir = '{_home}'")

    def test_event_with_user_account_observable_object(self):
        event = get_event_with_user_account_object()
        attributes, grouping_refs, object_refs, observables = self._run_observable_from_object_tests(event)
        username, userid, display_name, passwd, group1, group2, groupid, home, account_type, plc = (attribute['value'] for attribute in attributes)
        self.assertEqual(grouping_refs[0], object_refs[0])
        user_account = observables[0]
        self.assertEqual(user_account.id, object_refs[0])
        self.assertEqual(user_account.type, 'user-account')
        self.assertEqual(user_account.user_id, userid)
        self.assertEqual(user_account.credential, passwd)
        self.assertEqual(user_account.account_login, username)
        self.assertEqual(user_account.account_type, account_type)
        self.assertEqual(user_account.display_name, display_name)
        extension = user_account.extensions['unix-account-ext']
        self.assertEqual(extension.gid, int(groupid))
        self.assertEqual(extension.groups, [group1, group2])
        self.assertEqual(extension.home_dir, home)
        self.assertEqual(
            datetime.strftime(user_account.credential_last_changed, '%Y-%m-%dT%H:%M:%S'),
            plc
        )

    def test_event_with_vulnerability_object(self):
        event = get_event_with_vulnerability_object()
        orgc = event['Event']['Orgc']
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event)
        stix_objects = self.parser.stix_objects
        self._check_spec_versions(stix_objects)
        identity, grouping, vulnerability = stix_objects
        identity_id = self._check_identity_features(
            identity,
            orgc,
            self._datetime_from_timestamp(event['Event']['timestamp'])
        )
        args = (grouping, event['Event'], identity_id)
        object_ref = self._check_grouping_features(*args)[0]
        self._check_object_vulnerability_features(vulnerability, misp_object, identity_id, object_ref)

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

    def test_event_with_x509_observable_object(self):
        event = get_event_with_x509_object()
        attributes, grouping_refs, object_refs, observables = self._run_observable_from_object_tests(event)
        issuer, pem, pia, pie, pim, srlnmbr, signalg, subject, vnb, vna, version, md5, sha1 = (attribute['value'] for attribute in attributes)
        self.assertEqual(grouping_refs[0], object_refs[0])
        x509 = observables[0]
        self.assertEqual(x509.id, object_refs[0])
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

    def test_object_references(self):
        event = get_event_with_object_references()
        orgc = event['Event']['Orgc']
        ap_object, as_object, btc_object, coa_object, ip_object, vuln_object = deepcopy(event['Event']['Object'])
        self.parser.parse_misp_event(event)
        stix_objects = self._check_bundle_features(15)
        self._check_spec_versions(stix_objects)
        identity, grouping, attack_pattern, observed_data, autonomous_system, custom, coa, indicator, vulnerability, *relationships = stix_objects
        timestamp = self._datetime_from_timestamp(event['Event']['timestamp'])
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        args = (
            grouping,
            event['Event'],
            identity_id
        )
        object_refs = self._check_grouping_features(*args)
        ap_ref, observed_data_ref, as_ref, custom_ref, coa_ref, indicator_ref, vuln_ref, *relationship_refs = object_refs
        self.assertEqual(attack_pattern.id, ap_ref)
        self.assertEqual(observed_data.id, observed_data_ref)
        self.assertEqual(autonomous_system.id, as_ref)
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

    def test_attribute_with_attack_pattern_galaxy(self):
        attribute = get_indicator_attribute_with_galaxy()
        misp_attribute = {"Attribute": [attribute]}
        self.parser.parse_misp_attributes(misp_attribute)
        self.assertIsNotNone(self.parser.bundle)


class TestSTIX21ExportInteroperability(TestSTIX2Export):
    def setUp(self):
        self.parser = MISPtoSTIX21Parser(interoperability=True)

    def _run_galaxy_tests(self, event, timestamp):
        orgc = event['Event']['Orgc']
        self.parser.parse_misp_event(event)
        stix_objects = self.parser.stix_objects
        for stix_object in stix_objects:
            self.assertEqual(stix_object.spec_version, '2.1')
        mitre_identity, identity, grouping, stix_object = stix_objects
        identity_id = self._check_identity_features(identity, orgc, timestamp)
        args = (grouping, event['Event'], identity_id)
        self.assertEqual(grouping.type, 'grouping')
        self.assertEqual(grouping.id, f"grouping--{event['Event']['uuid']}")
        self.assertEqual(grouping.created_by_ref, identity_id)
        self.assertEqual(grouping.labels, self._labels)
        self.assertEqual(grouping.name, event['Event']['info'])
        self.assertEqual(grouping.created, timestamp)
        self.assertEqual(grouping.modified, timestamp)
        self.assertEqual(stix_object.id, grouping.object_refs[0])
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


class TestCollectionStix21Export(TestCollectionSTIX2Export):
    def test_attributes_collection(self):
        name = 'test_attributes_collection'
        to_test_name = f'{name}.json.out'
        reference_name = f'{name}_stix21.json'
        output_file = self._current_path / to_test_name
        input_files = [self._current_path / f'{name}_{n}.json' for n in (1, 2)]
        self.assertEqual(misp_collection_to_stix2_1(output_file, *input_files), 1)
        self._check_stix2_results_export(to_test_name, reference_name)
        self.assertEqual(misp_collection_to_stix2_1(output_file, *input_files, in_memory=True), 1)
        self._check_stix2_results_export(to_test_name, reference_name)

    def test_events_collection(self):
        name = 'test_events_collection'
        to_test_name = f'{name}.json.out'
        reference_name = f'{name}_stix21.json'
        output_file = self._current_path / to_test_name
        input_files = [self._current_path / f'{name}_{n}.json' for n in (1, 2)]
        self.assertEqual(misp_collection_to_stix2_1(output_file, *input_files), 1)
        self._check_stix2_results_export(to_test_name, reference_name)
        self.assertEqual(misp_collection_to_stix2_1(output_file, *input_files, in_memory=True), 1)
        self._check_stix2_results_export(to_test_name, reference_name)

    def test_event_export(self):
        name = 'test_events_collection_1.json'
        self.assertEqual(misp_to_stix2_1(self._current_path / name), 1)
        self._check_stix2_results_export(f'{name}.out', 'test_event_stix21.json')
