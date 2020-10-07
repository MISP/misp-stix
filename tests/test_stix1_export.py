#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import json
from misp_stix_converter import MISPtoSTIX1Parser
from pymisp import MISPEvent
from .test_events import *

_DEFAULT_NAMESPACE = 'MISP'
_DEFAULT_ORGNAME = 'MISP-Project'


class TestStix1Export(unittest.TestCase):
    def setUp(self):
        self.parser = MISPtoSTIX1Parser(_DEFAULT_NAMESPACE, _DEFAULT_ORGNAME)

    @staticmethod
    def get_marking_value(marking):
        if marking._XSI_TYPE == 'tlpMarking:TLPMarkingStructureType':
            return marking.color
        return marking.statement

    def test_base_event(self):
        event = get_base_event()
        uuid = event['Event']['uuid']
        timestamp = int(event['Event']['timestamp'])
        self.parser.parse_misp_event(event, '1.1.1')
        stix_package = self.parser.stix_package
        self.assertEqual(stix_package.id_, f"{_DEFAULT_NAMESPACE}:STIXPackage-{uuid}")
        self.assertEqual(int(stix_package.timestamp.timestamp()), timestamp)
        self.assertEqual(stix_package.version, '1.1.1')
        self.assertEqual(stix_package.stix_header.title, f'Export from {_DEFAULT_NAMESPACE} MISP')
        incident = stix_package.incidents[0]
        self.assertEqual(incident.id_, f"{_DEFAULT_NAMESPACE}:STIXPackage-{uuid}")
        self.assertEqual(incident.title, event['Event']['info'])
        self.assertEqual(incident.information_source.identity.name, _DEFAULT_ORGNAME)
        self.assertEqual(incident.reporter.identity.name, _DEFAULT_ORGNAME)

    def test_published_event(self):
        event = get_published_event()
        timestamp = int(event['Event']['timestamp'])
        publish_timestamp = int(event['Event']['publish_timestamp'])
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        self.assertEqual(int(incident.timestamp.timestamp()), timestamp)
        self.assertEqual(incident.time.incident_discovery.value.strftime("%Y-%m-%d"), event['Event']['date'])
        self.assertEqual(int(incident.time.incident_reported.value.timestamp()), publish_timestamp)

    def test_event_with_tags(self):
        event = get_event_with_tags()
        self.parser.parse_misp_event(event, '1.1.1')
        marking = self.parser.stix_package.incidents[0].handling[0]
        self.assertEqual(len(marking.marking_structures), 3)
        markings = tuple(self.get_marking_value(marking) for marking in marking.marking_structures)
        self.assertIn('WHITE', markings)
        self.assertIn('misp:tool="misp2stix"', markings)
        self.assertIn('misp-galaxy:mitre-attack-pattern="Code Signing - T1116"', markings)

    def test_event_with_attack_pattern_galaxy(self):
        event = get_event_with_attack_pattern_galaxy()
        galaxy = event['Galaxy'][0]
        cluster = galaxy['GalaxyCluster'][0]
        self.parser.parse_misp_event(event, '1.1.1')
        stix_package = self.parser.stix_package
        self.assertEqual(len(stix_package.ttps.ttp), 1)
        ttp = stix_package.ttps.ttp[0]
        ttp_id = f"{_DEFAULT_NAMESPACE}:TTP-{cluster['uuid']}"
        self.assertEqual(ttp.id_, ttp_id)
        self.assertEqual(ttp.title, f"{galaxy['name']} (MISP Galaxy)")
        attack_pattern = ttp.behavior.attack_patterns[0]
        self.assertEqual(attack_pattern.id_, f"{_DEFAULT_NAMESPACE}:AttackPattern-{cluster['uuid']}")
        self.assertEqual(attack_pattern.title, cluster['value'])
        self.assertEqual(attack_pattern.description.value, cluster['description'])
        related_ttp = stix_package.incidents[0].leveraged_ttps.ttp[0]
        self.assertEqual(related_ttp.relationship.value, galaxy['name'])
        self.assertEqual(related_ttp.item.idref, ttp_id)

    def test_event_with_course_of_action_galaxy(self):
        event = get_event_with_course_of_action_galaxy()
        cluster = event['Galaxy'][0]['GalaxyCluster'][0]
        self.parser.parse_misp_event(event, '1.1.1')
        stix_package = self.parser.stix_package
        self.assertEqual(len(stix_package.courses_of_action), 1)
        course_of_action = stix_package.courses_of_action[0]
        self.assertEqual(course_of_action.id_, f"{_DEFAULT_NAMESPACE}:CourseOfAction-{cluster['uuid']}")
        self.assertEqual(course_of_action.title, cluster['value'])
        self.assertEqual(course_of_action.description.value, cluster['description'])

    def test_event_with_malware_galaxy(self):
        event = get_event_with_malware_galaxy()
        galaxy = event['Galaxy'][0]
        cluster = galaxy['GalaxyCluster'][0]
        self.parser.parse_misp_event(event, '1.1.1')
        stix_package = self.parser.stix_package
        self.assertEqual(len(stix_package.ttps.ttp), 1)
        ttp = stix_package.ttps.ttp[0]
        ttp_id = f"{_DEFAULT_NAMESPACE}:TTP-{cluster['uuid']}"
        self.assertEqual(ttp.id_, ttp_id)
        self.assertEqual(ttp.title, f"{galaxy['name']} (MISP Galaxy)")
        malware = ttp.behavior.malware_instances[0]
        self.assertEqual(malware.id_, f"{_DEFAULT_NAMESPACE}:AttackPattern-{cluster['uuid']}")
        self.assertEqual(malware.title, cluster['value'])
        self.assertEqual(malware.description.value, cluster['description'])
        related_ttp = stix_package.incidents[0].leveraged_ttps.ttp[0]
        self.assertEqual(related_ttp.relationship.value, galaxy['name'])
        self.assertEqual(related_ttp.item.idref, ttp_id)
