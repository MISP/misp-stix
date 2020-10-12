#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import json
from misp_stix_converter import MISPtoSTIX1Parser
from pymisp import MISPEvent
from .test_events import *

_DEFAULT_NAMESPACE = 'MISP-Project'
_DEFAULT_ORGNAME = 'MISP-Project'


class TestStix1Export(unittest.TestCase):
    def setUp(self):
        self.parser = MISPtoSTIX1Parser(_DEFAULT_NAMESPACE, _DEFAULT_ORGNAME)

    ################################################################################
    #                              UTILITY FUNCTIONS.                              #
    ################################################################################

    def _check_destination_address(self, properties, category='ipv4-addr'):
        self.assertEqual(properties.category, category)
        self.assertFalse(properties.is_source)
        self.assertTrue(properties.is_destination)

    def _check_email_indicator(self, related_indicator, attribute, orgc):
        indicator = self._check_indicator_features(related_indicator, attribute, orgc)
        return self._check_email_observable(indicator.observable, attribute)

    def _check_email_observable(self, observable, attribute):
        self.assertEqual(observable.id_, f"{_DEFAULT_NAMESPACE}:Observable-{attribute['uuid']}")
        observable_object = observable.object_
        self.assertEqual(observable_object.id_, f"{_DEFAULT_NAMESPACE}:EmailMessageObject-{attribute['uuid']}")
        properties = observable_object.properties
        self.assertEqual(properties._XSI_TYPE, 'EmailMessageObjectType')
        return properties

    def _check_embedded_features(self, embedded_object, cluster, name, feature='title'):
        self.assertEqual(embedded_object.id_, f"{_DEFAULT_NAMESPACE}:{name}-{cluster['uuid']}")
        self.assertEqual(getattr(embedded_object, feature), cluster['value'])
        self.assertEqual(embedded_object.description.value, cluster['description'])

    def _check_indicator_features(self, related_indicator, attribute, orgc):
        self.assertEqual(related_indicator.relationship, attribute['category'])
        indicator = related_indicator.item
        self.assertEqual(indicator.id_, f"{_DEFAULT_NAMESPACE}:Indicator-{attribute['uuid']}")
        self.assertEqual(indicator.title, f"{attribute['category']}: {attribute['value']} (MISP Attribute)")
        self.assertEqual(indicator.description.value, attribute['comment'])
        self.assertEqual(int(indicator.timestamp.timestamp()), int(attribute['timestamp']))
        self.assertEqual(indicator.producer.identity.name, orgc)
        return indicator

    def _check_observable_features(self, observable, attribute, name, feature='value'):
        self.assertEqual(observable.id_, f"{_DEFAULT_NAMESPACE}:Observable-{attribute['uuid']}")
        observable_object = observable.object_
        self.assertEqual(observable_object.id_, f"{_DEFAULT_NAMESPACE}:{name}Object-{attribute['uuid']}")
        properties = observable_object.properties
        self.assertEqual(properties._XSI_TYPE, f'{name}ObjectType')
        try:
            self.assertEqual(getattr(properties, feature).value, attribute['value'])
        except AssertionError:
            self.assertIn(getattr(properties, feature).value, attribute['value'])

    def _check_related_ttp(self, stix_package, galaxy_name, cluster_uuid):
        related_ttp = stix_package.incidents[0].leveraged_ttps.ttp[0]
        self.assertEqual(related_ttp.relationship.value, galaxy_name)
        self.assertEqual(related_ttp.item.idref, f"{_DEFAULT_NAMESPACE}:TTP-{cluster_uuid}")

    def _check_source_address(self, properties, category='ipv4-addr'):
        self.assertEqual(properties.category, category)
        self.assertTrue(properties.is_source)
        self.assertFalse(properties.is_destination)

    def _check_ttp_fields(self, stix_package, cluster_uuid, galaxy_name):
        self.assertEqual(len(stix_package.ttps.ttp), 1)
        ttp = stix_package.ttps.ttp[0]
        self.assertEqual(ttp.id_, f"{_DEFAULT_NAMESPACE}:TTP-{cluster_uuid}")
        self.assertEqual(ttp.title, f"{galaxy_name} (MISP Galaxy)")
        return ttp

    @staticmethod
    def _get_marking_value(marking):
        if marking._XSI_TYPE == 'tlpMarking:TLPMarkingStructureType':
            return marking.color
        return marking.statement

    ################################################################################
    #                              EVENT FIELDS TESTS                              #
    ################################################################################

    def test_base_event(self):
        event = get_base_event()
        uuid = event['Event']['uuid']
        timestamp = int(event['Event']['timestamp'])
        info = event['Event']['info']
        self.parser.parse_misp_event(event, '1.1.1')
        stix_package = self.parser.stix_package
        self.assertEqual(stix_package.id_, f"{_DEFAULT_NAMESPACE}:STIXPackage-{uuid}")
        self.assertEqual(int(stix_package.timestamp.timestamp()), timestamp)
        self.assertEqual(stix_package.version, '1.1.1')
        self.assertEqual(stix_package.stix_header.title, f'Export from {_DEFAULT_NAMESPACE} MISP')
        incident = stix_package.incidents[0]
        self.assertEqual(incident.id_, f"{_DEFAULT_NAMESPACE}:Incident-{uuid}")
        self.assertEqual(incident.title, info)
        self.assertEqual(incident.information_source.identity.name, _DEFAULT_ORGNAME)
        self.assertEqual(incident.reporter.identity.name, _DEFAULT_ORGNAME)

    def test_published_event(self):
        event = get_published_event()
        timestamp = int(event['Event']['timestamp'])
        publish_timestamp = int(event['Event']['publish_timestamp'])
        date = event['Event']['date']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        self.assertEqual(int(incident.timestamp.timestamp()), timestamp)
        self.assertEqual(incident.time.incident_discovery.value.strftime("%Y-%m-%d"), date)
        self.assertEqual(int(incident.time.incident_reported.value.timestamp()), publish_timestamp)

    def test_event_with_tags(self):
        event = get_event_with_tags()
        self.parser.parse_misp_event(event, '1.1.1')
        marking = self.parser.stix_package.incidents[0].handling[0]
        self.assertEqual(len(marking.marking_structures), 3)
        markings = tuple(self._get_marking_value(marking) for marking in marking.marking_structures)
        self.assertIn('WHITE', markings)
        self.assertIn('misp:tool="misp2stix"', markings)
        self.assertIn('misp-galaxy:mitre-attack-pattern="Code Signing - T1116"', markings)

    ################################################################################
    #                        SINGLE ATTRIBUTES EXPORT TESTS                        #
    ################################################################################

    def test_event_with_as_attribute(self):
        event = get_event_with_as_attribute()
        attribute = event['Event']['Attribute'][0]
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        observable = incident.related_observables.observable[0]
        self.assertEqual(observable.relationship, attribute['category'])
        self._check_observable_features(observable.item, attribute, 'AS', feature='handle')

    def test_event_with_domain_attribute(self):
        event = get_event_with_domain_attribute()
        attribute = event['Event']['Attribute'][0]
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_features(related_indicator, attribute, orgc)
        self._check_observable_features(indicator.observable, attribute, 'DomainName')

    def test_event_with_domain_ip_attribute(self):
        event = get_event_with_domain_ip_attribute()
        attribute = event['Event']['Attribute'][0]
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_features(related_indicator, attribute, orgc)
        observable = indicator.observable
        self.assertEqual(observable.id_, f"{_DEFAULT_NAMESPACE}:ObservableComposition-{attribute['uuid']}")
        domain, address = observable.observable_composition.observables
        self._check_observable_features(domain, attribute, 'DomainName')
        self._check_observable_features(address, attribute, 'Address', feature='address_value')
        self._check_destination_address(address.object_.properties)

    def test_event_with_email_attributes(self):
        event = get_event_with_email_attributes()
        source, destination, subject, reply_to = event['Event']['Attribute']
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        src_indicator, dst_indicator = incident.related_indicators.indicator
        source_properties = self._check_email_indicator(src_indicator, source, orgc)
        self.assertEqual(source_properties.from_.address_value.value, source['value'])
        self.assertEqual(source_properties.from_.category, 'e-mail')
        destination_properties = self._check_email_indicator(dst_indicator, destination, orgc)
        self.assertEqual(destination_properties.to[0].address_value.value, destination['value'])
        self.assertEqual(destination_properties.to[0].category, 'e-mail')
        subject_observable, reply_to_observable = incident.related_observables.observable
        subject_properties = self._check_email_observable(subject_observable.item, subject)
        self.assertEqual(subject_properties.subject.value, subject['value'])
        reply_to_properties = self._check_email_observable(reply_to_observable.item, reply_to)
        self.assertEqual(reply_to_properties.reply_to.address_value.value, reply_to['value'])
        self.assertEqual(reply_to_properties.reply_to.category, 'e-mail')

    ################################################################################
    #                            GALAXIES EXPORT TESTS.                            #
    ################################################################################

    def test_event_with_attack_pattern_galaxy(self):
        event = get_event_with_attack_pattern_galaxy()
        galaxy = event['Event']['Galaxy'][0]
        cluster = galaxy['GalaxyCluster'][0]
        self.parser.parse_misp_event(event, '1.1.1')
        stix_package = self.parser.stix_package
        ttp = self._check_ttp_fields(stix_package, cluster['uuid'], galaxy['name'])
        attack_pattern = ttp.behavior.attack_patterns[0]
        self._check_embedded_features(attack_pattern, cluster, 'AttackPattern')
        self._check_related_ttp(stix_package, galaxy['name'], cluster['uuid'])

    def test_event_with_course_of_action_galaxy(self):
        event = get_event_with_course_of_action_galaxy()
        cluster = event['Event']['Galaxy'][0]['GalaxyCluster'][0]
        self.parser.parse_misp_event(event, '1.1.1')
        stix_package = self.parser.stix_package
        self.assertEqual(len(stix_package.courses_of_action), 1)
        course_of_action = stix_package.courses_of_action[0]
        self._check_embedded_features(course_of_action, cluster, 'CourseOfAction')

    def test_event_with_malware_galaxy(self):
        event = get_event_with_malware_galaxy()
        galaxy = event['Event']['Galaxy'][0]
        cluster = galaxy['GalaxyCluster'][0]
        self.parser.parse_misp_event(event, '1.1.1')
        stix_package = self.parser.stix_package
        ttp = self._check_ttp_fields(stix_package, cluster['uuid'], galaxy['name'])
        malware = ttp.behavior.malware_instances[0]
        self._check_embedded_features(malware, cluster, 'MalwareInstance')
        self._check_related_ttp(stix_package, galaxy['name'], cluster['uuid'])

    def test_event_with_threat_actor_galaxy(self):
        event = get_event_with_threat_actor_galaxy()
        galaxy = event['Event']['Galaxy'][0]
        cluster = galaxy['GalaxyCluster'][0]
        self.parser.parse_misp_event(event, '1.1.1')
        stix_package = self.parser.stix_package
        self.assertEqual(len(stix_package.threat_actors), 1)
        threat_actor = stix_package.threat_actors[0]
        threat_actor_id = f"{_DEFAULT_NAMESPACE}:ThreatActor-{cluster['uuid']}"
        self.assertEqual(threat_actor.id_, threat_actor_id)
        self.assertEqual(threat_actor.title, cluster['value'])
        self.assertEqual(threat_actor.description.value, cluster['description'])
        intended_effect = threat_actor.intended_effects[0]
        self.assertEqual(intended_effect.value, cluster['meta']['cfr-type-of-incident'][0])
        related_threat_actor = stix_package.incidents[0].attributed_threat_actors.threat_actor[0]
        self.assertEqual(related_threat_actor.relationship.value, galaxy['name'])
        self.assertEqual(related_threat_actor.item.idref, threat_actor_id)

    def test_event_with_tool_galaxy(self):
        event = get_event_with_tool_galaxy()
        galaxy = event['Event']['Galaxy'][0]
        cluster = galaxy['GalaxyCluster'][0]
        self.parser.parse_misp_event(event, '1.1.1')
        stix_package = self.parser.stix_package
        ttp = self._check_ttp_fields(stix_package, cluster['uuid'], galaxy['name'])
        tool = ttp.resources.tools[0]
        self._check_embedded_features(tool, cluster, 'ToolInformation', feature='name')
        self._check_related_ttp(stix_package, galaxy['name'], cluster['uuid'])

    def test_event_with_vulnerability_galaxy(self):
        event = get_event_with_vulnerability_galaxy()
        galaxy = event['Event']['Galaxy'][0]
        cluster = galaxy['GalaxyCluster'][0]
        self.parser.parse_misp_event(event, '1.1.1')
        stix_package = self.parser.stix_package
        ttp = self._check_ttp_fields(stix_package, cluster['uuid'], galaxy['name'])
        exploit_target = ttp.exploit_targets.exploit_target[0].item
        self.assertEqual(exploit_target.id_, f"{_DEFAULT_NAMESPACE}:ExploitTarget-{cluster['uuid']}")
        vulnerability = exploit_target.vulnerabilities[0]
        self._check_embedded_features(vulnerability, cluster, 'Vulnerability')
        self.assertEqual(vulnerability.cve_id, cluster['meta']['aliases'][0])
        self._check_related_ttp(stix_package, galaxy['name'], cluster['uuid'])
