#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .test_external_stix21_bundles import TestExternalSTIX21Bundles
from ._test_stix import TestSTIX21
from ._test_stix_import import TestExternalSTIX2Import, TestSTIX21Import


class TestExternalSTIX21Import(TestExternalSTIX2Import, TestSTIX21, TestSTIX21Import):
    
    ################################################################################
    #                          MISP GALAXIES IMPORT TESTS                          #
    ################################################################################

    def _check_location_galaxy_features(self, galaxies, stix_object, galaxy_type, cluster_value=None):
        self.assertEqual(len(galaxies), 1)
        galaxy = galaxies[0]
        self.assertEqual(len(galaxy.clusters), 1)
        cluster = galaxy.clusters[0]
        self._assert_multiple_equal(galaxy.type, cluster.type, galaxy_type)
        self.assertEqual(
            galaxy.name, self._galaxy_name_mapping(galaxy_type)['name']
        )
        self.assertEqual(
            galaxy.description,
            self._galaxy_name_mapping(galaxy_type)['description']
        )
        if cluster_value is None:
            self.assertEqual(cluster.value, stix_object.name)
        else:
            self.assertEqual(cluster.value, cluster_value)
        if hasattr(stix_object, 'description'):
            self.assertEqual(cluster.description, stix_object.description)
        return cluster.meta

    def test_stix21_bundle_with_attack_pattern_galaxy(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_attack_pattern_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, event_ap, indicator, attribute_ap, _ = bundle.objects
        self._check_misp_event_features_from_grouping(event, grouping)
        meta = self._check_galaxy_features(event.galaxies, event_ap)
        killchain = event_ap.kill_chain_phases[0]
        self.assertEqual(
            meta['kill_chain'],
            [f'{killchain.kill_chain_name}:{killchain.phase_name}']
        )
        self.assertEqual(
            meta['external_id'],
            event_ap.external_references[0].external_id
        )
        self.assertEqual(len(event.attributes), 1)
        attribute = event.attributes[0]
        self.assertEqual(attribute.uuid, indicator.id.split('--')[1])
        self._check_galaxy_features(attribute.galaxies, attribute_ap)
        killchain = attribute_ap.kill_chain_phases[0]
        self.assertEqual(
            meta['kill_chain'],
            [f'{killchain.kill_chain_name}:{killchain.phase_name}']
        )

    def test_stix21_bundle_with_campaign_galaxy(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_campaign_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, event_campaign, indicator, attribute_campaign, _ = bundle.objects
        self._check_misp_event_features_from_grouping(event, grouping)
        meta = self._check_galaxy_features(event.galaxies, event_campaign)
        self.assertEqual(meta, {})
        self.assertEqual(len(event.attributes), 1)
        attribute = event.attributes[0]
        self.assertEqual(attribute.uuid, indicator.id.split('--')[1])
        self._check_galaxy_features(attribute.galaxies, attribute_campaign),
        self.assertEqual(meta, {})

    def test_stix21_bundle_with_course_of_action_galaxy(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_course_of_action_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, event_coa, indicator, attribute_coa, _ = bundle.objects
        self._check_misp_event_features_from_grouping(event, grouping)
        meta = self._check_galaxy_features(event.galaxies, event_coa)
        self.assertEqual(
            meta['refs'],
            [reference.url for reference in event_coa.external_references]
        )
        self.assertEqual(len(event.attributes), 1)
        attribute = event.attributes[0]
        self.assertEqual(attribute.uuid, indicator.id.split('--')[1])
        meta = self._check_galaxy_features(attribute.galaxies, attribute_coa)
        url, external_id = attribute_coa.external_references
        self.assertEqual(meta['refs'], [url.url])
        self.assertEqual(meta['external_id'], external_id.external_id)

    def test_stix21_bundle_with_intrusion_set_galaxy(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_intrusion_set_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, event_is, indicator, attribute_is, _ = bundle.objects
        self._check_misp_event_features_from_grouping(event, grouping)
        meta = self._check_galaxy_features(event.galaxies, event_is)
        self.assertEqual(meta['synonyms'], event_is.aliases)
        self.assertEqual(meta['resource_level'], event_is.resource_level)
        self.assertEqual(meta['primary_motivation'], event_is.primary_motivation)
        self.assertEqual(len(event.attributes), 1)
        attribute = event.attributes[0]
        self.assertEqual(attribute.uuid, indicator.id.split('--')[1])
        meta = self._check_galaxy_features(attribute.galaxies, attribute_is)
        self.assertEqual(meta['synonyms'], attribute_is.aliases)
        self.assertEqual(meta['resource_level'], attribute_is.resource_level)
        self.assertEqual(meta['primary_motivation'], attribute_is.primary_motivation)

    def test_stix21_bundle_with_location_galaxy(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_location_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, event_location, indicator, attribute_location, _ = bundle.objects
        self._check_misp_event_features_from_grouping(event, grouping)
        country_meta = self._check_location_galaxy_features(
            event.galaxies, event_location, 'country'
        )
        self.assertEqual(country_meta, {})
        self.assertEqual(len(event.attributes), 1)
        attribute = event.attributes[0]
        self.assertEqual(attribute.uuid, indicator.id.split('--')[1])
        region_meta = self._check_location_galaxy_features(
            attribute.galaxies, attribute_location, 'region',
            cluster_value='154 - Northern Europe'
        )
        self.assertEqual(region_meta, {})

    def test_stix21_bundle_with_malware_galaxy(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_malware_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, event_malware, indicator, attribute_malware, _ = bundle.objects
        self._check_misp_event_features_from_grouping(event, grouping)
        meta = self._check_galaxy_features(event.galaxies, event_malware)
        self.assertEqual(meta['malware_types'], event_malware.malware_types)
        self.assertEqual(len(event.attributes), 1)
        attribute = event.attributes[0]
        self.assertEqual(attribute.uuid, indicator.id.split('--')[1])
        meta = self._check_galaxy_features(attribute.galaxies, attribute_malware)
        self.assertEqual(meta['malware_types'], attribute_malware.malware_types)

    def test_stix21_bundle_with_threat_actor_galaxy(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_threat_actor_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, event_ta, indicator, attribute_ta, _ = bundle.objects
        self._check_misp_event_features_from_grouping(event, grouping)
        meta = self._check_galaxy_features(event.galaxies, event_ta)
        self.assertEqual(meta['synonyms'], event_ta.aliases)
        self.assertEqual(meta['roles'], event_ta.roles)
        self.assertEqual(meta['resource_level'], event_ta.resource_level)
        self.assertEqual(meta['primary_motivation'], event_ta.primary_motivation)
        self.assertEqual(meta['threat_actor_types'], event_ta.threat_actor_types)
        self.assertEqual(len(event.attributes), 1)
        attribute = event.attributes[0]
        self.assertEqual(attribute.uuid, indicator.id.split('--')[1])
        meta = self._check_galaxy_features(attribute.galaxies, attribute_ta)
        self.assertEqual(meta['synonyms'], attribute_ta.aliases)
        self.assertEqual(meta['roles'], attribute_ta.roles)
        self.assertEqual(meta['resource_level'], attribute_ta.resource_level)
        self.assertEqual(meta['primary_motivation'], attribute_ta.primary_motivation)
        self.assertEqual(meta['threat_actor_types'], attribute_ta.threat_actor_types)

    def test_stix21_bundle_with_tool_galaxy(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_tool_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, event_tool, indicator, attribute_tool, _ = bundle.objects
        self._check_misp_event_features_from_grouping(event, grouping)
        meta = self._check_galaxy_features(event.galaxies, event_tool)
        killchain = event_tool.kill_chain_phases[0]
        self.assertEqual(
            meta['kill_chain'],
            [f'{killchain.kill_chain_name}:{killchain.phase_name}']
        )
        self.assertEqual(meta['tool_types'], event_tool.tool_types)
        self.assertEqual(len(event.attributes), 1)
        attribute = event.attributes[0]
        self.assertEqual(attribute.uuid, indicator.id.split('--')[1])
        meta = self._check_galaxy_features(attribute.galaxies, attribute_tool)
        self.assertEqual(
            meta['refs'], [attribute_tool.external_references[0].url]
        )
        killchain = attribute_tool.kill_chain_phases[0]
        self.assertEqual(
            meta['kill_chain'],
            [f'{killchain.kill_chain_name}:{killchain.phase_name}']
        )
        self.assertEqual(meta['tool_types'], attribute_tool.tool_types)

    def test_stix21_bundle_with_vulnerability_galaxy(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_vulnerability_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, event_vuln, indicator, attribute_vuln, _ = bundle.objects
        self._check_misp_event_features_from_grouping(event, grouping)
        meta = self._check_galaxy_features(event.galaxies, event_vuln)
        self.assertEqual(
            meta['external_id'], event_vuln.external_references[0].external_id
        )
        self.assertEqual(len(event.attributes), 1)
        attribute = event.attributes[0]
        self.assertEqual(attribute.uuid, indicator.id.split('--')[1])
        meta = self._check_galaxy_features(attribute.galaxies, attribute_vuln)
        self.assertEqual(
            meta['external_id'],
            attribute_vuln.external_references[0].external_id
        )