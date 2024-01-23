#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .test_external_stix20_bundles import TestExternalSTIX20Bundles
from ._test_stix import TestSTIX21
from ._test_stix_import import TestExternalSTIX2Import, TestSTIX21Import
from uuid import uuid5


class TestExternalSTIX21Import(TestExternalSTIX2Import, TestSTIX21, TestSTIX21Import):

    ############################################################################
    #                        MISP GALAXIES IMPORT TESTS                        #
    ############################################################################

    def test_stix20_bundle_with_attack_pattern_galaxy(self):
        bundle = TestExternalSTIX20Bundles.get_bundle_with_attack_pattern_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, event_ap, indicator, attribute_ap, _ = bundle.objects
        self._check_misp_event_features(event, report)
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

    def test_stix20_bundle_with_campaign_galaxy(self):
        bundle = TestExternalSTIX20Bundles.get_bundle_with_campaign_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, event_campaign, indicator, attribute_campaign, _ = bundle.objects
        self._check_misp_event_features(event, report)
        meta = self._check_galaxy_features(event.galaxies, event_campaign)
        self.assertEqual(meta, {})
        self.assertEqual(len(event.attributes), 1)
        attribute = event.attributes[0]
        self.assertEqual(attribute.uuid, indicator.id.split('--')[1])
        self._check_galaxy_features(attribute.galaxies, attribute_campaign)
        self.assertEqual(meta, {})

    def test_stix20_bundle_with_course_of_action_galaxy(self):
        bundle = TestExternalSTIX20Bundles.get_bundle_with_course_of_action_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, event_coa, indicator, attribute_coa, _ = bundle.objects
        self._check_misp_event_features(event, report)
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

    def test_stix20_bundle_with_intrusion_set_galaxy(self):
        bundle = TestExternalSTIX20Bundles.get_bundle_with_intrusion_set_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, event_is, indicator, attribute_is, _ = bundle.objects
        self._check_misp_event_features(event, report)
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

    def test_stix20_bundle_with_malware_galaxy(self):
        bundle = TestExternalSTIX20Bundles.get_bundle_with_malware_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, event_malware, indicator, attribute_malware, _ = bundle.objects
        self._check_misp_event_features(event, report)
        meta = self._check_galaxy_features(event.galaxies, event_malware)
        self.assertEqual(meta['labels'], event_malware.labels)
        self.assertEqual(len(event.attributes), 1)
        attribute = event.attributes[0]
        self.assertEqual(attribute.uuid, indicator.id.split('--')[1])
        meta = self._check_galaxy_features(attribute.galaxies, attribute_malware)
        self.assertEqual(meta['labels'], attribute_malware.labels)

    def test_stix20_bundle_with_threat_actor_galaxy(self):
        bundle = TestExternalSTIX20Bundles.get_bundle_with_threat_actor_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, event_ta, indicator, attribute_ta, _ = bundle.objects
        self._check_misp_event_features(event, report)
        meta = self._check_galaxy_features(event.galaxies, event_ta)
        self.assertEqual(meta['synonyms'], event_ta.aliases)
        self.assertEqual(meta['roles'], event_ta.roles)
        self.assertEqual(meta['resource_level'], event_ta.resource_level)
        self.assertEqual(meta['primary_motivation'], event_ta.primary_motivation)
        self.assertEqual(meta['labels'], event_ta.labels)
        self.assertEqual(len(event.attributes), 1)
        attribute = event.attributes[0]
        self.assertEqual(attribute.uuid, indicator.id.split('--')[1])
        meta = self._check_galaxy_features(attribute.galaxies, attribute_ta)
        self.assertEqual(meta['synonyms'], attribute_ta.aliases)
        self.assertEqual(meta['roles'], attribute_ta.roles)
        self.assertEqual(meta['resource_level'], attribute_ta.resource_level)
        self.assertEqual(meta['primary_motivation'], attribute_ta.primary_motivation)
        self.assertEqual(meta['labels'], attribute_ta.labels)

    def test_stix20_bundle_with_tool_galaxy(self):
        bundle = TestExternalSTIX20Bundles.get_bundle_with_tool_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, event_tool, indicator, attribute_tool, _ = bundle.objects
        self._check_misp_event_features(event, report)
        meta = self._check_galaxy_features(event.galaxies, event_tool)
        killchain = event_tool.kill_chain_phases[0]
        self.assertEqual(
            meta['kill_chain'],
            [f'{killchain.kill_chain_name}:{killchain.phase_name}']
        )
        self.assertEqual(meta['labels'], event_tool.labels)
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
        self.assertEqual(meta['labels'], attribute_tool.labels)

    def test_stix20_bundle_with_vulnerability_galaxy(self):
        bundle = TestExternalSTIX20Bundles.get_bundle_with_vulnerability_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, event_vuln, indicator, attribute_vuln, _ = bundle.objects
        self._check_misp_event_features(event, report)
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

    ############################################################################
    #                    OBSERVED DATA OBJECTS IMPORT TESTS                    #
    ############################################################################

    def _check_artifact_object(self, misp_object, observed_data, identifier=None):
        self.assertEqual(misp_object.name, 'artifact')
        self._check_misp_object_fields(misp_object, observed_data, identifier)
        object_id = observed_data.id
        if identifier is None:
            identifier = '0'
        else:
            object_id = f'{object_id} - {identifier}'
        self._check_artifact_fields(
            misp_object, observed_data.objects[identifier], object_id
        )

    def _check_as_attribute(self, attribute, observed_data, identifier=None):
        self._check_misp_object_fields(attribute, observed_data, identifier)
        autonomous_system = observed_data.objects[identifier or '0']
        self.assertEqual(attribute.type, 'AS')
        self.assertEqual(attribute.value, f'AS{autonomous_system.number}')

    def _check_as_object(self, misp_object, observed_data, identifier=None):
        self.assertEqual(misp_object.name, 'asn')
        self._check_misp_object_fields(misp_object, observed_data, identifier)
        object_id = observed_data.id
        if identifier is None:
            identifier = '0'
        else:
            object_id = f'{object_id} - {identifier}'
        autonomous_system = observed_data.objects[identifier]
        self._check_as_fields(misp_object, autonomous_system, object_id)

    def _check_directory_object(self, misp_object, observed_data, identifier=None):
        self.assertEqual(misp_object.name, 'directory')
        self._check_misp_object_fields(misp_object, observed_data, identifier)
        object_id = observed_data.id
        if identifier is None:
            identifier = '0'
        else:
            object_id = f'{object_id} - {identifier}'
        directory = observed_data.objects[identifier]
        accessed, created, modified = self._check_directory_fields(
            misp_object, directory, object_id
        )
        self.assertEqual(accessed, directory.accessed)
        self.assertEqual(created, directory.created)
        self.assertEqual(modified, directory.modified)

    def _check_email_address_attribute(
            self, observed_data, address, identifier=None):
        email_address = observed_data.objects[identifier or '0']
        self._check_misp_object_fields(address, observed_data, identifier)
        self.assertEqual(address.type, 'email-dst')
        self.assertEqual(address.value, email_address.value)

    def _check_email_address_attribute_with_display_name(
            self, observed_data, address, display_name, identifier=None):
        if identifier is None:
            email_address = observed_data.objects['0']
            self._check_misp_object_fields(
                address, observed_data, f'email-dst - {email_address.value}'
            )
            self._check_misp_object_fields(
                display_name, observed_data,
                f'email-dst-display-name - {email_address.display_name}'
            )
        else:
            email_address = observed_data.objects[identifier]
            self._check_misp_object_fields(
                address, observed_data,
                f'{identifier} - email-dst - {email_address.value}'
            )
            self._check_misp_object_fields(
                display_name, observed_data,
                f'{identifier} - email-dst-display-name - {email_address.display_name}'
            )
        self.assertEqual(address.type, 'email-dst')
        self.assertEqual(address.value, email_address.value)
        self.assertEqual(display_name.type, 'email-dst-display-name')
        self.assertEqual(display_name.value, email_address.display_name)

    def _check_generic_attribute(
            self, observed_data, attribute, attribute_type,
            identifier=None, feature='value'):
        observable_object = observed_data.objects[identifier or '0']
        self._check_misp_object_fields(attribute, observed_data, identifier)
        self.assertEqual(attribute.type, attribute_type)
        self.assertEqual(attribute.value, getattr(observable_object, feature))

    def _check_misp_object_fields(self, misp_object, observed_data, identifier=None):
        if identifier is None:
            self.assertEqual(misp_object.uuid, observed_data.id.split('--')[1])
        else:
            self.assertEqual(
                misp_object.uuid,
                uuid5(self._UUIDv4, f'{observed_data.id} - {identifier}')
            )
        if not (observed_data.modified == observed_data.first_observed == observed_data.last_observed):
            self.assertEqual(misp_object.first_seen, observed_data.first_observed)
            self.assertEqual(misp_object.last_seen, observed_data.last_observed)
        self.assertEqual(misp_object.timestamp, observed_data.modified)

    def _check_software_object(self, misp_object, observed_data, identifier):
        self.assertEqual(misp_object.name, 'software')
        self._check_misp_object_fields(misp_object, observed_data, identifier)
        object_id = f'{observed_data.id} - {identifier}'
        self._check_software_fields(
            misp_object, observed_data.objects[identifier], object_id
        )

    def test_stix20_bundle_with_artifact_object(self):
        bundle = TestExternalSTIX20Bundles.get_bundle_with_artifact_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data1, observed_data2 = bundle.objects
        misp_objects = self._check_misp_event_features(event, report)
        self.assertEqual(len(misp_objects), 3)
        multiple1, multiple2, single = misp_objects
        self._check_artifact_object(multiple1, observed_data1, '0')
        self._check_misp_object_fields(multiple2, observed_data1, '1')
        self._check_artifact_with_url_fields(
            multiple2, observed_data1.objects['1'], f'{observed_data1.id} - 1'
        )
        self._check_artifact_object(single, observed_data2)

    def test_stix20_bundle_with_as_objects(self):
        bundle = TestExternalSTIX20Bundles.get_bundle_with_as_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data1, observed_data2, observed_data3 = bundle.objects
        misp_content = self._check_misp_event_features(event, report)
        self.assertEqual(len(misp_content), 4)
        m_object, s_object, m_attribute, s_attribute = misp_content
        self._check_as_object(m_object, observed_data1, '0')
        self._check_as_object(s_object, observed_data2)
        self._check_as_attribute(m_attribute, observed_data1, '1')
        self._check_as_attribute(s_attribute, observed_data3)

    def test_stix20_bundle_with_directory_objects(self):
        bundle = TestExternalSTIX20Bundles.get_bundle_with_directory_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data1, observed_data2 = bundle.objects
        misp_objects = self._check_misp_event_features(event, report)
        self.assertEqual(len(misp_objects), 3)
        single_directory, directory, referenced_directory = misp_objects
        self._check_directory_object(single_directory, observed_data1)
        self._check_directory_object(directory, observed_data2, '0')
        self._check_directory_object(referenced_directory, observed_data2, '1')
        reference = directory.references[0]
        self._assert_multiple_equal(
            reference.referenced_uuid,
            referenced_directory.uuid,
            uuid5(self._UUIDv4, f'{observed_data2.id} - 1')
        )
        self.assertEqual(reference.relationship_type, 'contains')

    def test_stix20_bundle_with_domain_attributes(self):
        bundle = TestExternalSTIX20Bundles.get_bundle_with_domain_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle(bundle)
        event = self.parser.misp_event
        _, report, observed_data1, observed_data2 = bundle.objects
        attributes = self._check_misp_event_features(event, report)
        self.assertEqual(len(attributes), 3)
        m_domain1, m_domain2, s_domain = attributes
        self._check_generic_attribute(
            observed_data1, m_domain1, 'domain', '0'
        )
        self._check_generic_attribute(
            observed_data1, m_domain2, 'domain', '1'
        )
        self._check_generic_attribute(
            observed_data2, s_domain, 'domain'
        )

    def test_stix20_bundle_with_email_address_objects(self):
        bundle = TestExternalSTIX20Bundles.get_bundle_with_email_address_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data1, observed_data2, observed_data3 = bundle.objects
        attributes = self._check_misp_event_features(event, report)
        self.assertEqual(len(attributes), 6)
        mm_address, mm_display_name, ms_address, sm_address, sm_display_name, ss_address = attributes
        self._check_email_address_attribute_with_display_name(
            observed_data1, mm_address, mm_display_name, '0'
        )
        self._check_email_address_attribute(observed_data1, ms_address, '1')
        self._check_email_address_attribute_with_display_name(
            observed_data2, sm_address, sm_display_name
        )
        self._check_email_address_attribute(observed_data3, ss_address)

    def test_stix20_bundle_with_ip_address_attributes(self):
        bundle = TestExternalSTIX20Bundles.get_bundle_with_ip_address_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle(bundle)
        event = self.parser.misp_event
        _, report, observed_data1, observed_data2 = bundle.objects
        attributes = self._check_misp_event_features(event, report)
        self.assertEqual(len(attributes), 3)
        m_ip1, m_ip2, s_ip = attributes
        self._check_generic_attribute(
            observed_data1, m_ip1, 'ip-dst', '0'
        )
        self._check_generic_attribute(
            observed_data1, m_ip2, 'ip-dst', '1'
        )
        self._check_generic_attribute(
            observed_data2, s_ip, 'ip-dst'
        )

    def test_stix20_bundle_with_mac_address_attributes(self):
        bundle = TestExternalSTIX20Bundles.get_bundle_with_mac_address_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle(bundle)
        event = self.parser.misp_event
        _, report, observed_data1, observed_data2 = bundle.objects
        attributes = self._check_misp_event_features(event, report)
        self.assertEqual(len(attributes), 3)
        m_mac1, m_mac2, s_mac = attributes
        self._check_generic_attribute(
            observed_data1, m_mac1, 'mac-address', '0'
        )
        self._check_generic_attribute(
            observed_data1, m_mac2, 'mac-address', '1'
        )
        self._check_generic_attribute(
            observed_data2, s_mac, 'mac-address'
        )

    def test_stix20_bundle_with_mutex_attributes(self):
        bundle = TestExternalSTIX20Bundles.get_bundle_with_mutex_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle(bundle)
        event = self.parser.misp_event
        _, report, observed_data1, observed_data2 = bundle.objects
        attributes = self._check_misp_event_features(event, report)
        self.assertEqual(len(attributes), 3)
        m_mutex1, m_mutex2, s_mutex = attributes
        self._check_generic_attribute(
            observed_data1, m_mutex1, 'mutex', '0', 'name'
        )
        self._check_generic_attribute(
            observed_data1, m_mutex2, 'mutex', '1', 'name'
        )
        self._check_generic_attribute(
            observed_data2, s_mutex, 'mutex', feature='name'
        )

    def test_stix20_bundle_with_software_objects(self):
        bundle = TestExternalSTIX20Bundles.get_bundle_with_software_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data1, observed_data2 = bundle.objects
        misp_objects = self._check_misp_event_features(event, report)
        self.assertEqual(len(misp_objects), 3)
        multiple1, multiple2, single = misp_objects
        self._check_software_object(multiple1, observed_data1, '0')
        self._check_software_object(multiple2, observed_data1, '1')
        self._check_misp_object_fields(single, observed_data2)
        self._check_software_with_swid_fields(
            single, observed_data2.objects['0'], observed_data2.id
        )

    def test_stix20_bundle_with_url_attributes(self):
        bundle = TestExternalSTIX20Bundles.get_bundle_with_url_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle(bundle)
        event = self.parser.misp_event
        _, report, observed_data1, observed_data2 = bundle.objects
        attributes = self._check_misp_event_features(event, report)
        self.assertEqual(len(attributes), 3)
        m_url1, m_url2, s_url = attributes
        self._check_generic_attribute(
            observed_data1, m_url1, 'url', '0'
        )
        self._check_generic_attribute(
            observed_data1, m_url2, 'url', '1'
        )
        self._check_generic_attribute(
            observed_data2, s_url, 'url'
        )
