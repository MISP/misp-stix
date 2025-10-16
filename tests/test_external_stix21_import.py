#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .test_external_stix21_bundles import TestExternalSTIX21Bundles
from ._test_stix import TestSTIX21
from ._test_stix_import import TestExternalSTIX2Import, TestSTIX21Import, UUIDv4
from datetime import datetime
from uuid import uuid5

_ACS_EXTENSION_ID = 'extension-definition--3a65884d-005a-4290-8335-cb2d778a83ce'


class TestExternalSTIX21Import(TestExternalSTIX2Import, TestSTIX21, TestSTIX21Import):

    ############################################################################
    #                         MISP EVENT IMPORT TESTS.                         #
    ############################################################################

    def _check_acs_marking_features(self, meta, definition):
        for key, value in definition.items():
            if key == 'extension_type':
                continue
            if key == 'access_privilege':
                access_privileges = []
                for privilege in value:
                    action = privilege['privilege_action']
                    access_privileges.append(action)
                    feature = f'access_privilege.{action}'
                    self.assertEqual(
                        meta[f'{feature}.rule_effect'], privilege['rule_effect']
                    )
                    for scope, scopes in privilege['privilege_scope'].items():
                        self.assertEqual(
                            meta[f'{feature}.privilege_scope.{scope}'], scopes
                        )
                self.assertEqual(
                    meta['access_privilege.privilege_action'],
                    access_privileges
                )
                continue
            if key == 'control_set':
                for feature, control in value.items():
                    self.assertEqual(meta[f'control_set.{feature}'], control)
                continue
            self.assertEqual(meta[key], value)

    def test_stix21_bundle_with_acs_marking(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_acs_marking()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, ip_address, marking1, marking2 = bundle.objects
        self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(event.galaxies), 1)
        event_galaxy = event.galaxies[0]
        self.assertEqual(event_galaxy.name, 'STIX 2.1 ACS Marking')
        self.assertEqual(len(event_galaxy.clusters), 2)
        cluster1, cluster2 = event_galaxy.clusters
        definition1 = marking1.extensions[_ACS_EXTENSION_ID]
        self.assertEqual(cluster1.value, definition1['name'])
        self._check_acs_marking_features(cluster1.meta, definition1)
        definition2 = marking2.extensions[_ACS_EXTENSION_ID]
        self.assertEqual(cluster2.value, definition2['name'])
        self._check_acs_marking_features(cluster2.meta, definition2)
        self.assertEqual(len(event.attributes), 1)
        attribute = event.attributes[0]
        self.assertEqual(attribute.type, 'ip-dst')
        self.assertEqual(attribute.uuid, ip_address.id.split('--')[1])
        self.assertEqual(attribute.value, ip_address.value)

    def test_stix21_bundle_with_analyst_data(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_analyst_data()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        (_, grouping, attr_indicator, attr_opinion, _, ip_address, attr_note,
         obj_indicator, obj_opinion, obj_note, grouping_note) = bundle.objects
        self._check_misp_event_features_from_grouping(event, grouping)
        attribute1, attribute2 = event.attributes
        self.assertEqual(attribute1.uuid, attr_indicator.id.split('--')[1])
        self._check_misp_opinion(attribute1.opinions[0], attr_opinion)
        self.assertEqual(attribute2.uuid, ip_address.id.split('--')[1])
        self._check_misp_note(attribute2.notes[0], attr_note)
        file_object = event.objects[0]
        self.assertEqual(file_object.uuid, obj_indicator.id.split('--')[1])
        self._check_misp_note(file_object.notes[0], obj_note)
        self._check_misp_opinion(file_object.opinions[0], obj_opinion)
        self._check_misp_note(event.notes[0], grouping_note)

    def test_stix21_bundle_with_event_title_and_producer(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_without_grouping()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle(
            title='Malicious IP addresses report',
            producer='MISP Project'
        )
        event = self.parser.misp_event
        self.assertEqual(event.info, f'{self.parser.event_title}')
        self.assertEqual(
            event.tags[0]['name'],
            f'misp-galaxy:producer="{self.parser.producer}"'
        )

    def test_stix21_bundle_with_grouping_description(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_grouping_description()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, indicator = bundle.objects
        self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(event.attributes[0].uuid, indicator.id.split('--')[1])
        event_report = event.event_reports[0]
        self.assertEqual(
            event_report.uuid, uuid5(UUIDv4, f'description - {grouping.id}')
        )
        self.assertEqual(event_report.content, grouping.description)
        self.assertEqual(event_report.name, 'STIX 2.1 grouping description')
        self.assertEqual(event_report.timestamp, grouping.modified)

    def test_stix21_bundle_with_unreferenced_objects(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_unreferenced_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        (_, indicator1, grouping, indicator2, ip1, ip2, ip3, malware1,
         malware2, marking1, marking2, _) = bundle.objects
        self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(event.attributes), 5)
        attribute1, attribute2, *attributes = event.attributes
        self._assert_multiple_equal(attribute1.type, attribute2.type, 'ip-dst')
        self.assertEqual(attribute1.uuid, indicator2.id.split('--')[1])
        self.assertEqual(attribute1.value, indicator2.pattern.split(' = ')[1].strip("']"))
        self.assertEqual(len(attribute1.galaxies), 2)
        extension_definition = marking1.extensions[_ACS_EXTENSION_ID]
        names = ('ACS Marking', 'Malware')
        for galaxy, name, stix_object in zip(attribute1.galaxies, names, (extension_definition, malware2)):
            self.assertEqual(galaxy.name, f'STIX 2.1 {name}')
            self.assertEqual(galaxy.clusters[0].value, stix_object['name'])
        self.assertEqual(len(attribute1.tags), 5)
        attribute_tags = tuple(tag.name for tag in attribute1.tags)
        for access_privilege in extension_definition['access_privilege']:
            tag = f'acs-marking:privilege_action="{access_privilege["privilege_action"]}"'
            self.assertIn(tag, attribute_tags)
        control_set = extension_definition['control_set']
        self.assertIn(
            f'acs-marking:classification="{control_set["classification"]}"',
            attribute_tags
        )
        self.assertIn(
            f'acs-marking:formal_determination="{control_set["formal_determination"][0]}"',
            attribute_tags
        )
        for attribute, indicator in zip((attribute1, attribute2), (indicator2, indicator1)):
            self.assertEqual(attribute.uuid, indicator.id.split('--')[1])
            self.assertEqual(attribute.value, indicator.pattern.split(' = ')[1].strip("']"))
        for attribute, observable in zip(attributes, (ip1, ip3, ip2)):
            self.assertEqual(attribute.type, 'ip-dst')
            self.assertEqual(attribute.uuid, observable.id.split('--')[1])
            self.assertEqual(attribute.value, observable.value)
        extension_definition = marking2.extensions[_ACS_EXTENSION_ID]
        for galaxy, name, stix_object in zip(event.galaxies, names, (extension_definition, malware1)):
            self.assertEqual(galaxy.name, f'STIX 2.1 {name}')
            self.assertEqual(galaxy.clusters[0].value, stix_object['name'])
        event_tags = tuple(
            tag.name for tag in event.tags
            if tag.name != 'misp-galaxy:producer="MISP-Project"'
        )
        self.assertEqual(len(event_tags), 4)
        control_set = extension_definition['control_set']
        self.assertIn(
            f'acs-marking:classification="{control_set["classification"]}"',
            event_tags
        )
        for entity in control_set['entity']:
            self.assertIn(f'acs-marking:entity="{entity}"', event_tags)

    ############################################################################
    #                        MISP GALAXIES IMPORT TESTS                        #
    ############################################################################

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
        self.assertEqual(meta['synonyms'], event_ap.aliases)
        self.assertEqual(len(event.attributes), 1)
        attribute = event.attributes[0]
        self.assertEqual(attribute.uuid, indicator.id.split('--')[1])
        meta = self._check_galaxy_features(attribute.galaxies, attribute_ap)
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
        self.assertEqual(meta['synonyms'], event_campaign.aliases)
        self.assertEqual(meta['objective'], event_campaign.objective)
        self.assertEqual(len(event.attributes), 1)
        attribute = event.attributes[0]
        self.assertEqual(attribute.uuid, indicator.id.split('--')[1])
        self._check_galaxy_features(attribute.galaxies, attribute_campaign)

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
        self.assertEqual(meta['goals'], event_is.goals)
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
        country_meta = self._check_galaxy_features(
            event.galaxies, event_location
        )
        self.assertEqual(country_meta['country'], event_location.country)
        self.assertEqual(country_meta['region'], event_location.region)
        self.assertEqual(len(event.attributes), 1)
        attribute = event.attributes[0]
        self.assertEqual(attribute.uuid, indicator.id.split('--')[1])
        region_meta = self._check_galaxy_features(
            attribute.galaxies, attribute_location
        )
        self.assertEqual(
            region_meta['administrative_area'],
            attribute_location.administrative_area
        )
        self.assertEqual(region_meta['country'], attribute_location.country)

    def test_stix21_bundle_with_malware_galaxy(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_malware_galaxy()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, event_malware, indicator, attribute_malware, _ = bundle.objects
        self._check_misp_event_features_from_grouping(event, grouping)
        meta = self._check_galaxy_features(event.galaxies, event_malware)
        self.assertEqual(meta['synonyms'], event_malware.aliases)
        self.assertEqual(
            meta['architecture_execution_envs'],
            event_malware.architecture_execution_envs
        )
        self.assertEqual(meta['capabilities'], event_malware.capabilities)
        self.assertEqual(
            meta['implementation_languages'],
            event_malware.implementation_languages
        )
        self.assertEqual(meta['is_family'], event_malware.is_family)
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
        self.assertEqual(meta['tool_version'], attribute_tool.tool_version)

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

    ############################################################################
    #                    OBSERVED DATA OBJECTS IMPORT TESTS                    #
    ############################################################################

    def _check_archive_file_object(self, misp_object, observed_data, observable_object):
        self.assertEqual(misp_object.name, 'file')
        self.assertEqual(misp_object.uuid, observable_object.id.split('--')[1])
        self.assertEqual(misp_object.timestamp, observed_data.modified)
        comment = observable_object.extensions['archive-ext'].comment
        self.assertEqual(
            misp_object.comment,
            f'{comment} - Observed Data ID: {observed_data.id}'
        )
        self._check_archive_file_fields(misp_object, observable_object)

    def _check_artifact_object(self, misp_object, observed_data, artifact):
        self.assertEqual(misp_object.name, 'artifact')
        self._check_misp_object_fields(misp_object, observed_data, artifact.id)
        self._check_artifact_fields(misp_object, artifact)

    def _check_as_attribute(self, attribute, observed_data, autonomous_system):
        self._check_misp_object_fields(attribute, observed_data, autonomous_system.id)
        self.assertEqual(attribute.type, 'AS')
        self.assertEqual(attribute.value, f'AS{autonomous_system.number}')

    def _check_as_object(self, misp_object, observed_data, autonomous_system):
        self.assertEqual(misp_object.name, 'asn')
        self._check_misp_object_fields(misp_object, observed_data, autonomous_system.id)
        self._check_as_fields(misp_object, autonomous_system)

    def _check_content_ref_object(self, misp_object, observed_data, artifact):
        self.assertEqual(misp_object.name, 'artifact')
        self._check_misp_object_fields(misp_object, observed_data, artifact.id)
        self._check_content_ref_fields(misp_object, artifact)

    def _check_directory_object(self, misp_object, observed_data, directory):
        self.assertEqual(misp_object.name, 'directory')
        self._check_misp_object_fields(misp_object, observed_data, directory.id)
        atime, ctime, mtime = self._check_directory_fields(
            misp_object, directory, directory.id
        )
        self.assertEqual(atime, directory.atime)
        self.assertEqual(ctime, directory.ctime)
        self.assertEqual(mtime, directory.mtime)

    def _check_email_address_attribute(self, observed_data, address, email_address):
        self._check_misp_object_fields(address, observed_data, email_address.id)
        self.assertEqual(address.type, 'email')
        self.assertEqual(address.value, email_address.value)

    def _check_email_address_attribute_with_display_name(
            self, observed_data, address, display_name, email_address):
        self._check_misp_object_fields(
            address, observed_data,
            f'{email_address.id} - email - {email_address.value}',
            email_address.id, multiple=True
        )
        self.assertEqual(address.type, 'email')
        self.assertEqual(address.value, email_address.value)
        self._check_misp_object_fields(
            display_name, observed_data,
            f'{email_address.id} - email-dst-display-name - {email_address.display_name}',
            email_address.id, multiple=True
        )
        self.assertEqual(display_name.type, 'email-dst-display-name')
        self.assertEqual(display_name.value, email_address.display_name)

    def _check_email_artifact_object(self, misp_object, observed_data, artifact):
        self.assertEqual(misp_object.name, 'artifact')
        self._check_misp_object_fields(misp_object, observed_data, artifact.id)
        self._check_email_artifact_object_fields(misp_object, artifact)

    def _check_email_file_object(self, misp_object, observed_data, _file):
        self.assertEqual(misp_object.name, 'file')
        self._check_misp_object_fields(misp_object, observed_data, _file.id)
        self._check_email_file_object_fields(misp_object, _file)

    def _check_email_object(self, misp_object, observed_data, email_message,
                            from_address, to_address, cc_address):
        self.assertEqual(misp_object.name, 'email')
        message_id = email_message.id
        self._check_misp_object_fields(misp_object, observed_data, message_id)
        self._check_email_object_fields(
            misp_object, email_message, from_address, to_address, cc_address,
            message_id, f'{message_id} - {from_address.id}',
            f'{message_id} - {to_address.id}', f'{message_id} - {cc_address.id}'
        )

    def _check_file_and_pe_objects(self, observed_data, observable_object,
                                   file_object, pe_object, *sections):
        self.assertEqual(file_object.name, 'file')
        self._check_misp_object_fields(file_object, observed_data, observable_object.id)
        self._check_file_with_pe_fields(file_object, observable_object)
        self.assertEqual(len(file_object.references), 1)
        file_reference = file_object.references[0]
        self.assertEqual(file_reference.referenced_uuid, pe_object.uuid)
        self.assertEqual(file_reference.relationship_type, 'includes')
        self.assertEqual(pe_object.name, 'pe')
        object_id = f'{observable_object.id} - windows-pebinary-ext'
        self._check_misp_object_fields(
            pe_object, observed_data, object_id, multiple=True
        )
        extension = observable_object.extensions['windows-pebinary-ext']
        self._check_pe_fields(pe_object, extension, object_id)
        self.assertEqual(len(pe_object.references), len(sections))
        for reference, section in zip(pe_object.references, sections):
            self.assertEqual(reference.referenced_uuid, section.uuid)
            self.assertEqual(reference.relationship_type, 'includes')
        for index, section in enumerate(sections):
            self.assertEqual(section.name, 'pe-section')
            section_id = f'{object_id} - sections - {index}'
            self._check_misp_object_fields(
                section, observed_data, section_id, multiple=True
            )
            self._check_pe_section_fields(
                section, extension.sections[index], section_id
            )

    def _check_file_object(self, misp_object, observed_data, observable_object, *object_ids):
        self.assertEqual(misp_object.name, 'file')
        self._check_misp_object_fields(
            misp_object, observed_data, observable_object.id, *object_ids
        )
        self._check_file_fields(misp_object, observable_object)

    def _check_generic_attribute(
            self, observed_data, observable_object, attribute,
            attribute_type, feature='value'):
        self._check_misp_object_fields(attribute, observed_data, observable_object.id)
        self.assertEqual(attribute.type, attribute_type)
        self.assertEqual(attribute.value, getattr(observable_object, feature))

    def _check_misp_object_fields(self, misp_object, observed_data, object_id,
                                  *additional_ids, multiple=False):
        if multiple:
            self.assertEqual(misp_object.uuid, uuid5(UUIDv4, object_id))
        else:
            self.assertEqual(misp_object.uuid, object_id.split('--')[1])
        comments = (
            f'Observed Data ID: {additional_id}'
            if additional_id.startswith('observed-data--') else
            f'Observable object ID: {additional_id}'
            for additional_id in additional_ids
        )
        self.assertEqual(
            misp_object.comment,
            f"Observed Data ID: {f' - '.join((observed_data.id, *comments))}"
        )
        if not (observed_data.modified == observed_data.first_observed == observed_data.last_observed):
            self.assertEqual(misp_object.first_seen, observed_data.first_observed)
            self.assertEqual(misp_object.last_seen, observed_data.last_observed)
        self.assertEqual(misp_object.timestamp, observed_data.modified)

    def _check_network_traffic_fields(self, attributes, network_traffic, src_ip, dst_ip):
        src_port, dst_port, src_return, dst_return, *protocols, ip_src, ip_dst = attributes
        self.assertEqual(src_port.type, 'port')
        self.assertEqual(src_port.object_relation, 'src_port')
        self.assertEqual(src_port.value, network_traffic.src_port)
        self.assertEqual(
            src_port.uuid,
            uuid5(UUIDv4, f'{network_traffic.id} - src_port - {src_port.value}')
        )
        self.assertEqual(dst_port.type, 'port')
        self.assertEqual(dst_port.object_relation, 'dst_port')
        self.assertEqual(dst_port.value, network_traffic.dst_port)
        self.assertEqual(
            dst_port.uuid,
            uuid5(UUIDv4, f'{network_traffic.id} - dst_port - {dst_port.value}')
        )
        for index, protocol in enumerate(protocols):
            protocol_value = network_traffic.protocols[index].upper()
            self.assertEqual(protocol.type, 'text')
            self.assertEqual(protocol.object_relation, 'protocol')
            self.assertEqual(protocol.value, protocol_value)
            self.assertEqual(
                protocol.uuid,
                uuid5(
                    UUIDv4,
                    f'{network_traffic.id} - protocol - {protocol_value}'
                )
            )
        self.assertEqual(ip_src.type, 'ip-src')
        self.assertEqual(ip_src.object_relation, 'src_ip')
        self.assertEqual(ip_src.value, src_ip.value)
        self.assertEqual(
            ip_src.uuid,
            uuid5(
                UUIDv4,
                f'{network_traffic.id} - {src_ip.id} - src_ip - {src_ip.value}'
            )
        )
        self.assertEqual(ip_dst.type, 'ip-dst')
        self.assertEqual(ip_dst.object_relation, 'dst_ip')
        self.assertEqual(ip_dst.value, dst_ip.value)
        self.assertEqual(
            ip_dst.uuid,
            uuid5(
                UUIDv4,
                f'{network_traffic.id} - {dst_ip.id} - dst_ip - {dst_ip.value}'
            )
        )
        return src_return, dst_return

    def _check_network_traffic_object_with_packet_counts(
            self, misp_object, obbserved_data, network_traffic,
            src_ip, dst_ip, attributes_count):
        self.assertEqual(misp_object.name, 'network-traffic')
        self._check_misp_object_fields(
            misp_object, obbserved_data, network_traffic.id
        )
        self._check_network_traffic_packet_counts(
            misp_object, network_traffic, src_ip, dst_ip, attributes_count
        )

    def _check_network_traffic_object_with_packet_sizes(
            self, misp_object, observed_data, network_traffic,
            src_ip, dst_ip, attributes_count):
        self.assertEqual(misp_object.name, 'network-traffic')
        self._check_misp_object_fields(
            misp_object, observed_data, network_traffic.id
        )
        self._check_network_traffic_packet_sizes(
            misp_object, network_traffic, src_ip, dst_ip, attributes_count
        )

    def _check_network_traffic_packet_counts(self, misp_object, network_traffic,
                                             src_ip, dst_ip, attributes_count):
        attributes = misp_object.attributes
        self.assertEqual(len(attributes), attributes_count)
        src_packets, dst_packets = self._check_network_traffic_fields(
            attributes, network_traffic, src_ip, dst_ip
        )
        self.assertEqual(src_packets.type, 'counter')
        self.assertEqual(src_packets.object_relation, 'src_packets')
        self.assertEqual(src_packets.value, network_traffic.src_packets)
        self.assertEqual(
            src_packets.uuid,
            uuid5(
                UUIDv4,
                f'{network_traffic.id} - src_packets - {src_packets.value}'
            )
        )
        self.assertEqual(dst_packets.type, 'counter')
        self.assertEqual(dst_packets.object_relation, 'dst_packets')
        self.assertEqual(dst_packets.value, network_traffic.dst_packets)
        self.assertEqual(
            dst_packets.uuid,
            uuid5(
                UUIDv4,
                f'{network_traffic.id} - dst_packets - {dst_packets.value}'
            )
        )

    def _check_network_traffic_packet_sizes(self, misp_object, network_traffic,
                                            src_ip, dst_ip, attributes_count):
        attributes = misp_object.attributes
        self.assertEqual(len(attributes), attributes_count)
        src_bytes, dst_bytes = self._check_network_traffic_fields(
            attributes, network_traffic, src_ip, dst_ip
        )
        self.assertEqual(src_bytes.type, 'size-in-bytes')
        self.assertEqual(src_bytes.object_relation, 'src_byte_count')
        self.assertEqual(src_bytes.value, network_traffic.src_byte_count)
        self.assertEqual(
            src_bytes.uuid,
            uuid5(
                UUIDv4,
                f'{network_traffic.id} - src_byte_count - {src_bytes.value}'
            )
        )
        self.assertEqual(dst_bytes.type, 'size-in-bytes')
        self.assertEqual(dst_bytes.object_relation, 'dst_byte_count')
        self.assertEqual(dst_bytes.value, network_traffic.dst_byte_count)
        self.assertEqual(
            dst_bytes.uuid,
            uuid5(
                UUIDv4,
                f'{network_traffic.id} - dst_byte_count - {dst_bytes.value}'
            )
        )

    def _check_registry_key_object(
            self, misp_object, observed_data, registry_key, *values):
        self.assertEqual(misp_object.name, 'registry-key')
        self._check_misp_object_fields(misp_object, observed_data, registry_key.id)
        if values:
            modified = self._check_registry_key_fields(
                misp_object, registry_key
            )
            for index, value_object in enumerate(values):
                object_id = f'{registry_key.id} - values - {index}'
                self.assertEqual(value_object.name, 'registry-key-value')
                self._check_misp_object_fields(
                    value_object, observed_data, object_id, multiple=True
                )
                self._check_registry_key_value_fields(
                    value_object, registry_key['values'][index], object_id
                )
        else:
            modified = self._check_registry_key_with_values_fields(
                misp_object, registry_key
            )
        self.assertEqual(modified.value, registry_key.modified_time)

    def _check_registry_key_references(self, creator_user, regkey1, regkey2, *value_uuids):
        self.assertEqual(len(creator_user.references), 2)
        reference1, reference2 = creator_user.references
        self.assertEqual(reference1.referenced_uuid, regkey1.uuid)
        self.assertEqual(reference2.referenced_uuid, regkey2.uuid)
        self._assert_multiple_equal(
            reference1.relationship_type,
            reference2.relationship_type,
            'creates'
        )
        for reference, value_uuid in zip(regkey1.references, value_uuids):
            self.assertEqual(reference.referenced_uuid, value_uuid)
            self.assertEqual(reference.relationship_type, 'contains')

    def _check_software_object(self, misp_object, observed_data, software):
        self.assertEqual(misp_object.name, 'software')
        self._check_misp_object_fields(misp_object, observed_data, software.id)
        self._check_software_fields(misp_object, software)

    def _check_user_account_object(self, misp_object, user_account):
        self.assertEqual(len(misp_object.attributes), 11)
        self._check_user_account_fields(
            misp_object.attributes[:7], user_account
        )
        self._check_user_account_timeline_fields(
            misp_object.attributes[7:-1], user_account
        )
        password_last_changed = misp_object.attributes[-1]
        self.assertEqual(
            password_last_changed.object_relation, 'password_last_changed'
        )
        self.assertEqual(
            password_last_changed.value, user_account.credential_last_changed
        )
        self.assertEqual(
            password_last_changed.uuid,
            uuid5(
                UUIDv4,
                f'{user_account.id} - password_last_changed'
                f' - {password_last_changed.value}'
            )
        )

    def _check_wrapped_observable_objects(self, stix_objects, misp_content):
        (artifact1, artifact2, artifact3,
         AS1, AS2, AS3, AS4,
         directory1, directory2, directory3,
         domain1, domain2, domain3,
         domain4, ipv4_1, ipv6_1, domain5,
         email_addr1, email_addr2, email_addr3, email_addr4,
         email_message, email_addr5, email_addr6, email_addr7, artifact4, file1,
         file2, directory4, artifact5, file3, file4,
         md5Indicator1, fileIndicator1, sha1Indicator, artifactIndicator,
         ipIndicator1, emailAddrIndicator, sha256Indicator, fileIndicator2,
         md5Indicator2, ipIndicator2, ipIndicator3, processIndicator,
         ipv4_2, ipv6_2, ipv4_3,
         mac1, mac2, mac3,
         mutex1, mutex2, mutex3,
         ipv4_4, ipv4_5, ipv4_6, nt1, nt2, ipv4_7, ipv4_8, nt3, nt4, artifact6,
         process1, process2, file5, process3, file6, process4,
         regkey1, regkey2, regkey3, user1,
         software1, software2, software3,
         url1, url2, url3,
         user_account2, user_account3, user_account4,
         x509_cert1, x509_cert2, x509_cert3) = stix_objects
        (ntObj1, ntObj2, ntObj3, artifactObj1, ntObj4,
         emailObj, artifactObj2, fileObj1,
         processObj1, fileObj2, processObj2, procOrFile1, procOrFile2, processObj4,
         fileObj4, directoryObj1, artifactObj3, fileObj5, fileObj6, *PEs,
         regkeyObj1, regkeyObj2, valueObj1, valueObj2, userObj1, regkeyObj3,
         artifactObj4, artifactObj5, artifactObj6,
         asn1, asn2,
         directoryObj2, directoryObj3, directoryObj4,
         domainIpObj1, domainIpObj2,
         softwareObj1, softwareObj2, softwareObj3,
         userObj2, userObj3, userObj4,
         x509Obj1, x509Obj2, x509Obj3,
         asAttr1, asAttr2,
         domainAttr1, domainAttr2, domainAttr3,
         emailAttr1, dnAttr1, emailAttr2, emailAttr3, dnAttr2, emailAttr4,
         ipAttr1, ipAttr2, ipAttr3,
         macAttr1, macAttr2, macAttr3,
         mutexAttr1, mutexAttr2, mutexAttr3,
         urlAttr1, urlAttr2, urlAttr3) = misp_content

        ########################################################################
        #                       NETWORK TRAFFIC OBJECTS.                       #
        ########################################################################
        self._assert_multiple_equal(
            ntObj1.name, ntObj2.name, ntObj3.name, ntObj4.name,
            'network-traffic'
        )
        self.assertEqual(ntObj1.uuid, nt1.id.split('--')[1])
        self._check_wrapped_network_traffic_object(
            ntObj1, nt1.id, ipv4_4.id, ipv4_5.id, 8,
            (ntObj2.uuid, 'encapsulates')
        )
        self.assertEqual(ntObj2.uuid, nt2.id.split('--')[1])
        self._check_wrapped_network_traffic_object(
            ntObj2, nt2.id, ipv4_4.id, ipv4_6.id, 9,
            (ntObj1.uuid, 'encapsulated-by')
        )
        self.assertEqual(ntObj3.uuid, nt3.id.split('--')[1])
        self._check_wrapped_network_traffic_object(
            ntObj3, nt3.id, ipv4_5.id, ipv4_7.id, 9,
            (artifactObj1.uuid, 'source-sent'), (ntObj4.uuid, 'encapsulates'),
            dst_indicator_id=ipIndicator2.id
        )
        self.assertEqual(ntObj4.uuid, nt4.id.split('--')[1])
        self._check_wrapped_network_traffic_object(
            ntObj4, nt4.id, ipv4_7.id, ipv4_8.id, 10,
            (artifactObj1.uuid, 'destination-sent'),
            (ntObj3.uuid, 'encapsulated-by'),
            src_indicator_id=ipIndicator2.id, dst_indicator_id=ipIndicator3.id
        )
        self.assertEqual(artifactObj1.name, 'artifact')
        self.assertEqual(artifactObj1.uuid, artifact6.id.split('--')[1])
        md5, sha256, url = artifactObj1.attributes
        self._check_wrapped_attribute(
            md5.uuid, f'{fileIndicator1.id} - {artifact6.id}',
            md5.object_relation, md5.value
        )
        self._check_wrapped_attribute(
            sha256.uuid, f'{fileIndicator1.id} - {artifact6.id}',
            sha256.object_relation, sha256.value
        )
        self._check_wrapped_attribute(
            url.uuid, artifact6.id, url.object_relation, url.value
        )

        ########################################################################
        #                          EMAIL MESSAGE OBJECT.                       #
        ########################################################################
        self.assertEqual(emailObj.name, 'email')
        self.assertEqual(emailObj.uuid, email_message.id.split('--')[1])
        self._check_wrapped_email_object(
            emailObj, email_message.id, ipIndicator1.id, email_addr5.id,
            email_addr6.id, email_addr7.id, artifactObj2.uuid, fileObj1.uuid
        )
        self.assertEqual(artifactObj2.name, 'artifact')
        self.assertEqual(artifactObj2.uuid, artifact4.id.split('--')[1])
        self.assertEqual(len(artifactObj2.attributes), 3)
        payload_bin, *artifactObj2_attributes = artifactObj2.attributes
        payload_data = self._get_data_value(payload_bin.data)
        self.assertEqual(
            payload_bin.uuid,
            uuid5(UUIDv4, f'{artifact4.id} - payload_bin - {payload_data}')
        )
        self._check_wrapped_attributes(artifact4.id, *artifactObj2_attributes)
        self.assertEqual(fileObj1.name, 'file')
        self.assertEqual(fileObj1.uuid, file1.id.split('--')[1])
        sha256, filename = fileObj1.attributes
        self._check_wrapped_attribute(
            sha256.uuid, f'{sha256Indicator.id} - {file1.id}',
            sha256.object_relation, sha256.value
        )
        self._check_wrapped_attribute(
            filename.uuid, file1.id, filename.object_relation, filename.value
        )

        ########################################################################
        #                            PROCESS OBJECTS.                          #
        ########################################################################
        self._assert_multiple_equal(
            processObj1.name, processObj2.name, processObj4.name, 'process'
        )
        self.assertEqual(fileObj2.name, 'file')
        self.assertEqual(processObj1.uuid, process1.id.split('--')[1])
        self.assertEqual(len(processObj1.attributes), 3)
        self._check_wrapped_attributes(process1.id, *processObj1.attributes)
        self.assertEqual(len(processObj1.references), 3)
        file_ref, parent_ref, child_ref = processObj1.references
        self.assertEqual(file_ref.relationship_type, 'executes')
        self.assertEqual(parent_ref.relationship_type, 'child-of')
        self.assertEqual(child_ref.relationship_type, 'parent-of')
        self.assertEqual(child_ref.referenced_uuid, process3.id.split('--')[1])
        self._assert_multiple_equal(
            file_ref.referenced_uuid, fileObj2.uuid, file6.id.split('--')[1]
        )
        self.assertEqual(len(fileObj2.attributes), 4)
        self._check_wrapped_attributes(file6.id, *fileObj2.attributes)
        self._assert_multiple_equal(
            parent_ref.referenced_uuid, processObj2.uuid,
            process2.id.split('--')[1]
        )
        self.assertEqual(len(processObj2.attributes), 6)
        command_line, *procObj2_attributes = processObj2.attributes
        self._check_wrapped_attribute(
            command_line.uuid, f'{processIndicator.id} - {process2.id}',
            command_line.object_relation, command_line.value
        )
        self._check_wrapped_attributes(process2.id, *procObj2_attributes)
        self.assertEqual(len(processObj2.references), 1)
        binary_ref = processObj2.references[0]
        self.assertEqual(binary_ref.relationship_type, 'executes')
        file5_id = file5.id.split('--')[1]
        self.assertEqual(binary_ref.referenced_uuid, file5_id)
        process3_id = process3.id.split('--')[1]
        for misp_object in (procOrFile1, procOrFile2):
            if misp_object.uuid == file5_id:
                self.assertEqual(misp_object.name, 'file')
                self.assertEqual(len(misp_object.attributes), 4)
                self._check_wrapped_attributes(
                    file5.id, *misp_object.attributes
                )
                continue
            if misp_object.uuid == process3_id:
                self.assertEqual(misp_object.name, 'process')
                self.assertEqual(len(misp_object.attributes), 2)
                self._check_wrapped_attributes(
                    process3.id, *misp_object.attributes
                )
                continue
            self.fail(f'Unexpected process of file MISP Object with id {misp_object.uuid}')
        self.assertEqual(processObj4.uuid, process4.id.split('--')[1])
        self.assertEqual(len(processObj4.attributes), 3)
        self._check_wrapped_attributes(process4.id, *processObj4.attributes)

        ########################################################################
        #                             FILE OBJECTS                             #
        ########################################################################
        self._assert_multiple_equal(
            fileObj4.name, fileObj5.name, fileObj6.name, 'file'
        )
        self.assertEqual(len(fileObj4.attributes), 6)
        self._check_wrapped_attributes(file2.id, *fileObj4.attributes)
        self.assertEqual(len(fileObj4.references), 1)
        parent_ref = fileObj4.references[0]
        self.assertEqual(parent_ref.relationship_type, 'contained-in')
        self.assertEqual(directoryObj1.name, 'directory')
        self.assertEqual(len(directoryObj1.attributes), 1)
        self._check_wrapped_attributes(directory4.id, *directoryObj1.attributes)
        self.assertEqual(artifactObj3.name, 'artifact')
        self.assertEqual(artifactObj3.uuid, artifact5.id.split('--')[1])
        self.assertEqual(len(artifactObj3.attributes), 4)
        payload_bin, *artifactObj3_attributes = artifactObj3.attributes
        payload_data = self._get_data_value(payload_bin.data)
        self.assertEqual(
            payload_bin.uuid,
            uuid5(UUIDv4, f'{artifact5.id} - payload_bin - {payload_data}')
        )
        self._check_wrapped_attributes(artifact5.id, *artifactObj3_attributes)
        self.assertEqual(len(artifactObj3.references), 1)
        content_ref = artifactObj3.references[0]
        self.assertEqual(content_ref.relationship_type, 'content-of')
        self.assertEqual(fileObj5.uuid, file3.id.split('--')[1])
        self.assertEqual(len(fileObj5.attributes), 3)
        self._check_wrapped_attributes(file3.id, *fileObj5.attributes)
        self.assertEqual(len(fileObj5.references), 2)
        contains_file_ref, contains_directory_ref = fileObj5.references
        self._assert_multiple_equal(
            contains_file_ref.relationship_type,
            contains_directory_ref.relationship_type,
            'contains'
        )
        self._assert_multiple_equal(
            content_ref.referenced_uuid, contains_file_ref.referenced_uuid,
            fileObj4.uuid, file2.id.split('--')[1]
        )
        self._assert_multiple_equal(
            parent_ref.referenced_uuid, contains_directory_ref.referenced_uuid,
            directoryObj1.uuid, directory4.id.split('--')[1]
        )
        self.assertEqual(fileObj6.uuid, file4.id.split('--')[1])
        self.assertEqual(len(fileObj6.attributes), 7)
        md5, sha1, sha256, *fileObj6_attributes = fileObj6.attributes
        self._check_wrapped_attribute(
            md5.uuid, f'{fileIndicator2.id} - {file4.id}',
            md5.object_relation, md5.value
        )
        self._check_wrapped_attribute(
            sha1.uuid, f'{fileIndicator2.id} - {file4.id}',
            sha1.object_relation, sha1.value
        )
        self._check_wrapped_attribute(
            sha256.uuid, f'{fileIndicator2.id} - {file4.id}',
            sha256.object_relation, sha256.value
        )
        self._check_wrapped_attributes(file4.id, *fileObj6_attributes)
        self.assertEqual(len(fileObj6.references), 1)
        pe_ref = fileObj6.references[0]
        self.assertEqual(pe_ref.relationship_type, 'includes')
        pe_object, *section_objects = PEs
        self.assertEqual(pe_object.name, 'pe')
        pe_id = f'{file4.id} - windows-pebinary-ext'
        self._assert_multiple_equal(
            pe_ref.referenced_uuid, pe_object.uuid, uuid5(UUIDv4, pe_id)
        )
        self.assertEqual(len(pe_object.attributes), 3)
        self._check_wrapped_attributes(pe_id, *pe_object.attributes)
        self.assertEqual(len(pe_object.references), len(section_objects))
        for section_ref, section in zip(pe_object.references, enumerate(section_objects)):
            index, section_object = section
            object_id = f'{pe_id} - sections - {index}'
            self.assertEqual(section_ref.relationship_type, 'includes')
            self._assert_multiple_equal(
                section_ref.referenced_uuid, section_object.uuid,
                uuid5(UUIDv4, f'{pe_id} - sections - {index}')
            )
            self.assertEqual(section_object.name, 'pe-section')
            self.assertEqual(len(section_object.attributes), 4)
            if index == 1:
                *section_attributes, md5 = section_object.attributes
                self._check_wrapped_attributes(object_id, *section_attributes)
                self._check_wrapped_attribute(
                    md5.uuid, f'{md5Indicator2.id} - {object_id}',
                    md5.object_relation, md5.value
                )
            else:
                self._check_wrapped_attributes(
                    f'{pe_id} - sections - {index}', *section_object.attributes
                )

        ########################################################################
        #                         REGISTRY KEY OBJECTS                         #
        ########################################################################
        self._assert_multiple_equal(
            regkeyObj1.name, regkeyObj2.name, regkeyObj3.name, 'registry-key'
        )
        self._assert_multiple_equal(
            valueObj1.name, valueObj2.name, 'registry-key-value'
        )
        self.assertEqual(regkeyObj1.uuid, regkey1.id.split('--')[1])
        self.assertEqual(len(regkeyObj1.attributes), 5)
        self._check_wrapped_attributes(regkey1.id, *regkeyObj1.attributes)
        self.assertEqual(len(regkeyObj2.attributes), 2)
        self._check_wrapped_attributes(regkey2.id, *regkeyObj2.attributes)
        self.assertEqual(len(regkeyObj2.references), 2)
        for value_ref, value in zip(regkeyObj2.references, enumerate((valueObj1, valueObj2))):
            self.assertEqual(value_ref.relationship_type, 'contains')
            index, value_object = value
            value_id = f'{regkey2.id} - values - {index}'
            self._assert_multiple_equal(
                value_ref.referenced_uuid, value_object.uuid,
                uuid5(UUIDv4, value_id)
            )
            self.assertEqual(len(value_object.attributes), 3)
            self._check_wrapped_attributes(value_id, *value_object.attributes)
        self.assertEqual(userObj1.name, 'user-account')
        self.assertEqual(userObj1.uuid, user1.id.split('--')[1])
        self.assertEqual(len(userObj1.attributes), 4)
        self._check_wrapped_attributes(user1.id, *userObj1.attributes)
        self.assertEqual(len(userObj1.references), 2)
        creates1_ref, creates2_ref = userObj1.references
        self._assert_multiple_equal(
            creates1_ref.relationship_type,
            creates2_ref.relationship_type,
            'creates'
        )
        self._assert_multiple_equal(
            creates1_ref.referenced_uuid, regkeyObj2.uuid,
            regkey2.id.split('--')[1]
        )
        self._assert_multiple_equal(
            creates2_ref.referenced_uuid, regkeyObj3.uuid,
            regkey3.id.split('--')[1]
        )
        self.assertEqual(len(regkeyObj3.attributes), 5)
        self._check_wrapped_attributes(regkey3.id, *regkeyObj3.attributes)

        ########################################################################
        #                           ARTIFACT OBJECTS                           #
        ########################################################################
        self._assert_multiple_equal(
            artifactObj4.name, artifactObj5.name, artifactObj6.name, 'artifact'
        )
        self.assertEqual(artifactObj4.uuid, artifact1.id.split('--')[1])
        self.assertEqual(len(artifactObj4.attributes), 6)
        payload_bin, md5, *artifactObj4_attributes = artifactObj4.attributes
        payload_data = self._get_data_value(payload_bin.data)
        self.assertEqual(
            payload_bin.uuid,
            uuid5(UUIDv4, f'{artifact1.id} - payload_bin - {payload_data}')
        )
        self._check_wrapped_attribute(
            md5.uuid, f'{md5Indicator1.id} - {artifact1.id}',
            md5.object_relation, md5.value
        )
        self._check_wrapped_attributes(artifact1.id, *artifactObj4_attributes)
        self.assertEqual(artifactObj5.uuid, artifact2.id.split('--')[1])
        md5, sha256, url = artifactObj5.attributes
        self._check_wrapped_attribute(
            md5.uuid, f'{fileIndicator1.id} - {artifact2.id}',
            md5.object_relation, md5.value
        )
        self._check_wrapped_attribute(
            sha256.uuid, f'{fileIndicator1.id} - {artifact2.id}',
            sha256.object_relation, sha256.value
        )
        self._check_wrapped_attribute(
            url.uuid, artifact2.id, url.object_relation, url.value
        )
        self.assertEqual(artifactObj6.uuid, artifact3.id.split('--')[1])
        self.assertEqual(len(artifactObj6.attributes), 6)
        payload_bin, md5, sha1, sha256, *artifactObj6_attributes = artifactObj6.attributes
        payload_data = self._get_data_value(payload_bin.data)
        self.assertEqual(
            payload_bin.uuid,
            uuid5(UUIDv4, f'{artifact3.id} - payload_bin - {payload_data}')
        )
        self._check_wrapped_attribute(
            sha1.uuid, f'{sha1Indicator.id} - {artifact3.id}',
            sha1.object_relation, sha1.value
        )
        self._check_wrapped_attribute(
            sha256.uuid, f'{artifactIndicator.id} - {artifact3.id}',
            sha256.object_relation, sha256.value
        )
        self._check_wrapped_attributes(artifact3.id, md5, *artifactObj6_attributes)


        ########################################################################
        #                      AUTONOMOUS SYSTEM OBJECTS.                      #
        ########################################################################
        self._assert_multiple_equal(asn1.name, asn2.name, 'asn')
        self.assertEqual(asn1.uuid, AS1.id.split('--')[1])
        asAttribute1, asNameAttribute1 = asn1.attributes
        self._check_wrapped_attribute(
            asAttribute1.uuid, AS1.id,
            asAttribute1.object_relation, asAttribute1.value.lstrip('AS')
        )
        self._check_wrapped_attribute(
            asNameAttribute1.uuid, AS1.id,
            asNameAttribute1.object_relation, asNameAttribute1.value
        )
        self.assertEqual(asn2.uuid, AS3.id.split('--')[1])
        asAttribute2, asNameAttribute2 = asn2.attributes
        self._check_wrapped_attribute(
            asAttribute2.uuid, AS3.id,
            asAttribute2.object_relation, asAttribute2.value.lstrip('AS')
        )
        self._check_wrapped_attribute(
            asNameAttribute2.uuid, AS3.id,
            asNameAttribute2.object_relation, asNameAttribute2.value
        )

        ########################################################################
        #                          DIRECTORY OBJECTS.                          #
        ########################################################################
        self._assert_multiple_equal(
            directoryObj2.name, directoryObj3.name,
            directoryObj4.name, 'directory'
        )
        self.assertEqual(directoryObj2.uuid, directory1.id.split('--')[1])
        self.assertEqual(len(directoryObj2.attributes), 5)
        self._check_wrapped_attributes(directory1.id, *directoryObj2.attributes)
        self.assertEqual(directoryObj3.uuid, directory2.id.split('--')[1])
        self.assertEqual(len(directoryObj3.attributes), 5)
        self._check_wrapped_attributes(directory2.id, *directoryObj3.attributes)
        self.assertEqual(directoryObj4.uuid, directory3.id.split('--')[1])
        self.assertEqual(len(directoryObj4.attributes), 5)
        self._check_wrapped_attributes(directory3.id, *directoryObj4.attributes)

        ########################################################################
        #                          DOMAIN-IP OBJECTS.                          #
        ########################################################################
        self._assert_multiple_equal(
            domainIpObj1.name, domainIpObj2.name, 'domain-ip'
        )
        self.assertEqual(domainIpObj1.uuid, domain4.id.split('--')[1])
        domainAttribute1, ipAttribute1, ipAttribute2 = domainIpObj1.attributes
        self.assertEqual(
            domainAttribute1.uuid,
            uuid5(UUIDv4, f'{domain4.id} - domain - {domain4.value}')
        )
        self.assertEqual(
            ipAttribute1.uuid,
            uuid5(
                UUIDv4,
                f'{ipIndicator1.id} - {domain4.id} - '
                f'{ipv4_1.id} - ip - {ipv4_1.value}'
            )
        )
        self.assertEqual(
            ipAttribute2.uuid,
            uuid5(UUIDv4, f'{domain4.id} - {ipv6_1.id} - ip - {ipv6_1.value}')
        )
        self.assertEqual(domainIpObj1.references, [])
        self.assertEqual(domainIpObj2.uuid, domain5.id.split('--')[1])
        self.assertEqual(len(domainIpObj2.attributes), 1)
        domainAttribute2 = domainIpObj2.attributes[0]
        self.assertEqual(
            domainAttribute2.uuid,
            uuid5(UUIDv4, f'{domain5.id} - domain - {domain5.value}')
        )
        self.assertEqual(len(domainIpObj2.references), 1)
        alias_ref = domainIpObj2.references[0]
        self.assertEqual(alias_ref.relationship_type, 'alias-of')
        self._assert_multiple_equal(
            alias_ref.referenced_uuid, domainIpObj1.uuid
        )

        ########################################################################
        #                           SOFTWARE OBJECTS                           #
        ########################################################################
        self._assert_multiple_equal(
            softwareObj1.name, softwareObj2.name, softwareObj3.name, 'software'
        )
        self.assertEqual(softwareObj1.uuid, software1.id.split('--')[1])
        self.assertEqual(len(softwareObj1.attributes), 4)
        self._check_wrapped_attributes(software1.id, *softwareObj1.attributes)
        self.assertEqual(softwareObj2.uuid, software2.id.split('--')[1])
        self.assertEqual(len(softwareObj2.attributes), 4)
        self._check_wrapped_attributes(software2.id, *softwareObj2.attributes)
        self.assertEqual(softwareObj3.uuid, software3.id.split('--')[1])
        self.assertEqual(len(softwareObj3.attributes), 8)
        self._check_wrapped_attributes(software3.id, *softwareObj3.attributes)

        ########################################################################
        #                         USER-ACCOUNT OBJECTS                         #
        ########################################################################
        self._assert_multiple_equal(
            userObj2.name, userObj3.name, userObj4.name, 'user-account'
        )
        self.assertEqual(userObj2.uuid, user_account2.id.split('--')[1])
        self.assertEqual(len(userObj2.attributes), 11)
        self._check_wrapped_attributes(user_account2.id, *userObj2.attributes)
        self.assertEqual(userObj3.uuid, user_account3.id.split('--')[1])
        self.assertEqual(len(userObj3.attributes), 4)
        self._check_wrapped_attributes(user_account3.id, *userObj3.attributes)
        self.assertEqual(userObj4.uuid, user_account4.id.split('--')[1])
        self.assertEqual(len(userObj4.attributes), 11)
        self._check_wrapped_attributes(user_account4.id, *userObj4.attributes)

        ########################################################################
        #                             X509 OBJECTS                             #
        ########################################################################
        self._assert_multiple_equal(
            x509Obj1.name, x509Obj2.name, x509Obj3.name, 'x509'
        )
        self.assertEqual(x509Obj1.uuid, x509_cert1.id.split('--')[1])
        self.assertEqual(len(x509Obj1.attributes), 14)
        self._check_wrapped_attributes(x509_cert1.id, *x509Obj1.attributes)
        self.assertEqual(x509Obj2.uuid, x509_cert2.id.split('--')[1])
        self.assertEqual(len(x509Obj2.attributes), 14)
        self._check_wrapped_attributes(x509_cert2.id, *x509Obj2.attributes)
        self.assertEqual(x509Obj3.uuid, x509_cert3.id.split('--')[1])
        self.assertEqual(len(x509Obj3.attributes), 14)
        self._check_wrapped_attributes(x509_cert3.id, *x509Obj3.attributes)

        ########################################################################
        #                     AUTONOMOUS SYSTEM ATTRIBUTES                     #
        ########################################################################
        self._assert_multiple_equal(asAttr1.type, asAttr2.type, 'AS')
        self.assertEqual(asAttr1.uuid, AS2.id.split('--')[1])
        self.assertEqual(asAttr2.uuid, AS4.id.split('--')[1])

        ########################################################################
        #                          DOMAIN ATTRIBUTES.                          #
        ########################################################################
        self._assert_multiple_equal(
            domainAttr1.type, domainAttr2.type, domainAttr3.type, 'domain'
        )
        self.assertEqual(domainAttr1.uuid, domain1.id.split('--')[1])
        self.assertEqual(domainAttr2.uuid, domain2.id.split('--')[1])
        self.assertEqual(domainAttr3.uuid, domain3.id.split('--')[1])

        ########################################################################
        #                           EMAIL ATTRIBUTES                           #
        ########################################################################
        self._assert_multiple_equal(
            emailAttr1.type, emailAttr2.type, emailAttr3.type,
            emailAttr4.type, 'email'
        )
        self._assert_multiple_equal(
            dnAttr1.type, dnAttr2.type, 'email-dst-display-name'
        )
        self.assertEqual(
            emailAttr1.uuid,
            uuid5(UUIDv4, f'{email_addr1.id} - email - {email_addr1.value}')
        )
        self.assertEqual(
            dnAttr1.uuid,
            uuid5(
                UUIDv4, ' - '.join(
                    (
                        email_addr1.id, 'email-dst-display-name',
                        email_addr1.display_name
                    )
                )
            )
        )
        self.assertEqual(
            emailAttr2.uuid, uuid5(
                UUIDv4, f'{emailAddrIndicator.id} - {email_addr2.id}'
            )
        )
        self.assertEqual(
            emailAttr3.uuid,
            uuid5(UUIDv4, f'{email_addr3.id} - email - {email_addr3.value}')
        )
        self.assertEqual(
            dnAttr2.uuid,
            uuid5(
                UUIDv4, ' - '.join(
                    (
                        email_addr3.id, 'email-dst-display-name',
                        email_addr3.display_name
                    )
                )
            )
        )
        self.assertEqual(emailAttr4.uuid, email_addr4.id.split('--')[1])

        ########################################################################
        #                            IP ATTRIBUTES.                            #
        ########################################################################
        self._assert_multiple_equal(
            ipAttr1.type, ipAttr2.type, ipAttr3.type, 'ip-dst'
        )
        self.assertEqual(ipAttr1.uuid, ipv4_2.id.split('--')[1])
        self.assertEqual(ipAttr2.uuid, ipv4_3.id.split('--')[1])
        self.assertEqual(ipAttr3.uuid, ipv6_2.id.split('--')[1])

        ########################################################################
        #                            MAC ATTRIBUTES                            #
        ########################################################################
        self._assert_multiple_equal(
            macAttr1.type, macAttr2.type, macAttr3.type, 'mac-address'
        )
        self.assertEqual(macAttr1.uuid, mac1.id.split('--')[1])
        self.assertEqual(macAttr2.uuid, mac2.id.split('--')[1])
        self.assertEqual(macAttr3.uuid, mac3.id.split('--')[1])

        ########################################################################
        #                           MUTEX ATTRIBUTES                           #
        ########################################################################
        self._assert_multiple_equal(
            mutexAttr1.type, mutexAttr2.type, mutexAttr3.type, 'mutex'
        )
        self.assertEqual(mutexAttr1.uuid, mutex1.id.split('--')[1])
        self.assertEqual(mutexAttr2.uuid, mutex2.id.split('--')[1])
        self.assertEqual(mutexAttr3.uuid, mutex3.id.split('--')[1])

        ########################################################################
        #                            URL ATTRIBUTES                            #
        ########################################################################
        self._assert_multiple_equal(
            urlAttr1.type, urlAttr2.type, urlAttr3.type, 'url'
        )
        self.assertEqual(urlAttr1.uuid, url1.id.split('--')[1])
        self.assertEqual(urlAttr2.uuid, url2.id.split('--')[1])
        self.assertEqual(urlAttr3.uuid, url3.id.split('--')[1])

    def _check_x509_object(self, misp_object, observed_data, x509):
        self.assertEqual(misp_object.name, 'x509')
        self._check_misp_object_fields(misp_object, observed_data, x509.id)
        self._check_x509_fields(misp_object, x509)

    def test_stix21_bundle_with_artifact_objects(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_artifact_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, od1, od2, artifact1, artifact2, artifact3 = bundle.objects
        misp_objects = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(misp_objects), 3)
        multiple1, multiple2, single = misp_objects

        self._check_artifact_object(multiple1, od1, artifact1)

        self.assertEqual(multiple2.name, 'artifact')
        self._check_misp_object_fields(multiple2, od1, artifact2.id)
        self._check_artifact_with_url_fields(multiple2, artifact2, artifact2.id)

        self._check_artifact_object(single, od2, artifact3)

    def test_stix21_bundle_with_artifact_observable(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_artifact_observables()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, artifact1, artifact2 = bundle.objects
        misp_objects = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(misp_objects), 2)
        misp_object1, misp_object2 = misp_objects
        self._assert_multiple_equal(misp_object1.name, misp_object2.name, 'artifact')

        self.assertEqual(misp_object1.uuid, artifact1.id.split('--')[1])
        self._check_artifact_with_url_fields(misp_object1, artifact1, artifact1.id)

        self.assertEqual(misp_object2.uuid, artifact2.id.split('--')[1])
        self._check_artifact_fields(misp_object2, artifact2, artifact2.id)

    def test_stix21_bundle_with_as_objects(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_as_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, od1, od2, od3, as1, as2, as3, as4 = bundle.objects
        misp_content = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(misp_content), 4)
        m_object, s_object, m_attribute, s_attribute = misp_content

        self._check_as_object(m_object, od1, as1)
        self._check_as_object(s_object, od2, as3)

        self._check_as_attribute(m_attribute, od1, as2)
        self._check_as_attribute(s_attribute, od3, as4)

    def test_stix21_bundle_with_as_observables(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_as_observables()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, as1, as2 = bundle.objects
        misp_object, attribute = self._check_misp_event_features_from_grouping(event, grouping)

        self.assertEqual(misp_object.name, 'asn')
        self.assertEqual(misp_object.uuid, as1.id.split('--')[1])
        self._check_as_fields(misp_object, as1)

        self.assertEqual(attribute.uuid, as2.id.split('--')[1])
        self.assertEqual(attribute.type, 'AS')
        self.assertEqual(attribute.value, f'AS{as2.number}')

    def test_stix21_bundle_with_directory_objects(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_directory_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, od1, od2, directory1, directory2, directory3 = bundle.objects
        misp_objects = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(misp_objects), 3)
        referenced_directory, directory, single_directory = misp_objects

        self._check_directory_object(referenced_directory, od1, directory2)
        self._check_directory_object(directory, od1, directory1)
        self._check_directory_object(single_directory, od2, directory3)

        reference1 = directory.references[0]
        self._assert_multiple_equal(
            reference1.referenced_uuid,
            referenced_directory.uuid,
            directory2.id.split('--')[1]
        )
        self.assertEqual(reference1.relationship_type, 'contains')

        reference2 = referenced_directory.references[0]
        self._assert_multiple_equal(
            reference2.referenced_uuid,
            single_directory.uuid,
            directory3.id.split('--')[1]
        )
        self.assertEqual(reference2.relationship_type, 'contains')

    def test_stix21_bundle_with_directory_observables(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_directory_observables()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, directory1, directory2 = bundle.objects
        misp_objects = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(misp_objects), 2)
        misp_object1, misp_object2 = misp_objects
        self._assert_multiple_equal(misp_object1.name, misp_object2.name, 'directory')

        self.assertEqual(misp_object1.uuid, directory1.id.split('--')[1])
        self._check_directory_fields(misp_object1, directory1)
        reference = misp_object1.references[0]
        self.assertEqual(reference.relationship_type, 'contains')
        self._assert_multiple_equal(
            reference.referenced_uuid,
            misp_object2.uuid,
            directory2.id.split('--')[1]
        )
        self._check_directory_fields(misp_object2, directory2)

    def test_stix21_bundle_with_domain_attributes(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_domain_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, od1, od2, domain_1, domain_2, domain_3 = bundle.objects
        attributes = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(attributes), 3)
        m_domain1, m_domain2, s_domain = attributes
        self._check_generic_attribute(od1, domain_1, m_domain1, 'domain')
        self._check_generic_attribute(od1, domain_2, m_domain2, 'domain')
        self._check_generic_attribute(od2, domain_3, s_domain, 'domain')

    def test_stix21_bundle_with_domain_observable(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_domain_observable()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, domain = bundle.objects
        attribute = self._check_misp_event_features_from_grouping(event, grouping)[0]
        self.assertEqual(attribute.uuid, domain.id.split('--')[1])
        self.assertEqual(attribute.type, 'domain')
        self.assertEqual(attribute.value, domain.value)

    def test_stix21_bundle_with_domain_ip_objects(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_domain_ip_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, od1, od2, domain1, ipv4, ipv6, domain2 = bundle.objects
        misp_objects = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(misp_objects), 2)
        domain_object, domain_ip_object = misp_objects
        self._assert_multiple_equal(
            domain_object.name, domain_ip_object.name, 'domain-ip'
        )

        self._check_misp_object_fields(domain_object, od1, domain2.id)
        self.assertEqual(len(domain_object.attributes), 1)
        domain_attribute = domain_object.attributes[0]
        self._assert_multiple_equal(
            domain_attribute.type, domain_attribute.object_relation, 'domain'
        )
        self.assertEqual(domain_attribute.value, domain2.value)
        self.assertEqual(
            domain_attribute.uuid,
            uuid5(UUIDv4, f'{domain2.id} - domain - {domain2.value}')
        )

        self.assertEqual(len(domain_object.references), 1)
        reference = domain_object.references[0]
        self.assertEqual(reference.referenced_uuid, domain_ip_object.uuid)
        self.assertEqual(reference.relationship_type, 'alias-of')

        self._check_misp_object_fields(domain_ip_object, od2, domain1.id)
        self._check_domain_ip_fields(
            domain_ip_object, domain1, ipv4, ipv6,
            domain1.id, f'{domain1.id} - {ipv4.id}', f'{domain1.id} - {ipv6.id}'
        )

    def test_stix21_bundle_with_domain_ip_observables(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_domain_ip_observables()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, domain1, ipv4, ipv6, domain2 = bundle.objects
        misp_objects = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(misp_objects), 2)
        domain_ip_object, domain_object = misp_objects
        self._assert_multiple_equal(
            domain_ip_object.name, domain_object.name, 'domain-ip'
        )

        self.assertEqual(domain_ip_object.uuid, domain1.id.split('--')[1])
        self._check_domain_ip_fields(
            domain_ip_object, domain1, ipv4, ipv6,
            domain1.id, f'{domain1.id} - {ipv4.id}', f'{domain1.id} - {ipv6.id}'
        )

        self.assertEqual(domain_object.uuid, domain2.id.split('--')[1])
        self.assertEqual(len(domain_object.attributes), 1)
        domain_attribute = domain_object.attributes[0]
        self._assert_multiple_equal(
            domain_attribute.type, domain_attribute.object_relation, 'domain'
        )
        self.assertEqual(domain_attribute.value, domain2.value)
        self.assertEqual(
            domain_attribute.uuid,
            uuid5(UUIDv4, f'{domain2.id} - domain - {domain2.value}')
        )

        self.assertEqual(len(domain_object.references), 1)
        reference = domain_object.references[0]
        self.assertEqual(reference.referenced_uuid, domain_ip_object.uuid)
        self.assertEqual(reference.relationship_type, 'alias-of')

    def test_stix21_bundle_with_email_address_attributes(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_email_address_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, od1, od2, od3, ea1, ea2, ea3, ea4 = bundle.objects
        attributes = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(attributes), 6)
        mm_address, mm_display_name, ms_address, sm_address, sm_display_name, ss_address = attributes

        self._check_email_address_attribute_with_display_name(
            od1, mm_address, mm_display_name, ea1
        )
        self._check_email_address_attribute(od1, ms_address, ea2)

        self._check_email_address_attribute_with_display_name(
            od2, sm_address, sm_display_name, ea3
        )
        self._check_email_address_attribute(od3, ss_address, ea4)

    def test_stix21_bundle_with_email_address_observables(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_email_address_observables()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, address1, address2 = bundle.objects
        attributes = self._check_misp_event_features_from_grouping(event, grouping)
        email_address1, display_name, email_address2 = attributes
        self._assert_multiple_equal(
            email_address1.type, email_address2.type, 'email'
        )

        self.assertEqual(
            email_address1.uuid, uuid5(
                UUIDv4, f'{address1.id} - email - {address1.value}'
            )
        )
        self.assertEqual(email_address1.value, address1.value)

        self.assertEqual(display_name.type, 'email-dst-display-name')
        self.assertEqual(
            display_name.uuid, uuid5(
                UUIDv4,
                f'{address1.id} - {display_name.type} - {address1.display_name}'
            )
        )
        self.assertEqual(display_name.value, address1.display_name)

        self.assertEqual(email_address2.uuid, address2.id.split('--')[1])
        self.assertEqual(email_address2.value, address2.value)

    def test_stix21_bundle_with_email_message_objects(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_email_message_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, observed_data, message, ea1, ea2, ea3, artifact, _file = bundle.objects
        misp_objects = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(misp_objects), 3)
        email_object, artifact_object, file_object = misp_objects

        self._check_email_object(email_object, observed_data, message, ea1, ea2, ea3)
        email_references = email_object.references
        self.assertEqual(len(email_references), 2)
        artifact_reference, file_reference = email_references
        self.assertEqual(artifact_reference.referenced_uuid, artifact_object.uuid)
        self.assertEqual(artifact_reference.relationship_type, 'contains')
        self.assertEqual(file_reference.referenced_uuid, file_object.uuid)
        self.assertEqual(file_reference.relationship_type, 'contains')

        self._check_email_artifact_object(artifact_object, observed_data, artifact)
        self._check_email_file_object(file_object, observed_data, _file)

    def test_stix21_bundle_with_email_message_observables(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_email_message_observables()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, message, ea1, ea2, ea3, artifact, _file = bundle.objects
        misp_objects = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(misp_objects), 3)
        email_object, artifact_object, file_object = misp_objects

        self.assertEqual(email_object.name, 'email')
        message_id = message.id
        self.assertEqual(email_object.uuid, message_id.split('--')[1])
        self._check_email_object_fields(
            email_object, message, ea1, ea2, ea3, message_id,
            f'{message_id} - {ea1.id}', f'{message_id} - {ea2.id}',
            f'{message_id} - {ea3.id}'
        )
        email_references = email_object.references
        self.assertEqual(len(email_references), 2)
        artifact_reference, file_reference = email_references
        self.assertEqual(artifact_reference.referenced_uuid, artifact_object.uuid)
        self.assertEqual(artifact_reference.relationship_type, 'contains')
        self.assertEqual(file_reference.referenced_uuid, file_object.uuid)
        self.assertEqual(file_reference.relationship_type, 'contains')

        self.assertEqual(artifact_object.name, 'artifact')
        self.assertEqual(artifact_object.uuid, artifact.id.split('--')[1])
        self._check_email_artifact_object_fields(artifact_object, artifact)

        self.assertEqual(file_object.name, 'file')
        self.assertEqual(file_object.uuid, _file.id.split('--')[1])
        self._check_email_file_object_fields(file_object, _file)

    def test_stix21_bundle_with_file_objects(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_file_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, od1, od2, od3, file1, directory, artifact, file2, file3 = bundle.objects
        misp_objects = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(misp_objects), 10)
        file_object1, directory_object, artifact_object, archive, file_object2, pe_object, *sections = misp_objects

        self._check_file_object(file_object1, od1, file1, od2.id)

        self.assertEqual(directory_object.name, 'directory')
        self._check_misp_object_fields(directory_object, od1, directory.id, od2.id)
        self.assertEqual(len(directory_object.attributes), 1)
        path_attribute = directory_object.attributes[0]
        self.assertEqual(path_attribute.type, 'text')
        self.assertEqual(path_attribute.object_relation, 'path')
        self.assertEqual(path_attribute.value, directory.path)
        self.assertEqual(
            path_attribute.uuid,
            uuid5(UUIDv4, f'{directory.id} - path - {path_attribute.value}')
        )

        self._check_content_ref_object(artifact_object, od1, artifact)
        self._check_file_object_references(file_object1, directory_object, artifact_object)

        self._check_archive_file_object(archive, od2, file2)
        self._check_archive_object_references(archive, file_object1, directory_object)

        self._check_file_and_pe_objects(od3, file3, file_object2, pe_object, *sections)

    def test_stix21_bundle_with_file_observables(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_file_observables()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, file1, directory, artifact, file2, file3 = bundle.objects
        misp_objects = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(misp_objects), 10)
        file_object1, directory_object, artifact_object, archive, file_object2, pe_object, *sections = misp_objects
        self._assert_multiple_equal(
            file_object1.name, archive.name, file_object2.name, 'file'
        )

        self.assertEqual(file_object1.uuid, file1.id.split('--')[1])
        self._check_file_fields(file_object1, file1)

        self.assertEqual(directory_object.name, 'directory')
        self.assertEqual(directory_object.uuid, directory.id.split('--')[1])
        self.assertEqual(len(directory_object.attributes), 1)
        path_attribute = directory_object.attributes[0]
        self.assertEqual(path_attribute.type, 'text')
        self.assertEqual(path_attribute.object_relation, 'path')
        self.assertEqual(path_attribute.value, directory.path)
        self.assertEqual(
            path_attribute.uuid,
            uuid5(UUIDv4, f'{directory.id} - path - {path_attribute.value}')
        )

        self.assertEqual(artifact_object.name, 'artifact')
        self.assertEqual(artifact_object.uuid, artifact.id.split('--')[1])
        self._check_content_ref_fields(artifact_object, artifact)
        self._check_file_object_references(file_object1, directory_object, artifact_object)

        self.assertEqual(archive.uuid, file2.id.split('--')[1])
        self.assertEqual(archive.comment, file2.extensions['archive-ext'].comment)
        self._check_archive_file_fields(archive, file2)
        self._check_archive_object_references(archive, file_object1, directory_object)

        self.assertEqual(file_object2.uuid, file3.id.split('--')[1])
        self._check_file_with_pe_fields(file_object2, file3)
        file_reference = file_object2.references[0]
        self.assertEqual(file_reference.referenced_uuid, pe_object.uuid)
        self.assertEqual(file_reference.relationship_type, 'includes')

        self.assertEqual(pe_object.name, 'pe')
        object_id = f'{file3.id} - windows-pebinary-ext'
        self.assertEqual(pe_object.uuid, uuid5(UUIDv4, object_id))
        extension = file3.extensions['windows-pebinary-ext']
        self._check_pe_fields(pe_object, extension, object_id)

        self.assertEqual(len(pe_object.references), len(sections))
        for reference, section in zip(pe_object.references, sections):
            self.assertEqual(reference.referenced_uuid, section.uuid)
            self.assertEqual(reference.relationship_type, 'includes')
        for index, section in enumerate(sections):
            self.assertEqual(section.name, 'pe-section')
            section_id = f'{object_id} - sections - {index}'
            self.assertEqual(section.uuid, uuid5(UUIDv4, section_id))
            self._check_pe_section_fields(
                section, extension.sections[index], section_id
            )

    def test_stix21_bundle_with_ip_address_attributes(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_ip_address_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, od1, od2, address_1, address_2, address_3 = bundle.objects
        attributes = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(attributes), 3)
        m_ip1, m_ip2, s_ip = attributes
        self._check_generic_attribute(od1, address_1, m_ip1, 'ip-dst')
        self._check_generic_attribute(od1, address_2, m_ip2, 'ip-dst')
        self._check_generic_attribute(od2, address_3, s_ip, 'ip-dst')

    def test_stix21_bundle_with_ip_address_observables(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_ip_address_observables()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, address_1, address_2 = bundle.objects
        attributes = self._check_misp_event_features_from_grouping(event, grouping)
        ip_address1, ip_address2 = attributes
        self._assert_multiple_equal(ip_address1.type, ip_address2.type, 'ip-dst')

        self.assertEqual(ip_address1.uuid, address_1.id.split('--')[1])
        self.assertEqual(ip_address1.value, address_1.value)

        self.assertEqual(ip_address2.uuid, address_2.id.split('--')[1])
        self.assertEqual(ip_address2.value, address_2.value)

    def test_stix21_bundle_with_mac_address_attributes(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_mac_address_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, od1, od2, address_1, address_2, address_3 = bundle.objects
        attributes = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(attributes), 3)
        m_mac1, m_mac2, s_mac = attributes
        self._check_generic_attribute(od1, address_1, m_mac1, 'mac-address')
        self._check_generic_attribute(od1, address_2, m_mac2, 'mac-address')
        self._check_generic_attribute(od2, address_3, s_mac, 'mac-address')

    def test_stix21_bundle_with_mac_address_observables(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_mac_address_observable()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, address = bundle.objects
        attributes = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(attributes), 1)
        mac_address = attributes[0]
        self.assertEqual(mac_address.type, 'mac-address')
        self.assertEqual(mac_address.uuid, address.id.split('--')[1])
        self.assertEqual(mac_address.value, address.value)

    def test_stix21_bundle_with_mutex_attributes(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_mutex_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, od1, od2, mutex_1, mutex_2, mutex_3 = bundle.objects
        attributes = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(attributes), 3)
        m_mutex1, m_mutex2, s_mutex = attributes
        self._check_generic_attribute(od1, mutex_1, m_mutex1, 'mutex', 'name')
        self._check_generic_attribute(od1, mutex_2, m_mutex2, 'mutex', 'name')
        self._check_generic_attribute(od2, mutex_3, s_mutex, 'mutex', 'name')

    def test_stix21_bundle_with_mutex_observable(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_mutex_observable()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, mutex = bundle.objects
        attributes = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(attributes), 1)
        mutex_attribute = attributes[0]
        self.assertEqual(mutex_attribute.type, 'mutex')
        self.assertEqual(mutex_attribute.uuid, mutex.id.split('--')[1])
        self.assertEqual(mutex_attribute.value, mutex.name)

    def test_stix21_bundle_with_network_traffic_objects(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_network_traffic_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, od1, od2, ip1, ip2, ip3, nt1, nt2, ip4, ip5, nt3, nt4, artifact = bundle.objects
        misp_objects = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(misp_objects), 5)
        nt_object1, nt_object2, nt_object3, artifact_object, nt_object4 = misp_objects

        self._check_network_traffic_object_with_packet_sizes(
            nt_object1, od1, nt1, ip1, ip2, 8
        )
        self.assertEqual(len(nt_object1.references), 1)
        encapsulates1 = nt_object1.references[0]
        self.assertEqual(encapsulates1.referenced_uuid, nt_object2.uuid)

        self._check_network_traffic_object_with_packet_counts(
            nt_object2, od1, nt2, ip1, ip3, 9
        )
        self.assertEqual(len(nt_object2.references), 1)
        encapsulated1 = nt_object2.references[0]
        self.assertEqual(encapsulated1.referenced_uuid, nt_object1.uuid)

        self._check_network_traffic_object_with_packet_sizes(
            nt_object3, od2, nt3, ip2, ip4, 9
        )
        self.assertEqual(len(nt_object3.references), 2)
        payload_ref, encapsulates2 = nt_object3.references
        self.assertEqual(encapsulates2.referenced_uuid, nt_object4.uuid)
        self.assertEqual(payload_ref.referenced_uuid, artifact_object.uuid)
        self.assertEqual(payload_ref.relationship_type, 'source-sent')

        self._check_misp_object_fields(artifact_object, od2, artifact.id)
        self._check_payload_object_fields(artifact_object, artifact)

        self._check_network_traffic_object_with_packet_counts(
            nt_object4, od2, nt4, ip4, ip5, 10
        )
        self.assertEqual(len(nt_object4.references), 2)
        payload_ref, encapsulated2 = nt_object4.references
        self.assertEqual(encapsulated2.referenced_uuid, nt_object3.uuid)
        self.assertEqual(payload_ref.referenced_uuid, artifact_object.uuid)
        self.assertEqual(payload_ref.relationship_type, 'destination-sent')

        self._assert_multiple_equal(
            encapsulates1.relationship_type,
            encapsulates2.relationship_type,
            'encapsulates'
        )
        self._assert_multiple_equal(
            encapsulated1.relationship_type,
            encapsulated2.relationship_type,
            'encapsulated-by'
        )

    def test_stix21_bundle_with_network_traffic_observables(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_network_traffic_observables()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, ip1, ip2, ip3, nt1, nt2, artifact = bundle.objects
        misp_objects = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(misp_objects), 3)
        nt_object1, artifact_object, nt_object2 = misp_objects
        self._assert_multiple_equal(nt_object1.name, nt_object2.name, 'network-traffic')

        self.assertEqual(nt_object1.uuid, nt1.id.split('--')[1])
        self._check_network_traffic_packet_sizes(
            nt_object1, nt1, ip1, ip2, 9
        )
        self.assertEqual(len(nt_object1.references), 2)
        payload_ref, encapsulates2 = nt_object1.references
        self.assertEqual(encapsulates2.referenced_uuid, nt_object2.uuid)
        self.assertEqual(encapsulates2.relationship_type, 'encapsulates')
        self.assertEqual(payload_ref.referenced_uuid, artifact_object.uuid)
        self.assertEqual(payload_ref.relationship_type, 'source-sent')

        self.assertEqual(artifact_object.uuid, artifact.id.split('--')[1])
        self._check_payload_object_fields(artifact_object, artifact)

        self._check_network_traffic_packet_counts(
            nt_object2, nt2, ip2, ip3, 10
        )
        self.assertEqual(len(nt_object2.references), 2)
        payload_ref, encapsulated2 = nt_object2.references
        self.assertEqual(encapsulated2.referenced_uuid, nt_object1.uuid)
        self.assertEqual(encapsulated2.relationship_type, 'encapsulated-by')
        self.assertEqual(payload_ref.referenced_uuid, artifact_object.uuid)
        self.assertEqual(payload_ref.relationship_type, 'destination-sent')

    def test_stix21_bundle_with_process_objects(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_process_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, od1, od2, process1, process2, file1, process3, file2, process4 = bundle.objects
        misp_objects = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(misp_objects), 6)
        multiple, image1, parent, child, image2, single = misp_objects
        self._assert_multiple_equal(
            multiple.name, parent.name, child.name, single.name, 'process'
        )
        self._assert_multiple_equal(image1.name, image2.name, 'file')

        self._check_misp_object_fields(multiple, od1, process1.id)
        self._check_process_multiple_fields(multiple, process1)

        self._check_misp_object_fields(image1, od1, file2.id)
        self._check_process_image_reference_fields(image1, file2)

        self._check_misp_object_fields(parent, od1, process2.id)
        self._check_process_parent_fields(parent, process2)

        self._check_misp_object_fields(child, od1, process3.id)
        self._check_process_child_fields(child, process3)

        self._check_misp_object_fields(image2, od1, file1.id)
        self._check_process_image_reference_fields(image2, file1)

        self._check_misp_object_fields(single, od2, process4.id)
        self._check_process_single_fields(single, process4)

        self._check_process_object_references(multiple, parent, child, image1, image2)

    def test_stix21_bundle_with_process_observables(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_process_observables()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, process1, process2, file1, process3, file2 = bundle.objects
        misp_objects = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(misp_objects), 5)
        process, image1, parent, image2, child = misp_objects
        self._assert_multiple_equal(
            process.name, parent.name, child.name, 'process'
        )
        self._assert_multiple_equal(image1.name, image2.name, 'file')

        self.assertEqual(process.uuid, process1.id.split('--')[1])
        self._check_process_multiple_fields(process, process1)

        self.assertEqual(image1.uuid, file2.id.split('--')[1])
        self._check_process_image_reference_fields(image1, file2)

        self.assertEqual(parent.uuid, process2.id.split('--')[1])
        self._check_process_parent_fields(parent, process2)

        self.assertEqual(child.uuid, process3.id.split('--')[1])
        self._check_process_child_fields(child, process3)

        self.assertEqual(image2.uuid, file1.id.split('--')[1])
        self._check_process_image_reference_fields(image2, file1)

        self._check_process_object_references(process, parent, child, image1, image2)

    def test_stix21_bundle_with_registry_key_objects(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_registry_key_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, od1, od2, key1, key2, key3, user = bundle.objects
        misp_objects = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(misp_objects), 6)
        multiple1, multiple2, value1, value2, creator_user, single = misp_objects

        self._check_registry_key_object(multiple1, od1, key1)
        self._check_registry_key_object(multiple2, od1, key2, value1, value2)
        self._check_registry_key_object(single, od2, key3)

        self.assertEqual(creator_user.uuid, user.id.split('--')[1])
        self.assertEqual(creator_user.name, 'user-account')
        self.assertEqual(
            creator_user.comment,
            f'Observed Data ID: {od1.id} - Observed Data ID: {od2.id}'
        )
        self.assertEqual(creator_user.timestamp, od1.modified)
        self._assert_multiple_equal(
            creator_user.first_seen, od1.first_observed, od2.first_observed
        )
        self._check_creator_user_fields(creator_user, user, user.id)

        self._check_registry_key_references(
            creator_user, multiple2, single, value1.uuid, value2.uuid
        )

    def test_stix21_bundle_with_registry_key_observables(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_registry_key_observables()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, key1, key2, key3, user = bundle.objects
        misp_objects = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(misp_objects), 6)
        regkey1, regkey2, value1, value2, creator_user, regkey3 = misp_objects
        self._assert_multiple_equal(
            regkey1.name, regkey2.name, regkey3.name, 'registry-key'
        )
        self._assert_multiple_equal(
            value1.name, value2.name, 'registry-key-value'
        )

        self.assertEqual(regkey1.uuid, key1.id.split('--')[1])
        modified = self._check_registry_key_with_values_fields(regkey1, key1)
        self.assertEqual(modified.value, key1.modified_time)

        self.assertEqual(regkey2.uuid, key2.id.split('--')[1])
        modified = self._check_registry_key_fields(regkey2, key2)
        self.assertEqual(modified.value, key2.modified_time)

        value1_id = f'{key2.id} - values - 0'
        self.assertEqual(value1.uuid, uuid5(UUIDv4, value1_id))
        self._check_registry_key_value_fields(value1, key2['values'][0], value1_id)

        value2_id = f'{key2.id} - values - 1'
        self.assertEqual(value2.uuid, uuid5(UUIDv4, value2_id))
        self._check_registry_key_value_fields(value2, key2['values'][1], value2_id)

        self.assertEqual(creator_user.uuid, user.id.split('--')[1])
        self.assertEqual(creator_user.name, 'user-account')
        self._check_creator_user_fields(creator_user, user, user.id)

        self.assertEqual(regkey3.uuid, key3.id.split('--')[1])
        modified = self._check_registry_key_with_values_fields(regkey3, key3)
        self.assertEqual(modified.value, key3.modified_time)

        self._check_registry_key_references(
            creator_user, regkey2, regkey3, value1.uuid, value2.uuid
        )

    def test_stix21_bundle_with_software_objects(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_software_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, od1, od2, software1, software2, software3 = bundle.objects
        misp_objects = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(misp_objects), 3)
        multiple1, multiple2, single = misp_objects

        self._check_software_object(multiple1, od1, software1)
        self._check_software_object(multiple2, od1, software2)

        self.assertEqual(single.name, 'software')
        self._check_misp_object_fields(single, od2, software3.id)
        self._check_software_with_swid_fields(single, software3)

    def test_stix21_bundle_with_software_observables(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_software_observables()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, software1, software2 = bundle.objects
        misp_objects = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(misp_objects), 2)
        software_object1, software_object2 = misp_objects
        self._assert_multiple_equal(
            software_object1.name, software_object2.name, 'software'
        )

        self.assertEqual(software_object1.uuid, software1.id.split('--')[1])
        self._check_software_fields(software_object1, software1)

        self.assertEqual(software_object2.uuid, software2.id.split('--')[1])
        self._check_software_with_swid_fields(software_object2, software2)

    def test_stix21_bundle_with_url_attributes(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_url_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, od1, od2, url_1, url_2, url_3 = bundle.objects
        attributes = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(attributes), 3)
        m_url1, m_url2, s_url = attributes
        self._check_generic_attribute(od1, url_1, m_url1, 'url')
        self._check_generic_attribute(od1, url_2, m_url2, 'url')
        self._check_generic_attribute(od2, url_3, s_url, 'url')

    def test_stix21_bundle_with_url_observable(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_url_observable()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, url = bundle.objects
        attributes = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(attributes), 1)
        url_attribute = attributes[0]
        self.assertEqual(url_attribute.type, 'url')
        self.assertEqual(url_attribute.uuid, url.id.split('--')[1])
        self.assertEqual(url_attribute.value, url.value)

    def test_stix21_bundle_with_user_account_objects(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_user_account_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, od1, od2, user1, user2, user3 = bundle.objects
        misp_objects = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(misp_objects), 3)
        multiple1, multiple2, single = misp_objects
        self._assert_multiple_equal(
            multiple1.name, multiple2.name, single.name, 'user-account'
        )

        self._check_misp_object_fields(multiple1, od1, user1.id)
        self._check_user_account_object(multiple1, user1)

        self._check_misp_object_fields(multiple2, od1, user2.id)
        self._check_user_account_twitter_fields(multiple2, user2)

        self._check_misp_object_fields(single, od2, user3.id)
        self.assertEqual(len(single.attributes), 11)
        self._check_user_account_fields(single.attributes[:7], user3)
        self._check_user_account_extension_fields(
            single.attributes[7:], user3.extensions['unix-account-ext'],
            user3.id
        )

    def test_stix21_bundle_with_user_account_observables(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_user_account_observables()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, user1, user2, user3 = bundle.objects
        misp_objects = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(misp_objects), 3)
        user_account1, user_account2, user_account3 = misp_objects
        self._assert_multiple_equal(
            user_account1.name, user_account2.name,
            user_account3.name, 'user-account'
        )

        self.assertEqual(user_account1.uuid, user1.id.split('--')[1])
        self._check_user_account_object(user_account1, user1)

        self.assertEqual(user_account2.uuid, user2.id.split('--')[1])
        self._check_user_account_twitter_fields(user_account2, user2)

        self.assertEqual(user_account3.uuid, user3.id.split('--')[1])
        self.assertEqual(len(user_account3.attributes), 11)
        self._check_user_account_fields(user_account3.attributes[:7], user3)
        self._check_user_account_extension_fields(
            user_account3.attributes[7:], user3.extensions['unix-account-ext'],
            user3.id
        )

    def test_stix21_bundle_with_x509_objects(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_x509_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, od1, od2, cert1, cert2, cert3 = bundle.objects
        misp_objects = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(misp_objects), 3)
        multiple1, multiple2, single = misp_objects
        self._check_x509_object(multiple1, od1, cert1)
        self._check_x509_object(multiple2, od1, cert2)
        self._check_x509_object(single, od2, cert3)

    def test_stix21_bundle_with_wrapped_objects(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_wrapped_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, *stix_objects, observed_data = bundle.objects
        misp_content = self._check_misp_event_features_from_grouping(event, grouping)
        for misp_object in misp_content:
            self.assertEqual(misp_object.timestamp, observed_data.modified)
            self.assertEqual(misp_object.first_seen, observed_data.first_observed)
            self.assertEqual(misp_object.last_seen, observed_data.last_observed)
        self._check_wrapped_observable_objects(stix_objects, misp_content)

    def test_stix21_bundle_with_wrapped_observables(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_wrapped_observables()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, *stix_objects = bundle.objects
        misp_content = self._check_misp_event_features_from_grouping(event, grouping)
        self._check_wrapped_observable_objects(stix_objects, misp_content)

    def test_stix21_bundle_with_x509_observables(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_x509_observable()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, certificate = bundle.objects
        misp_objects = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(misp_objects), 1)
        x509_object = misp_objects[0]
        self.assertEqual(x509_object.name, 'x509')
        self.assertEqual(x509_object.uuid, certificate.id.split('--')[1])
        self._check_x509_fields(x509_object, certificate)
