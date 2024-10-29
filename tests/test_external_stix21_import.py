#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .test_external_stix21_bundles import TestExternalSTIX21Bundles
from ._test_stix import TestSTIX21
from ._test_stix_import import TestExternalSTIX2Import, TestSTIX21Import
from datetime import datetime
from uuid import uuid5


class TestExternalSTIX21Import(TestExternalSTIX2Import, TestSTIX21, TestSTIX21Import):

    ############################################################################
    #                         MISP EVENT IMPORT TESTS.                         #
    ############################################################################

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
            event_report.uuid,
            uuid5(self._UUIDv4, f'description - {grouping.id}')
        )
        self.assertEqual(event_report.content, grouping.description)
        self.assertEqual(event_report.name, 'STIX 2.1 grouping description')
        self.assertEqual(event_report.timestamp, grouping.modified)

    ############################################################################
    #                        MISP GALAXIES IMPORT TESTS                        #
    ############################################################################

    def _check_location_galaxy_features(
            self, galaxies, stix_object, galaxy_type, cluster_value=None):
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

    ############################################################################
    #                    OBSERVED DATA OBJECTS IMPORT TESTS                    #
    ############################################################################

    def _check_artifact_object(self, misp_object, observed_data, artifact):
        self.assertEqual(misp_object.name, 'artifact')
        self._check_misp_object_fields(misp_object, observed_data, artifact.id)
        self._check_artifact_fields(misp_object, artifact, artifact.id)

    def _check_as_attribute(self, attribute, observed_data, autonomous_system):
        self._check_misp_object_fields(attribute, observed_data, autonomous_system.id)
        self.assertEqual(attribute.type, 'AS')
        self.assertEqual(attribute.value, f'AS{autonomous_system.number}')

    def _check_as_object(self, misp_object, observed_data, autonomous_system):
        self.assertEqual(misp_object.name, 'asn')
        self._check_misp_object_fields(misp_object, observed_data, autonomous_system.id)
        self._check_as_fields(misp_object, autonomous_system, autonomous_system.id)

    def _check_content_ref_object(self, misp_object, observed_data, artifact):
        self.assertEqual(misp_object.name, 'artifact')
        self._check_misp_object_fields(misp_object, observed_data, artifact.id)
        self._check_content_ref_fields(misp_object, artifact, artifact.id)

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
        self.assertEqual(address.type, 'email-dst')
        self.assertEqual(address.value, email_address.value)

    def _check_email_address_attribute_with_display_name(
            self, observed_data, address, display_name, email_address):
        self._check_misp_object_fields(
            address, observed_data,
            f'{email_address.id} - email-dst - {email_address.value}',
            multiple=True
        )
        self.assertEqual(address.type, 'email-dst')
        self.assertEqual(address.value, email_address.value)
        self._check_misp_object_fields(
            display_name, observed_data,
            f'{email_address.id} - email-dst-display-name - {email_address.display_name}',
            multiple=True
        )
        self.assertEqual(display_name.type, 'email-dst-display-name')
        self.assertEqual(display_name.value, email_address.display_name)

    def _check_email_artifact_object(self, misp_object, observed_data, artifact):
        self.assertEqual(misp_object.name, 'artifact')
        self._check_misp_object_fields(misp_object, observed_data, artifact.id)
        self._check_email_artifact_object_fields(misp_object, artifact, artifact.id)

    def _check_email_file_object(self, misp_object, observed_data, _file):
        self.assertEqual(misp_object.name, 'file')
        self._check_misp_object_fields(misp_object, observed_data, _file.id)
        self._check_email_file_object_fields(misp_object, _file, _file.id)

    def _check_email_object(self, misp_object, observed_data, email_message,
                            from_address, to_address, cc_address):
        self.assertEqual(misp_object.name, 'email')
        self._check_misp_object_fields(misp_object, observed_data, email_message.id)
        self._check_email_object_fields(
            misp_object, email_message, from_address, to_address, cc_address,
            email_message.id, from_address.id, to_address.id, cc_address.id
        )

    def _check_file_and_pe_objects(self, observed_data, observable_object,
                                   file_object, pe_object, *sections):
        self.assertEqual(file_object.name, 'file')
        self._check_misp_object_fields(file_object, observed_data, observable_object.id)
        self._check_file_with_pe_fields(
            file_object, observable_object, observable_object.id
        )
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
            section_id = f'{object_id} - section - {index}'
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
        self._check_file_fields(
            misp_object, observable_object, observable_object.id
        )

    def _check_generic_attribute(
            self, observed_data, observable_object, attribute,
            attribute_type, feature='value'):
        self._check_misp_object_fields(attribute, observed_data, observable_object.id)
        self.assertEqual(attribute.type, attribute_type)
        self.assertEqual(attribute.value, getattr(observable_object, feature))

    def _check_misp_object_fields(self, misp_object, observed_data, object_id,
                                  *additional_ids, multiple=False):
        if multiple:
            self.assertEqual(misp_object.uuid, uuid5(self._UUIDv4, object_id))
        else:
            self.assertEqual(misp_object.uuid, object_id.split('--')[1])
        pattern = 'Observed Data ID: '
        self.assertEqual(
            misp_object.comment,
            f"{pattern}{f' - {pattern}'.join((observed_data.id, *additional_ids))}"
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
            uuid5(
                self._UUIDv4,
                f'{network_traffic.id} - src_port - {src_port.value}'
            )
        )
        self.assertEqual(dst_port.type, 'port')
        self.assertEqual(dst_port.object_relation, 'dst_port')
        self.assertEqual(dst_port.value, network_traffic.dst_port)
        self.assertEqual(
            dst_port.uuid,
            uuid5(
                self._UUIDv4,
                f'{network_traffic.id} - dst_port - {dst_port.value}'
            )
        )
        for index, protocol in enumerate(protocols):
            protocol_value = network_traffic.protocols[index].upper()
            self.assertEqual(protocol.type, 'text')
            self.assertEqual(protocol.object_relation, 'protocol')
            self.assertEqual(protocol.value, protocol_value)
            self.assertEqual(
                protocol.uuid,
                uuid5(
                    self._UUIDv4,
                    f'{network_traffic.id} - protocol - {protocol_value}'
                )
            )
        self.assertEqual(ip_src.type, 'ip-src')
        self.assertEqual(ip_src.object_relation, 'src_ip')
        self.assertEqual(ip_src.value, src_ip.value)
        self.assertEqual(
            ip_src.uuid,
            uuid5(
                self._UUIDv4,
                f'{network_traffic.id} - {src_ip.id} - src_ip - {src_ip.value}'
            )
        )
        self.assertEqual(ip_dst.type, 'ip-dst')
        self.assertEqual(ip_dst.object_relation, 'dst_ip')
        self.assertEqual(ip_dst.value, dst_ip.value)
        self.assertEqual(
            ip_dst.uuid,
            uuid5(
                self._UUIDv4,
                f'{network_traffic.id} - {dst_ip.id} - dst_ip - {dst_ip.value}'
            )
        )
        return src_return, dst_return

    def _check_network_traffic_object_with_packet_counts(
            self, misp_object, obbserved_data, network_traffic,
            src_ip, dst_ip, attributes_count):
        self.assertEqual(misp_object.name, 'network-traffic')
        self._check_misp_object_fields(misp_object, obbserved_data, network_traffic.id)
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
                self._UUIDv4,
                f'{network_traffic.id} - src_packets - {src_packets.value}'
            )
        )
        self.assertEqual(dst_packets.type, 'counter')
        self.assertEqual(dst_packets.object_relation, 'dst_packets')
        self.assertEqual(dst_packets.value, network_traffic.dst_packets)
        self.assertEqual(
            dst_packets.uuid,
            uuid5(
                self._UUIDv4,
                f'{network_traffic.id} - dst_packets - {dst_packets.value}'
            )
        )

    def _check_network_traffic_object_with_packet_sizes(
            self, misp_object, obbserved_data, network_traffic,
            src_ip, dst_ip, attributes_count):
        self.assertEqual(misp_object.name, 'network-traffic')
        self._check_misp_object_fields(misp_object, obbserved_data, network_traffic.id)
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
                self._UUIDv4,
                f'{network_traffic.id} - src_byte_count - {src_bytes.value}'
            )
        )
        self.assertEqual(dst_bytes.type, 'size-in-bytes')
        self.assertEqual(dst_bytes.object_relation, 'dst_byte_count')
        self.assertEqual(dst_bytes.value, network_traffic.dst_byte_count)
        self.assertEqual(
            dst_bytes.uuid,
            uuid5(
                self._UUIDv4,
                f'{network_traffic.id} - dst_byte_count - {dst_bytes.value}'
            )
        )

    def _check_registry_key_object(
            self, misp_object, observed_data, registry_key, *values):
        self.assertEqual(misp_object.name, 'registry-key')
        self._check_misp_object_fields(misp_object, observed_data, registry_key.id)
        if values:
            modified = self._check_registry_key_fields(
                misp_object, registry_key, registry_key.id
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
                misp_object, registry_key, registry_key.id
            )
        self.assertEqual(modified.value, registry_key.modified_time)

    def _check_software_object(self, misp_object, observed_data, software):
        self.assertEqual(misp_object.name, 'software')
        self._check_misp_object_fields(misp_object, observed_data, software.id)
        self._check_software_fields(misp_object, software, software.id)

    def _check_x509_object(self, misp_object, observed_data, x509):
        self.assertEqual(misp_object.name, 'x509')
        self._check_misp_object_fields(misp_object, observed_data, x509.id)
        self._check_x509_fields(misp_object, x509, x509.id)

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
        self._check_misp_object_fields(multiple2, od1, artifact2.id)
        self._check_artifact_with_url_fields(multiple2, artifact2, artifact2.id)
        self._check_artifact_object(single, od2, artifact3)

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
        self._check_misp_object_fields(
            domain_object, od1, domain2.id, multiple=True
        )
        self.assertEqual(len(domain_object.attributes), 1)
        domain_attribute = domain_object.attributes[0]
        self._assert_multiple_equal(
            domain_attribute.type, domain_attribute.object_relation, 'domain'
        )
        self.assertEqual(domain_attribute.value, domain2.value)
        self.assertEqual(
            domain_attribute.uuid,
            uuid5(self._UUIDv4, f'{domain2.id} - domain - {domain2.value}')
        )
        self.assertEqual(len(domain_object.references), 1)
        reference = domain_object.references[0]
        self.assertEqual(reference.referenced_uuid, domain_ip_object.uuid)
        self.assertEqual(reference.relationship_type, 'resolves-to')
        self._check_misp_object_fields(
            domain_ip_object, od2, f'{domain1.id} - {ipv4.id} - {ipv6.id}',
            multiple=True
        )
        self._check_domain_ip_fields(
            domain_ip_object, domain1, ipv4, ipv6,
            domain1.id, f'{domain1.id} - {ipv4.id}', f'{domain1.id} - {ipv6.id}'
        )

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
        path_attribute = directory_object.attributes[0]
        self.assertEqual(path_attribute.type, 'text')
        self.assertEqual(path_attribute.object_relation, 'path')
        self.assertEqual(path_attribute.value, directory.path)
        self.assertEqual(
            path_attribute.uuid,
            uuid5(
                self._UUIDv4, f'{directory.id} - path - {path_attribute.value}'
            )
        )
        self._check_content_ref_object(artifact_object, od1, artifact)
        self.assertEqual(len(file_object1.references), 1)
        file_reference = file_object1.references[0]
        self.assertEqual(file_reference.referenced_uuid, directory_object.uuid)
        self.assertEqual(file_reference.relationship_type, 'contained-in')
        self.assertEqual(len(artifact_object.references), 1)
        artifact_reference = artifact_object.references[0]
        self.assertEqual(artifact_reference.referenced_uuid, file_object1.uuid)
        self.assertEqual(artifact_reference.relationship_type, 'content-of')
        self._check_archive_file_object(archive, od2, file2)
        self.assertEqual(len(archive.references), 2)
        directory_reference, file_reference = archive.references
        self.assertEqual(
            directory_reference.referenced_uuid, file_object1.uuid
        )
        self.assertEqual(directory_reference.relationship_type, 'contains')
        self.assertEqual(file_reference.referenced_uuid, directory_object.uuid)
        self.assertEqual(file_reference.relationship_type, 'contains')
        self._check_file_and_pe_objects(od3, file3, file_object2, pe_object, *sections)

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

    def test_stix21_bundle_with_network_traffic_objects(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_network_traffic_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, od1, od2, ip1, ip2, ip3, nt1, nt2, ip4, ip5, nt3, nt4 = bundle.objects
        misp_objects = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(misp_objects), 4)
        nt_object1, nt_object2, nt_object3, nt_object4 = misp_objects
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
        self.assertEqual(len(nt_object3.references), 1)
        encapsulates2 = nt_object3.references[0]
        self.assertEqual(encapsulates2.referenced_uuid, nt_object4.uuid)
        self._check_network_traffic_object_with_packet_counts(
            nt_object4, od2, nt4, ip4, ip5, 10
        )
        self.assertEqual(len(nt_object4.references), 1)
        encapsulated2 = nt_object4.references[0]
        self.assertEqual(encapsulated2.referenced_uuid, nt_object3.uuid)
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

    def test_stix21_bundle_with_process_objects(self):
        bundle = TestExternalSTIX21Bundles.get_bundle_with_process_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, grouping, od1, od2, process1, process2, file1, process3, file2, process4 = bundle.objects
        misp_objects = self._check_misp_event_features_from_grouping(event, grouping)
        self.assertEqual(len(misp_objects), 6)
        multiple, parent, child, image1, image2, single = misp_objects
        self._assert_multiple_equal(
            multiple.name, parent.name, child.name, single.name, 'process'
        )
        self._assert_multiple_equal(image1.name, image2.name, 'file')

        self._check_misp_object_fields(multiple, od1, process1.id)
        self._check_process_multiple_fields(multiple, process1, process1.id)
        self.assertEqual(len(multiple.references), 3)
        child_ref, parent_ref, binary_ref = multiple.references
        self.assertEqual(child_ref.referenced_uuid, parent.uuid)
        self.assertEqual(child_ref.relationship_type, 'child-of')
        self.assertEqual(parent_ref.referenced_uuid, child.uuid)
        self.assertEqual(parent_ref.relationship_type, 'parent-of')
        self.assertEqual(binary_ref.referenced_uuid, image1.uuid)
        self.assertEqual(binary_ref.relationship_type, 'executes')

        self._check_misp_object_fields(parent, od1, process2.id)
        self._check_process_parent_fields(parent, process2, process2.id)
        self.assertEqual(len(parent.references), 1)
        reference = parent.references[0]
        self.assertEqual(reference.referenced_uuid, image2.uuid)
        self.assertEqual(reference.relationship_type, 'executes')

        self._check_misp_object_fields(child, od1, process3.id)
        self._check_process_child_fields(child, process3, process3.id)

        self._check_misp_object_fields(image1, od1, file2.id)
        self._check_process_image_reference_fields(image1, file2, file2.id)

        self._check_misp_object_fields(image2, od1, file1.id)
        self._check_process_image_reference_fields(image2, file1, file1.id)

        self._check_misp_object_fields(single, od2, process4.id)
        self._check_process_single_fields(single, process4, process4.id)

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
        self.assertEqual(len(creator_user.references), 2)
        reference1, reference2 = creator_user.references
        self.assertEqual(reference1.referenced_uuid, multiple2.uuid)
        self._assert_multiple_equal(
            reference1.relationship_type,
            reference2.relationship_type,
            'creates'
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
        self._check_misp_object_fields(single, od2, software3.id)
        self._check_software_with_swid_fields(single, software3, software3.id)

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
        self.assertEqual(len(multiple1.attributes), 11)
        self._check_user_account_fields(
            multiple1.attributes[:7], user1, user1.id
        )
        self._check_user_account_timeline_fields(
            multiple1.attributes[7:-1], user1, user1.id
        )
        password_last_changed = multiple1.attributes[-1]
        self.assertEqual(
            password_last_changed.object_relation, 'password_last_changed'
        )
        self.assertEqual(
            password_last_changed.value, user1.credential_last_changed
        )
        self.assertEqual(
            password_last_changed.uuid,
            uuid5(
                self._UUIDv4,
                f'{user1.id} - password_last_changed'
                f' - {password_last_changed.value}'
            )
        )
        self._check_misp_object_fields(multiple2, od1, user2.id)
        self._check_user_account_twitter_fields(multiple2, user2, user2.id)
        self._check_misp_object_fields(single, od2, user3.id)
        self.assertEqual(len(single.attributes), 11)
        self._check_user_account_fields(single.attributes[:7], user3, user3.id)
        self._check_user_account_extension_fields(
            single.attributes[7:], user3.extensions['unix-account-ext'],
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
