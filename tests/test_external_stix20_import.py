#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .test_external_stix20_bundles import TestExternalSTIX20Bundles
from ._test_stix import TestSTIX20
from ._test_stix_import import TestExternalSTIX2Import, TestSTIX20Import, UUIDv4
from uuid import uuid5


class TestExternalSTIX20Import(TestExternalSTIX2Import, TestSTIX20, TestSTIX20Import):

    ############################################################################
    #                         MISP EVENT IMPORT TESTS.                         #
    ############################################################################

    def test_stix20_bundle_with_event_title_and_producer(self):
        bundle = TestExternalSTIX20Bundles.get_bundle_without_report()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle(
            title='Malicious IP addresses report',
            producer='MISP Project'
        )
        event = self.parser.misp_event
        self.assertEqual(event.info, self.parser.event_title)
        self.assertEqual(
            event.tags[0]['name'],
            f'misp-galaxy:producer="{self.parser.producer}"'
        )

    def test_stix21_bundle_with_report_description(self):
        bundle = TestExternalSTIX20Bundles.get_bundle_with_report_description()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, indicator = bundle.objects
        self._check_misp_event_features(event, report)
        self.assertEqual(event.attributes[0].uuid, indicator.id.split('--')[1])
        event_report = event.event_reports[0]
        self.assertEqual(
            event_report.uuid, uuid5(UUIDv4, f'description - {report.id}')
        )
        self.assertEqual(event_report.content, report.description)
        self.assertEqual(event_report.name, 'STIX 2.0 report description')
        self.assertEqual(event_report.timestamp, report.modified)

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
        meta = self._check_galaxy_features(attribute.galaxies, attribute_ap)
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
        self.assertEqual(meta['synonyms'], event_campaign.aliases)
        self.assertEqual(meta['objective'], event_campaign.objective)
        self.assertEqual(len(event.attributes), 1)
        attribute = event.attributes[0]
        self.assertEqual(attribute.uuid, indicator.id.split('--')[1])
        self._check_galaxy_features(attribute.galaxies, attribute_campaign)

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

    def _check_archive_file_object(self, misp_object, observed_data):
        self.assertEqual(misp_object.name, 'file')
        self.assertEqual(
            misp_object.uuid, uuid5(UUIDv4, f'{observed_data.id} - 0')
        )
        self.assertEqual(misp_object.timestamp, observed_data.modified)
        observable_object = observed_data.objects['0']
        comment = observable_object.extensions['archive-ext'].comment
        self.assertEqual(
            misp_object.comment,
            f'{comment} - Observed Data ID: {observed_data.id}'
        )
        self._check_archive_file_fields(
            misp_object, observable_object, f'{observed_data.id} - 0'
        )

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
        autonomous_system = observed_data.objects[identifier or '0']
        self._check_misp_object_fields(attribute, observed_data, identifier)
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

    def _check_content_ref_object(self, misp_object, observed_data, identifier=None):
        self.assertEqual(misp_object.name, 'artifact')
        self._check_misp_object_fields(misp_object, observed_data, identifier)
        object_id = observed_data.id
        if identifier is None:
            identifier = '0'
        else:
            object_id = f'{object_id} - {identifier}'
        self._check_content_ref_fields(
            misp_object, observed_data.objects[identifier], object_id
        )

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
        self.assertEqual(address.type, 'email')
        self.assertEqual(address.value, email_address.value)

    def _check_email_address_attribute_with_display_name(
            self, observed_data, address, display_name, identifier=None):
        if identifier is None:
            email_address = observed_data.objects['0']
            self._check_misp_object_fields(
                address, observed_data, f'email - {email_address.value}'
            )
            self._check_misp_object_fields(
                display_name, observed_data,
                f'email-dst-display-name - {email_address.display_name}'
            )
        else:
            email_address = observed_data.objects[identifier]
            self._check_misp_object_fields(
                address, observed_data,
                f'{identifier} - email - {email_address.value}'
            )
            self._check_misp_object_fields(
                display_name, observed_data,
                f'{identifier} - email-dst-display-name - {email_address.display_name}'
            )
        self.assertEqual(address.type, 'email')
        self.assertEqual(address.value, email_address.value)
        self.assertEqual(display_name.type, 'email-dst-display-name')
        self.assertEqual(display_name.value, email_address.display_name)

    def _check_email_artifact_object(
            self, misp_object, observed_data, artifact_id):
        self.assertEqual(misp_object.name, 'artifact')
        self._check_misp_object_fields(misp_object, observed_data, artifact_id)
        self._check_email_artifact_object_fields(
            misp_object, observed_data.objects[artifact_id],
            f'{observed_data.id} - {artifact_id}'
        )

    def _check_email_file_object(self, misp_object, observed_data, file_id):
        self.assertEqual(misp_object.name, 'file')
        self._check_misp_object_fields(misp_object, observed_data, file_id)
        self._check_email_file_object_fields(
            misp_object, observed_data.objects[file_id],
            f'{observed_data.id} - {file_id}'
        )

    def _check_email_object(self, misp_object, observed_data,
                            email_message_id, from_id, to_id, cc_id):
        self.assertEqual(misp_object.name, 'email')
        self._check_misp_object_fields(
            misp_object, observed_data, email_message_id
        )
        object_id = f'{observed_data.id} - {email_message_id}'
        self._check_email_object_fields(
            misp_object, observed_data.objects[email_message_id],
            observed_data.objects[from_id], observed_data.objects[to_id],
            observed_data.objects[cc_id], object_id, f'{object_id} - {from_id}',
            f'{object_id} - {to_id}', f'{object_id} - {cc_id}'
        )

    def _check_file_and_pe_objects(self, observed_data, file_object,
                                   pe_object, *sections):
        self.assertEqual(file_object.name, 'file')
        self._check_misp_object_fields(file_object, observed_data)
        observable_object = observed_data.objects['0']
        self._check_file_with_pe_fields(
            file_object, observable_object, observed_data.id
        )
        file_reference = file_object.references[0]
        self.assertEqual(file_reference.referenced_uuid, pe_object.uuid)
        self.assertEqual(file_reference.relationship_type, 'includes')
        self.assertEqual(pe_object.name, 'pe')
        self._check_misp_object_fields(
            pe_object, observed_data, 'windows-pebinary-ext'
        )
        object_id = f'{observed_data.id} - windows-pebinary-ext'
        extension = observable_object.extensions['windows-pebinary-ext']
        self._check_pe_fields(pe_object, extension, object_id)
        self.assertEqual(len(pe_object.references), len(sections))
        for reference, section in zip(pe_object.references, sections):
            self.assertEqual(reference.referenced_uuid, section.uuid)
            self.assertEqual(reference.relationship_type, 'includes')
        for index, section in enumerate(sections):
            self.assertEqual(section.name, 'pe-section')
            section_id = f'windows-pebinary-ext - sections - {index}'
            self._check_misp_object_fields(section, observed_data, section_id)
            self._check_pe_section_fields(
                section, extension.sections[index],
                f'{observed_data.id} - {section_id}'
            )

    def _check_file_directory_object(self, misp_object, observed_data, object_id):
        self.assertEqual(misp_object.name, 'directory')
        self._check_misp_object_fields(misp_object, observed_data, object_id)
        directory = observed_data.objects[object_id]
        self.assertEqual(len(misp_object.attributes), 1)
        path_attribute = misp_object.attributes[0]
        self.assertEqual(path_attribute.type, 'text')
        self.assertEqual(path_attribute.object_relation, 'path')
        self.assertEqual(path_attribute.value, directory.path)
        self.assertEqual(
            path_attribute.uuid,
            uuid5(
                UUIDv4,
                f'{observed_data.id} - {object_id} - path - {path_attribute.value}'
            )
        )

    def _check_file_object(self, misp_object, observed_data, identifier=None):
        self.assertEqual(misp_object.name, 'file')
        self._check_misp_object_fields(misp_object, observed_data, identifier)
        object_id = observed_data.id
        if identifier is None:
            identifier = '0'
        else:
            object_id = f'{object_id} - {identifier}'
        self._check_file_fields(
            misp_object, observed_data.objects[identifier], object_id
        )

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
                uuid5(UUIDv4, f'{observed_data.id} - {identifier}')
            )
            self.assertEqual(
                misp_object.comment, f'Observed Data ID: {observed_data.id}'
            )
        if not (observed_data.modified == observed_data.first_observed == observed_data.last_observed):
            self.assertEqual(misp_object.first_seen, observed_data.first_observed)
            self.assertEqual(misp_object.last_seen, observed_data.last_observed)
        self.assertEqual(misp_object.timestamp, observed_data.modified)

    def _check_network_traffic_fields(
            self, attributes, network_traffic, src_ip, dst_ip,
            object_id, src_ip_id, dst_ip_id):
        src_port, dst_port, src_return, dst_return, *protocols, ip_src, ip_dst = attributes
        self.assertEqual(src_port.type, 'port')
        self.assertEqual(src_port.object_relation, 'src_port')
        self.assertEqual(src_port.value, network_traffic.src_port)
        self.assertEqual(
            src_port.uuid,
            uuid5(UUIDv4, f'{object_id} - src_port - {src_port.value}')
        )
        self.assertEqual(dst_port.type, 'port')
        self.assertEqual(dst_port.object_relation, 'dst_port')
        self.assertEqual(dst_port.value, network_traffic.dst_port)
        self.assertEqual(
            dst_port.uuid,
            uuid5(UUIDv4, f'{object_id} - dst_port - {dst_port.value}')
        )
        for index, protocol in enumerate(protocols):
            protocol_value = network_traffic.protocols[index].upper()
            self.assertEqual(protocol.type, 'text')
            self.assertEqual(protocol.object_relation, 'protocol')
            self.assertEqual(protocol.value, protocol_value)
            self.assertEqual(
                protocol.uuid,
                uuid5(UUIDv4, f'{object_id} - protocol - {protocol_value}')
            )
        self.assertEqual(ip_src.type, 'ip-src')
        self.assertEqual(ip_src.object_relation, 'src_ip')
        self.assertEqual(ip_src.value, src_ip.value)
        self.assertEqual(
            ip_src.uuid,
            uuid5(
                UUIDv4, f'{object_id} - {src_ip_id} - src_ip - {src_ip.value}'
            )
        )
        self.assertEqual(ip_dst.type, 'ip-dst')
        self.assertEqual(ip_dst.object_relation, 'dst_ip')
        self.assertEqual(ip_dst.value, dst_ip.value)
        self.assertEqual(
            ip_dst.uuid,
            uuid5(
                UUIDv4, f'{object_id} - {dst_ip_id} - dst_ip - {dst_ip.value}'
            )
        )
        return src_return, dst_return

    def _check_network_traffic_object_with_packet_counts(
            self, misp_object, observed_data, network_traffic_id,
            src_ip_id, dst_ip_id,attributes_count):
        self.assertEqual(misp_object.name, 'network-traffic')
        self._check_misp_object_fields(misp_object, observed_data,  network_traffic_id)
        network_traffic = observed_data.objects[network_traffic_id]
        attributes = misp_object.attributes
        self.assertEqual(len(attributes), attributes_count)
        object_id = f'{observed_data.id} - {network_traffic_id}'
        src_packets, dst_packets = self._check_network_traffic_fields(
            attributes, network_traffic, observed_data.objects[src_ip_id],
            observed_data.objects[dst_ip_id], object_id, src_ip_id, dst_ip_id
        )
        self.assertEqual(src_packets.type, 'counter')
        self.assertEqual(src_packets.object_relation, 'src_packets')
        self.assertEqual(src_packets.value, network_traffic.src_packets)
        self.assertEqual(
            src_packets.uuid,
            uuid5(UUIDv4, f'{object_id} - src_packets - {src_packets.value}')
        )
        self.assertEqual(dst_packets.type, 'counter')
        self.assertEqual(dst_packets.object_relation, 'dst_packets')
        self.assertEqual(dst_packets.value, network_traffic.dst_packets)
        self.assertEqual(
            dst_packets.uuid,
            uuid5(UUIDv4, f'{object_id} - dst_packets - {dst_packets.value}')
        )

    def _check_network_traffic_object_with_packet_sizes(
            self, misp_object, observed_data, network_traffic_id,
            src_ip_id, dst_ip_id, attributes_count):
        self.assertEqual(misp_object.name, 'network-traffic')
        self._check_misp_object_fields(misp_object, observed_data, network_traffic_id)
        network_traffic = observed_data.objects[network_traffic_id]
        attributes = misp_object.attributes
        self.assertEqual(len(attributes), attributes_count)
        object_id = f'{observed_data.id} - {network_traffic_id}'
        src_bytes, dst_bytes = self._check_network_traffic_fields(
            attributes, network_traffic, observed_data.objects[src_ip_id],
            observed_data.objects[dst_ip_id], object_id, src_ip_id, dst_ip_id
        )
        self.assertEqual(src_bytes.type, 'size-in-bytes')
        self.assertEqual(src_bytes.object_relation, 'src_byte_count')
        self.assertEqual(src_bytes.value, network_traffic.src_byte_count)
        self.assertEqual(
            src_bytes.uuid,
            uuid5(UUIDv4, f'{object_id} - src_byte_count - {src_bytes.value}')
        )
        self.assertEqual(dst_bytes.type, 'size-in-bytes')
        self.assertEqual(dst_bytes.object_relation, 'dst_byte_count')
        self.assertEqual(dst_bytes.value, network_traffic.dst_byte_count)
        self.assertEqual(
            dst_bytes.uuid,
            uuid5(UUIDv4, f'{object_id} - dst_byte_count - {dst_bytes.value}')
        )

    def _check_registry_key_object(
            self, misp_object, observed_data, *values, identifier=None):
        self.assertEqual(misp_object.name, 'registry-key')
        self._check_misp_object_fields(misp_object, observed_data, identifier)
        object_id = observed_data.id
        if identifier is None:
            identifier = '0'
        else:
            object_id = f'{observed_data.id} - {identifier}'
        registry_key = observed_data.objects[identifier]
        if values:
            modified = self._check_registry_key_fields(
                misp_object, registry_key, object_id
            )
            for index, value_object in enumerate(values):
                self.assertEqual(value_object.name, 'registry-key-value')
                self._check_misp_object_fields(
                    value_object, observed_data,
                    f'{identifier} - values - {index}'
                )
                self._check_registry_key_value_fields(
                    value_object, registry_key['values'][index],
                    f'{object_id} - values - {index}'
                )
        else:
            modified = self._check_registry_key_with_values_fields(
                misp_object, registry_key, object_id
            )
        self.assertEqual(modified.value, registry_key.modified)

    def _check_software_object(self, misp_object, observed_data, identifier):
        self.assertEqual(misp_object.name, 'software')
        self._check_misp_object_fields(misp_object, observed_data, identifier)
        object_id = f'{observed_data.id} - {identifier}'
        self._check_software_fields(
            misp_object, observed_data.objects[identifier], object_id
        )

    def _check_x509_object(self, misp_object, observed_data, identifier=None):
        self.assertEqual(misp_object.name, 'x509')
        self._check_misp_object_fields(misp_object, observed_data, identifier)
        object_id = observed_data.id
        if identifier is None:
            identifier = '0'
        else:
            object_id = f'{object_id} - {identifier}'
        self._check_x509_fields(
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
            uuid5(UUIDv4, f'{observed_data2.id} - 1')
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
        self._check_generic_attribute(observed_data1, m_domain1, 'domain', '0')
        self._check_generic_attribute(observed_data1, m_domain2, 'domain', '1')
        self._check_generic_attribute(observed_data2, s_domain, 'domain')

    def test_stix20_bundle_with_domain_ip_objects(self):
        bundle = TestExternalSTIX20Bundles.get_bundle_with_domain_ip_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        misp_objects = self._check_misp_event_features(event, report)
        domain_ip_object, domain_object = misp_objects
        self._assert_multiple_equal(
            domain_ip_object.name, domain_object.name, 'domain-ip')
        self._check_misp_object_fields(domain_ip_object, observed_data, '0')
        object_id = f'{observed_data.id} - 0'
        self._check_domain_ip_fields(
            domain_ip_object, *list(observed_data.objects.values())[:-1],
            object_id, f'{object_id} - 1', f'{object_id} - 2'
        )
        self._check_misp_object_fields(domain_object, observed_data, '3')
        object_id = f'{observed_data.id} - 3'
        self.assertEqual(len(domain_object.attributes), 1)
        domain = observed_data.objects['3']
        domain_attribute = domain_object.attributes[0]
        self._assert_multiple_equal(
            domain_attribute.type, domain_attribute.object_relation, 'domain'
        )
        self.assertEqual(domain_attribute.value, domain.value)
        self.assertEqual(domain_attribute.uuid, uuid5(UUIDv4, f'{object_id} - domain - {domain.value}'))
        self.assertEqual(len(domain_object.references), 1)
        resolving_reference = domain_object.references[0]
        self.assertEqual(resolving_reference.referenced_uuid, domain_ip_object.uuid)
        self.assertEqual(resolving_reference.relationship_type, 'alias-of')

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

    def test_stix20_bundle_with_email_message_objects(self):
        bundle = TestExternalSTIX20Bundles.get_bundle_with_email_message_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        misp_objects = self._check_misp_event_features(event, report)
        self.assertEqual(len(misp_objects), 3)
        email_object, artifact_object, file_object = misp_objects
        self._check_email_object(email_object, observed_data, '0', '1', '2', '3')
        email_references = email_object.references
        self.assertEqual(len(email_references), 2)
        artifact_reference, file_reference = email_references
        self.assertEqual(artifact_reference.referenced_uuid, artifact_object.uuid)
        self.assertEqual(artifact_reference.relationship_type, 'contains')
        self.assertEqual(file_reference.referenced_uuid, file_object.uuid)
        self.assertEqual(file_reference.relationship_type, 'contains')
        self._check_email_artifact_object(artifact_object, observed_data, '4')
        self._check_email_file_object(file_object, observed_data, '5')

    def test_stix20_bundle_with_file_objects(self):
        bundle = TestExternalSTIX20Bundles.get_bundle_with_file_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data1, observed_data2, observed_data3 = bundle.objects
        misp_objects = self._check_misp_event_features(event, report)
        self.assertEqual(len(misp_objects), 13)
        file1, directory1, artifact1, zip_file, file2, directory2, artifact2, file3, pe, *sections = misp_objects
        self._check_file_object(file1, observed_data1, '0')
        self._check_file_directory_object(directory1, observed_data1, '1')
        self._check_content_ref_object(artifact1, observed_data1, '2')
        self._check_file_object_references(file1, directory1, artifact1)
        self._check_archive_file_object(zip_file, observed_data2)
        self._check_archive_object_references(zip_file, file2, directory2)
        self._check_file_object(file2, observed_data2, '1')
        self._check_file_directory_object(directory2, observed_data2, '2')
        self._check_content_ref_object(artifact2, observed_data2, '3')
        self.assertEqual(len(file2.references), 1)
        file_reference = file2.references[0]
        self.assertEqual(file_reference.referenced_uuid, directory2.uuid)
        self.assertEqual(file_reference.relationship_type, 'contained-in')
        self.assertEqual(len(artifact2.references), 1)
        artifact_reference = artifact2.references[0]
        self.assertEqual(artifact_reference.referenced_uuid, file2.uuid)
        self.assertEqual(artifact_reference.relationship_type, 'content-of')
        self._check_file_and_pe_objects(observed_data3, file3, pe, *sections)

    def test_stix20_bundle_with_ip_address_attributes(self):
        bundle = TestExternalSTIX20Bundles.get_bundle_with_ip_address_attributes()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle(bundle)
        event = self.parser.misp_event
        _, report, observed_data1, observed_data2 = bundle.objects
        attributes = self._check_misp_event_features(event, report)
        self.assertEqual(len(attributes), 3)
        m_ip1, m_ip2, s_ip = attributes
        self._check_generic_attribute(observed_data1, m_ip1, 'ip-dst', '0')
        self._check_generic_attribute(observed_data1, m_ip2, 'ip-dst', '1')
        self._check_generic_attribute(observed_data2, s_ip, 'ip-dst')

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
        self._check_generic_attribute(observed_data2, s_mac, 'mac-address')

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

    def test_stix20_bundle_with_network_traffic_objects(self):
        bundle = TestExternalSTIX20Bundles.get_bundle_with_network_traffic_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data1, observed_data2 = bundle.objects
        misp_objects = self._check_misp_event_features(event, report)
        self.assertEqual(len(misp_objects), 5)
        nt1, nt2, nt3, artifact, nt4 = misp_objects
        self._check_network_traffic_object_with_packet_sizes(
            nt1, observed_data1, '3', '0', '1', 8
        )
        self.assertEqual(len(nt1.references), 1)
        encapsulates1 = nt1.references[0]
        self.assertEqual(encapsulates1.referenced_uuid, nt2.uuid)
        self._check_network_traffic_object_with_packet_counts(
            nt2, observed_data1, '4', '0', '2', 9
        )
        self.assertEqual(len(nt2.references), 1)
        encapsulated1 = nt2.references[0]
        self.assertEqual(encapsulated1.referenced_uuid, nt1.uuid)
        self._check_network_traffic_object_with_packet_sizes(
            nt3, observed_data2, '3', '0', '1', 9
        )
        self.assertEqual(len(nt3.references), 2)
        payload_ref, encapsulates2 = nt3.references
        self.assertEqual(encapsulates2.referenced_uuid, nt4.uuid)
        self.assertEqual(payload_ref.referenced_uuid, artifact.uuid)
        self.assertEqual(payload_ref.relationship_type, 'source-sent')
        self._check_misp_object_fields(artifact, observed_data2, '5')
        self._check_payload_object_fields(
            artifact, observed_data2.objects['5'], f'{observed_data2.id} - 5'
        )
        self._check_network_traffic_object_with_packet_counts(
            nt4, observed_data2, '4', '1', '2', 10
        )
        self.assertEqual(len(nt4.references), 2)
        payload_ref, encapsulated2 = nt4.references
        self.assertEqual(encapsulated2.referenced_uuid, nt3.uuid)
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

    def test_stix20_bundle_with_process_objects(self):
        bundle = TestExternalSTIX20Bundles.get_bundle_with_process_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data1, observed_data2 = bundle.objects
        misp_objects = self._check_misp_event_features(event, report)
        self.assertEqual(len(misp_objects), 6)
        multiple, image1, parent, child, image2, single = misp_objects
        self._assert_multiple_equal(
            multiple.name, parent.name, child.name, single.name, 'process'
        )
        self._assert_multiple_equal(image1.name, image2.name, 'file')

        self._check_misp_object_fields(multiple, observed_data1, '0')
        self._check_process_multiple_fields(
            multiple, observed_data1.objects['0'], f'{observed_data1.id} - 0'
        )

        self._check_misp_object_fields(image1, observed_data1, '4')
        self._check_process_image_reference_fields(
            image1, observed_data1.objects['4'], f'{observed_data1.id} - 4'
        )

        self._check_misp_object_fields(parent, observed_data1, '1')
        self._check_process_parent_fields(
            parent, observed_data1.objects['1'], f'{observed_data1.id} - 1'
        )

        self._check_misp_object_fields(child, observed_data1, '3')
        self._check_process_child_fields(
            child, observed_data1.objects['3'], f'{observed_data1.id} - 3'
        )

        self._check_misp_object_fields(image2, observed_data1, '2')
        self._check_process_image_reference_fields(
            image2, observed_data1.objects['2'], f'{observed_data1.id} - 2'
        )

        self._check_misp_object_fields(single, observed_data2)
        self._check_process_single_fields(
            single, observed_data2.objects['0'], observed_data2.id
        )

        self._check_process_object_references(
            multiple, parent, child, image1, image2
        )

    def test_stix20_bundle_with_registry_key_objects(self):
        bundle = TestExternalSTIX20Bundles.get_bundle_with_registry_key_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data1, observed_data2 = bundle.objects
        misp_objects = self._check_misp_event_features(event, report)
        self.assertEqual(len(misp_objects), 6)
        multiple1, multiple2, value1, value2, creator_user, single = misp_objects
        self._check_registry_key_object(multiple1, observed_data1, identifier='0')
        self._check_registry_key_object(
            multiple2, observed_data1, value1, value2, identifier='1'
        )
        self._check_registry_key_object(single, observed_data2)
        self._check_misp_object_fields(creator_user, observed_data1, '2')
        self._check_creator_user_fields(
            creator_user, observed_data1.objects['2'],
            f'{observed_data1.id} - 2'
        )
        self.assertEqual(len(creator_user.references), 1)
        reference = creator_user.references[0]
        self.assertEqual(reference.referenced_uuid, multiple2.uuid)
        self.assertEqual(reference.relationship_type, 'creates')
        self._check_registry_key_object(single, observed_data2)

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
        self._check_generic_attribute(observed_data1, m_url1, 'url', '0')
        self._check_generic_attribute(observed_data1, m_url2, 'url', '1')
        self._check_generic_attribute(observed_data2, s_url, 'url')

    def test_stix20_bundle_with_user_account_objects(self):
        bundle = TestExternalSTIX20Bundles.get_bundle_with_user_account_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data1, observed_data2 = bundle.objects
        misp_objects = self._check_misp_event_features(event, report)
        self.assertEqual(len(misp_objects), 3)
        multiple1, multiple2, single = misp_objects
        self._assert_multiple_equal(
            multiple1.name, multiple2.name, single.name, 'user-account'
        )
        self._check_misp_object_fields(multiple1, observed_data1, '0')
        self.assertEqual(len(multiple1.attributes), 11)
        user_account = observed_data1.objects['0']
        object_id = f'{observed_data1.id} - 0'
        self._check_user_account_fields(
            multiple1.attributes[:7], user_account, object_id
        )
        self._check_user_account_timeline_fields(
            multiple1.attributes[7:-1], user_account, object_id
        )
        password_last_changed = multiple1.attributes[-1]
        self.assertEqual(
            password_last_changed.object_relation, 'password_last_changed'
        )
        self.assertEqual(
            password_last_changed.value, user_account.password_last_changed
        )
        self.assertEqual(
            password_last_changed.uuid,
            uuid5(
                UUIDv4,
                f'{object_id} - password_last_changed'
                f' - {password_last_changed.value}'
            )
        )
        self._check_misp_object_fields(multiple2, observed_data1, '1')
        self._check_user_account_twitter_fields(
            multiple2, observed_data1.objects['1'], f'{observed_data1.id} - 1'
        )
        self._check_misp_object_fields(single, observed_data2)
        self.assertEqual(len(single.attributes), 11)
        user_account = observed_data2.objects['0']
        self._check_user_account_fields(
            single.attributes[:7], user_account, observed_data2.id
        )
        self._check_user_account_extension_fields(
            single.attributes[7:], user_account.extensions['unix-account-ext'],
            observed_data2.id
        )

    def test_stix20_bundle_with_wrapped_observable_objects(self):
        bundle = TestExternalSTIX20Bundles.get_bundle_with_wrapped_observable_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        misp_content = self._check_misp_event_features(event, report)
        (artifact1, artifact2, artifact3,
         AS1, AS2, AS3, AS4,
         directory1, directory2, directory3,
         domain1, domain2, domain3,
         domain4, ipv4_1, ipv6_1, domain5,
         email_addr1, email_addr2, email_addr3, email_addr4,
         email_message, email_addr5, email_addr6, email_addr7, artifact4, file1,
         file2, directory4, artifact5, file3, file4, directory5, artifact6, file5,
         ipv4_2, ipv6_2, ipv4_3,
         mac1, mac2, mac3,
         mutex1, mutex2, mutex3,
         ipv4_4, ipv4_5, ipv4_6, nt1, nt2, ipv4_7, ipv4_8, ipv4_9, nt3, nt4, artifact7,
         process1, process2, file6, process3, file7, process4,
         regkey1, regkey2, user1, regkey3,
         software1, software2, software3,
         url1, url2, url3,
         user_account2, user_account3, user_account4,
         x509_cert1, x509_cert2, x509_cert3) = observed_data.objects.keys()
        (ntObj1, ntObj2, ntObj3, artifactObj1, ntObj4,
         emailObj, artifactObj2, fileObj1,
         procObj1, fileObj2, procObj2, procObj3, fileObj3, procObj4,
         fileObj4, dirObj1, artObj3, fileObj5, fileObj6, dirObj2, artObj4, fileObj7, *PEs,
         regkeyObj1, regkeyObj2, valueObj1, valueObj2, userObj1, regkeyObj3,
         artifactObj5, artifactObj6, artifactObj7,
         asnObj1, asnObj2,
         directoryObj3, directoryObj4, directoryObj5,
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
        od_id = observed_data.id

        ########################################################################
        #                       NETWORK TRAFFIC OBJECTS.                       #
        ########################################################################
        self._assert_multiple_equal(
            ntObj1.name, ntObj2.name, ntObj3.name, ntObj4.name,
            'network-traffic'
        )
        nt1_id = f'{od_id} - {nt1}'
        self.assertEqual(ntObj1.uuid, uuid5(UUIDv4, nt1_id))
        self._check_wrapped_network_traffic_object(
            ntObj1, nt1_id, ipv4_4, ipv4_5, (ntObj2.uuid, 'encapsulates')
        )
        nt2_id = f'{od_id} - {nt2}'
        self.assertEqual(ntObj2.uuid, uuid5(UUIDv4, nt2_id))
        self._check_wrapped_network_traffic_object(
            ntObj2, nt2_id, ipv4_4, ipv4_6, (ntObj1.uuid, 'encapsulated-by')
        )
        nt3_id = f'{od_id} - {nt3}'
        self.assertEqual(ntObj3.uuid, uuid5(UUIDv4, nt3_id))
        self._check_wrapped_network_traffic_object(
            ntObj3, nt3_id, ipv4_7, ipv4_8,
            (artifactObj1.uuid, 'source-sent'), (ntObj4.uuid, 'encapsulates')
        )
        nt4_id = f'{od_id} - {nt4}'
        self.assertEqual(ntObj4.uuid, uuid5(UUIDv4, nt4_id))
        self._check_wrapped_network_traffic_object(
            ntObj4, nt4_id, ipv4_8, ipv4_9,
            (artifactObj1.uuid, 'destination-sent'),
            (ntObj3.uuid, 'encapsulated-by')
        )
        artifact1_id = f'{od_id} - {artifact7}'
        self.assertEqual(artifactObj1.name, 'artifact')
        self.assertEqual(artifactObj1.uuid, uuid5(UUIDv4, artifact1_id))
        self._check_wrapped_attributes(artifact1_id, *artifactObj1.attributes)

        ########################################################################
        #                         EMAIL MESSAGE OBJECT                         #
        ########################################################################
        email_id = f'{od_id} - {email_message}'
        self.assertEqual(emailObj.name, 'email')
        self.assertEqual(emailObj.uuid, uuid5(UUIDv4, email_id))
        self._check_wrapped_email_object(
            emailObj, email_id, email_addr5, email_addr6,
            email_addr7, artifactObj2.uuid, fileObj1.uuid
        )
        self.assertEqual(artifactObj2.name, 'artifact')
        artifact2_id = f'{od_id} - {artifact4}'
        self.assertEqual(artifactObj2.uuid, uuid5(UUIDv4, artifact2_id))
        payload_bin, *artifactObj2_attributes = artifactObj2.attributes
        payload_data = self._get_data_value(payload_bin.data)
        self.assertEqual(
            payload_bin.uuid,
            uuid5(UUIDv4, f'{artifact2_id} - payload_bin - {payload_data}')
        )
        self._check_wrapped_attributes(artifact2_id, *artifactObj2_attributes)
        self.assertEqual(fileObj1.name, 'file')
        file1_id = f'{od_id} - {file1}'
        self.assertEqual(fileObj1.uuid, uuid5(UUIDv4, file1_id))
        self._check_wrapped_attributes(file1_id, *fileObj1.attributes)

        ########################################################################
        #                           PROCESS OBJECTS                            #
        ########################################################################
        self._assert_multiple_equal(
            procObj1.name, procObj2.name, procObj3.name,
            procObj4.name, 'process'
        )
        self._assert_multiple_equal(fileObj2.name, fileObj3.name, 'file')
        process1_id = f'{od_id} - {process1}'
        self.assertEqual(procObj1.uuid, uuid5(UUIDv4, process1_id))
        self._check_wrapped_attributes(process1_id, *procObj1.attributes)
        self.assertEqual(len(procObj1.references), 3)
        file_ref, parent_ref, child_ref = procObj1.references
        file_ref.relationship_type = 'executes'
        parent_ref.relationship_type = 'child-of'
        child_ref.relationship_type = 'parent-of'
        process2_id = f'{od_id} - {process2}'
        self._assert_multiple_equal(
            parent_ref.referenced_uuid, procObj2.uuid,
            uuid5(UUIDv4, process2_id)
        )
        self._check_wrapped_attributes(process2_id, *procObj2.attributes)
        self.assertEqual(len(procObj2.references), 1)
        binary_ref = procObj2.references[0]
        binary_ref.relationship_type = 'executes'
        file2_id = f'{od_id} - {file7}'
        self._assert_multiple_equal(
            file_ref.referenced_uuid, fileObj2.uuid, uuid5(UUIDv4, file2_id)
        )
        self._check_wrapped_attributes(file2_id, *fileObj2.attributes)
        process3_id = f'{od_id} - {process3}'
        self._assert_multiple_equal(
            child_ref.referenced_uuid, procObj3.uuid,
            uuid5(UUIDv4, process3_id)
        )
        self._check_wrapped_attributes(process3_id, *procObj3.attributes)
        file3_id = f'{od_id} - {file6}'
        self._assert_multiple_equal(
            binary_ref.referenced_uuid, fileObj3.uuid, uuid5(UUIDv4, file3_id)
        )
        self._check_wrapped_attributes(file3_id, *fileObj3.attributes)
        process4_id = f'{od_id} - {process4}'
        self.assertEqual(procObj4.uuid, uuid5(UUIDv4, process4_id))
        self._check_wrapped_attributes(process4_id, *procObj4.attributes)

        ########################################################################
        #                           FILE OBJECTS                               #
        ########################################################################
        self._assert_multiple_equal(
            fileObj4.name, fileObj5.name, fileObj6.name, fileObj7.name, 'file'
        )
        self._assert_multiple_equal(dirObj1.name, dirObj2.name, 'directory')
        self._assert_multiple_equal(artObj3.name, artObj4.name, 'artifact')
        file4_id = f'{od_id} - {file2}'
        self._check_wrapped_attributes(file4_id, *fileObj4.attributes)
        self.assertEqual(len(fileObj4.references), 1)
        parent_ref = fileObj4.references[0]
        self.assertEqual(parent_ref.relationship_type, 'contained-in')
        directory1_id = f'{od_id} - {directory4}'
        self._assert_multiple_equal(
            parent_ref.referenced_uuid, dirObj1.uuid,
            uuid5(UUIDv4, directory1_id)
        )
        self._check_wrapped_attributes(directory1_id, *dirObj1.attributes)
        artifact3_id = f'{od_id} - {artifact5}'
        self.assertEqual(artObj3.uuid, uuid5(UUIDv4, artifact3_id))
        payload_bin, *artObj3_attributes = artObj3.attributes
        payload_data = self._get_data_value(payload_bin.data)
        self.assertEqual(
            payload_bin.uuid,
            uuid5(UUIDv4, f'{artifact3_id} - payload_bin - {payload_data}')
        )
        self._check_wrapped_attributes(artifact3_id, *artObj3_attributes)
        self.assertEqual(len(artObj3.references), 1)
        content_ref = artObj3.references[0]
        self.assertEqual(content_ref.relationship_type, 'content-of')
        self._assert_multiple_equal(
            content_ref.referenced_uuid, fileObj4.uuid, uuid5(UUIDv4, file4_id)
        )
        file5_id = f'{od_id} - {file3}'
        self.assertEqual(fileObj5.uuid, uuid5(UUIDv4, file5_id))
        self._check_wrapped_attributes(file5_id, *fileObj5.attributes)
        self.assertEqual(len(fileObj5.references), 2)
        contains_file_ref, contains_directory_ref = fileObj5.references
        self._assert_multiple_equal(
            contains_file_ref.relationship_type,
            contains_directory_ref.relationship_type,
            'contains'
        )
        file6_id = f'{od_id} - {file4}'
        self._check_wrapped_attributes(file6_id, *fileObj6.attributes)
        self.assertEqual(len(fileObj6.references), 1)
        parent_ref = fileObj6.references[0]
        self.assertEqual(parent_ref.relationship_type, 'contained-in')
        directory2_id = f'{od_id} - {directory5}'
        self._assert_multiple_equal(
            contains_directory_ref.referenced_uuid, parent_ref.referenced_uuid,
            dirObj2.uuid, uuid5(UUIDv4, directory2_id)
        )
        self._check_wrapped_attributes(directory2_id, *dirObj2.attributes)
        artifact4_id = f'{od_id} - {artifact6}'
        self.assertEqual(artObj4.uuid, uuid5(UUIDv4, artifact4_id))
        payload_bin, *artObj4_attributes = artObj4.attributes
        payload_data = self._get_data_value(payload_bin.data)
        self.assertEqual(
            payload_bin.uuid,
            uuid5(UUIDv4, f'{artifact4_id} - payload_bin - {payload_data}')
        )
        self._check_wrapped_attributes(artifact4_id, *artObj4_attributes)
        self.assertEqual(len(artObj4.references), 1)
        content_ref = artObj4.references[0]
        self.assertEqual(content_ref.relationship_type, 'content-of')
        self._assert_multiple_equal(
            contains_file_ref.referenced_uuid, content_ref.referenced_uuid,
            fileObj6.uuid, uuid5(UUIDv4, file6_id)
        )
        file7_id = f'{od_id} - {file5}'
        self.assertEqual(fileObj7.uuid, uuid5(UUIDv4, file7_id))
        self._check_wrapped_attributes(file7_id, *fileObj7.attributes)
        self.assertEqual(len(fileObj7.references), 1)
        pe_reference = fileObj7.references[0]
        self.assertEqual(pe_reference.relationship_type, 'includes')
        peObj, *sections = PEs
        pe_id = f'{file7_id} - windows-pebinary-ext'
        self.assertEqual(peObj.name, 'pe')
        self._assert_multiple_equal(
            pe_reference.referenced_uuid, peObj.uuid, uuid5(UUIDv4, pe_id)
        )
        self._check_wrapped_attributes(pe_id, *peObj.attributes)
        self.assertEqual(len(peObj.references), len(sections))
        for section_ref, section in zip(peObj.references, enumerate(sections)):
            index, section_object = section
            self.assertEqual(section_ref.relationship_type, 'includes')
            self._assert_multiple_equal(
                section_ref.referenced_uuid, section_object.uuid,
                uuid5(UUIDv4, f'{pe_id} - sections - {index}')
            )
            self.assertEqual(section_object.name, 'pe-section')
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
        regkey1_id = f'{od_id} - {regkey1}'
        self.assertEqual(regkeyObj1.uuid, uuid5(UUIDv4, regkey1_id))
        self._check_wrapped_attributes(regkey1_id, *regkeyObj1.attributes)
        regkey2_id = f'{od_id} - {regkey2}'
        self._check_wrapped_attributes(regkey2_id, *regkeyObj2.attributes)
        self.assertEqual(len(regkeyObj2.references), 2)
        for value_ref, value in zip(regkeyObj2.references, enumerate((valueObj1, valueObj2))):
            self.assertEqual(value_ref.relationship_type, 'contains')
            index, value_object = value
            value_id = f'{regkey2_id} - values - {index}'
            self._assert_multiple_equal(
                value_ref.referenced_uuid, value_object.uuid,
                uuid5(UUIDv4, value_id)
            )
            self._check_wrapped_attributes(value_id, *value_object.attributes)
        self.assertEqual(userObj1.name, 'user-account')
        user1_id = f'{od_id} - {user1}'
        self.assertEqual(userObj1.uuid, uuid5(UUIDv4, user1_id))
        self._check_wrapped_attributes(user1_id, *userObj1.attributes)
        self.assertEqual(len(userObj1.references), 1)
        creates_ref = userObj1.references[0]
        self.assertEqual(creates_ref.relationship_type, 'creates')
        self._assert_multiple_equal(
            creates_ref.referenced_uuid, regkeyObj2.uuid,
            uuid5(UUIDv4, regkey2_id)
        )
        regkey3_id = f'{od_id} - {regkey3}'
        self.assertEqual(regkeyObj3.uuid, uuid5(UUIDv4, regkey3_id))
        self._check_wrapped_attributes(regkey3_id, *regkeyObj3.attributes)

        ########################################################################
        #                           ARTIFACT OBJECTS                           #
        ########################################################################
        self._assert_multiple_equal(
            artifactObj5.name, artifactObj6.name, artifactObj7.name, 'artifact'
        )
        artifact5_id = f'{od_id} - {artifact1}'
        self.assertEqual(artifactObj5.uuid, uuid5(UUIDv4, artifact5_id))
        payload_bin, *artifactObj5_attributes = artifactObj5.attributes
        payload_data = self._get_data_value(payload_bin.data)
        self.assertEqual(
            payload_bin.uuid,
            uuid5(UUIDv4, f'{artifact5_id} - payload_bin - {payload_data}')
        )
        self._check_wrapped_attributes(artifact5_id, *artifactObj5_attributes)
        artifact6_id = f'{od_id} - {artifact2}'
        self.assertEqual(artifactObj6.uuid, uuid5(UUIDv4, artifact6_id))
        self._check_wrapped_attributes(artifact6_id, *artifactObj6.attributes)
        artifact7_id = f'{od_id} - {artifact3}'
        self.assertEqual(artifactObj7.uuid, uuid5(UUIDv4, artifact7_id))
        payload_bin, *artifactObj7_attributes = artifactObj7.attributes
        payload_data = self._get_data_value(payload_bin.data)
        self.assertEqual(
            payload_bin.uuid,
            uuid5(UUIDv4, f'{artifact7_id} - payload_bin - {payload_data}')
        )
        self._check_wrapped_attributes(artifact7_id, md5, *artifactObj7_attributes)

        ########################################################################
        #                      AUTONOMOUS SYSTEM OBJECTS.                      #
        ########################################################################
        self._assert_multiple_equal(asnObj1.name, asnObj2.name, 'asn')
        as1_id = f'{od_id} - {AS1}'
        self.assertEqual(asnObj1.uuid, uuid5(UUIDv4, as1_id))
        self._check_wrapped_attributes(as1_id, *asnObj1.attributes)
        as2_id = f'{od_id} - {AS3}'
        self.assertEqual(asnObj2.uuid, uuid5(UUIDv4, as2_id))
        self._check_wrapped_attributes(as2_id, *asnObj2.attributes)

        ########################################################################
        #                        DIRECTORY OBJECTS.                            #
        ########################################################################
        self._assert_multiple_equal(
            directoryObj3.name, directoryObj4.name,
            directoryObj5.name, 'directory'
        )
        directory3_id = f'{od_id} - {directory1}'
        self.assertEqual(directoryObj3.uuid, uuid5(UUIDv4, directory3_id))
        self._check_wrapped_attributes(directory3_id, *directoryObj3.attributes)
        directory4_id = f'{od_id} - {directory2}'
        self.assertEqual(directoryObj4.uuid, uuid5(UUIDv4, directory4_id))
        self._check_wrapped_attributes(directory4_id, *directoryObj4.attributes)
        directory5_id = f'{od_id} - {directory3}'
        self.assertEqual(directoryObj5.uuid, uuid5(UUIDv4, directory5_id))
        self._check_wrapped_attributes(directory5_id, *directoryObj5.attributes)

        ########################################################################
        #                           DOMAIN-IP OBJECT                           #
        ########################################################################
        self._assert_multiple_equal(
            domainIpObj1.name, domainIpObj2.name, 'domain-ip'
        )
        domainIp1_id = f'{od_id} - {domain4}'
        self.assertEqual(domainIpObj1.uuid, uuid5(UUIDv4, domainIp1_id))
        domainAttribute1, ipAttribute1, ipAttribute2 = domainIpObj1.attributes
        self.assertEqual(
            domainAttribute1.uuid,
            uuid5(UUIDv4, f'{domainIp1_id} - domain - {domainAttribute1.value}')
        )
        self.assertEqual(
            ipAttribute1.uuid,
            uuid5(
                UUIDv4,
                f'{domainIp1_id} - {ipv4_1} - ip - {ipAttribute1.value}'
            )
        )
        self.assertEqual(
            ipAttribute2.uuid,
            uuid5(
                UUIDv4,
                f'{domainIp1_id} - {ipv6_1} - ip - {ipAttribute2.value}'
            )
        )
        domainIp2_id = f'{od_id} - {domain5}'
        self.assertEqual(domainIpObj2.uuid, uuid5(UUIDv4, domainIp2_id))
        self.assertEqual(len(domainIpObj2.attributes), 1)
        domainAttribute2 = domainIpObj2.attributes[0]
        self.assertEqual(
            domainAttribute2.uuid,
            uuid5(UUIDv4, f'{domainIp2_id} - domain - {domainAttribute2.value}')
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
        software1_id = f'{od_id} - {software1}'
        self.assertEqual(softwareObj1.uuid, uuid5(UUIDv4, software1_id))
        self._check_wrapped_attributes(software1_id, *softwareObj1.attributes)
        software2_id = f'{od_id} - {software2}'
        self.assertEqual(softwareObj2.uuid, uuid5(UUIDv4, software2_id))
        self._check_wrapped_attributes(software2_id, *softwareObj2.attributes)
        software3_id = f'{od_id} - {software3}'
        self.assertEqual(softwareObj3.uuid, uuid5(UUIDv4, software3_id))
        self._check_wrapped_attributes(software3_id, *softwareObj3.attributes)

        ########################################################################
        #                         USER-ACCOUNT OBJECTS                         #
        ########################################################################
        self._assert_multiple_equal(
            userObj2.name, userObj3.name, userObj4.name, 'user-account'
        )
        user_account2_id = f'{od_id} - {user_account2}'
        self.assertEqual(userObj2.uuid, uuid5(UUIDv4, user_account2_id))
        self._check_wrapped_attributes(user_account2_id, *userObj2.attributes)
        user_account3_id = f'{od_id} - {user_account3}'
        self.assertEqual(userObj3.uuid, uuid5(UUIDv4, user_account3_id))
        self._check_wrapped_attributes(user_account3_id, *userObj3.attributes)
        user_account4_id = f'{od_id} - {user_account4}'
        self.assertEqual(userObj4.uuid, uuid5(UUIDv4, user_account4_id))
        self._check_wrapped_attributes(user_account4_id, *userObj4.attributes)

        ########################################################################
        #                             X509 OBJECTS                             #
        ########################################################################
        self._assert_multiple_equal(
            x509Obj1.name, x509Obj2.name, x509Obj3.name, 'x509'
        )
        x509_1_id = f'{od_id} - {x509_cert1}'
        self.assertEqual(x509Obj1.uuid, uuid5(UUIDv4, x509_1_id))
        self._check_wrapped_attributes(x509_1_id, *x509Obj1.attributes)
        x509_2_id = f'{od_id} - {x509_cert2}'
        self.assertEqual(x509Obj2.uuid, uuid5(UUIDv4, x509_2_id))
        self._check_wrapped_attributes(x509_2_id, *x509Obj2.attributes)
        x509_3_id = f'{od_id} - {x509_cert3}'
        self.assertEqual(x509Obj3.uuid, uuid5(UUIDv4, x509_3_id))
        self._check_wrapped_attributes(x509_3_id, *x509Obj3.attributes)

        ########################################################################
        #                     AUTONOMOUS SYSTEM ATTRIBUTES                     #
        ########################################################################
        self._assert_multiple_equal(asAttr1.type, asAttr2.type, 'AS')
        self.assertEqual(asAttr1.uuid, uuid5(UUIDv4, f'{od_id} - {AS2}'))
        self.assertEqual(asAttr2.uuid, uuid5(UUIDv4, f'{od_id} - {AS4}'))

        ########################################################################
        #                          DOMAIN ATTRIBUTES.                          #
        ########################################################################
        self._assert_multiple_equal(
            domainAttr1.type, domainAttr2.type, domainAttr3.type, 'domain'
        )
        self.assertEqual(
            domainAttr1.uuid, uuid5(UUIDv4, f'{od_id} - {domain1}')
        )
        self.assertEqual(
            domainAttr2.uuid, uuid5(UUIDv4, f'{od_id} - {domain2}')
        )
        self.assertEqual(
            domainAttr3.uuid, uuid5(UUIDv4, f'{od_id} - {domain3}')
        )

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
        email1_id = f'{od_id} - {email_addr1}'
        self.assertEqual(
            emailAttr1.uuid,
            uuid5(UUIDv4, f'{email1_id} - email - {emailAttr1.value}')
        )
        self.assertEqual(
            dnAttr1.uuid,
            uuid5(
                UUIDv4,
                f'{email1_id} - email-dst-display-name - {dnAttr1.value}'
            )
        )
        self.assertEqual(
            emailAttr2.uuid, uuid5(UUIDv4, f'{od_id} - {email_addr2}')
        )
        email3_id = f'{od_id} - {email_addr3}'
        self.assertEqual(
            emailAttr3.uuid,
            uuid5(UUIDv4, f'{email3_id} - email - {emailAttr3.value}')
        )
        self.assertEqual(
            dnAttr2.uuid,
            uuid5(
                UUIDv4,
                f'{email3_id} - email-dst-display-name - {dnAttr2.value}'
            )
        )
        self.assertEqual(
            emailAttr4.uuid, uuid5(UUIDv4, f'{od_id} - {email_addr4}')
        )

        ########################################################################
        #                            IP ATTRIBUTES.                            #
        ########################################################################
        self._assert_multiple_equal(
            ipAttr1.type, ipAttr2.type, ipAttr3.type, 'ip-dst'
        )
        self.assertEqual(ipAttr1.uuid, uuid5(UUIDv4, f'{od_id} - {ipv4_2}'))
        self.assertEqual(ipAttr2.uuid, uuid5(UUIDv4, f'{od_id} - {ipv4_3}'))
        self.assertEqual(ipAttr3.uuid, uuid5(UUIDv4, f'{od_id} - {ipv6_2}'))

        ########################################################################
        #                            MAC ATTRIBUTES                            #
        ########################################################################
        self._assert_multiple_equal(
            macAttr1.type, macAttr2.type, macAttr3.type, 'mac-address'
        )
        self.assertEqual(macAttr1.uuid, uuid5(UUIDv4, f'{od_id} - {mac1}'))
        self.assertEqual(macAttr2.uuid, uuid5(UUIDv4, f'{od_id} - {mac2}'))
        self.assertEqual(macAttr3.uuid, uuid5(UUIDv4, f'{od_id} - {mac3}'))

        ########################################################################
        #                           MUTEX ATTRIBUTES                           #
        ########################################################################
        self._assert_multiple_equal(
            mutexAttr1.type, mutexAttr2.type, mutexAttr3.type, 'mutex'
        )
        self.assertEqual(mutexAttr1.uuid, uuid5(UUIDv4, f'{od_id} - {mutex1}'))
        self.assertEqual(mutexAttr2.uuid, uuid5(UUIDv4, f'{od_id} - {mutex2}'))
        self.assertEqual(mutexAttr3.uuid, uuid5(UUIDv4, f'{od_id} - {mutex3}'))

        ########################################################################
        #                            URL ATTRIBUTES                            #
        ########################################################################
        self._assert_multiple_equal(
            urlAttr1.type, urlAttr2.type, urlAttr3.type, 'url'
        )
        self.assertEqual(urlAttr1.uuid, uuid5(UUIDv4, f'{od_id} - {url1}'))
        self.assertEqual(urlAttr2.uuid, uuid5(UUIDv4, f'{od_id} - {url2}'))
        self.assertEqual(urlAttr3.uuid, uuid5(UUIDv4, f'{od_id} - {url3}'))

    def test_stix20_bundle_with_x509_objects(self):
        bundle = TestExternalSTIX20Bundles.get_bundle_with_x509_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data1, observed_data2 = bundle.objects
        misp_objects = self._check_misp_event_features(event, report)
        self.assertEqual(len(misp_objects), 3)
        multiple1, multiple2, single = misp_objects
        self._check_x509_object(multiple1, observed_data1, '0')
        self._check_x509_object(multiple2, observed_data1, '1')
        self._check_x509_object(single, observed_data2)
