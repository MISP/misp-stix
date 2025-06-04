#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .test_external_stix20_bundles import TestExternalSTIX20Bundles
from ._test_stix import TestSTIX20
from ._test_stix_import import TestExternalSTIX2Import, TestSTIX20Import
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
            event_report.uuid,
            uuid5(self._UUIDv4, f'description - {report.id}')
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
        self.assertEqual(meta['first_seen'], event_campaign.first_seen)
        self.assertEqual(len(event.attributes), 1)
        attribute = event.attributes[0]
        self.assertEqual(attribute.uuid, indicator.id.split('--')[1])
        meta = self._check_galaxy_features(attribute.galaxies, attribute_campaign)
        self.assertEqual(
            meta,
            {
                'first_seen': attribute_campaign.first_seen,
                'created': attribute_campaign.created,
                'modified': attribute_campaign.modified
            }
        )

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
            section_id = f'windows-pebinary-ext - section - {index}'
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
                self._UUIDv4,
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
                uuid5(self._UUIDv4, f'{observed_data.id} - {identifier}')
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
            uuid5(
                self._UUIDv4,
                f'{object_id} - src_port - {src_port.value}'
            )
        )
        self.assertEqual(dst_port.type, 'port')
        self.assertEqual(dst_port.object_relation, 'dst_port')
        self.assertEqual(dst_port.value, network_traffic.dst_port)
        self.assertEqual(
            dst_port.uuid,
            uuid5(
                self._UUIDv4,
                f'{object_id} - dst_port - {dst_port.value}'
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
                    f'{object_id} - protocol - {protocol_value}'
                )
            )
        self.assertEqual(ip_src.type, 'ip-src')
        self.assertEqual(ip_src.object_relation, 'src_ip')
        self.assertEqual(ip_src.value, src_ip.value)
        self.assertEqual(
            ip_src.uuid,
            uuid5(
                self._UUIDv4,
                f'{object_id} - {src_ip_id} - src_ip - {src_ip.value}'
            )
        )
        self.assertEqual(ip_dst.type, 'ip-dst')
        self.assertEqual(ip_dst.object_relation, 'dst_ip')
        self.assertEqual(ip_dst.value, dst_ip.value)
        self.assertEqual(
            ip_dst.uuid,
            uuid5(
                self._UUIDv4,
                f'{object_id} - {dst_ip_id} - dst_ip - {dst_ip.value}'
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
            uuid5(
                self._UUIDv4,
                f'{object_id} - src_packets - {src_packets.value}'
            )
        )
        self.assertEqual(dst_packets.type, 'counter')
        self.assertEqual(dst_packets.object_relation, 'dst_packets')
        self.assertEqual(dst_packets.value, network_traffic.dst_packets)
        self.assertEqual(
            dst_packets.uuid,
            uuid5(
                self._UUIDv4,
                f'{object_id} - dst_packets - {dst_packets.value}'
            )
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
            uuid5(
                self._UUIDv4,
                f'{object_id} - src_byte_count - {src_bytes.value}'
            )
        )
        self.assertEqual(dst_bytes.type, 'size-in-bytes')
        self.assertEqual(dst_bytes.object_relation, 'dst_byte_count')
        self.assertEqual(dst_bytes.value, network_traffic.dst_byte_count)
        self.assertEqual(
            dst_bytes.uuid,
            uuid5(
                self._UUIDv4,
                f'{object_id} - dst_byte_count - {dst_bytes.value}'
            )
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

    def test_stix20_bundle_with_domain_ip_objects(self):
        bundle = TestExternalSTIX20Bundles.get_bundle_with_domain_ip_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data = bundle.objects
        misp_object = self._check_misp_event_features(event, report)
        self.assertEqual(len(misp_object), 1)
        domain_ip_object = misp_object[0]
        self.assertEqual(domain_ip_object.name, 'domain-ip')
        self._check_misp_object_fields(
            domain_ip_object, observed_data, '0 - 1 - 2'
        )
        object_id = f'{observed_data.id} - 0'
        self._check_domain_ip_fields(
            domain_ip_object, *observed_data.objects.values(),
            object_id, f'{object_id} - 1', f'{object_id} - 2'
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
        self.assertEqual(len(file1.references), 1)
        file_reference = file1.references[0]
        self.assertEqual(file_reference.referenced_uuid, directory1.uuid)
        self.assertEqual(file_reference.relationship_type, 'contained-in')
        self.assertEqual(len(artifact1.references), 1)
        artifact_reference = artifact1.references[0]
        self.assertEqual(artifact_reference.referenced_uuid, file1.uuid)
        self.assertEqual(artifact_reference.relationship_type, 'content-of')
        self._check_archive_file_object(
            zip_file, observed_data2, observed_data2.objects['0'],
            f'{observed_data2.id} - 0'
        )
        self.assertEqual(len(zip_file.references), 2)
        directory_reference, file_reference = zip_file.references
        self.assertEqual(
            directory_reference.referenced_uuid, file2.uuid
        )
        self.assertEqual(directory_reference.relationship_type, 'contains')
        self.assertEqual(file_reference.referenced_uuid, directory2.uuid)
        self.assertEqual(file_reference.relationship_type, 'contains')
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

    def test_stix20_bundle_with_network_traffic_objects(self):
        bundle = TestExternalSTIX20Bundles.get_bundle_with_network_traffic_objects()
        self.parser.load_stix_bundle(bundle)
        self.parser.parse_stix_bundle()
        event = self.parser.misp_event
        _, report, observed_data1, observed_data2 = bundle.objects
        misp_objects = self._check_misp_event_features(event, report)
        self.assertEqual(len(misp_objects), 4)
        nt1, nt2, nt3, nt4 = misp_objects
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
        self.assertEqual(len(nt3.references), 1)
        encapsulates2 = nt3.references[0]
        self.assertEqual(encapsulates2.referenced_uuid, nt4.uuid)
        self._check_network_traffic_object_with_packet_counts(
            nt4, observed_data2, '4', '1', '2', 10
        )
        self.assertEqual(len(nt4.references), 1)
        encapsulated2 = nt4.references[0]
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
        multiple, parent, child, image1, image2, single = misp_objects
        self._assert_multiple_equal(
            multiple.name, parent.name, child.name, single.name, 'process'
        )
        self._assert_multiple_equal(image1.name, image2.name, 'file')

        self._check_misp_object_fields(multiple, observed_data1, '0')
        self._check_process_multiple_fields(
            multiple, observed_data1.objects['0'], f'{observed_data1.id} - 0'
        )
        self.assertEqual(len(multiple.references), 3)
        child_ref, parent_ref, binary_ref = multiple.references
        self.assertEqual(child_ref.referenced_uuid, parent.uuid)
        self.assertEqual(child_ref.relationship_type, 'child-of')
        self.assertEqual(parent_ref.referenced_uuid, child.uuid)
        self.assertEqual(parent_ref.relationship_type, 'parent-of')
        self.assertEqual(binary_ref.referenced_uuid, image1.uuid)
        self.assertEqual(binary_ref.relationship_type, 'executes')

        self._check_misp_object_fields(parent, observed_data1, '1')
        self._check_process_parent_fields(
            parent, observed_data1.objects['1'], f'{observed_data1.id} - 1'
        )
        self.assertEqual(len(parent.references), 1)
        reference = parent.references[0]
        self.assertEqual(reference.referenced_uuid, image2.uuid)
        self.assertEqual(reference.relationship_type, 'executes')

        self._check_misp_object_fields(child, observed_data1, '3')
        self._check_process_child_fields(
            child, observed_data1.objects['3'], f'{observed_data1.id} - 3'
        )

        self._check_misp_object_fields(image2, observed_data1, '2')
        self._check_process_image_reference_fields(
            image2, observed_data1.objects['2'], f'{observed_data1.id} - 2'
        )

        self._check_misp_object_fields(image1, observed_data1, '4')
        self._check_process_image_reference_fields(
            image1, observed_data1.objects['4'], f'{observed_data1.id} - 4'
        )

        self._check_misp_object_fields(single, observed_data2)
        self._check_process_single_fields(
            single, observed_data2.objects['0'], observed_data2.id
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
        self._check_generic_attribute(
            observed_data1, m_url1, 'url', '0'
        )
        self._check_generic_attribute(
            observed_data1, m_url2, 'url', '1'
        )
        self._check_generic_attribute(
            observed_data2, s_url, 'url'
        )

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
                self._UUIDv4,
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
