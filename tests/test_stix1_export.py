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

    def _check_embedded_features(self, embedded_object, cluster, name, feature='title'):
        self.assertEqual(embedded_object.id_, f"{_DEFAULT_NAMESPACE}:{name}-{cluster['uuid']}")
        self.assertEqual(getattr(embedded_object, feature), cluster['value'])
        self.assertEqual(embedded_object.description.value, cluster['description'])

    def _check_identity_features(self, identity, attribute):
        self.assertEqual(identity.id_, f"{_DEFAULT_NAMESPACE}:Identity-{attribute['uuid']}")
        self.assertEqual(identity.name, f"{attribute['category']}: {attribute['value']} (MISP Attribute)")

    def _check_indicator_features(self, related_indicator, attribute, orgc):
        self.assertEqual(related_indicator.relationship, attribute['category'])
        indicator = related_indicator.item
        self.assertEqual(indicator.id_, f"{_DEFAULT_NAMESPACE}:Indicator-{attribute['uuid']}")
        self.assertEqual(indicator.title, f"{attribute['category']}: {attribute['value']} (MISP Attribute)")
        self.assertEqual(indicator.description.value, attribute['comment'])
        self.assertEqual(int(indicator.timestamp.timestamp()), int(attribute['timestamp']))
        self.assertEqual(indicator.producer.identity.name, orgc)
        return indicator

    def _check_observable_features(self, observable, attribute, name):
        self.assertEqual(observable.id_, f"{_DEFAULT_NAMESPACE}:Observable-{attribute['uuid']}")
        observable_object = observable.object_
        self.assertEqual(observable_object.id_, f"{_DEFAULT_NAMESPACE}:{name}-{attribute['uuid']}")
        properties = observable_object.properties
        self.assertEqual(properties._XSI_TYPE, f'{name}ObjectType')
        return properties

    def _check_related_ttp(self, stix_package, galaxy_name, cluster_uuid):
        related_ttp = stix_package.incidents[0].leveraged_ttps.ttp[0]
        self.assertEqual(related_ttp.relationship.value, galaxy_name)
        self.assertEqual(related_ttp.item.idref, f"{_DEFAULT_NAMESPACE}:TTP-{cluster_uuid}")

    def _check_source_address(self, properties, category='ipv4-addr'):
        self.assertEqual(properties.category, category)
        self.assertTrue(properties.is_source)
        self.assertFalse(properties.is_destination)

    def _check_ttp_fields_from_attribute(self, stix_package, attribute):
        ttp = self._check_ttp_length(stix_package)
        self.assertEqual(ttp.id_, f"{_DEFAULT_NAMESPACE}:TTP-{attribute['uuid']}")
        self.assertEqual(ttp.title, f"{attribute['category']}: {attribute['value']} (MISP Attribute)")
        return ttp

    def _check_ttp_fields_from_galaxy(self, stix_package, cluster_uuid, galaxy_name):
        ttp = self._check_ttp_length(stix_package)
        self.assertEqual(ttp.id_, f"{_DEFAULT_NAMESPACE}:TTP-{cluster_uuid}")
        self.assertEqual(ttp.title, f"{galaxy_name} (MISP Galaxy)")
        return ttp

    def _check_ttp_length(self, stix_package):
        self.assertEqual(len(stix_package.ttps.ttp), 1)
        return stix_package.ttps.ttp[0]

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
        properties = self._check_observable_features(
            observable.item,
            attribute,
            'AS'
        )
        self.assertEqual(properties.handle.value, attribute['value'])

    def test_event_with_attachment_attribute(self):
        event = get_event_with_attachment_attribute()
        attribute = event['Event']['Attribute'][0]
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        observable = incident.related_observables.observable[0]
        self.assertEqual(observable.relationship, attribute['category'])
        self.assertEqual(observable.item.title, attribute['value'])
        properties = self._check_observable_features(observable.item, attribute, 'Artifact')
        self.assertEqual(properties.raw_artifact.value, attribute['data'])

    def test_event_with_domain_attribute(self):
        event = get_event_with_domain_attribute()
        attribute = event['Event']['Attribute'][0]
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_features(related_indicator, attribute, orgc)
        properties = self._check_observable_features(indicator.observable, attribute, 'DomainName')
        self.assertEqual(properties.value.value, attribute['value'])

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
        domain_name, address = observable.observable_composition.observables
        domain, ip = attribute['value'].split('|')
        domain_properties = self._check_observable_features(domain_name, attribute, 'DomainName')
        self.assertEqual(domain_properties.value.value, domain)
        address_properties = self._check_observable_features(address, attribute, 'Address')
        self.assertEqual(address_properties.address_value.value, ip)
        self._check_destination_address(address_properties)

    def test_event_with_email_attachment_attribute(self):
        event = get_event_with_email_attachment_attribute()
        attribute = event['Event']['Attribute'][0]
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_features(related_indicator, attribute, orgc)
        properties = self._check_observable_features(indicator.observable, attribute, 'EmailMessage')
        referenced_uuid = f"{_DEFAULT_NAMESPACE}:File-{attribute['uuid']}"
        self.assertEqual(properties.attachments[0].object_reference, referenced_uuid)
        related_object = indicator.observable.object_.related_objects[0]
        self.assertEqual(related_object.id_, referenced_uuid)
        self.assertEqual(related_object.properties.file_name.value, attribute['value'])
        self.assertEqual(related_object.relationship.value, 'Contains')

    def test_event_with_email_attributes(self):
        event = get_event_with_email_attributes()
        source, destination, subject, reply_to = event['Event']['Attribute']
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        src_indicator, dst_indicator = incident.related_indicators.indicator
        source_indicator = self._check_indicator_features(src_indicator, source, orgc)
        source_properties = self._check_observable_features(
            source_indicator.observable,
            source,
            'EmailMessage'
        )
        self.assertEqual(source_properties.from_.address_value.value, source['value'])
        self.assertEqual(source_properties.from_.category, 'e-mail')
        destination_indicator = self._check_indicator_features(dst_indicator, destination, orgc)
        destination_properties = self._check_observable_features(
            destination_indicator.observable,
            destination,
            'EmailMessage'
        )
        self.assertEqual(destination_properties.to[0].address_value.value, destination['value'])
        self.assertEqual(destination_properties.to[0].category, 'e-mail')
        subject_observable, reply_to_observable = incident.related_observables.observable
        subject_properties = self._check_observable_features(
            subject_observable.item,
            subject,
            'EmailMessage'
        )
        self.assertEqual(subject_properties.subject.value, subject['value'])
        reply_to_properties = self._check_observable_features(
            reply_to_observable.item,
            reply_to,
            'EmailMessage'
        )
        self.assertEqual(reply_to_properties.reply_to.address_value.value, reply_to['value'])
        self.assertEqual(reply_to_properties.reply_to.category, 'e-mail')

    def test_event_with_filename_attribute(self):
        event = get_event_with_filename_attribute()
        attribute = event['Event']['Attribute'][0]
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_features(related_indicator, attribute, orgc)
        properties = self._check_observable_features(indicator.observable, attribute, 'File')
        self.assertEqual(properties.file_name.value, attribute['value'])

    def test_event_with_hash_attributes(self):
        event = get_event_with_hash_attributes()
        md5, tlsh = event['Event']['Attribute']
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        md5_r_indicator, tlsh_r_indicator = incident.related_indicators.indicator
        md5_indicator = self._check_indicator_features(md5_r_indicator, md5, orgc)
        md5_properties = self._check_observable_features(md5_indicator.observable, md5, 'File')
        self.assertEqual(md5_properties.hashes[0].type_.value, 'MD5')
        self.assertEqual(md5_properties.hashes[0].simple_hash_value.value, md5['value'])
        tlsh_indicator = self._check_indicator_features(tlsh_r_indicator, tlsh, orgc)
        tlsh_properties = self._check_observable_features(tlsh_indicator.observable, tlsh, 'File')
        self.assertEqual(tlsh_properties.hashes[0].type_.value, 'Other')
        self.assertEqual(tlsh_properties.hashes[0].simple_hash_value.value, tlsh['value'])

    def test_event_with_hash_composite_attributes(self):
        event = get_event_with_hash_composite_attributes()
        md5, tlsh = event['Event']['Attribute']
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        md5_r_indicator, tlsh_r_indicator = incident.related_indicators.indicator
        md5_indicator = self._check_indicator_features(md5_r_indicator, md5, orgc)
        md5_properties = self._check_observable_features(md5_indicator.observable, md5, 'File')
        filename, md5_value = md5['value'].split('|')
        self.assertEqual(md5_properties.file_name.value, filename)
        self.assertEqual(md5_properties.hashes[0].type_.value, 'MD5')
        self.assertEqual(md5_properties.hashes[0].simple_hash_value.value, md5_value)
        tlsh_indicator = self._check_indicator_features(tlsh_r_indicator, tlsh, orgc)
        tlsh_properties = self._check_observable_features(tlsh_indicator.observable, tlsh, 'File')
        filename, tlsh_value = tlsh['value'].split('|')
        self.assertEqual(tlsh_properties.file_name.value, filename)
        self.assertEqual(tlsh_properties.hashes[0].type_.value, 'Other')
        self.assertEqual(tlsh_properties.hashes[0].simple_hash_value.value, tlsh_value)

    def test_event_with_hostname_attribute(self):
        event = get_event_with_hostname_attribute()
        attribute = event['Event']['Attribute'][0]
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_features(related_indicator, attribute, orgc)
        properties = self._check_observable_features(indicator.observable, attribute, 'Hostname')
        self.assertEqual(properties.hostname_value.value, attribute['value'])

    def test_event_with_hostname_port_attribute(self):
        event = get_event_with_hostname_port_attribute()
        attribute = event['Event']['Attribute'][0]
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_features(related_indicator, attribute, orgc)
        properties = self._check_observable_features(indicator.observable, attribute, 'SocketAddress')
        hostname, port = attribute['value'].split('|')
        self.assertEqual(properties.hostname.hostname_value.value, hostname)
        self.assertEqual(properties.port.port_value.value, int(port))

    def test_event_with_http_attributes(self):
        event = get_event_with_http_attributes()
        http_method, user_agent = event['Event']['Attribute']
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        r_http_method, r_user_agent = incident.related_observables.observable
        self.assertEqual(r_http_method.relationship, http_method['category'])
        http_method_properties = self._check_observable_features(
            r_http_method.item,
            http_method,
            'HTTPSession'
        )
        request_response = http_method_properties.http_request_response[0]
        self.assertEqual(
            request_response.http_client_request.http_request_line.http_method.value,
            http_method['value']
        )
        self.assertEqual(r_user_agent.relationship, user_agent['category'])
        user_agent_properties = self._check_observable_features(
            r_user_agent.item,
            user_agent,
            'HTTPSession'
        )
        request = user_agent_properties.http_request_response[0].http_client_request
        self.assertEqual(
            request.http_request_header.parsed_header.user_agent.value,
            user_agent['value']
        )

    def test_event_with_ip_attributes(self):
        event = get_event_with_ip_attributes()
        ip_src, ip_dst = event['Event']['Attribute']
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_src, related_dst = incident.related_indicators.indicator
        src_indicator = self._check_indicator_features(related_src, ip_src, orgc)
        src_properties = self._check_observable_features(src_indicator.observable, ip_src, 'Address')
        self.assertEqual(src_properties.address_value.value, ip_src['value'])
        self._check_source_address(src_properties)
        dst_indicator = self._check_indicator_features(related_dst, ip_dst, orgc)
        dst_properties = self._check_observable_features(dst_indicator.observable, ip_dst, 'Address')
        self.assertEqual(dst_properties.address_value.value, ip_dst['value'])
        self._check_destination_address(dst_properties)

    def test_event_with_ip_port_attributes(self):
        event = get_event_with_ip_port_attributes()
        ip_src, ip_dst = event['Event']['Attribute']
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_src, related_dst = incident.related_indicators.indicator
        src_indicator = self._check_indicator_features(related_src, ip_src, orgc)
        src_properties = self._check_observable_features(src_indicator.observable, ip_src, 'SocketAddress')
        ip, port = ip_src['value'].split('|')
        self.assertEqual(src_properties.port.port_value.value, int(port))
        self.assertEqual(src_properties.ip_address.address_value.value, ip)
        self._check_source_address(src_properties.ip_address)
        dst_indicator = self._check_indicator_features(related_dst, ip_dst, orgc)
        dst_properties = self._check_observable_features(dst_indicator.observable, ip_dst, 'SocketAddress')
        ip, port = ip_dst['value'].split('|')
        self.assertEqual(dst_properties.port.port_value.value, int(port))
        self.assertEqual(dst_properties.ip_address.address_value.value, ip)
        self._check_destination_address(dst_properties.ip_address)

    def test_event_with_mac_address_attribute(self):
        event = get_event_with_mac_address_attribute()
        attribute = event['Event']['Attribute'][0]
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        observable = incident.related_observables.observable[0]
        self.assertEqual(observable.relationship, attribute['category'])
        properties = self._check_observable_features(observable.item, attribute, 'System')
        self.assertEqual(properties.network_interface_list[0].mac, attribute['value'])

    def test_event_with_malware_sample_attribute(self):
        event = get_event_with_malware_sample_attribute()
        attribute = event['Event']['Attribute'][0]
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_features(related_indicator, attribute, orgc)
        filename, md5 = attribute['value'].split('|')
        self.assertEqual(indicator.observable.title, filename)
        properties = self._check_observable_features(indicator.observable, attribute, 'Artifact')
        self.assertEqual(properties.raw_artifact.value, attribute['data'])
        self.assertEqual(properties.hashes[0].type_.value, 'MD5')
        self.assertEqual(properties.hashes[0].simple_hash_value.value, md5)

    def test_event_with_mutex_attribute(self):
        event = get_event_with_mutex_attribute()
        attribute = event['Event']['Attribute'][0]
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_features(related_indicator, attribute, orgc)
        properties = self._check_observable_features(indicator.observable, attribute, 'Mutex')
        self.assertEqual(properties.name.value, attribute['value'])

    def test_event_with_named_pipe_attribute(self):
        event = get_event_with_named_pipe_attribute()
        attribute = event['Event']['Attribute'][0]
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        observable = incident.related_observables.observable[0]
        self.assertEqual(observable.relationship, attribute['category'])
        properties = self._check_observable_features(observable.item, attribute, 'Pipe')
        self.assertTrue(properties.named)
        self.assertEqual(properties.name.value, attribute['value'])

    def test_event_with_pattern_attribute(self):
        event = get_event_with_pattern_attribute()
        attribute = event['Event']['Attribute'][0]
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_features(related_indicator, attribute, orgc)
        properties = self._check_observable_features(indicator.observable, attribute, 'File')
        self.assertEqual(properties.byte_runs[0].byte_run_data, attribute['value'])

    def test_event_with_port_attribute(self):
        event = get_event_with_port_attribute()
        attribute = event['Event']['Attribute'][0]
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        observable = incident.related_observables.observable[0]
        self.assertEqual(observable.relationship, attribute['category'])
        properties = self._check_observable_features(observable.item, attribute, 'Port')
        self.assertEqual(properties.port_value.value, int(attribute['value']))

    def test_event_with_regkey_attribute(self):
        event = get_event_with_regkey_attribute()
        attribute = event['Event']['Attribute'][0]
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_features(related_indicator, attribute, orgc)
        properties = self._check_observable_features(
            indicator.observable,
            attribute,
            'WindowsRegistryKey'
        )
        self.assertEqual(properties.key.value, attribute['value'])

    def test_event_with_regkey_value_attribute(self):
        event = get_event_with_regkey_value_attribute()
        attribute = event['Event']['Attribute'][0]
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_features(related_indicator, attribute, orgc)
        properties = self._check_observable_features(
            indicator.observable,
            attribute,
            'WindowsRegistryKey'
        )
        regkey, value = attribute['value'].split('|')
        self.assertEqual(properties.key.value, regkey)
        self.assertEqual(properties.values[0].data.value, value)

    def test_event_with_target_attributes(self):
        event = get_event_with_target_attributes()
        email, external, location, machine, org, user = event['Event']['Attribute']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        self.assertEqual(
            incident.affected_assets[0].description.value,
            f"{machine['value']} ({machine['comment']})"
        )
        email_victim, external_victim, victim_location, victim_org, victim_user = incident.victims
        self._check_identity_features(email_victim, email)
        self.assertEqual(
            email_victim.specification.electronic_address_identifiers[0].value,
            email['value']
        )
        self._check_identity_features(external_victim, external)
        self.assertEqual(
            external_victim.specification.party_name.name_lines[0].value,
            f"External target: {external['value']}"
        )
        self._check_identity_features(victim_location, location)
        self.assertEqual(
            victim_location.specification.addresses[0].free_text_address.address_lines[0],
            location['value']
        )
        self._check_identity_features(victim_org, org)
        self.assertEqual(
            victim_org.specification.party_name.organisation_names[0].name_elements[0].value,
            org['value']
        )
        self._check_identity_features(victim_user, user)
        self.assertEqual(
            victim_user.specification.party_name.person_names[0].name_elements[0].value,
            user['value']
        )

    def test_event_with_test_mechanism_attributes(self):
        event = get_event_with_test_mechanism_attributes()
        snort, yara = event['Event']['Attribute']
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        r_snort, r_yara = incident.related_indicators.indicator
        snort_indicator = self._check_indicator_features(r_snort, snort, orgc)
        snort_tm = snort_indicator.test_mechanisms[0]
        self.assertEqual(snort_tm._XSI_TYPE, 'snortTM:SnortTestMechanismType')
        self.assertEqual(snort_tm.rules[0].value['value'], snort['value'])
        yara_indicator = self._check_indicator_features(r_yara, yara, orgc)
        yara_tm = yara_indicator.test_mechanisms[0]
        self.assertEqual(yara_tm._XSI_TYPE, 'yaraTM:YaraTestMechanismType')
        self.assertEqual(yara_tm.rule.value['value'], yara['value'])

    def test_event_with_undefined_attributes(self):
        event = get_event_with_undefined_attributes()
        header, comment = event['Event']['Attribute']
        self.parser.parse_misp_event(event, '1.1.1')
        stix_package = self.parser.stix_package
        self.assertEqual(stix_package.stix_header.description.value, header['value'])
        incident = self.parser.stix_package.incidents[0]
        journal_entry = incident.history.history_items[0].journal_entry
        self.assertEqual(journal_entry.value, f"Attribute ({comment['category']} - {comment['type']}): {comment['value']}")

    def test_event_with_url_attribute(self):
        event = get_event_with_url_attribute()
        attribute = event['Event']['Attribute'][0]
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_features(related_indicator, attribute, orgc)
        properties = self._check_observable_features(indicator.observable, attribute, 'URI')
        self.assertEqual(properties.value.value, attribute['value'])

    def test_event_with_vulnerability_attribute(self):
        event = get_event_with_vulnerability_attribute()
        attribute = event['Event']['Attribute'][0]
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        stix_package = self.parser.stix_package
        ttp = self._check_ttp_fields_from_attribute(stix_package, attribute)
        exploit_target = ttp.exploit_targets.exploit_target[0].item
        self.assertEqual(exploit_target.id_, f"{_DEFAULT_NAMESPACE}:ExploitTarget-{attribute['uuid']}")
        vulnerability = exploit_target.vulnerabilities[0]
        self.assertEqual(vulnerability.cve_id, attribute['value'])

    def test_event_with_windows_service_attributes(self):
        event = get_event_with_windows_service_attributes()
        displayname, name = event['Event']['Attribute']
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        r_displayname, r_name = incident.related_observables.observable
        self.assertEqual(r_displayname.relationship, displayname['category'])
        displayname_properties = self._check_observable_features(
            r_displayname.item,
            displayname,
            'WindowsService'
        )
        self.assertEqual(displayname_properties.display_name, displayname['value'])
        self.assertEqual(r_name.relationship, name['category'])
        name_properties = self._check_observable_features(
            r_name.item,
            name,
            'WindowsService'
        )
        self.assertEqual(name_properties.service_name, name['value'])

    def test_event_with_x509_fingerprint_attributes(self):
        event = get_event_with_x509_fingerprint_attributes()
        md5, sha1, sha256 = event['Event']['Attribute']
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        r_x509_md5, r_x509_sha1, r_x509_sha256 = incident.related_indicators.indicator
        x509_md5 = self._check_indicator_features(r_x509_md5, md5, orgc)
        md5_properties = self._check_observable_features(x509_md5.observable, md5, 'X509Certificate')
        md5_signature = md5_properties.certificate_signature
        self.assertEqual(md5_signature.signature_algorithm.value, "MD5")
        self.assertEqual(md5_signature.signature.value, md5['value'])
        x509_sha1 = self._check_indicator_features(r_x509_sha1, sha1, orgc)
        sha1_properties = self._check_observable_features(x509_sha1.observable, sha1, 'X509Certificate')
        sha1_signature = sha1_properties.certificate_signature
        self.assertEqual(sha1_signature.signature_algorithm.value, "SHA1")
        self.assertEqual(sha1_signature.signature.value, sha1['value'])
        x509_sha256 = self._check_indicator_features(r_x509_sha256, sha256, orgc)
        sha256_properties = self._check_observable_features(x509_sha256.observable, sha256, 'X509Certificate')
        sha256_signature = sha256_properties.certificate_signature
        self.assertEqual(sha256_signature.signature_algorithm.value, "SHA256")
        self.assertEqual(sha256_signature.signature.value, sha256['value'])

    ################################################################################
    #                            GALAXIES EXPORT TESTS.                            #
    ################################################################################

    def test_event_with_attack_pattern_galaxy(self):
        event = get_event_with_attack_pattern_galaxy()
        galaxy = event['Event']['Galaxy'][0]
        cluster = galaxy['GalaxyCluster'][0]
        self.parser.parse_misp_event(event, '1.1.1')
        stix_package = self.parser.stix_package
        ttp = self._check_ttp_fields_from_galaxy(stix_package, cluster['uuid'], galaxy['name'])
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
        ttp = self._check_ttp_fields_from_galaxy(stix_package, cluster['uuid'], galaxy['name'])
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
        ttp = self._check_ttp_fields_from_galaxy(stix_package, cluster['uuid'], galaxy['name'])
        tool = ttp.resources.tools[0]
        self._check_embedded_features(tool, cluster, 'ToolInformation', feature='name')
        self._check_related_ttp(stix_package, galaxy['name'], cluster['uuid'])

    def test_event_with_vulnerability_galaxy(self):
        event = get_event_with_vulnerability_galaxy()
        galaxy = event['Event']['Galaxy'][0]
        cluster = galaxy['GalaxyCluster'][0]
        self.parser.parse_misp_event(event, '1.1.1')
        stix_package = self.parser.stix_package
        ttp = self._check_ttp_fields_from_galaxy(stix_package, cluster['uuid'], galaxy['name'])
        exploit_target = ttp.exploit_targets.exploit_target[0].item
        self.assertEqual(exploit_target.id_, f"{_DEFAULT_NAMESPACE}:ExploitTarget-{cluster['uuid']}")
        vulnerability = exploit_target.vulnerabilities[0]
        self._check_embedded_features(vulnerability, cluster, 'Vulnerability')
        self.assertEqual(vulnerability.cve_id, cluster['meta']['aliases'][0])
        self._check_related_ttp(stix_package, galaxy['name'], cluster['uuid'])
