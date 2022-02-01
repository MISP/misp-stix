#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import unittest
from datetime import datetime, timezone
from misp_stix_converter import (MISPtoSTIX1EventsParser, misp_attribute_collection_to_stix1,
                                 misp_event_collection_to_stix1, misp_to_stix1, stix1_framing)
from pathlib import Path
from uuid import uuid5, UUID
from .test_events import *
from ._test_stix_export import TestCollectionSTIX1Export

_DEFAULT_NAMESPACE = 'https://github.com/MISP/MISP'
_DEFAULT_ORGNAME = 'MISP-Project'
_ORGNAME_ID = re.sub('[\W]+', '', _DEFAULT_ORGNAME.replace(' ', '_'))

misp_reghive = {
    "HKEY_CLASSES_ROOT": "HKEY_CLASSES_ROOT",
    "HKCR": "HKEY_CLASSES_ROOT",
    "HKEY_CURRENT_CONFIG": "HKEY_CURRENT_CONFIG",
    "HKCC": "HKEY_CURRENT_CONFIG",
    "HKEY_CURRENT_USER": "HKEY_CURRENT_USER",
    "HKCU": "HKEY_CURRENT_USER",
    "HKEY_LOCAL_MACHINE": "HKEY_LOCAL_MACHINE",
    "HKLM": "HKEY_LOCAL_MACHINE",
    "HKEY_USERS": "HKEY_USERS",
    "HKU": "HKEY_USERS",
    "HKEY_CURRENT_USER_LOCAL_SETTINGS": "HKEY_CURRENT_USER_LOCAL_SETTINGS",
    "HKCULS": "HKEY_CURRENT_USER_LOCAL_SETTINGS",
    "HKEY_PERFORMANCE_DATA": "HKEY_PERFORMANCE_DATA",
    "HKPD": "HKEY_PERFORMANCE_DATA",
    "HKEY_PERFORMANCE_NLSTEXT": "HKEY_PERFORMANCE_NLSTEXT",
    "HKPN": "HKEY_PERFORMANCE_NLSTEXT",
    "HKEY_PERFORMANCE_TEXT": "HKEY_PERFORMANCE_TEXT",
    "HKPT": "HKEY_PERFORMANCE_TEXT",
}


class TestStix1Export(unittest.TestCase):

    ################################################################################
    #                              UTILITY FUNCTIONS.                              #
    ################################################################################

    @staticmethod
    def _add_ids_flag(event):
        for misp_object in event['Event']['Object']:
            misp_object['Attribute'][0]['to_ids'] = True

    def _check_asn_properties(self, properties, attributes):
        asn, description, subnet1, subnet2 = attributes
        self.assertEqual(properties.handle.value, asn['value'])
        self.assertEqual(properties.name.value, description['value'])
        custom_properties = properties.custom_properties
        self.assertEqual(len(custom_properties), 2)
        for attribute, custom in zip((subnet1, subnet2), custom_properties):
            self.assertEqual(custom.name, attribute['object_relation'])
            self.assertEqual(custom.value, attribute['value'])

    def _check_attachment_properties(self, observable, attribute):
        self.assertEqual(observable.title, attribute['value'])
        properties = self._check_observable_features(observable, attribute, 'Artifact')
        self.assertEqual(properties.raw_artifact.value, attribute['data'])

    def _check_credential_properties(self, properties, attributes):
        text, username, password, _type, origin, _format, notification = attributes
        self.assertEqual(properties.description.value, text['value'])
        self.assertEqual(properties.username.value, username['value'])
        self.assertEqual(len(properties.authentication), 1)
        authentication = properties.authentication[0]
        self.assertEqual(authentication.authentication_type.value, _type['value'])
        self.assertEqual(authentication.authentication_data.value, password['value'])
        struct_auth_meca = authentication.structured_authentication_mechanism
        self.assertEqual(struct_auth_meca.description.value, _format['value'])
        custom_properties = properties.custom_properties
        self._check_custom_properties((origin, notification), custom_properties)

    def _check_coa_taken(self, coa_taken, uuid, timestamp=None):
        self.assertEqual(coa_taken.course_of_action.idref, f'{_ORGNAME_ID}:CourseOfAction-{uuid}')
        if timestamp is not None:
            self.assertEqual(
                coa_taken.course_of_action.timestamp,
                datetime.utcfromtimestamp(int(timestamp))
            )

    def _check_course_of_action_fields(self, course_of_action, misp_object):
        self.assertEqual(course_of_action.id_, f"{_ORGNAME_ID}:CourseOfAction-{misp_object['uuid']}")
        name, type_, objective, stage, cost, impact, efficacy = misp_object['Attribute']
        self.assertEqual(course_of_action.title, name['value'])
        self.assertEqual(course_of_action.type_.value, type_['value'])
        self.assertEqual(course_of_action.objective.description.value, objective['value'])
        self.assertEqual(course_of_action.stage.value, stage['value'])
        self.assertEqual(course_of_action.cost.value, cost['value'])
        self.assertEqual(course_of_action.impact.value, impact['value'])
        self.assertEqual(course_of_action.efficacy.value, efficacy['value'])

    def _check_custom_properties(self, attributes, custom_properties):
        self.assertEqual(len(custom_properties), len(attributes))
        for attribute, custom in zip(attributes, custom_properties):
            self.assertEqual(custom.name, attribute['object_relation'])
            self.assertEqual(custom.value, attribute['value'])

    def _check_custom_property(self, attribute, custom_properties):
        self.assertEqual(custom_properties.name, attribute['type'])
        self.assertEqual(custom_properties.value, attribute['value'])

    def _check_destination_address(self, properties, category='ipv4-addr'):
        self.assertEqual(properties.category, category)
        self.assertFalse(properties.is_source)
        self.assertTrue(properties.is_destination)

    def _check_domain_ip_observables(self, observables, attributes):
        self.assertEqual(len(observables), len(attributes))
        domain, ip = attributes
        domain_observable, ip_observable = observables
        domain_properties = self._check_observable_features(domain_observable, domain, "DomainName")
        self.assertEqual(domain_properties.value.value, domain['value'])
        ip_properties = self._check_observable_features(ip_observable, ip, 'Address')
        self.assertEqual(ip_properties.address_value.value, ip['value'])

    def _check_email_properties(self, properties, related_objects, attributes):
        from_, to_, cc1, cc2, reply_to, subject, attachment1, attachment2, x_mailer, user_agent, boundary, message_id = attributes
        header = properties.header
        self.assertEqual(header.from_.address_value.value, from_['value'])
        self.assertEqual(len(header.to), 1)
        self.assertEqual(header.to[0].address_value.value, to_['value'])
        self.assertEqual(len(header.cc), 2)
        self.assertEqual(header.cc[0].address_value.value, cc1['value'])
        self.assertEqual(header.cc[1].address_value.value, cc2['value'])
        self.assertEqual(header.reply_to.address_value.value, reply_to['value'])
        self.assertEqual(header.subject.value, subject['value'])
        self.assertEqual(header.x_mailer.value, x_mailer['value'])
        self.assertEqual(header.user_agent.value, user_agent['value'])
        self.assertEqual(header.boundary.value, boundary['value'])
        self.assertEqual(header.message_id.value, message_id['value'])
        attachments = properties.attachments
        self.assertEqual(len(attachments), 2)
        self.assertEqual(len(related_objects), 2)
        for attachment, related_object, attribute in zip(attachments, related_objects, (attachment1, attachment2)):
            self.assertEqual(attachment.object_reference, related_object.id_)
            self.assertEqual(related_object.relationship, 'Contains')
            self.assertEqual(related_object.properties.file_name.value, attribute['value'])

    def _check_embedded_features(self, embedded_object, cluster, name, feature='title'):
        self.assertEqual(embedded_object.id_, f"{_ORGNAME_ID}:{name}-{cluster['uuid']}")
        self.assertEqual(getattr(embedded_object, feature), cluster['value'])
        self.assertEqual(embedded_object.description.value, cluster['description'])

    def _check_file_and_pe_properties(self, properties, file_object, pe_object, section_object):
        filename, md5, sha1, sha256, size, entropy = file_object['Attribute']
        self.assertEqual(properties.file_name.value, filename['value'])
        self.assertEqual(properties.size_in_bytes.value, int(size['value']))
        self.assertEqual(properties.peak_entropy.value, float(entropy['value']))
        self.assertEqual(len(properties.hashes), 3)
        for hash_property, attribute in zip(properties.hashes, (md5, sha1, sha256)):
            self._check_simple_hash_property(hash_property, attribute['value'], attribute['type'].upper())
        self._check_pe_and_section_properties(properties, pe_object, section_object)

    def _check_file_observables(self, observables, misp_object):
        self.assertEqual(len(observables), 3)
        attributes = misp_object['Attribute']
        attachment = attributes.pop(6)
        malware_sample = attributes.pop(0)
        malware_sample_observable, attachment_observable, file_observable = observables
        self._check_malware_sample_properties(malware_sample_observable, malware_sample)
        self._check_attachment_properties(attachment_observable, attachment)
        file_properties = self._check_observable_features(file_observable, misp_object, 'File')
        self._check_file_properties(file_properties, attributes, with_artifact=True)

    def _check_file_properties(self, properties, attributes, with_artifact=False):
        custom_properties = properties.custom_properties
        if with_artifact:
            filename, md5, sha1, sha256, size, path, encoding = attributes
            self._check_custom_properties([encoding], custom_properties)
        else:
            malware_sample, filename, md5, sha1, sha256, size, attachment, path, encoding = attributes
            self._check_custom_properties((malware_sample, attachment, encoding), custom_properties)
        self.assertEqual(properties.file_name.value, filename['value'])
        self.assertEqual(properties.file_path.value, path['value'])
        self.assertEqual(properties.size_in_bytes.value, int(size['value']))
        hashes = properties.hashes
        self.assertEqual(len(hashes), 3)
        for hash_property, attribute in zip(hashes, (md5, sha1, sha256)):
            self._check_simple_hash_property(hash_property, attribute['value'], attribute['type'].upper())

    def _check_fuzzy_hash_property(self, hash_property, value, hash_type):
        self.assertEqual(hash_property.type_.value, hash_type)
        self.assertEqual(hash_property.fuzzy_hash_value.value, value)

    def _check_identity_features(self, identity, attribute):
        self.assertEqual(identity.id_, f"{_ORGNAME_ID}:Identity-{attribute['uuid']}")
        self.assertEqual(identity.name, f"{attribute['category']}: {attribute['value']} (MISP Attribute)")

    def _check_indicator_attribute_features(self, related_indicator, attribute, orgc):
        self.assertEqual(related_indicator.relationship, attribute['category'])
        indicator = related_indicator.item
        self.assertEqual(indicator.id_, f"{_ORGNAME_ID}:Indicator-{attribute['uuid']}")
        self.assertEqual(indicator.title, f"{attribute['category']}: {attribute['value']} (MISP Attribute)")
        self.assertEqual(indicator.description.value, attribute['comment'])
        self.assertEqual(
            self._get_utc_timestamp(indicator.timestamp),
            int(attribute['timestamp'])
        )
        self.assertEqual(indicator.producer.identity.name, orgc)
        return indicator

    def _check_indicator_object_features(self, related_indicator, misp_object, orgc):
        self.assertEqual(related_indicator.relationship, misp_object['meta-category'])
        indicator = related_indicator.item
        self.assertEqual(indicator.id_, f"{_ORGNAME_ID}:Indicator-{misp_object['uuid']}")
        self.assertEqual(indicator.title, f"{misp_object['meta-category']}: {misp_object['name']} (MISP Object)")
        self.assertEqual(indicator.description.value, misp_object['description'])
        self.assertEqual(
            self._get_utc_timestamp(indicator.timestamp),
            int(misp_object['timestamp'])
        )
        self.assertEqual(indicator.producer.identity.name, orgc)
        return indicator

    def _check_ip_port_observables(self, observables, misp_object):
        attributes = misp_object['Attribute']
        self.assertEqual(len(observables), len(attributes) - 1)
        ip, port, domain, _ = attributes
        ip_observable, port_observable, domain_observable = observables
        ip_properties = self._check_observable_features(ip_observable, ip, 'Address')
        self.assertEqual(ip_properties.address_value.value, ip['value'])
        self.assertEqual(port_observable.id_, f"{_ORGNAME_ID}:Observable-{port['uuid']}")
        port_object = port_observable.object_
        self.assertEqual(port_object.id_, f"{_ORGNAME_ID}:dstPort-{port['uuid']}")
        port_properties = port_object.properties
        self.assertEqual(port_properties._XSI_TYPE, 'PortObjectType')
        self.assertEqual(port_properties.port_value.value, int(port['value']))
        domain_properties = self._check_observable_features(domain_observable, domain, "DomainName")
        self.assertEqual(domain_properties.value.value, domain['value'])

    def _check_malware_sample_properties(self, observable, attribute):
        filename, md5 = attribute['value'].split('|')
        self.assertEqual(observable.title, filename)
        properties = self._check_observable_features(observable, attribute, 'Artifact')
        self.assertEqual(properties.raw_artifact.value, attribute['data'])
        self._check_simple_hash_property(properties.hashes[0], md5, 'MD5')

    def _check_mutex_properties(self, properties, attributes):
        name, *custom_attributes = attributes
        self.assertEqual(properties.name, name['value'])
        self._check_custom_properties(custom_attributes, properties.custom_properties)

    def _check_network_connection_properties(self, properties, attributes):
        ip_src, ip_dst, src_port, dst_port, hostname, layer3, layer4, layer7 = attributes
        src_socket = properties.source_socket_address
        self.assertEqual(src_socket.ip_address.address_value.value, ip_src['value'])
        self.assertEqual(src_socket.port.port_value.value, int(src_port['value']))
        dst_socket = properties.destination_socket_address
        self.assertEqual(dst_socket.ip_address.address_value.value, ip_dst['value'])
        self.assertEqual(dst_socket.hostname.hostname_value.value, hostname['value'])
        self.assertEqual(dst_socket.port.port_value.value, int(dst_port['value']))
        self.assertEqual(properties.layer3_protocol.value, layer3['value'])
        self.assertEqual(properties.layer4_protocol.value, layer4['value'])
        self.assertEqual(properties.layer7_protocol.value, layer7['value'])

    def _check_network_socket_properties(self, properties, attributes):
        ip_src, ip_dst, src_port, dst_port, hostname, address, domain, type_, state, protocol = attributes
        src_socket = properties.local_address
        self.assertEqual(src_socket.ip_address.address_value.value, ip_src['value'])
        self.assertEqual(src_socket.port.port_value.value, int(src_port['value']))
        dst_socket = properties.remote_address
        self.assertEqual(dst_socket.ip_address.address_value.value, ip_dst['value'])
        self.assertEqual(dst_socket.hostname.hostname_value.value, hostname['value'])
        self.assertEqual(dst_socket.port.port_value.value, int(dst_port['value']))
        self.assertEqual(properties.address_family.value, address['value'])
        self.assertEqual(properties.domain.value, domain['value'])
        self.assertEqual(properties.type_.value, type_['value'])
        self.assertEqual(properties.protocol.value, protocol['value'])
        self.assertEqual(getattr(properties, f"is_{state['value']}"), True)

    def _check_observable_features(self, observable, attribute, name):
        self.assertEqual(observable.id_, f"{_ORGNAME_ID}:Observable-{attribute['uuid']}")
        observable_object = observable.object_
        try:
            self.assertEqual(
                observable_object.id_,
                f"{_ORGNAME_ID}:{name}-{attribute['uuid']}"
            )
            self.assertEqual(
                observable_object.properties._XSI_TYPE,
                f'{name}ObjectType'
            )
        except AssertionError:
            self.assertEqual(
                observable_object.id_,
                f"{_ORGNAME_ID}:Custom-{attribute['uuid']}"
            )
            self.assertEqual(
                observable_object.properties._XSI_TYPE,
                'CustomObjectType'
            )
        return observable_object.properties

    def _check_pe_and_section_properties(self, properties, pe_object, section_object):
        type_, compilation, entrypoint, original, internal, description, fileversion, langid, productname, productversion, companyname, copyright, sections, imphash, impfuzzy = pe_object['Attribute']
        self.assertEqual(properties.type_.value, type_['value'])
        headers = properties.headers
        self.assertEqual(headers.optional_header.address_of_entry_point.value, entrypoint['value'])
        file_header = headers.file_header
        self.assertEqual(file_header.number_of_sections.value, int(sections['value']))
        self.assertEqual(len(file_header.hashes), 2)
        for hash_property, attribute in zip(file_header.hashes, (imphash, impfuzzy)):
            self.assertEqual(hash_property.simple_hash_value.value, attribute['value'])
        resource = properties.resources[0]
        self.assertEqual(resource.companyname.value, companyname['value'])
        self.assertEqual(resource.filedescription.value, description['value'])
        self.assertEqual(resource.fileversion.value, fileversion['value'])
        self.assertEqual(resource.internalname.value, internal['value'])
        self.assertEqual(resource.langid.value, langid['value'])
        self.assertEqual(resource.legalcopyright.value, copyright['value'])
        self.assertEqual(resource.originalfilename.value, original['value'])
        self.assertEqual(resource.productname.value, productname['value'])
        self.assertEqual(resource.productversion.value, productversion['value'])
        self._check_custom_properties([compilation], properties.custom_properties)
        name, size, entropy, md5, sha1, sha256, sha512, ssdeep = section_object['Attribute']
        self.assertEqual(len(properties.sections), 1)
        section = properties.sections[0]
        self.assertEqual(section.entropy.value, float(entropy['value']))
        section_header = section.section_header
        self.assertEqual(section_header.name.value, name['value'])
        self.assertEqual(section_header.size_of_raw_data.value, size['value'])
        hashes = section.data_hashes
        attributes = (md5, sha1, sha256, sha512)
        md5_hash, sha1_hash, sha256_hash, sha512_hash, ssdeep_hash = hashes
        hashes = (md5_hash, sha1_hash, sha256_hash, sha512_hash)
        for hash_property, attribute in zip(hashes, attributes):
            self._check_simple_hash_property(hash_property, attribute['value'], attribute['type'].upper())
        self._check_fuzzy_hash_property(ssdeep_hash, ssdeep['value'], ssdeep['type'].upper())

    def _check_process_properties(self, properties, attributes):
        pid, child, parent, name, image, parent_image, port = attributes
        self.assertEqual(properties.pid.value, int(pid['value']))
        self.assertEqual(properties.parent_pid.value, int(parent['value']))
        self.assertEqual(properties.name.value, name['value'])
        self.assertEqual(len(properties.child_pid_list), 1)
        self.assertEqual(properties.child_pid_list[0].value, int(child['value']))
        self.assertEqual(properties.image_info.file_name.value, image['value'])
        self.assertEqual(len(properties.port_list), 1)
        self.assertEqual(properties.port_list[0].port_value.value, int(port['value']))
        self._check_custom_properties([parent_image], properties.custom_properties)

    def _check_registry_key_properties(self, properties, attributes):
        regkey, hive, name, data, datatype, modified = attributes
        self.assertEqual(properties.key.value, regkey['value'])
        self.assertEqual(properties.hive.value, misp_reghive[hive['value'].lstrip('\\').upper()])
        values = properties.values
        self.assertEqual(len(values), 1)
        key_value = values.value[0]
        self.assertEqual(key_value.name.value, name['value'])
        self.assertEqual(key_value.data.value, data['value'])
        self.assertEqual(key_value.datatype.value, datatype['value'])
        self.assertEqual(properties.modified_time.value, datetime.strptime(modified['value'], '%Y-%m-%dT%H:%M:%S'))

    def _check_related_object(self, related_ttp, galaxy_name, cluster_uuid, timestamp=None, object_type='TTP'):
        self.assertEqual(related_ttp.relationship.value, galaxy_name)
        self.assertEqual(related_ttp.item.idref, f"{_ORGNAME_ID}:{object_type}-{cluster_uuid}")
        if timestamp is not None:
            self.assertEqual(
                related_ttp.item.timestamp,
                datetime.utcfromtimestamp(int(timestamp))
            )

    def _check_simple_hash_property(self, hash_property, value, hash_type):
        self.assertEqual(hash_property.type_.value, hash_type)
        self.assertEqual(hash_property.simple_hash_value.value, value)

    def _check_source_address(self, properties, category='ipv4-addr'):
        self.assertEqual(properties.category, category)
        self.assertTrue(properties.is_source)
        self.assertFalse(properties.is_destination)

    def _check_ttp_fields(self, ttp, uuid, identifier, object_type, timestamp=None):
        self.assertEqual(ttp.id_, f"{_ORGNAME_ID}:TTP-{uuid}")
        self.assertEqual(ttp.title, f"{identifier} (MISP {object_type})")
        if timestamp is not None:
            self.assertEqual(
                ttp.timestamp,
                datetime.utcfromtimestamp(int(timestamp))
            )

    def _check_ttp_fields_from_attribute(self, stix_package, attribute):
        ttp = self._check_ttp_length(stix_package, 1)[0]
        self._check_ttp_fields(
            ttp,
            attribute['uuid'],
            f"{attribute['category']}: {attribute['value']}",
            'Attribute',
            timestamp=attribute['timestamp']
        )
        return ttp

    def _check_ttp_fields_from_galaxy(self, stix_package, cluster_uuid, galaxy_name):
        ttp = self._check_ttp_length(stix_package, 1)[0]
        self._check_ttp_fields(ttp, cluster_uuid, galaxy_name, 'Galaxy')
        return ttp

    def _check_ttp_fields_from_object(self, stix_package, misp_object):
        ttp = self._check_ttp_length(stix_package, 1)[0]
        self._check_ttp_fields(
            ttp,
            misp_object['uuid'],
            f"{misp_object['meta-category']}: {misp_object['name']}",
            'Object',
            timestamp=misp_object['timestamp']
        )
        return ttp

    def _check_ttp_length(self, stix_package, length):
        self.assertEqual(len(stix_package.ttps.ttp), length)
        return stix_package.ttps.ttp

    def _check_ttps_from_galaxies(self, stix_package, uuids, names):
        ttps = self._check_ttp_length(stix_package, len(uuids))
        for ttp, uuid, name in zip(ttps, uuids, names):
            self._check_ttp_fields(ttp, uuid, name, 'Galaxy')
        return ttps

    def _check_url_observables(self, observables, misp_object):
        attributes = misp_object['Attribute']
        self.assertEqual(len(observables), len(attributes))
        url, domain, hostname, ip, port = attributes
        url_observable, domain_observable, hostname_observable, ip_observable, port_observable = observables
        url_properties = self._check_observable_features(url_observable, url, 'URI')
        self.assertEqual(url_properties.value.value, url['value'])
        domain_properties = self._check_observable_features(domain_observable, domain, 'DomainName')
        self.assertEqual(domain_properties.value.value, domain['value'])
        hostname_properties = self._check_observable_features(hostname_observable, hostname, 'Hostname')
        self.assertEqual(hostname_properties.hostname_value.value, hostname['value'])
        ip_properties = self._check_observable_features(ip_observable, ip, 'Address')
        self.assertEqual(ip_properties.address_value.value, ip['value'])
        port_properties = self._check_observable_features(port_observable, port, 'Port')
        self.assertEqual(port_properties.port_value.value, int(port['value']))

    def _check_unix_user_account_properties(self, properties, attributes):
        username, user_id, display_name, password, group1, group2, group_id, home_dir, _ = attributes
        self.assertEqual(properties.username.value, username['value'])
        self.assertEqual(properties.full_name.value, display_name['value'])
        self.assertEqual(len(properties.authentication), 1)
        authentication = properties.authentication[0]
        self.assertEqual(authentication.authentication_type.value, 'password')
        self.assertEqual(authentication.authentication_data.value, password['value'])
        self.assertEqual(properties.group_id.value, int(group_id['value']))
        self.assertEqual(properties.home_directory.value, home_dir['value'])
        self._check_custom_properties((user_id, group1, group2), properties.custom_properties)

    def _check_user_account_properties(self, properties, attributes):
        username, user_id, display_name, password, group1, group2, group_id, home_dir = attributes
        self.assertEqual(properties.username.value, username['value'])
        self.assertEqual(properties.full_name.value, display_name['value'])
        self.assertEqual(len(properties.authentication), 1)
        authentication = properties.authentication[0]
        self.assertEqual(authentication.authentication_type.value, 'password')
        self.assertEqual(authentication.authentication_data.value, password['value'])
        self.assertEqual(properties.home_directory.value, home_dir['value'])
        self._check_custom_properties((user_id, group1, group2, group_id), properties.custom_properties)

    def _check_windows_user_account_properties(self, properties, attributes):
        username, user_id, display_name, password, group1, group2, group_id, home_dir, account_type = attributes
        self.assertEqual(properties.username.value, username['value'])
        self.assertEqual(properties.security_id.value, user_id['value'])
        self.assertEqual(properties.full_name.value, display_name['value'])
        self.assertEqual(len(properties.authentication), 1)
        authentication = properties.authentication[0]
        self.assertEqual(authentication.authentication_type.value, 'password')
        self.assertEqual(authentication.authentication_data.value, password['value'])
        self.assertEqual(properties.home_directory.value, home_dir['value'])
        group_list = properties.group_list
        self.assertEqual(len(group_list), 2)
        group1_properties, group2_properties = group_list
        self.assertEqual(group1_properties.name.value, group1['value'])
        self.assertEqual(group2_properties.name.value, group2['value'])
        self._check_custom_properties((group_id, account_type), properties.custom_properties)

    def _check_whois_properties(self, properties, attributes):
        registrar, email, org, name, phone, creation, modification, expiration, domain, nameserver, ip = attributes
        self.assertEqual(properties.registrar_info.name.value, registrar['value'])
        registrants = properties.registrants
        self.assertEqual(len(registrants), 1)
        registrant = registrants[0]
        self.assertEqual(registrant.email_address.address_value.value, email['value'])
        self.assertEqual(registrant.organization.value, org['value'])
        self.assertEqual(registrant.name.value, name['value'])
        self.assertEqual(registrant.phone_number.value, phone['value'])
        self.assertEqual(properties.creation_date.value, datetime.strptime(creation['value'], '%Y-%m-%dT%H:%M:%S').date())
        self.assertEqual(properties.updated_date.value, datetime.strptime(modification['value'], '%Y-%m-%dT%H:%M:%S').date())
        self.assertEqual(properties.expiration_date.value, datetime.strptime(expiration['value'], '%Y-%m-%dT%H:%M:%S').date())
        self.assertEqual(properties.domain_name.value.value, domain['value'])
        nameservers = properties.nameservers
        self.assertEqual(len(nameservers), 1)
        self.assertEqual(nameservers[0].value.value, nameserver['value'])
        self.assertEqual(properties.ip_address.address_value.value, ip['value'])

    def _check_x509_properties(self, properties, attributes):
        issuer, pem, pubkey_algo, exponent, modulus, serial, signature_algo, subject, before, after, version, md5, sha1 = attributes
        certificate = properties.certificate
        self.assertEqual(certificate.issuer.value, issuer['value'])
        self.assertEqual(certificate.serial_number.value, serial['value'])
        self.assertEqual(certificate.signature_algorithm.value, signature_algo['value'])
        self.assertEqual(certificate.subject.value, subject['value'])
        self.assertEqual(certificate.version.value, int(version['value']))
        validity = certificate.validity
        self.assertEqual(validity.not_before.value, datetime.strptime(before['value'], '%Y-%m-%dT%H:%M:%S'))
        self.assertEqual(validity.not_after.value, datetime.strptime(after['value'], '%Y-%m-%dT%H:%M:%S'))
        pubkey = certificate.subject_public_key
        self.assertEqual(pubkey.public_key_algorithm.value, pubkey_algo['value'])
        rsa_pubkey = pubkey.rsa_public_key
        self.assertEqual(rsa_pubkey.exponent.value, int(exponent['value']))
        self.assertEqual(rsa_pubkey.modulus.value, modulus['value'])
        self.assertEqual(properties.raw_certificate.value, pem['value'])
        signature = properties.certificate_signature
        self.assertEqual(signature.signature_algorithm.value, 'SHA1')
        self.assertEqual(signature.signature.value, sha1['value'])
        self._check_custom_properties([md5], properties.custom_properties)

    @staticmethod
    def _get_marking_value(marking):
        if marking._XSI_TYPE == 'tlpMarking:TLPMarkingStructureType':
            return marking.color
        return marking.statement

    @staticmethod
    def _get_test_printing(stix_object):
        return stix_object.to_xml(include_namespaces=False).decode().replace('"', '\"').encode()

    @staticmethod
    def _get_utc_timestamp(dtime):
        return int(dtime.replace(tzinfo=timezone.utc).timestamp())

    @staticmethod
    def _remove_ids_flags(event):
        for misp_object in event['Event']['Object']:
            for attribute in misp_object['Attribute']:
                attribute['to_ids'] = False

    def _run_composition_from_indicator_object_tests(self, event):
        self._add_ids_flag(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event)
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_object_features(related_indicator, misp_object, orgc)
        observables = indicator.observable.observable_composition.observables
        return observables, misp_object

    def _run_composition_from_observable_object_tests(self, event):
        self._remove_ids_flags(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event)
        incident = self.parser.stix_package.incidents[0]
        observable = incident.related_observables.observable[0]
        prefix = f"{_ORGNAME_ID}:{misp_object['name']}"
        self.assertEqual(
            observable.item.id_,
            f"{prefix}_ObservableComposition-{misp_object['uuid']}"
        )
        observables = observable.item.observable_composition.observables
        return observables, misp_object

    def _run_indicator_from_object_tests(self, event, object_type):
        self._add_ids_flag(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event)
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_object_features(
            related_indicator,
            misp_object,
            orgc
        )
        properties = self._check_observable_features(
            indicator.observable,
            misp_object,
            object_type
        )
        return properties, misp_object['Attribute']

    def _run_indicator_from_objects_tests(self, event, object_type):
        self._add_ids_flag(event)
        misp_objects = deepcopy(event['Event']['Object'])
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event)
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_object_features(
            related_indicator,
            misp_objects[0],
            orgc
        )
        properties = self._check_observable_features(
            indicator.observable,
            misp_objects[0],
            object_type
        )
        return properties, misp_objects

    def _run_indicator_tests(self, event, object_type):
        attribute = event['Event']['Attribute'][0]
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event)
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_attribute_features(
            related_indicator,
            attribute,
            orgc
        )
        properties = self._check_observable_features(
            indicator.observable,
            attribute,
            object_type
        )
        return properties, attribute

    def _run_indicators_tests(self, event, object_type):
        attributes = event['Event']['Attribute']
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event)
        incident = self.parser.stix_package.incidents[0]
        related_indicators = incident.related_indicators.indicator
        properties = []
        for related, attribute in zip(related_indicators, attributes):
            indicator = self._check_indicator_attribute_features(
                related,
                attribute,
                orgc
            )
            properties.append(
                self._check_observable_features(
                    indicator.observable,
                    attribute,
                    object_type
                )
            )
        return properties, attributes

    def _run_observable_from_object_tests(self, event, object_type):
        self._remove_ids_flags(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event)
        incident = self.parser.stix_package.incidents[0]
        observable = incident.related_observables.observable[0]
        self.assertEqual(observable.relationship, misp_object['meta-category'])
        properties = self._check_observable_features(
            observable.item,
            misp_object,
            object_type
        )
        return properties, misp_object['Attribute']

    def _run_observable_from_objects_tests(self, event, object_type):
        self._remove_ids_flags(event)
        misp_objects = deepcopy(event['Event']['Object'])
        self.parser.parse_misp_event(event)
        incident = self.parser.stix_package.incidents[0]
        observable = incident.related_observables.observable[0]
        self.assertEqual(observable.relationship, misp_objects[0]['meta-category'])
        properties = self._check_observable_features(
            observable.item,
            misp_objects[0],
            object_type
        )
        return properties, misp_objects

    def _run_observable_tests(self, event, object_type):
        attribute = event['Event']['Attribute'][0]
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event)
        incident = self.parser.stix_package.incidents[0]
        observable = incident.related_observables.observable[0]
        self.assertEqual(observable.relationship, attribute['category'])
        properties = self._check_observable_features(
            observable.item,
            attribute,
            object_type
        )
        return properties, attribute

    def _run_observables_tests(self, event, object_type):
        attributes = event['Event']['Attribute']
        self.parser.parse_misp_event(event)
        incident = self.parser.stix_package.incidents[0]
        related_observables = incident.related_observables.observable
        properties = []
        for related, attribute in zip(related_observables, attributes):
            self.assertEqual(related.relationship, attribute['category'])

            properties.append(
                self._check_observable_features(related.item, attribute, object_type)
            )
        return properties, attributes

    ################################################################################
    #                              EVENT FIELDS TESTS                              #
    ################################################################################

    def _test_base_event(self, version):
        event = get_base_event()
        uuid = event['Event']['uuid']
        info = event['Event']['info']
        self.parser.parse_misp_event(event)
        stix_package = self.parser.stix_package
        self.assertEqual(stix_package.id_, f"{_ORGNAME_ID}:STIXPackage-{uuid}")
        self.assertEqual(
            self._get_utc_timestamp(stix_package.timestamp),
            int(event['Event']['timestamp'])
        )
        self.assertEqual(stix_package.version, version)
        self.assertEqual(stix_package.stix_header.title, f"Export from {_DEFAULT_ORGNAME}'s MISP")
        incident = stix_package.incidents[0]
        self.assertEqual(incident.id_, f"{_ORGNAME_ID}:Incident-{uuid}")
        self.assertEqual(incident.title, info)
        self.assertEqual(incident.information_source.identity.name, _DEFAULT_ORGNAME)
        self.assertEqual(incident.reporter.identity.name, _DEFAULT_ORGNAME)

    def _test_published_event(self):
        event = get_published_event()
        self.parser.parse_misp_event(event)
        incident = self.parser.stix_package.incidents[0]
        self.assertEqual(
            self._get_utc_timestamp(incident.timestamp),
            int(event['Event']['timestamp'])
        )
        self.assertEqual(
            incident.time.incident_discovery.value.strftime("%Y-%m-%d"),
            event['Event']['date']
        )
        self.assertEqual(
            self._get_utc_timestamp(incident.time.incident_reported.value),
            int(event['Event']['publish_timestamp'])
        )

    def _test_event_with_tags(self):
        event = get_event_with_tags()
        self.parser.parse_misp_event(event)
        marking = self.parser.stix_package.incidents[0].handling[0]
        self.assertEqual(len(marking.marking_structures), 3)
        markings = tuple(self._get_marking_value(marking) for marking in marking.marking_structures)
        self.assertIn('WHITE', markings)
        self.assertIn('misp:tool="misp2stix"', markings)
        self.assertIn('misp-galaxy:mitre-attack-pattern="Code Signing - T1116"', markings)

    ################################################################################
    #                        SINGLE ATTRIBUTES EXPORT TESTS                        #
    ################################################################################

    def _test_embedded_indicator_attribute_galaxy(self):
        event = get_embedded_indicator_attribute_galaxy()
        attribute = event['Event']['Attribute'][0]
        ap_galaxy, coa_galaxy = attribute['Galaxy']
        ap_cluster = ap_galaxy['GalaxyCluster'][0]
        coa_cluster = coa_galaxy['GalaxyCluster'][0]
        galaxy = event['Event']['Galaxy'][0]
        cluster = galaxy['GalaxyCluster'][0]
        self.parser.parse_misp_event(event)
        stix_package = self.parser.stix_package
        malware_ttp, attack_pattern_ttp = self._check_ttps_from_galaxies(
            stix_package,
            (cluster['uuid'], ap_cluster['uuid']),
            (galaxy['name'], ap_galaxy['name'])
        )
        attack_pattern = attack_pattern_ttp.behavior.attack_patterns[0]
        self._check_embedded_features(attack_pattern, ap_cluster, 'AttackPattern')
        malware = malware_ttp.behavior.malware_instances[0]
        self._check_embedded_features(malware, cluster, 'MalwareInstance')
        course_of_action = stix_package.courses_of_action[0]
        self._check_embedded_features(course_of_action, coa_cluster, 'CourseOfAction')
        incident = stix_package.incidents[0]
        self._check_related_object(incident.leveraged_ttps.ttp[0], galaxy['name'], cluster['uuid'])
        indicator = incident.related_indicators.indicator[0].item
        self._check_related_object(
            indicator.indicated_ttps[0],
            ap_galaxy['name'],
            ap_cluster['uuid']
        )
        self._check_related_object(
            indicator.suggested_coas[0],
            coa_galaxy['name'],
            coa_cluster['uuid'],
            object_type='CourseOfAction'
        )

    def _test_embedded_non_indicator_attribute_galaxy(self):
        event = get_embedded_non_indicator_attribute_galaxy()
        attribute = event['Event']['Attribute'][0]
        attribute_galaxy = attribute['Galaxy'][0]
        attribute_cluster = attribute_galaxy['GalaxyCluster'][0]
        coa_galaxy, malware_galaxy = event['Event']['Galaxy']
        coa_cluster = coa_galaxy['GalaxyCluster'][0]
        malware_cluster = malware_galaxy['GalaxyCluster'][0]
        self.parser.parse_misp_event(event)
        stix_package = self.parser.stix_package
        malware_ttp, attack_pattern_ttp, vulnerability_ttp = self._check_ttp_length(
            stix_package,
            3
        )
        self._check_ttp_fields(
            attack_pattern_ttp,
            attribute_cluster['uuid'],
            attribute_galaxy['name'],
            'Galaxy'
        )
        self._check_ttp_fields(
            malware_ttp,
            malware_cluster['uuid'],
            malware_galaxy['name'],
            'Galaxy'
        )
        self._check_ttp_fields(
            vulnerability_ttp,
            attribute['uuid'],
            f"{attribute['category']}: {attribute['value']}",
            'Attribute',
            timestamp=attribute['timestamp']
        )
        attack_pattern = attack_pattern_ttp.behavior.attack_patterns[0]
        self._check_embedded_features(attack_pattern, attribute_cluster, 'AttackPattern')
        malware = malware_ttp.behavior.malware_instances[0]
        self._check_embedded_features(malware, malware_cluster, 'MalwareInstance')
        exploit_target = vulnerability_ttp.exploit_targets.exploit_target[0].item
        self.assertEqual(exploit_target.id_, f"{_ORGNAME_ID}:ExploitTarget-{attribute['uuid']}")
        course_of_action = stix_package.courses_of_action[0]
        self._check_embedded_features(course_of_action, coa_cluster, 'CourseOfAction')
        incident = stix_package.incidents[0]
        related_malware, related_vulnerability = incident.leveraged_ttps.ttp
        self._check_related_object(
            related_malware,
            malware_galaxy['name'],
            malware_cluster['uuid']
        )
        self._check_related_object(
            related_vulnerability,
            attribute['type'],
            attribute['uuid']
        )
        self._check_related_object(
            vulnerability_ttp.related_ttps[0],
            attribute_galaxy['name'],
            attribute_cluster['uuid']
        )
        self._check_coa_taken(incident.coa_taken[0], coa_cluster['uuid'])

    def _test_embedded_observable_attribute_galaxy(self):
        event = get_embedded_observable_attribute_galaxy()
        attribute = event['Event']['Attribute'][0]
        galaxy = event['Event']['Galaxy'][0]
        cluster = galaxy['GalaxyCluster'][0]
        self.parser.parse_misp_event(event)
        stix_package = self.parser.stix_package
        ttp = self._check_ttp_fields_from_galaxy(stix_package, cluster['uuid'], galaxy['name'])
        malware = ttp.behavior.malware_instances[0]
        self._check_embedded_features(malware, cluster, 'MalwareInstance')
        self._check_related_object(
            stix_package.incidents[0].leveraged_ttps.ttp[0],
            galaxy['name'],
            cluster['uuid']
        )
        ttp = self._check_ttp_fields_from_galaxy(stix_package, cluster['uuid'], galaxy['name'])
        malware = ttp.behavior.malware_instances[0]
        self._check_embedded_features(malware, cluster, 'MalwareInstance')
        self._check_related_object(
            stix_package.incidents[0].leveraged_ttps.ttp[0],
            galaxy['name'],
            cluster['uuid']
        )

    def _test_event_with_as_attribute(self):
        event = get_event_with_as_attribute()
        properties, attribute = self._run_observable_tests(event, 'AS')
        self.assertEqual(properties.handle.value, attribute['value'])

    def _test_event_with_attachment_attribute(self):
        event = get_event_with_attachment_attribute()
        attribute = event['Event']['Attribute'][0]
        self.parser.parse_misp_event(event)
        incident = self.parser.stix_package.incidents[0]
        observable = incident.related_observables.observable[0]
        self.assertEqual(observable.relationship, attribute['category'])
        self._check_attachment_properties(observable.item, attribute)

    def _test_event_with_campaign_name_attribute(self):
        event = get_event_with_campaign_name_attribute()
        attribute = event['Event']['Attribute'][0]
        self.parser.parse_misp_event(event)
        campaign = self.parser.stix_package.campaigns[0]
        self.assertEqual(campaign.id_, f"{_ORGNAME_ID}:Campaign-{attribute['uuid']}")
        self.assertEqual(
            campaign.title,
            f"{attribute['category']}: {attribute['value']} (MISP Attribute)"
        )
        self.assertEqual(campaign.names[0], attribute['value'])
        self.assertEqual(
            campaign.timestamp,
            datetime.utcfromtimestamp(int(attribute['timestamp']))
        )

    def _test_event_with_custom_attributes(self):
        event = get_event_with_stix1_custom_attributes()
        btc, iban, phone, passport = event['Event']['Attribute']
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event)
        incident = self.parser.stix_package.incidents[0]
        btc_rindicator, iban_rindicator = incident.related_indicators.indicator
        btc_indicator = self._check_indicator_attribute_features(btc_rindicator, btc, orgc)
        btc_properties = self._check_observable_features(btc_indicator.observable, btc, 'Custom')
        self._check_custom_property(btc, btc_properties.custom_properties.property_[0])
        iban_indicator = self._check_indicator_attribute_features(iban_rindicator, iban, orgc)
        iban_properties = self._check_observable_features(iban_indicator.observable, iban, 'Custom')
        self._check_custom_property(iban, iban_properties.custom_properties.property_[0])
        phone_observable, passport_observable = incident.related_observables.observable
        self.assertEqual(phone_observable.relationship, phone['category'])
        phone_properties = self._check_observable_features(phone_observable.item, phone, 'Custom')
        self._check_custom_property(phone, phone_properties.custom_properties.property_[0])
        self.assertEqual(passport_observable.relationship, passport['category'])
        passport_properties = self._check_observable_features(
            passport_observable.item,
            passport,
            'Custom'
        )
        self._check_custom_property(passport, passport_properties.custom_properties.property_[0])

    def _test_event_with_domain_attribute(self):
        event = get_event_with_domain_attribute()
        properties, attribute = self._run_indicator_tests(event, 'DomainName')
        self.assertEqual(properties.value.value, attribute['value'])

    def _test_event_with_domain_ip_attribute(self):
        event = get_event_with_domain_ip_attribute()
        attribute = event['Event']['Attribute'][0]
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event)
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_attribute_features(related_indicator, attribute, orgc)
        observable = indicator.observable
        self.assertEqual(observable.id_, f"{_ORGNAME_ID}:ObservableComposition-{attribute['uuid']}")
        domain_observable, address_observable = observable.observable_composition.observables
        attribute_uuid = attribute['uuid']
        domain, ip = attribute['value'].split('|')
        self.assertEqual(domain_observable.id_, f'{_ORGNAME_ID}:Observable-{uuid5(UUID(attribute_uuid), domain)}')
        domain_object = domain_observable.object_
        self.assertEqual(domain_object.id_, f'{_ORGNAME_ID}:DomainName-{attribute_uuid}')
        domain_properties = domain_object.properties
        self.assertEqual(domain_properties._XSI_TYPE, 'DomainNameObjectType')
        self.assertEqual(domain_properties.value.value, domain)
        self.assertEqual(address_observable.id_, f'{_ORGNAME_ID}:Observable-{uuid5(UUID(attribute_uuid), ip)}')
        address_object = address_observable.object_
        self.assertEqual(address_object.id_, f'{_ORGNAME_ID}:Address-{attribute_uuid}')
        address_properties = address_object.properties
        self.assertEqual(address_properties._XSI_TYPE, 'AddressObjectType')
        self.assertEqual(address_properties.address_value.value, ip)
        self._check_destination_address(address_properties)

    def _test_event_with_email_attachment_attribute(self):
        event = get_event_with_email_attachment_attribute()
        attribute = event['Event']['Attribute'][0]
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event)
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_attribute_features(related_indicator, attribute, orgc)
        properties = self._check_observable_features(indicator.observable, attribute, 'EmailMessage')
        referenced_uuid = f"{_ORGNAME_ID}:File-{attribute['uuid']}"
        self.assertEqual(properties.attachments[0].object_reference, referenced_uuid)
        related_object = indicator.observable.object_.related_objects[0]
        self.assertEqual(related_object.id_, referenced_uuid)
        self.assertEqual(related_object.properties.file_name.value, attribute['value'])
        self.assertEqual(related_object.relationship.value, 'Contains')

    def _test_event_with_email_attributes(self):
        event = get_event_with_email_attributes()
        source, destination, subject, reply_to, message_id, x_mailer, boundary = event['Event']['Attribute']
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event)
        incident = self.parser.stix_package.incidents[0]
        src_indicator, dst_indicator = incident.related_indicators.indicator
        source_indicator = self._check_indicator_attribute_features(src_indicator, source, orgc)
        source_properties = self._check_observable_features(
            source_indicator.observable,
            source,
            'EmailMessage'
        )
        self.assertEqual(source_properties.from_.address_value.value, source['value'])
        self.assertEqual(source_properties.from_.category, 'e-mail')
        destination_indicator = self._check_indicator_attribute_features(dst_indicator, destination, orgc)
        destination_properties = self._check_observable_features(
            destination_indicator.observable,
            destination,
            'EmailMessage'
        )
        self.assertEqual(destination_properties.to[0].address_value.value, destination['value'])
        self.assertEqual(destination_properties.to[0].category, 'e-mail')
        subject_observable, reply_to_observable, message_id_observable, x_mailer_observable, boundary_observable = incident.related_observables.observable
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
        message_id_properties = self._check_observable_features(
            message_id_observable.item,
            message_id,
            'EmailMessage'
        )
        self.assertEqual(message_id_properties.message_id.value, message_id['value'])
        x_mailer_properties = self._check_observable_features(
            x_mailer_observable.item,
            x_mailer,
            'EmailMessage'
        )
        self.assertEqual(x_mailer_properties.header.x_mailer.value, x_mailer['value'])
        boundary_properties = self._check_observable_features(
            boundary_observable.item,
            boundary,
            'EmailMessage'
        )
        self.assertEqual(boundary_properties.header.boundary.value, boundary['value'])

    def _test_event_with_email_body_attribute(self):
        event = get_event_with_email_body_attribute()
        properties, attribute = self._run_observable_tests(event, 'EmailMessage')
        self.assertEqual(properties.raw_body.value, attribute['value'])

    def _test_event_with_email_header_attribute(self):
        event = get_event_with_email_header_attribute()
        properties, attribute = self._run_observable_tests(event, 'EmailMessage')
        self.assertEqual(properties.raw_header.value, attribute['value'])

    def _test_event_with_filename_attribute(self):
        event = get_event_with_filename_attribute()
        properties, attribute = self._run_indicator_tests(event, 'File')
        self.assertEqual(properties.file_name.value, attribute['value'])

    def _test_event_with_hash_attributes(self):
        event = get_event_with_hash_attributes()
        properties, attributes = self._run_indicators_tests(event, 'File')
        md5_properties, sha1_properties, sha224_properties, sha256_properties, sha3_256_properties, sha384_properties, ssdeep_properties, tlsh_properties = properties
        md5, sha1, sha224, sha256, sha3_256, sha384, ssdeep, tlsh = attributes
        self._check_simple_hash_property(md5_properties.hashes[0], md5['value'], 'MD5')
        self._check_simple_hash_property(sha1_properties.hashes[0], sha1['value'], 'SHA1')
        self._check_simple_hash_property(sha224_properties.hashes[0], sha224['value'], 'SHA224')
        self._check_simple_hash_property(sha256_properties.hashes[0], sha256['value'], 'SHA256')
        self._check_custom_property(sha3_256, sha3_256_properties.custom_properties.property_[0])
        self._check_simple_hash_property(sha384_properties.hashes[0], sha384['value'], 'SHA384')
        self._check_fuzzy_hash_property(ssdeep_properties.hashes[0], ssdeep['value'], 'SSDEEP')
        self._check_simple_hash_property(tlsh_properties.hashes[0], tlsh['value'], 'Other')

    def _test_event_with_hash_composite_attributes(self):
        event = get_event_with_hash_composite_attributes()
        properties, attributes = self._run_indicators_tests(event, 'File')
        md5_properties, sha1_properties, sha224_properties, sha256_properties, sha3_256_properties, sha384_properties, ssdeep_properties, tlsh_properties = properties
        md5, sha1, sha224, sha256, sha3_256, sha384, ssdeep, tlsh = attributes
        filename, md5_value = md5['value'].split('|')
        self.assertEqual(md5_properties.file_name.value, filename)
        self._check_simple_hash_property(md5_properties.hashes[0], md5_value, 'MD5')
        filename, sha1_value = sha1['value'].split('|')
        self.assertEqual(sha1_properties.file_name.value, filename)
        self._check_simple_hash_property(sha1_properties.hashes[0], sha1_value, 'SHA1')
        filename, sha224_value = sha224['value'].split('|')
        self.assertEqual(sha224_properties.file_name.value, filename)
        self._check_simple_hash_property(sha224_properties.hashes[0], sha224_value, 'SHA224')
        filename, sha256_value = sha256['value'].split('|')
        self.assertEqual(sha256_properties.file_name.value, filename)
        self._check_simple_hash_property(sha256_properties.hashes[0], sha256_value, 'SHA256')
        self._check_custom_property(sha3_256, sha3_256_properties.custom_properties.property_[0])
        filename, sha384_value = sha384['value'].split('|')
        self.assertEqual(sha384_properties.file_name.value, filename)
        self._check_simple_hash_property(sha384_properties.hashes[0], sha384_value, 'SHA384')
        filename, ssdeep_value = ssdeep['value'].split('|')
        self.assertEqual(ssdeep_properties.file_name.value, filename)
        self._check_fuzzy_hash_property(ssdeep_properties.hashes[0], ssdeep_value, 'SSDEEP')
        filename, tlsh_value = tlsh['value'].split('|')
        self.assertEqual(tlsh_properties.file_name.value, filename)
        self._check_simple_hash_property(tlsh_properties.hashes[0], tlsh_value, 'Other')

    def _test_event_with_hostname_attribute(self):
        event = get_event_with_hostname_attribute()
        properties, attribute = self._run_indicator_tests(event, 'Hostname')
        self.assertEqual(properties.hostname_value.value, attribute['value'])

    def _test_event_with_hostname_port_attribute(self):
        event = get_event_with_hostname_port_attribute()
        properties, attribute = self._run_indicator_tests(event, 'SocketAddress')
        hostname, port = attribute['value'].split('|')
        self.assertEqual(properties.hostname.hostname_value.value, hostname)
        self.assertEqual(properties.port.port_value.value, int(port))

    def _test_event_with_http_attributes(self):
        event = get_event_with_http_attributes()
        properties, attributes = self._run_observables_tests(event, 'HTTPSession')
        http_method_properties, user_agent_properties = properties
        http_method, user_agent = event['Event']['Attribute']
        request_response = http_method_properties.http_request_response[0]
        self.assertEqual(
            request_response.http_client_request.http_request_line.http_method.value,
            http_method['value']
        )
        request = user_agent_properties.http_request_response[0].http_client_request
        self.assertEqual(
            request.http_request_header.parsed_header.user_agent.value,
            user_agent['value']
        )

    def _test_event_with_ip_attributes(self):
        event = get_event_with_ip_attributes()
        properties, attributes = self._run_indicators_tests(event, 'Address')
        src_properties, dst_properties = properties
        ip_src, ip_dst = attributes
        self.assertEqual(src_properties.address_value.value, ip_src['value'])
        self._check_source_address(src_properties)
        self.assertEqual(dst_properties.address_value.value, ip_dst['value'])
        self._check_destination_address(dst_properties)

    def _test_event_with_ip_port_attributes(self):
        event = get_event_with_ip_port_attributes()
        properties, attributes = self._run_indicators_tests(event, 'SocketAddress')
        src_properties, dst_properties = properties
        ip_src, ip_dst = attributes
        ip, port = ip_src['value'].split('|')
        self.assertEqual(src_properties.port.port_value.value, int(port))
        self.assertEqual(src_properties.ip_address.address_value.value, ip)
        self._check_source_address(src_properties.ip_address)
        ip, port = ip_dst['value'].split('|')
        self.assertEqual(dst_properties.port.port_value.value, int(port))
        self.assertEqual(dst_properties.ip_address.address_value.value, ip)
        self._check_destination_address(dst_properties.ip_address)

    def _test_event_with_mac_address_attribute(self):
        event = get_event_with_mac_address_attribute()
        properties, attribute = self._run_observable_tests(event, 'System')
        self.assertEqual(properties.network_interface_list[0].mac, attribute['value'])

    def _test_event_with_malware_sample_attribute(self):
        event = get_event_with_malware_sample_attribute()
        attribute = event['Event']['Attribute'][0]
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event)
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_attribute_features(related_indicator, attribute, orgc)
        self._check_malware_sample_properties(indicator.observable, attribute)

    def _test_event_with_mutex_attribute(self):
        event = get_event_with_mutex_attribute()
        properties, attribute = self._run_indicator_tests(event, 'Mutex')
        self.assertEqual(properties.name.value, attribute['value'])

    def _test_event_with_named_pipe_attribute(self):
        event = get_event_with_named_pipe_attribute()
        properties, attribute = self._run_observable_tests(event, 'Pipe')
        self.assertTrue(properties.named)
        self.assertEqual(properties.name.value, attribute['value'])

    def _test_event_with_pattern_attribute(self):
        event = get_event_with_pattern_attribute()
        properties, attribute = self._run_indicator_tests(event, 'File')
        self.assertEqual(properties.byte_runs[0].byte_run_data, attribute['value'])

    def _test_event_with_port_attribute(self):
        event = get_event_with_port_attribute()
        properties, attribute = self._run_observable_tests(event, 'Port')
        self.assertEqual(properties.port_value.value, int(attribute['value']))

    def _test_event_with_regkey_attribute(self):
        event = get_event_with_regkey_attribute()
        properties, attribute = self._run_indicator_tests(event, 'WindowsRegistryKey')
        self.assertEqual(properties.key.value, attribute['value'])

    def _test_event_with_regkey_value_attribute(self):
        event = get_event_with_regkey_value_attribute()
        properties, attribute = self._run_indicator_tests(event, 'WindowsRegistryKey')
        regkey, value = attribute['value'].split('|')
        self.assertEqual(properties.key.value, regkey)
        self.assertEqual(properties.values[0].data.value, value)

    def _test_event_with_size_in_bytes_attribute(self):
        event = get_event_with_size_in_bytes_attribute()
        properties, attribute = self._run_observable_tests(event, 'File')
        self.assertEqual(properties.size_in_bytes.value, int(attribute['value']))

    def _test_event_with_target_attributes(self):
        event = get_event_with_target_attributes()
        email, external, location, machine, org, user = event['Event']['Attribute']
        self.parser.parse_misp_event(event)
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

    def _test_event_with_test_mechanism_attributes(self):
        event = get_event_with_test_mechanism_attributes()
        snort, yara = event['Event']['Attribute']
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event)
        incident = self.parser.stix_package.incidents[0]
        r_snort, r_yara = incident.related_indicators.indicator
        snort_indicator = self._check_indicator_attribute_features(r_snort, snort, orgc)
        snort_tm = snort_indicator.test_mechanisms[0]
        self.assertEqual(snort_tm._XSI_TYPE, 'snortTM:SnortTestMechanismType')
        self.assertEqual(snort_tm.rules[0].value['value'], snort['value'])
        yara_indicator = self._check_indicator_attribute_features(r_yara, yara, orgc)
        yara_tm = yara_indicator.test_mechanisms[0]
        self.assertEqual(yara_tm._XSI_TYPE, 'yaraTM:YaraTestMechanismType')
        self.assertEqual(yara_tm.rule.value['value'], yara['value'])

    def _test_event_with_undefined_attributes(self):
        event = get_event_with_undefined_attributes()
        header, comment = event['Event']['Attribute']
        self.parser.parse_misp_event(event)
        stix_package = self.parser.stix_package
        self.assertEqual(stix_package.stix_header.description.value, header['value'])
        incident = self.parser.stix_package.incidents[0]
        default_entry, journal_entry = incident.history.history_items
        self.assertEqual(
            default_entry.journal_entry.value,
            'MISP Tag: misp:tool="MISP-STIX-Converter"'
        )
        self.assertEqual(
            journal_entry.journal_entry.value,
            f"Attribute ({comment['category']} - {comment['type']}): {comment['value']}"
        )

    def _test_event_with_url_attribute(self):
        event = get_event_with_url_attribute()
        properties, attribute = self._run_indicator_tests(event, 'URI')
        self.assertEqual(properties.value.value, attribute['value'])

    def _test_event_with_vulnerability_attribute(self):
        event = get_event_with_vulnerability_attribute()
        attribute = event['Event']['Attribute'][0]
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event)
        stix_package = self.parser.stix_package
        ttp = self._check_ttp_fields_from_attribute(stix_package, attribute)
        exploit_target = ttp.exploit_targets.exploit_target[0].item
        self.assertEqual(exploit_target.id_, f"{_ORGNAME_ID}:ExploitTarget-{attribute['uuid']}")
        vulnerability = exploit_target.vulnerabilities[0]
        self.assertEqual(vulnerability.cve_id, attribute['value'])
        incident = stix_package.incidents[0]
        self._check_related_object(
            incident.leveraged_ttps.ttp[0],
            attribute['type'],
            attribute['uuid']
        )

    def _test_event_with_weakness_attribute(self):
        event = get_event_with_weakness_attribute()
        attribute = event['Event']['Attribute'][0]
        self.parser.parse_misp_event(event)
        stix_package = self.parser.stix_package
        ttp = self._check_ttp_fields_from_attribute(stix_package, attribute)
        exploit_target = ttp.exploit_targets.exploit_target[0].item
        self.assertEqual(exploit_target.id_, f"{_ORGNAME_ID}:ExploitTarget-{attribute['uuid']}")
        weakness = exploit_target.weaknesses[0]
        incident = stix_package.incidents[0]
        self._check_related_object(
            incident.leveraged_ttps.ttp[0],
            attribute['type'],
            attribute['uuid']
        )

    def _test_event_with_whois_registrant_attributes(self):
        event = get_event_with_whois_registrant_attributes()
        properties, attributes = self._run_observables_tests(event, 'Whois')
        email_properties, name_properties, org_properties, phone_properties = properties
        email, name, org, phone = attributes
        self.assertEqual(
            email_properties.registrants[0].email_address.address_value.value,
            email['value']
        )
        self.assertEqual(name_properties.registrants[0].name.value, name['value'])
        self.assertEqual(
            org_properties.registrants[0].organization.value,
            org['value']
        )
        self.assertEqual(
            phone_properties.registrants[0].phone_number.value,
            phone['value']
        )

    def _test_event_with_whois_registrar_attribute(self):
        event = get_event_with_whois_registrar_attribute()
        properties, attribute = self._run_observable_tests(event, 'Whois')
        self.assertEqual(properties.registrar_info.name, attribute['value'])

    def _test_event_with_windows_service_attributes(self):
        event = get_event_with_windows_service_attributes()
        properties, attributes = self._run_observables_tests(event, 'WindowsService')
        displayname_properties, name_properties = properties
        displayname, name = attributes
        self.assertEqual(displayname_properties.display_name, displayname['value'])
        self.assertEqual(name_properties.service_name, name['value'])

    def _test_event_with_x509_fingerprint_attributes(self):
        event = get_event_with_x509_fingerprint_attributes()
        properties, attributes = self._run_indicators_tests(event, 'X509Certificate')
        md5_properties, sha1_properties, sha256_properties = properties
        md5, sha1, sha256 = attributes
        md5_signature = md5_properties.certificate_signature
        self.assertEqual(md5_signature.signature_algorithm.value, "MD5")
        self.assertEqual(md5_signature.signature.value, md5['value'])
        sha1_signature = sha1_properties.certificate_signature
        self.assertEqual(sha1_signature.signature_algorithm.value, "SHA1")
        self.assertEqual(sha1_signature.signature.value, sha1['value'])
        sha256_signature = sha256_properties.certificate_signature
        self.assertEqual(sha256_signature.signature_algorithm.value, "SHA256")
        self.assertEqual(sha256_signature.signature.value, sha256['value'])

    ################################################################################
    #                          MISP OBJECTS EXPORT TESTS.                          #
    ################################################################################

    def _test_embedded_indicator_object_galaxy(self):
        event = get_embedded_indicator_object_galaxy()
        self._add_ids_flag(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        malware_galaxy = misp_object['Attribute'][0]['Galaxy'][0]
        malware_cluster = malware_galaxy['GalaxyCluster'][0]
        coa_attribute_galaxy = misp_object['Attribute'][1]['Galaxy'][0]
        coa_attribute_cluster = coa_attribute_galaxy['GalaxyCluster'][0]
        tool_galaxy, coa_event_galaxy = event['Event']['Galaxy']
        tool_cluster = tool_galaxy['GalaxyCluster'][0]
        coa_event_cluster = coa_event_galaxy['GalaxyCluster'][0]
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event)
        stix_package = self.parser.stix_package
        tool_ttp, malware_ttp = self._check_ttps_from_galaxies(
            stix_package,
            (tool_cluster['uuid'], malware_cluster['uuid']),
            (tool_galaxy['name'], malware_galaxy['name'])
        )
        malware = malware_ttp.behavior.malware_instances[0]
        self._check_embedded_features(malware, malware_cluster, 'MalwareInstance')
        tool = tool_ttp.resources.tools[0]
        self._check_embedded_features(tool, tool_cluster, 'ToolInformation', feature='name')
        self.assertEqual(len(stix_package.courses_of_action), 1)
        course_of_action = stix_package.courses_of_action[0]
        self._check_embedded_features(course_of_action, coa_attribute_cluster, 'CourseOfAction')
        self._check_embedded_features(course_of_action, coa_event_cluster, 'CourseOfAction')
        incident = stix_package.incidents[0]
        self._check_related_object(
            incident.leveraged_ttps.ttp[0],
            tool_galaxy['name'],
            tool_cluster['uuid']
        )
        indicator = incident.related_indicators.indicator[0].item
        self._check_related_object(
            indicator.indicated_ttps[0],
            malware_galaxy['name'],
            malware_cluster['uuid']
        )
        self._check_related_object(
            indicator.suggested_coas[0],
            coa_attribute_galaxy['name'],
            coa_attribute_cluster['uuid'],
            object_type='CourseOfAction'
        )
        self._check_coa_taken(incident.coa_taken[0], coa_event_cluster['uuid'])

    def _test_embedded_non_indicator_object_galaxy(self):
        event = get_embedded_non_indicator_object_galaxy()
        coa_object, ttp_object = deepcopy(event['Event']['Object'])
        malware_galaxy = ttp_object['Attribute'][0]['Galaxy'][0]
        malware_cluster = malware_galaxy['GalaxyCluster'][0]
        coa_galaxy, tool_galaxy = event['Event']['Galaxy']
        coa_cluster = coa_galaxy['GalaxyCluster'][0]
        tool_cluster = tool_galaxy['GalaxyCluster'][0]
        self.parser.parse_misp_event(event)
        stix_package = self.parser.stix_package
        tool_ttp, malware_ttp, vulnerability_ttp = self._check_ttp_length(
            stix_package,
            3
        )
        self._check_ttp_fields(
            malware_ttp,
            malware_cluster['uuid'],
            malware_galaxy['name'],
            'Galaxy'
        )
        self._check_ttp_fields(
            tool_ttp,
            tool_cluster['uuid'],
            tool_galaxy['name'],
            'Galaxy'
        )
        self._check_ttp_fields(
            vulnerability_ttp,
            ttp_object['uuid'],
            f"{ttp_object['meta-category']}: {ttp_object['name']}",
            'Object',
            timestamp=ttp_object['timestamp']
        )
        malware = malware_ttp.behavior.malware_instances[0]
        self._check_embedded_features(malware, malware_cluster, 'MalwareInstance')
        tool = tool_ttp.resources.tools[0]
        self._check_embedded_features(tool, tool_cluster, 'ToolInformation', feature='name')
        exploit_target = vulnerability_ttp.exploit_targets.exploit_target[0].item
        self.assertEqual(exploit_target.id_, f"{_ORGNAME_ID}:ExploitTarget-{ttp_object['uuid']}")
        coa_from_galaxy, coa_from_object = stix_package.courses_of_action
        self._check_embedded_features(coa_from_galaxy, coa_cluster, 'CourseOfAction')
        self._check_course_of_action_fields(coa_from_object, coa_object)
        incident = stix_package.incidents[0]
        related_tool, related_vulnerability = incident.leveraged_ttps.ttp
        self._check_related_object(
            related_tool,
            tool_galaxy['name'],
            tool_cluster['uuid']
        )
        self._check_related_object(
            related_vulnerability,
            ttp_object['name'],
            ttp_object['uuid']
        )
        self._check_related_object(
            vulnerability_ttp.related_ttps[0],
            malware_galaxy['name'],
            malware_cluster['uuid']
        )
        self.assertEqual(len(incident.coa_taken), 2)
        gcoa_taken, ecoa_taken = incident.coa_taken
        self._check_coa_taken(gcoa_taken, coa_cluster['uuid'])
        self._check_coa_taken(ecoa_taken, coa_object['uuid'])

    def _test_embedded_object_galaxy_with_multiple_clusters(self):
        event = get_embedded_object_galaxy_with_multiple_clusters()
        self._add_ids_flag(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        galaxy1 = misp_object['Attribute'][0]['Galaxy'][0]
        cluster1 = galaxy1['GalaxyCluster'][0]
        galaxy2 = misp_object['Attribute'][1]['Galaxy'][0]
        cluster2 = galaxy2['GalaxyCluster'][0]
        self.parser.parse_misp_event(event)
        stix_package = self.parser.stix_package
        ttp1, ttp2 = self._check_ttp_length(stix_package, 2)
        self._check_ttp_fields(ttp1, cluster1['uuid'], galaxy1['name'], 'Galaxy')
        self._check_ttp_fields(ttp2, cluster2['uuid'], galaxy2['name'], 'Galaxy')
        malware1 = ttp1.behavior.malware_instances[0]
        self._check_embedded_features(malware1, cluster1, 'MalwareInstance')
        malware2 = ttp2.behavior.malware_instances[0]
        self._check_embedded_features(malware2, cluster2, 'MalwareInstance')
        indicator = stix_package.incidents[0].related_indicators.indicator[0].item
        related_ttp1, related_ttp2 = indicator.indicated_ttps
        self._check_related_object(related_ttp1, galaxy1['name'], cluster1['uuid'])
        self._check_related_object(related_ttp2, galaxy2['name'], cluster2['uuid'])

    def _test_embedded_observable_object_galaxy(self):
        event = get_embedded_observable_object_galaxy()
        self._remove_ids_flags(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        galaxy = event['Event']['Galaxy'][0]
        cluster = galaxy['GalaxyCluster'][0]
        self.parser.parse_misp_event(event)
        stix_package = self.parser.stix_package
        ttp = self._check_ttp_fields_from_galaxy(stix_package, cluster['uuid'], galaxy['name'])
        tool = ttp.resources.tools[0]
        self._check_embedded_features(tool, cluster, 'ToolInformation', feature='name')
        self._check_related_object(
            stix_package.incidents[0].leveraged_ttps.ttp[0],
            galaxy['name'],
            cluster['uuid']
        )

    def _test_event_with_asn_object_indicator(self):
        event = get_event_with_asn_object()
        properties, attributes = self._run_indicator_from_object_tests(event, 'AS')
        self._check_asn_properties(properties, attributes)

    def _test_event_with_asn_object_observable(self):
        event = get_event_with_asn_object()
        properties, attributes = self._run_observable_from_object_tests(event, 'AS')
        self._check_asn_properties(properties, attributes)

    def _test_event_with_attack_pattern_object(self):
        event = get_event_with_attack_pattern_object()
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event)
        stix_package = self.parser.stix_package
        ttp = self._check_ttp_fields_from_object(stix_package, misp_object)
        attack_pattern = ttp.behavior.attack_patterns[0]
        self.assertEqual(attack_pattern.id_, f"{_ORGNAME_ID}:AttackPattern-{misp_object['uuid']}")
        id_, name, summary = misp_object['Attribute']
        self.assertEqual(attack_pattern.capec_id, f"CAPEC-{id_['value']}")
        self.assertEqual(attack_pattern.title, name['value'])
        self.assertEqual(attack_pattern.description.value, summary['value'])
        self._check_related_object(
            stix_package.incidents[0].leveraged_ttps.ttp[0],
            misp_object['name'],
            misp_object['uuid'],
            timestamp=misp_object['timestamp']
        )

    def _test_event_with_course_of_action_object(self):
        event = get_event_with_course_of_action_object()
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event)
        stix_package = self.parser.stix_package
        self.assertEqual(len(stix_package.courses_of_action), 1)
        course_of_action = stix_package.courses_of_action[0]
        self._check_course_of_action_fields(course_of_action, misp_object)
        self._check_coa_taken(
            stix_package.incidents[0].coa_taken[0],
            misp_object['uuid'],
            timestamp=misp_object['timestamp']
        )

    def _test_event_with_credential_object_indicator(self):
        event = get_event_with_credential_object()
        properties, attributes = self._run_indicator_from_object_tests(
            event,
            'UserAccount'
        )
        self._check_credential_properties(properties, attributes)

    def _test_event_with_credential_object_observable(self):
        event = get_event_with_credential_object()
        properties, attributes = self._run_observable_from_object_tests(
            event,
            'UserAccount'
        )
        self._check_credential_properties(properties, attributes)

    def _test_event_with_custom_objects(self):
        event = get_event_with_custom_objects()
        account, btc, person, report = deepcopy(event['Event']['Object'])
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event)
        incident = self.parser.stix_package.incidents[0]
        account_rindicator, btc_rindicator = incident.related_indicators.indicator
        account_indicator = self._check_indicator_object_features(
            account_rindicator,
            account,
            orgc
        )
        account_properties = self._check_observable_features(
            account_indicator.observable,
            account,
            'Custom'
        )
        self._check_custom_properties(account['Attribute'], account_properties.custom_properties)
        btc_indicator = self._check_indicator_object_features(
            btc_rindicator,
            btc,
            orgc
        )
        btc_properties = self._check_observable_features(
            btc_indicator.observable,
            btc,
            'Custom'
        )
        self._check_custom_properties(btc['Attribute'], btc_properties.custom_properties)
        person_observable, report_observable = incident.related_observables.observable
        self.assertEqual(person_observable.relationship, person['meta-category'])
        person_properties = self._check_observable_features(person_observable.item, person, 'Custom')
        self._check_custom_properties(person['Attribute'], person_properties.custom_properties)
        self.assertEqual(report_observable.relationship, report['meta-category'])
        report_properties = self._check_observable_features(report_observable.item, report, 'Custom')
        self._check_custom_properties(report['Attribute'], report_properties.custom_properties)

    def _test_event_with_domain_ip_object_indicator(self):
        event = get_event_with_domain_ip_object()
        observables, misp_object = self._run_composition_from_indicator_object_tests(event)
        self._check_domain_ip_observables(observables, misp_object['Attribute'])

    def _test_event_with_domain_ip_object_observable(self):
        event = get_event_with_domain_ip_object()
        observables, misp_object = self._run_composition_from_observable_object_tests(event)
        self._check_domain_ip_observables(observables, misp_object['Attribute'])

    def _test_event_with_email_object_indicator(self):
        event = get_event_with_email_object()
        self._add_ids_flag(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event)
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_object_features(related_indicator, misp_object, orgc)
        properties = self._check_observable_features(indicator.observable, misp_object, 'EmailMessage')
        related_objects = indicator.observable.object_.related_objects
        self._check_email_properties(properties, related_objects, misp_object['Attribute'])

    def _test_event_with_email_object_observable(self):
        event = get_event_with_email_object()
        self._remove_ids_flags(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event)
        incident = self.parser.stix_package.incidents[0]
        observable = incident.related_observables.observable[0]
        self.assertEqual(observable.relationship, misp_object['meta-category'])
        properties = self._check_observable_features(observable.item, misp_object, 'EmailMessage')
        related_objects = observable.item.object_.related_objects
        self._check_email_properties(properties, related_objects, misp_object['Attribute'])

    def _test_event_with_file_and_pe_objects_indicators(self):
        event = get_event_with_file_and_pe_objects()
        properties, misp_objects = self._run_indicator_from_objects_tests(
            event,
            'WindowsExecutableFile'
        )
        self._check_file_and_pe_properties(properties, *misp_objects)

    def _test_event_with_file_and_pe_objects_observables(self):
        event = get_event_with_file_and_pe_objects()
        properties, misp_objects = self._run_observable_from_objects_tests(
            event,
            'WindowsExecutableFile'
        )
        self._check_file_and_pe_properties(properties, *misp_objects)

    def _test_event_with_file_object_indicator(self):
        event = get_event_with_file_object()
        properties, attributes = self._run_indicator_from_object_tests(
            event,
            'File'
        )
        self._check_file_properties(properties, attributes)

    def _test_event_with_file_object_observable(self):
        event = get_event_with_file_object()
        properties, attributes = self._run_observable_from_object_tests(
            event,
            'File'
        )
        self._check_file_properties(properties, attributes)

    def _test_event_with_file_object_with_artifact_indicator(self):
        event = get_event_with_file_object_with_artifact()
        args = self._run_composition_from_indicator_object_tests(event)
        self._check_file_observables(*args)

    def _test_event_with_file_object_with_artifact_observable(self):
        event = get_event_with_file_object_with_artifact()
        args = self._run_composition_from_observable_object_tests(event)
        self._check_file_observables(*args)

    def _test_event_with_ip_port_object_indicator(self):
        event = get_event_with_ip_port_object()
        args = self._run_composition_from_indicator_object_tests(event)
        self._check_ip_port_observables(*args)

    def _test_event_with_ip_port_object_observable(self):
        event = get_event_with_ip_port_object()
        args = self._run_composition_from_observable_object_tests(event)
        self._check_ip_port_observables(*args)

    def _test_event_with_mutex_object_indicator(self):
        event = get_event_with_mutex_object()
        properties, attributes = self._run_indicator_from_object_tests(event, 'Mutex')
        self._check_mutex_properties(properties, attributes)

    def _test_event_with_mutex_object_observable(self):
        event = get_event_with_mutex_object()
        properties, attributes = self._run_observable_from_object_tests(event, 'Mutex')
        self._check_mutex_properties(properties, attributes)

    def _test_event_with_network_connection_object_indicator(self):
        event = get_event_with_network_connection_object()
        properties, attributes = self._run_indicator_from_object_tests(
            event,
            'NetworkConnection'
        )
        self._check_network_connection_properties(properties, attributes)

    def _test_event_with_network_connection_object_observable(self):
        event = get_event_with_network_connection_object()
        properties, attributes = self._run_observable_from_object_tests(
            event,
            'NetworkConnection'
        )
        self._check_network_connection_properties(properties, attributes)

    def _test_event_with_network_socket_object_indicator(self):
        event = get_event_with_network_socket_object()
        properties, attributes = self._run_indicator_from_object_tests(
            event,
            'NetworkSocket'
        )
        self._check_network_socket_properties(properties, attributes)

    def _test_event_with_network_socket_object_observable(self):
        event = get_event_with_network_socket_object()
        properties, attributes = self._run_observable_from_object_tests(
            event,
            'NetworkSocket'
        )
        self._check_network_socket_properties(properties, attributes)

    def _test_event_with_pe_and_section_object_indicator(self):
        event = get_event_with_pe_objects()
        properties, misp_objects = self._run_indicator_from_objects_tests(
            event,
            'WindowsExecutableFile'
        )
        self._check_pe_and_section_properties(properties, *misp_objects)

    def _test_event_with_pe_and_section_object_observable(self):
        event = get_event_with_pe_objects()
        properties, misp_objects = self._run_observable_from_objects_tests(
            event,
            'WindowsExecutableFile'
        )
        self._check_pe_and_section_properties(properties, *misp_objects)

    def _test_event_with_process_object_indicator(self):
        event = get_event_with_process_object()
        properties, attributes = self._run_indicator_from_object_tests(
            event,
            'Process'
        )
        self._check_process_properties(properties, attributes)

    def _test_event_with_process_object_observable(self):
        event = get_event_with_process_object()
        properties, attributes = self._run_observable_from_object_tests(
            event,
            'Process'
        )
        self._check_process_properties(properties, attributes)

    def _test_event_with_registry_key_object_indicator(self):
        event = get_event_with_registry_key_object()
        properties, attributes = self._run_indicator_from_object_tests(
            event,
            'WindowsRegistryKey'
        )
        self._check_registry_key_properties(properties, attributes)

    def _test_event_with_registry_key_object_observable(self):
        event = get_event_with_registry_key_object()
        properties, attributes = self._run_observable_from_object_tests(
            event,
            'WindowsRegistryKey'
        )
        self._check_registry_key_properties(properties, attributes)

    def _test_event_with_url_object_indicator(self):
        event = get_event_with_url_object()
        args = self._run_composition_from_indicator_object_tests(event)
        self._check_url_observables(*args)

    def _test_event_with_url_object_observable(self):
        event = get_event_with_url_object()
        args = self._run_composition_from_observable_object_tests(event)
        self._check_url_observables(*args)

    def _test_event_with_user_account_objects_indicator(self):
        event = get_event_with_user_account_objects()
        self._add_ids_flag(event)
        user, unix, windows = deepcopy(event['Event']['Object'])
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event)
        incident = self.parser.stix_package.incidents[0]
        user_rindicator, unix_rindicator, windows_rindicator = incident.related_indicators.indicator
        user_indicator = self._check_indicator_object_features(user_rindicator, user, orgc)
        user_properties = self._check_observable_features(user_indicator.observable, user, 'UserAccount')
        self._check_user_account_properties(user_properties, user['Attribute'])
        unix_indicator = self._check_indicator_object_features(unix_rindicator, unix, orgc)
        unix_properties = self._check_observable_features(unix_indicator.observable, unix, 'UnixUserAccount')
        self._check_unix_user_account_properties(unix_properties, unix['Attribute'])
        windows_indicator = self._check_indicator_object_features(windows_rindicator, windows, orgc)
        windows_properties = self._check_observable_features(windows_indicator.observable, windows, 'WindowsUserAccount')
        self._check_windows_user_account_properties(windows_properties, windows['Attribute'])

    def _test_event_with_user_account_objects_observable(self):
        event = get_event_with_user_account_objects()
        self._remove_ids_flags(event)
        user, unix, windows = deepcopy(event['Event']['Object'])
        self.parser.parse_misp_event(event)
        incident = self.parser.stix_package.incidents[0]
        user_observable, unix_observable, windows_observable = incident.related_observables.observable
        self.assertEqual(user_observable.relationship, user['meta-category'])
        user_properties = self._check_observable_features(user_observable.item, user, 'UserAccount')
        self._check_user_account_properties(user_properties, user['Attribute'])
        self.assertEqual(unix_observable.relationship, unix['meta-category'])
        unix_properties = self._check_observable_features(unix_observable.item, unix, 'UnixUserAccount')
        self._check_unix_user_account_properties(unix_properties, unix['Attribute'])
        self.assertEqual(windows_observable.relationship, windows['meta-category'])
        windows_properties = self._check_observable_features(windows_observable.item, windows, 'WindowsUserAccount')
        self._check_windows_user_account_properties(windows_properties, windows['Attribute'])

    def _test_event_with_vulnerability_and_weakness_related_object(self):
        event = get_event_with_vulnerability_and_weakness_objects()
        vulnerability, weakness = deepcopy(event['Event']['Object'])
        self.parser.parse_misp_event(event)
        stix_package = self.parser.stix_package
        vulnerability_ttp, weakness_ttp = self._check_ttp_length(stix_package, 2)
        self._check_related_object(
            vulnerability_ttp.related_ttps[0],
            'weakened-by',
            weakness['uuid'],
            timestamp=weakness['timestamp']
        )

    def _test_event_with_vulnerability_object(self):
        event = get_event_with_vulnerability_object()
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event)
        stix_package = self.parser.stix_package
        ttp = self._check_ttp_fields_from_object(stix_package, misp_object)
        exploit_target = ttp.exploit_targets.exploit_target[0].item
        self.assertEqual(exploit_target.id_, f"{_ORGNAME_ID}:ExploitTarget-{misp_object['uuid']}")
        vulnerability = exploit_target.vulnerabilities[0]
        id_, cvss, summary, created, published, reference1, reference2 = misp_object['Attribute']
        self.assertEqual(vulnerability.cve_id, id_['value'])
        self.assertEqual(vulnerability.cvss_score.overall_score, cvss['value'])
        self.assertEqual(vulnerability.description.value, summary['value'])
        self.assertEqual(vulnerability.discovered_datetime.value, datetime.strptime(created['value'], '%Y-%m-%dT%H:%M:%S'))
        self.assertEqual(vulnerability.published_datetime.value, datetime.strptime(published['value'], '%Y-%m-%dT%H:%M:%S'))
        references = vulnerability.references
        self.assertEqual(len(references), 2)
        self.assertEqual(references[0], reference1['value'])
        self.assertEqual(references[1], reference2['value'])
        self._check_related_object(
            stix_package.incidents[0].leveraged_ttps.ttp[0],
            misp_object['name'],
            misp_object['uuid'],
            timestamp=misp_object['timestamp']
        )

    def _test_event_with_weakness_object(self):
        event = get_event_with_weakness_object()
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event)
        stix_package = self.parser.stix_package
        ttp = self._check_ttp_fields_from_object(stix_package, misp_object)
        exploit_target = ttp.exploit_targets.exploit_target[0].item
        self.assertEqual(exploit_target.id_, f"{_ORGNAME_ID}:ExploitTarget-{misp_object['uuid']}")
        weakness = exploit_target.weaknesses[0]
        id_, description = misp_object['Attribute']
        self.assertEqual(weakness.cwe_id, id_['value'])
        self.assertEqual(weakness.description.value, description['value'])
        self._check_related_object(
            stix_package.incidents[0].leveraged_ttps.ttp[0],
            misp_object['name'],
            misp_object['uuid'],
            timestamp=misp_object['timestamp']
        )

    def _test_event_with_whois_object_indicator(self):
        event = get_event_with_whois_object()
        properties, attributes = self._run_indicator_from_object_tests(
            event,
            'Whois'
        )
        self._check_whois_properties(properties, attributes)

    def _test_event_with_whois_object_observable(self):
        event = get_event_with_whois_object()
        properties, attributes = self._run_observable_from_object_tests(
            event,
            'Whois'
        )
        self._check_whois_properties(properties, attributes)

    def _test_event_with_x509_object_indicator(self):
        event = get_event_with_x509_object()
        properties, attributes = self._run_indicator_from_object_tests(
            event,
            'X509Certificate'
        )
        self._check_x509_properties(properties, attributes)

    def _test_event_with_x509_object_observable(self):
        event = get_event_with_x509_object()
        properties, attributes = self._run_observable_from_object_tests(
            event,
            'X509Certificate'
        )
        self._check_x509_properties(properties, attributes)

    ################################################################################
    #                            GALAXIES EXPORT TESTS.                            #
    ################################################################################

    def _test_event_with_attack_pattern_galaxy(self):
        event = get_event_with_attack_pattern_galaxy()
        galaxy = event['Event']['Galaxy'][0]
        cluster = galaxy['GalaxyCluster'][0]
        self.parser.parse_misp_event(event)
        stix_package = self.parser.stix_package
        ttp = self._check_ttp_fields_from_galaxy(stix_package, cluster['uuid'], galaxy['name'])
        attack_pattern = ttp.behavior.attack_patterns[0]
        self._check_embedded_features(attack_pattern, cluster, 'AttackPattern')
        self._check_related_object(stix_package.incidents[0].leveraged_ttps.ttp[0], galaxy['name'], cluster['uuid'])

    def _test_event_with_course_of_action_galaxy(self):
        event = get_event_with_course_of_action_galaxy()
        cluster = event['Event']['Galaxy'][0]['GalaxyCluster'][0]
        self.parser.parse_misp_event(event)
        stix_package = self.parser.stix_package
        self.assertEqual(len(stix_package.courses_of_action), 1)
        course_of_action = stix_package.courses_of_action[0]
        self._check_embedded_features(course_of_action, cluster, 'CourseOfAction')
        self._check_coa_taken(stix_package.incidents[0].coa_taken[0], cluster['uuid'])

    def _test_event_with_malware_galaxy(self):
        event = get_event_with_malware_galaxy()
        galaxy = event['Event']['Galaxy'][0]
        cluster = galaxy['GalaxyCluster'][0]
        self.parser.parse_misp_event(event)
        stix_package = self.parser.stix_package
        ttp = self._check_ttp_fields_from_galaxy(stix_package, cluster['uuid'], galaxy['name'])
        malware = ttp.behavior.malware_instances[0]
        self._check_embedded_features(malware, cluster, 'MalwareInstance')
        self._check_related_object(stix_package.incidents[0].leveraged_ttps.ttp[0], galaxy['name'], cluster['uuid'])

    def _test_event_with_threat_actor_galaxy(self):
        event = get_event_with_threat_actor_galaxy()
        galaxy = event['Event']['Galaxy'][0]
        cluster = galaxy['GalaxyCluster'][0]
        self.parser.parse_misp_event(event)
        stix_package = self.parser.stix_package
        self.assertEqual(len(stix_package.threat_actors), 1)
        threat_actor = stix_package.threat_actors[0]
        threat_actor_id = f"{_ORGNAME_ID}:ThreatActor-{cluster['uuid']}"
        self.assertEqual(threat_actor.id_, threat_actor_id)
        self.assertEqual(threat_actor.title, cluster['value'])
        self.assertEqual(threat_actor.description.value, cluster['description'])
        intended_effect = threat_actor.intended_effects[0]
        self.assertEqual(intended_effect.value, cluster['meta']['cfr-type-of-incident'][0])
        related_threat_actor = stix_package.incidents[0].attributed_threat_actors.threat_actor[0]
        self.assertEqual(related_threat_actor.relationship.value, galaxy['name'])
        self.assertEqual(related_threat_actor.item.idref, threat_actor_id)

    def _test_event_with_tool_galaxy(self):
        event = get_event_with_tool_galaxy()
        galaxy = event['Event']['Galaxy'][0]
        cluster = galaxy['GalaxyCluster'][0]
        self.parser.parse_misp_event(event)
        stix_package = self.parser.stix_package
        ttp = self._check_ttp_fields_from_galaxy(stix_package, cluster['uuid'], galaxy['name'])
        tool = ttp.resources.tools[0]
        self._check_embedded_features(tool, cluster, 'ToolInformation', feature='name')
        self._check_related_object(stix_package.incidents[0].leveraged_ttps.ttp[0], galaxy['name'], cluster['uuid'])

    def _test_event_with_vulnerability_galaxy(self):
        event = get_event_with_vulnerability_galaxy()
        galaxy = event['Event']['Galaxy'][0]
        cluster = galaxy['GalaxyCluster'][0]
        self.parser.parse_misp_event(event)
        stix_package = self.parser.stix_package
        ttp = self._check_ttp_fields_from_galaxy(stix_package, cluster['uuid'], galaxy['name'])
        exploit_target = ttp.exploit_targets.exploit_target[0].item
        self.assertEqual(exploit_target.id_, f"{_ORGNAME_ID}:ExploitTarget-{cluster['uuid']}")
        vulnerability = exploit_target.vulnerabilities[0]
        self._check_embedded_features(vulnerability, cluster, 'Vulnerability')
        self.assertEqual(vulnerability.cve_id, cluster['meta']['aliases'][0])
        self._check_related_object(stix_package.incidents[0].leveraged_ttps.ttp[0], galaxy['name'], cluster['uuid'])


class TestStix11Export(TestStix1Export):
    def setUp(self):
        self.parser = MISPtoSTIX1EventsParser(_ORGNAME_ID, '1.1.1')

    ################################################################################
    #                              EVENT FIELDS TESTS                              #
    ################################################################################

    def test_base_event(self):
        self._test_base_event('1.1.1')

    def test_published_event(self):
        self._test_published_event()

    def test_event_with_tags(self):
        self._test_event_with_tags()

    ################################################################################
    #                        SINGLE ATTRIBUTES EXPORT TESTS                        #
    ################################################################################

    def test_embedded_indicator_attribute_galaxy(self):
        self._test_embedded_indicator_attribute_galaxy()

    def test_embedded_non_indicator_attribute_galaxy(self):
        self._test_embedded_non_indicator_attribute_galaxy()

    def test_embedded_observable_attribute_galaxy(self):
        self._test_embedded_observable_attribute_galaxy()

    def test_event_with_as_attribute(self):
        self._test_event_with_as_attribute()

    def _test_event_with_attachment_attribute(self):
        self._test_event_with_attachment_attribute()

    def test_event_with_campaign_name_attribute(self):
        self._test_event_with_campaign_name_attribute()

    def test_event_with_custom_attributes(self):
        self._test_event_with_custom_attributes()

    def test_event_with_domain_attribute(self):
        self._test_event_with_domain_attribute()

    def test_event_with_domain_ip_attribute(self):
        self._test_event_with_domain_ip_attribute()

    def test_event_with_email_attachment_attribute(self):
        self._test_event_with_email_attachment_attribute()

    def test_event_with_email_attributes(self):
        self._test_event_with_email_attributes()

    def test_event_with_email_body_attribute(self):
        self._test_event_with_email_body_attribute()

    def test_event_with_email_header_attribute(self):
        self._test_event_with_email_header_attribute()

    def test_event_with_filename_attribute(self):
        self._test_event_with_filename_attribute()

    def test_event_with_hash_attributes(self):
        self._test_event_with_hash_attributes()

    def test_event_with_hash_composite_attributes(self):
        self._test_event_with_hash_composite_attributes()

    def test_event_with_hostname_attribute(self):
        self._test_event_with_hostname_attribute()

    def test_event_with_hostname_port_attribute(self):
        self._test_event_with_hostname_port_attribute()

    def test_event_with_http_attributes(self):
        self._test_event_with_http_attributes()

    def test_event_with_ip_attributes(self):
        self._test_event_with_ip_attributes()

    def test_event_with_ip_port_attributes(self):
        self._test_event_with_ip_port_attributes()

    def test_event_with_mac_address_attribute(self):
        self._test_event_with_mac_address_attribute()

    def test_event_with_malware_sample_attribute(self):
        self._test_event_with_malware_sample_attribute()

    def test_event_with_mutex_attribute(self):
        self._test_event_with_mutex_attribute()

    def test_event_with_named_pipe_attribute(self):
        self._test_event_with_named_pipe_attribute()

    def test_event_with_pattern_attribute(self):
        self._test_event_with_pattern_attribute()

    def test_event_with_port_attribute(self):
        self._test_event_with_port_attribute()

    def test_event_with_regkey_attribute(self):
        self._test_event_with_regkey_attribute()

    def test_event_with_regkey_value_attribute(self):
        self._test_event_with_regkey_value_attribute()

    def test_event_with_size_in_bytes_attribute(self):
        self._test_event_with_size_in_bytes_attribute()

    def test_event_with_target_attributes(self):
        self._test_event_with_target_attributes()

    def test_event_with_test_mechanism_attributes(self):
        self._test_event_with_test_mechanism_attributes()

    def test_event_with_undefined_attributes(self):
        self._test_event_with_undefined_attributes()

    def test_event_with_url_attribute(self):
        self._test_event_with_url_attribute()

    def test_event_with_vulnerability_attribute(self):
        self._test_event_with_vulnerability_attribute()

    def test_event_with_weakness_attribute(self):
        self._test_event_with_weakness_attribute()

    def test_event_with_whois_registrant_attributes(self):
        self._test_event_with_whois_registrant_attributes()

    def test_event_with_whois_registrar_attribute(self):
        self._test_event_with_whois_registrar_attribute()

    def test_event_with_windows_service_attributes(self):
        self._test_event_with_windows_service_attributes()

    def test_event_with_x509_fingerprint_attributes(self):
        self._test_event_with_x509_fingerprint_attributes()

    ################################################################################
    #                          MISP OBJECTS EXPORT TESTS.                          #
    ################################################################################

    def test_embedded_indicator_object_galaxy(self):
        self._test_embedded_indicator_object_galaxy()

    def test_embedded_non_indicator_object_galaxy(self):
        self._test_embedded_non_indicator_object_galaxy()

    def test_embedded_object_galaxy_with_multiple_clusters(self):
        self._test_embedded_object_galaxy_with_multiple_clusters()

    def test_embedded_observable_object_galaxy(self):
        self._test_embedded_observable_object_galaxy()

    def test_event_with_asn_object_indicator(self):
        self._test_event_with_asn_object_indicator()

    def test_event_with_asn_object_observable(self):
        self._test_event_with_asn_object_observable()

    def est_event_with_attack_pattern_object(self):
        self._test_event_with_attack_pattern_object()

    def test_event_with_course_of_action_object(self):
        self._test_event_with_course_of_action_object()

    def test_event_with_credential_object_indicator(self):
        self._test_event_with_credential_object_indicator()

    def test_event_with_credential_object_observable(self):
        self._test_event_with_credential_object_observable()

    def test_event_with_custom_objects(self):
        self._test_event_with_custom_objects()

    def test_event_with_domain_ip_object_indicator(self):
        self._test_event_with_domain_ip_object_indicator()

    def test_event_with_domain_ip_object_observable(self):
        self._test_event_with_domain_ip_object_observable()

    def test_event_with_email_object_indicator(self):
        self._test_event_with_email_object_indicator()

    def test_event_with_email_object_observable(self):
        self._test_event_with_email_object_observable()

    def test_event_with_file_and_pe_objects_indicators(self):
        self._test_event_with_file_and_pe_objects_indicators()

    def test_event_with_file_and_pe_objects_observables(self):
        self._test_event_with_file_and_pe_objects_observables()

    def test_event_with_file_object_indicator(self):
        self._test_event_with_file_object_indicator()

    def test_event_with_file_object_observable(self):
        self._test_event_with_file_object_observable()

    def test_event_with_file_object_with_artifact_indicator(self):
        self._test_event_with_file_object_with_artifact_indicator()

    def test_event_with_file_object_with_artifact_observable(self):
        self._test_event_with_file_object_with_artifact_observable()

    def test_event_with_ip_port_object_indicator(self):
        self._test_event_with_ip_port_object_indicator()

    def test_event_with_ip_port_object_observable(self):
        self._test_event_with_ip_port_object_observable()

    def test_event_with_mutex_object_indicator(self):
        self._test_event_with_mutex_object_indicator()

    def test_event_with_mutex_object_observable(self):
        self._test_event_with_mutex_object_observable()

    def test_event_with_network_connection_object_indicator(self):
        self._test_event_with_network_connection_object_indicator()

    def test_event_with_network_connection_object_observable(self):
        self._test_event_with_network_connection_object_observable()

    def test_event_with_network_socket_object_indicator(self):
        self._test_event_with_network_socket_object_indicator()

    def test_event_with_network_socket_object_observable(self):
        self._test_event_with_network_socket_object_observable()

    def test_event_with_pe_and_section_object_indicator(self):
        self._test_event_with_pe_and_section_object_indicator()

    def test_event_with_pe_and_section_object_observable(self):
        self._test_event_with_pe_and_section_object_observable()

    def test_event_with_process_object_indicator(self):
        self._test_event_with_process_object_indicator()

    def test_event_with_process_object_observable(self):
        self._test_event_with_process_object_observable()

    def test_event_with_registry_key_object_indicator(self):
        self._test_event_with_registry_key_object_indicator()

    def test_event_with_registry_key_object_observable(self):
        self._test_event_with_registry_key_object_observable()

    def test_event_with_url_object_indicator(self):
        self._test_event_with_url_object_indicator()

    def test_event_with_url_object_observable(self):
        self._test_event_with_url_object_observable()

    def test_event_with_user_account_objects_indicator(self):
        self._test_event_with_user_account_objects_indicator()

    def test_event_with_user_account_objects_observable(self):
        self._test_event_with_user_account_objects_observable()

    def test_event_with_vulnerability_and_weakness_related_object(self):
        self._test_event_with_vulnerability_and_weakness_related_object()

    def test_event_with_vulnerability_object(self):
        self._test_event_with_vulnerability_object()

    def test_event_with_weakness_object(self):
        self._test_event_with_weakness_object()

    def test_event_with_whois_object_indicator(self):
        self._test_event_with_whois_object_indicator()

    def test_event_with_whois_object_observable(self):
        self._test_event_with_whois_object_observable()

    def test_event_with_x509_object_indicator(self):
        self._test_event_with_x509_object_indicator()

    def test_event_with_x509_object_observable(self):
        self._test_event_with_x509_object_observable()

    ################################################################################
    #                            GALAXIES EXPORT TESTS.                            #
    ################################################################################

    def test_event_with_attack_pattern_galaxy(self):
        self._test_event_with_attack_pattern_galaxy()

    def test_event_with_course_of_action_galaxy(self):
        self._test_event_with_course_of_action_galaxy()

    def test_event_with_malware_galaxy(self):
        self._test_event_with_malware_galaxy()

    def test_event_with_threat_actor_galaxy(self):
        self._test_event_with_threat_actor_galaxy()

    def test_event_with_tool_galaxy(self):
        self._test_event_with_tool_galaxy()

    def test_event_with_vulnerability_galaxy(self):
        self._test_event_with_vulnerability_galaxy()


class TestStix12Export(TestStix1Export):
    def setUp(self):
        self.parser = MISPtoSTIX1EventsParser(_ORGNAME_ID, '1.2')

    ################################################################################
    #                              EVENT FIELDS TESTS                              #
    ################################################################################

    def test_base_event(self):
        self._test_base_event('1.2')

    def test_published_event(self):
        self._test_published_event()

    def test_event_with_tags(self):
        self._test_event_with_tags()

    ################################################################################
    #                        SINGLE ATTRIBUTES EXPORT TESTS                        #
    ################################################################################

    def test_embedded_indicator_attribute_galaxy(self):
        self._test_embedded_indicator_attribute_galaxy()

    def test_embedded_non_indicator_attribute_galaxy(self):
        self._test_embedded_non_indicator_attribute_galaxy()

    def test_embedded_observable_attribute_galaxy(self):
        self._test_embedded_observable_attribute_galaxy()

    def test_event_with_as_attribute(self):
        self._test_event_with_as_attribute()

    def _test_event_with_attachment_attribute(self):
        self._test_event_with_attachment_attribute()

    def test_event_with_campaign_name_attribute(self):
        self._test_event_with_campaign_name_attribute()

    def test_event_with_custom_attributes(self):
        self._test_event_with_custom_attributes()

    def test_event_with_domain_attribute(self):
        self._test_event_with_domain_attribute()

    def test_event_with_domain_ip_attribute(self):
        self._test_event_with_domain_ip_attribute()

    def test_event_with_email_attachment_attribute(self):
        self._test_event_with_email_attachment_attribute()

    def test_event_with_email_attributes(self):
        self._test_event_with_email_attributes()

    def test_event_with_email_body_attribute(self):
        self._test_event_with_email_body_attribute()

    def test_event_with_email_header_attribute(self):
        self._test_event_with_email_header_attribute()

    def test_event_with_filename_attribute(self):
        self._test_event_with_filename_attribute()

    def test_event_with_hash_attributes(self):
        self._test_event_with_hash_attributes()

    def test_event_with_hash_composite_attributes(self):
        self._test_event_with_hash_composite_attributes()

    def test_event_with_hostname_attribute(self):
        self._test_event_with_hostname_attribute()

    def test_event_with_hostname_port_attribute(self):
        self._test_event_with_hostname_port_attribute()

    def test_event_with_http_attributes(self):
        self._test_event_with_http_attributes()

    def test_event_with_ip_attributes(self):
        self._test_event_with_ip_attributes()

    def test_event_with_ip_port_attributes(self):
        self._test_event_with_ip_port_attributes()

    def test_event_with_mac_address_attribute(self):
        self._test_event_with_mac_address_attribute()

    def test_event_with_malware_sample_attribute(self):
        self._test_event_with_malware_sample_attribute()

    def _test_event_with_mutex_attribute(self):
        self._test_event_with_mutex_attribute()

    def _test_event_with_named_pipe_attribute(self):
        self._test_event_with_named_pipe_attribute()

    def _test_event_with_pattern_attribute(self):
        self._test_event_with_pattern_attribute()

    def _test_event_with_port_attribute(self):
        self._test_event_with_port_attribute()

    def _test_event_with_regkey_attribute(self):
        self._test_event_with_regkey_attribute()

    def _test_event_with_regkey_value_attribute(self):
        self._test_event_with_regkey_value_attribute()

    def _test_event_with_size_in_bytes_attribute(self):
        self._test_event_with_size_in_bytes_attribute()

    def _test_event_with_target_attributes(self):
        self._test_event_with_target_attributes()

    def _test_event_with_test_mechanism_attributes(self):
        self._test_event_with_test_mechanism_attributes()

    def _test_event_with_undefined_attributes(self):
        self._test_event_with_undefined_attributes()

    def _test_event_with_url_attribute(self):
        self._test_event_with_url_attribute()

    def _test_event_with_vulnerability_attribute(self):
        self._test_event_with_vulnerability_attribute()

    def _test_event_with_weakness_attribute(self):
        self._test_event_with_weakness_attribute()

    def _test_event_with_whois_registrant_attributes(self):
        self._test_event_with_whois_registrant_attributes()

    def _test_event_with_whois_registrar_attribute(self):
        self._test_event_with_whois_registrar_attribute()

    def _test_event_with_windows_service_attributes(self):
        self._test_event_with_windows_service_attributes()

    def _test_event_with_x509_fingerprint_attributes(self):
        self._test_event_with_x509_fingerprint_attributes()

    ################################################################################
    #                          MISP OBJECTS EXPORT TESTS.                          #
    ################################################################################

    def test_embedded_indicator_object_galaxy(self):
        self._test_embedded_indicator_object_galaxy()

    def test_embedded_non_indicator_object_galaxy(self):
        self._test_embedded_non_indicator_object_galaxy()

    def test_embedded_object_galaxy_with_multiple_clusters(self):
        self._test_embedded_object_galaxy_with_multiple_clusters()

    def test_embedded_observable_object_galaxy(self):
        self._test_embedded_observable_object_galaxy()

    def test_event_with_asn_object_indicator(self):
        self._test_event_with_asn_object_indicator()

    def test_event_with_asn_object_observable(self):
        self._test_event_with_asn_object_observable()

    def est_event_with_attack_pattern_object(self):
        self._test_event_with_attack_pattern_object()

    def test_event_with_course_of_action_object(self):
        self._test_event_with_course_of_action_object()

    def test_event_with_credential_object_indicator(self):
        self._test_event_with_credential_object_indicator()

    def test_event_with_credential_object_observable(self):
        self._test_event_with_credential_object_observable()

    def test_event_with_custom_objects(self):
        self._test_event_with_custom_objects()

    def test_event_with_domain_ip_object_indicator(self):
        self._test_event_with_domain_ip_object_indicator()

    def test_event_with_domain_ip_object_observable(self):
        self._test_event_with_domain_ip_object_observable()

    def test_event_with_email_object_indicator(self):
        self._test_event_with_email_object_indicator()

    def test_event_with_email_object_observable(self):
        self._test_event_with_email_object_observable()

    def test_event_with_file_and_pe_objects_indicators(self):
        self._test_event_with_file_and_pe_objects_indicators()

    def test_event_with_file_and_pe_objects_observables(self):
        self._test_event_with_file_and_pe_objects_observables()

    def test_event_with_file_object_indicator(self):
        self._test_event_with_file_object_indicator()

    def test_event_with_file_object_observable(self):
        self._test_event_with_file_object_observable()

    def test_event_with_file_object_with_artifact_indicator(self):
        self._test_event_with_file_object_with_artifact_indicator()

    def test_event_with_file_object_with_artifact_observable(self):
        self._test_event_with_file_object_with_artifact_observable()

    def test_event_with_ip_port_object_indicator(self):
        self._test_event_with_ip_port_object_indicator()

    def test_event_with_ip_port_object_observable(self):
        self._test_event_with_ip_port_object_observable()

    def test_event_with_mutex_object_indicator(self):
        self._test_event_with_mutex_object_indicator()

    def test_event_with_mutex_object_observable(self):
        self._test_event_with_mutex_object_observable()

    def test_event_with_network_connection_object_indicator(self):
        self._test_event_with_network_connection_object_indicator()

    def test_event_with_network_connection_object_observable(self):
        self._test_event_with_network_connection_object_observable()

    def test_event_with_network_socket_object_indicator(self):
        self._test_event_with_network_socket_object_indicator()

    def test_event_with_network_socket_object_observable(self):
        self._test_event_with_network_socket_object_observable()

    def test_event_with_pe_and_section_object_indicator(self):
        self._test_event_with_pe_and_section_object_indicator()

    def test_event_with_pe_and_section_object_observable(self):
        self._test_event_with_pe_and_section_object_observable()

    def test_event_with_process_object_indicator(self):
        self._test_event_with_process_object_indicator()

    def test_event_with_process_object_observable(self):
        self._test_event_with_process_object_observable()

    def test_event_with_registry_key_object_indicator(self):
        self._test_event_with_registry_key_object_indicator()

    def test_event_with_registry_key_object_observable(self):
        self._test_event_with_registry_key_object_observable()

    def test_event_with_url_object_indicator(self):
        self._test_event_with_url_object_indicator()

    def test_event_with_url_object_observable(self):
        self._test_event_with_url_object_observable()

    def test_event_with_user_account_objects_indicator(self):
        self._test_event_with_user_account_objects_indicator()

    def test_event_with_user_account_objects_observable(self):
        self._test_event_with_user_account_objects_observable()

    def test_event_with_vulnerability_and_weakness_related_object(self):
        self._test_event_with_vulnerability_and_weakness_related_object()

    def test_event_with_vulnerability_object(self):
        self._test_event_with_vulnerability_object()

    def test_event_with_weakness_object(self):
        self._test_event_with_weakness_object()

    def test_event_with_whois_object_indicator(self):
        self._test_event_with_whois_object_indicator()

    def test_event_with_whois_object_observable(self):
        self._test_event_with_whois_object_observable()

    def test_event_with_x509_object_indicator(self):
        self._test_event_with_x509_object_indicator()

    def test_event_with_x509_object_observable(self):
        self._test_event_with_x509_object_observable()

    ################################################################################
    #                            GALAXIES EXPORT TESTS.                            #
    ################################################################################

    def test_event_with_attack_pattern_galaxy(self):
        self._test_event_with_attack_pattern_galaxy()

    def test_event_with_course_of_action_galaxy(self):
        self._test_event_with_course_of_action_galaxy()

    def test_event_with_malware_galaxy(self):
        self._test_event_with_malware_galaxy()

    def test_event_with_threat_actor_galaxy(self):
        self._test_event_with_threat_actor_galaxy()

    def test_event_with_tool_galaxy(self):
        self._test_event_with_tool_galaxy()

    def test_event_with_vulnerability_galaxy(self):
        self._test_event_with_vulnerability_galaxy()


class TestCollectionStix1Export(TestCollectionSTIX1Export):
    def test_attribute_collection_export_11(self):
        name = 'test_attributes_collection'
        to_test_name = f'{name}.json.out'
        reference_name = f'{name}_stix11.xml'
        output_file = self._current_path / to_test_name
        input_files = [self._current_path / f'{name}_{n}.json' for n in (1, 2)]
        self.assertEqual(
            misp_attribute_collection_to_stix1(
                output_file,
                *input_files,
                return_format='xml',
                version='1.1.1',
                in_memory=True
            ),
            1
        )
        self._check_stix1_export_results(to_test_name, reference_name)
        self.assertEqual(
            misp_attribute_collection_to_stix1(
                output_file,
                *input_files,
                return_format='xml',
                version='1.1.1'
            ),
            1
        )
        self._check_stix1_export_results(to_test_name, reference_name)

    def test_attribute_collection_export_12(self):
        name = 'test_attributes_collection'
        to_test_name = f'{name}.json.out'
        reference_name = f'{name}_stix12.xml'
        output_file = self._current_path / to_test_name
        input_files = [self._current_path / f'{name}_{n}.json' for n in (1, 2)]
        self.assertEqual(
            misp_attribute_collection_to_stix1(
                output_file,
                *input_files,
                return_format='xml',
                version='1.2',
                in_memory=True
            ),
            1
        )
        self._check_stix1_export_results(to_test_name, reference_name)
        self.assertEqual(
            misp_attribute_collection_to_stix1(
                output_file,
                *input_files,
                return_format='xml',
                version='1.2'
            ),
            1
        )
        self._check_stix1_export_results(to_test_name, reference_name)

    def test_event_collection_export_11(self):
        name = 'test_events_collection'
        to_test_name = f'{name}.json.out'
        reference_name = f'{name}_stix11.xml'
        output_file = self._current_path / to_test_name
        input_files = [self._current_path / f'{name}_{n}.json' for n in (1, 2)]
        self.assertEqual(
            misp_event_collection_to_stix1(
                output_file,
                *input_files,
                return_format='xml',
                version='1.1.1'
            ),
            1
        )
        self._check_stix1_collection_export_results(to_test_name, reference_name)
        self.assertEqual(
            misp_event_collection_to_stix1(
                output_file,
                *input_files,
                return_format='xml',
                version='1.1.1',
                in_memory=True
            ),
            1
        )
        self._check_stix1_collection_export_results(to_test_name, reference_name)

    def test_event_collection_export_12(self):
        name = 'test_events_collection'
        to_test_name = f'{name}.json.out'
        reference_name = f'{name}_stix12.xml'
        output_file = self._current_path / to_test_name
        input_files = [self._current_path / f'{name}_{n}.json' for n in (1, 2)]
        self.assertEqual(
            misp_event_collection_to_stix1(
                output_file,
                *input_files,
                return_format='xml',
                version='1.2'
            ),
            1
        )
        self._check_stix1_collection_export_results(to_test_name, reference_name)
        self.assertEqual(
            misp_event_collection_to_stix1(
                output_file,
                *input_files,
                return_format='xml',
                version='1.2',
                in_memory=True
            ),
            1
        )
        self._check_stix1_collection_export_results(to_test_name, reference_name)

    def test_event_export_11(self):
        name = 'test_events_collection_1.json'
        self.assertEqual(misp_to_stix1(self._current_path / name, 'xml', '1.1.1'), 1)
        self._check_stix1_export_results(f'{name}.out', 'test_event_stix11.xml')

    def test_event_export_12(self):
        name = 'test_events_collection_1.json'
        self.assertEqual(misp_to_stix1(self._current_path / name, 'xml', '1.2'), 1)
        self._check_stix1_export_results(f'{name}.out', 'test_event_stix12.xml')
