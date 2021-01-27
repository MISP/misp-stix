#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import json
import os
from datetime import datetime, timezone
from misp_stix_converter import MISPtoSTIX1Parser, misp_to_stix, stix_framing
from .test_events import *

_DEFAULT_NAMESPACE = 'https://github.com/MISP/MISP'
_DEFAULT_ORGNAME = 'MISP-Project'

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
    def setUp(self):
        self.parser = MISPtoSTIX1Parser(_DEFAULT_ORGNAME)

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
        self.assertEqual(coa_taken.course_of_action.idref, f'{_DEFAULT_ORGNAME}:CourseOfAction-{uuid}')
        if timestamp is not None:
            self.assertEqual(
                coa_taken.course_of_action.timestamp,
                datetime.utcfromtimestamp(int(timestamp))
            )

    def _check_course_of_action_fields(self, course_of_action, misp_object):
        self.assertEqual(course_of_action.id_, f"{_DEFAULT_ORGNAME}:CourseOfAction-{misp_object['uuid']}")
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
        from_, to_, cc1, cc2, reply_to, subject, attachment1, attachment2, x_mailer, user_agent, boundary = attributes
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
        attachments = properties.attachments
        self.assertEqual(len(attachments), 2)
        self.assertEqual(len(related_objects), 2)
        for attachment, related_object, attribute in zip(attachments, related_objects, (attachment1, attachment2)):
            self.assertEqual(attachment.object_reference, related_object.id_)
            self.assertEqual(related_object.relationship, 'Contains')
            self.assertEqual(related_object.properties.file_name.value, attribute['value'])

    def _check_embedded_features(self, embedded_object, cluster, name, feature='title'):
        self.assertEqual(embedded_object.id_, f"{_DEFAULT_ORGNAME}:{name}-{cluster['uuid']}")
        self.assertEqual(getattr(embedded_object, feature), cluster['value'])
        self.assertEqual(embedded_object.description.value, cluster['description'])

    def _check_file_and_pe_properties(self, properties, file_object, pe_object, section_object):
        filename, md5, sha1, sha256, size, entropy = file_object['Attribute']
        self.assertEqual(properties.file_name.value, filename['value'])
        self.assertEqual(properties.size_in_bytes.value, int(size['value']))
        self.assertEqual(properties.peak_entropy.value, float(entropy['value']))
        self.assertEqual(len(properties.hashes), 3)
        for hash_property, attribute in zip(properties.hashes, (md5, sha1, sha256)):
            self._check_hash_property(hash_property, attribute['value'], attribute['type'].upper())
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
            self._check_hash_property(hash_property, attribute['value'], attribute['type'].upper())
        self.assertEqual(ssdeep_hash.type_.value, ssdeep['type'].upper())
        self.assertEqual(ssdeep_hash.fuzzy_hash_value.value, ssdeep['value'])

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
            self._check_hash_property(hash_property, attribute['value'], attribute['type'].upper())

    def _check_hash_property(self, hash_property, value, hash_type):
        self.assertEqual(hash_property.type_.value, hash_type)
        self.assertEqual(hash_property.simple_hash_value.value, value)

    def _check_identity_features(self, identity, attribute):
        self.assertEqual(identity.id_, f"{_DEFAULT_ORGNAME}:Identity-{attribute['uuid']}")
        self.assertEqual(identity.name, f"{attribute['category']}: {attribute['value']} (MISP Attribute)")

    def _check_indicator_attribute_features(self, related_indicator, attribute, orgc):
        self.assertEqual(related_indicator.relationship, attribute['category'])
        indicator = related_indicator.item
        self.assertEqual(indicator.id_, f"{_DEFAULT_ORGNAME}:Indicator-{attribute['uuid']}")
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
        self.assertEqual(indicator.id_, f"{_DEFAULT_ORGNAME}:Indicator-{misp_object['uuid']}")
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
        self.assertEqual(len(observables), len(attributes))
        ip, port, domain = attributes
        ip_observable, port_observable, domain_observable = observables
        ip_properties = self._check_observable_features(ip_observable, ip, 'Address')
        self.assertEqual(ip_properties.address_value.value, ip['value'])
        self.assertEqual(port_observable.id_, f"{_DEFAULT_ORGNAME}:Observable-{port['uuid']}")
        port_object = port_observable.object_
        self.assertEqual(port_object.id_, f"{_DEFAULT_ORGNAME}:dstPort-{port['uuid']}")
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
        self._check_hash_property(properties.hashes[0], md5, 'MD5')

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

    def _check_network_socket_prooperties(self, properties, attributes):
        ip_src, ip_dst, src_port, dst_port, hostname, address, domain, state, protocol = attributes
        src_socket = properties.local_address
        self.assertEqual(src_socket.ip_address.address_value.value, ip_src['value'])
        self.assertEqual(src_socket.port.port_value.value, int(src_port['value']))
        dst_socket = properties.remote_address
        self.assertEqual(dst_socket.ip_address.address_value.value, ip_dst['value'])
        self.assertEqual(dst_socket.hostname.hostname_value.value, hostname['value'])
        self.assertEqual(dst_socket.port.port_value.value, int(dst_port['value']))
        self.assertEqual(properties.address_family.value, address['value'])
        self.assertEqual(properties.domain.value, domain['value'])
        self.assertEqual(properties.protocol.value[0], protocol['value'])
        self.assertEqual(getattr(properties, f"is_{state['value']}"), True)

    def _check_observable_features(self, observable, attribute, name):
        self.assertEqual(observable.id_, f"{_DEFAULT_ORGNAME}:Observable-{attribute['uuid']}")
        observable_object = observable.object_
        self.assertEqual(observable_object.id_, f"{_DEFAULT_ORGNAME}:{name}-{attribute['uuid']}")
        properties = observable_object.properties
        self.assertEqual(properties._XSI_TYPE, f'{name}ObjectType')
        return properties

    def _check_process_properties(self, properties, attributes):
        pid, child, parent, name, image, port = attributes
        self.assertEqual(properties.pid.value, int(pid['value']))
        self.assertEqual(properties.parent_pid.value, int(parent['value']))
        self.assertEqual(properties.name.value, name['value'])
        self.assertEqual(len(properties.child_pid_list), 1)
        self.assertEqual(properties.child_pid_list[0].value, int(child['value']))
        self.assertEqual(properties.image_info.file_name.value, image['value'])
        self.assertEqual(len(properties.port_list), 1)
        self.assertEqual(properties.port_list[0].port_value.value, int(port['value']))

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
        self.assertEqual(related_ttp.item.idref, f"{_DEFAULT_ORGNAME}:{object_type}-{cluster_uuid}")
        if timestamp is not None:
            self.assertEqual(
                related_ttp.item.timestamp,
                datetime.utcfromtimestamp(int(timestamp))
            )

    def _check_source_address(self, properties, category='ipv4-addr'):
        self.assertEqual(properties.category, category)
        self.assertTrue(properties.is_source)
        self.assertFalse(properties.is_destination)

    def _check_ttp_fields(self, ttp, uuid, identifier, object_type):
        self.assertEqual(ttp.id_, f"{_DEFAULT_ORGNAME}:TTP-{uuid}")
        self.assertEqual(ttp.title, f"{identifier} (MISP {object_type})")

    def _check_ttp_fields_from_attribute(self, stix_package, attribute):
        ttp = self._check_ttp_length(stix_package, 1)[0]
        self._check_ttp_fields(
            ttp,
            attribute['uuid'],
            f"{attribute['category']}: {attribute['value']}",
            'Attribute'
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
            'Object'
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

    ################################################################################
    #                              EVENT FIELDS TESTS                              #
    ################################################################################

    def test_base_event(self):
        event = get_base_event()
        uuid = event['Event']['uuid']
        info = event['Event']['info']
        self.parser.parse_misp_event(event, '1.1.1')
        stix_package = self.parser.stix_package
        self.assertEqual(stix_package.id_, f"{_DEFAULT_ORGNAME}:STIXPackage-{uuid}")
        self.assertEqual(
            self._get_utc_timestamp(stix_package.timestamp),
            int(event['Event']['timestamp'])
        )
        self.assertEqual(stix_package.version, '1.1.1')
        self.assertEqual(stix_package.stix_header.title, f"Export from {_DEFAULT_ORGNAME}'s MISP")
        incident = stix_package.incidents[0]
        self.assertEqual(incident.id_, f"{_DEFAULT_ORGNAME}:Incident-{uuid}")
        self.assertEqual(incident.title, info)
        self.assertEqual(incident.information_source.identity.name, _DEFAULT_ORGNAME)
        self.assertEqual(incident.reporter.identity.name, _DEFAULT_ORGNAME)

    def test_published_event(self):
        event = get_published_event()
        self.parser.parse_misp_event(event, '1.1.1')
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

    def test_embedded_indicator_attribute_galaxy(self):
        event = get_embedded_indicator_attribute_galaxy()
        attribute = event['Event']['Attribute'][0]
        ap_galaxy, coa_galaxy = attribute['Galaxy']
        ap_cluster = ap_galaxy['GalaxyCluster'][0]
        coa_cluster = coa_galaxy['GalaxyCluster'][0]
        galaxy = event['Event']['Galaxy'][0]
        cluster = galaxy['GalaxyCluster'][0]
        self.parser.parse_misp_event(event, '1.1.1')
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

    def test_embedded_non_indicator_attribute_galaxy(self):
        event = get_embedded_non_indicator_attribute_galaxy()
        attribute = event['Event']['Attribute'][0]
        attribute_galaxy = attribute['Galaxy'][0]
        attribute_cluster = attribute_galaxy['GalaxyCluster'][0]
        coa_galaxy, malware_galaxy = event['Event']['Galaxy']
        coa_cluster = coa_galaxy['GalaxyCluster'][0]
        malware_cluster = malware_galaxy['GalaxyCluster'][0]
        self.parser.parse_misp_event(event, '1.1.1')
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
            'Attribute'
        )
        attack_pattern = attack_pattern_ttp.behavior.attack_patterns[0]
        self._check_embedded_features(attack_pattern, attribute_cluster, 'AttackPattern')
        malware = malware_ttp.behavior.malware_instances[0]
        self._check_embedded_features(malware, malware_cluster, 'MalwareInstance')
        exploit_target = vulnerability_ttp.exploit_targets.exploit_target[0].item
        self.assertEqual(exploit_target.id_, f"{_DEFAULT_ORGNAME}:ExploitTarget-{attribute['uuid']}")
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

    def test_embedded_observable_attribute_galaxy(self):
        event = get_embedded_observable_attribute_galaxy()
        attribute = event['Event']['Attribute'][0]
        galaxy = event['Event']['Galaxy'][0]
        cluster = galaxy['GalaxyCluster'][0]
        self.parser.parse_misp_event(event, '1.1.1')
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

    def test_event_with_as_attribute(self):
        event = get_event_with_as_attribute()
        attribute = event['Event']['Attribute'][0]
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        observable = incident.related_observables.observable[0]
        self.assertEqual(observable.relationship, attribute['category'])
        properties = self._check_observable_features(observable.item, attribute, 'AS')
        self.assertEqual(properties.handle.value, attribute['value'])

    def test_event_with_attachment_attribute(self):
        event = get_event_with_attachment_attribute()
        attribute = event['Event']['Attribute'][0]
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        observable = incident.related_observables.observable[0]
        self.assertEqual(observable.relationship, attribute['category'])
        self._check_attachment_properties(observable.item, attribute)

    def test_event_with_custom_attributes(self):
        event = get_event_with_custom_attributes()
        btc, iban, phone, passport = event['Event']['Attribute']
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
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

    def test_event_with_domain_attribute(self):
        event = get_event_with_domain_attribute()
        attribute = event['Event']['Attribute'][0]
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_attribute_features(related_indicator, attribute, orgc)
        properties = self._check_observable_features(indicator.observable, attribute, 'DomainName')
        self.assertEqual(properties.value.value, attribute['value'])

    def test_event_with_domain_ip_attribute(self):
        event = get_event_with_domain_ip_attribute()
        attribute = event['Event']['Attribute'][0]
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_attribute_features(related_indicator, attribute, orgc)
        observable = indicator.observable
        self.assertEqual(observable.id_, f"{_DEFAULT_ORGNAME}:ObservableComposition-{attribute['uuid']}")
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
        indicator = self._check_indicator_attribute_features(related_indicator, attribute, orgc)
        properties = self._check_observable_features(indicator.observable, attribute, 'EmailMessage')
        referenced_uuid = f"{_DEFAULT_ORGNAME}:File-{attribute['uuid']}"
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
        indicator = self._check_indicator_attribute_features(related_indicator, attribute, orgc)
        properties = self._check_observable_features(indicator.observable, attribute, 'File')
        self.assertEqual(properties.file_name.value, attribute['value'])

    def test_event_with_hash_attributes(self):
        event = get_event_with_hash_attributes()
        md5, tlsh = event['Event']['Attribute']
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        md5_r_indicator, tlsh_r_indicator = incident.related_indicators.indicator
        md5_indicator = self._check_indicator_attribute_features(md5_r_indicator, md5, orgc)
        md5_properties = self._check_observable_features(md5_indicator.observable, md5, 'File')
        self._check_hash_property(md5_properties.hashes[0], md5['value'], 'MD5')
        tlsh_indicator = self._check_indicator_attribute_features(tlsh_r_indicator, tlsh, orgc)
        tlsh_properties = self._check_observable_features(tlsh_indicator.observable, tlsh, 'File')
        self._check_hash_property(tlsh_properties.hashes[0], tlsh['value'], 'Other')

    def test_event_with_hash_composite_attributes(self):
        event = get_event_with_hash_composite_attributes()
        md5, tlsh = event['Event']['Attribute']
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        md5_r_indicator, tlsh_r_indicator = incident.related_indicators.indicator
        md5_indicator = self._check_indicator_attribute_features(md5_r_indicator, md5, orgc)
        md5_properties = self._check_observable_features(md5_indicator.observable, md5, 'File')
        filename, md5_value = md5['value'].split('|')
        self.assertEqual(md5_properties.file_name.value, filename)
        self._check_hash_property(md5_properties.hashes[0], md5_value, 'MD5')
        tlsh_indicator = self._check_indicator_attribute_features(tlsh_r_indicator, tlsh, orgc)
        tlsh_properties = self._check_observable_features(tlsh_indicator.observable, tlsh, 'File')
        filename, tlsh_value = tlsh['value'].split('|')
        self.assertEqual(tlsh_properties.file_name.value, filename)
        self._check_hash_property(tlsh_properties.hashes[0], tlsh_value, 'Other')

    def test_event_with_hostname_attribute(self):
        event = get_event_with_hostname_attribute()
        attribute = event['Event']['Attribute'][0]
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_attribute_features(related_indicator, attribute, orgc)
        properties = self._check_observable_features(indicator.observable, attribute, 'Hostname')
        self.assertEqual(properties.hostname_value.value, attribute['value'])

    def test_event_with_hostname_port_attribute(self):
        event = get_event_with_hostname_port_attribute()
        attribute = event['Event']['Attribute'][0]
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_attribute_features(related_indicator, attribute, orgc)
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
        src_indicator = self._check_indicator_attribute_features(related_src, ip_src, orgc)
        src_properties = self._check_observable_features(src_indicator.observable, ip_src, 'Address')
        self.assertEqual(src_properties.address_value.value, ip_src['value'])
        self._check_source_address(src_properties)
        dst_indicator = self._check_indicator_attribute_features(related_dst, ip_dst, orgc)
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
        src_indicator = self._check_indicator_attribute_features(related_src, ip_src, orgc)
        src_properties = self._check_observable_features(src_indicator.observable, ip_src, 'SocketAddress')
        ip, port = ip_src['value'].split('|')
        self.assertEqual(src_properties.port.port_value.value, int(port))
        self.assertEqual(src_properties.ip_address.address_value.value, ip)
        self._check_source_address(src_properties.ip_address)
        dst_indicator = self._check_indicator_attribute_features(related_dst, ip_dst, orgc)
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
        indicator = self._check_indicator_attribute_features(related_indicator, attribute, orgc)
        self._check_malware_sample_properties(indicator.observable, attribute)

    def test_event_with_mutex_attribute(self):
        event = get_event_with_mutex_attribute()
        attribute = event['Event']['Attribute'][0]
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_attribute_features(related_indicator, attribute, orgc)
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
        indicator = self._check_indicator_attribute_features(related_indicator, attribute, orgc)
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
        indicator = self._check_indicator_attribute_features(related_indicator, attribute, orgc)
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
        indicator = self._check_indicator_attribute_features(related_indicator, attribute, orgc)
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
        snort_indicator = self._check_indicator_attribute_features(r_snort, snort, orgc)
        snort_tm = snort_indicator.test_mechanisms[0]
        self.assertEqual(snort_tm._XSI_TYPE, 'snortTM:SnortTestMechanismType')
        self.assertEqual(snort_tm.rules[0].value['value'], snort['value'])
        yara_indicator = self._check_indicator_attribute_features(r_yara, yara, orgc)
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
        default_entry, journal_entry = incident.history.history_items
        self.assertEqual(
            default_entry.journal_entry.value,
            'MISP Tag: misp:tool="MISP-STIX-Converter"'
        )
        self.assertEqual(
            journal_entry.journal_entry.value,
            f"Attribute ({comment['category']} - {comment['type']}): {comment['value']}"
        )

    def test_event_with_url_attribute(self):
        event = get_event_with_url_attribute()
        attribute = event['Event']['Attribute'][0]
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_attribute_features(related_indicator, attribute, orgc)
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
        self.assertEqual(exploit_target.id_, f"{_DEFAULT_ORGNAME}:ExploitTarget-{attribute['uuid']}")
        vulnerability = exploit_target.vulnerabilities[0]
        self.assertEqual(vulnerability.cve_id, attribute['value'])
        incident = stix_package.incidents[0]
        self._check_related_object(
            incident.leveraged_ttps.ttp[0],
            attribute['type'],
            attribute['uuid']
        )

    def test_event_with_weakness_attribute(self):
        event = get_event_with_weakness_attribute()
        attribute = event['Event']['Attribute'][0]
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        stix_package = self.parser.stix_package
        ttp = self._check_ttp_fields_from_attribute(stix_package, attribute)
        exploit_target = ttp.exploit_targets.exploit_target[0].item
        self.assertEqual(exploit_target.id_, f"{_DEFAULT_ORGNAME}:ExploitTarget-{attribute['uuid']}")
        weakness = exploit_target.weaknesses[0]
        incident = stix_package.incidents[0]
        self._check_related_object(
            incident.leveraged_ttps.ttp[0],
            attribute['type'],
            attribute['uuid']
        )

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
        x509_md5 = self._check_indicator_attribute_features(r_x509_md5, md5, orgc)
        md5_properties = self._check_observable_features(x509_md5.observable, md5, 'X509Certificate')
        md5_signature = md5_properties.certificate_signature
        self.assertEqual(md5_signature.signature_algorithm.value, "MD5")
        self.assertEqual(md5_signature.signature.value, md5['value'])
        x509_sha1 = self._check_indicator_attribute_features(r_x509_sha1, sha1, orgc)
        sha1_properties = self._check_observable_features(x509_sha1.observable, sha1, 'X509Certificate')
        sha1_signature = sha1_properties.certificate_signature
        self.assertEqual(sha1_signature.signature_algorithm.value, "SHA1")
        self.assertEqual(sha1_signature.signature.value, sha1['value'])
        x509_sha256 = self._check_indicator_attribute_features(r_x509_sha256, sha256, orgc)
        sha256_properties = self._check_observable_features(x509_sha256.observable, sha256, 'X509Certificate')
        sha256_signature = sha256_properties.certificate_signature
        self.assertEqual(sha256_signature.signature_algorithm.value, "SHA256")
        self.assertEqual(sha256_signature.signature.value, sha256['value'])

    ################################################################################
    #                          MISP OBJECTS EXPORT TESTS.                          #
    ################################################################################

    def test_embedded_indicator_object_galaxy(self):
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
        self.parser.parse_misp_event(event, '1.1.1')
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

    def test_embedded_non_indicator_object_galaxy(self):
        event = get_embedded_non_indicator_object_galaxy()
        coa_object, ttp_object = deepcopy(event['Event']['Object'])
        malware_galaxy = ttp_object['Attribute'][0]['Galaxy'][0]
        malware_cluster = malware_galaxy['GalaxyCluster'][0]
        coa_galaxy, tool_galaxy = event['Event']['Galaxy']
        coa_cluster = coa_galaxy['GalaxyCluster'][0]
        tool_cluster = tool_galaxy['GalaxyCluster'][0]
        self.parser.parse_misp_event(event, '1.1.1')
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
            'Object'
        )
        malware = malware_ttp.behavior.malware_instances[0]
        self._check_embedded_features(malware, malware_cluster, 'MalwareInstance')
        tool = tool_ttp.resources.tools[0]
        self._check_embedded_features(tool, tool_cluster, 'ToolInformation', feature='name')
        exploit_target = vulnerability_ttp.exploit_targets.exploit_target[0].item
        self.assertEqual(exploit_target.id_, f"{_DEFAULT_ORGNAME}:ExploitTarget-{ttp_object['uuid']}")
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

    def test_embedded_object_galaxy_with_multiple_clusters(self):
        event = get_embedded_object_galaxy_with_multiple_clusters()
        self._add_ids_flag(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        galaxy1 = misp_object['Attribute'][0]['Galaxy'][0]
        cluster1 = galaxy1['GalaxyCluster'][0]
        galaxy2 = misp_object['Attribute'][1]['Galaxy'][0]
        cluster2 = galaxy2['GalaxyCluster'][0]
        self.parser.parse_misp_event(event, '1.1.1')
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

    def test_embedded_observable_object_galaxy(self):
        event = get_embedded_observable_object_galaxy()
        self._remove_ids_flags(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        galaxy = event['Event']['Galaxy'][0]
        cluster = galaxy['GalaxyCluster'][0]
        self.parser.parse_misp_event(event, '1.1.1')
        stix_package = self.parser.stix_package
        ttp = self._check_ttp_fields_from_galaxy(stix_package, cluster['uuid'], galaxy['name'])
        tool = ttp.resources.tools[0]
        self._check_embedded_features(tool, cluster, 'ToolInformation', feature='name')
        self._check_related_object(
            stix_package.incidents[0].leveraged_ttps.ttp[0],
            galaxy['name'],
            cluster['uuid']
        )

    def test_event_with_asn_object_indicator(self):
        event = get_event_with_asn_object()
        self._add_ids_flag(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_object_features(related_indicator, misp_object, orgc)
        properties = self._check_observable_features(indicator.observable, misp_object, 'AS')
        self._check_asn_properties(properties, misp_object['Attribute'])

    def test_event_with_asn_object_observable(self):
        event = get_event_with_asn_object()
        self._remove_ids_flags(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        observable = incident.related_observables.observable[0]
        self.assertEqual(observable.relationship, misp_object['meta-category'])
        properties = self._check_observable_features(observable.item, misp_object, 'AS')
        self._check_asn_properties(properties, misp_object['Attribute'])

    def test_event_with_attack_pattern_object(self):
        event = get_event_with_attack_pattern_object()
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event, '1.1.1')
        stix_package = self.parser.stix_package
        ttp = self._check_ttp_fields_from_object(stix_package, misp_object)
        attack_pattern = ttp.behavior.attack_patterns[0]
        self.assertEqual(attack_pattern.id_, f"{_DEFAULT_ORGNAME}:AttackPattern-{misp_object['uuid']}")
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

    def test_event_with_course_of_action_object(self):
        event = get_event_with_course_of_action_object()
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event, '1.1.1')
        stix_package = self.parser.stix_package
        self.assertEqual(len(stix_package.courses_of_action), 1)
        course_of_action = stix_package.courses_of_action[0]
        self._check_course_of_action_fields(course_of_action, misp_object)
        self._check_coa_taken(
            stix_package.incidents[0].coa_taken[0],
            misp_object['uuid'],
            timestamp=misp_object['timestamp']
        )

    def test_event_with_credential_object_indicator(self):
        event = get_event_with_credential_object()
        self._add_ids_flag(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_object_features(related_indicator, misp_object, orgc)
        properties = self._check_observable_features(indicator.observable, misp_object, 'UserAccount')
        self._check_credential_properties(properties, misp_object['Attribute'])

    def test_event_with_credential_object_observable(self):
        event = get_event_with_credential_object()
        self._remove_ids_flags(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        observable = incident.related_observables.observable[0]
        self.assertEqual(observable.relationship, misp_object['meta-category'])
        properties = self._check_observable_features(observable.item, misp_object, 'UserAccount')
        self._check_credential_properties(properties, misp_object['Attribute'])

    def test_event_with_custom_objects(self):
        event = get_event_with_custom_objects()
        account, btc, person = deepcopy(event['Event']['Object'])
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
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
        observable = incident.related_observables.observable[0]
        self.assertEqual(observable.relationship, person['meta-category'])
        properties = self._check_observable_features(observable.item, person, 'Custom')
        self._check_custom_properties(person['Attribute'], properties.custom_properties)

    def test_event_with_domain_ip_object_indicator(self):
        event = get_event_with_domain_ip_object()
        self._add_ids_flag(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_object_features(related_indicator, misp_object, orgc)
        observables = indicator.observable.observable_composition.observables
        self._check_domain_ip_observables(observables, misp_object['Attribute'])

    def test_event_with_domain_ip_object_observable(self):
        event = get_event_with_domain_ip_object()
        self._remove_ids_flags(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        observable = incident.related_observables.observable[0]
        self.assertEqual(observable.item.id_, f"{_DEFAULT_ORGNAME}:{misp_object['name']}_ObservableComposition-{misp_object['uuid']}")
        observables = observable.item.observable_composition.observables
        self._check_domain_ip_observables(observables, misp_object['Attribute'])

    def test_event_with_email_object_indicator(self):
        event = get_event_with_email_object()
        self._add_ids_flag(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_object_features(related_indicator, misp_object, orgc)
        properties = self._check_observable_features(indicator.observable, misp_object, 'EmailMessage')
        related_objects = indicator.observable.object_.related_objects
        self._check_email_properties(properties, related_objects, misp_object['Attribute'])

    def test_event_with_email_object_observable(self):
        event = get_event_with_email_object()
        self._remove_ids_flags(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        observable = incident.related_observables.observable[0]
        self.assertEqual(observable.relationship, misp_object['meta-category'])
        properties = self._check_observable_features(observable.item, misp_object, 'EmailMessage')
        related_objects = observable.item.object_.related_objects
        self._check_email_properties(properties, related_objects, misp_object['Attribute'])

    def test_event_with_file_and_pe_objects_indicators(self):
        event = get_event_with_file_and_pe_objects()
        self._add_ids_flag(event)
        file, pe, section = deepcopy(event['Event']['Object'])
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_object_features(related_indicator, file, orgc)
        properties = self._check_observable_features(indicator.observable, file, 'WindowsExecutableFile')
        self._check_file_and_pe_properties(properties, file, pe, section)

    def test_event_with_file_and_pe_objects_observables(self):
        event = get_event_with_file_and_pe_objects()
        self._remove_ids_flags(event)
        file, pe, section = deepcopy(event['Event']['Object'])
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        observable = incident.related_observables.observable[0]
        self.assertEqual(observable.relationship, file['meta-category'])
        properties = self._check_observable_features(observable.item, file, 'WindowsExecutableFile')
        # related_objects = observable.item.object_.related_objects
        self._check_file_and_pe_properties(properties, file, pe, section)

    def test_event_with_file_object_indicator(self):
        event = get_event_with_file_object()
        self._add_ids_flag(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_object_features(related_indicator, misp_object, orgc)
        properties = self._check_observable_features(indicator.observable, misp_object, 'File')
        self._check_file_properties(properties, misp_object['Attribute'])

    def test_event_with_file_object_observable(self):
        event = get_event_with_file_object()
        self._remove_ids_flags(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        observable = incident.related_observables.observable[0]
        self.assertEqual(observable.relationship, misp_object['meta-category'])
        properties = self._check_observable_features(observable.item, misp_object, 'File')
        self._check_file_properties(properties, misp_object['Attribute'])

    def test_event_with_file_object_with_artifact_indicator(self):
        event = get_event_with_file_object_with_artifact()
        self._add_ids_flag(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_object_features(related_indicator, misp_object, orgc)
        observables = indicator.observable.observable_composition.observables
        self._check_file_observables(observables, misp_object)

    def test_event_with_file_object_with_artifact_observable(self):
        event = get_event_with_file_object_with_artifact()
        self._remove_ids_flags(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        observable = incident.related_observables.observable[0]
        self.assertEqual(observable.item.id_, f"{_DEFAULT_ORGNAME}:{misp_object['name']}_ObservableComposition-{misp_object['uuid']}")
        observables = observable.item.observable_composition.observables
        self._check_file_observables(observables, misp_object)

    def test_event_with_ip_port_object_indicator(self):
        event = get_event_with_ip_port_object()
        self._add_ids_flag(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_object_features(related_indicator, misp_object, orgc)
        observables = indicator.observable.observable_composition.observables
        self._check_ip_port_observables(observables, misp_object)

    def test_event_with_ip_port_object_observable(self):
        event = get_event_with_ip_port_object()
        self._remove_ids_flags(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        observable = incident.related_observables.observable[0]
        self.assertEqual(observable.item.id_, f"{_DEFAULT_ORGNAME}:{misp_object['name']}_ObservableComposition-{misp_object['uuid']}")
        observables = observable.item.observable_composition.observables
        self._check_ip_port_observables(observables, misp_object)

    def test_event_with_network_connection_object_indicator(self):
        event = get_event_with_network_connection_object()
        self._add_ids_flag(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_object_features(related_indicator, misp_object, orgc)
        properties = self._check_observable_features(indicator.observable, misp_object, 'NetworkConnection')
        self._check_network_connection_properties(properties, misp_object['Attribute'])

    def test_event_with_network_connection_object_observable(self):
        event = get_event_with_network_connection_object()
        self._remove_ids_flags(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        observable = incident.related_observables.observable[0]
        self.assertEqual(observable.relationship, misp_object['meta-category'])
        properties = self._check_observable_features(observable.item, misp_object, 'NetworkConnection')
        self._check_network_connection_properties(properties, misp_object['Attribute'])

    def test_event_with_network_socket_object_indicator(self):
        event = get_event_with_network_socket_object()
        self._add_ids_flag(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_object_features(related_indicator, misp_object, orgc)
        properties = self._check_observable_features(indicator.observable, misp_object, 'NetworkSocket')
        self._check_network_socket_prooperties(properties, misp_object['Attribute'])

    def test_event_with_network_socket_object_observable(self):
        event = get_event_with_network_socket_object()
        self._remove_ids_flags(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        observable = incident.related_observables.observable[0]
        self.assertEqual(observable.relationship, misp_object['meta-category'])
        properties = self._check_observable_features(observable.item, misp_object, 'NetworkSocket')
        self._check_network_socket_prooperties(properties, misp_object['Attribute'])

    def test_event_with_process_object_indicator(self):
        event = get_event_with_process_object()
        self._add_ids_flag(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_object_features(related_indicator, misp_object, orgc)
        properties = self._check_observable_features(indicator.observable, misp_object, 'Process')
        self._check_process_properties(properties, misp_object['Attribute'])

    def test_event_with_process_object_observable(self):
        event = get_event_with_process_object()
        self._remove_ids_flags(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        observable = incident.related_observables.observable[0]
        self.assertEqual(observable.relationship, misp_object['meta-category'])
        properties = self._check_observable_features(observable.item, misp_object, 'Process')
        self._check_process_properties(properties, misp_object['Attribute'])

    def test_event_with_registry_key_object_indicator(self):
        event = get_event_with_registry_key_object()
        self._add_ids_flag(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_object_features(related_indicator, misp_object, orgc)
        properties = self._check_observable_features(indicator.observable, misp_object, 'WindowsRegistryKey')
        self._check_registry_key_properties(properties, misp_object['Attribute'])

    def test_event_with_registry_key_object_observable(self):
        event = get_event_with_registry_key_object()
        self._remove_ids_flags(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        observable = incident.related_observables.observable[0]
        self.assertEqual(observable.relationship, misp_object['meta-category'])
        properties = self._check_observable_features(observable.item, misp_object, 'WindowsRegistryKey')
        self._check_registry_key_properties(properties, misp_object['Attribute'])

    def test_event_with_url_object_indicator(self):
        event = get_event_with_url_object()
        self._add_ids_flag(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_object_features(related_indicator, misp_object, orgc)
        observables = indicator.observable.observable_composition.observables
        self._check_url_observables(observables, misp_object)

    def test_event_with_url_object_observable(self):
        event = get_event_with_url_object()
        self._remove_ids_flags(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        observable = incident.related_observables.observable[0]
        self.assertEqual(observable.item.id_, f"{_DEFAULT_ORGNAME}:{misp_object['name']}_ObservableComposition-{misp_object['uuid']}")
        observables = observable.item.observable_composition.observables
        self._check_url_observables(observables, misp_object)

    def test_event_with_user_account_objects_indicator(self):
        event = get_event_with_user_account_objects()
        self._add_ids_flag(event)
        user, unix, windows = deepcopy(event['Event']['Object'])
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
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

    def test_event_with_user_account_objects_observable(self):
        event = get_event_with_user_account_objects()
        self._remove_ids_flags(event)
        user, unix, windows = deepcopy(event['Event']['Object'])
        self.parser.parse_misp_event(event, '1.1.1')
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

    def test_event_with_vulnerability_and_weakness_related_object(self):
        event = get_event_with_vulnerability_and_weakness_objects()
        vulnerability, weakness = deepcopy(event['Event']['Object'])
        self.parser.parse_misp_event(event, '1.1.1')
        stix_package = self.parser.stix_package
        vulnerability_ttp, weakness_ttp = self._check_ttp_length(stix_package, 2)
        self._check_related_object(
            vulnerability_ttp.related_ttps[0],
            'weakened-by',
            weakness['uuid'],
            timestamp=weakness['timestamp']
        )

    def test_event_with_vulnerability_object(self):
        event = get_event_with_vulnerability_object()
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event, '1.1.1')
        stix_package = self.parser.stix_package
        ttp = self._check_ttp_fields_from_object(stix_package, misp_object)
        exploit_target = ttp.exploit_targets.exploit_target[0].item
        self.assertEqual(exploit_target.id_, f"{_DEFAULT_ORGNAME}:ExploitTarget-{misp_object['uuid']}")
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

    def test_event_with_weakness_object(self):
        event = get_event_with_weakness_object()
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event, '1.1.1')
        stix_package = self.parser.stix_package
        ttp = self._check_ttp_fields_from_object(stix_package, misp_object)
        exploit_target = ttp.exploit_targets.exploit_target[0].item
        self.assertEqual(exploit_target.id_, f"{_DEFAULT_ORGNAME}:ExploitTarget-{misp_object['uuid']}")
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

    def test_event_with_whois_object_indicator(self):
        event = get_event_with_whois_object()
        self._add_ids_flag(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_object_features(related_indicator, misp_object, orgc)
        properties = self._check_observable_features(indicator.observable, misp_object, 'Whois')
        self._check_whois_properties(properties, misp_object['Attribute'])

    def test_event_with_whois_object_observable(self):
        event = get_event_with_whois_object()
        self._remove_ids_flags(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        observable = incident.related_observables.observable[0]
        self.assertEqual(observable.relationship, misp_object['meta-category'])
        properties = self._check_observable_features(observable.item, misp_object, 'Whois')
        self._check_whois_properties(properties, misp_object['Attribute'])

    def test_event_with_x509_object_indicator(self):
        event = get_event_with_x509_object()
        self._add_ids_flag(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        orgc = event['Event']['Orgc']['name']
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        related_indicator = incident.related_indicators.indicator[0]
        indicator = self._check_indicator_object_features(related_indicator, misp_object, orgc)
        properties = self._check_observable_features(indicator.observable, misp_object, 'X509Certificate')
        self._check_x509_properties(properties, misp_object['Attribute'])

    def test_event_with_x509_object_observable(self):
        event = get_event_with_x509_object()
        self._remove_ids_flags(event)
        misp_object = deepcopy(event['Event']['Object'][0])
        self.parser.parse_misp_event(event, '1.1.1')
        incident = self.parser.stix_package.incidents[0]
        observable = incident.related_observables.observable[0]
        self.assertEqual(observable.relationship, misp_object['meta-category'])
        properties = self._check_observable_features(observable.item, misp_object, 'X509Certificate')
        self._check_x509_properties(properties, misp_object['Attribute'])

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
        self._check_related_object(stix_package.incidents[0].leveraged_ttps.ttp[0], galaxy['name'], cluster['uuid'])

    def test_event_with_course_of_action_galaxy(self):
        event = get_event_with_course_of_action_galaxy()
        cluster = event['Event']['Galaxy'][0]['GalaxyCluster'][0]
        self.parser.parse_misp_event(event, '1.1.1')
        stix_package = self.parser.stix_package
        self.assertEqual(len(stix_package.courses_of_action), 1)
        course_of_action = stix_package.courses_of_action[0]
        self._check_embedded_features(course_of_action, cluster, 'CourseOfAction')
        self._check_coa_taken(stix_package.incidents[0].coa_taken[0], cluster['uuid'])

    def test_event_with_malware_galaxy(self):
        event = get_event_with_malware_galaxy()
        galaxy = event['Event']['Galaxy'][0]
        cluster = galaxy['GalaxyCluster'][0]
        self.parser.parse_misp_event(event, '1.1.1')
        stix_package = self.parser.stix_package
        ttp = self._check_ttp_fields_from_galaxy(stix_package, cluster['uuid'], galaxy['name'])
        malware = ttp.behavior.malware_instances[0]
        self._check_embedded_features(malware, cluster, 'MalwareInstance')
        self._check_related_object(stix_package.incidents[0].leveraged_ttps.ttp[0], galaxy['name'], cluster['uuid'])

    def test_event_with_threat_actor_galaxy(self):
        event = get_event_with_threat_actor_galaxy()
        galaxy = event['Event']['Galaxy'][0]
        cluster = galaxy['GalaxyCluster'][0]
        self.parser.parse_misp_event(event, '1.1.1')
        stix_package = self.parser.stix_package
        self.assertEqual(len(stix_package.threat_actors), 1)
        threat_actor = stix_package.threat_actors[0]
        threat_actor_id = f"{_DEFAULT_ORGNAME}:ThreatActor-{cluster['uuid']}"
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
        self._check_related_object(stix_package.incidents[0].leveraged_ttps.ttp[0], galaxy['name'], cluster['uuid'])

    def test_event_with_vulnerability_galaxy(self):
        event = get_event_with_vulnerability_galaxy()
        galaxy = event['Event']['Galaxy'][0]
        cluster = galaxy['GalaxyCluster'][0]
        self.parser.parse_misp_event(event, '1.1.1')
        stix_package = self.parser.stix_package
        ttp = self._check_ttp_fields_from_galaxy(stix_package, cluster['uuid'], galaxy['name'])
        exploit_target = ttp.exploit_targets.exploit_target[0].item
        self.assertEqual(exploit_target.id_, f"{_DEFAULT_ORGNAME}:ExploitTarget-{cluster['uuid']}")
        vulnerability = exploit_target.vulnerabilities[0]
        self._check_embedded_features(vulnerability, cluster, 'Vulnerability')
        self.assertEqual(vulnerability.cve_id, cluster['meta']['aliases'][0])
        self._check_related_object(stix_package.incidents[0].leveraged_ttps.ttp[0], galaxy['name'], cluster['uuid'])

class TestCollectionExport(unittest.TestCase):
    def setUp(self):
        self._current_path = os.path.dirname(os.path.realpath(__file__))

    def tearDown(self):
        for filename in self._filenames:
            os.remove(f'{filename}.out')

    def _check_misp_to_stix_export(self):
        for filename in self._filenames:
            return_code = misp_to_stix(
                filename,
                'xml',
                '1.1.1',
                namespace=_DEFAULT_NAMESPACE,
                org=_DEFAULT_ORGNAME
            )
            self.assertEqual(return_code, 1)
            with open(f'{filename}.out', 'rt', encoding='utf-8') as f:
                yield f.read()

    def test_events_collection(self):
        stripped_orgname = _DEFAULT_ORGNAME.replace('-', '')
        fixed_line = f'\t id="{stripped_orgname}:Package-0c467501-2514-462f-90d6-3ea04bb0e721" version="1.1.1" timestamp="2020-10-25T16:22:00">'
        header, separator, footer = stix_framing(
            _DEFAULT_NAMESPACE,
            _DEFAULT_ORGNAME,
            'xml'
        )
        start = f'id="{stripped_orgname.replace("-", "")}:Package-'
        header = '\n'.join(fixed_line if line.strip().startswith(start) else line for line in header.split('\n'))
        name = 'test_events_collection'
        self._filenames = tuple(f"{self._current_path}/{name}_{n}.json" for n in (1, 2))
        packages = self._check_misp_to_stix_export()
        content = separator.join(packages)
        with open(f'{self._current_path}/{name}.xml', 'rt', encoding='utf-8') as f:
            self.assertEqual(f'{header}{content}{footer}', f.read())
