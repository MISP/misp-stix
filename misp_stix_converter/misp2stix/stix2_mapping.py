#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional


class Stix2Mapping:
    def __init__(self):
        self.__external_id_to_source_name = {
            'CAPEC': 'capec',
            'CVE': 'cve',
            'CWE': 'cwe',
            'MOB': 'mitre-mobile-attack',
            'PRE': 'mitre-pre-attack',
            'REF': 'reference_from_CAPEC'
        }
        self.__hash_attribute_types = (
            'md5',
            'sha1',
            'sha224',
            'sha256',
            'sha384',
            'sha512',
            'sha512/224',
            'sha512/256',
            'sha3-224',
            'sha3-256',
            'sha3-384',
            'sha3-512',
            'ssdeep',
            'tlsh'
        )
        self.__source_names = (
            'ATTACK',
            'NIST Mobile Threat Catalogue',
            'WASC',
            'capec',
            'cve',
            'cwe',
            'mitre-attack',
            'mitre-ics-attack',
            'mitre-mobile-attack',
            'mitre-pre-attack',
            'reference_from_CAPEC'
        )

    def _declare_attributes_mapping(self, updates: Optional[dict]=None):
        self.__misp_identity_args = {
            'id': 'identity--55f6ea65-aa10-4c5a-bf01-4f84950d210f',
            'type': 'identity',
            'identity_class': 'organization',
            'name': 'MISP',
            'created': '2015-09-14T15:40:21Z',
            'modified': '2015-09-14T15:40:21Z'
        }
        self.__relationship_specs = {
            'attack-pattern': {
                'malware': 'uses',
                'tool': 'uses',
                'vulnerability': 'targets'
            },
            'campaign': {
                'attack-pattern': 'uses',
                'intrusion-set': 'attributed-to',
                'malware': 'uses',
                'threat-actor': 'attributed-to',
                'tool': 'uses',
                'vulnerability': 'targets'
            },
            'course-of-action': {
                'attack-pattern': 'mitigates',
                'malware': 'mitigates',
                'tool': 'mitigates',
                'vulnerability': 'mitigates'
            },
            'indicator': {
                'attack-pattern': 'indicates',
                'intrusion-set': 'indicates',
                'malware': 'indicates',
                'threat-actor': 'indicates',
                'tool': 'indicates'
            }
        }
        # ATTRIBUTES MAPPING
        self.__attribute_types_mapping = {
            'AS': '_parse_autonomous_system_attribute',
            'attachment': '_parse_attachment_attribute',
            'campaign-name': '_parse_campaign_name_attribute',
            'domain': '_parse_domain_attribute',
            'domain|ip': '_parse_domain_ip_attribute',
            'email': '_parse_email_attribute',
            'email-attachment': '_parse_email_attachment_attribute',
            'email-body': '_parse_email_body_attribute',
            'email-dst': '_parse_email_destination_attribute',
            'email-header': '_parse_email_header_attribute',
            'email-reply-to': '_parse_email_reply_to_attribute',
            'email-src': '_parse_email_source_attribute',
            'email-subject': '_parse_email_subject_attribute',
            'email-x-mailer': '_parse_email_x_mailer_attribute',
            'filename': '_parse_filename_attribute',
            'hostname': '_parse_domain_attribute',
            'hostname|port': '_parse_hostname_port_attribute',
            'http-method': '_parse_http_method_attribute',
            'mac-address': '_parse_mac_address_attribute',
            'malware-sample': '_parse_malware_sample_attribute',
            'mutex': '_parse_mutex_attribute',
            'port': '_parse_port_attribute',
            'regkey': '_parse_regkey_attribute',
            'regkey|value': '_parse_regkey_value_attribute',
            'size-in-bytes': '_parse_size_in_bytes_attribute',
            'user-agent': '_parse_user_agent_attribute',
            'vulnerability': '_parse_vulnerability_attribute'
        }
        self.__attribute_types_mapping.update(
            dict.fromkeys(
                self.__hash_attribute_types,
                '_parse_hash_attribute'
            )
        )
        self.__attribute_types_mapping.update(
            dict.fromkeys(
                (f"filename|{hash}" for hash in self.__hash_attribute_types),
                '_parse_hash_composite_attribute'
            )
        )
        self.__attribute_types_mapping.update(
            dict.fromkeys(
                (
                    'ip-src',
                    'ip-dst'
                ),
                '_parse_ip_attribute'
            )
        )
        self.__attribute_types_mapping.update(
            dict.fromkeys(
                (
                    'ip-src|port',
                    'ip-dst|port'
                ),
                '_parse_ip_port_attribute'
            )
        )
        self.__attribute_types_mapping.update(
            dict.fromkeys(
                [
                    "uri",
                    "url",
                    "link"
                ],
                '_parse_url_attribute'
            )
        )
        self.__attribute_types_mapping.update(
            dict.fromkeys(
                [
                    'x509-fingerprint-md5',
                    'x509-fingerprint-sha1',
                    'x509-fingerprint-sha256'
                ],
                '_parse_x509_fingerprint_attribute'
            )
        )
        if updates is not None:
            self.__attribute_types_mapping.update(updates)
        # GALAXIES MAPPING
        _attack_pattern_types = (
            'mitre-attack-pattern',
            'mitre-enterprise-attack-attack-pattern',
            'mitre-mobile-attack-attack-pattern',
            'mitre-pre-attack-attack-pattern'
        )
        _course_of_action_types = (
            'mitre-course-of-action',
            'mitre-enterprise-attack-course-of-action',
            'mitre-mobile-attack-course-of-action'
        )
        _intrusion_set_types = (
            'mitre-enterprise-attack-intrusion-set',
            'mitre-intrusion-set',
            'mitre-mobile-attack-intrusion-set',
            'mitre-pre-attack-intrusion-set'
        )
        _malware_types = (
            'android',
            'banker',
            'stealer',
            'backdoor',
            'ransomware',
            'mitre-malware',
            'malpedia',
            'mitre-enterprise-attack-malware',
            'mitre-mobile-attack-malware'
        )
        _threat_actor_types = (
            'threat-actor',
            'microsoft-activity-group'
        )
        _tool_types = (
            'botnet',
            'rat',
            'exploit-kit',
            'tds',
            'tool',
            'mitre-tool',
            'mitre-enterprise-attack-tool',
            'mitre-mobile-attack-tool'
        )
        self.__cluster_to_stix_object = {'branded-vulnerability': 'vulnerability'}
        self.__cluster_to_stix_object.update(
            dict.fromkeys(
                _attack_pattern_types,
                'attack-pattern'
            )
        )
        self.__cluster_to_stix_object.update(
            dict.fromkeys(
                _course_of_action_types,
                'course-of-action'
            )
        )
        self.__cluster_to_stix_object.update(
            dict.fromkeys(
                _intrusion_set_types,
                'intrusion-set'
            )
        )
        self.__cluster_to_stix_object.update(
            dict.fromkeys(
                _malware_types,
                'malware'
            )
        )
        self.__cluster_to_stix_object.update(
            dict.fromkeys(
                _threat_actor_types,
                'threat-actor'
            )
        )
        self.__cluster_to_stix_object.update(
            dict.fromkeys(
                _tool_types,
                'tool'
            )
        )
        self.__galaxy_types_mapping = {'branded-vulnerability': '_parse_vulnerability_{}_galaxy'}
        self.__galaxy_types_mapping.update(
            dict.fromkeys(
                _attack_pattern_types,
                '_parse_attack_pattern_{}_galaxy'
            )
        )
        self.__galaxy_types_mapping.update(
            dict.fromkeys(
                _course_of_action_types,
                '_parse_course_of_action_{}_galaxy'
            )
        )
        self.__galaxy_types_mapping.update(
            dict.fromkeys(
                _intrusion_set_types,
                '_parse_intrusion_set_{}_galaxy'
            )
        )
        self.__galaxy_types_mapping.update(
            dict.fromkeys(
                _malware_types,
                '_parse_malware_{}_galaxy'
            )
        )
        self.__galaxy_types_mapping.update(
            dict.fromkeys(
                _threat_actor_types,
                '_parse_threat_actor_{}_galaxy'
            )
        )
        self.__galaxy_types_mapping.update(
            dict.fromkeys(
                _tool_types,
                '_parse_tool_{}_galaxy'
            )
        )

    def _declare_objects_mapping(self, updates: Optional[dict]=None):
        self.__objects_mapping = {
            'asn': '_parse_asn_object',
            'attack-pattern': '_parse_attack_pattern_object',
            'course-of-action': '_parse_course_of_action_object',
            'credential': '_parse_credential_object',
            'domain-ip': '_parse_domain_ip_object',
            'email': '_parse_email_object',
            'facebook-account': '_parse_account_object',
            'file': '_parse_file_object',
            'ip-port': '_parse_ip_port_object',
            'mutex': '_parse_mutex_object',
            'network-connection': '_parse_network_connection_object',
            'network-socket': '_parse_network_socket_object',
            'pe': '_populate_objects_to_parse',
            'pe-section': '_populate_objects_to_parse',
            'process': '_parse_process_object',
            'registry-key': '_parse_registry_key_object',
            'twitter-account': '_parse_account_object',
            'url': '_parse_url_object',
            'user-account': '_parse_user_account_object',
            'vulnerability': '_parse_vulnerability_object',
            'x509': '_parse_x509_object'
        }
        if updates is not None:
            self.__objects_mapping.update(updates)
        self.__address_family_enum_list = (
            "AF_UNSPEC",
            "AF_INET",
            "AF_IPX",
            "AF_APPLETALK",
            "AF_NETBIOS",
            "AF_INET6",
            "AF_IRDA",
            "AF_BTH"
        )
        self.__as_single_fields = (
            'asn',
            'description'
        )
        self.__attack_pattern_object_mapping = {
            'name': 'name',
            'summary': 'description'
        }
        self.__attack_pattern_reference_mapping = {
            'id': ('capec', 'external_id'),
            'references': ('mitre-attack', 'url')
        }
        self.__attack_pattern_single_fields = (
            'name',
            'summary'
        )
        self.__course_of_action_object_mapping = (
            'name',
            'description'
        )
        self.__credential_single_fields = (
            'username',
        )
        self.__domain_family_enum_list = (
            "PF_INET",
            "PF_IPX",
            "PF_APPLETALK",
            "PF_INET6",
            "PF_AX25",
            "PF_NETROM"
        )
        self.__domain_ip_object_mapping = {
            'domain': 'value',
            'hostname': 'value',
            'ip': 'resolves_to_refs[*].value'
        }
        self.__domain_ip_single_fields = (
            'first-seen',
            'hostname',
            'last-seen',
            'port',
            'registration-date',
            'text'
        )
        self.__email_header_fields = {
            'reply-to': 'Reply-To',
            'x-mailer': 'X-Mailer'
        }
        self.__email_data_fields = (
            'attachment',
            'screenshot'
        )
        self.__facebook_account_object_mapping = {
            'account-id': 'user_id',
            'account-name': 'account_login'
        }
        self.__facebook_account_single_fields = (
            'account-id',
            'account-name'
        )
        self.__file_data_fields = (
            'attachment',
            'malware-sample'
        )
        self.__file_hash_main_types = (
            'md5',
            'sha1',
            'sha224',
            'sha256',
            'sha384',
            'sha512',
            'sha3-224',
            'sha3-256',
            'sha3-384',
            'sha3-512',
            'ssdeep',
            'tlsh'
        )
        self.__file_hash_types = (
            'sha512/224',
            'sha512/256',
        )
        self.__file_object_mapping = {
            'filename': 'name',
            'file-encoding': 'name_enc',
            'mime-type': 'mime_type',
            'size-in-bytes': 'size'
        }
        self.__file_single_fields = self.__file_data_fields + self.__hash_attribute_types + ('path',)
        self.__ip_port_object_mapping = {
            'ip_features': {
                'ip': "dst_ref.type = '{}' AND network-traffic:dst_ref.value",
                'ip-src': "src_ref.type = '{}' AND network-traffic:src_ref.value",
                'ip-dst': "dst_ref.type = '{}' AND network-traffic:dst_ref.value",
            },
            'domain_features': {
                'domain': "dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value",
                'hostname': "dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value"
            },
            'features': {
                'dst-port': "dst_port",
                'first-seen': "start",
                'last-seen': "end",
                'src-port': "src_port"
            }
        }
        self.__ip_port_single_fields = (
            'first-seen',
            'last-seen'
        )
        self.__network_connection_mapping = {
            "features": {
                'dst-port': 'dst_port',
                'first-packet-seen': 'start',
                'src-port': 'src_port'
            },
            'protocols': (
                'layer3-protocol',
                'layer4-protocol',
                'layer7-protocol'
            )
        }
        self.__network_socket_state_fields = (
            'blocking',
            'listening'
        )
        self.__pe_object_mapping = {
            'features': {
                'imphash': 'imphash',
                'number-sections': 'number_of_sections',
                'type': 'pe_type'
            },
            'header': {
                'entrypoint-address': 'address_of_entry_point',
            }
        }
        self.__pe_object_single_fields = (
            'entrypoint-address',
            'imphash',
            'number-sections',
            'type'
        )
        self.__pe_section_mapping = {
            'entropy': 'entropy',
            'name': 'name',
            'size-in-bytes': 'size'
        }
        self.__socket_type_enum_list = (
            "SOCK_STREAM",
            "SOCK_DGRAM",
            "SOCK_RAW",
            "SOCK_RDM",
            "SOCK_SEQPACKET"
        )
        self.__twitter_account_object_mapping = {
            'displayed-name': 'display_name',
            'id': 'user_id',
            'name': 'account_login'
        }
        self.__twitter_account_single_fields = (
            'displayed-name',
            'id',
            'name'
        )
        self.__user_account_single_fields = (
            'account-type',
            'can_escalate_privs',
            'created',
            'disabled',
            'display-name',
            'expires',
            'first_login',
            'group-id',
            'home_dir',
            'is_service_account',
            'last_login',
            'password',
            'password_last_changed',
            'privileged',
            'shell',
            'user-id',
            'username'
        )
        self.__x509_hash_fields = (
            'x509-fingerprint-md5',
            'x509-fingerprint-sha1',
            'x509-fingerprint-sha256'
        )
        self.__x509_object_mapping = {
            'extension': {
                'dns_names': 'DNS name',
                'email': 'email',
                'ip': 'IP',
                'rid': 'RID',
                'uri': 'URI'
            },
            'features': {
                'issuer': 'issuer',
                'pubkey-info-algorithm': 'subject_public_key_algorithm',
                'pubkey-info-exponent': 'subject_public_key_exponent',
                'pubkey-info-modulus': 'subject_public_key_modulus',
                'serial-number': 'serial_number',
                'signature_algorithm': 'signature_algorithm',
                'subject': 'subject',
                'version': 'version'
            },
            'timeline': {
                'validity-not-after': 'validity_not_after',
                'validity-not-before': 'validity_not_before'
            }
        }
        self.__x509_single_fields = (
            'is_ca',
            'issuer',
            'pem',
            'pubkey-info-algorithm',
            'pubkey-info-exponent',
            'pubkey-info-modulus',
            'pubkey-info-size',
            'raw-base64',
            'self_signed',
            'serial-number',
            'signature_algorithm',
            'subject',
            'text',
            'validity-not-after',
            'validity-not-before',
            'version',
            'x509-fingerprint-md5',
            'x509-fingerprint-sha1',
            'x509-fingerprint-sha256'
        )

    @property
    def address_family_enum_list(self) -> tuple:
        return self.__address_family_enum_list

    @property
    def as_single_fields(self) -> tuple:
        return self.__as_single_fields

    @property
    def attack_pattern_object_mapping(self) -> dict:
        return self.__attack_pattern_object_mapping

    @property
    def attack_pattern_reference_mapping(self) -> dict:
        return self.__attack_pattern_reference_mapping

    @property
    def attack_pattern_single_fields(self) -> tuple:
        return self.__attack_pattern_single_fields

    @property
    def attribute_types_mapping(self) -> dict:
        return self.__attribute_types_mapping

    @property
    def cluster_to_stix_object(self) -> dict:
        return self.__cluster_to_stix_object

    @property
    def course_of_action_object_mapping(self) -> tuple:
        return self.__course_of_action_object_mapping

    @property
    def credential_object_mapping(self) -> dict:
        return self.__credential_object_mapping

    @property
    def credential_single_fields(self) -> tuple:
        return self.__credential_single_fields

    @property
    def domain_family_enum_list(self) -> tuple:
        return self.__domain_family_enum_list

    @property
    def domain_ip_object_mapping(self) -> dict:
        return self.__domain_ip_object_mapping

    @property
    def domain_ip_single_fields(self) -> tuple:
        return self.__domain_ip_single_fields

    @property
    def email_header_fields(self) -> dict:
        return self.__email_header_fields

    @property
    def email_data_fields(self) -> tuple:
        return self.__email_data_fields

    @property
    def external_id_to_source_name(self) -> dict:
        return self.__external_id_to_source_name

    @property
    def facebook_account_object_mapping(self) -> dict:
        return self.__facebook_account_object_mapping

    @property
    def facebook_account_single_fields(self) -> tuple:
        return self.__facebook_account_single_fields

    @property
    def file_data_fields(self) -> tuple:
        return self.__file_data_fields

    @property
    def file_hash_main_types(self) -> tuple:
        return self.__file_hash_main_types

    @property
    def file_hash_types(self) -> tuple:
        return self.__file_hash_types

    @property
    def file_object_mapping(self) -> dict:
        return self.__file_object_mapping

    @property
    def file_single_fields(self) -> tuple:
        return self.__file_single_fields

    @property
    def galaxy_types_mapping(self) -> dict:
        return self.__galaxy_types_mapping

    @property
    def hash_attribute_types(self) -> tuple:
        return self.__hash_attribute_types

    @property
    def ip_port_object_mapping(self) -> dict:
        return self.__ip_port_object_mapping

    @property
    def ip_port_single_fields(self) -> tuple:
        return self.__ip_port_single_fields

    @property
    def misp_identity_args(self) -> dict:
        return self.__misp_identity_args

    @property
    def network_connection_mapping(self) -> dict:
        return self.__network_connection_mapping

    @property
    def network_socket_state_fields(self) -> tuple:
        return self.__network_socket_state_fields

    @property
    def objects_mapping(self) -> dict:
        return self.__objects_mapping

    @property
    def pe_object_mapping(self) -> dict:
        return self.__pe_object_mapping

    @property
    def pe_object_single_fields(self) -> tuple:
        return self.__pe_object_single_fields

    @property
    def pe_section_mapping(self) -> dict:
        return self.__pe_section_mapping

    @property
    def relationship_specs(self) -> dict:
        return self.__relationship_specs

    @property
    def socket_type_enum_list(self) -> tuple:
        return self.__socket_type_enum_list

    @property
    def source_names(self) -> tuple:
        return self.__source_names

    @property
    def twitter_account_object_mapping(self) -> dict:
        return self.__twitter_account_object_mapping

    @property
    def twitter_account_single_fields(self) -> tuple:
        return self.__twitter_account_single_fields

    @property
    def user_account_single_fields(self) -> tuple:
        return self.__user_account_single_fields

    @property
    def x509_hash_fields(self) -> tuple:
        return self.__x509_hash_fields

    @property
    def x509_object_mapping(self) -> dict:
        return self.__x509_object_mapping

    @property
    def x509_single_fields(self) -> tuple:
        return self.__x509_single_fields
