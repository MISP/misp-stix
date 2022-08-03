#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .. import Mapping
from typing import Optional


class Stix2Mapping:
    def __init__(self):
        self.__external_id_to_source_name = Mapping(
            CAPEC = 'capec',
            CVE = 'cve',
            CWE = 'cwe',
            MOB = 'mitre-mobile-attack',
            PRE = 'mitre-pre-attack',
            REF = 'reference_from_CAPEC'
        )
        self.__pe_section_hash_types = (
            'md5',
            'sha1',
            'sha224',
            'sha256',
            'sha384',
            'sha512',
            'sha512/224',
            'sha512/256',
            'ssdeep'
        )
        hash_attribute_types = (
            'authentihash',
            'imphash',
            'sha3-224',
            'sha3-256',
            'sha3-384',
            'sha3-512',
            'tlsh',
            'vhash'
        )
        self.__hash_attribute_types = self.__pe_section_hash_types + hash_attribute_types
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
        self.__misp_identity_args = Mapping(
            id = 'identity--55f6ea65-aa10-4c5a-bf01-4f84950d210f',
            type = 'identity',
            identity_class = 'organization',
            name = 'MISP',
            created = '2015-09-14T15:40:21Z',
            modified = '2015-09-14T15:40:21Z'
        )
        self.__relationship_specs = Mapping(
            **{
                'attack-pattern': Mapping(
                    malware = 'uses',
                    tool = 'uses',
                    vulnerability = 'targets'
                ),
                'campaign': Mapping(
                    **{
                        'attack-pattern': 'uses',
                        'intrusion-set': 'attributed-to',
                        'malware': 'uses',
                        'threat-actor': 'attributed-to',
                        'tool': 'uses',
                        'vulnerability': 'targets'
                    }
                ),
                'course-of-action': Mapping(
                    **{
                        'attack-pattern': 'mitigates',
                        'malware': 'mitigates',
                        'tool': 'mitigates',
                        'vulnerability': 'mitigates'
                    }
                ),
                'indicator': Mapping(
                    **{
                        'attack-pattern': 'indicates',
                        'intrusion-set': 'indicates',
                        'malware': 'indicates',
                        'threat-actor': 'indicates',
                        'tool': 'indicates'
                    }
                )
            }
        )
        # ATTRIBUTES MAPPING
        _attribute_types_mapping = {
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
            'github-username': '_parse_github_username_attribute',
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
        _attribute_types_mapping.update(
            dict.fromkeys(
                self.__hash_attribute_types,
                '_parse_hash_attribute'
            )
        )
        _attribute_types_mapping.update(
            dict.fromkeys(
                (
                    'cdhash',
                    'impfuzzy',
                    'pehash',
                    'telfhash'
                ),
                '_parse_hash_attribute'
            )
        )
        _attribute_types_mapping.update(
            dict.fromkeys(
                (f"filename|{hash}" for hash in self.__hash_attribute_types),
                '_parse_hash_composite_attribute'
            )
        )
        _attribute_types_mapping.update(
            dict.fromkeys(
                (
                    'filename|impfuzzy',
                    'filename|pehash'
                ),
                '_parse_hash_composite_attribute'
            )
        )
        _attribute_types_mapping.update(
            dict.fromkeys(
                (
                    'ip-src',
                    'ip-dst'
                ),
                '_parse_ip_attribute'
            )
        )
        _attribute_types_mapping.update(
            dict.fromkeys(
                (
                    'ip-src|port',
                    'ip-dst|port'
                ),
                '_parse_ip_port_attribute'
            )
        )
        _attribute_types_mapping.update(
            dict.fromkeys(
                [
                    "uri",
                    "url",
                    "link"
                ],
                '_parse_url_attribute'
            )
        )
        _attribute_types_mapping.update(
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
            _attribute_types_mapping.update(updates)
        self.__attribute_types_mapping = Mapping(**_attribute_types_mapping)
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
        _cluster_to_stix_object = {'branded-vulnerability': 'vulnerability'}
        _cluster_to_stix_object.update(
            dict.fromkeys(
                _attack_pattern_types,
                'attack-pattern'
            )
        )
        _cluster_to_stix_object.update(
            dict.fromkeys(
                _course_of_action_types,
                'course-of-action'
            )
        )
        _cluster_to_stix_object.update(
            dict.fromkeys(
                _intrusion_set_types,
                'intrusion-set'
            )
        )
        _cluster_to_stix_object.update(
            dict.fromkeys(
                _malware_types,
                'malware'
            )
        )
        _cluster_to_stix_object.update(
            dict.fromkeys(
                _threat_actor_types,
                'threat-actor'
            )
        )
        _cluster_to_stix_object.update(
            dict.fromkeys(
                _tool_types,
                'tool'
            )
        )
        self.__cluster_to_stix_object = Mapping(**_cluster_to_stix_object)
        _galaxy_types_mapping = {'branded-vulnerability': '_parse_vulnerability_{}_galaxy'}
        _galaxy_types_mapping.update(
            dict.fromkeys(
                _attack_pattern_types,
                '_parse_attack_pattern_{}_galaxy'
            )
        )
        _galaxy_types_mapping.update(
            dict.fromkeys(
                _course_of_action_types,
                '_parse_course_of_action_{}_galaxy'
            )
        )
        _galaxy_types_mapping.update(
            dict.fromkeys(
                _intrusion_set_types,
                '_parse_intrusion_set_{}_galaxy'
            )
        )
        _galaxy_types_mapping.update(
            dict.fromkeys(
                _malware_types,
                '_parse_malware_{}_galaxy'
            )
        )
        _galaxy_types_mapping.update(
            dict.fromkeys(
                _threat_actor_types,
                '_parse_threat_actor_{}_galaxy'
            )
        )
        _galaxy_types_mapping.update(
            dict.fromkeys(
                _tool_types,
                '_parse_tool_{}_galaxy'
            )
        )
        self.__galaxy_types_mapping = Mapping(**_galaxy_types_mapping)

    def _declare_objects_mapping(self, updates: Optional[dict]=None):
        _objects_mapping = {
            'android-app': '_parse_android_app_object',
            'asn': '_parse_asn_object',
            'attack-pattern': '_parse_attack_pattern_object',
            'course-of-action': '_parse_course_of_action_object',
            'cpe-asset': '_parse_cpe_asset_object',
            'credential': '_parse_credential_object',
            'domain-ip': '_parse_domain_ip_object',
            'email': '_parse_email_object',
            'employee': '_parse_employee_object',
            'facebook-account': '_parse_account_object_with_attachment',
            'file': '_parse_file_object',
            'github-user': '_parse_account_object_with_attachment',
            'gitlab-user': '_parse_account_object',
            'http-request': '_parse_http_request_object',
            'image': '_parse_image_object',
            'ip-port': '_parse_ip_port_object',
            'legal-entity': '_parse_legal_entity_object',
            'lnk': '_parse_lnk_object',
            'mutex': '_parse_mutex_object',
            'netflow': '_parse_netflow_object',
            'network-connection': '_parse_network_connection_object',
            'network-socket': '_parse_network_socket_object',
            'news-agency': '_parse_news_agency_object',
            'organization': '_parse_organization_object',
            'parler-account': '_parse_account_object_with_attachment',
            'pe': '_populate_objects_to_parse',
            'pe-section': '_populate_objects_to_parse',
            'process': '_parse_process_object',
            'reddit-account': '_parse_account_object_with_attachment',
            'registry-key': '_parse_registry_key_object',
            'script': '_parse_script_object',
            'telegram-account': '_parse_account_object',
            'twitter-account': '_parse_account_object_with_attachment',
            'url': '_parse_url_object',
            'user-account': '_parse_user_account_object',
            'vulnerability': '_parse_vulnerability_object',
            'x509': '_parse_x509_object'
        }
        if updates is not None:
            _objects_mapping.update(updates)
        self.__objects_mapping = Mapping(**_objects_mapping)
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
        self.__android_app_object_mapping = Mapping(
            name = 'name'
        )
        self.__android_app_single_fields = (
            'name',
        )
        self.__as_single_fields = (
            'asn',
            'description'
        )
        self.__attack_pattern_object_mapping = Mapping(
            name = 'name',
            summary = 'description'
        )
        self.__attack_pattern_reference_mapping = Mapping(
            id = ('capec', 'external_id'),
            references = ('mitre-attack', 'url')
        )
        self.__attack_pattern_single_fields = (
            'name',
            'summary'
        )
        self.__course_of_action_object_mapping = (
            'name',
            'description'
        )
        self.__cpe_asset_object_mapping = Mapping(
            cpe = 'cpe',
            language = 'languages',
            product = 'name',
            vendor = 'vendor',
            version = 'version'
        )
        self.__cpe_asset_single_fields = (
            'cpe',
            'product',
            'vendor',
            'version'
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
        self.__domain_ip_object_mapping = Mapping(
            domain = 'value',
            hostname = 'value',
            ip = 'resolves_to_refs[*].value'
        )
        self.__domain_ip_single_fields = (
            'first-seen',
            'hostname',
            'last-seen',
            'port',
            'registration-date',
            'text'
        )
        self.__domain_ip_standard_fields = (
            'domain',
            'hostname',
            'ip'
        )
        self.__email_header_fields = Mapping(
            **{
                'reply-to': 'Reply-To',
                'x-mailer': 'X-Mailer'
            }
        )
        self.__email_data_fields = (
            'attachment',
            'screenshot'
        )
        self.__employee_contact_info_fields = (
            'email-address',
        )
        self.__employee_single_fields = (
            'first-name',
            'full-name',
            'last-name',
            'text'
        )
        self.__facebook_account_data_fields = (
            'attachment',
            'user-avatar'
        )
        self.__facebook_account_object_mapping = Mapping(
            **{
                'account-id': 'user_id',
                'account-name': 'account_login'
            }
        )
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
        self.__file_object_mapping = Mapping(
            **{
                'filename': 'name',
                'file-encoding': 'name_enc',
                'mime-type': 'mime_type',
                'size-in-bytes': 'size'
            }
        )
        self.__file_single_fields = self.__file_data_fields + self.__hash_attribute_types + ('path',)
        self.__github_user_data_fields = (
            'profile-image',
        )
        self.__github_user_object_mapping = Mapping(
            **{
                'id': 'user_id',
                'user-fullname': 'display_name',
                'username': 'account_login'
            }
        )
        self.__github_user_single_fields = (
            'id',
            'user-fullname',
            'username'
        )
        self.__gitlab_user_object_mapping = Mapping(
            id = 'user_id',
            name = 'display_name',
            username = 'account_login'
        )
        self.__gitlab_user_single_fields = (
            'id',
            'name',
            'username'
        )
        self.__http_request_object_mapping = Mapping(
            references = {
                'ip-src': "src_ref.type = '{}' AND network-traffic:src_ref.value",
                'ip-dst': "dst_ref.type = '{}' AND network-traffic:dst_ref.value",
                'host': "dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value"
            },
            request_extension = {
                'method': 'request_method',
                'uri': 'request_value',
                'url': 'request_value'
            },
            request_header = {
                'content-type': 'Content-Type',
                'cookie': 'Cookie',
                'referer': 'Referer',
                'user-agent': 'User-Agent'
            }
        )
        self.__http_request_single_fields = (
            'basicauth-password',
            'basicauth-user',
            'host',
            'ip-dst',
            'ip-src',
            'method',
            'proxy-password',
            'proxy-user',
            'text',
            'uri',
            'url'
        )
        self.__image_data_fields = (
            'attachment',
        )
        self.__image_single_fields = (
            'attachment',
            'filename',
            'url'
        )
        self.__image_uuid_fields = (
            'attachment',
            'url'
        )
        self.__ip_port_object_mapping = Mapping(
            ip_features = Mapping(
                **{
                    'ip': "dst_ref.type = '{}' AND network-traffic:dst_ref.value",
                    'ip-src': "src_ref.type = '{}' AND network-traffic:src_ref.value",
                    'ip-dst': "dst_ref.type = '{}' AND network-traffic:dst_ref.value"
                }
            ),
            domain_features = Mapping(
                domain = "dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value",
                hostname = "dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value"
            ),
            features = Mapping(
                **{
                    'dst-port': "dst_port",
                    'first-seen': "start",
                    'last-seen': "end",
                    'src-port': "src_port"
                }
            )
        )
        self.__ip_port_single_fields = (
            'first-seen',
            'last-seen',
            'protocol'
        )
        self.__legal_entity_contact_info_fields = (
            'phone-number',
            'website'
        )
        self.__legal_entity_data_fields = (
            'logo',
        )
        self.__legal_entity_object_mapping = Mapping(
            business = 'sectors',
            name = 'name',
            text = 'description'
        )
        self.__legal_entity_single_fields = (
            'name',
            'text'
        )
        self.__lnk_data_fields = (
            'malware-sample',
        )
        self.__lnk_hash_types = (
            'md5',
            'sha1',
            'sha224',
            'sha256',
            'sha384',
            'sha512',
            'sha512/224',
            'sha512/256',
            'ssdeep',
            'tlsh'
        )
        self.__lnk_object_mapping = Mapping(
            **{
                'size-in-bytes': 'size'
            }
        )
        self.__lnk_path_fields = (
            'path',
            'fullpath'
        )
        lnk_single_fields = (
            'lnk-access-time',
            'lnk-creation-time',
            'lnk-modification-time',
            'malware-sample',
            'size-in-bytes'
        )
        self.__lnk_single_fields = self.__lnk_hash_types + lnk_single_fields
        self.__netflow_object_mapping = Mapping(
            features = {
                'src-port': 'src_port',
                'dst-port': 'dst_port',
                'byte-count': 'src_byte_count',
                'first-packet-seen': 'start',
                'last-packet-seen': 'end',
                'packet-count': 'src_packets'
            },
            extensions = {
                'icmp-type': "extensions.'icmp-ext'.icmp_type_hex",
                'tcp-flags': "extensions.'tcp-ext'.src_flags_hex"
            }
        )
        self.__network_connection_mapping = Mapping(
            features = Mapping(
                **{
                    'dst-port': 'dst_port',
                    'first-packet-seen': 'start',
                    'src-port': 'src_port'
                }
            ),
            protocols = (
                'layer3-protocol',
                'layer4-protocol',
                'layer7-protocol'
            )
        )
        self.__network_socket_state_fields = (
            'blocking',
            'listening'
        )
        self.__news_agency_contact_info_fields = (
            'address',
            'e-mail',
            'fax-number',
            'phone-number',
            'link'
        )
        self.__news_agency_data_fields = (
            'attachment',
        )
        self.__news_agency_object_mapping = Mapping(
            name = 'name'
        )
        self.__news_agency_single_fields = (
            'name',
        )
        self.__organization_contact_info_fields = (
            'address',
            'e-mail',
            'fax-number',
            'phone-number'
        )
        self.__organization_single_fields = (
            'description',
            'name'
        )
        self.__parler_account_data_fields = (
            'attachment',
            'cover-photo',
            'profile-photo'
        )
        self.__parler_account_object_mapping = Mapping(
            **{
                'account-id': 'user_id',
                'account-name': 'account_login'
            }
        )
        self.__parler_account_single_fields = (
            'account-id',
            'account-name'
        )
        self.__pe_object_mapping = Mapping(
            features = Mapping(
                **{
                    'imphash': 'imphash',
                    'number-sections': 'number_of_sections',
                    'type': 'pe_type'
                }
            ),
            header = Mapping(
                **{
                    'entrypoint-address': 'address_of_entry_point',
                }
            )
        )
        self.__pe_object_single_fields = (
            'entrypoint-address',
            'imphash',
            'number-sections',
            'type'
        )
        self.__pe_section_mapping = Mapping(
            **{
                'entropy': 'entropy',
                'name': 'name',
                'size-in-bytes': 'size'
            }
        )
        self.__reddit_account_data_fields = (
            'account-avatar',
            'attachment'
        )
        self.__reddit_account_object_mapping = Mapping(
            **{
                'account-id': 'user_id',
                'account-name': 'account_login'
            }
        )
        self.__reddit_account_single_fields = (
            'account-id',
            'account-name'
        )
        self.__registry_key_mapping = Mapping(
            **{
                'data-type': 'data_type',
                'name': 'name'
            }
        )
        self.__script_data_fields = (
            'script-as-attachment',
        )
        self.__script_single_fields = (
            'comment',
            'filename'
        )
        self.__script_to_malware_mapping = Mapping(
            comment = 'description',
            filename = 'name',
            language = 'implementation_languages'
        )
        self.__script_to_tool_mapping = Mapping(
            comment = 'description',
            filename = 'name'
        )
        self.__socket_type_enum_list = (
            "SOCK_STREAM",
            "SOCK_DGRAM",
            "SOCK_RAW",
            "SOCK_RDM",
            "SOCK_SEQPACKET"
        )
        self.__telegram_account_object_mapping = Mapping(
            id = 'user_id',
            username = 'account_login'
        )
        self.__telegram_account_single_fields = (
            'id',
            'username'
        )
        self.__twitter_account_data_fields = (
            'attachment',
            'profile-banner',
            'profile-image'
        )
        self.__twitter_account_object_mapping = Mapping(
            **{
                'displayed-name': 'display_name',
                'id': 'user_id',
                'name': 'account_login'
            }
        )
        self.__twitter_account_single_fields = (
            'displayed-name',
            'id',
            'name'
        )
        self.__user_account_data_fields = (
            'user-avatar',
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
        self.__x509_object_mapping = Mapping(
            extension = Mapping(
                dns_names = 'DNS name',
                email = 'email',
                ip = 'IP',
                rid = 'RID',
                uri = 'URI'
            ),
            features = Mapping(
                **{
                    'issuer': 'issuer',
                    'pubkey-info-algorithm': 'subject_public_key_algorithm',
                    'pubkey-info-exponent': 'subject_public_key_exponent',
                    'pubkey-info-modulus': 'subject_public_key_modulus',
                    'serial-number': 'serial_number',
                    'signature_algorithm': 'signature_algorithm',
                    'subject': 'subject',
                    'version': 'version'
                }
            ),
            timeline = Mapping(
                **{
                    'validity-not-after': 'validity_not_after',
                    'validity-not-before': 'validity_not_before'
                }
            )
        )
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
    def android_app_object_mapping(self) -> dict:
        return self.__android_app_object_mapping

    @property
    def android_app_single_fields(self) -> tuple:
        return self.__android_app_single_fields

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
    def cpe_asset_object_mapping(self) -> dict:
        return self.__cpe_asset_object_mapping

    @property
    def cpe_asset_single_fields(self) -> tuple:
        return self.__cpe_asset_single_fields

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
    def domain_ip_standard_fields(self) -> tuple:
        return self.__domain_ip_standard_fields

    @property
    def email_header_fields(self) -> dict:
        return self.__email_header_fields

    @property
    def email_data_fields(self) -> tuple:
        return self.__email_data_fields

    @property
    def employee_contact_info_fields(self) -> tuple:
        return self.__employee_contact_info_fields

    @property
    def employee_single_fields(self) -> tuple:
        return self.__employee_single_fields

    @property
    def external_id_to_source_name(self) -> dict:
        return self.__external_id_to_source_name

    @property
    def facebook_account_data_fields(self) -> tuple:
        return self.__facebook_account_data_fields

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
    def github_user_data_fields(self) -> tuple:
        return self.__github_user_data_fields

    @property
    def github_user_object_mapping(self) -> dict:
        return self.__github_user_object_mapping

    @property
    def github_user_single_fields(self) -> tuple:
        return self.__github_user_single_fields

    @property
    def gitlab_user_object_mapping(self) -> dict:
        return self.__gitlab_user_object_mapping

    @property
    def gitlab_user_single_fields(self) -> tuple:
        return self.__gitlab_user_single_fields

    @property
    def hash_attribute_types(self) -> tuple:
        return self.__hash_attribute_types

    @property
    def http_request_object_mapping(self) -> dict:
        return self.__http_request_object_mapping

    @property
    def http_request_single_fields(self) -> tuple:
        return self.__http_request_single_fields

    @property
    def image_data_fields(self) -> tuple:
        return self.__image_data_fields

    @property
    def image_single_fields(self) -> tuple:
        return self.__image_single_fields

    @property
    def image_uuid_fields(self) -> tuple:
        return self.__image_uuid_fields

    @property
    def ip_port_object_mapping(self) -> dict:
        return self.__ip_port_object_mapping

    @property
    def ip_port_single_fields(self) -> tuple:
        return self.__ip_port_single_fields

    @property
    def legal_entity_contact_info_fields(self) -> tuple:
        return self.__legal_entity_contact_info_fields

    @property
    def legal_entity_data_fields(self) -> tuple:
        return self.__legal_entity_data_fields

    @property
    def legal_entity_object_mapping(self) -> dict:
        return self.__legal_entity_object_mapping

    @property
    def legal_entity_single_fields(self) -> tuple:
        return self.__legal_entity_single_fields

    @property
    def lnk_data_fields(self) -> tuple:
        return self.__lnk_data_fields

    @property
    def lnk_hash_types(self) -> tuple:
        return self.__lnk_hash_types

    @property
    def lnk_object_mapping(self) -> dict:
        return self.__lnk_object_mapping

    @property
    def lnk_path_fields(self) -> tuple:
        return self.__lnk_path_fields

    @property
    def lnk_single_fields(self) -> tuple:
        return self.__lnk_single_fields

    @property
    def misp_identity_args(self) -> dict:
        return self.__misp_identity_args

    @property
    def netflow_object_mapping(self) -> dict:
        return self.__netflow_object_mapping

    @property
    def network_connection_mapping(self) -> dict:
        return self.__network_connection_mapping

    @property
    def network_socket_state_fields(self) -> tuple:
        return self.__network_socket_state_fields

    @property
    def news_agency_contact_info_fields(self) -> tuple:
        return self.__news_agency_contact_info_fields

    @property
    def news_agency_data_fields(self) -> tuple:
        return self.__news_agency_data_fields

    @property
    def news_agency_object_mapping(self) -> dict:
        return self.__news_agency_object_mapping

    @property
    def news_agency_single_fields(self) -> tuple:
        return self.__news_agency_single_fields

    @property
    def objects_mapping(self) -> dict:
        return self.__objects_mapping

    @property
    def organization_contact_info_fields(self) -> tuple:
        return self.__organization_contact_info_fields

    @property
    def organization_single_fields(self) -> tuple:
        return self.__organization_single_fields

    @property
    def parler_account_data_fields(self) -> tuple:
        return self.__parler_account_data_fields

    @property
    def parler_account_object_mapping(self) -> dict:
        return self.__parler_account_object_mapping

    @property
    def parler_account_single_fields(self) -> tuple:
        return self.__parler_account_single_fields

    @property
    def pe_object_mapping(self) -> dict:
        return self.__pe_object_mapping

    @property
    def pe_object_single_fields(self) -> tuple:
        return self.__pe_object_single_fields

    @property
    def pe_section_hash_types(self) -> tuple:
        return self.__pe_section_hash_types

    @property
    def pe_section_mapping(self) -> dict:
        return self.__pe_section_mapping

    @property
    def reddit_account_data_fields(self) -> tuple:
        return self.__reddit_account_data_fields

    @property
    def reddit_account_object_mapping(self) -> dict:
        return self.__reddit_account_object_mapping

    @property
    def reddit_account_single_fields(self) -> tuple:
        return self.__reddit_account_single_fields

    @property
    def registry_key_mapping(self) -> dict:
        return self.__registry_key_mapping

    @property
    def relationship_specs(self) -> dict:
        return self.__relationship_specs

    @property
    def script_data_fields(self) -> tuple:
        return self.__script_data_fields

    @property
    def script_single_fields(self) -> tuple:
        return self.__script_single_fields

    @property
    def script_to_malware_mapping(self) -> dict:
        return self.__script_to_malware_mapping

    @property
    def script_to_tool_mapping(self) -> dict:
        return self.__script_to_tool_mapping

    @property
    def socket_type_enum_list(self) -> tuple:
        return self.__socket_type_enum_list

    @property
    def source_names(self) -> tuple:
        return self.__source_names

    @property
    def telegram_account_object_mapping(self) -> dict:
        return self.__telegram_account_object_mapping

    @property
    def telegram_account_single_fields(self) -> tuple:
        return self.__telegram_account_single_fields

    @property
    def twitter_account_data_fields(self) -> tuple:
        return self.__twitter_account_data_fields

    @property
    def twitter_account_object_mapping(self) -> dict:
        return self.__twitter_account_object_mapping

    @property
    def twitter_account_single_fields(self) -> tuple:
        return self.__twitter_account_single_fields

    @property
    def user_account_data_fields(self) -> tuple:
        return self.__user_account_data_fields

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
