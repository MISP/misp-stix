#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .. import Mapping
from .stix_mapping import MISPtoSTIXMapping
from typing import Union


class MISPtoSTIX2Mapping(MISPtoSTIXMapping):
    __external_id_to_source_name = Mapping(
        CAPEC='capec',
        CVE='cve',
        CWE='cwe',
        MOB='mitre-mobile-attack',
        PRE='mitre-pre-attack',
        REF='reference_from_CAPEC'
    )
    __pe_section_hash_types = (
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
    __hash_attribute_types = (
        'authentihash',
        'imphash',
        'sha3-224',
        'sha3-256',
        'sha3-384',
        'sha3-512',
        'tlsh',
        'vhash'
    )
    __hash_attribute_types = __pe_section_hash_types + __hash_attribute_types
    __source_names = (
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
    __generic_galaxy_types = (
        'attack-pattern', 'campaign', 'course-of-action', 'intrusion-set',
        'malware', 'threat-actor', 'tool', 'vulnerability'
    )
    __misp_identity_args = Mapping(
        id='identity--55f6ea65-aa10-4c5a-bf01-4f84950d210f',
        type='identity',
        identity_class='organization',
        name='MISP',
        created='2015-09-14T15:40:21Z',
        modified='2015-09-14T15:40:21Z'
    )
    __relationship_specs = Mapping(
        **{
            'attack-pattern': {
                'identity': 'targets',
                'location': 'targets',
                'tool': 'uses',
                'vulnerability': 'targets'
            },
            'campaign': {
                'attack-pattern': 'uses',
                'identity': 'targets',
                'intrusion-set': 'attributed-to',
                'malware': 'uses',
                'threat-actor': 'attributed-to',
                'tool': 'uses',
                'vulnerability': 'targets'
            },
            'course-of-action': {
                'attack-pattern': 'mitigates',
                'tool': 'mitigates'
            },
            'indicator': {
                'attack-pattern': 'indicates',
                'campaign': 'indicates',
                'intrusion-set': 'indicates',
                'malware': 'indicates',
                'observed-data': 'based-on',
                'threat-actor': 'indicates',
                'tool': 'indicates'
            },
            'intrusion-set': {
                'attack-pattern': 'uses',
                'identity': 'targets',
                'malware': 'uses',
                'threat-actor': 'attributed-to',
                'tool': 'uses',
                'vulnerability': 'targets',
            },
            'malware': {
                'attack-pattern': 'uses',
                'intrusion-set': 'authored-by',
                'threat-actor': 'authored-by'
            },
            'threat-actor': {
                'attack-pattern': 'uses',
                'malware': 'uses',
                'tool': 'uses',
                'vulnerability': 'targets'
            },
            'tool': {
                'identity': 'targets',
                'location': 'targets'
            }
        }
    )

    # ATTRIBUTES MAPPING
    __attribute_types_mapping = Mapping(
        **{
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
            'vulnerability': '_parse_vulnerability_attribute',
            **dict.fromkeys(
                (
                    'cdhash', 'impfuzzy', 'pehash', 'telfhash',
                    *__hash_attribute_types
                ),
                '_parse_hash_attribute'
            ),
            **dict.fromkeys(
                (
                    'filename|impfuzzy', 'filename|pehash',
                    *(f"filename|{hash}" for hash in __hash_attribute_types)
                ),
                '_parse_hash_composite_attribute'
            ),
            **dict.fromkeys(('ip-src', 'ip-dst'), '_parse_ip_attribute'),
            **dict.fromkeys(
                ('ip-src|port', 'ip-dst|port'), '_parse_ip_port_attribute'
            ),
            **dict.fromkeys(('uri', 'url', 'link'), '_parse_url_attribute'),
            **dict.fromkeys(
                (
                    'x509-fingerprint-md5', 'x509-fingerprint-sha1',
                    'x509-fingerprint-sha256'
                ),
                '_parse_x509_fingerprint_attribute'
            )
        }
    )

    # GALAXIES MAPPING
    __cluster_to_stix_object = Mapping(
        **{
            'branded-vulnerability': 'vulnerability',
            'sector': 'identity',
            **dict.fromkeys(
                MISPtoSTIXMapping.attack_pattern_types(), 'attack-pattern'
            ),
            **dict.fromkeys(
                MISPtoSTIXMapping.course_of_action_types(), 'course-of-action'
            ),
            **dict.fromkeys(
                MISPtoSTIXMapping.intrusion_set_types(), 'intrusion-set'
            ),
            **dict.fromkeys(MISPtoSTIXMapping.malware_types(), 'malware'),
            **dict.fromkeys(
                MISPtoSTIXMapping.threat_actor_types(), 'threat-actor'
            ),
            **dict.fromkeys(MISPtoSTIXMapping.tool_types(), 'tool'),
        }
    )
    __galaxy_types_mapping = Mapping(
        **{
            'branded-vulnerability': '_parse_vulnerability_{}_galaxy',
            'sector': '_parse_sector_{}_galaxy',
            **dict.fromkeys(
                MISPtoSTIXMapping.attack_pattern_types(),
                '_parse_attack_pattern_{}_galaxy'
            ),
            **dict.fromkeys(
                MISPtoSTIXMapping.course_of_action_types(),
                '_parse_course_of_action_{}_galaxy'
            ),
            **dict.fromkeys(
                MISPtoSTIXMapping.intrusion_set_types(),
                '_parse_intrusion_set_{}_galaxy'
            ),
            **dict.fromkeys(
                MISPtoSTIXMapping.malware_types(), '_parse_malware_{}_galaxy'
            ),
            **dict.fromkeys(
                MISPtoSTIXMapping.threat_actor_types(),
                '_parse_threat_actor_{}_galaxy'
            ),
            **dict.fromkeys(
                MISPtoSTIXMapping.tool_types(), '_parse_tool_{}_galaxy'
            )
        }
    )
    __external_references_fields = Mapping(
        **{
            'external_id': '_parse_external_id',
            'refs': '_parse_external_url',
            'Technique ID': '_parse_external_id'
        }
    )
    __campaign_meta_mapping = Mapping(
        synonyms='_parse_synonyms_meta_field'
    )
    __generic_meta_mapping = Mapping(
        **{
            'attack-pattern': {'created': True, 'modified': True},
            'campaign': {
                'created': True, 'first_seen': True, 'last_seen': True,
                'modified': True, 'objective': True
            },
            'course-of-action': {'created': True, 'modified': True},
            'intrusion-set': {
                'created': True, 'first_seen': True, 'goals': False,
                'last_seen': True, 'modified': True, 'primary_motivation': True,
                'resource_level': True, 'secondary_motivations': False
            },
            'tool': {'created': True, 'modified': True, 'tool_version': True},
            'vulnerability': {'created': True, 'modified': True}
        }
    )
    __intrusion_set_meta_mapping = Mapping(
        synonyms='_parse_synonyms_meta_field'
    )
    __malware_meta_mapping = Mapping(
        **{
            'is_family': '_parse_malware_is_family_field',
            'kill_chain': '_parse_kill_chain',
            'labels': '_parse_malware_types',
            'malware_types': '_parse_malware_types',
            'synonyms': '_parse_synonyms_21_meta_field',
            'type': '_parse_malware_types'
        }
    )
    __threat_actor_meta_mapping = Mapping(
        **{
            'labels': '_parse_threat_actor_types',
            'synonyms': '_parse_synonyms_meta_field',
            'threat_actor_types': '_parse_threat_actor_types',
            'type': '_parse_threat_actor_types'
        }
    )
    __tool_meta_mapping = Mapping(
        **{
            'labels': '_parse_tool_types',
            'kill_chain': '_parse_kill_chain',
            'synonyms': '_parse_synonyms_21_meta_field',
            'tool_types': '_parse_tool_types',
            'type': '_parse_tool_types'
        }
    )
    __vulnerability_meta_mapping = Mapping(
        **{
            'aliases': '_parse_external_references'
        }
    )

    # MISP OBJECTS MAPPING
    __objects_mapping = Mapping(
        **{
            'android-app': '_parse_android_app_object',
            'asn': '_parse_asn_object',
            'attack-pattern': '_parse_attack_pattern_object',
            'course-of-action': '_parse_course_of_action_object',
            'cpe-asset': '_parse_cpe_asset_object',
            'credential': '_parse_credential_object',
            'domain-ip': '_parse_domain_ip_object',
            'domain|ip': '_parse_domain_ip_object',
            'email': '_parse_email_object',
            'employee': '_parse_employee_object',
            'facebook-account': '_parse_account_object_with_attachment',
            'file': '_parse_file_object',
            'github-user': '_parse_account_object_with_attachment',
            'gitlab-user': '_parse_account_object',
            'http-request': '_parse_http_request_object',
            'identity': '_parse_identity_object',
            'image': '_parse_image_object',
            'intrusion-set': '_parse_intrusion_set_object',
            'ip-port': '_parse_ip_port_object',
            'ip|port': '_parse_ip_port_object',
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
            'person': '_parse_person_object',
            'process': '_parse_process_object',
            'reddit-account': '_parse_account_object_with_attachment',
            'registry-key': '_parse_registry_key_object',
            'script': '_parse_script_object',
            'stix2-pattern': '_parse_stix_pattern_object',
            'telegram-account': '_parse_account_object',
            'twitter-account': '_parse_account_object_with_attachment',
            'url': '_parse_url_object',
            'user-account': '_parse_user_account_object',
            'vulnerability': '_parse_vulnerability_object',
            'x509': '_parse_x509_object'
        }
    )
    __address_family_enum_list = (
        "AF_UNSPEC", "AF_INET", "AF_IPX", "AF_APPLETALK",
        "AF_NETBIOS", "AF_INET6", "AF_IRDA", "AF_BTH"
    )
    __android_app_object_mapping = Mapping(
        name='name'
    )
    __android_app_single_fields = (
        'name',
    )
    __as_single_fields = (
        'asn',
        'description'
    )
    __attack_pattern_object_mapping = Mapping(
        name='name',
        summary='description'
    )
    __attack_pattern_reference_mapping = Mapping(
        id=('capec', 'external_id'),
        references=('mitre-attack', 'url')
    )
    __attack_pattern_single_fields = (
        'name',
        'summary'
    )
    __course_of_action_object_mapping = (
        'name',
        'description'
    )
    __cpe_asset_object_mapping = Mapping(
        cpe='cpe',
        language='languages',
        product='name',
        vendor='vendor',
        version='version'
    )
    __cpe_asset_single_fields = (
        'cpe',
        'product',
        'vendor',
        'version'
    )
    __credential_single_fields = (
        'username',
    )
    __domain_family_enum_list = (
        "PF_INET",
        "PF_IPX",
        "PF_APPLETALK",
        "PF_INET6",
        "PF_AX25",
        "PF_NETROM"
    )
    __domain_ip_object_mapping = Mapping(
        domain='value',
        hostname='value',
        ip='resolves_to_refs[*].value'
    )
    __domain_ip_single_fields = (
        'first-seen',
        'hostname',
        'last-seen',
        'port',
        'registration-date',
        'text'
    )
    __domain_ip_standard_fields = (
        'domain',
        'hostname',
        'ip'
    )
    __email_header_fields = Mapping(
        **{
            'reply-to': 'Reply-To',
            'x-mailer': 'X-Mailer'
        }
    )
    __email_data_fields = (
        'attachment',
        'screenshot'
    )
    __employee_contact_info_fields = (
        'email-address',
    )
    __employee_single_fields = (
        'first-name',
        'full-name',
        'last-name',
        'text'
    )
    __facebook_account_data_fields = (
        'attachment',
        'user-avatar'
    )
    __facebook_account_object_mapping = Mapping(
        **{
            'account-id': 'user_id',
            'account-name': 'account_login'
        }
    )
    __facebook_account_single_fields = (
        'account-id',
        'account-name'
    )
    __file_data_fields = (
        'attachment',
        'malware-sample'
    )
    __file_hash_main_types = (
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
    __file_hash_types = (
        'sha512/224',
        'sha512/256',
    )
    __file_object_mapping = Mapping(
        **{
            'filename': 'name',
            'file-encoding': 'name_enc',
            'mime-type': 'mime_type',
            'size-in-bytes': 'size'
        }
    )
    __file_single_fields = (
        'access-time',
        'creation-time',
        'modification-time',
        'path',
        *__file_data_fields,
        *__hash_attribute_types
    )
    __github_user_data_fields = (
        'profile-image',
    )
    __github_user_object_mapping = Mapping(
        **{
            'id': 'user_id',
            'user-fullname': 'display_name',
            'username': 'account_login'
        }
    )
    __github_user_single_fields = (
        'id',
        'user-fullname',
        'username'
    )
    __gitlab_user_object_mapping = Mapping(
        id='user_id',
        name='display_name',
        username='account_login'
    )
    __gitlab_user_single_fields = (
        'id',
        'name',
        'username'
    )
    __http_request_object_mapping = Mapping(
        references={
            'ip-src': "src_ref.type = '{}' AND network-traffic:src_ref.value",
            'ip-dst': "dst_ref.type = '{}' AND network-traffic:dst_ref.value",
            'host': "dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value"
        },
        request_extension={
            'method': 'request_method',
            'uri': 'request_value',
            'url': 'request_value'
        },
        request_header={
            'content-type': 'Content-Type',
            'cookie': 'Cookie',
            'referer': 'Referer',
            'user-agent': 'User-Agent'
        }
    )
    __http_request_single_fields = (
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
    __identity_single_fields = (
        'contact_information',
        'description',
        'identity_class',
        'name'
    )
    __image_data_fields = (
        'attachment',
    )
    __image_single_fields = (
        'attachment',
        'filename',
        'url'
    )
    __image_uuid_fields = (
        'attachment',
        'url'
    )
    __intrusion_set_object_mapping = Mapping(
        features={
            'aliases': 'aliases',
            'description': 'description',
            'goals': 'goals',
            'name': 'name',
            'primary-motivation': 'primary_motivation',
            'resource_level': 'resource_level',
            'secondary-motivation': 'secondary_motivations'
        },
        timeline={
            'first_seen': 'first_seen',
            'last_seen': 'last_seen'
        }
    )
    __intrusion_set_single_fields = (
        'description',
        'first_seen',
        'last_seen',
        'name',
        'primary-motivation',
        'resource_level'
    )
    __ip_port_object_mapping = Mapping(
        ip_features={
            'ip': "dst_ref.type = '{}' AND network-traffic:dst_ref.value",
            'ip-src': "src_ref.type = '{}' AND network-traffic:src_ref.value",
            'ip-dst': "dst_ref.type = '{}' AND network-traffic:dst_ref.value"
        },
        domain_features={
            'domain': "dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value",
            'hostname': "dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value"
        },
        features={
            'dst-port': "dst_port",
            'src-port': "src_port"
        },
        timeline={
            'first-seen': "start",
            'last-seen': "end"
        }
    )
    __ip_port_single_fields = (
        'first-seen',
        'last-seen',
        'protocol'
    )
    __legal_entity_contact_info_fields = (
        'phone-number',
        'website'
    )
    __legal_entity_data_fields = (
        'logo',
    )
    __legal_entity_object_mapping = Mapping(
        business='sectors',
        name='name',
        text='description'
    )
    __legal_entity_single_fields = (
        'name',
        'text'
    )
    __lnk_data_fields = (
        'malware-sample',
    )
    __lnk_hash_types = (
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
    __lnk_object_mapping = Mapping(
        **{
            'size-in-bytes': 'size'
        }
    )
    __lnk_path_fields = (
        'path',
        'fullpath'
    )
    __lnk_single_fields = (
        'lnk-access-time',
        'lnk-creation-time',
        'lnk-modification-time',
        'malware-sample',
        'size-in-bytes',
        *__lnk_hash_types
    )
    __netflow_object_mapping = Mapping(
        features={
            'src-port': 'src_port',
            'dst-port': 'dst_port',
            'byte-count': 'src_byte_count',
            'packet-count': 'src_packets'
        },
        timeline={
            'first-packet-seen': 'start',
            'last-packet-seen': 'end'
        },
        extensions={
            'icmp-type': "extensions.'icmp-ext'.icmp_type_hex",
            'tcp-flags': "extensions.'tcp-ext'.src_flags_hex"
        }
    )
    __network_connection_mapping = Mapping(
        features={
            'dst-port': 'dst_port',
            'first-packet-seen': 'start',
            'src-port': 'src_port'
        },
        protocols=(
            'layer3-protocol',
            'layer4-protocol',
            'layer7-protocol'
        )
    )
    __network_socket_state_fields = (
        'blocking',
        'listening'
    )
    __news_agency_contact_info_fields = (
        'address',
        'e-mail',
        'fax-number',
        'phone-number',
        'link'
    )
    __news_agency_data_fields = (
        'attachment',
    )
    __news_agency_object_mapping = Mapping(
            name='name'
        )
    __news_agency_single_fields = (
        'name',
    )
    __organization_contact_info_fields = (
        'address',
        'e-mail',
        'fax-number',
        'phone-number'
    )
    __organization_single_fields = (
        'description',
        'name'
    )
    __parler_account_data_fields = (
        'attachment',
        'cover-photo',
        'profile-photo'
    )
    __parler_account_object_mapping = Mapping(
        **{
            'account-id': 'user_id',
            'account-name': 'account_login'
        }
    )
    __parler_account_single_fields = (
        'account-id',
        'account-name'
    )
    __pe_object_mapping = Mapping(
        features={
            'imphash': 'imphash',
            'number-sections': 'number_of_sections',
            'type': 'pe_type'
        },
        header={
            'entrypoint-address': 'address_of_entry_point',
        }
    )
    __pe_object_single_fields = (
        'entrypoint-address',
        'imphash',
        'number-sections',
        'type'
    )
    __pe_section_mapping = Mapping(
        **{
            'entropy': 'entropy',
            'name': 'name',
            'size-in-bytes': 'size'
        }
    )
    __person_contact_info_fields = (
        'address',
        'e-mail',
        'fax-number',
        'phone-number'
    )
    __person_single_fields = (
        'first-name',
        'full-name',
        'last-name',
        'middle-name',
        'text'
    )
    __reddit_account_data_fields = (
        'account-avatar',
        'attachment'
    )
    __reddit_account_object_mapping = Mapping(
        **{
            'account-id': 'user_id',
            'account-name': 'account_login'
        }
    )
    __reddit_account_single_fields = (
        'account-id',
        'account-name'
    )
    __registry_key_mapping = Mapping(
        **{
            'data-type': 'data_type',
            'name': 'name'
        }
    )
    __script_data_fields = (
        'script-as-attachment',
    )
    __script_single_fields = (
        'comment',
        'filename'
    )
    __script_to_malware_mapping = Mapping(
        comment='description',
        filename='name',
        language='implementation_languages'
    )
    __script_to_tool_mapping = Mapping(
        comment='description',
        filename='name'
    )
    __socket_type_enum_list = (
        "SOCK_STREAM",
        "SOCK_DGRAM",
        "SOCK_RAW",
        "SOCK_RDM",
        "SOCK_SEQPACKET"
    )
    __stix_pattern_object_mapping = Mapping(
        **{
            'comment': 'description',
            'stix2-pattern': 'pattern',
            'version': 'pattern_version'
        }
    )
    __telegram_account_object_mapping = Mapping(
        id='user_id',
        username='account_login'
    )
    __telegram_account_single_fields = (
        'id',
        'username'
    )
    __twitter_account_data_fields = (
        'attachment',
        'profile-banner',
        'profile-image'
    )
    __twitter_account_object_mapping = Mapping(
        **{
            'displayed-name': 'display_name',
            'id': 'user_id',
            'name': 'account_login'
        }
    )
    __twitter_account_single_fields = (
        'displayed-name',
        'id',
        'name'
    )
    __user_account_data_fields = (
        'user-avatar',
    )
    __user_account_single_fields = (
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
    __x509_hash_fields = (
        'x509-fingerprint-md5',
        'x509-fingerprint-sha1',
        'x509-fingerprint-sha256'
    )
    __x509_object_mapping = Mapping(
        extension={
            'dns_names': 'DNS name',
            'email': 'email',
            'ip': 'IP',
            'rid': 'RID',
            'uri': 'URI'
        },
        features={
            'issuer': 'issuer',
            'pubkey-info-algorithm': 'subject_public_key_algorithm',
            'pubkey-info-exponent': 'subject_public_key_exponent',
            'pubkey-info-modulus': 'subject_public_key_modulus',
            'serial-number': 'serial_number',
            'signature_algorithm': 'signature_algorithm',
            'subject': 'subject',
            'version': 'version'
        },
        timeline={
            'validity-not-after': 'validity_not_after',
            'validity-not-before': 'validity_not_before'
        }
    )
    __x509_single_fields = (
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

    @classmethod
    def address_family_enum_list(cls) -> tuple:
        return cls.__address_family_enum_list

    @classmethod
    def android_app_object_mapping(cls) -> dict:
        return cls.__android_app_object_mapping

    @classmethod
    def android_app_single_fields(cls) -> tuple:
        return cls.__android_app_single_fields

    @classmethod
    def as_single_fields(cls) -> tuple:
        return cls.__as_single_fields

    @classmethod
    def attack_pattern_object_mapping(cls) -> dict:
        return cls.__attack_pattern_object_mapping

    @classmethod
    def attack_pattern_reference_mapping(cls, field: str) -> Union[tuple, None]:
        return cls.__attack_pattern_reference_mapping.get(field)

    @classmethod
    def attack_pattern_single_fields(cls) -> tuple:
        return cls.__attack_pattern_single_fields

    @classmethod
    def attribute_types_mapping(cls) -> dict:
        return cls.__attribute_types_mapping

    @classmethod
    def campaign_meta_mapping(cls, field: str) -> Union[str, None]:
        return cls.__campaign_meta_mapping.get(field)

    @classmethod
    def cluster_to_stix_object(cls) -> dict:
        return cls.__cluster_to_stix_object

    @classmethod
    def course_of_action_object_mapping(cls) -> tuple:
        return cls.__course_of_action_object_mapping

    @classmethod
    def cpe_asset_object_mapping(cls) -> dict:
        return cls.__cpe_asset_object_mapping

    @classmethod
    def cpe_asset_single_fields(cls) -> tuple:
        return cls.__cpe_asset_single_fields

    @classmethod
    def credential_single_fields(cls) -> tuple:
        return cls.__credential_single_fields

    @classmethod
    def domain_family_enum_list(cls) -> tuple:
        return cls.__domain_family_enum_list

    @classmethod
    def domain_ip_object_mapping(cls) -> dict:
        return cls.__domain_ip_object_mapping

    @classmethod
    def domain_ip_single_fields(cls) -> tuple:
        return cls.__domain_ip_single_fields

    @classmethod
    def domain_ip_standard_fields(cls) -> tuple:
        return cls.__domain_ip_standard_fields

    @classmethod
    def email_header_fields(cls) -> dict:
        return cls.__email_header_fields

    @classmethod
    def email_data_fields(cls) -> tuple:
        return cls.__email_data_fields

    @classmethod
    def employee_contact_info_fields(cls) -> tuple:
        return cls.__employee_contact_info_fields

    @classmethod
    def employee_single_fields(cls) -> tuple:
        return cls.__employee_single_fields

    @classmethod
    def external_id_to_source_name(cls) -> dict:
        return cls.__external_id_to_source_name

    @classmethod
    def external_references_fields(cls, field: str) -> Union[str, None]:
        return cls.__external_references_fields.get(field)

    @classmethod
    def facebook_account_data_fields(cls) -> tuple:
        return cls.__facebook_account_data_fields

    @classmethod
    def facebook_account_object_mapping(cls) -> dict:
        return cls.__facebook_account_object_mapping

    @classmethod
    def facebook_account_single_fields(cls) -> tuple:
        return cls.__facebook_account_single_fields

    @classmethod
    def file_data_fields(cls) -> tuple:
        return cls.__file_data_fields

    @classmethod
    def file_hash_main_types(cls) -> tuple:
        return cls.__file_hash_main_types

    @classmethod
    def file_hash_types(cls) -> tuple:
        return cls.__file_hash_types

    @classmethod
    def file_object_mapping(cls) -> dict:
        return cls.__file_object_mapping

    @classmethod
    def file_single_fields(cls) -> tuple:
        return cls.__file_single_fields

    @classmethod
    def galaxy_types_mapping(cls) -> dict:
        return cls.__galaxy_types_mapping

    @classmethod
    def generic_galaxy_types(cls) -> tuple:
        return cls.__generic_galaxy_types

    @classmethod
    def generic_meta_mapping(cls) -> dict:
        return cls.__generic_meta_mapping

    @classmethod
    def github_user_data_fields(cls) -> tuple:
        return cls.__github_user_data_fields

    @classmethod
    def github_user_object_mapping(cls) -> dict:
        return cls.__github_user_object_mapping

    @classmethod
    def github_user_single_fields(cls) -> tuple:
        return cls.__github_user_single_fields

    @classmethod
    def gitlab_user_object_mapping(cls) -> dict:
        return cls.__gitlab_user_object_mapping

    @classmethod
    def gitlab_user_single_fields(cls) -> tuple:
        return cls.__gitlab_user_single_fields

    @classmethod
    def hash_attribute_types(cls) -> tuple:
        return cls.__hash_attribute_types

    @classmethod
    def http_request_object_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__http_request_object_mapping.get(field)

    @classmethod
    def http_request_single_fields(cls) -> tuple:
        return cls.__http_request_single_fields

    @classmethod
    def identity_single_fields(cls) -> tuple:
        return cls.__identity_single_fields

    @classmethod
    def image_data_fields(cls) -> tuple:
        return cls.__image_data_fields

    @classmethod
    def image_single_fields(cls) -> tuple:
        return cls.__image_single_fields

    @classmethod
    def image_uuid_fields(cls) -> tuple:
        return cls.__image_uuid_fields

    @classmethod
    def intrusion_set_meta_mapping(cls, field: str) -> Union[str, None]:
        return cls.__intrusion_set_meta_mapping.get(field)

    @classmethod
    def intrusion_set_object_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__intrusion_set_object_mapping.get(field)

    @classmethod
    def intrusion_set_single_fields(cls) -> tuple:
        return cls.__intrusion_set_single_fields

    @classmethod
    def ip_port_object_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__ip_port_object_mapping.get(field)

    @classmethod
    def ip_port_single_fields(cls) -> tuple:
        return cls.__ip_port_single_fields

    @classmethod
    def legal_entity_contact_info_fields(cls) -> tuple:
        return cls.__legal_entity_contact_info_fields

    @classmethod
    def legal_entity_data_fields(cls) -> tuple:
        return cls.__legal_entity_data_fields

    @classmethod
    def legal_entity_object_mapping(cls) -> dict:
        return cls.__legal_entity_object_mapping

    @classmethod
    def legal_entity_single_fields(cls) -> tuple:
        return cls.__legal_entity_single_fields

    @classmethod
    def lnk_data_fields(cls) -> tuple:
        return cls.__lnk_data_fields

    @classmethod
    def lnk_hash_types(cls) -> tuple:
        return cls.__lnk_hash_types

    @classmethod
    def lnk_object_mapping(cls) -> dict:
        return cls.__lnk_object_mapping

    @classmethod
    def lnk_path_fields(cls) -> tuple:
        return cls.__lnk_path_fields

    @classmethod
    def lnk_single_fields(cls) -> tuple:
        return cls.__lnk_single_fields

    @classmethod
    def malware_meta_mapping(cls, field: str) -> Union[str, None]:
        return cls.__malware_meta_mapping.get(field)

    @classmethod
    def misp_identity_args(cls) -> dict:
        return cls.__misp_identity_args

    @classmethod
    def netflow_object_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__netflow_object_mapping.get(field)

    @classmethod
    def network_connection_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__network_connection_mapping.get(field)

    @classmethod
    def network_socket_state_fields(cls) -> tuple:
        return cls.__network_socket_state_fields

    @classmethod
    def news_agency_contact_info_fields(cls) -> tuple:
        return cls.__news_agency_contact_info_fields

    @classmethod
    def news_agency_data_fields(cls) -> tuple:
        return cls.__news_agency_data_fields

    @classmethod
    def news_agency_object_mapping(cls) -> dict:
        return cls.__news_agency_object_mapping

    @classmethod
    def news_agency_single_fields(cls) -> tuple:
        return cls.__news_agency_single_fields

    @classmethod
    def objects_mapping(cls) -> dict:
        return cls.__objects_mapping

    @classmethod
    def organization_contact_info_fields(cls) -> tuple:
        return cls.__organization_contact_info_fields

    @classmethod
    def organization_single_fields(cls) -> tuple:
        return cls.__organization_single_fields

    @classmethod
    def parler_account_data_fields(cls) -> tuple:
        return cls.__parler_account_data_fields

    @classmethod
    def parler_account_object_mapping(cls) -> dict:
        return cls.__parler_account_object_mapping

    @classmethod
    def parler_account_single_fields(cls) -> tuple:
        return cls.__parler_account_single_fields

    @classmethod
    def pe_object_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__pe_object_mapping.get(field)

    @classmethod
    def pe_object_single_fields(cls) -> tuple:
        return cls.__pe_object_single_fields

    @classmethod
    def pe_section_hash_types(cls) -> tuple:
        return cls.__pe_section_hash_types

    @classmethod
    def pe_section_mapping(cls) -> dict:
        return cls.__pe_section_mapping

    @classmethod
    def person_contact_info_fields(cls) -> tuple:
        return cls.__person_contact_info_fields

    @classmethod
    def person_single_fields(cls) -> tuple:
        return cls.__person_single_fields

    @classmethod
    def reddit_account_data_fields(cls) -> tuple:
        return cls.__reddit_account_data_fields

    @classmethod
    def reddit_account_object_mapping(cls) -> dict:
        return cls.__reddit_account_object_mapping

    @classmethod
    def reddit_account_single_fields(cls) -> tuple:
        return cls.__reddit_account_single_fields

    @classmethod
    def registry_key_mapping(cls) -> dict:
        return cls.__registry_key_mapping

    @classmethod
    def relationship_specs(cls, field: str) -> Union[dict, None]:
        return cls.__relationship_specs.get(field)

    @classmethod
    def script_data_fields(cls) -> tuple:
        return cls.__script_data_fields

    @classmethod
    def script_single_fields(cls) -> tuple:
        return cls.__script_single_fields

    @classmethod
    def script_to_malware_mapping(cls) -> dict:
        return cls.__script_to_malware_mapping

    @classmethod
    def script_to_tool_mapping(cls) -> dict:
        return cls.__script_to_tool_mapping

    @classmethod
    def socket_type_enum_list(cls) -> tuple:
        return cls.__socket_type_enum_list

    @classmethod
    def source_names(cls) -> tuple:
        return cls.__source_names

    @classmethod
    def stix_pattern_object_mapping(cls, field: str) -> Union[str, None]:
        return cls.__stix_pattern_object_mapping.get(field)

    @classmethod
    def telegram_account_object_mapping(cls) -> dict:
        return cls.__telegram_account_object_mapping

    @classmethod
    def telegram_account_single_fields(cls) -> tuple:
        return cls.__telegram_account_single_fields

    @classmethod
    def threat_actor_meta_mapping(cls, field: str) -> Union[str, None]:
        return cls.__threat_actor_meta_mapping.get(field)

    @classmethod
    def tool_meta_mapping(cls, field: str) -> Union[str, None]:
        return cls.__tool_meta_mapping.get(field)

    @classmethod
    def twitter_account_data_fields(cls) -> tuple:
        return cls.__twitter_account_data_fields

    @classmethod
    def twitter_account_object_mapping(cls) -> dict:
        return cls.__twitter_account_object_mapping

    @classmethod
    def twitter_account_single_fields(cls) -> tuple:
        return cls.__twitter_account_single_fields

    @classmethod
    def user_account_data_fields(cls) -> tuple:
        return cls.__user_account_data_fields

    @classmethod
    def user_account_single_fields(cls) -> tuple:
        return cls.__user_account_single_fields

    @classmethod
    def vulnerability_meta_mapping(cls, field: str) -> Union[str, None]:
        return cls.__vulnerability_meta_mapping.get(field)

    @classmethod
    def x509_hash_fields(cls) -> tuple:
        return cls.__x509_hash_fields

    @classmethod
    def x509_object_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__x509_object_mapping.get(field)

    @classmethod
    def x509_single_fields(cls) -> tuple:
        return cls.__x509_single_fields
