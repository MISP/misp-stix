#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .. import Mapping
from .stix2_mapping import STIX2toMISPMapping
from typing import Union


class InternalSTIX2toMISPMapping(STIX2toMISPMapping):
    __object_type_refs_to_skip = (
        *STIX2toMISPMapping.object_type_refs_to_skip(),
        *STIX2toMISPMapping.observable_object_types()
    )
    __attributes_mapping = {
        'vulnerability': '_parse_vulnerability_attribute'
    }
    __indicator_attributes_mapping = Mapping(
        **{
            'AS': '_attribute_from_AS',
            'attachment': '_attribute_from_attachment',
            'malware-sample': '_attribute_from_malware_sample',
            **dict.fromkeys(
                (
                    'authentihash', 'cdhash', 'domain', 'email',
                    'email-attachment', 'email-body', 'email-dst',
                    'email-header', 'email-message-id', 'email-reply-to',
                    'email-src', 'email-subject', 'email-x-mailer', 'filename',
                    'hostname', 'http-method', 'imphash', 'impfuzzy', 'link',
                    'mac-address', 'md5', 'mutex', 'pehash', 'port', 'sha1',
                    'sha224', 'sha256', 'sha384', 'sha512', 'sha512/224',
                    'sha512/256', 'sha3-224', 'sha3-256', 'sha3-384',
                    'sha3-512', 'size-in-bytes', 'ssdeep', 'regkey', 'telfhash',
                    'tlsh', 'uri', 'url', 'user-agent', 'vhash',
                    'x509-fingerprint-md5', 'x509-fingerprint-sha1',
                    'x509-fingerprint-sha256'
                ),
                '_attribute_from_simple_pattern'
            ),
            **dict.fromkeys(
                (
                    'filename|authentihash', 'filename|imphash',
                    'filename|impfuzzy', 'filename|md5', 'filename|pehash',
                    'filename|sha1', 'filename|sha224', 'filename|sha256',
                    'filename|sha384', 'filename|sha512', 'filename|sha512/224',
                    'filename|sha512/256', 'filename|sha3-224',
                    'filename|sha3-256', 'filename|sha3-384',
                    'filename|sha3-512', 'filename|ssdeep', 'filename|tlsh',
                    'filename|vhash'
                ),
                '_attribute_from_filename_hash'
            ),
            **dict.fromkeys(
                (
                    'domain|ip', 'hostname|port', 'regkey|value'
                ),
                '_attribute_from_double_pattern'
            ),
            **dict.fromkeys(
                (
                    'github-username', 'ip-src', 'ip-dst'
                ),
                '_attribute_from_dual_pattern'
            ),
            **dict.fromkeys(
                (
                    'ip-src|port', 'ip-dst|port'
                ),
                '_attribute_from_ip_port'
            ),
            **dict.fromkeys(
                (
                    'sigma', 'snort', 'yara'
                ),
                '_attribute_from_patterning_language'
            )
        }
    )
    __observable_attributes_mapping = Mapping(
        **{
            'AS': '_attribute_from_AS',
            'attachment': '_attribute_from_attachment',
            'domain': '_attribute_from_domain',
            'domain|ip': '_attribute_from_domain_ip',
            'email-attachment': '_attribute_from_email_attachment',
            'email-body': '_attribute_from_email_body',
            'email-header': '_attribute_from_email_header',
            'email-message-id': '_attribute_from_email_message_id',
            'email-reply-to': '_attribute_from_email_reply_to',
            'email-subject': '_attribute_from_email_subject',
            'email-x-mailer': '_attribute_from_email_x_mailer',
            'github-username': '_attribute_from_github_username',
            'hostname|port': '_attribute_from_hostname_port',
            'malware-sample': '_attribute_from_malware_sample',
            'regkey': '_attribute_from_regkey',
            'regkey|value': '_attribute_from_regkey_value',
            **dict.fromkeys(
                (
                    'domain', 'email', 'hostname', 'link', 'mac-address',
                    'mutex', 'uri', 'url'
                ),
                '_attribute_from_first'
            ),
            **dict.fromkeys(
                (
                    'authentihash', 'cdhash', 'imphash', 'impfuzzy', 'md5',
                    'pehash', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
                    'sha512/224', 'sha512/256', 'sha3-224', 'sha3-256',
                    'sha3-384', 'sha3-512', 'ssdeep', 'telfhash', 'tlsh',
                    'vhash', 'x509-fingerprint-md5', 'x509-fingerprint-sha1',
                    'x509-fingerprint-sha256'
                ),
                '_attribute_from_hash'
            ),
            **dict.fromkeys(
                (
                    'filename|authentihash', 'filename|imphash',
                    'filename|impfuzzy', 'filename|md5', 'filename|pehash',
                    'filename|sha1', 'filename|sha224', 'filename|sha256',
                    'filename|sha384', 'filename|sha512', 'filename|sha512/224',
                    'filename|sha512/256', 'filename|sha3-224',
                    'filename|sha3-256', 'filename|sha3-384',
                    'filename|sha3-512', 'filename|ssdeep', 'filename|tlsh',
                    'filename|vhash'
                ),
                '_attribute_from_filename_hash'
            ),
            **dict.fromkeys(
                (
                    'ip-src|port', 'ip-dst|port'
                ),
                '_attribute_from_ip_port'
            ),
            **dict.fromkeys(
                (
                    'filename', 'mutex'
                ),
                '_attribute_from_name'
            ),
            **dict.fromkeys(
                (
                    'email-dst', 'email-src', 'ip-src', 'ip-dst'
                ),
                '_attribute_from_address'
            )
        }
    )
    __objects_mapping = Mapping(
        **{
            'android-app': '_object_from_android_app',
            'asn': '_object_from_asn',
            'attack-pattern': '_parse_attack_pattern_object',
            'course-of-action': '_parse_course_of_action_object',
            'cpe-asset': '_object_from_cpe_asset',
            'credential': '_object_from_credential',
            'domain-ip': '_object_from_domain_ip',
            'email': '_object_from_email',
            'employee': '_parse_employee_object',
            'facebook-account': '_object_from_facebook_account',
            'file': '_object_from_file',
            'geolocation': '_parse_location_object',
            'github-user': '_object_from_github_user',
            'gitlab-user': '_object_from_gitlab_user',
            'http-request': '_object_from_http_request',
            'image': '_object_from_image',
            'ip-port': '_object_from_ip_port',
            'legal-entity': '_parse_legal_entity_object',
            'lnk': '_object_from_lnk',
            'malware': '_parse_malware_object',
            'mutex': '_object_from_mutex',
            'netflow': '_object_from_netflow',
            'network-connection': '_object_from_network_connection',
            'network-socket': '_object_from_network_socket',
            'news-agency': '_parse_news_agency_object',
            'organization': '_parse_organization_object',
            'parler-account': '_object_from_parler_account',
            'process': '_object_from_process',
            'reddit-account': '_object_from_reddit_account',
            'registry-key': '_object_from_registry_key',
            'script': '_parse_script_object',
            'telegram-account': '_object_from_telegram_account',
            'twitter-account': '_object_from_twitter_account',
            'url': '_object_from_url',
            'user-account': '_object_from_user_account',
            'vulnerability': '_parse_vulnerability_object',
            'x509': '_object_from_x509',
            **dict.fromkeys(
                (
                    'sigma', 'suricata', 'yara'
                ),
                '_object_from_patterning_language'
            )
        }
    )

    # ATTRIBUTES DECLARATION
    __dst_as_attribute = Mapping(
        **{'type': 'AS', 'object_relation': 'dst-as'}
    )
    __host_attribute = Mapping(
        **{'type': 'hostname', 'object_relation': 'host'}
    )
    __hostname_dst_attribute = Mapping(
        **{'type': 'hostname', 'object_relation': 'hostname-dst'}
    )
    __hostname_src_attribute = Mapping(
        **{'type': 'hostname', 'object_relation': 'hostname-src'}
    )
    __icmp_type_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'icmp-type'}
    )
    __protocol_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'protocol'}
    )
    __src_as_attribute = Mapping(
        **{'type': 'AS', 'object_relation': 'src-as'}
    )
    __tcp_flags_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'tcp-flags'}
    )

    # OBJECT ATTRIBUTES DECLARATION
    __account_id_attribute = {'type': 'text', 'object_relation': 'account-id'}
    __account_name_attribute = {'type': 'text', 'object_relation': 'account-name'}
    __alias_attribute = {'type': 'text', 'object_relation': 'alias'}
    __archive_attribute = {'type': 'link', 'object_relation': 'archive'}
    __attachment_attribute = {'type': 'attachment', 'object_relation': 'attachment'}
    __authentihash_attribute = {'type': 'authentihash', 'object_relation': 'authentihash'}
    __basicauth_password_attribute = {'type': 'text', 'object_relation': 'basicauth-password'}
    __basicauth_user_attribute = {'type': 'text', 'object_relation': 'basicauth-user'}
    __bcc_attribute = {'type': 'email-dst', 'object_relation': 'bcc'}
    __bcc_display_name_attribute = {'type': 'email-dst-display-name', 'object_relation': 'bcc-display-name'}
    __bio_attribute = {'type': 'text', 'object_relation': 'bio'}
    __byte_count_attribute = {'type': 'counter', 'object_relation': 'byte-count'}
    __cc_attribute = {'type': 'email-dst', 'object_relation': 'cc'}
    __cc_display_name_attribute = {'type': 'email-dst-display-name', 'object_relation': 'cc-display-name'}
    __certificate_attribute = {'type': 'x509-fingerprint-sha1', 'object_relation': 'certificate'}
    __comment_text_attribute = {'type': 'text', 'object_relation': 'comment'}
    __community_id_attribute = {'type': 'community-id', 'object_relation': 'community-id'}
    __compilation_timestamp_attribute = {'type': 'datetime', 'object_relation': 'compilation-timestamp'}
    __direction_attribute = {'type': 'text', 'object_relation': 'direction'}
    __email_attachment_attribute = {'type': 'email-attachment', 'object_relation': 'attachment'}
    __email_header_attribute = {'type': 'email-header', 'object_relation': 'header'}
    __eml_attribute = {'type': 'attachment', 'object_relation': 'eml'}
    __employee_type_attribute = {'type': 'text', 'object_relation': 'employee-type'}
    __fake_process_name_attribute = {'type': 'boolean', 'object_relation': 'fake-process-name'}
    __first_seen_attribute = {'type': 'datetime', 'object_relation': 'first-seen'}
    __flow_count_attribute = {'type': 'counter', 'object_relation': 'flow-count'}
    __followers_attribute = {'type': 'text', 'object_relation': 'followers'}
    __following_attribute = {'type': 'text', 'object_relation': 'following'}
    __format_attribute = {'type': 'text', 'object_relation': 'format'}
    __fullpath_attribute = {'type': 'text', 'object_relation': 'fullpath'}
    __from_attribute = {'type': 'email-src', 'object_relation': 'from'}
    __from_display_name_attribute = {'type': 'email-src-display-name', 'object_relation': 'from-display-name'}
    __from_domain_attribute = {'type': 'domain', 'object_relation': 'from-domain'}
    __guid_attribute = {'type': 'text', 'object_relation': 'guid'}
    __header_attribute = {'type': 'text', 'object_relation': 'header'}
    __hostname_attribute = {'type': 'hostname', 'object_relation': 'hostname'}
    __id_attribute = {'type': 'text', 'object_relation': 'id'}
    __image_attribute = {'type': 'filename', 'object_relation': 'image'}
    __image_text_attribute = {'type': 'text', 'object_relation': 'image-text'}
    __integrity_level_attribute = {'type': 'text', 'object_relation': 'integrity-level'}
    __ip_protocol_number_attribute = {'type': '', 'object_relation': 'ip-protocol-number'}
    __ip_source_attribute = {'type': 'ip-src', 'object_relation': 'ip-src'}
    __ip_version_attribute = {'type': 'counter', 'object_relation': 'ip_version'}
    __is_ca_attribute = {'type': 'boolean', 'object_relation': 'is_ca'}
    __likes_attribute = {'type': 'text', 'object_relation': 'likes'}
    __last_seen_attribute = {'type': 'datetime', 'object_relation': 'last-seen'}
    __link_attribute = {'type': 'link', 'object_relation': 'link'}
    __lnk_access_time_attribute = {'type': 'datetime', 'object_relation': 'lnk-access-time'}
    __lnk_creation_time_attribute = {'type': 'datetime', 'object_relation': 'lnk-creation-time'}
    __lnk_modification_time_attribute = {'type': 'datetime', 'object_relation': 'lnk-modification-time'}
    __mime_boundary_attribute = {'type': 'email-mime-boundary', 'object_relation': 'mime-boundary'}
    __msg_attribute = {'type': 'attachment', 'object_relation': 'msg'}
    __packet_count_attribute = {'type': 'counter', 'object_relation': 'packet-count'}
    __parent_command_line_attribute = {'type': 'text', 'object_relation': 'parent-command-line'}
    __parent_guid_attribute = {'type': 'text', 'object_relation': 'parent-guid'}
    __parent_image_attribute = {'type': 'filename', 'object_relation': 'parent-image'}
    __parent_pid_attribute = {'type': 'text', 'object_relation': 'parent-pid'}
    __parent_process_name_attribute = {'type': 'text', 'object_relation': 'parent-process-name'}
    __parent_process_path_attribute = {'type': 'text', 'object_relation': 'parent-process-path'}
    __pattern_in_file_attribute = {'type': 'pattern-in-file', 'object_relation': 'pattern-in-file'}
    __pem_attribute = {'type': 'text', 'object_relation': 'pem'}
    __pgid_attribute = {'type': 'text', 'object_relation': 'pgid'}
    __port_attribute = {'type': 'port', 'object_relation': 'port'}
    __process_state_attribute = {'type': 'process-state', 'object_relation': 'process-state'}
    __proxy_password_attribute = {'type': 'text', 'object_relation': 'proxy-password'}
    __proxy_user_attribute = {'type': 'text', 'object_relation': 'proxy-user'}
    __pubkey_info_size_attribute = {'type': 'text', 'object_relation': 'pubkey-info-size'}
    __raw_base64_attribute = {'type': 'text', 'object_relation': 'raw-base64'}
    __received_hostname_attribute = {'type': 'hostname', 'object_relation': 'received-header-hostname'}
    __received_ip_attribute = {'type': 'ip-src', 'object_relation': 'received-header-ip'}
    __reply_to_display_name_attribute = {'type': 'email-dst-display-name', 'object_relation': 'reply-to-display-name'}
    __return_path_attribute = {'type': 'email-src', 'object_relation': 'return-path'}
    __role_attribute = {'type': 'text', 'object_relation': 'role'}
    __screenshot_attribute = {'type': 'attachment', 'object_relation': 'screenshot'}
    __script_attribute = {'type': 'text', 'object_relation': 'script'}
    __sha224_attribute = {'type': 'sha224', 'object_relation': 'sha224'}
    __sha3_224_attribute = {'type': 'sha3-224', 'object_relation': 'sha3-224'}
    __sha3_384_attribute = {'type': 'sha3-384', 'object_relation': 'sha3-384'}
    __sha384_attribute = {'type': 'sha384', 'object_relation': 'sha384'}
    __state_attribute = {'type': 'text', 'object_relation': 'state'}
    __start_time_attribute = {'type': 'datetime', 'object_relation': 'start-time'}
    __telfhash_attribute = {'type': 'telfhash', 'object_relation': 'telfhash'}
    __text_attribute = {'type': 'text', 'object_relation': 'text'}
    __thread_index_attribute = {'type': 'email-thread-index', 'object_relation': 'thread-index'}
    __to_attribute = {'type': 'email-dst', 'object_relation': 'to'}
    __to_display_name_attribute = {'type': 'email-dst-display-name', 'object_relation': 'to-display-name'}
    __user_avatar_attribute = {'type': 'attachment', 'object_relation': 'user-avatar'}
    __user_creator_attribute = {'type': 'text', 'object_relation': 'user-creator'}
    __user_process_attribute = {'type': 'text', 'object_relation': 'user-process'}
    __verified_attribute = {'type': 'text', 'object_relation': 'verified'}
    __vhash_attribute = {'type': 'vhash', 'object_relation': 'vhash'}

    # STIX TO MISP OBJECTS MAPPING
    __android_app_object_mapping = Mapping(
        name=STIX2toMISPMapping.name_attribute(),
        x_misp_appid={'type': 'text', 'object_relation': 'appid'},
        x_misp_certificate={'type': 'sha1', 'object_relation': 'certificate'},
        x_misp_domain=STIX2toMISPMapping.domain_attribute(),
        x_misp_sha256=STIX2toMISPMapping.sha256_attribute()
    )
    __annotation_object_mapping = Mapping(
        content=__text_attribute,
        x_misp_attachment=__attachment_attribute,
        x_misp_creation_date={'type': 'datetime', 'object_relation': 'creation-date'},
        x_misp_format=__format_attribute,
        x_misp_modification_data={'type': 'datetime', 'object_relation': 'modification-date'},
        x_misp_ref={'type': 'link', 'object_relation': 'ref'},
        x_misp_type=STIX2toMISPMapping.type_attribute()
    )
    __asn_object_mapping = Mapping(
        number=STIX2toMISPMapping.asn_attribute(),
        name=STIX2toMISPMapping.description_attribute(),
        x_misp_country={'type': 'text', 'object_relation': 'country'},
        x_misp_export={'type': 'text', 'object_relation': 'export'},
        x_misp_first_seen=__first_seen_attribute,
        x_misp_import={'type': 'text', 'object_relation': 'import'},
        x_misp_last_seen=__last_seen_attribute,
        x_misp_mp_export={'type': 'text', 'object_relation': 'mp-export'},
        x_misp_mp_import={'type': 'text', 'object_relation': 'mp-import'},
        x_misp_subnet_announced={'type': 'ip-src', 'object_relation': 'subnet-announced'}
    )
    __course_of_action_object_mapping = Mapping(
        name=STIX2toMISPMapping.name_attribute(),
        description=STIX2toMISPMapping.description_attribute(),
        x_misp_cost={'type': 'text', 'object_relation': 'cost'},
        x_misp_efficacy={'type': 'text', 'object_relation': 'efficacy'},
        x_misp_impact={'type': 'text', 'object_relation': 'impact'},
        x_misp_objective={'type': 'text', 'object_relation': 'objective'},
        x_misp_stage={'type': 'text', 'object_relation': 'stage'},
        x_misp_type=STIX2toMISPMapping.type_attribute()
    )
    __cpe_asset_object_mapping = Mapping(
        cpe=STIX2toMISPMapping.cpe_attribute(),
        languages=STIX2toMISPMapping.language_attribute(),
        name={'type': 'text', 'object_relation': 'product'},
        vendor=STIX2toMISPMapping.vendor_attribute(),
        version=STIX2toMISPMapping.version_attribute(),
        x_misp_description=STIX2toMISPMapping.description_attribute(),
        x_misp_other={'type': 'text', 'object_relation': 'other'},
        x_misp_part={'type': 'text', 'object_relation': 'part'},
        x_misp_product={'type': 'text', 'object_relation': 'product'},
        x_misp_sw_edition={'type': 'text', 'object_relation': 'sw_edition'},
        x_misp_target_hw={'type': 'text', 'object_relation': 'target_hw'},
        x_misp_target_sw={'type': 'text', 'object_relation': 'target_sw'},
        x_misp_update={'type': 'text', 'object_relation': 'update'}
    )
    __credential_object_mapping = Mapping(
        user_id=STIX2toMISPMapping.username_attribute(),
        credential=STIX2toMISPMapping.password_attribute(),
        x_misp_password=STIX2toMISPMapping.password_attribute(),
        x_misp_format=__format_attribute,
        x_misp_notification={'type': 'text', 'object_relation': 'notification'},
        x_misp_origin={'type': 'text', 'object_relation': 'origin'},
        x_misp_text=__text_attribute,
        x_misp_type=STIX2toMISPMapping.type_attribute()
    )
    __domain_ip_object_mapping = Mapping(
        value=STIX2toMISPMapping.domain_attribute(),
        x_misp_first_seen=__first_seen_attribute,
        x_misp_hostname=__hostname_attribute,
        x_misp_last_seen=__last_seen_attribute,
        x_misp_port=__port_attribute,
        x_misp_registration_date={'type': 'datetime', 'object_relation': 'registration-date'},
        x_misp_text=__text_attribute
    )
    __email_object_mapping = Mapping(
        body=STIX2toMISPMapping.email_body_attribute(),
        date=STIX2toMISPMapping.send_date_attribute(),
        message_id=STIX2toMISPMapping.message_id_attribute(),
        subject=STIX2toMISPMapping.email_subject_attribute(),
        x_misp_attachment=__email_attachment_attribute,
        x_misp_from_domain=__from_domain_attribute,
        x_misp_ip_src=__ip_source_attribute,
        x_misp_message_id=STIX2toMISPMapping.message_id_attribute(),
        x_misp_mime_boundary=__mime_boundary_attribute,
        x_misp_received_header_hostname=__received_hostname_attribute,
        x_misp_received_header_ip=__received_ip_attribute,
        x_misp_reply_to_display_name=__reply_to_display_name_attribute,
        x_misp_return_path=__return_path_attribute,
        x_misp_screenshot=__screenshot_attribute,
        x_misp_thread_index=__thread_index_attribute,
        x_misp_user_agent=STIX2toMISPMapping.user_agent_attribute()
    )
    __email_pattern_mapping = Mapping(
        **{
            'additional_header_fields.reply_to': STIX2toMISPMapping.reply_to_attribute(),
            'additional_header_fields.x_mailer': STIX2toMISPMapping.x_mailer_attribute(),
            'bcc_refs': {
                'display_name': __bcc_display_name_attribute,
                'value': __bcc_attribute
            },
            'cc_refs': {
                'display_name': __cc_display_name_attribute,
                'value': __cc_attribute
            },
            'from_ref.display_name': __from_display_name_attribute,
            'from_ref.value': __from_attribute,
            'to_refs': {
                'display_name': __to_display_name_attribute,
                'value': __to_attribute
            },
            **__email_object_mapping
        }
    )
    __facebook_account_object_mapping = Mapping(
        user_id=__account_id_attribute,
        account_login=__account_name_attribute,
        x_misp_archive=__archive_attribute,
        x_misp_attachment=__attachment_attribute,
        x_misp_description=STIX2toMISPMapping.description_attribute(),
        x_misp_link=__link_attribute,
        x_misp_url=STIX2toMISPMapping.url_attribute(),
        x_misp_user_avatar=__user_avatar_attribute
    )
    __file_hashes_mapping = Mapping(
        **{
            'AUTHENTIHASH': __authentihash_attribute,
            'IMPHASH': STIX2toMISPMapping.imphash_attribute(),
            'MD5': STIX2toMISPMapping.md5_attribute(),
            'SHA1': STIX2toMISPMapping.sha1_attribute(),
            'SHA-1': STIX2toMISPMapping.sha1_attribute(),
            'SHA224': __sha224_attribute,
            'SHA256': STIX2toMISPMapping.sha256_attribute(),
            'SHA-256': STIX2toMISPMapping.sha256_attribute(),
            'SHA3224': __sha3_224_attribute,
            'SHA3-256': STIX2toMISPMapping.sha3_256_attribute(),
            'SHA3384': __sha3_384_attribute,
            'SHA3-512': STIX2toMISPMapping.sha3_512_attribute(),
            'SHA384': __sha384_attribute,
            'SHA512': STIX2toMISPMapping.sha512_attribute(),
            'SHA-512': STIX2toMISPMapping.sha512_attribute(),
            'ssdeep': STIX2toMISPMapping.ssdeep_attribute(),
            'SSDEEP': STIX2toMISPMapping.ssdeep_attribute(),
            'TELFHASH': __telfhash_attribute,
            'TLSH': STIX2toMISPMapping.tlsh_attribute(),
            'VHASH': __vhash_attribute
        }
    )
    __file_object_mapping = Mapping(
        accessed=STIX2toMISPMapping.access_time_attribute(),
        atime=STIX2toMISPMapping.access_time_attribute(),
        created=STIX2toMISPMapping.creation_time_attribute(),
        ctime=STIX2toMISPMapping.creation_time_attribute(),
        mime_type=STIX2toMISPMapping.mime_type_attribute(),
        modified=STIX2toMISPMapping.modification_time_attribute(),
        mtime=STIX2toMISPMapping.modification_time_attribute(),
        name=STIX2toMISPMapping.filename_attribute(),
        name_enc=STIX2toMISPMapping.file_encoding_attribute(),
        size=STIX2toMISPMapping.size_in_bytes_attribute(),
        x_misp_attachment=__attachment_attribute,
        x_misp_certificate=__certificate_attribute,
        x_misp_compilation_timestamp=__compilation_timestamp_attribute,
        x_misp_entropy=STIX2toMISPMapping.entropy_attribute(),
        x_misp_fullpath=__fullpath_attribute,
        x_misp_path=STIX2toMISPMapping.path_attribute(),
        x_misp_pattern_in_file=__pattern_in_file_attribute,
        x_misp_state=__state_attribute,
        x_misp_text=__text_attribute
    )
    __file_pattern_mapping = Mapping(
        **{
            'hashes.AUTHENTIHASH': __authentihash_attribute,
            'hashes.IMPHASH': STIX2toMISPMapping.imphash_attribute(),
            'hashes.MD5': STIX2toMISPMapping.md5_attribute(),
            'hashes.SHA1': STIX2toMISPMapping.sha1_attribute(),
            'hashes.SHA224': __sha224_attribute,
            'hashes.SHA256': STIX2toMISPMapping.sha256_attribute(),
            'hashes.SHA3224': __sha3_224_attribute,
            'hashes.SHA3256': STIX2toMISPMapping.sha3_256_attribute(),
            'hashes.SHA3384': __sha3_384_attribute,
            'hashes.SHA3512': STIX2toMISPMapping.sha3_512_attribute(),
            'hashes.SHA384': __sha384_attribute,
            'hashes.SHA512': STIX2toMISPMapping.sha512_attribute(),
            'hashes.SSDEEP': STIX2toMISPMapping.ssdeep_attribute(),
            'hashes.TELFHASH': __telfhash_attribute,
            'hashes.TLSH': STIX2toMISPMapping.tlsh_attribute(),
            'hashes.VHASH': __vhash_attribute,
            'mime_type': STIX2toMISPMapping.mime_type_attribute(),
            'name': STIX2toMISPMapping.filename_attribute(),
            'name_enc': STIX2toMISPMapping.file_encoding_attribute(),
            'parent_directory_ref.path': STIX2toMISPMapping.path_attribute(),
            'size': STIX2toMISPMapping.size_in_bytes_attribute(),
            'x_misp_certificate': __certificate_attribute,
            'x_misp_compilation_timestamp': __compilation_timestamp_attribute,
            'x_misp_entropy': STIX2toMISPMapping.entropy_attribute(),
            'x_misp_fullpath': __fullpath_attribute,
            'x_misp_path': STIX2toMISPMapping.path_attribute(),
            'x_misp_pattern_in_file': __pattern_in_file_attribute,
            'x_misp_state': __state_attribute,
            'x_misp_text': __text_attribute
        }
    )
    __github_user_object_mapping = Mapping(
        user_id=__id_attribute,
        account_login={'type': 'github-username', 'object_relation': 'username'},
        display_name={'type': 'text', 'object_relation': 'user-fullname'},
        x_misp_avatar_url={'type': 'link', 'object_relation': 'avatar_url'},
        x_misp_bio=__bio_attribute,
        x_misp_blog={'type': 'text', 'object_relation': 'blog'},
        x_misp_company={'type': 'text', 'object_relation': 'company'},
        x_misp_follower={'type': 'github-username', 'object_relation': 'follower'},
        x_misp_following={'type': 'github-username', 'object_relation': 'following'},
        x_misp_link=__link_attribute,
        x_misp_location={'type': 'text', 'object_relation': 'location'},
        x_misp_node_id={'type': 'text', 'object_relation': 'node_id'},
        x_misp_organisation={'type': 'github-organisation', 'object_relation': 'organisation'},
        x_misp_profile_image={'type': 'attachment', 'object_relation': 'profile-image'},
        x_misp_public_gists={'type': 'text', 'object_relation': 'public_gists'},
        x_misp_public_repos={'type': 'text', 'object_relation': 'public_repos'},
        x_misp_repository={'type': 'github-repository', 'object_relation': 'repository'},
        x_misp_twitter_username={'type': 'text', 'object_relation': 'twitter_username'},
        x_misp_verified=__verified_attribute
    )
    __gitlab_user_object_mapping = Mapping(
        user_id=__id_attribute,
        display_name=STIX2toMISPMapping.name_attribute(),
        account_login=STIX2toMISPMapping.username_attribute(),
        x_misp_avatar_url={'type': 'link', 'object_relation': 'avatar_url'},
        x_misp_state={'type': 'text', 'object_relation': 'state'},
        x_misp_web_url={'type': 'link', 'object_relation': 'web_url'}
    )
    __http_request_extension_mapping = Mapping(
        request_method=STIX2toMISPMapping.method_attribute(),
        request_value=STIX2toMISPMapping.uri_attribute()
    )
    __http_request_header_mapping = Mapping(
        **{
            'Content-Type': STIX2toMISPMapping.content_type_attribute(),
            'Cookie': STIX2toMISPMapping.cookie_attribute(),
            'Referer': STIX2toMISPMapping.referer_attribute(),
            'User-Agent': STIX2toMISPMapping.user_agent_attribute()
        }
    )
    __http_ext = "extensions.'http-request-ext'"
    __http_request_object_mapping = Mapping(
        x_misp_basicauth_password=__basicauth_password_attribute,
        x_misp_basicauth_user=__basicauth_user_attribute,
        x_misp_header=__header_attribute,
        x_misp_proxy_password=__proxy_password_attribute,
        x_misp_proxy_user=__proxy_user_attribute,
        x_misp_text=__text_attribute,
        x_misp_url=STIX2toMISPMapping.url_attribute()
    )
    __http_request_pattern_mapping = Mapping(
        **{
            f"{__http_ext}.request_method": STIX2toMISPMapping.method_attribute(),
            f"{__http_ext}.request_header.'Content-Type'": STIX2toMISPMapping.content_type_attribute(),
            f"{__http_ext}.request_header.'Cookie'": STIX2toMISPMapping.cookie_attribute(),
            f"{__http_ext}.request_header.'Referer'": STIX2toMISPMapping.referer_attribute(),
            f"{__http_ext}.request_header.'User-Agent'": STIX2toMISPMapping.user_agent_attribute(),
            'x_misp_basicauth_password': __basicauth_password_attribute,
            'x_misp_basicauth_user': __basicauth_user_attribute,
            'x_misp_header': __header_attribute,
            'x_misp_proxy_password': __proxy_password_attribute,
            'x_misp_proxy_user': __proxy_user_attribute,
            'x_misp_text': __text_attribute,
        }
    )
    __image_object_mapping = Mapping(
        name=STIX2toMISPMapping.filename_attribute(),
        x_misp_archive=__archive_attribute,
        x_misp_image_text=__image_text_attribute,
        x_misp_link=__link_attribute,
        x_misp_username=STIX2toMISPMapping.username_attribute()
    )
    __image_pattern_mapping = Mapping(
        **{
            'content_ref.url': STIX2toMISPMapping.url_attribute(),
            'content_ref.x_misp_url': STIX2toMISPMapping.url_attribute(),
            **__image_object_mapping
        }
    )
    __ip_port_object_mapping = Mapping(
        dst_port=STIX2toMISPMapping.dst_port_attribute(),
        src_port=STIX2toMISPMapping.src_port_attribute(),
        start=__first_seen_attribute,
        end=__last_seen_attribute,
        x_misp_AS={'type': 'AS', 'object_relation': 'AS'},
        x_misp_country_code={'type': 'text', 'object_relation': 'country-code'},
        x_misp_domain=STIX2toMISPMapping.domain_attribute(),
        x_misp_hostname=__hostname_attribute,
        x_misp_ip=STIX2toMISPMapping.ip_attribute(),
        x_misp_text=__text_attribute
    )
    __lnk_object_mapping = Mapping(
        name=STIX2toMISPMapping.filename_attribute(),
        accessed=__lnk_access_time_attribute,
        atime=__lnk_access_time_attribute,
        created=__lnk_creation_time_attribute,
        ctime=__lnk_creation_time_attribute,
        modified=__lnk_modification_time_attribute,
        mtime=__lnk_modification_time_attribute,
        size=STIX2toMISPMapping.size_in_bytes_attribute(),
        x_misp_fullpath=__fullpath_attribute,
        x_misp_path=STIX2toMISPMapping.path_attribute(),
        x_misp_birth_droid_file_identifier={'type': 'text', 'object_relation': 'birth-droid-file-identifier'},
        x_misp_birth_droid_volume_identifier={'type': 'text', 'object_relation': 'birth-droid-volume-identifier'},
        x_misp_droid_file_identifier={'type': 'text', 'object_relation': 'droid-file-identifier'},
        x_misp_droid_volume_identifier={'type': 'text', 'object_relation': 'droid-volume-identifier'},
        x_misp_entropy=STIX2toMISPMapping.entropy_attribute(),
        x_misp_lnk_command_line_arguments={'type': 'text', 'object_relation': 'lnk-command-line-arguments'},
        x_misp_lnk_description={'type': 'text', 'object_relation': 'lnk-description'},
        x_misp_lnk_drive_serial_number={'type': 'text', 'object_relation': 'lnk-drive-serial-number'},
        x_misp_lnk_drive_type={'type': 'text', 'object_relation': 'lnk-drive-type'},
        x_misp_lnk_file_attribute_flags={'type': 'text', 'object_relation': 'lnk-file-attribute-flags'},
        x_misp_lnk_file_size={'type': 'size-in-bytes', 'object_relation': 'lnk-file-size'},
        x_misp_lnk_hot_key_value={'type': 'text', 'object_relation': 'lnk-hot-key-value'},
        x_misp_lnk_icon_text={'type': 'text', 'object_relation': 'lnk-icon-text'},
        x_misp_lnk_local_path={'type': 'text', 'object_relation': 'lnk-local-path'},
        x_misp_lnk_relative_path={'type': 'text', 'object_relation': 'lnk-relative-path'},
        x_misp_lnk_show_window_value={'type': 'text', 'object_relation': 'lnk-show-window-value'},
        x_misp_lnk_volume_label={'type': 'text', 'object_relation': 'lnk-volume-label'},
        x_misp_lnk_working_directory={'type': 'text', 'object_relation': 'lnk-working-directory'},
        x_misp_machine_identifier={'type': 'text', 'object_relation': 'machine-identifier'},
        x_misp_pattern_in_file=__pattern_in_file_attribute,
        x_misp_state=__state_attribute,
        x_misp_text=__text_attribute
    )
    __lnk_pattern_mapping = Mapping(
        **{
            'hashes.MD5': STIX2toMISPMapping.md5_attribute(),
            'hashes.SHA1': STIX2toMISPMapping.sha1_attribute(),
            'hashes.SHA224': __sha224_attribute,
            'hashes.SHA256': STIX2toMISPMapping.sha256_attribute(),
            'hashes.SHA384': __sha384_attribute,
            'hashes.SHA512': STIX2toMISPMapping.sha512_attribute(),
            'hashes.SSDEEP': STIX2toMISPMapping.ssdeep_attribute(),
            'hashes.TLSH': STIX2toMISPMapping.tlsh_attribute(),
            'parent_directory_ref.path': STIX2toMISPMapping.path_attribute(),
            **__lnk_object_mapping
        }
    )
    __mutex_object_mapping = Mapping(
        name=STIX2toMISPMapping.name_attribute(),
        x_misp_description=STIX2toMISPMapping.description_attribute(),
        x_misp_operating_system={
            'type': 'text', 'object_relation': 'operating-system'
        }
    )
    __netflow_object_mapping = Mapping(
        dst_port=STIX2toMISPMapping.dst_port_attribute(),
        src_port=STIX2toMISPMapping.src_port_attribute(),
        start=STIX2toMISPMapping.first_packet_seen_attribute(),
        end=STIX2toMISPMapping.last_packet_seen_attribute(),
        src_byte_count=__byte_count_attribute,
        src_packets=__packet_count_attribute,
        x_misp_community_id=__community_id_attribute,
        x_misp_direction=__direction_attribute,
        x_misp_flow_count=__flow_count_attribute,
        x_misp_ip_protocol_number=__ip_protocol_number_attribute,
        x_misp_ip_version=__ip_version_attribute
    )
    __netflow_pattern_mapping = Mapping(
        **{
            'protocols[0]': __protocol_attribute,
            "extensions.'icmp-ext'.icmp_type_hex": __icmp_type_attribute,
            "extensions.'tcp-ext'.src_flags_hex": __tcp_flags_attribute,
            **__netflow_object_mapping
        }
    )
    __network_connection_object_mapping = Mapping(
        dst_port=STIX2toMISPMapping.dst_port_attribute(),
        src_port=STIX2toMISPMapping.src_port_attribute(),
        start=STIX2toMISPMapping.first_packet_seen_attribute(),
        x_misp_community_id=__community_id_attribute,
        x_misp_hostname_dst=__hostname_dst_attribute,
        x_misp_hostname_src=__hostname_src_attribute
    )
    __network_socket_object_mapping = Mapping(
        dst_port=STIX2toMISPMapping.dst_port_attribute(),
        src_port=STIX2toMISPMapping.src_port_attribute(),
        x_misp_address_family=STIX2toMISPMapping.address_family_attribute(),
        x_misp_domain_family=STIX2toMISPMapping.domain_family_attribute(),
        x_misp_filename=STIX2toMISPMapping.filename_attribute(),
        x_misp_hostname_dst=__hostname_dst_attribute,
        x_misp_hostname_src=__hostname_src_attribute,
        x_misp_option={'type': 'text', 'object_relation': 'option'}
    )
    __parent_process_object_mapping = Mapping(
        command_line=__parent_command_line_attribute,
        name=__parent_process_name_attribute,
        x_misp_process_name=__parent_process_name_attribute,
        pid=__parent_pid_attribute,
        x_misp_guid=__parent_guid_attribute,
        x_misp_process_path=__parent_process_path_attribute
    )
    __parler_account_object_mapping = Mapping(
        user_id=__account_id_attribute,
        account_login=__account_name_attribute,
        x_misp_archive=__archive_attribute,
        x_misp_attachment=__attachment_attribute,
        x_misp_badge={'type': 'link', 'object_relation': 'badge'},
        x_misp_bio=__bio_attribute,
        x_misp_comments={'type': 'text', 'object_relation': 'comments'},
        x_misp_cover_photo={'type': 'attachment', 'object_relation': 'cover-photo'},
        x_misp_followers=__followers_attribute,
        x_misp_following=__following_attribute,
        x_misp_human={'type': 'boolean', 'object_relation': 'human'},
        x_misp_interactions={'type': 'float', 'object_relation': 'interactions'},
        x_misp_likes=__likes_attribute,
        x_misp_link=__link_attribute,
        x_misp_posts={'type': 'text', 'object_relation': 'posts'},
        x_misp_profile_photo={'type': 'attachment', 'object_relation': 'profile-photo'},
        x_misp_url=STIX2toMISPMapping.url_attribute(),
        x_misp_verified={'type': 'boolean', 'object_relation': 'verified'},
    )
    __pe_object_mapping = Mapping(
        imphash=STIX2toMISPMapping.imphash_attribute(),
        number_of_sections=STIX2toMISPMapping.number_of_sections_attribute(),
        pe_type=STIX2toMISPMapping.type_attribute(),
        x_misp_authentihash=__authentihash_attribute,
        x_misp_company_name={'type': 'text', 'object_relation': 'company-name'},
        x_misp_compilation_timestamp=__compilation_timestamp_attribute,
        x_misp_entrypoint_section_at_position={
            'type': 'text',
            'object_relation': 'entrypoint-section-at-position'
        },
        x_misp_file_description={'type': 'text', 'object_relation': 'file-description'},
        x_misp_file_version={'type': 'text', 'object_relation': 'file-version'},
        x_misp_impfuzzy={'type': 'impfuzzy', 'object_relation': 'impfuzzy'},
        x_misp_internal_filename={'type': 'filename', 'object_relation': 'internal-filename'},
        x_misp_lang_id={'type': 'text', 'object_relation': 'lang-id'},
        x_misp_legal_copyright={'type': 'text', 'object_relation': 'legal-copyright'},
        x_misp_original_filename={'type': 'filename', 'object_relation': 'original-filename'},
        x_misp_pehash={'type': 'pehash', 'object_relation': 'pehash'},
        x_misp_product_name={'type': 'text', 'object_relation': 'product-name'},
        x_misp_product_version={'type': 'text', 'object_relation': 'product-version'},
        x_misp_richpe={'type': 'md5', 'object_relation': 'richpe'},
        x_misp_text=__text_attribute
    )
    __pe_section_object_mapping = Mapping(
        entropy=STIX2toMISPMapping.entropy_attribute(),
        name=STIX2toMISPMapping.name_attribute(),
        size=STIX2toMISPMapping.size_in_bytes_attribute(),
        x_misp_characteristic={'type': 'text', 'object_relation': 'characteristic'},
        x_misp_offset={'type': 'hex', 'object_relation': 'offset'},
        x_misp_text=__text_attribute,
        x_misp_virtual_address={'type': 'hex', 'object_relation': 'virtual_address'},
        x_misp_virtual_size={'type': 'size-in-bytes', 'object_relation': 'virtual_size'}
    )
    __process_object_mapping = Mapping(
        arguments=STIX2toMISPMapping.args_attribute(),
        x_misp_args=STIX2toMISPMapping.args_attribute(),
        command_line=STIX2toMISPMapping.command_line_attribute(),
        created=STIX2toMISPMapping.creation_time_attribute(),
        created_time=STIX2toMISPMapping.creation_time_attribute(),
        cwd=STIX2toMISPMapping.current_directory_attribute(),
        is_hidden=STIX2toMISPMapping.hidden_attribute(),
        name=STIX2toMISPMapping.name_attribute(),
        x_misp_name=STIX2toMISPMapping.name_attribute(),
        pid=STIX2toMISPMapping.pid_attribute(),
        x_misp_fake_process_name=__fake_process_name_attribute,
        x_misp_guid=__guid_attribute,
        x_misp_integrity_level=__integrity_level_attribute,
        x_misp_pgid=__pgid_attribute,
        x_misp_port=__port_attribute,
        x_misp_process_state=__process_state_attribute,
        x_misp_start_time=__start_time_attribute,
        x_misp_user_creator=__user_creator_attribute,
        x_misp_user_process=__user_process_attribute
    )
    __process_pattern_mapping = Mapping(
        **{
            'binary_ref.name': __image_attribute,
            'image_ref.name': __image_attribute,
            'parent_ref.command_line': __parent_command_line_attribute,
            'parent_ref.name': __parent_process_name_attribute,
            'parent_ref.pid': __parent_pid_attribute,
            'parent_ref.binary_ref.name': __parent_image_attribute,
            'parent_ref.image_ref.name': __parent_image_attribute,
            'parent_ref.x_misp_guid': __parent_guid_attribute,
            'parent_ref.x_misp_process_name': __parent_process_name_attribute,
            'parent_ref.x_misp_process_path': __parent_process_path_attribute,
            **__process_object_mapping
        }
    )
    __reddit_account_object_mapping = Mapping(
        user_id=__account_id_attribute,
        account_login=__account_name_attribute,
        x_misp_account_avatar={'type': 'attachment', 'object_relation': 'account-avatar'},
        x_misp_account_avatar_url={'type': 'url', 'object_relation': 'account-avatar-url'},
        x_misp_archive=__archive_attribute,
        x_misp_attachment=__attachment_attribute,
        x_misp_description=STIX2toMISPMapping.description_attribute(),
        x_misp_link=__link_attribute,
        x_misp_moderator_of={'type': '', 'object_relation': 'moderator-of'},
        x_misp_trophies={'type': '', 'object_relation': 'trophies'},
        x_misp_url=STIX2toMISPMapping.url_attribute()
    )
    __registry_key_object_mapping = Mapping(
        key=STIX2toMISPMapping.regkey_attribute(),
        modified=STIX2toMISPMapping.last_modified_attribute(),
        modified_time=STIX2toMISPMapping.last_modified_attribute(),
        x_misp_hive={'type': 'text', 'object_relation': 'hive'},
        x_misp_root_keys={'type': 'text', 'object_relation': 'root-keys'}
    )
    __sigma_object_mapping = Mapping(
        pattern=STIX2toMISPMapping.sigma_attribute(),
        description=STIX2toMISPMapping.comment_attribute(),
        name=STIX2toMISPMapping.sigma_rule_name_attribute(),
        x_misp_context={'type': 'text', 'object_relation': 'context'}
    )
    __telegram_account_object_mapping = Mapping(
        user_id=__id_attribute,
        account_login=STIX2toMISPMapping.username_attribute(),
        x_misp_first_name={'type': 'text', 'object_relation': 'first_name'},
        x_misp_last_name={'type': 'text', 'object_relation': 'last_name'},
        x_misp_phone={'type': 'text', 'object_relation': 'phone'},
        x_misp_verified={'type': 'text', 'object_relation': 'verified'}
    )
    __twitter_account_object_mapping = Mapping(
        user_id=__id_attribute,
        account_login=STIX2toMISPMapping.name_attribute(),
        display_name={'type': 'text', 'object_relation': 'displayed-name'},
        x_misp_archive=__archive_attribute,
        x_misp_attachment=__attachment_attribute,
        x_misp_bio=__bio_attribute,
        x_misp_description=STIX2toMISPMapping.description_attribute(),
        x_misp_embedded_link={'type': 'url', 'object_relation': 'embedded-link'},
        x_misp_embedded_safe_link={'type': 'link', 'object_relation': 'embedded-safe-link'},
        x_misp_followers=__followers_attribute,
        x_misp_following=__following_attribute,
        x_misp_hashtag={'type': 'text', 'object_relation': 'hashtag'},
        x_misp_joined_date={'type': 'text', 'object_relation': 'joined-date'},
        x_misp_likes=__likes_attribute,
        x_misp_link=__link_attribute,
        x_misp_listed={'type': 'text', 'object_relation': 'listed'},
        x_misp_location={'type': 'text', 'object_relation': 'location'},
        x_misp_media={'type': 'text', 'object_relation': 'media'},
        x_misp_private={'type': 'text', 'object_relation': 'private'},
        x_misp_profile_banner={'type': 'attachment', 'object_relation': 'profile-banner'},
        x_misp_profile_banner_url={'type': 'url', 'object_relation': 'profile-banner-url'},
        x_misp_profile_image={'type': 'attachment', 'object_relation': 'profile-image'},
        x_misp_profile_image_url={'type': 'url', 'object_relation': 'profile-image-url'},
        x_misp_tweets={'type': 'text', 'object_relation': 'tweets'},
        x_misp_twitter_followers={'type': 'text', 'object_relation': 'twitter-followers'},
        x_misp_twitter_following={'type': 'text', 'object_relation': 'twitter-following'},
        x_misp_url=STIX2toMISPMapping.url_attribute(),
        x_misp_verified=__verified_attribute
    )
    __url_object_mapping = Mapping(
        value=STIX2toMISPMapping.url_attribute(),
        x_misp_credential={'type': 'text', 'object_relation': 'credential'},
        x_misp_domain=STIX2toMISPMapping.domain_attribute(),
        x_misp_domain_without_tld={'type': 'text', 'object_relation': 'domain_without_tld'},
        x_misp_first_seen=__first_seen_attribute,
        x_misp_fragment={'type': 'text', 'object_relation': 'fragment'},
        x_misp_host=__host_attribute,
        x_misp_ip=STIX2toMISPMapping.ip_attribute(),
        x_misp_last_seen=__last_seen_attribute,
        x_misp_port=__port_attribute,
        x_misp_query_string={'type': 'text', 'object_relation': 'query_string'},
        x_misp_resource_path={'type': 'text', 'object_relation': 'resource_path'},
        x_misp_scheme={'type': 'text', 'object_relation': 'scheme'},
        x_misp_subdomain={'type': 'text', 'object_relation': 'subdomain'},
        x_misp_text=__text_attribute,
        x_misp_tld={'type': 'text', 'object_relation': 'tld'}
    )
    __user_account_object_mapping = Mapping(
        account_login=STIX2toMISPMapping.username_attribute(),
        account_type=STIX2toMISPMapping.account_type_attribute(),
        can_escalate_privs=STIX2toMISPMapping.can_escalate_privs_attribute(),
        credential=STIX2toMISPMapping.password_attribute(),
        x_misp_password=STIX2toMISPMapping.password_attribute(),
        display_name=STIX2toMISPMapping.display_name_attribute(),
        is_disabled=STIX2toMISPMapping.disabled_attribute(),
        is_privileged=STIX2toMISPMapping.privileged_attribute(),
        is_service_account=STIX2toMISPMapping.is_service_account_attribute(),
        user_id=STIX2toMISPMapping.user_id_attribute(),
        x_misp_description=STIX2toMISPMapping.description_attribute(),
        x_misp_link=__link_attribute,
        x_misp_user_avatar=__user_avatar_attribute,
        account_created=STIX2toMISPMapping.created_attribute(),
        account_expires=STIX2toMISPMapping.expires_attribute(),
        account_first_login=STIX2toMISPMapping.first_login_attribute(),
        account_last_login=STIX2toMISPMapping.last_login_attribute(),
        credential_last_changed=STIX2toMISPMapping.password_last_changed_attribute(),
        password_last_changed=STIX2toMISPMapping.password_last_changed_attribute()
    )
    __x509_object_mapping = Mapping(
        is_self_signed=STIX2toMISPMapping.is_self_signed_attribute(),
        issuer=STIX2toMISPMapping.issuer_attribute(),
        serial_number=STIX2toMISPMapping.serial_number_attribute(),
        signature_algorithm=STIX2toMISPMapping.signature_algorithm_attribute(),
        subject=STIX2toMISPMapping.subject_attribute(),
        subject_public_key_algorithm=STIX2toMISPMapping.pubkey_info_algorithm_attribute(),
        subject_public_key_exponent=STIX2toMISPMapping.pubkey_info_exponent_attribute(),
        subject_public_key_modulus=STIX2toMISPMapping.pubkey_info_modulus_attribute(),
        validity_not_after=STIX2toMISPMapping.validity_not_after_attribute(),
        validity_not_before=STIX2toMISPMapping.validity_not_before_attribute(),
        version=STIX2toMISPMapping.version_attribute(),
        x_misp_is_ca=__is_ca_attribute,
        x_misp_pem=__pem_attribute,
        x_misp_pubkey_info_size=__pubkey_info_size_attribute,
        x_misp_raw_base64=__raw_base64_attribute,
        x_misp_text=__text_attribute
    )
    __x509_pattern_mapping = Mapping(
        **{
            'hashes.MD5': STIX2toMISPMapping.x509_md5_attribute(),
            'hashes.SHA1': STIX2toMISPMapping.x509_sha1_attribute(),
            'hashes.SHA256': STIX2toMISPMapping.x509_sha256_attribute(),
            **__x509_object_mapping
        }
    )
    __x509_subject_alternative_name_mapping = Mapping(
        **{
            'DNS name': {'type': 'hostname', 'object_relation': 'dns_names'},
            'email': {'type': 'email-dst', 'object_relation': 'email'},
            'IP': STIX2toMISPMapping.ip_attribute(),
            'RID': {'type': 'text', 'object_relation': 'rid'},
            'URI': STIX2toMISPMapping.uri_attribute()
        }
    )
    __yara_object_mapping = Mapping(
        pattern=STIX2toMISPMapping.yara_attribute(),
        description=STIX2toMISPMapping.comment_attribute(),
        name=STIX2toMISPMapping.yara_rule_name_attribute(),
        pattern_version=STIX2toMISPMapping.version_attribute(),
        x_misp_context={'type': 'text', 'object_relation': 'context'}
    )

    @classmethod
    def android_app_object_mapping(cls) -> dict:
        return cls.__android_app_object_mapping

    @classmethod
    def android_app_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__android_app_object_mapping.get(field)

    @classmethod
    def annotation_object_mapping(cls) -> dict:
        return cls.__annotation_object_mapping

    @classmethod
    def asn_object_mapping(cls) -> dict:
        return cls.__asn_object_mapping

    @classmethod
    def asn_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__asn_object_mapping.get(field)

    @classmethod
    def attributes_mapping(cls, field) -> Union[str, None]:
        return cls.__attributes_mapping.get(field)

    @classmethod
    def course_of_action_object_mapping(cls) -> dict:
        return cls.__course_of_action_object_mapping

    @classmethod
    def cpe_asset_object_mapping(cls) -> dict:
        return cls.__cpe_asset_object_mapping

    @classmethod
    def cpe_asset_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__cpe_asset_object_mapping.get(field)

    @classmethod
    def credential_object_mapping(cls) -> dict:
        return cls.__credential_object_mapping

    @classmethod
    def credential_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__credential_object_mapping.get(field)

    @classmethod
    def domain_ip_object_mapping(cls) -> dict:
        return cls.__domain_ip_object_mapping

    @classmethod
    def domain_ip_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__domain_ip_object_mapping.get(field)

    @classmethod
    def dst_as_attribute(cls) -> dict:
        return cls.__dst_as_attribute

    @classmethod
    def email_object_mapping(cls) -> dict:
        return cls.__email_object_mapping

    @classmethod
    def email_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__email_pattern_mapping.get(field)

    @classmethod
    def facebook_account_object_mapping(cls) -> dict:
        return cls.__facebook_account_object_mapping

    @classmethod
    def facebook_account_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__facebook_account_object_mapping.get(field)

    @classmethod
    def file_hashes_mapping(cls, field) -> Union[dict, None]:
        return cls.__file_hashes_mapping.get(field)

    @classmethod
    def file_object_mapping(cls) -> dict:
        return cls.__file_object_mapping

    @classmethod
    def file_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__file_pattern_mapping.get(field)

    @classmethod
    def github_user_object_mapping(cls) -> dict:
        return cls.__github_user_object_mapping

    @classmethod
    def github_user_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__github_user_object_mapping.get(field)

    @classmethod
    def gitlab_user_object_mapping(cls) -> dict:
        return cls.__gitlab_user_object_mapping

    @classmethod
    def gitlab_user_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__gitlab_user_object_mapping.get(field)

    @classmethod
    def host_attribute(cls) -> dict:
        return cls.__host_attribute

    @classmethod
    def hostname_dst_attribute(cls) -> dict:
        return cls.__hostname_dst_attribute

    @classmethod
    def hostname_src_attribute(cls) -> dict:
        return cls.__hostname_src_attribute

    @classmethod
    def http_request_extension_mapping(cls) -> dict:
        return cls.__http_request_extension_mapping

    @classmethod
    def http_request_header_mapping(cls) -> dict:
        return cls.__http_request_header_mapping

    @classmethod
    def http_request_object_mapping(cls) -> dict:
        return cls.__http_request_object_mapping

    @classmethod
    def http_request_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__http_request_pattern_mapping.get(field)

    @classmethod
    def icmp_type_attribute(cls) -> dict:
        return cls.__icmp_type_attribute

    @classmethod
    def image_object_mapping(cls) -> dict:
        return cls.__image_object_mapping

    @classmethod
    def image_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__image_pattern_mapping.get(field)

    @classmethod
    def indicator_attributes_mapping(cls, field) -> Union[str, None]:
        return cls.__indicator_attributes_mapping.get(field)

    @classmethod
    def ip_port_object_mapping(cls) -> dict:
        return cls.__ip_port_object_mapping

    @classmethod
    def ip_port_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__ip_port_object_mapping.get(field)

    @classmethod
    def lnk_object_mapping(cls) -> dict:
        return cls.__lnk_object_mapping

    @classmethod
    def lnk_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__lnk_pattern_mapping.get(field)

    @classmethod
    def mutex_object_mapping(cls) -> dict:
        return cls.__mutex_object_mapping

    @classmethod
    def mutex_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__mutex_object_mapping.get(field)

    @classmethod
    def netflow_object_mapping(cls) -> dict:
        return cls.__netflow_object_mapping

    @classmethod
    def netflow_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__netflow_pattern_mapping.get(field)

    @classmethod
    def network_connection_object_mapping(cls) -> dict:
        return cls.__network_connection_object_mapping

    @classmethod
    def network_connection_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__network_connection_object_mapping.get(field)

    @classmethod
    def network_socket_object_mapping(cls) -> dict:
        return cls.__network_socket_object_mapping

    @classmethod
    def network_socket_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__network_socket_object_mapping.get(field)

    @classmethod
    def objects_mapping(cls, field) -> Union[str, None]:
        return cls.__objects_mapping.get(field)

    @classmethod
    def object_type_refs_to_skip(cls) -> tuple:
        return cls.__object_type_refs_to_skip

    @classmethod
    def observable_attributes_mapping(cls, field) -> Union[str, None]:
        return cls.__observable_attributes_mapping.get(field)

    @classmethod
    def parent_process_object_mapping(cls) -> dict:
        return cls.__parent_process_object_mapping

    @classmethod
    def parler_account_object_mapping(cls) -> dict:
        return cls.__parler_account_object_mapping

    @classmethod
    def parler_account_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__parler_account_object_mapping.get(field)

    @classmethod
    def pe_object_mapping(cls) -> dict:
        return cls.__pe_object_mapping

    @classmethod
    def pe_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__pe_object_mapping.get(field)

    @classmethod
    def pe_section_object_mapping(cls) -> dict:
        return cls.__pe_section_object_mapping

    @classmethod
    def pe_section_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__pe_section_object_mapping.get(field)

    @classmethod
    def process_object_mapping(cls) -> dict:
        return cls.__process_object_mapping

    @classmethod
    def process_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__process_pattern_mapping.get(field)

    @classmethod
    def protocol_attribute(cls) -> dict:
        return cls.__protocol_attribute

    @classmethod
    def reddit_account_object_mapping(cls) -> dict:
        return cls.__reddit_account_object_mapping

    @classmethod
    def reddit_account_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__reddit_account_object_mapping.get(field)

    @classmethod
    def registry_key_object_mapping(cls) -> dict:
        return cls.__registry_key_object_mapping

    @classmethod
    def registry_key_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__registry_key_object_mapping.get(field)

    @classmethod
    def sigma_object_mapping(cls) -> dict:
        return cls.__sigma_object_mapping

    @classmethod
    def src_as_attribute(cls) -> dict:
        return cls.__src_as_attribute

    @classmethod
    def tcp_flags_attribute(cls) -> dict:
        return cls.__tcp_flags_attribute

    @classmethod
    def telegram_account_object_mapping(cls) -> dict:
        return cls.__telegram_account_object_mapping

    @classmethod
    def telegram_account_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__telegram_account_object_mapping.get(field)

    @classmethod
    def twitter_account_object_mapping(cls) -> dict:
        return cls.__twitter_account_object_mapping

    @classmethod
    def twitter_account_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__twitter_account_object_mapping.get(field)

    @classmethod
    def url_object_mapping(cls) -> dict:
        return cls.__url_object_mapping

    @classmethod
    def url_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__url_object_mapping.get(field)

    @classmethod
    def user_account_object_mapping(cls) -> dict:
        return cls.__user_account_object_mapping

    @classmethod
    def user_account_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__user_account_object_mapping.get(field)

    @classmethod
    def x509_object_mapping(cls) -> dict:
        return cls.__x509_object_mapping

    @classmethod
    def x509_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__x509_pattern_mapping.get(field)

    @classmethod
    def x509_subject_alternative_name_mapping(cls, field) -> Union[dict, None]:
        return cls.__x509_subject_alternative_name_mapping.get(field)

    @classmethod
    def yara_object_mapping(cls) -> dict:
        return cls.__yara_object_mapping
