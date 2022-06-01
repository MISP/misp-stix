#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .. import Mapping
from .stix2_mapping import STIX2Mapping


class InternalSTIX2Mapping(STIX2Mapping):
    def __init__(self):
        super().__init__()
        self._declare_mapping(
            updates = {
                'location': {
                    'x_misp_altitude': {'type': 'float', 'object_relation': 'altitude'},
                    'x_misp_country': {'type': 'text', 'object_relation': 'country'},
                    'x_misp_epsg': {'type': 'text', 'object_relation': 'epsg'},
                    'x_misp_first_seen': {'type': 'datetime', 'object_relation': 'first-seen'},
                    'x_misp_last_seen': {'type': 'datetime', 'object_relation': 'last-seen'},
                    'x_misp_neighborhood': {'type': 'text', 'object_relation': 'neighborhood'},
                    'x_misp_spacial_reference': {
                        'type': 'text',
                        'object_relation': 'spacial-reference'
                    }
                }
            }
        )
        self.__attributes_mapping = {
            'vulnerability': '_parse_vulnerability_attribute'
        }
        indicator_attributes_mapping = {
            'AS': '_attribute_from_AS',
            'attachment': '_attribute_from_attachment',
            'malware-sample': '_attribute_from_malware_sample'
        }
        indicator_attributes_mapping.update(
            dict.fromkeys(
                (
                    'authentihash',
                    'cdhash',
                    'domain',
                    'email',
                    'email-attachment',
                    'email-body',
                    'email-dst',
                    'email-header',
                    'email-message-id',
                    'email-reply-to',
                    'email-src',
                    'email-subject',
                    'email-x-mailer',
                    'filename',
                    'hostname',
                    'http-method',
                    'imphash',
                    'impfuzzy',
                    'link',
                    'mac-address',
                    'md5',
                    'mutex',
                    'pehash',
                    'port',
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
                    'size-in-bytes',
                    'ssdeep',
                    'regkey',
                    'telfhash',
                    'tlsh',
                    'uri',
                    'url',
                    'user-agent',
                    'vhash',
                    'x509-fingerprint-md5',
                    'x509-fingerprint-sha1',
                    'x509-fingerprint-sha256'
                ),
                '_attribute_from_simple_pattern'
            )
        )
        indicator_attributes_mapping.update(
            dict.fromkeys(
                (
                    'filename|authentihash',
                    'filename|imphash',
                    'filename|impfuzzy',
                    'filename|md5',
                    'filename|pehash',
                    'filename|sha1',
                    'filename|sha224',
                    'filename|sha256',
                    'filename|sha384',
                    'filename|sha512',
                    'filename|sha512/224',
                    'filename|sha512/256',
                    'filename|sha3-224',
                    'filename|sha3-256',
                    'filename|sha3-384',
                    'filename|sha3-512',
                    'filename|ssdeep',
                    'filename|tlsh',
                    'filename|vhash'
                ),
                '_attribute_from_filename_hash'
            )
        )
        indicator_attributes_mapping.update(
            dict.fromkeys(
                (
                    'domain|ip',
                    'hostname|port',
                    'regkey|value'
                ),
                '_attribute_from_double_pattern'
            )
        )
        indicator_attributes_mapping.update(
            dict.fromkeys(
                (
                    'github-username',
                    'ip-src',
                    'ip-dst'
                ),
                '_attribute_from_dual_pattern'
            )
        )
        indicator_attributes_mapping.update(
            dict.fromkeys(
                (
                    'ip-src|port',
                    'ip-dst|port'
                ),
                '_attribute_from_ip_port'
            )
        )
        indicator_attributes_mapping.update(
            dict.fromkeys(
                (
                    'sigma',
                    'snort',
                    'yara'
                ),
                '_attribute_from_patterning_language'
            )
        )
        self.__indicator_attributes_mapping = Mapping(**indicator_attributes_mapping)
        observable_attributes_mapping = {
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
            'regkey|value': '_attribute_from_regkey_value'
        }
        observable_attributes_mapping.update(
            dict.fromkeys(
                (
                    'domain',
                    'email',
                    'hostname',
                    'link',
                    'mac-address',
                    'mutex',
                    'uri',
                    'url'
                ),
                '_attribute_from_first'
            )
        )
        observable_attributes_mapping.update(
            dict.fromkeys(
                (
                    'authentihash',
                    'cdhash',
                    'imphash',
                    'impfuzzy',
                    'md5',
                    'pehash',
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
                    'telfhash',
                    'tlsh',
                    'vhash',
                    'x509-fingerprint-md5',
                    'x509-fingerprint-sha1',
                    'x509-fingerprint-sha256'
                ),
                '_attribute_from_hash'
            )
        )
        observable_attributes_mapping.update(
            dict.fromkeys(
                (
                    'filename|authentihash',
                    'filename|imphash',
                    'filename|impfuzzy',
                    'filename|md5',
                    'filename|pehash',
                    'filename|sha1',
                    'filename|sha224',
                    'filename|sha256',
                    'filename|sha384',
                    'filename|sha512',
                    'filename|sha512/224',
                    'filename|sha512/256',
                    'filename|sha3-224',
                    'filename|sha3-256',
                    'filename|sha3-384',
                    'filename|sha3-512',
                    'filename|ssdeep',
                    'filename|tlsh',
                    'filename|vhash'
                ),
                '_attribute_from_filename_hash'
            )
        )
        observable_attributes_mapping.update(
            dict.fromkeys(
                (
                    'ip-src|port',
                    'ip-dst|port'
                ),
                '_attribute_from_ip_port'
            )
        )
        observable_attributes_mapping.update(
            dict.fromkeys(
                (
                    'filename',
                    'mutex'
                ),
                '_attribute_from_name'
            )
        )
        observable_attributes_mapping.update(
            dict.fromkeys(
                (
                    'email-dst',
                    'email-src',
                    'ip-src',
                    'ip-dst'
                ),
                '_attribute_from_second'
            )
        )
        self.__observable_attributes_mapping = Mapping(**observable_attributes_mapping)
        galaxies_mapping = {'branded-vulnerability': '_galaxy_from_attack_pattern'}
        galaxies_mapping.update(
            dict.fromkeys(
                (
                    'mitre-attack-pattern',
                    'mitre-enterprise-attack-attack-pattern',
                    'mitre-mobile-attack-attack-pattern',
                    'mitre-pre-attack-attack-pattern'
                ),
                '_galaxy_from_attack_pattern'
            )
        )
        galaxies_mapping.update(
            dict.fromkeys(
                (
                    'mitre-course-of-action',
                    'mitre-enterprise-attack-course-of-action',
                    'mitre-mobile-attack-course-of-action'
                ),
                '_galaxy_from_course_of_action'
            )
        )
        galaxies_mapping.update(
            dict.fromkeys(
                (
                    'mitre-enterprise-attack-intrusion-set',
                    'mitre-intrusion-set',
                    'mitre-mobile-attack-intrusion-set',
                    'mitre-pre-attack-intrusion-set'
                ),
                '_galaxy_from_intrusion_set'
            )
        )
        galaxies_mapping.update(
            dict.fromkeys(
                (
                    'android',
                    'banker',
                    'stealer',
                    'backdoor',
                    'ransomware',
                    'mitre-malware',
                    'malpedia',
                    'mitre-enterprise-attack-malware',
                    'mitre-mobile-attack-malware'
                ),
                '_galaxy_from_malware'
            )
        ),
        galaxies_mapping.update(
            dict.fromkeys(
                (
                    'threat-actor',
                    'microsoft-activity-group'
                ),
                '_galaxy_from_threat_actor'
            )
        )
        galaxies_mapping.update(
            dict.fromkeys(
                (
                    'botnet',
                    'rat',
                    'exploit-kit',
                    'tds',
                    'tool',
                    'mitre-tool',
                    'mitre-enterprise-attack-tool',
                    'mitre-mobile-attack-tool'
                ),
                '_galaxy_from_tool'
            )
        )
        self.__galaxies_mapping = Mapping(**galaxies_mapping)
        objects_mapping = {
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
            'github-user': '_object_from_github_user',
            'gitlab-user': '_object_from_gitlab_user',
            'image': '_object_from_image',
            'ip-port': '_object_from_ip_port',
            'legal-entity': '_parse_legal_entity_object',
            'lnk': '_object_from_lnk',
            'mutex': '_object_from_mutex',
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
            'x509': '_object_from_x509'
        }
        objects_mapping.update(
            dict.fromkeys(
                (
                    'suricata',
                    'yara'
                ),
                '_object_from_patterning_language'
            )
        )
        self.__objects_mapping = Mapping(**objects_mapping)

        # ATTRIBUTES DECLARATION
        account_id_attribute = {'type': 'text', 'object_relation': 'account-id'}
        account_name_attribute = {'type': 'text', 'object_relation': 'account-name'}
        alias_attribute = {'type': 'text', 'object_relation': 'alias'}
        archive_attribute = {'type': 'link', 'object_relation': 'archive'}
        attachment_attribute = {'type': 'attachment', 'object_relation': 'attachment'}
        authentihash_attribute = {'type': 'authentihash', 'object_relation': 'authentihash'}
        bcc_attribute = {'type': 'email-dst', 'object_relation': 'bcc'}
        bcc_display_name_attribute = {'type': 'email-dst-display-name', 'object_relation': 'bcc-display-name'}
        bio_attribute = {'type': 'text', 'object_relation': 'bio'}
        cc_attribute = {'type': 'email-dst', 'object_relation': 'cc'}
        cc_display_name_attribute = {'type': 'email-dst-display-name', 'object_relation': 'cc-display-name'}
        certificate_attribute = {'type': 'x509-fingerprint-sha1', 'object_relation': 'certificate'}
        comment_attribute = {'type': 'text', 'object_relation': 'comment'}
        compilation_timestamp_attribute = {'type': 'datetime', 'object_relation': 'compilation-timestamp'}
        description_attribute = {'type': 'text', 'object_relation': 'description'}
        email_attachment_attribute = {'type': 'email-attachment', 'object_relation': 'attachment'}
        email_body_attribute = {'type': 'email-body', 'object_relation': 'email-body'}
        email_header_attribute = {'type': 'email-header', 'object_relation': 'header'}
        eml_attribute = {'type': 'attachment', 'object_relation': 'eml'}
        employee_type_attribute = {'type': 'text', 'object_relation': 'employee-type'}
        entropy_attribute = {'type': 'float', 'object_relation': 'entropy'}
        file_encoding_attribute = {'type': 'text', 'object_relation': 'file-encoding'}
        filename_attribute = {'type': 'filename', 'object_relation': 'filename'}
        followers_attribute = {'type': 'text', 'object_relation': 'followers'}
        following_attribute = {'type': 'text', 'object_relation': 'following'}
        fullpath_attribute = {'type': 'text', 'object_relation': 'fullpath'}
        from_attribute = {'type': 'email-src', 'object_relation': 'from'}
        from_display_name_attribute = {'type': 'email-src-display-name', 'object_relation': 'from-display-name'}
        from_domain_attribute = {'type': 'domain', 'object_relation': 'from-domain'}
        id_attribute = {'type': 'text', 'object_relation': 'id'}
        imphash_attribute = {'type': 'imphash', 'object_relation': 'imphash'}
        ip_source_attribute = {'type': 'ip-src', 'object_relation': 'ip-src'}
        language_attribute = {'type': 'text', 'object_relation': 'language'}
        last_changed_attribute = {'type': 'datetime', 'object_relation': 'password_last_changed'}
        likes_attribute = {'type': 'text', 'object_relation': 'likes'}
        link_attribute = {'type': 'link', 'object_relation': 'link'}
        md5_attribute = {'type': 'md5', 'object_relation': 'md5'}
        message_id_attribute = {'type': 'email-message-id', 'object_relation': 'message-id'}
        mime_boundary_attribute = {'type': 'email-mime-boundary', 'object_relation': 'mime-boundary'}
        mime_type_attribute = {'type': 'mime-type', 'object_relation': 'mimetype'}
        msg_attribute = {'type': 'attachment', 'object_relation': 'msg'}
        name_attribute = {'type': 'text', 'object_relation': 'name'}
        password_attribute = {'type': 'text', 'object_relation': 'password'}
        path_attribute = {'type': 'text', 'object_relation': 'path'}
        pattern_in_file_attribute = {'type': 'pattern-in-file', 'object_relation': 'pattern-in-file'}
        received_hostname_attribute = {'type': 'hostname', 'object_relation': 'received-header-hostname'}
        received_ip_attribute = {'type': 'ip-src', 'object_relation': 'received-header-ip'}
        reply_to_attribute = {'type': 'email-reply-to', 'object_relation': 'reply-to'}
        reply_to_display_name_attribute = {'type': 'email-dst-display-name', 'object_relation': 'reply-to-display-name'}
        return_path_attribute = {'type': 'email-src', 'object_relation': 'return-path'}
        role_attribute = {'type': 'text', 'object_relation': 'role'}
        screenshot_attribute = {'type': 'attachment', 'object_relation': 'screenshot'}
        script_attribute = {'type': 'text', 'object_relation': 'script'}
        send_date_attribute = {'type': 'datetime', 'object_relation': 'send-date'}
        sha1_attribute = {'type': 'sha1', 'object_relation': 'sha1'}
        sha224_attribute = {'type': 'sha224', 'object_relation': 'sha224'}
        sha256_attribute = {'type': 'sha256', 'object_relation': 'sha256'}
        sha3_224_attribute = {'type': 'sha3-224', 'object_relation': 'sha3-224'}
        sha3_256_attribute = {'type': 'sha3-256', 'object_relation': 'sha3-256'}
        sha3_384_attribute = {'type': 'sha3-384', 'object_relation': 'sha3-384'}
        sha3_512_attribute = {'type': 'sha3-512', 'object_relation': 'sha3-512'}
        sha384_attribute = {'type': 'sha384', 'object_relation': 'sha384'}
        sha512_attribute = {'type': 'sha512', 'object_relation': 'sha512'}
        size_in_bytes_attribute = {'type': 'size-in-bytes', 'object_relation': 'size-in-bytes'}
        ssdeep_attribute = {'type': 'ssdeep', 'object_relation': 'ssdeep'}
        state_attribute = {'type': 'text', 'object_relation': 'state'}
        subject_attribute = {'type': 'email-subject', 'object_relation': 'subject'}
        telfhash_attribute = {'type': 'telfhash', 'object_relation': 'telfhash'}
        text_attribute = {'type': 'text', 'object_relation': 'text'}
        thread_index_attribute = {'type': 'email-thread-index', 'object_relation': 'thread-index'}
        tlsh_attribute = {'type': 'tlsh', 'object_relation': 'tlsh'}
        to_attribute = {'type': 'email-dst', 'object_relation': 'to'}
        to_display_name_attribute = {'type': 'email-dst-display-name', 'object_relation': 'to-display-name'}
        url_attribute = {'type': 'url', 'object_relation': 'url'}
        username_attribute = {'type': 'text', 'object_relation': 'username'}
        user_agent_attribute = {'type': 'text', 'object_relation': 'user-agent'}
        user_avatar_attribute = {'type': 'attachment', 'object_relation': 'user-avatar'}
        verified_attribute = {'type': 'text', 'object_relation': 'verified'}
        version_attribute = {'type': 'text', 'object_relation': 'version'}
        vhash_attribute = {'type': 'vhash', 'object_relation': 'vhash'}
        x_mailer_attribute = {'type': 'email-x-mailer', 'object_relation': 'x-mailer'}

        # STIX TO MISP OBJECTS MAPPING
        self.__asn_object_mapping = Mapping(
            number = {'type': 'AS', 'object_relation': 'asn'},
            name = description_attribute,
            x_misp_country = {'type': 'text', 'object_relation': 'country'},
            x_misp_export = {'type': 'text', 'object_relation': 'export'},
            x_misp_first_seen = {'type': 'datetime', 'object_relation': 'first-seen'},
            x_misp_import = {'type': 'text', 'object_relation': 'import'},
            x_misp_last_seen = {'type': 'datetime', 'object_relation': 'last-seen'},
            x_misp_mp_export = {'type': 'text', 'object_relation': 'mp-export'},
            x_misp_mp_import = {'type': 'text', 'object_relation': 'mp-import'},
            x_misp_subnet_announced = {'type': 'ip-src', 'object_relation': 'subnet-announced'}
        )
        self.__attack_pattern_object_mapping = Mapping(
            description = {'type': 'text', 'object_relation': 'summary'},
            name = name_attribute,
            x_misp_prerequisites = {'type': 'text', 'object_relation': 'prerequisites'},
            x_misp_related_weakness = {'type': 'weakness', 'object_relation': 'related-weakness'},
            x_misp_solutions = {'type': 'text', 'object_relation': 'solutions'}
        )
        self.__course_of_action_object_mapping = Mapping(
            name = name_attribute,
            description = description_attribute,
            x_misp_cost = {'type': 'text', 'object_relation': 'cost'},
            x_misp_efficacy = {'type': 'text', 'object_relation': 'efficacy'},
            x_misp_impact = {'type': 'text', 'object_relation': 'impact'},
            x_misp_objective = {'type': 'text', 'object_relation': 'objective'},
            x_misp_stage = {'type': 'text', 'object_relation': 'stage'},
            x_misp_type = {'type': 'text', 'object_relation': 'type'}
        )
        self.__cpe_asset_object_mapping = Mapping(
            cpe = {'type': 'cpe', 'object_relation': 'cpe'},
            languages = {'type': 'text', 'object_relation': 'language'},
            name = {'type': 'text', 'object_relation': 'product'},
            vendor = {'type': 'text', 'object_relation': 'vendor'},
            version = {'type': 'text', 'object_relation': 'version'},
            x_misp_description = description_attribute,
            x_misp_other = {'type': 'text', 'object_relation': 'other'},
            x_misp_part = {'type': 'text', 'object_relation': 'part'},
            x_misp_product = {'type': 'text', 'object_relation': 'product'},
            x_misp_sw_edition = {'type': 'text', 'object_relation': 'sw_edition'},
            x_misp_target_hw = {'type': 'text', 'object_relation': 'target_hw'},
            x_misp_target_sw = {'type': 'text', 'object_relation': 'target_sw'},
            x_misp_update = {'type': 'text', 'object_relation': 'update'},
        )
        self.__credential_object_mapping = Mapping(
            user_id = username_attribute,
            credential = password_attribute,
            x_misp_password = password_attribute,
            x_misp_format = {'type': 'text', 'object_relation': 'format'},
            x_misp_notification = {'type': 'text', 'object_relation': 'notification'},
            x_misp_origin = {'type': 'text', 'object_relation': 'origin'},
            x_misp_text = text_attribute,
            x_misp_type = {'type': 'text', 'object_relation': 'type'},
        )
        self.__domain_ip_object_mapping = Mapping(
            value = {'type': 'domain', 'object_relation': 'domain'},
            x_misp_first_seen = {'type': 'datetime', 'object_relation': ''},
            x_misp_hostname = {'type': 'hostname', 'object_relation': 'hostname'},
            x_misp_last_seen = {'type': 'datetime', 'object_relation': ''},
            x_misp_port = {'type': 'port', 'object_relation': 'port'},
            x_misp_registration_date = {'type': 'datetime', 'object_relation': ''},
            x_misp_text = text_attribute
        )
        self.__email_additional_header_fields_mapping = Mapping(
            **{
                'Reply-To': reply_to_attribute,
                'X-Mailer': x_mailer_attribute
            }
        )
        self.__email_indicator_object_mapping = Mapping(
            **{
                'additional_header_fields.reply_to': reply_to_attribute,
                'additional_header_fields.x_mailer': x_mailer_attribute,
                'bcc_refs': {
                    'display_name': bcc_display_name_attribute,
                    'value': bcc_attribute
                },
                'body': email_body_attribute,
                'cc_refs': {
                    'display_name': cc_display_name_attribute,
                    'value': cc_attribute
                },
                'date': send_date_attribute,
                'from_ref.display_name': from_display_name_attribute,
                'from_ref.value': from_attribute,
                'message_id': message_id_attribute,
                'subject': subject_attribute,
                'to_refs': {
                    'display_name': to_display_name_attribute,
                    'value': to_attribute
                },
                'x_misp_attachment': email_attachment_attribute,
                'x_misp_from_domain': from_domain_attribute,
                'x_misp_ip_src': ip_source_attribute,
                'x_misp_message_id': message_id_attribute,
                'x_misp_mime_boundary': mime_boundary_attribute,
                'x_misp_received_header_hostname': received_hostname_attribute,
                'x_misp_received_header_ip': received_ip_attribute,
                'x_misp_reply_to_display_name': reply_to_display_name_attribute,
                'x_misp_return_path': return_path_attribute,
                'x_misp_screenshot': screenshot_attribute,
                'x_misp_thread_index': thread_index_attribute,
                'x_misp_user_agent': user_agent_attribute
            }
        )
        self.__email_object_mapping = Mapping(
            body = email_body_attribute,
            date = send_date_attribute,
            message_id = message_id_attribute,
            subject = subject_attribute,
            x_misp_attachment = email_attachment_attribute,
            x_misp_from_domain = from_domain_attribute,
            x_misp_ip_src = ip_source_attribute,
            x_misp_message_id = message_id_attribute,
            x_misp_mime_boundary = mime_boundary_attribute,
            x_misp_received_header_hostname = received_hostname_attribute,
            x_misp_received_header_ip = received_ip_attribute,
            x_misp_reply_to_display_name = reply_to_display_name_attribute,
            x_misp_return_path = return_path_attribute,
            x_misp_screenshot = screenshot_attribute,
            x_misp_thread_index = thread_index_attribute,
            x_misp_user_agent = user_agent_attribute
        )
        self.__employee_object_mapping = Mapping(
            name = {'type': 'full-name', 'object_relation': 'full-name'},
            description = {'type': 'text', 'object_relation': 'text'},
            roles = employee_type_attribute,
            x_misp_business_unit = {'type': 'target-org', 'object_relation': 'business_unit'},
            x_misp_employee_type = employee_type_attribute,
            x_misp_first_name = {'type': 'first-name', 'object_relation': 'first-name'},
            x_misp_last_name = {'type': 'last-name', 'object_relation': 'last-name'},
            x_misp_primary_asset = {'type': 'target-machine', 'object_relation': 'primary-asset'},
            x_misp_userid = {'type': 'target-user', 'object_relation': 'userid'}
        )
        self.__facebook_account_object_mapping = Mapping(
            user_id = account_id_attribute,
            account_login = account_name_attribute,
            x_misp_archive = archive_attribute,
            x_misp_attachment = attachment_attribute,
            x_misp_description = description_attribute,
            x_misp_link = link_attribute,
            x_misp_url = url_attribute,
            x_misp_user_avatar = user_avatar_attribute
        )
        self.__file_hashes_object_mapping = Mapping(
            **{
                'AUTHENTIHASH': authentihash_attribute,
                'IMPHASH': imphash_attribute,
                'MD5': md5_attribute,
                'SHA-1': sha1_attribute,
                'SHA224': sha224_attribute,
                'SHA-256': sha256_attribute,
                'SHA3224': sha3_224_attribute,
                'SHA3-256': sha3_256_attribute,
                'SHA3384': sha3_384_attribute,
                'SHA3-512': sha3_512_attribute,
                'SHA384': sha384_attribute,
                'SHA-512': sha512_attribute,
                'ssdeep': ssdeep_attribute,
                'SSDEEP': ssdeep_attribute,
                'TELFHASH': telfhash_attribute,
                'TLSH': tlsh_attribute,
                'VHASH': vhash_attribute
            }
        )
        self.__file_indicator_object_mapping = Mapping(
            **{
                'hashes.AUTHENTIHASH': authentihash_attribute,
                'hashes.IMPHASH': imphash_attribute,
                'hashes.MD5': md5_attribute,
                'hashes.SHA1': sha1_attribute,
                'hashes.SHA224': sha224_attribute,
                'hashes.SHA256': sha256_attribute,
                'hashes.SHA3224': sha3_224_attribute,
                'hashes.SHA3256': sha3_256_attribute,
                'hashes.SHA3384': sha3_384_attribute,
                'hashes.SHA3512': sha3_512_attribute,
                'hashes.SHA384': sha384_attribute,
                'hashes.SHA512': sha512_attribute,
                'hashes.SSDEEP': ssdeep_attribute,
                'hashes.TELFHASH': telfhash_attribute,
                'hashes.TLSH': tlsh_attribute,
                'hashes.VHASH': vhash_attribute,
                'mime_type': mime_type_attribute,
                'name': filename_attribute,
                'name_enc': file_encoding_attribute,
                'parent_directory_ref.path': path_attribute,
                'size': size_in_bytes_attribute,
                'x_misp_certificate': certificate_attribute,
                'x_misp_compilation_timestamp': compilation_timestamp_attribute,
                'x_misp_entropy': entropy_attribute,
                'x_misp_fullpath': fullpath_attribute,
                'x_misp_path': path_attribute,
                'x_misp_pattern_in_file': pattern_in_file_attribute,
                'x_misp_state': state_attribute,
                'x_misp_text': text_attribute
            }
        )
        self.__file_observable_object_mapping = Mapping(
            mime_type = mime_type_attribute,
            name = filename_attribute,
            name_enc = file_encoding_attribute,
            size = size_in_bytes_attribute,
            x_misp_attachment = attachment_attribute,
            x_misp_certificate = certificate_attribute,
            x_misp_compilation_timestamp = compilation_timestamp_attribute,
            x_misp_entropy = entropy_attribute,
            x_misp_fullpath = fullpath_attribute,
            x_misp_path = path_attribute,
            x_misp_pattern_in_file = pattern_in_file_attribute,
            x_misp_state = state_attribute,
            x_misp_text = text_attribute
        )
        self.__github_user_object_mapping = Mapping(
            user_id = id_attribute,
            account_login = {'type': 'github-username', 'object_relation': 'username'},
            display_name = {'type': 'text', 'object_relation': 'user-fullname'},
            x_misp_avatar_url = {'type': 'link', 'object_relation': 'avatar_url'},
            x_misp_bio = bio_attribute,
            x_misp_blog = {'type': 'text', 'object_relation': 'blog'},
            x_misp_company = {'type': 'text', 'object_relation': 'company'},
            x_misp_follower = {'type': 'github-username', 'object_relation': 'follower'},
            x_misp_following = {'type': 'github-username', 'object_relation': 'following'},
            x_misp_link = link_attribute,
            x_misp_location = {'type': 'text', 'object_relation': 'location'},
            x_misp_node_id = {'type': 'text', 'object_relation': 'node_id'},
            x_misp_organisation = {'type': 'github-organisation', 'object_relation': 'organisation'},
            x_misp_profile_image = {'type': 'attachment', 'object_relation': 'profile-image'},
            x_misp_public_gists = {'type': 'text', 'object_relation': 'public_gists'},
            x_misp_public_repos = {'type': 'text', 'object_relation': 'public_repos'},
            x_misp_repository = {'type': 'github-repository', 'object_relation': 'repository'},
            x_misp_twitter_username = {'type': 'text', 'object_relation': 'twitter_username'},
            x_misp_verified = verified_attribute
        )
        self.__gitlab_user_object_mapping = Mapping(
            user_id = id_attribute,
            display_name = name_attribute,
            account_login = username_attribute,
            x_misp_avatar_url = {'type': 'link', 'object_relation': 'avatar_url'},
            x_misp_state = {'type': 'text', 'object_relation': 'state'},
            x_misp_web_url = {'type': 'link', 'object_relation': 'web_url'}
        )
        self.__legal_entity_contact_information_mapping = Mapping(
            **{
                'phone-number': {'type': 'phone-number'},
                'website': {'type': 'link'}
            }
        )
        self.__legal_entity_object_mapping = Mapping(
            name = name_attribute,
            description = text_attribute,
            sectors = {'type': 'text', 'object_relation': 'business'},
            x_misp_commercial_name = {'type': 'text', 'object_relation': 'commercial-name'},
            x_misp_legal_form = {'type': 'text', 'object_relation': 'legal-form'},
            x_misp_registration_number = {'type': 'text', 'object_relation': 'registration-number'}
        )
        self.__news_agency_contact_information_mapping = Mapping(
            **{
                'address': {'type': 'text'},
                'e-mail': {'type': 'email-src'},
                'fax-number': {'type': 'phone-number'},
                'link': {'type': 'link'},
                'phone-number': {'type': 'phone-number'}
            }
        )
        self.__news_agency_object_mapping = Mapping(
            name = name_attribute,
            x_misp_alias = alias_attribute,
            x_misp_archive = {'type': 'link', 'object_relation': 'archive'},
            x_misp_url = {'type': 'url', 'object_relation': 'url'}
        )
        self.__organization_contact_information_mapping = Mapping(
            **{
                'address': {'type': 'text'},
                'e-mail': {'type': 'email-src'},
                'fax-number': {'type': 'phone-number'},
                'phone-number': {'type': 'phone-number'}
            }
        )
        self.__organization_object_mapping = Mapping(
            name = name_attribute,
            description = description_attribute,
            roles = role_attribute,
            x_misp_role = role_attribute,
            x_misp_alias = alias_attribute,
            x_misp_date_of_inception = {
                'type': 'datetime',
                'object_relation': 'date-of-inception'
            },
            x_misp_type_of_organization = {
                'type': 'text',
                'object_relation': 'type-of-organization'
            },
            x_misp_VAT = {'type': 'text', 'object_relation': 'VAT'}
        )
        self.__parler_account_object_mapping = Mapping(
            user_id = account_id_attribute,
            account_login = account_name_attribute,
            x_misp_archive = archive_attribute,
            x_misp_attachment = attachment_attribute,
            x_misp_badge = {'type': 'link', 'object_relation': 'badge'},
            x_misp_bio = bio_attribute,
            x_misp_comments = {'type': 'text', 'object_relation': 'comments'},
            x_misp_cover_photo = {'type': 'attachment', 'object_relation': 'cover-photo'},
            x_misp_followers = followers_attribute,
            x_misp_following = following_attribute,
            x_misp_human = {'type': 'boolean', 'object_relation': 'human'},
            x_misp_interactions = {'type': 'float', 'object_relation': 'interactions'},
            x_misp_likes = likes_attribute,
            x_misp_link = link_attribute,
            x_misp_posts = {'type': 'text', 'object_relation': 'posts'},
            x_misp_profile_photo = {'type': 'attachment', 'object_relation': 'profile-photo'},
            x_misp_url = url_attribute,
            x_misp_verified = {'type': 'boolean', 'object_relation': 'verified'},
        )
        self.__reddit_account_object_mapping = Mapping(
            user_id = account_id_attribute,
            account_login = account_name_attribute,
            x_misp_account_avatar = {'type': 'attachment', 'object_relation': 'account-avatar'},
            x_misp_account_avatar_url = {'type': 'url', 'object_relation': 'account-avatar-url'},
            x_misp_archive = archive_attribute,
            x_misp_attachment = attachment_attribute,
            x_misp_description = description_attribute,
            x_misp_link = link_attribute,
            x_misp_moderator_of = {'type': '', 'object_relation': 'moderator-of'},
            x_misp_trophies = {'type': '', 'object_relation': 'trophies'},
            x_misp_url = url_attribute
        )
        self.__script_from_malware_object_mapping = Mapping(
            name = filename_attribute,
            description = comment_attribute,
            implementation_languages = language_attribute,
            x_misp_script = script_attribute,
            x_misp_state = state_attribute
        )
        self.__script_from_tool_object_mapping = Mapping(
            name = filename_attribute,
            description = comment_attribute,
            x_misp_language = language_attribute,
            x_misp_script = script_attribute,
            x_misp_state = state_attribute
        )
        self.__suricata_object_mapping = Mapping(
            pattern = {'type': 'snort', 'object_relation': 'suricata'},
            description = comment_attribute,
            pattern_version = version_attribute
        )
        self.__telegram_account_object_mapping = Mapping(
            user_id = id_attribute,
            account_login = username_attribute,
            x_misp_first_name = {'type': 'text', 'object_relation': 'first_name'},
            x_misp_last_name = {'type': 'text', 'object_relation': 'last_name'},
            x_misp_phone = {'type': 'text', 'object_relation': 'phone'},
            x_misp_verified = {'type': 'text', 'object_relation': 'verified'}
        )
        self.__twitter_account_object_mapping = Mapping(
            user_id = id_attribute,
            account_login = name_attribute,
            display_name = {'type': 'text', 'object_relation': 'displayed-name'},
            x_misp_archive = archive_attribute,
            x_misp_attachment = attachment_attribute,
            x_misp_bio = bio_attribute,
            x_misp_description = description_attribute,
            x_misp_embedded_link = {'type': 'url', 'object_relation': 'embedded-link'},
            x_misp_embedded_safe_link = {'type': 'link', 'object_relation': 'embedded-safe-link'},
            x_misp_followers = followers_attribute,
            x_misp_following = following_attribute,
            x_misp_hashtag = {'type': 'text', 'object_relation': 'hashtag'},
            x_misp_joined_date = {'type': 'text', 'object_relation': 'joined-date'},
            x_misp_likes = likes_attribute,
            x_misp_link = link_attribute,
            x_misp_listed = {'type': 'text', 'object_relation': 'listed'},
            x_misp_location = {'type': 'text', 'object_relation': 'location'},
            x_misp_media = {'type': 'text', 'object_relation': 'media'},
            x_misp_private = {'type': 'text', 'object_relation': 'private'},
            x_misp_profile_banner = {'type': 'attachment', 'object_relation': 'profile-banner'},
            x_misp_profile_banner_url = {'type': 'url', 'object_relation': 'profile-banner-url'},
            x_misp_profile_image = {'type': 'attachment', 'object_relation': 'profile-image'},
            x_misp_profile_image_url = {'type': 'url', 'object_relation': 'profile-image-url'},
            x_misp_tweets = {'type': 'text', 'object_relation': 'tweets'},
            x_misp_twitter_followers = {'type': 'text', 'object_relation': 'twitter-followers'},
            x_misp_twitter_following = {'type': 'text', 'object_relation': 'twitter-following'},
            x_misp_url = url_attribute,
            x_misp_verified = verified_attribute
        )
        self.__user_account_object_mapping = Mapping(
            account_login = username_attribute,
            account_type = {'type': 'text', 'object_relation': 'account-type'},
            can_escalate_privs = {'type': 'boolean', 'object_relation': 'can_escalate_privs'},
            credential = password_attribute,
            x_misp_password = password_attribute,
            display_name = {'type': 'text', 'object_relation': 'display-name'},
            is_disabled = {'type': 'boolean', 'object_relation': 'disabled'},
            is_privileged = {'type': 'boolean', 'object_relation': 'privileged'},
            is_service_account = {'type': 'boolean', 'object_relation': 'is_service_account'},
            user_id = {'type': 'text', 'object_relation': 'user-id'},
            x_misp_description = description_attribute,
            x_misp_link = link_attribute,
            x_misp_user_avatar = user_avatar_attribute,
            account_created = {'type': 'datetime', 'object_relation': 'created'},
            account_expires = {'type': 'datetime', 'object_relation': 'expires'},
            account_first_login = {'type': 'datetime', 'object_relation': 'first_login'},
            account_last_login = {'type': 'datetime', 'object_relation': 'last_login'},
            credential_last_changed = last_changed_attribute,
            password_last_changed = last_changed_attribute
        )
        self.__user_account_unix_extenstion_mapping = Mapping(
            gid = {'type': 'text', 'object_relation': 'group-id'},
            groups = {'type': 'text', 'object_relation': 'group'},
            home_dir = {'type': 'text', 'object_relation': 'home_dir'},
            shell = {'type': 'text', 'object_relation': 'shell'}
        )
        self.__vulnerability_object_mapping = Mapping(
            description = description_attribute,
            x_misp_created = {'type': 'datetime', 'object_relation': 'created'},
            x_misp_credit = {'type': 'text', 'object_relation': 'credit'},
            x_misp_cvss_score = {'type': 'float', 'object_relation': 'cvss-score'},
            x_misp_modified = {'type': 'datetime', 'object_relation': 'modified'},
            x_misp_published = {'type': 'datetime', 'object_relation': 'published'},
            x_misp_state = {'type': 'text', 'object_relation': 'state'},
            x_misp_summary = {'type': 'text', 'object_relation': 'summary'},
            x_misp_vulnerable_configuration = {
                'type': 'cpe',
                'object_relation': 'vulnerable-configuration'
            }
        )
        self.__yara_object_mapping = Mapping(
            pattern = {'type': 'yara', 'object_relation': 'yara'},
            description = comment_attribute,
            pattern_version = version_attribute,
            x_misp_context = {'type': 'text', 'object_relation': 'context'},
            x_misp_yara_rule_name = {'type': 'text', 'object_relation': 'yara-rule-name'}
        )

    @property
    def asn_object_mapping(self) -> dict:
        return self.__asn_object_mapping

    @property
    def attack_pattern_object_mapping(self) -> dict:
        return self.__attack_pattern_object_mapping

    @property
    def attributes_mapping(self) -> dict:
        return self.__attributes_mapping

    @property
    def course_of_action_object_mapping(self) -> dict:
        return self.__course_of_action_object_mapping

    @property
    def cpe_asset_object_mapping(self) -> dict:
        return self.__cpe_asset_object_mapping

    @property
    def credential_object_mapping(self) -> dict:
        return self.__credential_object_mapping

    @property
    def domain_ip_object_mapping(self) -> dict:
        return self.__domain_ip_object_mapping

    @property
    def email_additional_header_fields_mapping(self) -> dict:
        return self.__email_additional_header_fields_mapping

    @property
    def email_indicator_object_mapping(self) -> dict:
        return self.__email_indicator_object_mapping

    @property
    def email_object_mapping(self) -> dict:
        return self.__email_object_mapping

    @property
    def employee_object_mapping(self) -> dict:
        return self.__employee_object_mapping

    @property
    def facebook_account_object_mapping(self) -> dict:
        return self.__facebook_account_object_mapping

    @property
    def file_hashes_object_mapping(self) -> dict:
        return self.__file_hashes_object_mapping

    @property
    def file_indicator_object_mapping(self) -> dict:
        return self.__file_indicator_object_mapping

    @property
    def file_observable_object_mapping(self) -> dict:
        return self.__file_observable_object_mapping

    @property
    def galaxies_mapping(self) -> dict:
        return self.__galaxies_mapping

    @property
    def github_user_object_mapping(self) -> dict:
        return self.__github_user_object_mapping

    @property
    def gitlab_user_object_mapping(self) -> dict:
        return self.__gitlab_user_object_mapping

    @property
    def indicator_attributes_mapping(self) -> dict:
        return self.__indicator_attributes_mapping

    @property
    def legal_entity_contact_information_mapping(self) -> dict:
        return self.__legal_entity_contact_information_mapping

    @property
    def legal_entity_object_mapping(self) -> dict:
        return self.__legal_entity_object_mapping

    @property
    def news_agency_object_mapping(self) -> dict:
        return self.__news_agency_object_mapping

    @property
    def news_agency_contact_information_mapping(self) -> dict:
        return self.__news_agency_contact_information_mapping

    @property
    def objects_mapping(self) -> dict:
        return self.__objects_mapping

    @property
    def observable_attributes_mapping(self) -> dict:
        return self.__observable_attributes_mapping

    @property
    def organization_object_mapping(self) -> dict:
        return self.__organization_object_mapping

    @property
    def organization_contact_information_mapping(self) -> dict:
        return self.__organization_contact_information_mapping

    @property
    def parler_account_object_mapping(self) -> dict:
        return self.__parler_account_object_mapping

    @property
    def reddit_account_object_mapping(self) -> dict:
        return self.__reddit_account_object_mapping

    @property
    def script_from_malware_object_mapping(self) -> dict:
        return self.__script_from_malware_object_mapping

    @property
    def script_from_tool_object_mapping(self) -> dict:
        return self.__script_from_tool_object_mapping

    @property
    def suricata_object_mapping(self) -> dict:
        return self.__suricata_object_mapping

    @property
    def telegram_account_object_mapping(self) -> dict:
        return self.__telegram_account_object_mapping

    @property
    def twitter_account_object_mapping(self) -> dict:
        return self.__twitter_account_object_mapping

    @property
    def user_account_object_mapping(self) -> dict:
        return self.__user_account_object_mapping

    @property
    def user_account_unix_extension_mapping(self) -> dict:
        return self.__user_account_unix_extenstion_mapping

    @property
    def vulnerability_object_mapping(self) -> dict:
        return self.__vulnerability_object_mapping

    @property
    def yara_object_mapping(self) -> dict:
        return self.__yara_object_mapping
