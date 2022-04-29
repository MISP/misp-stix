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
            'facebook-account': '_object_from_account',
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
        alias_attribute = {'type': 'text', 'object_relation': 'alias'}
        comment_attribute = {'type': 'text', 'object_relation': 'comment'}
        description_attribute = {'type': 'text', 'object_relation': 'description'}
        employee_type_attribute = {'type': 'text', 'object_relation': 'employee-type'}
        filename_attribute = {'type': 'filename', 'object_relation': 'filename'}
        id_attribute = {'type': 'text', 'object_relation': 'id'}
        language_attribute = {'type': 'text', 'object_relation': 'language'}
        name_attribute = {'type': 'text', 'object_relation': 'name'}
        role_attribute = {'type': 'text', 'object_relation': 'role'}
        script_attribute = {'type': 'text', 'object_relation': 'script'}
        state_attribute = {'type': 'text', 'object_relation': 'state'}
        username_attribute = {'type': 'text', 'object_relation': 'username'}
        version_attribute = {'type': 'text', 'object_relation': 'version'}

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
            description = {'type': 'text', 'object_relation': 'text'},
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
    def employee_object_mapping(self) -> dict:
        return self.__employee_object_mapping

    @property
    def galaxies_mapping(self) -> dict:
        return self.__galaxies_mapping

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
    def vulnerability_object_mapping(self) -> dict:
        return self.__vulnerability_object_mapping

    @property
    def yara_object_mapping(self) -> dict:
        return self.__yara_object_mapping
