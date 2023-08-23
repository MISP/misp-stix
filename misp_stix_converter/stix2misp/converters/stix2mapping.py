#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ... import Mapping
from abc import ABCMeta
from typing import Union


class STIX2Mapping(metaclass=ABCMeta):
    # SINGLE ATTRIBUTES MAPPING
    __access_time_attribute = Mapping(
        **{'type': 'datetime', 'object_relation': 'access-time'}
    )
    __alias_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'alias'}
    )
    __creation_time_attribute = Mapping(
        **{'type': 'datetime', 'object_relation': 'creation-time'}
    )
    __description_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'description'}
    )
    __entropy_attribute = Mapping(
        **{'type': 'float', 'object_relation': 'entropy'}
    )
    __file_encoding_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'file-encoding'}
    )
    __filename_attribute = Mapping(
        **{'type': 'filename', 'object_relation': 'filename'}
    )
    __imphash_attribute = Mapping(
        **{'type': 'imphash', 'object_relation': 'imphash'}
    )
    __language_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'language'}
    )
    __md5_attribute = Mapping(
        **{'type': 'md5', 'object_relation': 'md5'}
    )
    __mime_type_attribute = Mapping(
        **{'type': 'mime-type', 'object_relation': 'mimetype'}
    )
    __modification_time_attribute = Mapping(
        **{'type': 'datetime', 'object_relation': 'modification-time'}
    )
    __name_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'name'}
    )
    __path_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'path'}
    )
    __references_attribute = Mapping(
        **{'type': 'link', 'object_relation': 'references'}
    )
    __sha1_attribute = Mapping(
        **{'type': 'sha1', 'object_relation': 'sha1'}
    )
    __sha256_attribute = Mapping(
        **{'type': 'sha256', 'object_relation': 'sha256'}
    )
    __sha3_256_attribute = Mapping(
        **{'type': 'sha3-256', 'object_relation': 'sha3-256'}
    )
    __sha3_512_attribute = Mapping(
        **{'type': 'sha3-512', 'object_relation': 'sha3-512'}
    )
    __sha512_attribute = Mapping(
        **{'type': 'sha512', 'object_relation': 'sha512'}
    )
    __size_in_bytes_attribute = Mapping(
        **{'type': 'size-in-bytes', 'object_relation': 'size-in-bytes'}
    )
    __ssdeep_attribute = Mapping(
        **{'type': 'ssdeep', 'object_relation': 'ssdeep'}
    )
    __summary_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'summary'}
    )
    __text_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'text'}
    )
    __tlsh_attribute = Mapping(
        **{'type': 'tlsh', 'object_relation': 'tlsh'}
    )
    __url_attribute = Mapping(
        **{'type': 'url', 'object_relation': 'url'}
    )

    __timeline_mapping = Mapping(
        **{
            'indicator': ('valid_from', 'valid_until'),
            'observed-data': ('first_observed', 'last_observed')
        }
    )

    @classmethod
    def access_time_attribute(cls) -> dict:
        return cls.__access_time_attribute

    @classmethod
    def alias_attribute(cls) -> dict:
        return cls.__alias_attribute

    @classmethod
    def creation_time_attribute(cls) -> dict:
        return cls.__creation_time_attribute

    @classmethod
    def description_attribute(cls) -> dict:
        return cls.__description_attribute

    @classmethod
    def entropy_attribute(cls) -> dict:
        return cls.__entropy_attribute

    @classmethod
    def file_encoding_attribute(cls) -> dict:
        return cls.__file_encoding_attribute

    @classmethod
    def filename_attribute(cls) -> dict:
        return cls.__filename_attribute

    @classmethod
    def imphash_attribute(cls) -> dict:
        return cls.__imphash_attribute

    @classmethod
    def language_attribute(cls) -> dict:
        return cls.__language_attribute

    @classmethod
    def md5_attribute(cls) -> dict:
        return cls.__md5_attribute

    @classmethod
    def mime_type_attribute(cls) -> dict:
        return cls.__mime_type_attribute

    @classmethod
    def modification_time_attribute(cls) -> dict:
        return cls.__modification_time_attribute

    @classmethod
    def name_attribute(cls) -> dict:
        return cls.__name_attribute

    @classmethod
    def path_attribute(cls) -> dict:
        return cls.__path_attribute

    @classmethod
    def references_attribute(cls) -> dict:
        return cls.__references_attribute

    @classmethod
    def sha1_attribute(cls) -> dict:
        return cls.__sha1_attribute

    @classmethod
    def sha256_attribute(cls) -> dict:
        return cls.__sha256_attribute

    @classmethod
    def sha3_256_attribute(cls) -> dict:
        return cls.__sha3_256_attribute

    @classmethod
    def sha3_512_attribute(cls) -> dict:
        return cls.__sha3_512_attribute

    @classmethod
    def sha512_attribute(cls) -> dict:
        return cls.__sha512_attribute

    @classmethod
    def size_in_bytes_attribute(cls) -> dict:
        return cls.__size_in_bytes_attribute

    @classmethod
    def ssdeep_attribute(cls) -> dict:
        return cls.__ssdeep_attribute

    @classmethod
    def summary_attribute(cls) -> dict:
        return cls.__summary_attribute

    @classmethod
    def text_attribute(cls) -> dict:
        return cls.__text_attribute

    @classmethod
    def timeline_mapping(cls, field: str) -> Union[tuple, None]:
        return cls.__timeline_mapping.get(field)

    @classmethod
    def tlsh_attribute(cls) -> dict:
        return cls.__tlsh_attribute

    @classmethod
    def url_attribute(cls) -> dict:
        return cls.__url_attribute


class ExternalSTIX2Mapping(STIX2Mapping, metaclass=ABCMeta):
    __galaxy_name_mapping = Mapping(
        **{
            "attack-pattern": {
                "name": "Attack Pattern",
                "description": "Attack Patterns are a type of TTP that describe ways that adversaries attempt to compromise targets. Attack Patterns are used to help categorize attacks, generalize specific attacks to the patterns that they follow, and provide detailed information about how attacks are performed.",
                "icon": "map"
            },
            "campaign": {
                "name": "Campaign",
                "description": "A Campaign is a grouping of adversarial behaviors that describes a set of malicious activities or attacks (sometimes called waves) that occur over a period of time against a specific set of targets. Campaigns usually have well defined objectives and may be part of an Intrusion Set.",
                "icon": "user-secret"
            },
            "country": {
                "name": "Country",
                "description": "Country meta information based on the database provided by geonames.org."
            },
            "course-of-action": {
                "name": "Course of Action",
                "description": "A Course of Action is an action taken either to prevent an attack or to respond to an attack that is in progress. It may describe technical, automatable responses (applying patches, reconfiguring firewalls) but can also describe higher level actions like employee training or policy changes.",
                "icon": "link"
            },
            "intrusion-set": {
                "name": "Intrusion Set",
                "description": "An Intrusion Set is a grouped set of adversarial behaviors and resources with common properties that is believed to be orchestrated by a single organization. An Intrusion Set may capture multiple Campaigns or other activities that are all tied together by shared attributes indicating a commonly known or unknown Threat Actor.",
                "icon": "user-secret"
            },
            "malware": {
                "name": "Malware",
                "description": "Malware is a type of TTP that represents malicious code. It generally refers to a program that is inserted into a system, usually covertly. The intent is to compromise the confidentiality, integrity, or availability of the victim's data, applications, or operating system (OS) or otherwise annoy or disrupt the victim.",
                "icon": "optin-monster"
            },
            "region": {
                "name": "Regions UN M49",
                "description": "Regions based on UN M49."
            },
            "sector": {
                "name": "Sector",
                "description": "Activity sectors"
            },
            "threat-actor": {
                "name": "Threat Actor",
                "description": "Threat Actors are actual individuals, groups, or organizations believed to be operating with malicious intent. A Threat Actor is not an Intrusion Set but may support or be affiliated with various Intrusion Sets, groups, or organizations over time.",
                "icon": "user-secret"
            },
            "tool": {
                "name": "Tool",
                "description": "Tools are legitimate software that can be used by threat actors to perform attacks. Knowing how and when threat actors use such tools can be important for understanding how campaigns are executed. Unlike malware, these tools or software packages are often found on a system and have legitimate purposes for power users, system administrators, network administrators, or even normal users.",
                "icon": "gavel"
            },
            "vulnerability": {
                "name": "Vulnerability",
                "description": "A Vulnerability is a weakness or defect in the requirements, designs, or implementations of the computational logic (e.g., code) found in software and some hardware components (e.g., firmware) that can be directly exploited to negatively impact the confidentiality, integrity, or availability of that system.",
                "icon": "bug"
            }
        }
    )

    @classmethod
    def galaxy_name_mapping(cls, field) -> Union[dict, None]:
        return cls.__galaxy_name_mapping.get(field)


class InternalSTIX2Mapping(STIX2Mapping, metaclass=ABCMeta):
    __attachment_attribute = Mapping(
        **{'type': 'attachment', 'object_relation': 'attachment'}
    )
    __comment_text_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'comment'}
    )
    __script_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'script'}
    )
    __state_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'state'}
    )

    __attributes_mapping = {
        'vulnerability': '_parse_vulnerability_attribute'
    }
    __dash_meta_fields = (
        'x_misp_attribution_confidence',
        'x_misp_calling_code',
        'x_misp_cfr_suspected_state_sponsor',
        'x_misp_cfr_suspected_victims',
        'x_misp_cfr_target_category',
        'x_misp_cfr_type_of_incident',
        'x_misp_colt_average',
        'x_misp_colt_median',
        'x_misp_iso_code',
        'x_misp_member_of',
        'x_misp_mode_of_operation',
        'x_misp_official_languages',
        'x_misp_official_refs',
        'x_misp_payment_method',
        'x_misp_ransomenotes_refs',
        'x_misp_ransomnotes_filenames',
        'x_misp_ransomnotes_refs',
        'x_misp_spoken_language',
        'x_misp_suspected_victims',
        'x_misp_target_category',
        'x_misp_territory_type',
        'x_misp_threat_actor_classification',
        'x_misp_top_level_domain'
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

    @classmethod
    def attachment_attribute(cls) -> dict:
        return cls.__attachment_attribute

    @classmethod
    def attributes_mapping(cls, field: str) -> Union[str, None]:
        return cls.__attributes_mapping.get(field)

    @classmethod
    def comment_text_attribute(cls) -> dict:
        return cls.__comment_text_attribute

    @classmethod
    def dash_meta_fields(cls) -> tuple:
        return cls.__dash_meta_fields

    @classmethod
    def objects_mapping(cls, field: str) -> Union[str, None]:
        return cls.__objects_mapping.get(field)

    @classmethod
    def script_attribute(cls) -> dict:
        return cls.__script_attribute

    @classmethod
    def state_attribute(cls) -> dict:
        return cls.__state_attribute
