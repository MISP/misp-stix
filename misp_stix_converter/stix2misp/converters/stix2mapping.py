#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ... import Mapping
from abc import ABCMeta
from typing import Union


class STIX2Mapping:
    # SINGLE ATTRIBUTES MAPPING
    __access_time_attribute = Mapping(
        **{'type': 'datetime', 'object_relation': 'access-time'}
    )
    __account_type_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'account-type'}
    )
    __address_family_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'address-family'}
    )
    __alias_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'alias'}
    )
    __args_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'args'}
    )
    __asn_attribute = Mapping(
        **{'type': 'AS', 'object_relation': 'asn'}
    )
    __can_escalate_privs_attribute = Mapping(
        **{'type': 'boolean', 'object_relation': 'can_escalate_privs'}
    )
    __command_line_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'command-line'}
    )
    __comment_attribute = Mapping(
        **{'type': 'comment', 'object_relation': 'comment'}
    )
    __content_type_attribute = Mapping(
        **{'type': 'other', 'object_relation': 'content-type'}
    )
    __cookie_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'cookie'}
    )
    __cpe_attribute = Mapping(
        **{'type': 'cpe', 'object_relation': 'cpe'}
    )
    __created_attribute = Mapping(
        **{'type': 'datetime', 'object_relation': 'created'}
    )
    __creation_time_attribute = Mapping(
        **{'type': 'datetime', 'object_relation': 'creation-time'}
    )
    __current_directory_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'current-directory'}
    )
    __data_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'data'}
    )
    __data_type_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'data-type'}
    )
    __description_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'description'}
    )
    __disabled_attribute = Mapping(
        **{'type': 'boolean', 'object_relation': 'disabled'}
    )
    __display_name_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'display-name'}
    )
    __domain_attribute = Mapping(
        **{'type': 'domain', 'object_relation': 'domain'}
    )
    __domain_family_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'domain-family'}
    )
    __dst_port_attribute = Mapping(
        **{'type': 'port', 'object_relation': 'dst-port'}
    )
    __email_body_attribute = Mapping(
        **{'type': 'email-body', 'object_relation': 'email-body'}
    )
    __email_subject_attribute = Mapping(
        **{'type': 'email-subject', 'object_relation': 'subject'}
    )
    __entropy_attribute = Mapping(
        **{'type': 'float', 'object_relation': 'entropy'}
    )
    __entrypoint_address_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'entrypoint-address'}
    )
    __expires_attribute = Mapping(
        **{'type': 'datetime', 'object_relation': 'expires'}
    )
    __file_encoding_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'file-encoding'}
    )
    __filename_attribute = Mapping(
        **{'type': 'filename', 'object_relation': 'filename'}
    )
    __first_login_attribute = Mapping(
        **{'type': 'datetime', 'object_relation': 'first_login'}
    )
    __first_packet_seen_attribute = Mapping(
        **{'type': 'datetime', 'object_relation': 'first-packet-seen'}
    )
    __hidden_attribute = Mapping(
        **{'type': 'boolean', 'object_relation': 'hidden'}
    )
    __imphash_attribute = Mapping(
        **{'type': 'imphash', 'object_relation': 'imphash'}
    )
    __ip_attribute = Mapping(
        **{'type': 'ip-dst', 'object_relation': 'ip'}
    )
    __ip_dst_attribute = Mapping(
        **{'type': 'ip-dst', 'object_relation': 'ip-dst'}
    )
    __ip_src_attribute = Mapping(
        **{'type': 'ip-src', 'object_relation': 'ip-src'}
    )
    __is_self_signed_attribute = Mapping(
        **{'type': 'boolean', 'object_relation': 'self_signed'}
    )
    __is_service_account_attribute = Mapping(
        **{'type': 'boolean', 'object_relation': 'is_service_account'}
    )
    __issuer_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'issuer'}
    )
    __language_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'language'}
    )
    __last_login_attribute = Mapping(
        **{'type': 'datetime', 'object_relation': 'last_login'}
    )
    __last_modified_attribute = Mapping(
        **{'type': 'datetime', 'object_relation': 'last-modified'}
    )
    __last_packet_seen_attribute = Mapping(
        **{'type': 'datetime', 'object_relation': 'last-packet-seen'}
    )
    __md5_attribute = Mapping(
        **{'type': 'md5', 'object_relation': 'md5'}
    )
    __message_id_attribute = Mapping(
        **{'type': 'email-message-id', 'object_relation': 'message-id'}
    )
    __method_attribute = Mapping(
        **{'type': 'http-method', 'object_relation': 'method'}
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
    __number_of_sections_attribute = Mapping(
        **{'type': 'counter', 'object_relation': 'number-sections'}
    )
    __password_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'password'}
    )
    __password_last_changed_attribute = Mapping(
        **{'type': 'datetime', 'object_relation': 'password_last_changed'}
    )
    __path_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'path'}
    )
    __pid_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'pid'}
    )
    __privileged_attribute = Mapping(
        **{'type': 'boolean', 'object_relation': 'privileged'}
    )
    __pubkey_info_algorithm_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'pubkey-info-algorithm'}
    )
    __pubkey_info_exponent_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'pubkey-info-exponent'}
    )
    __pubkey_info_modulus_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'pubkey-info-modulus'}
    )
    __reference_attribute = Mapping(
        **{'type': 'link', 'object_relation': 'reference'}
    )
    __references_attribute = Mapping(
        **{'type': 'link', 'object_relation': 'references'}
    )
    __referer_attribute = Mapping(
        **{'type': 'other', 'object_relation': 'referer'}
    )
    __regkey_attribute = Mapping(
        **{'type': 'regkey', 'object_relation': 'key'}
    )
    __reply_to_attribute = Mapping(
        **{'type': 'email-reply-to', 'object_relation': 'reply-to'}
    )
    __send_date_attribute = Mapping(
        **{'type': 'datetime', 'object_relation': 'send-date'}
    )
    __serial_number_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'serial-number'}
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
    __sigma_attribute = Mapping(
        **{'type': 'sigma', 'object_relation': 'sigma'}
    )
    __sigma_rule_name_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'sigma-rule-name'}
    )
    __signature_algorithm_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'signature_algorithm'}
    )
    __size_in_bytes_attribute = Mapping(
        **{'type': 'size-in-bytes', 'object_relation': 'size-in-bytes'}
    )
    __snort_attribute = Mapping(
        **{'type': 'snort', 'object_relation': 'suricata'}
    )
    __src_port_attribute = Mapping(
        **{'type': 'port', 'object_relation': 'src-port'}
    )
    __ssdeep_attribute = Mapping(
        **{'type': 'ssdeep', 'object_relation': 'ssdeep'}
    )
    __subject_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'subject'}
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
    __type_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'type'}
    )
    __uri_attribute = Mapping(
        **{'type': 'uri', 'object_relation': 'uri'}
    )
    __url_attribute = Mapping(
        **{'type': 'url', 'object_relation': 'url'}
    )
    __user_agent_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'user-agent'}
    )
    __user_id_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'user-id'}
    )
    __username_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'username'}
    )
    __validity_not_after_attribute = Mapping(
        **{'type': 'datetime', 'object_relation': 'validity-not-after'}
    )
    __validity_not_before_attribute = Mapping(
        **{'type': 'datetime', 'object_relation': 'validity-not-before'}
    )
    __vendor_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'vendor'}
    )
    __version_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'version'}
    )
    __x_mailer_attribute = Mapping(
        **{'type': 'email-x-mailer', 'object_relation': 'x-mailer'}
    )
    __x509_md5_attribute = Mapping(
        **{
            'type': 'x509-fingerprint-md5',
            'object_relation': 'x509-fingerprint-md5'
        }
    )
    __x509_sha1_attribute = Mapping(
        **{
            'type': 'x509-fingerprint-sha1',
            'object_relation': 'x509-fingerprint-sha1'
        }
    )
    __x509_sha256_attribute = Mapping(
        **{
            'type': 'x509-fingerprint-sha256',
            'object_relation': 'x509-fingerprint-sha256'
        }
    )
    __yara_attribute = Mapping(
        **{'type': 'yara', 'object_relation': 'yara'}
    )
    __yara_rule_name_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'yara-rule-name'}
    )

    # MISP OBJECTS MAPPING
    __connection_protocols = Mapping(
        **{
            **dict.fromkeys(('tcp', 'TCP', 'udp', 'UDP'), '4'),
            **dict.fromkeys(
                (
                    'arp', 'icmp', 'ip', 'ipv4', 'ipv6',
                    'ARP', 'ICMP', 'IP', 'IPV4', 'IPV6'
                ),
                '3'
            ),
            **dict.fromkeys(
                ('http', 'HTTP', 'https', 'HTTPS', 'ftp', 'FTP'), '7'
            )
        }
    )
    __network_socket_extension_mapping = Mapping(
        address_family=__address_family_attribute,
        protocol_family=__domain_family_attribute,
        socket_type={'type': 'text', 'object_relation': 'socket-type'}
    )
    __registry_key_values_mapping = Mapping(
        data=__data_attribute,
        data_type=__data_type_attribute,
        name=__name_attribute
    )
    __unix_user_account_extention_mapping = Mapping(
        gid={'type': 'text', 'object_relation': 'group-id'},
        groups={'type': 'text', 'object_relation': 'group'},
        home_dir={'type': 'text', 'object_relation': 'home_dir'},
        shell={'type': 'text', 'object_relation': 'shell'}
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
    def account_type_attribute(cls) -> dict:
        return cls.__account_type_attribute

    @classmethod
    def address_family_attribute(cls) -> dict:
        return cls.__address_family_attribute

    @classmethod
    def alias_attribute(cls) -> dict:
        return cls.__alias_attribute

    @classmethod
    def args_attribute(cls) -> dict:
        return cls.__args_attribute

    @classmethod
    def asn_attribute(cls) -> dict:
        return cls.__asn_attribute

    @classmethod
    def can_escalate_privs_attribute(cls) -> dict:
        return cls.__can_escalate_privs_attribute

    @classmethod
    def command_line_attribute(cls) -> dict:
        return cls.__command_line_attribute

    @classmethod
    def comment_attribute(cls) -> dict:
        return cls.__comment_attribute

    @classmethod
    def connection_protocols(cls, field: str) -> Union[str, None]:
        return cls.__connection_protocols.get(field)

    @classmethod
    def content_type_attribute(cls) -> dict:
        return cls.__content_type_attribute

    @classmethod
    def cookie_attribute(cls) -> dict:
        return cls.__cookie_attribute

    @classmethod
    def cpe_attribute(cls) -> dict:
        return cls.__cpe_attribute

    @classmethod
    def created_attribute(cls) -> dict:
        return cls.__created_attribute

    @classmethod
    def creation_time_attribute(cls) -> dict:
        return cls.__creation_time_attribute

    @classmethod
    def current_directory_attribute(cls) -> dict:
        return cls.__current_directory_attribute

    @classmethod
    def description_attribute(cls) -> dict:
        return cls.__description_attribute

    @classmethod
    def disabled_attribute(cls) -> dict:
        return cls.__disabled_attribute

    @classmethod
    def display_name_attribute(cls) -> dict:
        return cls.__display_name_attribute

    @classmethod
    def domain_attribute(cls) -> dict:
        return cls.__domain_attribute

    @classmethod
    def domain_family_attribute(cls) -> dict:
        return cls.__domain_family_attribute

    @classmethod
    def dst_port_attribute(cls) -> dict:
        return cls.__dst_port_attribute

    @classmethod
    def email_body_attribute(cls) -> dict:
        return cls.__email_body_attribute

    @classmethod
    def email_subject_attribute(cls) -> dict:
        return cls.__email_subject_attribute

    @classmethod
    def entropy_attribute(cls) -> dict:
        return cls.__entropy_attribute

    @classmethod
    def entrypoint_address_attribute(cls) -> dict:
        return cls.__entrypoint_address_attribute

    @classmethod
    def expires_attribute(cls) -> dict:
        return cls.__expires_attribute

    @classmethod
    def file_encoding_attribute(cls) -> dict:
        return cls.__file_encoding_attribute

    @classmethod
    def filename_attribute(cls) -> dict:
        return cls.__filename_attribute

    @classmethod
    def first_login_attribute(cls) -> dict:
        return cls.__first_login_attribute

    @classmethod
    def first_packet_seen_attribute(cls) -> dict:
        return cls.__first_packet_seen_attribute

    @classmethod
    def hidden_attribute(cls) -> dict:
        return cls.__hidden_attribute

    @classmethod
    def imphash_attribute(cls) -> dict:
        return cls.__imphash_attribute

    @classmethod
    def ip_attribute(cls) -> dict:
        return cls.__ip_attribute

    @classmethod
    def ip_dst_attribute(cls) -> dict:
        return cls.__ip_dst_attribute

    @classmethod
    def ip_src_attribute(cls) -> dict:
        return cls.__ip_src_attribute

    @classmethod
    def is_self_signed_attribute(cls) -> dict:
        return cls.__is_self_signed_attribute

    @classmethod
    def is_service_account_attribute(cls) -> dict:
        return cls.__is_service_account_attribute

    @classmethod
    def issuer_attribute(cls) -> dict:
        return cls.__issuer_attribute

    @classmethod
    def language_attribute(cls) -> dict:
        return cls.__language_attribute

    @classmethod
    def last_login_attribute(cls) -> dict:
        return cls.__last_login_attribute

    @classmethod
    def last_modified_attribute(cls) -> dict:
        return cls.__last_modified_attribute

    @classmethod
    def last_packet_seen_attribute(cls) -> dict:
        return cls.__last_packet_seen_attribute

    @classmethod
    def md5_attribute(cls) -> dict:
        return cls.__md5_attribute

    @classmethod
    def message_id_attribute(cls) -> dict:
        return cls.__message_id_attribute

    @classmethod
    def method_attribute(cls) -> dict:
        return cls.__method_attribute

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
    def network_socket_extension_mapping(cls) -> dict:
        return cls.__network_socket_extension_mapping

    @classmethod
    def number_of_sections_attribute(cls) -> dict:
        return cls.__number_of_sections_attribute

    @classmethod
    def password_attribute(cls) -> dict:
        return cls.__password_attribute

    @classmethod
    def password_last_changed_attribute(cls) -> dict:
        return cls.__password_last_changed_attribute

    @classmethod
    def path_attribute(cls) -> dict:
        return cls.__path_attribute

    @classmethod
    def pid_attribute(cls) -> dict:
        return cls.__pid_attribute

    @classmethod
    def privileged_attribute(cls) -> dict:
        return cls.__privileged_attribute

    @classmethod
    def pubkey_info_algorithm_attribute(cls) -> dict:
        return cls.__pubkey_info_algorithm_attribute

    @classmethod
    def pubkey_info_exponent_attribute(cls) -> dict:
        return cls.__pubkey_info_exponent_attribute

    @classmethod
    def pubkey_info_modulus_attribute(cls) -> dict:
        return cls.__pubkey_info_modulus_attribute

    @classmethod
    def references_attribute(cls) -> dict:
        return cls.__references_attribute

    @classmethod
    def referer_attribute(cls) -> dict:
        return cls.__referer_attribute

    @classmethod
    def registry_key_values_mapping(cls) -> dict:
        return cls.__registry_key_values_mapping

    @classmethod
    def regkey_attribute(cls) -> dict:
        return cls.__regkey_attribute

    @classmethod
    def reply_to_attribute(cls) -> dict:
        return cls.__reply_to_attribute

    @classmethod
    def send_date_attribute(cls) -> dict:
        return cls.__send_date_attribute

    @classmethod
    def serial_number_attribute(cls) -> dict:
        return cls.__serial_number_attribute

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
    def sigma_attribute(cls) -> dict:
        return cls.__sigma_attribute

    @classmethod
    def sigma_reference_attribute(cls) -> dict:
        return cls.__reference_attribute

    @classmethod
    def sigma_rule_name_attribute(cls) -> dict:
        return cls.__sigma_rule_name_attribute

    @classmethod
    def signature_algorithm_attribute(cls) -> dict:
        return cls.__signature_algorithm_attribute

    @classmethod
    def size_in_bytes_attribute(cls) -> dict:
        return cls.__size_in_bytes_attribute

    @classmethod
    def snort_attribute(cls) -> dict:
        return cls.__snort_attribute

    @classmethod
    def src_port_attribute(cls) -> dict:
        return cls.__src_port_attribute

    @classmethod
    def ssdeep_attribute(cls) -> dict:
        return cls.__ssdeep_attribute

    @classmethod
    def subject_attribute(cls) -> dict:
        return cls.__subject_attribute

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
    def type_attribute(cls) -> dict:
        return cls.__type_attribute

    @classmethod
    def uri_attribute(cls) -> dict:
        return cls.__uri_attribute

    @classmethod
    def url_attribute(cls) -> dict:
        return cls.__url_attribute

    @classmethod
    def unix_user_account_extention_mapping(cls) -> dict:
        return cls.__unix_user_account_extention_mapping

    @classmethod
    def user_agent_attribute(cls) -> dict:
        return cls.__user_agent_attribute

    @classmethod
    def user_id_attribute(cls) -> dict:
        return cls.__user_id_attribute

    @classmethod
    def username_attribute(cls) -> dict:
        return cls.__username_attribute

    @classmethod
    def validity_not_after_attribute(cls) -> dict:
        return cls.__validity_not_after_attribute

    @classmethod
    def validity_not_before_attribute(cls) -> dict:
        return cls.__validity_not_before_attribute

    @classmethod
    def vendor_attribute(cls) -> dict:
        return cls.__vendor_attribute

    @classmethod
    def version_attribute(cls) -> dict:
        return cls.__version_attribute

    @classmethod
    def x_mailer_attribute(cls) -> dict:
        return cls.__x_mailer_attribute

    @classmethod
    def x509_md5_attribute(cls) -> dict:
        return cls.__x509_md5_attribute

    @classmethod
    def x509_sha1_attribute(cls) -> dict:
        return cls.__x509_sha1_attribute

    @classmethod
    def x509_sha256_attribute(cls) -> dict:
        return cls.__x509_sha256_attribute

    @classmethod
    def yara_attribute(cls) -> dict:
        return cls.__yara_attribute

    @classmethod
    def yara_reference_attribute(cls) -> dict:
        return cls.__reference_attribute

    @classmethod
    def yara_rule_name_attribute(cls) -> dict:
        return cls.__yara_rule_name_attribute


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
    # SINGLE ATTRIBUTES
    __attachment_attribute = Mapping(
        **{'type': 'attachment', 'object_relation': 'attachment'}
    )
    __authentihash_attribute = Mapping(
        **{'type': 'authentihash', 'object_relation': 'authentihash'}
    )
    __comment_text_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'comment'}
    )
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
    __parent_command_line_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'parent-command-line'}
    )
    __parent_guid_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'parent-guid'}
    )
    __parent_pid_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'parent-pid'}
    )
    __parent_process_name_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'parent-process-name'}
    )
    __parent_process_path_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'parent-process-path'}
    )
    __protocol_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'protocol'}
    )
    __script_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'script'}
    )
    __sha224_attribute = Mapping(
        **{'type': 'sha224', 'object_relation': 'sha224'}
    )
    __sha3_224_attribute = Mapping(
        **{'type': 'sha3-224', 'object_relation': 'sha3-224'}
    )
    __sha3_384_attribute = Mapping(
        **{'type': 'sha3-384', 'object_relation': 'sha3-384'}
    )
    __sha384_attribute = Mapping(
        **{'type': 'sha384', 'object_relation': 'sha384'}
    )
    __src_as_attribute = Mapping(
        **{'type': 'AS', 'object_relation': 'src-as'}
    )
    __state_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'state'}
    )
    __tcp_flags_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'tcp-flags'}
    )
    __telfhash_attribute = Mapping(
        **{'type': 'telfhash', 'object_relation': 'telfhash'}
    )
    __vhash_attribute = Mapping(
        **{'type': 'vhash', 'object_relation': 'vhash'}
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

    # OBJECT ATTRIBUTES
    __account_id_attribute = {'type': 'text', 'object_relation': 'account-id'}
    __account_name_attribute = {'type': 'text', 'object_relation': 'account-name'}
    __archive_attribute = {'type': 'link', 'object_relation': 'archive'}
    __bio_attribute = {'type': 'text', 'object_relation': 'bio'}
    __community_id_attribute = {'type': 'community-id', 'object_relation': 'community-id'}
    __compilation_timestamp_attribute = {'type': 'datetime', 'object_relation': 'compilation-timestamp'}
    __first_seen_attribute = {'type': 'datetime', 'object_relation': 'first-seen'}
    __followers_attribute = {'type': 'text', 'object_relation': 'followers'}
    __following_attribute = {'type': 'text', 'object_relation': 'following'}
    __format_attribute = {'type': 'text', 'object_relation': 'format'}
    __fullpath_attribute = {'type': 'text', 'object_relation': 'fullpath'}
    __guid_attribute = {'type': 'text', 'object_relation': 'guid'}
    __header_attribute = {'type': 'text', 'object_relation': 'header'}
    __hostname_attribute = {'type': 'hostname', 'object_relation': 'hostname'}
    __id_attribute = {'type': 'text', 'object_relation': 'id'}
    __image_text_attribute = {'type': 'text', 'object_relation': 'image-text'}
    __last_seen_attribute = {'type': 'datetime', 'object_relation': 'last-seen'}
    __likes_attribute = {'type': 'text', 'object_relation': 'likes'}
    __link_attribute = {'type': 'link', 'object_relation': 'link'}
    __lnk_access_time_attribute = {'type': 'datetime', 'object_relation': 'lnk-access-time'}
    __lnk_creation_time_attribute = {'type': 'datetime', 'object_relation': 'lnk-creation-time'}
    __lnk_modification_time_attribute = {'type': 'datetime', 'object_relation': 'lnk-modification-time'}
    __packet_count_attribute = {'type': 'counter', 'object_relation': 'packet-count'}
    __pattern_in_file_attribute = {'type': 'pattern-in-file', 'object_relation': 'pattern-in-file'}
    __pgid_attribute = {'type': 'text', 'object_relation': 'pgid'}
    __port_attribute = {'type': 'port', 'object_relation': 'port'}
    __process_state_attribute = {'type': 'process-state', 'object_relation': 'process-state'}
    __proxy_password_attribute = {'type': 'text', 'object_relation': 'proxy-password'}
    __proxy_user_attribute = {'type': 'text', 'object_relation': 'proxy-user'}
    __start_time_attribute = {'type': 'datetime', 'object_relation': 'start-time'}
    __user_avatar_attribute = {'type': 'attachment', 'object_relation': 'user-avatar'}
    __user_creator_attribute = {'type': 'text', 'object_relation': 'user-creator'}
    __user_process_attribute = {'type': 'text', 'object_relation': 'user-process'}
    __verified_attribute = {'type': 'text', 'object_relation': 'verified'}

    # OBJECTS MAPPING
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
    __android_app_object_mapping = Mapping(
        name=STIX2Mapping.name_attribute(),
        x_misp_appid={'type': 'text', 'object_relation': 'appid'},
        x_misp_certificate={'type': 'sha1', 'object_relation': 'certificate'},
        x_misp_domain=STIX2Mapping.domain_attribute(),
        x_misp_sha256=STIX2Mapping.sha256_attribute()
    )
    __asn_object_mapping = Mapping(
        number=STIX2Mapping.asn_attribute(),
        name=STIX2Mapping.description_attribute(),
        x_misp_country={'type': 'text', 'object_relation': 'country'},
        x_misp_export={'type': 'text', 'object_relation': 'export'},
        x_misp_first_seen=__first_seen_attribute,
        x_misp_import={'type': 'text', 'object_relation': 'import'},
        x_misp_last_seen=__last_seen_attribute,
        x_misp_mp_export={'type': 'text', 'object_relation': 'mp-export'},
        x_misp_mp_import={'type': 'text', 'object_relation': 'mp-import'},
        x_misp_subnet_announced={'type': 'ip-src', 'object_relation': 'subnet-announced'}
    )
    __cpe_asset_object_mapping = Mapping(
        cpe=STIX2Mapping.cpe_attribute(),
        languages=STIX2Mapping.language_attribute(),
        name={'type': 'text', 'object_relation': 'product'},
        vendor=STIX2Mapping.vendor_attribute(),
        version=STIX2Mapping.version_attribute(),
        x_misp_description=STIX2Mapping.description_attribute(),
        x_misp_other={'type': 'text', 'object_relation': 'other'},
        x_misp_part={'type': 'text', 'object_relation': 'part'},
        x_misp_product={'type': 'text', 'object_relation': 'product'},
        x_misp_sw_edition={'type': 'text', 'object_relation': 'sw_edition'},
        x_misp_target_hw={'type': 'text', 'object_relation': 'target_hw'},
        x_misp_target_sw={'type': 'text', 'object_relation': 'target_sw'},
        x_misp_update={'type': 'text', 'object_relation': 'update'}
    )
    __credential_object_mapping = Mapping(
        user_id=STIX2Mapping.username_attribute(),
        credential=STIX2Mapping.password_attribute(),
        x_misp_password=STIX2Mapping.password_attribute(),
        x_misp_format=__format_attribute,
        x_misp_notification={'type': 'text', 'object_relation': 'notification'},
        x_misp_origin={'type': 'text', 'object_relation': 'origin'},
        x_misp_text=STIX2Mapping.text_attribute(),
        x_misp_type=STIX2Mapping.type_attribute()
    )
    __domain_ip_object_mapping = Mapping(
        value=STIX2Mapping.domain_attribute(),
        x_misp_first_seen=__first_seen_attribute,
        x_misp_hostname=__hostname_attribute,
        x_misp_last_seen=__last_seen_attribute,
        x_misp_port=__port_attribute,
        x_misp_registration_date={'type': 'datetime', 'object_relation': 'registration-date'},
        x_misp_text=STIX2Mapping.text_attribute()
    )
    __email_object_mapping = Mapping(
        body=STIX2Mapping.email_body_attribute(),
        date=STIX2Mapping.send_date_attribute(),
        message_id=STIX2Mapping.message_id_attribute(),
        subject=STIX2Mapping.email_subject_attribute(),
        x_misp_attachment={'type': 'email-attachment', 'object_relation': 'attachment'},
        x_misp_from_domain={'type': 'domain', 'object_relation': 'from-domain'},
        x_misp_ip_src=STIX2Mapping.ip_src_attribute(),
        x_misp_message_id=STIX2Mapping.message_id_attribute(),
        x_misp_mime_boundary={'type': 'email-mime-boundary', 'object_relation': 'mime-boundary'},
        x_misp_received_header_hostname={'type': 'hostname', 'object_relation': 'received-header-hostname'},
        x_misp_received_header_ip={'type': 'ip-src', 'object_relation': 'received-header-ip'},
        x_misp_reply_to_display_name={'type': 'email-dst-display-name', 'object_relation': 'reply-to-display-name'},
        x_misp_return_path={'type': 'email-src', 'object_relation': 'return-path'},
        x_misp_screenshot={'type': 'attachment', 'object_relation': 'screenshot'},
        x_misp_thread_index={'type': 'email-thread-index', 'object_relation': 'thread-index'},
        x_misp_user_agent=STIX2Mapping.user_agent_attribute()
    )
    __facebook_account_object_mapping = Mapping(
        user_id=__account_id_attribute,
        account_login=__account_name_attribute,
        x_misp_archive=__archive_attribute,
        x_misp_attachment=__attachment_attribute,
        x_misp_description=STIX2Mapping.description_attribute(),
        x_misp_link=__link_attribute,
        x_misp_url=STIX2Mapping.url_attribute(),
        x_misp_user_avatar=__user_avatar_attribute
    )
    __file_hashes_mapping = Mapping(
        **{
            'AUTHENTIHASH': __authentihash_attribute,
            'IMPHASH': STIX2Mapping.imphash_attribute(),
            'MD5': STIX2Mapping.md5_attribute(),
            'SHA1': STIX2Mapping.sha1_attribute(),
            'SHA-1': STIX2Mapping.sha1_attribute(),
            'SHA224': __sha224_attribute,
            'SHA256': STIX2Mapping.sha256_attribute(),
            'SHA-256': STIX2Mapping.sha256_attribute(),
            'SHA3224': __sha3_224_attribute,
            'SHA3-256': STIX2Mapping.sha3_256_attribute(),
            'SHA3384': __sha3_384_attribute,
            'SHA3-512': STIX2Mapping.sha3_512_attribute(),
            'SHA384': __sha384_attribute,
            'SHA512': STIX2Mapping.sha512_attribute(),
            'SHA-512': STIX2Mapping.sha512_attribute(),
            'ssdeep': STIX2Mapping.ssdeep_attribute(),
            'SSDEEP': STIX2Mapping.ssdeep_attribute(),
            'TELFHASH': __telfhash_attribute,
            'TLSH': STIX2Mapping.tlsh_attribute(),
            'VHASH': __vhash_attribute
        }
    )
    __file_object_mapping = Mapping(
        accessed=STIX2Mapping.access_time_attribute(),
        atime=STIX2Mapping.access_time_attribute(),
        created=STIX2Mapping.creation_time_attribute(),
        ctime=STIX2Mapping.creation_time_attribute(),
        mime_type=STIX2Mapping.mime_type_attribute(),
        modified=STIX2Mapping.modification_time_attribute(),
        mtime=STIX2Mapping.modification_time_attribute(),
        name=STIX2Mapping.filename_attribute(),
        name_enc=STIX2Mapping.file_encoding_attribute(),
        size=STIX2Mapping.size_in_bytes_attribute(),
        x_misp_attachment=__attachment_attribute,
        x_misp_certificate={'type': 'x509-fingerprint-sha1', 'object_relation': 'certificate'},
        x_misp_compilation_timestamp=__compilation_timestamp_attribute,
        x_misp_entropy=STIX2Mapping.entropy_attribute(),
        x_misp_fullpath=__fullpath_attribute,
        x_misp_path=STIX2Mapping.path_attribute(),
        x_misp_pattern_in_file=__pattern_in_file_attribute,
        x_misp_state=__state_attribute,
        x_misp_text=STIX2Mapping.text_attribute()
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
        display_name=STIX2Mapping.name_attribute(),
        account_login=STIX2Mapping.username_attribute(),
        x_misp_avatar_url={'type': 'link', 'object_relation': 'avatar_url'},
        x_misp_state={'type': 'text', 'object_relation': 'state'},
        x_misp_web_url={'type': 'link', 'object_relation': 'web_url'}
    )
    __http_request_object_mapping = Mapping(
        x_misp_basicauth_password={'type': 'text', 'object_relation': 'basicauth-password'},
        x_misp_basicauth_user={'type': 'text', 'object_relation': 'basicauth-user'},
        x_misp_header=__header_attribute,
        x_misp_proxy_password=__proxy_password_attribute,
        x_misp_proxy_user=__proxy_user_attribute,
        x_misp_text=STIX2Mapping.text_attribute(),
        x_misp_url=STIX2Mapping.url_attribute()
    )
    __image_object_mapping = Mapping(
        name=STIX2Mapping.filename_attribute(),
        x_misp_archive=__archive_attribute,
        x_misp_image_text=__image_text_attribute,
        x_misp_link=__link_attribute,
        x_misp_username=STIX2Mapping.username_attribute()
    )
    __ip_port_object_mapping = Mapping(
        dst_port=STIX2Mapping.dst_port_attribute(),
        src_port=STIX2Mapping.src_port_attribute(),
        start=__first_seen_attribute,
        end=__last_seen_attribute,
        x_misp_AS={'type': 'AS', 'object_relation': 'AS'},
        x_misp_country_code={'type': 'text', 'object_relation': 'country-code'},
        x_misp_domain=STIX2Mapping.domain_attribute(),
        x_misp_hostname=__hostname_attribute,
        x_misp_ip=STIX2Mapping.ip_attribute(),
        x_misp_text=STIX2Mapping.text_attribute()
    )
    __lnk_object_mapping = Mapping(
        name=STIX2Mapping.filename_attribute(),
        accessed=__lnk_access_time_attribute,
        atime=__lnk_access_time_attribute,
        created=__lnk_creation_time_attribute,
        ctime=__lnk_creation_time_attribute,
        modified=__lnk_modification_time_attribute,
        mtime=__lnk_modification_time_attribute,
        size=STIX2Mapping.size_in_bytes_attribute(),
        x_misp_fullpath=__fullpath_attribute,
        x_misp_path=STIX2Mapping.path_attribute(),
        x_misp_birth_droid_file_identifier={'type': 'text', 'object_relation': 'birth-droid-file-identifier'},
        x_misp_birth_droid_volume_identifier={'type': 'text', 'object_relation': 'birth-droid-volume-identifier'},
        x_misp_droid_file_identifier={'type': 'text', 'object_relation': 'droid-file-identifier'},
        x_misp_droid_volume_identifier={'type': 'text', 'object_relation': 'droid-volume-identifier'},
        x_misp_entropy=STIX2Mapping.entropy_attribute(),
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
        x_misp_text=STIX2Mapping.text_attribute()
    )
    __mutex_object_mapping = Mapping(
        name=STIX2Mapping.name_attribute(),
        x_misp_description=STIX2Mapping.description_attribute(),
        x_misp_operating_system={
            'type': 'text', 'object_relation': 'operating-system'
        }
    )
    __netflow_object_mapping = Mapping(
        dst_port=STIX2Mapping.dst_port_attribute(),
        src_port=STIX2Mapping.src_port_attribute(),
        start=STIX2Mapping.first_packet_seen_attribute(),
        end=STIX2Mapping.last_packet_seen_attribute(),
        src_byte_count={'type': 'counter', 'object_relation': 'byte-count'},
        src_packets=__packet_count_attribute,
        x_misp_community_id=__community_id_attribute,
        x_misp_direction={'type': 'text', 'object_relation': 'direction'},
        x_misp_flow_count={'type': 'counter', 'object_relation': 'flow-count'},
        x_misp_ip_protocol_number={'type': '', 'object_relation': 'ip-protocol-number'},
        x_misp_ip_version={'type': 'counter', 'object_relation': 'ip_version'}
    )
    __network_connection_object_mapping = Mapping(
        dst_port=STIX2Mapping.dst_port_attribute(),
        src_port=STIX2Mapping.src_port_attribute(),
        start=STIX2Mapping.first_packet_seen_attribute(),
        x_misp_community_id=__community_id_attribute,
        x_misp_hostname_dst=__hostname_dst_attribute,
        x_misp_hostname_src=__hostname_src_attribute
    )
    __network_socket_object_mapping = Mapping(
        dst_port=STIX2Mapping.dst_port_attribute(),
        src_port=STIX2Mapping.src_port_attribute(),
        x_misp_address_family=STIX2Mapping.address_family_attribute(),
        x_misp_domain_family=STIX2Mapping.domain_family_attribute(),
        x_misp_filename=STIX2Mapping.filename_attribute(),
        x_misp_hostname_dst=__hostname_dst_attribute,
        x_misp_hostname_src=__hostname_src_attribute,
        x_misp_option={'type': 'text', 'object_relation': 'option'}
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
        x_misp_url=STIX2Mapping.url_attribute(),
        x_misp_verified={'type': 'boolean', 'object_relation': 'verified'},
    )
    __pe_object_mapping = Mapping(
        imphash=STIX2Mapping.imphash_attribute(),
        number_of_sections=STIX2Mapping.number_of_sections_attribute(),
        pe_type=STIX2Mapping.type_attribute(),
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
        x_misp_text=STIX2Mapping.text_attribute()
    )
    __pe_section_object_mapping = Mapping(
        entropy=STIX2Mapping.entropy_attribute(),
        name=STIX2Mapping.name_attribute(),
        size=STIX2Mapping.size_in_bytes_attribute(),
        x_misp_characteristic={'type': 'text', 'object_relation': 'characteristic'},
        x_misp_offset={'type': 'hex', 'object_relation': 'offset'},
        x_misp_text=STIX2Mapping.text_attribute(),
        x_misp_virtual_address={'type': 'hex', 'object_relation': 'virtual_address'},
        x_misp_virtual_size={'type': 'size-in-bytes', 'object_relation': 'virtual_size'}
    )
    __process_object_mapping = Mapping(
        arguments=STIX2Mapping.args_attribute(),
        x_misp_args=STIX2Mapping.args_attribute(),
        command_line=STIX2Mapping.command_line_attribute(),
        created=STIX2Mapping.creation_time_attribute(),
        created_time=STIX2Mapping.creation_time_attribute(),
        cwd=STIX2Mapping.current_directory_attribute(),
        is_hidden=STIX2Mapping.hidden_attribute(),
        name=STIX2Mapping.name_attribute(),
        x_misp_name=STIX2Mapping.name_attribute(),
        pid=STIX2Mapping.pid_attribute(),
        x_misp_fake_process_name={'type': 'boolean', 'object_relation': 'fake-process-name'},
        x_misp_guid=__guid_attribute,
        x_misp_integrity_level={'type': 'text', 'object_relation': 'integrity-level'},
        x_misp_pgid=__pgid_attribute,
        x_misp_port=__port_attribute,
        x_misp_process_state=__process_state_attribute,
        x_misp_start_time=__start_time_attribute,
        x_misp_user_creator=__user_creator_attribute,
        x_misp_user_process=__user_process_attribute
    )
    __reddit_account_object_mapping = Mapping(
        user_id=__account_id_attribute,
        account_login=__account_name_attribute,
        x_misp_account_avatar={'type': 'attachment', 'object_relation': 'account-avatar'},
        x_misp_account_avatar_url={'type': 'url', 'object_relation': 'account-avatar-url'},
        x_misp_archive=__archive_attribute,
        x_misp_attachment=__attachment_attribute,
        x_misp_description=STIX2Mapping.description_attribute(),
        x_misp_link=__link_attribute,
        x_misp_moderator_of={'type': '', 'object_relation': 'moderator-of'},
        x_misp_trophies={'type': '', 'object_relation': 'trophies'},
        x_misp_url=STIX2Mapping.url_attribute()
    )
    __registry_key_object_mapping = Mapping(
        key=STIX2Mapping.regkey_attribute(),
        modified=STIX2Mapping.last_modified_attribute(),
        modified_time=STIX2Mapping.last_modified_attribute(),
        x_misp_hive={'type': 'text', 'object_relation': 'hive'},
        x_misp_root_keys={'type': 'text', 'object_relation': 'root-keys'}
    )
    __telegram_account_object_mapping = Mapping(
        user_id=__id_attribute,
        account_login=STIX2Mapping.username_attribute(),
        x_misp_first_name={'type': 'text', 'object_relation': 'first_name'},
        x_misp_last_name={'type': 'text', 'object_relation': 'last_name'},
        x_misp_phone={'type': 'text', 'object_relation': 'phone'},
        x_misp_verified={'type': 'text', 'object_relation': 'verified'}
    )
    __twitter_account_object_mapping = Mapping(
        user_id=__id_attribute,
        account_login=STIX2Mapping.name_attribute(),
        display_name={'type': 'text', 'object_relation': 'displayed-name'},
        x_misp_archive=__archive_attribute,
        x_misp_attachment=__attachment_attribute,
        x_misp_bio=__bio_attribute,
        x_misp_description=STIX2Mapping.description_attribute(),
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
        x_misp_url=STIX2Mapping.url_attribute(),
        x_misp_verified=__verified_attribute
    )
    __url_object_mapping = Mapping(
        value=STIX2Mapping.url_attribute(),
        x_misp_credential={'type': 'text', 'object_relation': 'credential'},
        x_misp_domain=STIX2Mapping.domain_attribute(),
        x_misp_domain_without_tld={'type': 'text', 'object_relation': 'domain_without_tld'},
        x_misp_first_seen=__first_seen_attribute,
        x_misp_fragment={'type': 'text', 'object_relation': 'fragment'},
        x_misp_host=__host_attribute,
        x_misp_ip=STIX2Mapping.ip_attribute(),
        x_misp_last_seen=__last_seen_attribute,
        x_misp_port=__port_attribute,
        x_misp_query_string={'type': 'text', 'object_relation': 'query_string'},
        x_misp_resource_path={'type': 'text', 'object_relation': 'resource_path'},
        x_misp_scheme={'type': 'text', 'object_relation': 'scheme'},
        x_misp_subdomain={'type': 'text', 'object_relation': 'subdomain'},
        x_misp_text=STIX2Mapping.text_attribute(),
        x_misp_tld={'type': 'text', 'object_relation': 'tld'}
    )
    __user_account_object_mapping = Mapping(
        account_login=STIX2Mapping.username_attribute(),
        account_type=STIX2Mapping.account_type_attribute(),
        can_escalate_privs=STIX2Mapping.can_escalate_privs_attribute(),
        credential=STIX2Mapping.password_attribute(),
        x_misp_password=STIX2Mapping.password_attribute(),
        display_name=STIX2Mapping.display_name_attribute(),
        is_disabled=STIX2Mapping.disabled_attribute(),
        is_privileged=STIX2Mapping.privileged_attribute(),
        is_service_account=STIX2Mapping.is_service_account_attribute(),
        user_id=STIX2Mapping.user_id_attribute(),
        x_misp_description=STIX2Mapping.description_attribute(),
        x_misp_link=__link_attribute,
        x_misp_user_avatar=__user_avatar_attribute,
        account_created=STIX2Mapping.created_attribute(),
        account_expires=STIX2Mapping.expires_attribute(),
        account_first_login=STIX2Mapping.first_login_attribute(),
        account_last_login=STIX2Mapping.last_login_attribute(),
        credential_last_changed=STIX2Mapping.password_last_changed_attribute(),
        password_last_changed=STIX2Mapping.password_last_changed_attribute()
    )
    __x509_object_mapping = Mapping(
        is_self_signed=STIX2Mapping.is_self_signed_attribute(),
        issuer=STIX2Mapping.issuer_attribute(),
        serial_number=STIX2Mapping.serial_number_attribute(),
        signature_algorithm=STIX2Mapping.signature_algorithm_attribute(),
        subject=STIX2Mapping.subject_attribute(),
        subject_public_key_algorithm=STIX2Mapping.pubkey_info_algorithm_attribute(),
        subject_public_key_exponent=STIX2Mapping.pubkey_info_exponent_attribute(),
        subject_public_key_modulus=STIX2Mapping.pubkey_info_modulus_attribute(),
        validity_not_after=STIX2Mapping.validity_not_after_attribute(),
        validity_not_before=STIX2Mapping.validity_not_before_attribute(),
        version=STIX2Mapping.version_attribute(),
        x_misp_is_ca={'type': 'boolean', 'object_relation': 'is_ca'},
        x_misp_pem={'type': 'text', 'object_relation': 'pem'},
        x_misp_pubkey_info_size={'type': 'text', 'object_relation': 'pubkey-info-size'},
        x_misp_raw_base64={'type': 'text', 'object_relation': 'raw-base64'},
        x_misp_text=STIX2Mapping.text_attribute()
    )
    __x509_subject_mapping = Mapping(
        **{
            'DNS name': {'type': 'hostname', 'object_relation': 'dns_names'},
            'email': {'type': 'email-dst', 'object_relation': 'email'},
            'IP': STIX2Mapping.ip_attribute(),
            'RID': {'type': 'text', 'object_relation': 'rid'},
            'URI': STIX2Mapping.uri_attribute()
        }
    )

    @classmethod
    def android_app_object_mapping(cls) -> dict:
        return cls.__android_app_object_mapping

    @classmethod
    def asn_object_mapping(cls) -> dict:
        return cls.__asn_object_mapping

    @classmethod
    def attachment_attribute(cls) -> dict:
        return cls.__attachment_attribute

    @classmethod
    def attributes_mapping(cls, field: str) -> Union[str, None]:
        return cls.__attributes_mapping.get(field)

    @classmethod
    def authentihash_attribute(cls) -> dict:
        return cls.__authentihash_attribute

    @classmethod
    def comment_text_attribute(cls) -> dict:
        return cls.__comment_text_attribute

    @classmethod
    def cpe_asset_object_mapping(cls) -> dict:
        return cls.__cpe_asset_object_mapping

    @classmethod
    def credential_object_mapping(cls) -> dict:
        return cls.__credential_object_mapping

    @classmethod
    def dash_meta_fields(cls) -> tuple:
        return cls.__dash_meta_fields

    @classmethod
    def domain_ip_object_mapping(cls) -> dict:
        return cls.__domain_ip_object_mapping

    @classmethod
    def dst_as_attribute(cls) -> dict:
        return cls.__dst_as_attribute

    @classmethod
    def email_object_mapping(cls) -> dict:
        return cls.__email_object_mapping

    @classmethod
    def facebook_account_object_mapping(cls) -> dict:
        return cls.__facebook_account_object_mapping

    @classmethod
    def file_hashes_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__file_hashes_mapping.get(field)

    @classmethod
    def file_object_mapping(cls) -> dict:
        return cls.__file_object_mapping

    @classmethod
    def github_user_object_mapping(cls) -> dict:
        return cls.__github_user_object_mapping

    @classmethod
    def gitlab_user_object_mapping(cls) -> dict:
        return cls.__gitlab_user_object_mapping

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
    def http_request_object_mapping(cls) -> dict:
        return cls.__http_request_object_mapping

    @classmethod
    def icmp_type_attribute(cls) -> dict:
        return cls.__icmp_type_attribute

    @classmethod
    def image_object_mapping(cls) -> dict:
        return cls.__image_object_mapping

    @classmethod
    def ip_port_object_mapping(cls) -> dict:
        return cls.__ip_port_object_mapping

    @classmethod
    def lnk_object_mapping(cls) -> dict:
        return cls.__lnk_object_mapping

    @classmethod
    def mutex_object_mapping(cls) -> dict:
        return cls.__mutex_object_mapping

    @classmethod
    def netflow_object_mapping(cls) -> dict:
        return cls.__netflow_object_mapping

    @classmethod
    def network_connection_object_mapping(cls) -> dict:
        return cls.__network_connection_object_mapping

    @classmethod
    def network_socket_object_mapping(cls) -> dict:
        return cls.__network_socket_object_mapping

    @classmethod
    def objects_mapping(cls, field: str) -> Union[str, None]:
        return cls.__objects_mapping.get(field)

    @classmethod
    def parent_command_line_attribute(cls) -> dict:
        return cls.__parent_command_line_attribute

    @classmethod
    def parent_guid_attribute(cls) -> dict:
        return cls.__parent_guid_attribute

    @classmethod
    def parent_pid_attribute(cls) -> dict:
        return cls.__parent_pid_attribute

    @classmethod
    def parent_process_name_attribute(cls) -> dict:
        return cls.__parent_process_name_attribute

    @classmethod
    def parent_process_path_attribute(cls) -> dict:
        return cls.__parent_process_path_attribute

    @classmethod
    def parler_account_object_mapping(cls) -> dict:
        return cls.__parler_account_object_mapping

    @classmethod
    def pe_object_mapping(cls) -> dict:
        return cls.__pe_object_mapping

    @classmethod
    def pe_section_object_mapping(cls) -> dict:
        return cls.__pe_section_object_mapping

    @classmethod
    def process_object_mapping(cls) -> dict:
        return cls.__process_object_mapping

    @classmethod
    def protocol_attribute(cls) -> dict:
        return cls.__protocol_attribute

    @classmethod
    def reddit_account_object_mapping(cls) -> dict:
        return cls.__reddit_account_object_mapping

    @classmethod
    def registry_key_object_mapping(cls) -> dict:
        return cls.__registry_key_object_mapping

    @classmethod
    def script_attribute(cls) -> dict:
        return cls.__script_attribute

    @classmethod
    def sha224_attribute(cls) -> dict:
        return cls.__sha224_attribute

    @classmethod
    def sha3_224_attribute(cls) -> dict:
        return cls.__sha3_224_attribute

    @classmethod
    def sha3_384_attribute(cls) -> dict:
        return cls.__sha3_384_attribute

    @classmethod
    def sha384_attribute(cls) -> dict:
        return cls.__sha384_attribute

    @classmethod
    def src_as_attribute(cls) -> dict:
        return cls.__src_as_attribute

    @classmethod
    def state_attribute(cls) -> dict:
        return cls.__state_attribute

    @classmethod
    def tcp_flags_attribute(cls) -> dict:
        return cls.__tcp_flags_attribute

    @classmethod
    def telegram_account_object_mapping(cls) -> dict:
        return cls.__telegram_account_object_mapping

    @classmethod
    def telfhash_attribute(cls) -> dict:
        return cls.__telfhash_attribute

    @classmethod
    def twitter_account_object_mapping(cls) -> dict:
        return cls.__twitter_account_object_mapping

    @classmethod
    def url_object_mapping(cls) -> dict:
        return cls.__url_object_mapping

    @classmethod
    def user_account_object_mapping(cls) -> dict:
        return cls.__user_account_object_mapping

    @classmethod
    def vhash_attribute(cls) -> dict:
        return cls.__vhash_attribute

    @classmethod
    def x509_object_mapping(cls) -> dict:
        return cls.__x509_object_mapping

    @classmethod
    def x509_subject_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__x509_subject_mapping.get(field)
