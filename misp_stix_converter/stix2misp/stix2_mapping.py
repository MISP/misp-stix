#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .. import Mapping
from abc import ABCMeta
from typing import Union


class STIX2toMISPMapping(metaclass=ABCMeta):
    # Some general mapping variables
    __bundle_to_misp_mapping = Mapping(
        **{
            '0': '_parse_bundle_with_no_report',
            '1': '_parse_bundle_with_single_report',
            '2': '_parse_bundle_with_multiple_reports'
        }
    )
    __mac_address_pattern = '^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    __marking_extension_mapping = Mapping(
        **{
            'extension-definition--3a65884d-005a-4290-8335-cb2d778a83ce': 'acs'
        }
    )
    __marking_vocabularies_fields = (
        'caveat', 'classification', 'entity', 'formal_determination',
        'sensitivity', 'shareability'
    )
    __object_type_refs_to_skip = (
        'marking-definition', 'opinion', 'relationship',
        'sighting', 'x-misp-opinion'
    )
    __observable_object_types = (
        'network-traffic',
        'file',
        'email-message',
        'artifact',
        'autonomous-system',
        'directory',
        'domain-name',
        'email-addr',
        'ipv4-addr',
        'ipv6-addr',
        'mac-addr',
        'mutex',
        'process',
        'software',
        'url',
        'user-account',
        'windows-registry-key',
        'x509-certificate'
    )
    __stix_object_loading_mapping = Mapping(
        **{
            'attack-pattern': '_load_attack_pattern',
            'campaign': '_load_campaign',
            'course-of-action': '_load_course_of_action',
            'grouping': '_load_grouping',
            'identity': '_load_identity',
            'indicator': '_load_indicator',
            'intrusion-set': '_load_intrusion_set',
            'location': '_load_location',
            'malware': '_load_malware',
            'malware-analysis': '_load_malware_analysis',
            'marking-definition': '_load_marking_definition',
            'note': '_load_note',
            'observed-data': '_load_observed_data',
            'opinion': '_load_opinion',
            'relationship': '_load_relationship',
            'report': '_load_report',
            'sighting': '_load_sighting',
            'threat-actor': '_load_threat_actor',
            'tool': '_load_tool',
            'vulnerability': '_load_vulnerability',
            'x-misp-attribute': '_load_custom_attribute',
            'x-misp-galaxy-cluster': '_load_custom_galaxy_cluster',
            'x-misp-object': '_load_custom_object',
            'x-misp-opinion': '_load_custom_opinion',
            **dict.fromkeys(
                __observable_object_types,
                '_load_observable_object'
            )
        }
    )
    __stix_to_misp_mapping = Mapping(
        **{
            'attack-pattern': 'attack_pattern_parser',
            'campaign': 'campaign_parser',
            'course-of-action': 'course_of_action_parser',
            'identity': 'identity_parser',
            'indicator': 'indicator_parser',
            'intrusion-set': 'intrusion_set_parser',
            'location': 'location_parser',
            'malware': 'malware_parser',
            'malware-analysis': 'malware_analysis_parser',
            'note': 'note_parser',
            'observed-data': 'observed_data_parser',
            'sighting': 'sighting_parser',
            'threat-actor': 'threat_actor_parser',
            'tool': 'tool_parser',
            'vulnerability': 'vulnerability_parser',
            'x-misp-attribute': 'custom_object_parser',
            'x-misp-galaxy-cluster': 'custom_object_parser',
            'x-misp-object': 'custom_object_parser'
        }
    )
    __timeline_mapping = Mapping(
        **{
            'indicator': ('valid_from', 'valid_until'),
            'observed-data': ('first_observed', 'last_observed')
        }
    )

    # KNOWN IDENTITY REFERENCES
    __identity_references = {
        "identity--b3bca3c2-1f3d-4b54-b44f-dac42c3a8f01": "CISA"
    }

    # SINGLE ATTRIBUTES MAPPING
    __access_time_attribute = Mapping(
        **{'type': 'datetime', 'object_relation': 'access-time'}
    )
    __account_type_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'account-type'}
    )
    __accuracy_radius_attribute = Mapping(
        **{'type': 'float', 'object_relation': 'accuracy-radius'}
    )
    __address_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'address'}
    )
    __address_family_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'address-family'}
    )
    __args_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'args'}
    )
    __asn_attribute = Mapping(
        **{'type': 'AS', 'object_relation': 'asn'}
    )
    __attack_pattern_id_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'id'}
    )
    __can_escalate_privs_attribute = Mapping(
        **{'type': 'boolean', 'object_relation': 'can_escalate_privs'}
    )
    __city_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'city'}
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
    __country_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'countrycode'}
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
    __dst_bytes_count_attribute = Mapping(
        **{'type': 'counter', 'object_relation': 'dst-bytes-count'}
    )
    __dst_packets_count_attribute = Mapping(
        **{'type': 'counter', 'object_relation': 'dst-packets-count'}
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
    __group_id_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'group-id'}
    )
    __groups_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'group'}
    )
    __hidden_attribute = Mapping(
        **{'type': 'boolean', 'object_relation': 'hidden'}
    )
    __home_dir_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'home_dir'}
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
    __latitude_attribute = Mapping(
        **{'type': 'float', 'object_relation': 'latitude'}
    )
    __longitude_attribute = Mapping(
        **{'type': 'float', 'object_relation': 'longitude'}
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
    __region_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'region'}
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
    __shell_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'shell'}
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
    __src_bytes_count_attribute = Mapping(
        **{'type': 'counter', 'object_relation': 'src-bytes-count'}
    )
    __src_packets_count_attribute = Mapping(
        **{'type': 'counter', 'object_relation': 'src-packets-count'}
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
    __subnet_announced_attribute = Mapping(
        **{'type': 'ip-src', 'object_relation': 'subnet-announced'}
    )
    __summary_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'summary'}
    )
    __suricata_reference_attribute = Mapping(
        **{'type': 'link', 'object_relation': 'ref'}
    )
    __swid_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'swid'}
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
    __vulnerability_attribute = Mapping(
        **{'type': 'vulnerability', 'object_relation': 'id'}
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
    __zipcode_attribute = Mapping(
        **{'type': 'text', 'object_relation': 'zipcode'}
    )

    # MISP GALAXIES MAPPING
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
    __regions_mapping = Mapping(
        **{
            'world': '001 - World',
            'africa': '002 - Africa',
            'eastern-africa': '014 - Eastern Africa',
            'middle-africa': '017 - Middle Africa',
            'northern-africa': '015 - Northern Africa',
            'southern-africa': '018 - Southern Africa',
            'western-africa': '011 - Western Africa',
            'americas': '019 - Americas',
            'caribbean': '029 - Caribbean',
            'central-america': '013 - Central America',
            'latin-america-caribbean': '419 - Latin America and the Caribbean',
            'northern-america': '021 - Northern America',
            'south-america': '005 - South America',
            'asia': '142 - Asia',
            'central-asia': '143 - Central Asia',
            'eastern-asia': '030 - Eastern Asia',
            'southern-asia': '034 - Southern Asia',
            'south-eastern-asia': '035 - South-eastern Asia',
            'western-asia': '145 - Western Asia',
            'europe': '150 - Europe',
            'eastern-europe': '151 - Eastern Europe',
            'northern-europe': '154 - Northern Europe',
            'southern-europe': '039 - Southern Europe',
            'western-europe': '155 - Western Europe',
            'oceania': '009 - Oceania',
            'antarctica': '010 - Antarctica',
            'australia-new-zealand': '053 - Australia and New Zealand',
            'melanesia': '054 - Melanesia',
            'micronesia': '057 - Micronesia',
            'polynesia': '061 - Polynesia'
        }
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
    __email_additional_header_fields_mapping = Mapping(
        **{
            'Reply-To': __reply_to_attribute,
            'X-Mailer': __x_mailer_attribute
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
    __suricata_object_mapping = Mapping(
        pattern=__snort_attribute,
        description=__comment_attribute,
        pattern_version=__version_attribute
    )
    __user_account_unix_extention_mapping = Mapping(
        gid=__group_id_attribute,
        groups=__groups_attribute,
        home_dir=__home_dir_attribute,
        shell=__shell_attribute
    )

    @classmethod
    def access_time_attribute(cls) -> dict:
        return cls.__access_time_attribute

    @classmethod
    def account_type_attribute(cls) -> dict:
        return cls.__account_type_attribute

    @classmethod
    def accuracy_radius_attribute(cls) -> dict:
        return cls.__accuracy_radius_attribute

    @classmethod
    def address_attribute(cls) -> dict:
        return cls.__address_attribute

    @classmethod
    def address_family_attribute(cls) -> dict:
        return cls.__address_family_attribute

    @classmethod
    def args_attribute(cls) -> dict:
        return cls.__args_attribute

    @classmethod
    def asn_attribute(cls) -> dict:
        return cls.__asn_attribute

    @classmethod
    def attack_pattern_id_attribute(cls) -> dict:
        return cls.__attack_pattern_id_attribute

    @classmethod
    def bundle_to_misp_mapping(cls, field: str) -> Union[str, None]:
        return cls.__bundle_to_misp_mapping.get(field)

    @classmethod
    def can_escalate_privs_attribute(cls) -> dict:
        return cls.__can_escalate_privs_attribute

    @classmethod
    def city_attribute(cls) -> dict:
        return cls.__city_attribute

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
    def country_attribute(cls) -> dict:
        return cls.__country_attribute

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
    def dash_meta_fields(cls) -> tuple:
        return cls.__dash_meta_fields

    @classmethod
    def data_attribute(cls) -> dict:
        return cls.__data_attribute

    @classmethod
    def data_type_attribute(cls) -> dict:
        return cls.__data_type_attribute

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
    def dst_bytes_count_attribute(cls) -> dict:
        return cls.__dst_bytes_count_attribute

    @classmethod
    def dst_packets_count_attribute(cls) -> dict:
        return cls.__dst_packets_count_attribute

    @classmethod
    def dst_port_attribute(cls) -> dict:
        return cls.__dst_port_attribute

    @classmethod
    def email_additional_header_fields_mapping(cls) -> dict:
        return cls.__email_additional_header_fields_mapping

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
    def group_id_attribute(cls) -> dict:
        return cls.__group_id_attribute

    @classmethod
    def groups_attribute(cls) -> dict:
        return cls.__groups_attribute

    @classmethod
    def hidden_attribute(cls) -> dict:
        return cls.__hidden_attribute

    @classmethod
    def home_dir_attribute(cls) -> dict:
        return cls.__home_dir_attribute

    @classmethod
    def identity_references(cls, identity_id: str) -> Union[str, None]:
        return cls.__identity_references.get(identity_id)

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
    def is_cls_signed_attribute(cls) -> dict:
        return cls.__is_cls_signed_attribute

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
    def latitude_attribute(cls) -> dict:
        return cls.__latitude_attribute

    @classmethod
    def longitude_attribute(cls) -> dict:
        return cls.__longitude_attribute

    @classmethod
    def mac_address_pattern(cls) -> str:
        return cls.__mac_address_pattern

    @classmethod
    def marking_extension_mapping(cls, field: str) -> Union[str, None]:
        return cls.__marking_extension_mapping.get(field)

    @classmethod
    def marking_vocabularies_fields(cls) -> tuple:
        return cls.__marking_vocabularies_fields

    @classmethod
    def message_id_attribute(cls) -> dict:
        return cls.__message_id_attribute

    @classmethod
    def method_attribute(cls) -> dict:
        return cls.__method_attribute

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
    def network_socket_extension_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__network_socket_extension_mapping.get(field)

    @classmethod
    def network_socket_extension_object_mapping(cls) -> dict:
        return cls.__network_socket_extension_mapping

    @classmethod
    def number_of_sections_attribute(cls) -> dict:
        return cls.__number_of_sections_attribute

    @classmethod
    def object_type_refs_to_skip(cls) -> tuple:
        return cls.__object_type_refs_to_skip

    @classmethod
    def observable_object_types(cls) -> tuple:
        return cls.__observable_object_types

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
    def reference_attribute(cls) -> dict:
        return cls.__reference_attribute

    @classmethod
    def references_attribute(cls) -> dict:
        return cls.__references_attribute

    @classmethod
    def referer_attribute(cls) -> dict:
        return cls.__referer_attribute

    @classmethod
    def region_attribute(cls) -> dict:
        return cls.__region_attribute

    @classmethod
    def regions_mapping(cls, field: str, default_value: str) -> str:
        return cls.__regions_mapping.get(field, default_value)

    @classmethod
    def registry_key_values_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__registry_key_values_mapping.get(field)

    @classmethod
    def registry_key_values_object_mapping(cls) -> dict:
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
    def shell_attribute(cls) -> dict:
        return cls.__shell_attribute

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
    def src_bytes_count_attribute(cls) -> dict:
        return cls.__src_bytes_count_attribute

    @classmethod
    def src_packets_count_attribute(cls) -> dict:
        return cls.__src_packets_count_attribute

    @classmethod
    def src_port_attribute(cls) -> dict:
        return cls.__src_port_attribute

    @classmethod
    def ssdeep_attribute(cls) -> dict:
        return cls.__ssdeep_attribute

    @classmethod
    def stix_object_loading_mapping(cls, field: str) -> Union[str, None]:
        return cls.__stix_object_loading_mapping.get(field)

    @classmethod
    def stix_to_misp_mapping(cls, field: str) -> Union[str, None]:
        return cls.__stix_to_misp_mapping.get(field)

    @classmethod
    def subject_attribute(cls) -> dict:
        return cls.__subject_attribute

    @classmethod
    def subnet_announced_attribute(cls) -> dict:
        return cls.__subnet_announced_attribute

    @classmethod
    def summary_attribute(cls) -> dict:
        return cls.__summary_attribute

    @classmethod
    def suricata_object_mapping(cls) -> dict:
        return cls.__suricata_object_mapping

    @classmethod
    def suricata_reference_attribute(cls) -> dict:
        return cls.__suricata_reference_attribute

    @classmethod
    def swid_attribute(cls) -> dict:
        return cls.__swid_attribute

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
    def user_account_unix_extension_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__user_account_unix_extention_mapping.get(field)

    @classmethod
    def user_account_unix_extension_object_mapping(cls) -> dict:
        return cls.__user_account_unix_extention_mapping

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
    def vulnerability_attribute(cls) -> dict:
        return cls.__vulnerability_attribute

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

    @classmethod
    def zipcode_attribute(cls) -> dict:
        return cls.__zipcode_attribute
