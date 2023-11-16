#!/usr/bin/env python4
# -*- coding: utf-8 -*-

from .. import Mapping
from .stix2_mapping import STIX2toMISPMapping
from typing import Union


class ExternalSTIX2toMISPMapping(STIX2toMISPMapping):
    __pattern_forbidden_relations = (
        ' < ',
        ' <= ',
        ' > ',
        ' >= ',
        ' FOLLOWEDBY ',
        ' ISSUBSET ',
        ' ISSUPERSET',
        ' MATCHES ',
        ' NOT ',
        ' REPEATS ',
        ' WITHIN '
    )

    # MAIN STIX OBJECTS MAPPING
    __observable_mapping = Mapping(
        **{
            'autonomous-system': 'as',
            'directory': 'directory',
            'domain-name': 'domain',
            'email-addr': 'email_address',
            'mac-addr': 'mac_address',
            'mutex': 'mutex',
            'software': 'software',
            'url': 'url',
            'user-account': 'user_account',
            'windows-registry-key': 'registry_key',
            'x509-certificate': 'x509',
            **dict.fromkeys(
                (
                    'autonomous-system_ipv4-addr',
                    'autonomous-system_ipv6-addr',
                    'autonomous-system_ipv4-addr_ipv6-addr'
                ),
                'asn'
            ),
            **dict.fromkeys(
                (
                    'domain-name_ipv4-addr',
                    'domain-name_ipv6-addr',
                    'domain-name_ipv4-addr_ipv6-addr'
                ),
                'domain_ip'
            ),
            **dict.fromkeys(
                (
                    'artifact_email-addr_email-message',
                    'artifact_email-addr_email-message_file',
                    'artifact_email-message',
                    'email-addr_email-message',
                    'email-addr_email-message_file',
                    'email-message',
                    'email-message_file'
                ),
                'email'
            ),
            **dict.fromkeys(
                (
                    'artifact_file',
                    'artifact_directory_file',
                    'directory_file',
                    'file'
                ),
                'file'
            ),
            **dict.fromkeys(
                (
                    'ipv4-addr',
                    'ipv6-addr'
                ),
                'ip_address'
            ),
            **dict.fromkeys(
                (
                    'domain-name_ipv4-addr_network-traffic',
                    'domain-name_ipv6-addr_network-traffic',
                    'domain-name_ipv4-addr_ipv6-addr_network-traffic',
                    'domain-name_ipv4-addr_mac-addr_network-traffic',
                    'domain-name_ipv6-addr_mac-addr_network-traffic',
                    'domain-name_ipv4-addr_ipv6-addr_mac-addr_network-traffic',
                    'domain-name_network-traffic',
                    'domain-name_network-traffic_url',
                    'ipv4-addr_network-traffic',
                    'ipv6-addr_network-traffic',
                    'ipv4-addr_ipv6-addr_network-traffic',
                    'mac-addr_network-traffic',
                    'mac-addr_ipv4-addr_network-traffic',
                    'mac-addr_ipv6-addr_network-traffic',
                    'mac-addr_ipv4-addr_ipv6-addr_network-traffic',
                    'network-traffic'
                ),
                'network_traffic'
            ),
            **dict.fromkeys(
                (
                    'file_process',
                    'process'
                ),
                'process'
            )
        }
    )
    __pattern_mapping = Mapping(
        **{
            'directory': 'directory',
            'email-addr': 'email_address',
            'email-message': 'email_message',
            'mac-addr': 'mac_address',
            'mutex': 'mutex',
            'network-traffic': 'network_traffic',
            'process': 'process',
            'software': 'software',
            'user-account': 'user_account',
            'windows-registry-key': 'registry_key',
            'x509-certificate': 'x509',
            **dict.fromkeys(
                (
                    'autonomous-system',
                    'autonomous-system_ipv4-addr',
                    'autonomous-system_ipv6-addr',
                    'autonomous-system_ipv4-addr_ipv6-addr'
                ),
                'asn'
            ),
            **dict.fromkeys(
                (
                    'domain-name',
                    'domain-name_ipv4-addr',
                    'domain-name_ipv6-addr',
                    'domain-name_ipv4-addr_ipv6-addr',
                    'domain-name_network-traffic'
                ),
                'domain_ip_port'
            ),
            **dict.fromkeys(
                (
                    'artifact_file',
                    'directory_file',
                    'file'
                ),
                'file'
            ),
            **dict.fromkeys(
                (
                    'ipv4-addr',
                    'ipv6-addr',
                    'ipv4-addr_ipv6-addr'
                ),
                'ip_address'
            ),
            **dict.fromkeys(
                (
                    'ipv4-addr_ipv6-addr_process',
                    'ipv4-addr_process',
                    'ipv6-addr_process',
                    'process'
                ),
                'process'
            ),
            **dict.fromkeys(
                (
                    'domain-name_ipv4-addr_url',
                    'domain-name_ipv6-addr_url',
                    'domain-name_ipv4-addr_ipv6-addr_url',
                    'domain-name_network-traffic_url',
                    'url'
                ),
                'url'
            )
        }
    )

    # MISP OBJECTS MAPPING
    __course_of_action_object_mapping = Mapping(
        name=STIX2toMISPMapping.name_attribute(),
        description=STIX2toMISPMapping.description_attribute()
    )
    __sigma_object_mapping = Mapping(
        pattern=STIX2toMISPMapping.sigma_attribute(),
        description=STIX2toMISPMapping.comment_attribute(),
        name=STIX2toMISPMapping.sigma_rule_name_attribute()
    )
    __yara_object_mapping = Mapping(
        pattern=STIX2toMISPMapping.yara_attribute(),
        description=STIX2toMISPMapping.comment_attribute(),
        name=STIX2toMISPMapping.yara_rule_name_attribute(),
        pattern_version=STIX2toMISPMapping.version_attribute()
    )

    # STIX OBSERVABLE OBJECTS TO MISP MAPPING
    __directory_object_mapping = Mapping(
        accessed=STIX2toMISPMapping.access_time_attribute(),
        atime=STIX2toMISPMapping.access_time_attribute(),
        created=STIX2toMISPMapping.creation_time_attribute(),
        ctime=STIX2toMISPMapping.creation_time_attribute(),
        modified=STIX2toMISPMapping.modification_time_attribute(),
        mtime=STIX2toMISPMapping.modification_time_attribute(),
        path=STIX2toMISPMapping.path_attribute(),
        path_enc={'type': 'text', 'object_relaiton': 'path-encoding'}
    )
    __email_object_fields = (
        'bcc_refs',
        'cc_refs',
        'body_multipart',
        'date',
        'from_ref'
        'raw_email_ref'
    )
    __email_object_mapping = Mapping(
        body=STIX2toMISPMapping.email_body_attribute(),
        date=STIX2toMISPMapping.send_date_attribute(),
        message_id=STIX2toMISPMapping.message_id_attribute(),
        subject=STIX2toMISPMapping.email_subject_attribute()
    )
    __file_hashes_mapping = Mapping(
        **{
            'MD5': STIX2toMISPMapping.md5_attribute(),
            'SHA-1': STIX2toMISPMapping.sha1_attribute(),
            'SHA-256': STIX2toMISPMapping.sha256_attribute(),
            'SHA-512': STIX2toMISPMapping.sha512_attribute(),
            'SHA3-256': STIX2toMISPMapping.sha3_256_attribute(),
            'SHA3-512': STIX2toMISPMapping.sha3_512_attribute(),
            'SSDEEP': STIX2toMISPMapping.ssdeep_attribute(),
            'TLSH': STIX2toMISPMapping.tlsh_attribute()
        }
    )
    __file_object_fields = (
        'contains_refs',
        'name_enc',
        'parent_directory_ref'
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
        size=STIX2toMISPMapping.size_in_bytes_attribute()
    )
    __network_connection_object_reference_mapping = Mapping(
        **{
            'domain-name_dst': 'hostname-dst',
            'domain-name_src': 'hostname-src',
            'ipv4-addr_dst': 'ip-dst',
            'ipv4-addr_src': 'ip-src',
            'ipv6-addr_dst': 'ip-dst',
            'ipv6-addr_src': 'ip-src',
            'mac-address_dst': 'mac-dst',
            'mac-address_src': 'mad-src'
        }
    )
    __network_socket_object_reference_mapping = Mapping(
        **{
            'domain-name_dst': 'hostname-dst',
            'domain-name_src': 'hostname-src',
            'ipv4-addr_dst': 'ip-dst',
            'ipv4-addr_src': 'ip-src',
            'ipv6-addr_dst': 'ip-dst',
            'ipv6-addr_src': 'ip-src'
        }
    )
    __network_traffic_object_mapping = Mapping(
        src_port=STIX2toMISPMapping.src_port_attribute(),
        dst_port=STIX2toMISPMapping.dst_port_attribute(),
        start=STIX2toMISPMapping.first_packet_seen_attribute(),
        end=STIX2toMISPMapping.last_packet_seen_attribute(),
        src_byte_count=STIX2toMISPMapping.src_bytes_count_attribute(),
        dst_byte_count=STIX2toMISPMapping.dst_bytes_count_attribute(),
        src_packets=STIX2toMISPMapping.src_packets_count_attribute(),
        dst_packets=STIX2toMISPMapping.dst_packets_count_attribute()
    )
    __pe_object_mapping = Mapping(
        imphash=STIX2toMISPMapping.imphash_attribute(),
        number_of_sections=STIX2toMISPMapping.number_of_sections_attribute(),
        pe_type=STIX2toMISPMapping.type_attribute()
    )
    __pe_optional_header_mapping = Mapping(
        address_of_entry_point=STIX2toMISPMapping.entrypoint_address_attribute()
    )
    __pe_section_object_mapping = Mapping(
        entropy=STIX2toMISPMapping.entropy_attribute(),
        name=STIX2toMISPMapping.name_attribute(),
        size=STIX2toMISPMapping.size_in_bytes_attribute()
    )
    __process_object_mapping = Mapping(
        command_line=STIX2toMISPMapping.command_line_attribute(),
        created=STIX2toMISPMapping.creation_time_attribute(),
        created_time=STIX2toMISPMapping.creation_time_attribute(),
        cwd=STIX2toMISPMapping.current_directory_attribute(),
        is_hidden=STIX2toMISPMapping.hidden_attribute(),
        name=STIX2toMISPMapping.name_attribute(),
        pid=STIX2toMISPMapping.pid_attribute()
    )
    __registry_key_object_fields = (
        'modified',
        'modified_time'
    )
    __registry_key_object_mapping = Mapping(
        key=STIX2toMISPMapping.regkey_attribute(),
        modified=STIX2toMISPMapping.last_modified_attribute(),
        modified_time=STIX2toMISPMapping.last_modified_attribute()
    )
    __software_object_mapping = Mapping(
        name=STIX2toMISPMapping.name_attribute(),
        cpe=STIX2toMISPMapping.cpe_attribute(),
        swid=STIX2toMISPMapping.swid_attribute(),
        vendor=STIX2toMISPMapping.vendor_attribute(),
        version=STIX2toMISPMapping.version_attribute()
    )
    __user_account_object_mapping = Mapping(
        account_login=STIX2toMISPMapping.username_attribute(),
        account_type=STIX2toMISPMapping.account_type_attribute(),
        can_escalate_privs=STIX2toMISPMapping.can_escalate_privs_attribute(),
        credential=STIX2toMISPMapping.password_attribute(),
        display_name=STIX2toMISPMapping.display_name_attribute(),
        is_disabled=STIX2toMISPMapping.disabled_attribute(),
        is_privileged=STIX2toMISPMapping.privileged_attribute(),
        is_service_account=STIX2toMISPMapping.is_service_account_attribute(),
        user_id=STIX2toMISPMapping.user_id_attribute(),
        account_created=STIX2toMISPMapping.created_attribute(),
        account_expires=STIX2toMISPMapping.expires_attribute(),
        account_first_login=STIX2toMISPMapping.first_login_attribute(),
        account_last_login=STIX2toMISPMapping.last_login_attribute(),
        credential_last_changed=STIX2toMISPMapping.password_last_changed_attribute(),
        password_last_changed=STIX2toMISPMapping.password_last_changed_attribute()
    )
    __x509_hashes_mapping = Mapping(
        **{
            'MD5': STIX2toMISPMapping.x509_md5_attribute(),
            'SHA-1': STIX2toMISPMapping.x509_sha1_attribute(),
            'SHA-256': STIX2toMISPMapping.x509_sha256_attribute()
        }
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
        version=STIX2toMISPMapping.version_attribute()
    )

    # STIX PATTERN TO MISP MAPPING
    __asn_pattern_mapping = Mapping(
        name=STIX2toMISPMapping.description_attribute(),
        number=STIX2toMISPMapping.asn_attribute()
    )
    __domain_ip_pattern_mapping = Mapping(
        **{
            'domain-name': STIX2toMISPMapping.domain_attribute(),
            'ipv4-addr': STIX2toMISPMapping.ip_attribute(),
            'ipv6-addr': STIX2toMISPMapping.ip_attribute()
        }
    )
    __email_address_pattern_mapping = Mapping(
        **{
            'display_names': {
                'type': 'email-dst-display-name',
                'object_relation': 'to-display-name'
            },
            'value': {
                'type': 'email-dst', 'object_relation': 'to'
            }
        }
    )
    __http_request_extension_mapping = Mapping(
        **{
            'request_method': STIX2toMISPMapping.method_attribute(),
            'request_value': STIX2toMISPMapping.uri_attribute(),
            'Content-Type': STIX2toMISPMapping.content_type_attribute(),
            'Cookie': STIX2toMISPMapping.cookie_attribute(),
            'Referer': STIX2toMISPMapping.referer_attribute(),
            'User-Agent': STIX2toMISPMapping.user_agent_attribute()
        }
    )
    __process_pattern_mapping = Mapping(
        arguments=STIX2toMISPMapping.args_attribute(),
        **__process_object_mapping
    )
    __registry_key_pattern_mapping = Mapping(
        data=STIX2toMISPMapping.data_attribute(),
        data_type=STIX2toMISPMapping.data_type_attribute(),
        name=STIX2toMISPMapping.name_attribute(),
        **__registry_key_object_mapping
    )
    __software_pattern_mapping = Mapping(
        languages=STIX2toMISPMapping.language_attribute(),
        **__software_object_mapping
    )
    __user_account_pattern_mapping = Mapping(
        gid=STIX2toMISPMapping.group_id_attribute(),
        groups=STIX2toMISPMapping.groups_attribute(),
        home_dir=STIX2toMISPMapping.home_dir_attribute(),
        shell=STIX2toMISPMapping.shell_attribute(),
        **__user_account_object_mapping
    )

    # MISP GALAXIES MAPPING
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
    def asn_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__asn_pattern_mapping.get(field)

    @classmethod
    def course_of_action_object_mapping(cls) -> dict:
        return cls.__course_of_action_object_mapping

    @classmethod
    def directory_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__directory_object_mapping.get(field)

    @classmethod
    def directory_object_mapping(cls) -> dict:
        return cls.__directory_object_mapping

    @classmethod
    def domain_ip_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__domain_ip_pattern_mapping.get(field)

    @classmethod
    def email_address_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__email_address_pattern_mapping.get(field)

    @classmethod
    def email_message_mapping(cls, field) -> Union[dict, None]:
        return cls.__email_object_mapping.get(field)

    @classmethod
    def email_object_fields(cls) -> tuple:
        return cls.__email_object_fields

    @classmethod
    def email_object_mapping(cls) -> dict:
        return cls.__email_object_mapping

    @classmethod
    def file_hashes_object_mapping(cls) -> dict:
        return cls.__file_hashes_mapping

    @classmethod
    def file_hashes_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__file_hashes_mapping.get(field)

    @classmethod
    def file_object_fields(cls) -> tuple:
        return cls.__file_object_fields

    @classmethod
    def file_object_mapping(cls) -> dict:
        return cls.__file_object_mapping

    @classmethod
    def file_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__file_object_mapping.get(field)

    @classmethod
    def galaxy_name_mapping(cls, field) -> Union[dict, None]:
        return cls.__galaxy_name_mapping.get(field)

    @classmethod
    def http_request_extension_mapping(cls, field) -> Union[dict, None]:
        return cls.__http_request_extension_mapping.get(field)

    @classmethod
    def network_connection_object_reference_mapping(cls, field) -> Union[str, None]:
        return cls.__network_connection_object_reference_mapping.get(field)

    @classmethod
    def network_socket_object_reference_mapping(cls, field) -> Union[str, None]:
        return cls.__network_socket_object_reference_mapping.get(field)

    @classmethod
    def network_traffic_object_mapping(cls) -> dict:
        return cls.__network_traffic_object_mapping

    @classmethod
    def network_traffic_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__network_traffic_object_mapping.get(field)

    @classmethod
    def observable_mapping(cls, field) -> Union[str, None]:
        return cls.__observable_mapping.get(field)

    @classmethod
    def pattern_forbidden_relations(cls) -> tuple:
        return cls.__pattern_forbidden_relations

    @classmethod
    def pattern_mapping(cls, field) -> Union[str, None]:
        return cls.__pattern_mapping.get(field)

    @classmethod
    def pe_object_mapping(cls) -> dict:
        return cls.__pe_object_mapping

    @classmethod
    def pe_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__pe_object_mapping.get(field)

    @classmethod
    def pe_optional_header_object_mapping(cls) -> dict:
        return cls.__pe_optional_header_mapping

    @classmethod
    def pe_optional_header_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__pe_optional_header_mapping.get(field)

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
    def registry_key_object_fields(cls) -> tuple:
        return cls.__registry_key_object_fields

    @classmethod
    def registry_key_object_mapping(cls) -> dict:
        return cls.__registry_key_object_mapping

    @classmethod
    def registry_key_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__registry_key_pattern_mapping.get(field)

    @classmethod
    def sigma_object_mapping(cls) -> dict:
        return cls.__sigma_object_mapping

    @classmethod
    def software_object_mapping(cls) -> dict:
        return cls.__software_object_mapping

    @classmethod
    def software_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__software_pattern_mapping.get(field)

    @classmethod
    def user_account_object_mapping(cls) -> dict:
        return cls.__user_account_object_mapping

    @classmethod
    def user_account_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__user_account_pattern_mapping.get(field)

    @classmethod
    def x509_hashes_object_mapping(cls) -> dict:
        return cls.__x509_hashes_mapping

    @classmethod
    def x509_hashes_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__x509_hashes_mapping.get(field)

    @classmethod
    def x509_object_mapping(cls) -> dict:
        return cls.__x509_object_mapping

    @classmethod
    def x509_pattern_mapping(cls, field) -> Union[dict, None]:
        return cls.__x509_object_mapping.get(field)

    @classmethod
    def yara_object_mapping(cls) -> dict:
        return cls.__yara_object_mapping
