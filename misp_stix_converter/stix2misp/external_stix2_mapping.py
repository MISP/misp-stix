#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .. import Mapping
from .stix2_mapping import STIX2toMISPMapping


class ExternalSTIX2toMISPMapping(STIX2toMISPMapping):
    def __init__(self):
        super().__init__()
        self._declare_mapping()
        self.__pattern_forbidden_relations = (
            ' < ',
            ' <= ',
            ' > ',
            ' >= ',
            ' FOLLOWEDBY ',
            ' ISSUBSET ',
            ' ISSUPERSET',
            ' LIKE ',
            ' MATCHES ',
            ' NOT ',
            ' REPEATS ',
            ' WITHIN '
        )

        # MAIN STIX OBJECTS MAPPING
        observable_mapping = {
            'autonomous-system': 'as',
            'directory': 'directory',
            'domain-name': 'domain',
            'domain-name_network-traffic': 'domain_network_traffic',
            'domain-name_network-traffic_url': 'network_traffic',
            'email-addr': 'email_address',
            'mac-addr': 'mac_address',
            'mutex': 'mutex',
            'software': 'software',
            'url': 'url',
            'user-account': 'user_account',
            'windows-registry-key': 'registry_key',
            'x509-certificate': 'x509'
        }
        observable_mapping.update(
            dict.fromkeys(
                (
                    'autonomous-system_ipv4-addr',
                    'autonomous-system_ipv6-addr',
                    'autonomous-system_ipv4-addr_ipv6-addr'
                ),
                'asn'
            )
        )
        observable_mapping.update(
            dict.fromkeys(
                (
                    'domain-name_ipv4-addr',
                    'domain-name_ipv6-addr',
                    'domain-name_ipv4-addr_ipv6-addr'
                ),
                'domain_ip'
            )
        )
        observable_mapping.update(
            dict.fromkeys(
                (
                ),
                'domain_ip_network_traffic'
            )
        )
        observable_mapping.update(
            dict.fromkeys(
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
            )
        )
        observable_mapping.update(
            dict.fromkeys(
                (
                    'artifact_file',
                    'artifact_directory_file',
                    'directory_file',
                    'file'
                ),
                'file'
            )
        )
        observable_mapping.update(
            dict.fromkeys(
                (
                    'ipv4-addr',
                    'ipv6-addr'
                ),
                'ip_address'
            )
        )
        observable_mapping.update(
            dict.fromkeys(
                (
                    'domain-name_ipv4-addr_network-traffic',
                    'domain-name_ipv6-addr_network-traffic',
                    'domain-name_ipv4-addr_ipv6-addr_network-traffic',
                    'domain-name_ipv4-addr_mac-addr_network-traffic',
                    'domain-name_ipv6-addr_mac-addr_network-traffic',
                    'domain-name_ipv4-addr_ipv6-addr_mac-addr_network-traffic',
                    'mac-addr_network-traffic',
                    'mac-addr_ipv4-addr_network-traffic',
                    'mac-addr_ipv6-addr_network-traffic',
                    'mac-addr_ipv4-addr_ipv6-addr_network-traffic',
                    'ipv4-addr_network-traffic',
                    'ipv6-addr_network-traffic',
                    'ipv4-addr_ipv6-addr_network-traffic'
                ),
                'network_traffic'
            )
        )
        observable_mapping.update(
            dict.fromkeys(
                (
                    'file_process',
                    'process'
                ),
                'process'
            )
        )
        self.__observable_mapping = Mapping(**observable_mapping)
        pattern_mapping = {
            'email-addr': '_parse_email_address_pattern',
            'email-message': '_parse_email_message_pattern',
            'mac-addr': '_parse_mac_address_pattern',
            'mutex': '_parse_mutex_pattern',
            'network-traffic': '_parse_network_traffic_pattern',
            'process': '_parse_process_pattern',
            'user-account': '_parse_user_account_pattern',
            'windows-registry-key': '_parse_regkey_pattern',
            'x509-certificate': '_parse_x509_pattern'
        }
        pattern_mapping.update(
            dict.fromkeys(
                (
                    'artifact_file',
                    'directory',
                    'directory_file',
                    'file'
                ),
                '_parse_file_pattern'
            )
        )
        pattern_mapping.update(
            dict.fromkeys(
                (
                    'autonomous-system',
                    'autonomous-system_ipv4-addr',
                    'autonomous-system_ipv6-addr',
                    'autonomous-system_ipv4-addr_ipv6-addr'
                ),
                '_parse_asn_pattern'
            )
        )
        pattern_mapping.update(
            dict.fromkeys(
                (
                    'domain-name',
                    'domain-name_ipv4-addr',
                    'domain-name_ipv6-addr',
                    'domain-name_ipv4-addr_ipv6-addr',
                    'domain-name_network-traffic'
                ),
                '_parse_domain_ip_port_pattern'
            )
        )
        pattern_mapping.update(
            dict.fromkeys(
                (
                    'domain-name_ipv4-addr_url',
                    'domain-name_ipv6-addr_url',
                    'domain-name_ipv4-addr_ipv6-addr_url',
                    'domain-name_network-traffic_url',
                    'url'
                ),
                '_parse_url_pattern'
            )
        )
        pattern_mapping.update(
            dict.fromkeys(
                (
                    'ipv4-addr',
                    'ipv6-addr',
                    'ipv4-addr_ipv6-addr'
                ),
                '_parse_ip_address_pattern'
            )
        )
        self.__pattern_mapping = Mapping(**pattern_mapping)

        # MISP OBJECTS MAPPING
        self.__attack_pattern_object_mapping = Mapping(
            name = self.name_attribute,
            description = self.summary_attribute
        )
        self.__course_of_action_object_mapping = Mapping(
            name = self.name_attribute,
            description = self.description_attribute
        )
        self.__identity_object_multiple_fields = (
            'roles', 'sectors'
        )
        self.__identity_object_single_fields = (
            'name',
            'description',
            'identity_class',
            'contact_information'
        )
        self.__sigma_object_mapping = Mapping(
            pattern = self.sigma_attribute,
            description = self.comment_attribute,
            name = self.sigma_rule_name_attribute
        )
        self.__vulnerability_object_mapping = Mapping(
            name = self.summary_attribute,
            description = self.description_attribute
        )
        self.__yara_object_mapping = Mapping(
            pattern = self.yara_attribute,
            description = self.comment_attribute,
            name = self.yara_rule_name_attribute,
            pattern_version = self.version_attribute
        )

        # STIX OBSERVABLE OBJECTS TO MISP MAPPING
        self.__directory_object_mapping = Mapping(
            accessed = self.access_time_attribute,
            atime = self.access_time_attribute,
            created = self.creation_time_attribute,
            ctime = self.creation_time_attribute,
            modified = self.modification_time_attribute,
            mtime = self.modification_time_attribute,
            path = self.path_attribute,
            path_enc = {'type': 'text', 'object_relaiton': 'path-encoding'}
        )
        self.__email_object_fields = (
            'bcc_refs',
            'cc_refs',
            'body_multipart',
            'date',
            'from_ref'
            'raw_email_ref'
        )
        self.__email_object_mapping = Mapping(
            body = self.email_body_attribute,
            date = self.send_date_attribute,
            message_id = self.message_id_attribute,
            subject = self.email_subject_attribute
        )
        self.__file_hashes_object_mapping = Mapping(
            **{
                'MD5': self.md5_attribute,
                'SHA-1': self.sha1_attribute,
                'SHA-256': self.sha256_attribute,
                'SHA-512': self.sha512_attribute,
                'SHA3-256': self.sha3_256_attribute,
                'SHA3-512': self.sha3_512_attribute,
                'SSDEEP': self.ssdeep_attribute,
                'TLSH': self.tlsh_attribute
            }
        )
        self.__file_object_fields = (
            'contains_refs',
            'name_enc',
            'parent_directory_ref'
        )
        self.__file_object_mapping = Mapping(
            accessed = self.access_time_attribute,
            atime = self.access_time_attribute,
            created = self.creation_time_attribute,
            ctime = self.creation_time_attribute,
            mime_type = self.mime_type_attribute,
            modified = self.modification_time_attribute,
            mtime = self.modification_time_attribute,
            name = self.filename_attribute,
            name_enc = self.file_encoding_attribute,
            size = self.size_in_bytes_attribute
        )
        self.__network_connection_object_reference_mapping = Mapping(
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
        self.__network_socket_object_reference_mapping = Mapping(
            **{
                'domain-name_dst': 'hostname-dst',
                'domain-name_src': 'hostname-src',
                'ipv4-addr_dst': 'ip-dst',
                'ipv4-addr_src': 'ip-src',
                'ipv6-addr_dst': 'ip-dst',
                'ipv6-addr_src': 'ip-src'
            }
        )
        self.__network_traffic_object_mapping = Mapping(
            src_port = self.src_port_attribute,
            dst_port = self.dst_port_attribute,
            start = self.first_packet_seen_attribute,
            end = self.last_packet_seen_attribute,
            src_byte_count = self.src_bytes_count_attribute,
            dst_byte_count = self.dst_bytes_count_attribute,
            src_packets = self.src_packets_count_attribute,
            dst_packets = self.dst_packets_count_attribute
        )
        self.__pe_object_mapping = Mapping(
            imphash = self.imphash_attribute,
            number_of_sections = self.number_of_sections_attribute,
            pe_type = self.type_attribute
        )
        self.__pe_section_object_mapping = Mapping(
            entropy = self.entropy_attribute,
            name = self.name_attribute,
            size = self.size_in_bytes_attribute
        )
        self.__process_object_mapping = Mapping(
            command_line = self.command_line_attribute,
            created = self.creation_time_attribute,
            created_time = self.creation_time_attribute,
            cwd = self.current_directory_attribute,
            is_hidden = self.hidden_attribute,
            name = self.name_attribute,
            pid = self.pid_attribute
        )
        self.__registry_key_object_fields = (
            'modified',
            'modified_time'
        )
        self.__registry_key_object_mapping = Mapping(
            key = self.regkey_attribute,
            modified = self.last_modified_attribute,
            modified_time = self.last_modified_attribute
        )
        self.__software_object_mapping = Mapping(
            name = self.name_attribute,
            cpe = self.cpe_attribute,
            swid = self.swid_attribute,
            vendor = self.vendor_attribute,
            version = self.version_attribute
        )
        self.__user_account_object_mapping = Mapping(
            account_login = self.username_attribute,
            account_type = self.account_type_attribute,
            can_escalate_privs = self.can_escalate_privs_attribute,
            credential = self.password_attribute,
            display_name = self.display_name_attribute,
            is_disabled = self.disabled_attribute,
            is_privileged = self.privileged_attribute,
            is_service_account = self.is_service_account_attribute,
            user_id = self.user_id_attribute,
            account_created = self.created_attribute,
            account_expires = self.expires_attribute,
            account_first_login = self.first_login_attribute,
            account_last_login = self.last_login_attribute,
            credential_last_changed = self.password_last_changed_attribute,
            password_last_changed = self.password_last_changed_attribute
        )
        self.__x509_hashes_object_mapping = Mapping(
            **{
                'MD5': self.x509_md5_attribute,
                'SHA-1': self.x509_sha1_attribute,
                'SHA-256': self.x509_sha256_attribute
            }
        )
        self.__x509_object_mapping = Mapping(
            is_self_signed = self.is_self_signed_attribute,
            issuer = self.issuer_attribute,
            serial_number = self.serial_number_attribute,
            signature_algorithm = self.signature_algorithm_attribute,
            subject = self.subject_attribute,
            subject_public_key_algorithm = self.pubkey_info_algorithm_attribute,
            subject_public_key_exponent = self.pubkey_info_exponent_attribute,
            subject_public_key_modulus = self.pubkey_info_modulus_attribute,
            validity_not_after = self.validity_not_after_attribute,
            validity_not_before = self.validity_not_before_attribute,
            version = self.version_attribute
        )

        # STIX PATTERN TO MISP MAPPING
        self.__domain_ip_pattern_mapping = Mapping(
            **{
                'domain-name': self.domain_attribute,
                'ipv4-addr': self.ip_attribute,
                'ipv6-addr': self.ip_attribute
            }
        )
        self.__email_address_pattern_mapping = Mapping(
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
        self.__email_message_pattern_mapping = Mapping(
            body = self.email_body_attribute,
            date = self.send_date_attribute,
            message_id = self.message_id_attribute,
            subject = self.email_subject_attribute
        )
        self.__file_pattern_mapping = Mapping(
            mime_type = self.mime_type_attribute,
            name = self.filename_attribute,
            name_enc = self.file_encoding_attribute,
            size = self.size_in_bytes_attribute
        )
        self.__process_pattern_mapping = Mapping(
            arguments = self.args_attribute,
            command_line = self.command_line_attribute,
            created = self.creation_time_attribute,
            created_time = self.creation_time_attribute,
            cwd = self.current_directory_attribute,
            is_hidden = self.hidden_attribute,
        )
        self.__regkey_pattern_mapping = Mapping(
            data = self.data_attribute,
            data_type = self.data_type_attribute,
            modified = self.last_modified_attribute,
            modified_time = self.last_modified_attribute,
            name = self.name_attribute,
            key = self.regkey_attribute,
            pid = self.pid_attribute
        )

        # MISP GALAXIES MAPPING
        self.__galaxy_name_mapping = Mapping(
            **{
                "attack-pattern": {
                    "name": "Attack Pattern",
                    "description": "Attack Patterns are a type of TTP that describe ways that adversaries attempt to compromise targets. Attack Patterns are used to help categorize attacks, generalize specific attacks to the patterns that they follow, and provide detailed information about how attacks are performed."
                },
                "campaign": {
                    "name": "Campaign",
                    "description": "A Campaign is a grouping of adversarial behaviors that describes a set of malicious activities or attacks (sometimes called waves) that occur over a period of time against a specific set of targets. Campaigns usually have well defined objectives and may be part of an Intrusion Set."
                },
                "country": {
                    "name": "Country",
                    "description": "Country meta information based on the database provided by geonames.org."
                },
                "course-of-action": {
                    "name": "Course of Action",
                    "description": "A Course of Action is an action taken either to prevent an attack or to respond to an attack that is in progress. It may describe technical, automatable responses (applying patches, reconfiguring firewalls) but can also describe higher level actions like employee training or policy changes."
                },
                "intrusion-set": {
                    "name": "Intrusion Set",
                    "description": "An Intrusion Set is a grouped set of adversarial behaviors and resources with common properties that is believed to be orchestrated by a single organization. An Intrusion Set may capture multiple Campaigns or other activities that are all tied together by shared attributes indicating a commonly known or unknown Threat Actor."
                },
                "malware": {
                    "name": "Malware",
                    "description": "Malware is a type of TTP that represents malicious code. It generally refers to a program that is inserted into a system, usually covertly. The intent is to compromise the confidentiality, integrity, or availability of the victim's data, applications, or operating system (OS) or otherwise annoy or disrupt the victim."
                },
                "region": {
                    "name": "Regions UN M49",
                    "description": "Regions based on UN M49."
                },
                "threat-actor": {
                    "name": "Threat Actor",
                    "description": "Threat Actors are actual individuals, groups, or organizations believed to be operating with malicious intent. A Threat Actor is not an Intrusion Set but may support or be affiliated with various Intrusion Sets, groups, or organizations over time."
                },
                "tool": {
                    "name": "Tool",
                    "description": "Tools are legitimate software that can be used by threat actors to perform attacks. Knowing how and when threat actors use such tools can be important for understanding how campaigns are executed. Unlike malware, these tools or software packages are often found on a system and have legitimate purposes for power users, system administrators, network administrators, or even normal users."
                },
                "vulnerability": {
                    "name": "Vulnerability",
                    "description": "A Vulnerability is a weakness or defect in the requirements, designs, or implementations of the computational logic (e.g., code) found in software and some hardware components (e.g., firmware) that can be directly exploited to negatively impact the confidentiality, integrity, or availability of that system."
                }
            }
        )
        self.__location_object_fields = (
            'city',
            'latitude',
            'longitude',
            'postal_code',
            'street_address',
        )

    @property
    def attack_pattern_object_mapping(self) -> dict:
        return self.__attack_pattern_object_mapping

    @property
    def course_of_action_object_mapping(self) -> dict:
        return self.__course_of_action_object_mapping

    @property
    def directory_object_mapping(self) -> dict:
        return self.__directory_object_mapping

    @property
    def domain_ip_pattern_mapping(self) -> dict:
        return self.__domain_ip_pattern_mapping

    @property
    def email_address_pattern_mapping(self) -> dict:
        return self.__email_address_pattern_mapping

    @property
    def email_message_pattern_mapping(self) -> dict:
        return self.__email_message_pattern_mapping

    @property
    def email_object_fields(self) -> tuple:
        return self.__email_object_fields

    @property
    def email_object_mapping(self) -> dict:
        return self.__email_object_mapping

    @property
    def file_hashes_object_mapping(self) -> dict:
        return self.__file_hashes_object_mapping

    @property
    def file_object_fields(self) -> tuple:
        return self.__file_object_fields

    @property
    def file_object_mapping(self) -> dict:
        return self.__file_object_mapping

    @property
    def file_pattern_mapping(self) -> dict:
        return self.__file_pattern_mapping

    @property
    def galaxy_name_mapping(self) -> dict:
        return self.__galaxy_name_mapping

    @property
    def identity_object_multiple_fields(self) -> tuple:
        return self.__identity_object_multiple_fields

    @property
    def identity_object_single_fields(self) -> tuple:
        return self.__identity_object_single_fields

    @property
    def location_object_fields(self) -> tuple:
        return self.__location_object_fields

    @property
    def network_connection_object_reference_mapping(self) -> dict:
        return self.__network_connection_object_reference_mapping

    @property
    def network_socket_extension_object_mapping(self) -> dict:
        return self.__network_socket_extension_object_mapping

    @property
    def network_socket_object_reference_mapping(self) -> dict:
        return self.__network_socket_object_reference_mapping

    @property
    def network_traffic_object_mapping(self) -> dict:
        return self.__network_traffic_object_mapping

    @property
    def observable_mapping(self) -> dict:
        return self.__observable_mapping

    @property
    def pattern_forbidden_relations(self) -> tuple:
        return self.__pattern_forbidden_relations

    @property
    def pattern_mapping(self) -> dict:
        return self.__pattern_mapping

    @property
    def pe_object_mapping(self) -> dict:
        return self.__pe_object_mapping

    @property
    def pe_section_object_mapping(self) -> dict:
        return self.__pe_section_object_mapping

    @property
    def process_object_mapping(self) -> dict:
        return self.__process_object_mapping

    @property
    def process_pattern_mapping(self) -> dict:
        return self.__process_pattern_mapping

    @property
    def registry_key_object_fields(self) -> tuple:
        return self.__registry_key_object_fields

    @property
    def registry_key_object_mapping(self) -> dict:
        return self.__registry_key_object_mapping

    @property
    def regkey_pattern_mapping(self) -> dict:
        return self.__regkey_pattern_mapping

    @property
    def sigma_object_mapping(self) -> dict:
        return self.__sigma_object_mapping

    @property
    def software_object_mapping(self) -> dict:
        return self.__software_object_mapping

    @property
    def user_account_object_mapping(self) -> dict:
        return self.__user_account_object_mapping

    @property
    def vulnerability_object_mapping(self) -> dict:
        return self.__vulnerability_object_mapping

    @property
    def x509_hashes_object_mapping(self) -> dict:
        return self.__x509_hashes_object_mapping

    @property
    def x509_object_mapping(self) -> dict:
        return self.__x509_object_mapping

    @property
    def yara_object_mapping(self) -> dict:
        return self.__yara_object_mapping