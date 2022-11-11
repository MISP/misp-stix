#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .. import Mapping
from .stix2_mapping import STIX2Mapping


class ExternalSTIX2Mapping(STIX2Mapping):
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
            'domain-name_network-traffic': '_parse_domain_network_traffic_observable',
            'email-addr': '_parse_email_address_observable',
            'mac-addr': '_parse_mac_address_observable',
            'mutex': 'parse_mutex_observable',
            'x509-certificate': 'parse_x509_observable',
            'user-account': 'parse_user_account_observable',
            'windows-registry-key': 'parse_regkey_observable'
        }
        observable_mapping.update(
            dict.fromkeys(
                (
                    'artifact_file',
                    'artifact_directory_file',
                    'directory_file',
                    'file'
                ),
                '_parse_file_observable'
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
                '_parse_email_observable'
            )
        )
        observable_mapping.update(
            dict.fromkeys(
                (
                    'autonomous-system',
                    'autonomous-system_ipv4-addr',
                    'autonomous-system_ipv6-addr',
                    'autonomous-system-ipv4-addr_ipv6-addr'
                ),
                '_parse_asn_observable'
            )
        )
        observable_mapping.update(
            dict.fromkeys(
                (
                    'domain-name',
                    'domain-name_ipv4-addr',
                    'domain-name_ipv6-addr',
                    'domain-name_ipv4-addr_ipv6-addr'
                ),
                '_parse_domain_ip_observable'
            )
        )
        observable_mapping.update(
            dict.fromkeys(
                (
                    'domain-name_ipv4-addr_network-traffic',
                    'domain-name_ipv6-addr_network-traffic',
                    'domain-name_ipv4-addr_ipv6-addr_network-traffic'
                ),
                '_parse_domain_ip_network_traffic_observable'
            )
        )
        observable_mapping.update(
            dict.fromkeys(
                (
                    'domain-name_network-traffic_url',
                    'url'
                ),
                '_parse_url_observable'
            )
        )
        observable_mapping.update(
            dict.fromkeys(
                (
                    'file_process',
                    'process'
                ),
                '_parse_process_observable'
            )
        )
        observable_mapping.update(
            dict.fromkeys(
                (
                    'ipv4-addr',
                    'ipv6-addr'
                ),
                '_parse_ip_address_observable'
            )
        )
        observable_mapping.update(
            dict.fromkeys(
                (
                    'ipv4-addr_network-traffic',
                    'ipv6-addr_network-traffic',
                    'ipv4-addr_ipv6-addr_network-traffic'
                ),
                '_parse_parse_ip_network_traffic_observable'
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
        self.__x509_pattern_mapping = Mapping(
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

    @property
    def attack_pattern_object_mapping(self) -> dict:
        return self.__attack_pattern_object_mapping

    @property
    def course_of_action_object_mapping(self) -> dict:
        return self.__course_of_action_object_mapping

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
    def file_pattern_mapping(self) -> dict:
        return self.__file_pattern_mapping

    @property
    def identity_object_multiple_fields(self) -> tuple:
        return self.__identity_object_multiple_fields

    @property
    def identity_object_single_fields(self) -> tuple:
        return self.__identity_object_single_fields

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
    def process_pattern_mapping(self) -> dict:
        return self.__process_pattern_mapping

    @property
    def regkey_pattern_mapping(self) -> dict:
        return self.__regkey_pattern_mapping

    @property
    def sigma_object_mapping(self) -> dict:
        return self.__sigma_object_mapping

    @property
    def vulnerability_object_mapping(self) -> dict:
        return self.__vulnerability_object_mapping

    @property
    def x509_pattern_mapping(self) -> dict:
        return self.__x509_pattern_mapping

    @property
    def yara_object_mapping(self) -> dict:
        return self.__yara_object_mapping