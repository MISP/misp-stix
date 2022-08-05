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
            'email-addr': 'parse_email_address_pattern',
            'email-message': 'parse_email_message_pattern',
            'mac-addr': 'parse_mac_address_pattern',
            'mutex': 'parse_mutex_pattern',
            'network-traffic': 'parse_network_traffic_pattern',
            'process': 'parse_process_pattern',
            'user-account': 'parse_user_account_pattern',
            'windows-registry-key': 'parse_regkey_pattern',
            'x509-certificate': 'parse_x509_pattern'
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

    @property
    def attack_pattern_object_mapping(self) -> dict:
        return self.__attack_pattern_object_mapping

    @property
    def course_of_action_object_mapping(self) -> dict:
        return self.__course_of_action_object_mapping

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
    def sigma_object_mapping(self) -> dict:
        return self.__sigma_object_mapping

    @property
    def vulnerability_object_mapping(self) -> dict:
        return self.__vulnerability_object_mapping

    @property
    def yara_object_mapping(self) -> dict:
        return self.__yara_object_mapping