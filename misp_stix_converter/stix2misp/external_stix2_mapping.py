#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .. import Mapping
from .stix2_mapping import STIX2Mapping


class ExternalSTIX2Mapping(STIX2Mapping):
    def __init__(self):
        super().__init__()
        self._declare_mapping()
        self.__pattern_forbidden_relations = (
            ' LIKE ',
            ' FOLLOWEDBY ',
            ' MATCHES ',
            ' ISSUBSET ',
            ' ISSUPERSET',
            ' REPEATS '
        )

        # MAIN STIX OBJECTS MAPPING
        observable_mapping = {
            ('domain-name', 'network-traffic'): '_parse_domain_network_traffic_observable',
            ('email-addr',): '_parse_email_address_observable',
            ('mac-addr',): '_parse_mac_address_observable',
            ('mutex',): 'parse_mutex_observable',
            ('x509-certificate',): 'parse_x509_observable',
            ('user-account',): 'parse_user_account_observable',
            ('windows-registry-key',): 'parse_regkey_observable'
        }
        observable_mapping.update(
            dict.fromkeys(
                (
                    ('artifact', 'file'),
                    ('artifact', 'directory', 'file'),
                    ('directory', 'file'),
                    ('file',)
                ),
                '_parse_file_observable'
            )
        )
        observable_mapping.update(
            dict.fromkeys(
                (
                    ('artifact', 'email-addr', 'email-message', 'file'),
                    ('email-addr', 'email-message'),
                    ('email-addr', 'email-message', 'file'),
                    ('email-message',)
                ),
                '_parse_email_observable'
            )
        )
        observable_mapping.update(
            dict.fromkeys(
                (
                    ('autonomous-system',),
                    ('autonomous-system', 'ipv4-addr'),
                    ('autonomous-system', 'ipv6-addr'),
                    ('autonomous-system', 'ipv4-addr', 'ipv6-addr')
                ),
                '_parse_asn_observable'
            )
        )
        observable_mapping.update(
            dict.fromkeys(
                (
                    ('domain-name',),
                    ('domain-name', 'ipv4-addr'),
                    ('domain-name', 'ipv6-addr'),
                    ('domain-name', 'ipv4-addr', 'ipv6-addr')
                ),
                '_parse_domain_ip_observable'
            )
        )
        observable_mapping.update(
            dict.fromkeys(
                (
                    ('domain-name', 'ipv4-addr', 'network-traffic'),
                    ('domain-name', 'ipv6-addr', 'network-traffic'),
                    ('domain-name', 'ipv4-addr', 'ipv6-addr', 'network-traffic')
                ),
                '_parse_domain_ip_network_traffic_observable'
            )
        )
        observable_mapping.update(
            dict.fromkeys(
                (
                    ('domain-name', 'network-traffic', 'url'),
                    ('url',)
                ),
                '_parse_url_observable'
            )
        )
        observable_mapping.update(
            dict.fromkeys(
                (
                    ('file', 'process'),
                    ('process',)
                ),
                '_parse_process_observable'
            )
        )
        observable_mapping.update(
            dict.fromkeys(
                (
                    ('ipv4-addr',),
                    ('ipv6-addr',),
                ),
                '_parse_ip_address_observable'
            )
        )
        observable_mapping.update(
            dict.fromkeys(
                (
                    ('ipv4-addr', 'network-traffic'),
                    ('ipv6-addr', 'network-traffic'),
                    ('ipv4-addr', 'ipv6-addr', 'network-traffic')
                ),
                '_parse_parse_ip_network_traffic_observable'
            )
        )
        self.__observable_mapping = Mapping(**observable_mapping)
        pattern_mapping = {
            ('email-addr',): 'parse_email_address_pattern',
            ('email-message',): 'parse_email_message_pattern',
            ('mac-addr',): 'parse_mac_address_pattern',
            ('mutex',): 'parse_mutex_pattern',
            ('network-traffic',): 'parse_network_traffic_pattern',
            ('process',): 'parse_process_pattern',
            ('user-account',): 'parse_user_account_pattern',
            ('windows-registry-key',): 'parse_regkey_pattern',
            ('x509-certificate',): 'parse_x509_pattern'
        }
        pattern_mapping.update(
            dict.fromkeys(
                (
                    ('artifact', 'file'),
                    ('directory',),
                    ('directory', 'file'),
                    ('file',)
                ),
                '_parse_file_pattern'
            )
        )
        pattern_mapping.update(
            dict.fromkeys(
                (
                    ('autonomous-system', ),
                    ('autonomous-system', 'ipv4-addr'),
                    ('autonomous-system', 'ipv6-addr'),
                    ('autonomous-system', 'ipv4-addr', 'ipv6-addr')
                ),
                '_parse_asn_pattern'
            )
        )
        pattern_mapping.update(
            dict.fromkeys(
                (
                    ('domain-name',),
                    ('domain-name', 'ipv4-addr'),
                    ('domain-name', 'ipv6-addr'),
                    ('domain-name', 'ipv4-addr', 'ipv6-addr'),
                    ('domain-name', 'network-traffic')
                ),
                '_parse_domain_ip_port_pattern'
            )
        )
        pattern_mapping.update(
            dict.fromkeys(
                (
                    ('domain-name', 'ipv4-addr', 'url'),
                    ('domain-name', 'ipv6-addr', 'url'),
                    ('domain-name', 'ipv4-addr', 'ipv6-addr', 'url'),
                    ('domain-name', 'network-traffic', 'url'),
                    ('url',)
                ),
                '_parse_url_pattern'
            )
        )
        pattern_mapping.update(
            dict.fromkeys(
                (
                    ('ipv4-addr',),
                    ('ipv6-addr',),
                    ('ipv4-addr', 'ipv6-addr')
                ),
                '_parse_ip_address_pattern'
            )
        )
        self.__pattern_mapping = Mapping(**pattern_mapping)
        self.__pattern_type_mapping = Mapping(
            sigma = '_parse_sigma_pattern',
            snort = '_parse_snort_pattern',
            suricata = '_parse_suricata_pattern',
            yara = '_parse_yara_pattern'
        )

        # MISP OBJECTS MAPPING
        self.__vulnerability_object_mapping = Mapping(
            name = self.summary_attribute,
            description = self.description_attribute
        )

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
    def pattern_type_mapping(self) -> dict:
        return self.__pattern_type_mapping

    @property
    def vulnerability_object_mapping(self) -> dict:
        return self.__vulnerability_object_mapping
