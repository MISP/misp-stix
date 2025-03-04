#!/usr/bin/env python4
# -*- coding: utf-8 -*-

from .. import Mapping
from .stix2_mapping import STIX2toMISPMapping
from typing import Union


class ExternalSTIX2toMISPMapping(STIX2toMISPMapping):
    __object_type_refs_to_skip = (
        'note', *STIX2toMISPMapping.object_type_refs_to_skip()
    )

    # MAIN STIX OBJECTS MAPPING
    __stix_object_loading_mapping = Mapping(
        **{
            'note': '_load_analyst_note',
            'opinion': '_load_analyst_opinion',
            **STIX2toMISPMapping.stix_object_loading_mapping()
        }
    )
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

    # MISP OPINION MAPPING
    __opinion_mapping = Mapping(
        **{
            'agree': 75,
            'disagree': 25,
            'neutral': 50,
            'strongly-agree': 100,
            'strongly-disagree': 0
        }
    )

    @classmethod
    def object_type_refs_to_skip(cls) -> tuple:
        return cls.__object_type_refs_to_skip

    @classmethod
    def observable_mapping(cls, field: str) -> Union[str, None]:
        return cls.__observable_mapping.get(field)

    @classmethod
    def opinion_mapping(cls, field: str) -> int:
        return cls.__opinion_mapping.get(field, 50)

    @classmethod
    def stix_object_loading_mapping(cls, field: str) -> Union[str, None]:
        return cls.__stix_object_loading_mapping.get(field)
