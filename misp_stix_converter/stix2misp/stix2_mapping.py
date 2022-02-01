#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .. import Mapping
from typing import Optional


class STIX2Mapping:
    def __init__(self):
        self.__pattern_forbidden_relations = (
            ' LIKE ',
            ' FOLLOWEDBY ',
            ' MATCHES ',
            ' ISSUBSET ',
            ' ISSUPERSET ',
            ' REPEATS '
        )

    def _declare_mapping(self, updates: Optional[dict]=None):
        stix_to_misp_mapping = {
            'attack-pattern': '_load_attack_pattern',
            'course-of-action': '_load_course_of_action',
            'grouping': '_load_grouping',
            'identity': '_load_identity',
            'indicator': '_parse_indicator',
            'intrusion-set': '_load_intrusion_set',
            'location': '_parse_location',
            'malware': '_load_malware',
            'marking-definition': '_load_marking_definition',
            'note': '_parse_note',
            'observed-data': '_parse_observed_data',
            'relationship': '_load_relationship',
            'report': '_load_report',
            'threat-actor': '_load_threat_actor',
            'tool': '_load_tool',
            'vulnerability': '_load_vulnerability',
            'x-misp-attribute': '_parse_custom_attribute',
            'x-misp-object': '_parse_custom_object'
        }
        stix_to_misp_mapping.update(
            dict.fromkeys(
                (
                    'artifact',
                    'autonomous-system',
                    'directory',
                    'domain-name',
                    'email-addr',
                    'email-message',
                    'file',
                    'ipv4-addr',
                    'ipv6-addr',
                    'mac-addr',
                    'mutex',
                    'network-traffic',
                    'process',
                    'software',
                    'url',
                    'user-account',
                    'windows-registry-key',
                    'x509-certificate'
                ),
                '_load_observable_object'
            )
        )
        self.__stix_to_misp_mapping = Mapping(**stix_to_misp_mapping)


    @property
    def pattern_forbidden_relations(self) -> tuple:
        return self.__pattern_forbidden_relations

    @property
    def stix_to_misp_mapping(self) -> dict:
        return self.__stix_to_misp_mapping