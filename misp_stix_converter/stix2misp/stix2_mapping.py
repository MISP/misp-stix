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
        self.__bundle_to_misp_mapping = Mapping(
            **{
                '0': '_parse_bundle_with_no_report',
                '1': '_parse_bundle_with_single_report',
                '2': '_parse_bundle_with_multiple_reports'
            }
        )

    def _declare_mapping(self, updates: Optional[dict]=None):
        stix_to_misp_mapping = {
            'attack-pattern': '_load_attack_pattern',
            'course-of-action': '_load_course_of_action',
            'grouping': '_load_grouping',
            'identity': '_load_identity',
            'indicator': '_load_indicator',
            'intrusion-set': '_load_intrusion_set',
            'location': '_load_location',
            'malware': '_load_malware',
            'marking-definition': '_load_marking_definition',
            'note': '_load_note',
            'observed-data': '_load_observed_data',
            'relationship': '_load_relationship',
            'report': '_load_report',
            'threat-actor': '_load_threat_actor',
            'tool': '_load_tool',
            'vulnerability': '_load_vulnerability',
            'x-misp-attribute': '_load_custom_attribute',
            'x-misp-object': '_load_custom_object'
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
    def bundle_to_misp_mapping(self) -> dict:
        return self.__bundle_to_misp_mapping

    @property
    def pattern_forbidden_relations(self) -> tuple:
        return self.__pattern_forbidden_relations

    @property
    def stix_to_misp_mapping(self) -> dict:
        return self.__stix_to_misp_mapping