#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .. import Mapping
from typing import Optional


class STIX2Mapping:
    def __init__(self):
        self.__bundle_to_misp_mapping = Mapping(
            **{
                '0': '_parse_bundle_with_no_report',
                '1': '_parse_bundle_with_single_report',
                '2': '_parse_bundle_with_multiple_reports'
            }
        )
        self.__timeline_mapping = Mapping(
            **{
                'indicator': ('valid_from', 'valid_until'),
                'observed-data': ('first_observed', 'last_observed')
            }
        )

    def _declare_mapping(self, updates: Optional[dict]=None):
        stix_object_loading_mapping = {
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
            'sighting': '_load_sighting',
            'threat-actor': '_load_threat_actor',
            'tool': '_load_tool',
            'vulnerability': '_load_vulnerability',
            'x-misp-attribute': '_load_custom_attribute',
            'x-misp-object': '_load_custom_object'
        }
        stix_object_loading_mapping.update(
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
        self.__stix_object_loading_mapping = Mapping(**stix_object_loading_mapping)
        self.__stix_to_misp_mapping = Mapping(
            **{
                'attack-pattern': '_parse_attack_pattern',
                'course-of-action': '_parse_course_of_action',
                'grouping': '_parse_grouping',
                'identity': '_parse_identity',
                'indicator': '_parse_indicator',
                'intrusion-set': '_parse_intrusion_set',
                'location': '_parse_location',
                'malware': '_parse_malware',
                'marking-definition': '_parse_marking_definition',
                'note': '_parse_note',
                'observed-data': '_parse_observed_data',
                'relationship': '_parse_relationship',
                'report': '_parse_report',
                'sighting': '_parse_sighting',
                'threat-actor': '_parse_threat_actor',
                'tool': '_parse_tool',
                'vulnerability': '_parse_vulnerability',
                'x-misp-attribute': '_parse_custom_attribute',
                'x-misp-object': '_parse_custom_object'
            }
        )

        # SINGLE ATTRIBUTES MAPPING
        self.__description_attribute = Mapping(type='text', object_relation='description')
        self.__references_attribute = Mapping(type='link', object_relation='references')
        self.__summary_attribute = Mapping(type='text', object_relation='summary')
        self.__vulnerability_attribute = Mapping(type='vulnerability', object_relation='id')

    @property
    def bundle_to_misp_mapping(self) -> dict:
        return self.__bundle_to_misp_mapping

    @property
    def description_attribute(self) -> dict:
        return self.__description_attribute

    @property
    def stix_object_loading_mapping(self) -> dict:
        return self.__stix_object_loading_mapping

    @property
    def stix_to_misp_mapping(self) -> dict:
        return self.__stix_to_misp_mapping

    @property
    def summary_attribute(self) -> dict:
        return self.__summary_attribute

    @property
    def timeline_mapping(self) -> dict:
        return self.__timeline_mapping

    @property
    def references_attribute(self) -> dict:
        return self.__references_attribute

    @property
    def vulnerability_attribute(self) -> dict:
        return self.__vulnerability_attribute