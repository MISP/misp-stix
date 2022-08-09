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
        self.__observable_object_types = (
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
        )
        self.__timeline_mapping = Mapping(
            **{
                'indicator': ('valid_from', 'valid_until'),
                'observed-data': ('first_observed', 'last_observed')
            }
        )

    def _declare_mapping(self, updates: Optional[dict]={}):
        SROs = ('opinion', 'relationship', 'sighting', 'x-misp-opinion')
        self.__object_type_refs_to_skip = self.observable_object_types + SROs
        stix_object_loading_mapping = {
            'attack-pattern': '_load_attack_pattern',
            'campaign': '_load_campaign',
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
            'opinion': '_load_opinion',
            'relationship': '_load_relationship',
            'report': '_load_report',
            'sighting': '_load_sighting',
            'threat-actor': '_load_threat_actor',
            'tool': '_load_tool',
            'vulnerability': '_load_vulnerability',
            'x-misp-attribute': '_load_custom_attribute',
            'x-misp-object': '_load_custom_object',
            'x-misp-opinion': '_load_custom_opinion'
        }
        stix_object_loading_mapping.update(
            dict.fromkeys(
                self.observable_object_types,
                '_load_observable_object'
            )
        )
        self.__stix_object_loading_mapping = Mapping(**stix_object_loading_mapping)
        self.__stix_to_misp_mapping = Mapping(
            **{
                'attack-pattern': '_parse_attack_pattern',
                'campaign': '_parse_campaign',
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
                'report': '_parse_report',
                'sighting': '_parse_sighting',
                'threat-actor': '_parse_threat_actor',
                'tool': '_parse_tool',
                'vulnerability': '_parse_vulnerability',
                'x-misp-attribute': '_parse_custom_attribute',
                'x-misp-object': '_parse_custom_object'
            }
        )

        # ATTRIBUTES MAPPING DECLARATION
        comment_attribute = {'type': 'comment', 'object_relation': 'comment'}
        sigma_attribute = {'type': 'sigma', 'object_relation': 'sigma'}
        snort_attribute = {'type': 'snort', 'object_relation': 'suricata'}
        version_attribute = {'type': 'text', 'object_relation': 'version'}
        yara_attribute = {'type': 'yara', 'object_relation': 'yara'}

        # SINGLE ATTRIBUTES MAPPING
        self.__accuracy_radius_attribute = Mapping(
            **{
                'type': 'float',
                'object_relation': 'accuracy_radius'
            }
        )
        self.__attack_pattern_id_attribute = {'type': 'text', 'object_relation': 'id'}
        self.__attack_pattern_references_attribute = {
            'type': 'link',
            'object_relation': 'references'
        }
        self.__comment_attribute = Mapping(**comment_attribute)
        self.__description_attribute = {'type': 'text', 'object_relation': 'description'}
        self.__name_attribute = {'type': 'text', 'object_relation': 'name'}
        self.__references_attribute = Mapping(
            **{
                'type': 'link',
                'object_relation': 'references'
            }
        )
        self.__sigma_attribute = Mapping(**sigma_attribute)
        self.__sigma_reference_attribute = Mapping(
            **{
                'type': 'link',
                'object_relation': 'reference'
            }
        )
        self.__sigma_rule_name_attribute = Mapping(
            **{
                'type': 'text',
                'object_relation': 'sigma-rule-name'
            }
        )
        self.__snort_attribute = Mapping(**snort_attribute)
        self.__summary_attribute = Mapping(**{'type': 'text', 'object_relation': 'summary'})
        self.__suricata_reference_attribute = Mapping(
            **{
                'type': 'link',
                'object_relation': 'ref'
            }
        )
        self.__version_attribute = Mapping(**version_attribute)
        self.__vulnerability_attribute = Mapping(
            **{
                'type': 'vulnerability',
                'object_relation': 'id'
            }
        )
        self.__yara_attribute = Mapping(**yara_attribute)
        self.__yara_rule_name_attribute = Mapping(**{'type': 'text', 'object_relation': 'yara-rule-name'})

        # MISP OBJECTS MAPPING
        self.__connection_protocols = {
            "IP": "3", "ICMP": "3", "ARP": "3",
            "TCP": "4", "UDP": "4",
            "HTTP": "7", "HTTPS": "7", "FTP": "7"
        }
        location_object_mapping = {
            'city': {'type': 'text', 'object_relation': 'city'},
            'country': {'type': 'text', 'object_relation': 'countrycode'},
            'description': {'type': 'text', 'object_relation': 'text'},
            'latitude': {'type': 'float', 'object_relation': 'latitude'},
            'longitude': {'type': 'float', 'object_relation': 'longitude'},
            'postal_code': {'type': 'text', 'object_relation': 'zipcode'},
            'region': {'type': 'text', 'object_relation': 'region'},
            'street_address': {'type': 'text', 'object_relation': 'address'}
        }
        if 'location' in updates:
            location_object_mapping.update(updates['location'])
        self.__location_object_mapping = Mapping(**location_object_mapping)
        self.__suricata_object_mapping = Mapping(
            pattern = snort_attribute,
            description = comment_attribute,
            pattern_version = version_attribute
        )

    @property
    def accuracy_radius_attribute(self) -> dict:
        return self.__accuracy_radius_attribute

    @property
    def attack_pattern_id_attribute(self) -> dict:
        return self.__attack_pattern_id_attribute

    @property
    def attack_pattern_references_attribute(self) -> dict:
        return self.__attack_pattern_references_attribute

    @property
    def bundle_to_misp_mapping(self) -> dict:
        return self.__bundle_to_misp_mapping

    @property
    def comment_attribute(self) -> dict:
        return self.__comment_attribute

    @property
    def connection_protocols(self) -> dict:
        return self.__connection_protocols

    @property
    def description_attribute(self) -> dict:
        return self.__description_attribute

    @property
    def location_object_mapping(self) -> dict:
        return self.__location_object_mapping

    @property
    def name_attribute(self) -> dict:
        return self.__name_attribute

    @property
    def object_type_refs_to_skip(self) -> tuple:
        return self.__object_type_refs_to_skip

    @property
    def observable_object_types(self) -> tuple:
        return self.__observable_object_types

    @property
    def sigma_attribute(self) -> dict:
        return self.__sigma_attribute

    @property
    def sigma_reference_attribute(self) -> dict:
        return self.__sigma_reference_attribute

    @property
    def sigma_rule_name_attribute(self) -> dict:
        return self.__sigma_rule_name_attribute

    @property
    def snort_attribute(self) -> dict:
        return self.__snort_attribute

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
    def suricata_object_mapping(self) -> dict:
        return self.__suricata_object_mapping

    @property
    def suricata_reference_attribute(self) -> dict:
        return self.__suricata_reference_attribute

    @property
    def timeline_mapping(self) -> dict:
        return self.__timeline_mapping

    @property
    def references_attribute(self) -> dict:
        return self.__references_attribute

    @property
    def version_attribute(self) -> dict:
        return self.__version_attribute

    @property
    def vulnerability_attribute(self) -> dict:
        return self.__vulnerability_attribute

    @property
    def yara_attribute(self) -> dict:
        return self.__yara_attribute

    @property
    def yara_rule_name_attribute(self) -> dict:
        return self.__yara_rule_name_attribute
