#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .. import Mapping
from abc import ABCMeta
from typing import Union


class STIX2toMISPMapping(metaclass=ABCMeta):
    # Some general mapping variables
    __bundle_to_misp_mapping = Mapping(
        **{
            '0': '_parse_bundle_with_no_report',
            '1': '_parse_bundle_with_single_report',
            '2': '_parse_bundle_with_multiple_reports'
        }
    )
    __marking_extension_mapping = Mapping(
        **{
            'extension-definition--3a65884d-005a-4290-8335-cb2d778a83ce': 'acs'
        }
    )
    __marking_vocabularies_fields = (
        'caveat', 'classification', 'entity', 'formal_determination',
        'sensitivity', 'shareability'
    )
    __object_type_refs_to_skip = (
        'marking-definition', 'opinion', 'relationship',
        'sighting', 'x-misp-opinion'
    )
    __observable_object_types = (
        'network-traffic',
        'file',
        'email-message',
        'artifact',
        'autonomous-system',
        'directory',
        'domain-name',
        'email-addr',
        'ipv4-addr',
        'ipv6-addr',
        'mac-addr',
        'mutex',
        'process',
        'software',
        'url',
        'user-account',
        'windows-registry-key',
        'x509-certificate'
    )
    __stix_object_loading_mapping = Mapping(
        **{
            'attack-pattern': '_load_attack_pattern',
            'campaign': '_load_campaign',
            'course-of-action': '_load_course_of_action',
            'grouping': '_load_grouping',
            'identity': '_load_identity',
            'indicator': '_load_indicator',
            'intrusion-set': '_load_intrusion_set',
            'location': '_load_location',
            'malware': '_load_malware',
            'malware-analysis': '_load_malware_analysis',
            'marking-definition': '_load_marking_definition',
            'observed-data': '_load_observed_data',
            'relationship': '_load_relationship',
            'report': '_load_report',
            'sighting': '_load_sighting',
            'threat-actor': '_load_threat_actor',
            'tool': '_load_tool',
            'vulnerability': '_load_vulnerability',
            **dict.fromkeys(
                __observable_object_types,
                '_load_observable_object'
            )
        }
    )
    __stix_to_misp_mapping = Mapping(
        **{
            'attack-pattern': 'attack_pattern_parser',
            'campaign': 'campaign_parser',
            'course-of-action': 'course_of_action_parser',
            'identity': 'identity_parser',
            'indicator': 'indicator_parser',
            'intrusion-set': 'intrusion_set_parser',
            'location': 'location_parser',
            'malware': 'malware_parser',
            'malware-analysis': 'malware_analysis_parser',
            'note': 'note_parser',
            'observed-data': 'observed_data_parser',
            'sighting': 'sighting_parser',
            'threat-actor': 'threat_actor_parser',
            'tool': 'tool_parser',
            'vulnerability': 'vulnerability_parser',
            'x-misp-attribute': 'custom_object_parser',
            'x-misp-event-report': 'custom_object_parser',
            'x-misp-galaxy-cluster': 'custom_object_parser',
            'x-misp-object': 'custom_object_parser'
        }
    )

    # KNOWN IDENTITY REFERENCES
    __identity_references = {
        "identity--b3bca3c2-1f3d-4b54-b44f-dac42c3a8f01": "CISA"
    }

    @classmethod
    def bundle_to_misp_mapping(cls, field: str) -> Union[str, None]:
        return cls.__bundle_to_misp_mapping.get(field)

    @classmethod
    def identity_references(cls, identity_id: str) -> Union[str, None]:
        return cls.__identity_references.get(identity_id)

    @classmethod
    def marking_extension_mapping(cls, field: str) -> Union[str, None]:
        return cls.__marking_extension_mapping.get(field)

    @classmethod
    def marking_vocabularies_fields(cls) -> tuple:
        return cls.__marking_vocabularies_fields

    @classmethod
    def object_type_refs_to_skip(cls) -> tuple:
        return cls.__object_type_refs_to_skip

    @classmethod
    def observable_object_types(cls) -> tuple:
        return cls.__observable_object_types

    @classmethod
    def stix_object_loading_mapping(cls) -> dict:
        return cls.__stix_object_loading_mapping

    @classmethod
    def stix_to_misp_mapping(cls, field: str) -> Union[str, None]:
        return cls.__stix_to_misp_mapping.get(field)
