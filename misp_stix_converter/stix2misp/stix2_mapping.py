#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .. import Mapping
from typing import Optional


class STIX2toMISPMapping:
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
        reference_attribute = {'type': 'link', 'object_relation': 'reference'}
        references_attribute = {'type': 'link', 'object_relation': 'references'}
        snort_attribute = {'type': 'snort', 'object_relation': 'suricata'}
        version_attribute = {'type': 'text', 'object_relation': 'version'}

        # SINGLE ATTRIBUTES MAPPING
        self.__accuracy_radius_attribute = Mapping(
            **{'type': 'float', 'object_relation': 'accuracy_radius'}
        )
        self.__args_attribute = Mapping(
            **{'type': 'text', 'object_relation': 'args'}
        )
        self.__attack_pattern_id_attribute = Mapping(
            **{'type': 'text', 'object_relation': 'id'}
        )
        self.__attack_pattern_references_attribute = Mapping(**references_attribute)
        self.__command_line_attribute = Mapping(
            **{'type': 'text', 'object_relation': 'command-line'}
        )
        self.__comment_attribute = Mapping(**comment_attribute)
        self.__content_type_attribute = Mapping(
            **{'type': 'other', 'object_relation': 'content-type'}
        )
        self.__cookie_attribute = Mapping(
            **{'type': 'text', 'object_relation': 'cookie'}
        )
        self.__creation_time_attribute = Mapping(
            **{'type': 'datetime', 'object_relation': 'creation-time'}
        )
        self.__current_directory_attribute = Mapping(
            **{'type': 'text', 'object_relation': 'current-directory'}
        )
        self.__data_attribute = Mapping(
            **{'type': 'text', 'object_relation': 'data'}
        )
        self.__data_type_attribute = Mapping(
            **{'type': 'text', 'object_relation': 'data-type'}
        )
        self.__description_attribute = Mapping(
            **{'type': 'text', 'object_relation': 'description'}
        )
        self.__domain_attribute = Mapping(
            **{'type': 'domain', 'object_relation': 'domain'}
        )
        self.__dst_port_attribute = Mapping(
            **{'type': 'port', 'object_relation': 'dst-port'}
        )
        self.__email_body_attribute = Mapping(
            **{'type': 'email-body', 'object_relation': 'email-body'}
        )
        self.__email_subject_attribute = Mapping(
            **{'type': 'email-subject', 'object_relation': 'subject'}
        )
        self.__file_encoding_attribute = Mapping(
            **{'type': 'text', 'object_relation': 'file-encoding'}
        )
        self.__filename_attribute = Mapping(
            **{'type': 'filename', 'object_relation': 'filename'}
        )
        self.__hidden_attribute = Mapping(
            **{'type': 'boolean', 'object_relation': 'hidden'}
        )
        self.__ip_attribute = Mapping(
            **{'type': 'ip-dst', 'object_relation': 'ip'}
        )
        self.__is_self_signed_attribute = Mapping(
            **{'type': 'boolean', 'object_relation': 'self_signed'}
        )
        self.__issuer_attribute = Mapping(
            **{'type': 'text', 'object_relation': 'issuer'}
        )
        self.__last_modified_attribute = Mapping(
            **{'type': 'datetime', 'object_relation': 'last-modified'}
        )
        self.__message_id_attribute = Mapping(
            **{'type': 'email-message-id', 'object_relation': 'message-id'}
        )
        self.__method_attribute = Mapping(
            **{'type': 'http-method', 'object_relation': 'method'}
        )
        self.__mime_type_attribute = Mapping(
            **{'type': 'mime-type', 'object_relation': 'mimetype'}
        )
        self.__name_attribute = Mapping(
            **{'type': 'text', 'object_relation': 'name'}
        )
        self.__pid_attribute = Mapping(
            **{'type': 'text', 'object_relation': 'pid'}
        )
        self.__pubkey_info_algorithm_attribute = Mapping(
            **{'type': 'text', 'object_relation': 'pubkey-info-algorithm'}
        )
        self.__pubkey_info_exponent_attribute = Mapping(
            **{'type': 'text', 'object_relation': 'pubkey-info-exponent'}
        )
        self.__pubkey_info_modulus_attribute = Mapping(
            **{'type': 'text', 'object_relation': 'pubkey-info-modulus'}
        )
        self.__references_attribute = Mapping(**references_attribute)
        self.__referer_attribute = Mapping(
            **{'type': 'other', 'object_relation': 'referer'}
        )
        self.__regkey_attribute = Mapping(
            **{'type': 'regkey', 'object_relation': 'key'}
        )
        self.__send_date_attribute = Mapping(
            **{'type': 'datetime', 'object_relation': 'send-date'}
        )
        self.__serial_number_attribute = Mapping(
            **{'type': 'text', 'object_relation': 'serial-number'}
        )
        self.__sigma_attribute = Mapping(
            **{'type': 'sigma', 'object_relation': 'sigma'}
        )
        self.__sigma_reference_attribute = Mapping(**reference_attribute)
        self.__sigma_rule_name_attribute = Mapping(
            **{'type': 'text', 'object_relation': 'sigma-rule-name'}
        )
        self.__signature_algorithm_attribute = Mapping(
            **{'type': 'text', 'object_relation': 'signature_algorithm'}
        )
        self.__size_in_bytes_attribute = Mapping(
            **{'type': 'size-in-bytes', 'object_relation': 'size-in-bytes'}
        )
        self.__snort_attribute = Mapping(**snort_attribute)
        self.__src_port_attribute = Mapping(
            **{'type': 'port', 'object_relation': 'src-port'}
        )
        self.__subject_attribute = Mapping(
            **{'type': 'text', 'object_relation': 'subject'}
        )
        self.__summary_attribute = Mapping(
            **{'type': 'text', 'object_relation': 'summary'}
        )
        self.__suricata_reference_attribute = Mapping(
            **{'type': 'link', 'object_relation': 'ref'}
        )
        self.__uri_attribute = Mapping(
            **{'type': 'uri', 'object_relation': 'uri'}
        )
        self.__url_attribute = Mapping(
            **{'type': 'url', 'object_relation': 'url'}
        )
        self.__user_agent_attribute = Mapping(
            **{'type': 'text', 'object_relation': 'user-agent'}
        )
        self.__validity_not_after_attribute = Mapping(
            **{'type': 'datetime', 'object_relation': 'validity-not-after'}
        )
        self.__validity_not_before_attribute = Mapping(
            **{'type': 'datetime', 'object_relation': 'validity-not-before'}
        )
        self.__version_attribute = Mapping(**version_attribute)
        self.__vulnerability_attribute = Mapping(
            **{'type': 'vulnerability', 'object_relation': 'id'}
        )
        self.__yara_attribute = Mapping(
            **{'type': 'yara', 'object_relation': 'yara'}
        )
        self.__yara_reference_attribute = Mapping(**reference_attribute)
        self.__yara_rule_name_attribute = Mapping(
            **{'type': 'text', 'object_relation': 'yara-rule-name'}
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

        self.__attack_pattern_meta_mapping = Mapping(
            aliases = 'synonyms',
            external_references = 'refs',
            kill_chain_phases = 'kill_chain'
        )
        self.__campaign_meta_mapping = Mapping(
            aliases = 'synonyms',
            objective = 'objective'
        )
        self.__intrusion_set_meta_mapping = Mapping(
            aliases = 'synonyms',
            goals = 'goals',
            primary_motivation = 'primary_motivation',
            resource_level = 'resource_level',
            secondary_motivations = 'secondary_motivations'
        )
        self.__malware_meta_mapping = Mapping(
            aliases = 'synonyms',
            architecture_execution_envs = 'architecture_execution_envs',
            capabilities = 'capabilities',
            implementation_languages = 'implementation_languages',
            is_family = 'is_family',
            kill_chain_phases = 'kill_chain',
            labels = 'labels',
            malware_types = 'malware_types',
            operating_system_refs = 'operating_system_refs',
            sample_refs = 'sample_refs'
        )
        self.__threat_actor_meta_mapping = Mapping(
            aliases = 'synonyms',
            goals = 'goals',
            labels = 'labels',
            personal_motivations = 'personal_motivations',
            primary_motivation = 'primary_motivation',
            resource_level = 'resource_level',
            roles = 'roles',
            secondary_motivations = 'secondary_motivations',
            sophistication = 'sophistication',
            threat_actor_types = 'threat_actor_types'
        )
        self.__tool_meta_mapping = Mapping(
            aliases = 'synonyms',
            kill_chain_phases = 'kill_chain',
            labels = 'labels',
            tool_types = 'tool_types',
            tool_version = 'tool_version'
        )

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
    def args_attribute(self) -> dict:
        return self.__args_attribute

    @property
    def attack_pattern_id_attribute(self) -> dict:
        return self.__attack_pattern_id_attribute

    @property
    def attack_pattern_meta_mapping(self) -> dict:
        return self.__attack_pattern_meta_mapping

    @property
    def attack_pattern_references_attribute(self) -> dict:
        return self.__attack_pattern_references_attribute

    @property
    def bundle_to_misp_mapping(self) -> dict:
        return self.__bundle_to_misp_mapping

    @property
    def campaign_meta_mapping(self) -> dict:
        return self.__campaign_meta_mapping

    @property
    def command_line_attribute(self) -> dict:
        return self.__command_line_attribute

    @property
    def comment_attribute(self) -> dict:
        return self.__comment_attribute

    @property
    def connection_protocols(self) -> dict:
        return self.__connection_protocols

    @property
    def content_type_attribute(self) -> dict:
        return self.__content_type_attribute

    @property
    def cookie_attribute(self) -> dict:
        return self.__cookie_attribute

    @property
    def creation_time_attribute(self) -> dict:
        return self.__creation_time_attribute

    @property
    def current_directory_attribute(self) -> dict:
        return self.__current_directory_attribute

    @property
    def description_attribute(self) -> dict:
        return self.__description_attribute

    @property
    def data_attribute(self) -> dict:
        return self.__data_attribute

    @property
    def data_type_attribute(self) -> dict:
        return self.__data_type_attribute

    @property
    def domain_attribute(self) -> dict:
        return self.__domain_attribute

    @property
    def dst_port_attribute(self) -> dict:
        return self.__dst_port_attribute

    @property
    def email_body_attribute(self) -> dict:
        return self.__email_body_attribute

    @property
    def email_subject_attribute(self) -> dict:
        return self.__email_subject_attribute

    @property
    def file_encoding_attribute(self) -> dict:
        return self.__file_encoding_attribute

    @property
    def filename_attribute(self) -> dict:
        return self.__filename_attribute

    @property
    def galaxy_name_mapping(self) -> dict:
        return self.__galaxy_name_mapping

    @property
    def hidden_attribute(self) -> dict:
        return self.__hidden_attribute

    @property
    def intrusion_set_meta_mapping(self) -> dict:
        return self.__intrusion_set_meta_mapping

    @property
    def ip_attribute(self) -> dict:
        return self.__ip_attribute

    @property
    def is_self_signed_attribute(self) -> dict:
        return self.__is_self_signed_attribute

    @property
    def issuer_attribute(self) -> dict:
        return self.__issuer_attribute

    @property
    def last_modified_attribute(self) -> dict:
        return self.__last_modified_attribute

    @property
    def location_object_mapping(self) -> dict:
        return self.__location_object_mapping

    @property
    def malware_meta_mapping(self) -> dict:
        return self.__malware_meta_mapping

    @property
    def message_id_attribute(self) -> dict:
        return self.__message_id_attribute

    @property
    def method_attribute(self) -> dict:
        return self.__method_attribute

    @property
    def mime_type_attribute(self) -> dict:
        return self.__mime_type_attribute

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
    def pid_attribute(self) -> dict:
        return self.__pid_attribute

    @property
    def pubkey_info_algorithm_attribute(self) -> dict:
        return self.__pubkey_info_algorithm_attribute

    @property
    def pubkey_info_exponent_attribute(self) -> dict:
        return self.__pubkey_info_exponent_attribute

    @property
    def pubkey_info_modulus_attribute(self) -> dict:
        return self.__pubkey_info_modulus_attribute

    @property
    def references_attribute(self) -> dict:
        return self.__references_attribute

    @property
    def referer_attribute(self) -> dict:
        return self.__referer_attribute

    @property
    def regkey_attribute(self) -> dict:
        return self.__regkey_attribute

    @property
    def send_date_attribute(self) -> dict:
        return self.__send_date_attribute

    @property
    def serial_number_attribute(self) -> dict:
        return self.__serial_number_attribute

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
    def signature_algorithm_attribute(self) -> dict:
        return self.__signature_algorithm_attribute

    @property
    def size_in_bytes_attribute(self) -> dict:
        return self.__size_in_bytes_attribute

    @property
    def snort_attribute(self) -> dict:
        return self.__snort_attribute

    @property
    def src_port_attribute(self) -> dict:
        return self.__src_port_attribute

    @property
    def stix_object_loading_mapping(self) -> dict:
        return self.__stix_object_loading_mapping

    @property
    def stix_to_misp_mapping(self) -> dict:
        return self.__stix_to_misp_mapping

    @property
    def subject_attribute(self) -> dict:
        return self.__subject_attribute

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
    def threat_actor_meta_mapping(self) -> dict:
        return self.__threat_actor_meta_mapping

    @property
    def timeline_mapping(self) -> dict:
        return self.__timeline_mapping

    @property
    def tool_meta_mapping(self) -> dict:
        return self.__tool_meta_mapping

    @property
    def uri_attribute(self) -> dict:
        return self.__uri_attribute

    @property
    def url_attribute(self) -> dict:
        return self.__url_attribute

    @property
    def user_agent_attribute(self) -> dict:
        return self.__user_agent_attribute

    @property
    def validity_not_after_attribute(self) -> dict:
        return self.__validity_not_after_attribute

    @property
    def validity_not_before_attribute(self) -> dict:
        return self.__validity_not_before_attribute

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
    def yara_reference_attribute(self) -> dict:
        return self.__yara_reference_attribute

    @property
    def yara_rule_name_attribute(self) -> dict:
        return self.__yara_rule_name_attribute
