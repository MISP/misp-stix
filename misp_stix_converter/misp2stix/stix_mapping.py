#!/usr/bin/env python3
# -*- coding: utf-8 -*-


class MISPtoSTIXMapping:
    __attack_pattern_types = (
        'cmtmf-attack-pattern',
        'mitre-attack-pattern',
        'mitre-enterprise-attack-attack-pattern',
        'mitre-ics-techniques',
        'mitre-mobile-attack-attack-pattern',
        'mitre-pre-attack-attack-pattern'
    )
    __course_of_action_types = (
        'mitre-course-of-action',
        'mitre-enterprise-attack-course-of-action',
        'mitre-mobile-attack-course-of-action'
    )
    __intrusion_set_types = (
        'mitre-enterprise-attack-intrusion-set',
        'mitre-intrusion-set',
        'mitre-mobile-attack-intrusion-set',
        'mitre-pre-attack-intrusion-set'
    )
    __malware_types = (
        'android',
        'backdoor',
        'banker',
        'cryptominers',
        'malpedia',
        'mitre-enterprise-attack-malware',
        'mitre-ics-software',
        'mitre-malware',
        'mitre-mobile-attack-malware',
        'ransomware',
        'stealer'
    )
    __threat_actor_types = (
        '360net-threat-actor',
        'microsoft-activity-group',
        'mitre-ics-groups',
        'threat-actor'
    )
    __tool_types = (
        'botnet',
        'rat',
        'exploit-kit',
        'tds',
        'tool',
        'mitre-tool',
        'mitre-enterprise-attack-tool',
        'mitre-mobile-attack-tool'
    )
    __vulnerability_types = (
        'branded-vulnerability',
    )

    @classmethod
    def attack_pattern_types(cls) -> tuple:
        return cls.__attack_pattern_types

    @classmethod
    def course_of_action_types(cls) -> tuple:
        return cls.__course_of_action_types

    @classmethod
    def intrusion_set_types(cls) -> tuple:
        return cls.__intrusion_set_types

    @classmethod
    def malware_types(cls) -> tuple:
        return cls.__malware_types

    @classmethod
    def threat_actor_types(cls) -> tuple:
        return cls.__threat_actor_types

    @classmethod
    def tool_types(cls) -> tuple:
        return cls.__tool_types

    @classmethod
    def vulnerability_types(cls) -> tuple:
        return cls.__vulnerability_types