#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from types import MappingProxyType
from typing import Optional

# The MISP galaxy types the export writes as each kind of STIX construct. A
# galaxy type in none of them has no construct: the export warns it is not
# mapped and keeps the cluster as a tag only.
_ATTACK_PATTERN_TYPES = (
    'cmtmf-attack-pattern',
    'mitre-attack-pattern',
    'mitre-enterprise-attack-attack-pattern',
    'mitre-ics-techniques',
    'mitre-mobile-attack-attack-pattern',
    'mitre-pre-attack-attack-pattern'
)
_COURSE_OF_ACTION_TYPES = (
    'mitre-course-of-action',
    'mitre-enterprise-attack-course-of-action',
    'mitre-mobile-attack-course-of-action'
)
_INTRUSION_SET_TYPES = (
    'mitre-enterprise-attack-intrusion-set',
    'mitre-intrusion-set',
    'mitre-mobile-attack-intrusion-set',
    'mitre-pre-attack-intrusion-set'
)
_MALWARE_TYPES = (
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
_THREAT_ACTOR_TYPES = (
    '360net-threat-actor',
    'microsoft-activity-group',
    'mitre-ics-groups',
    'threat-actor'
)
_TOOL_TYPES = (
    'botnet',
    'rat',
    'exploit-kit',
    'tds',
    'tool',
    'mitre-tool',
    'mitre-enterprise-attack-tool',
    'mitre-mobile-attack-tool'
)
_VULNERABILITY_TYPES = (
    'branded-vulnerability',
)

# The STIX 1 construct kind each galaxy type is exported as, named as the
# import names the construct it reads a cluster from. STIX 1 has no intrusion
# set: those galaxy types are not here, nor is any type the export does not map.
_STIX1_CONSTRUCT_KINDS = MappingProxyType({
    **dict.fromkeys(_ATTACK_PATTERN_TYPES, 'attack_pattern'),
    **dict.fromkeys(_COURSE_OF_ACTION_TYPES, 'course_of_action'),
    **dict.fromkeys(_MALWARE_TYPES, 'malware'),
    **dict.fromkeys(_THREAT_ACTOR_TYPES, 'threat_actor'),
    **dict.fromkeys(_TOOL_TYPES, 'tool'),
    **dict.fromkeys(_VULNERABILITY_TYPES, 'vulnerability')
})


def _stix1_construct_kind(galaxy_type: str) -> Optional[str]:
    """The kind of STIX 1 construct a cluster of the galaxy type is exported
    as, None for a galaxy type STIX 1 maps to no construct."""
    return _STIX1_CONSTRUCT_KINDS.get(galaxy_type)
