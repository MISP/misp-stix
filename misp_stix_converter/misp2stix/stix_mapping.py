#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ..tools.galaxy_types import (
    _ATTACK_PATTERN_TYPES, _COURSE_OF_ACTION_TYPES, _INTRUSION_SET_TYPES,
    _MALWARE_TYPES, _THREAT_ACTOR_TYPES, _TOOL_TYPES, _VULNERABILITY_TYPES)


class MISPtoSTIXMapping:
    __attack_pattern_types = _ATTACK_PATTERN_TYPES
    __course_of_action_types = _COURSE_OF_ACTION_TYPES
    __intrusion_set_types = _INTRUSION_SET_TYPES
    __malware_types = _MALWARE_TYPES
    __threat_actor_types = _THREAT_ACTOR_TYPES
    __tool_types = _TOOL_TYPES
    __vulnerability_types = _VULNERABILITY_TYPES

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