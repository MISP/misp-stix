#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .. import Mapping


class STIX1Mapping:
    def __init__(self):
        self.__threat_level_mapping = Mapping(
            High = '1',
            Medium = '2',
            Low = '3',
            Undefined = '4'
        )

    @property
    def threat_level_mapping(self) -> dict:
        return self.__threat_level_mapping