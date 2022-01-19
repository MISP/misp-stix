#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .. import Mapping


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

    @property
    def pattern_forbidden_relations(self) -> tuple:
        self.__pattern_forbidden_relations