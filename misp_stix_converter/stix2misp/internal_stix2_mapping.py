#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .. import Mapping
from .stix2_mapping import STIX2Mapping


class InternalSTIX2Mapping(STIX2Mapping):
    def __init__(self):
        super().__init__()
        self._declare_mapping()
        self.__observable_attributes_mapping = {}
        self.__observable_objects_mapping = {}

    @property
    def observable_attributes_mapping(self) -> dict:
        return self.__observable_attributes_mapping

    @property
    def observable_objects_mapping(self) -> dict:
        return self.__observable_objects_mapping