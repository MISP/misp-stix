# -*- coding: utf-8 -*-
#!/usr/bin/env python3

from collections import defaultdict


class STIXtoMISPParser:
    def __init__(self):
        self.__errors = defaultdict(list)
        self.__warnings = defaultdict(set)

    @property
    def errors(self) -> dict:
        return self.__errors

    @property
    def warnings(self) -> set:
        return self.__warnings

    def _undefined_object_error(self, object_id: str):
        message = f"Unable to define the object identified with the id: {object_id}"
        self.__errors[self._identifier].append(message)

    def _unknown_attribute_type_warning(self, attribute_type: str):
        message = f"MISP attribute type not mapped: {attribute_type}"
        self.__warnings[self._identifier].add(message)

    def _unknown_object_name_warning(self, name: str):
        message = f"MISP object name not mapped: {name}"
        self.__warnings[self._identifier].add(message)

    def _unknown_stix_object_type_warning(self, object_type: str):
        message = f"Unknown STIX object type: {object_type}"
        self.__warnings[self._identifier].add(message)