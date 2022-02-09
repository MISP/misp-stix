# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import traceback
from collections import defaultdict


class STIXtoMISPParser:
    def __init__(self):
        self.__errors = defaultdict(set)
        self.__warnings = defaultdict(set)

    @property
    def errors(self) -> dict:
        return self.__errors

    @property
    def warnings(self) -> set:
        return self.__warnings

    def _object_ref_loading_error(self, object_ref: str):
        message = f"Error loading the STIX object with id {object_ref}"
        self.__errors[self._identifier].add(message)

    def _object_type_loading_error(self, object_type: str):
        message = f"Error loading the STIX object of type {object_type}"
        self.__errors[self._identifier].add(message)

    def _observed_data_error(self, observed_data_id: str, exception: Exception):
        traceback = self._parse_traceback(exception)
        message = f"Error with the observed data object with id {observed_data_id}: {traceback}"
        self.__errors[self._identifier].add(message)

    @staticmethod
    def _parse_traceback(exception: Exception) -> str:
        tb = ''.join(traceback.format_tb(exception.__traceback__))
        return f'{tb}{exception.__str__()}'

    def _undefined_object_error(self, object_id: str):
        message = f"Unable to define the object identified with the id: {object_id}"
        self.__errors[self._identifier].add(message)

    def _unknown_attribute_type_warning(self, attribute_type: str):
        message = f"MISP attribute type not mapped: {attribute_type}"
        self.__warnings[self._identifier].add(message)

    def _unknown_object_name_warning(self, name: str):
        message = f"MISP object name not mapped: {name}"
        self.__warnings[self._identifier].add(message)

    def _unknown_stix_object_type_warning(self, object_type: str):
        message = f"Unknown STIX object type: {object_type}"
        self.__warnings[self._identifier].add(message)