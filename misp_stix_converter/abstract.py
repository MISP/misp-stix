#!/usr/bin/env python3

from abc import ABCMeta
from collections import defaultdict
from typing import Optional
from uuid import UUID, uuid5

_UUIDv4 = UUID('76beed5f-7251-457e-8c2a-b45f7b589d3d')


class AbstractParser(metaclass=ABCMeta):

    def __init__(self):
        self.__errors: defaultdict = defaultdict(list)
        self.__warnings: defaultdict = defaultdict(set)
        self.__identifier: str

    @property
    def errors(self) -> dict:
        return self.__errors

    @property
    def identifier(self) -> str:
        return self.__identifier

    @property
    def warnings(self) -> dict:
        return {
            identifier: list(warnings)
            for identifier, warnings in self.__warnings.items()
        }

    @staticmethod
    def _create_v5_uuid(value: str) -> UUID:
        return uuid5(_UUIDv4, value)

    def _set_identifier(self, identifier: str):
        self.__identifier = identifier

    def _add_error(self, error: str, identifier: Optional[str] = None):
        self.__errors[identifier or self.identifier].append(error)

    def _add_warning(self, warning: str, identifier: Optional[str] = None):
        self.__warnings[identifier or self.identifier].add(warning)
