#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from collections.abc import Mapping


class InvalidStixObject(Mapping):
    def __getitem__(self, key: str):
        if hasattr(self, key):
            return getattr(self, key)
        raise KeyError(key)

    def __iter__(self):
        return iter(self.__dict__)

    def __len__(self):
        return len(self.__dict__)


class InvalidMarkingDefinition(InvalidStixObject):
    def __init__(self, marking_definition: dict):
        self.__id = marking_definition['id']
        self.__type = marking_definition['type']
        self.__definition_type = marking_definition.get('definition_type')
        self.__name = marking_definition.get('name')
        self.__definition = marking_definition.get('definition')

    @property
    def id(self) -> str:
        return self.__id
    
    @property
    def type(self) -> str:
        return self.__type
    
    @property
    def definition_type(self) -> str:
        return self.__definition_type
    
    @property
    def name(self) -> str:
        return self.__name
    
    @property
    def definition(self) -> str:
        return self.__definition