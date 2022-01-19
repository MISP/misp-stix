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
        return self.__wargnings