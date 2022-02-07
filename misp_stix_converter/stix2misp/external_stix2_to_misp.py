#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .external_stix2_mapping import ExternalSTIX2Mapping
from .stix2_to_misp import STIX2toMISPParser


class ExternalSTIX2toMISPParser(STIX2toMISPParser):
    def __init__(self, single_event: bool):
        super().__init__(single_event)
        self._mapping = ExternalSTIX2Mapping()
