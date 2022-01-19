#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .stix1_to_misp import STIX1toMISPParser


class ExternalSTIX1toMISPParser(STIX1toMISPParser):
    def __init__(self):
        super().__init__()