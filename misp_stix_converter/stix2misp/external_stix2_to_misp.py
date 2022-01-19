#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .stix2_to_misp import STIX2toMISPParser


class ExternalSTIX2toMISPParser(STIX2toMISPParser):
    def __init__(self):
        super().__init__()