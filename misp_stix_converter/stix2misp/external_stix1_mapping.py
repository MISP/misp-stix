#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .. import Mapping
from .stix1_mapping import STIX1Mapping


class ExternalSTIX1Mapping(STIX1Mapping):
    def __init__(self):
        super().__init__()