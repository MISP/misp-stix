# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import stix2
from .importparser import STIXtoMISPParser


class STIX2toMISPParser(STIXtoMISPParser):
    def __init__(self):
        super().__init__()