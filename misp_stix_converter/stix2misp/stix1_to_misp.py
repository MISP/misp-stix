# -*- coding: utf-8 -*-
#!/usr/bin/env python3

from .importparser import STIXtoMISPParser


class STIX1toMISPParser(STIXtoMISPParser):
    def __init__(self):
        super.__init__()