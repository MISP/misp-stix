# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import stix.extensions.marking.ais
from .importer import ImportParser
from stix.core import STIXPackage


class Stix1ImportParser(ImportParser):
    def __init__(self):
        super().__init__()


class Stix1FromMISPImportParser(Stix1ImportParser):
    def __init__(self):
        super().__init__()


class ExternalStix1ImportParser(Stix1ImportParser):
    def __init__(self):
        super().__init__()
