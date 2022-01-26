# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import stix2
from .importparser import STIXtoMISPParser
from pymisp import MISPEvent, MISPObject, MISPAttribute
from stix2.v20.bundle import Bundle as Bundle_v20
from stix2.v21.bundle import Bundle as Bundle_v21
from typing import Union


class STIX2toMISPParser(STIXtoMISPParser):
    def __init__(self):
        super().__init__()

    def parse_stix_content(self, filename: str):
        with open(filename, 'rt', encoding='utf-8') as f:
            self.__bundle = stix2.parse(f.read(), allow_custom=True, interoperability=True)
        self.__stix_version = self.bundle.spec_version if hasattr(self.bundle, 'spec_version') else '2.1'
        self.__misp_event = MISPEvent()

    @property
    def bundle(self) -> Union[Bundle_v20, Bundle_v21]:
        return self.__bundle

    @property
    def misp_event(self) -> MISPEvent:
        return self.__misp_event

    @property
    def stix_version(self) -> str:
        return self.__stix_version