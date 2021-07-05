# -*- coding: utf-8 -*-
#!/usr/bin/env python3

from .exportparser import ExportParser
from .misp_to_stix20 import MISPtoSTIX20Parser
from .misp_to_stix21 import MISPtoSTIX21Parser
from stix2.v20 import Bundle as Bundle_v20
from stix2.v21 import Bundle as Bundle_v21


class Stix2ExportParser(ExportParser):
    def _parse_json_content(self):
        if self._json_content.get('response'):
            if isinstance(self._json_content['response'], list):
                stix_objects = []
                for event in self._json_content['response']:
                    self._parser.parse_misp_event(event)
                    stix_objects.extend(self._parser.stix_objects)
                return stix_objects
            self._parser.parse_attributes(self._json_content['response'])
        else:
            self._parser.parse_misp_event(self._json_content)
        return self._parser.stix_objects

    @property
    def bundle(self):
        return self._bundle


class Stix20ExportParser(Stix2ExportParser):
    def __init__(self):
        self._parser = MISPtoSTIX20Parser()

    def generate_stix20_bundle(self):
        stix_objects = self._parse_json_content()
        self._bundle = Bundle_v20(stix_objects)


class Stix21ExportParser(Stix2ExportParser):
    def __init__(self):
        self._parser = MISPtoSTIX21Parser()

    def generate_stix21_bundle(self):
        stix_objects = self._parse_json_content()
        self._bundle = Bundle_v21(stix_objects)
