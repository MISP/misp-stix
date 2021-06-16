# -*- coding: utf-8 -*-
#!/usr/bin/env python3

from stix2.v21 import Bundle
from .exportparser import ExportParser
from .misp_to_stix21 import MISPtoSTIX21Parser


class Stix21ExportParser(ExportParser):
    def generate_stix21_bundle(self):
        if self._json_event.get('response'):
            stix_objects = []
            parser = MISPtoSTIX21Parser()
            for event in self._json_event['response']:
                parser.parse_misp_event(event)
                stix_objects.extend(parser.stix_objects)
        else:
            parser = MISPtoSTIX21Parser()
            parser.parse_misp_event(self._json_event)
            stix_objects = parser.stix_objects
        self._bundle = Bundle(stix_objects)

    @property
    def bundle(self):
        return self._bundle
