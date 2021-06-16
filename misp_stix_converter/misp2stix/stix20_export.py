# -*- coding: utf-8 -*-
#!/usr/bin/env python3

from stix2.v20 import Bundle
from .exportparser import ExportParser
from .misp_to_stix20 import MISPtoSTIX20Parser


class Stix20ExportParser(ExportParser):
    def generate_stix20_bundle(self):
        if self._json_event.get('response'):
            stix_objects = []
            parser = MISPtoSTIX20Parser()
            for event in self._json_event['response']:
                parser.parse_misp_event(event)
                stix_objects.extend(parser.stix_objects)
        else:
            parser = MISPtoSTIX20Parser()
            parser.parse_misp_event(self._json_event)
            stix_objects = parser.stix_objects
        self._bundle = Bundle(stix_objects)

    @property
    def bundle(self):
        return self._bundle
