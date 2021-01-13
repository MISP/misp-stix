# -*- coding: utf-8 -*-
#!/usr/bin/env python3

from .exportparser import ExportParser
from .framing import stix_framing
from .misp_to_stix1 import MISPtoSTIX1Parser


class Stix1ExportParser(ExportParser):
    def __init__(self, return_format, namespace, org, include_namespaces=True):
        self.return_format = return_format
        self.baseurl = namespace
        self.orgname = org
        self.include_namespaces = include_namespaces
        try:
            idgen.set_id_namespace({namespace: self.orgname})
        except ValueError:
            try:
                idgen.set_id_namespace(Namespace(namespace, self.orgname))
            except TypeError:
                idgen.set_id_namespace(Namespace(namespace, self.orgname, 'MISP'))
        self.namespace = idgen.get_id_namespace_alias()

    def generate_stix1_package(self, version):
        if self.json_event.get('response'):
            for event in self.json_event['response']:
                self._stix_package = STIXPackage()
                package_generator = MISPtoSTIX1Parser(self.namespace, self.orgname)
                package_generator.parse_misp_event(self.load(event), version)
                self._stix_package.add_related_package(package_generator.stix_package)
        else:
            package_generator = MISPtoSTIX1Parser(self.namespace, self.orgname)
            package_generator.parse_misp_event(self.json_event, version)
            self._stix_package = package_generator.stix_package

    @property
    def stix_package(self):
        return self._stix_package

    ################################################################################
    ##                             UTILITY FUNCTIONS.                             ##
    ################################################################################

    @staticmethod
    def _extract_event(event):
        if event.get('Event'):
            return event['Event']
        return event

    def _format_to_package(self, args={}):
        if self.return_format == 'xml':
            args = {
                'include_namespaces': self.include_namespaces,
                'include_schemalocs': self.include_namespaces,
                'encoding': 'utf8'
            }
        return f'to_{self.return_format}', args
