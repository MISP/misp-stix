# -*- coding: utf-8 -*-
#!/usr/bin/env python3

from .exportparser import ExportParser
from .framing import stix_framing
from .misp_to_stix1 import MISPtoStix1Parser


class Stix1ExportParser(ExportParser):
    def __init__(self, return_format, namespace, org):
        self.return_format = return_format
        self.baseurl = namespace
        self.orgname = org
        try:
            idgen.set_id_namespace({namespace: self.orgname})
        except ValueError:
            try:
                idgen.set_id_namespace(Namespace(namespace, self.orgname))
            except TypeError:
                idgen.set_id_namespace(Namespace(namespace, self.orgname, 'MISP'))
        self.namespace = idgen.get_id_namespace_alias()

    def generate_stix1_package(self, version):
        stix_package = STIXPackage()
        if self.json_event.get('response'):
            for event in self.json_event['response']:
                package_generator = MISPtoSTIX1Parser(self.namespace, self.orgname)
                package_generator.parse_misp_event(event['Event'], version)
                stix_package.add_related_package(package_generator.get_package())
        else:
            package_generator = MISPtoStix1Parser(self.namespace, self.orgname)
            package_generator.parse_misp_event(self.json_event['Event'], version)
            stix_package.add_related_package(package_generator.get_package())

    # def generate_stix1_json_package(self):
    #     if self.json_event.get('response'):


        # to_call, args = self._format_to_package()

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
                'include_namespaces': False,
                'include_schemalocs': False,
                'encoding': 'utf8'
            }
        return f'to_{self.return_format}', args
