# -*- coding: utf-8 -*-
#!/usr/bin/env python3

from mixbox import idgen
from mixbox.namespaces import Namespace
from stix.core import STIXPackage
from .exportparser import ExportParser
from .framing import stix_framing
from .misp_to_stix1 import MISPtoSTIX1Parser


class Stix1ExportParser(ExportParser):
    def __init__(self, return_format, namespace, org, include_namespaces):
        self._return_format = return_format
        self._orgname = org
        self._include_namespaces = include_namespaces
        try:
            idgen.set_id_namespace({namespace: self._orgname})
        except ValueError:
            try:
                idgen.set_id_namespace(Namespace(namespace, self._orgname))
            except TypeError:
                idgen.set_id_namespace(Namespace(namespace, self._orgname, 'MISP'))
        self._namespace = idgen.get_id_namespace_alias()

    def generate_stix1_package(self, version):
        if self.json_event.get('response'):
            self._stix_package = STIXPackage()
            self._stix_package.version = version
            for event in self.json_event['response']:
                package_generator = MISPtoSTIX1Parser(self._orgname)
                package_generator.parse_misp_event(event, version)
                self._stix_package.add_related_package(package_generator.stix_package)
        else:
            package_generator = MISPtoSTIX1Parser(self._namespace, self._orgname)
            package_generator.parse_misp_event(self.json_event, version)
            self._stix_package = package_generator.stix_package

    @property
    def stix_package(self):
        return self._stix_package

    @property
    def decoded_package(self):
        if self._return_format == 'xml':
            return self._stix_package.to_xml(**self.xml_args)
        return self._stix_package.to_dict()

    @property
    def xml_args(self):
        return {
            'include_namespaces': self._include_namespaces,
            'include_schemalocs': self._include_namespaces,
            'encoding': 'utf8'
        }
