# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import datetime
import json
import re
from mixbox import idgen
from mixbox.namespaces import Namespace
from stix.core import STIXHeader, STIXPackage
from .stix1_mapping import NS_DICT, SCHEMALOC_DICT

json_footer = ']}\n'


def stix_framing(namespace, orgname, return_format):
    real_orgname = orgname
    orgname = re.sub('[\W]+', '', orgname.replace(" ", "_"))
    namespaces = {namespace: orgname}
    namespaces.update(NS_DICT)
    try:
        idgen.set_id_namespace(Namespace(namespace, orgname))
    except TypeError:
        idgen.set_id_namespace(Namespace(namespace, orgname, "MISP"))
    stix_package = STIXPackage()
    stix_header = STIXHeader()
    stix_header.title = f"Export from {real_orgname}'s MISP"
    stix_header.package_intents="Threat Report"
    stix_package.stix_header = stix_header
    stix_package.version = "1.1.1"
    stix_package.timestamp = datetime.datetime.now()
    if return_format == 'xml':
        return _stix_xml_framing(stix_package, namespaces, SCHEMALOC_DICT)
    return _stix_json_framing(stix_package)


def stix_xml_separator():
    header = "stix:Related_Package"
    return f"        </{header}>\n        <{header}>\n"


def stix20_framing(uuid):
    header = '{"type": "bundle", "spec_version": "2.0", "id":'
    return f'{header} "bundle--{uuid}", "objects": [', ',', json_footer


def _stix_json_framing(stix_package):
    header = stix_package.to_json()[:-1]
    header = f'{header}, "related_packages": '
    return header, ',', json_footer


def _stix_xml_framing(stix_package, namespaces, schemaloc):
    s_stix = "</stix:STIX_Package>\n"
    s_related = "stix:Related_Package"
    header = stix_package.to_xml(auto_namespace=False, ns_dict=namespaces, schemaloc_dict=schemaloc)
    header = header.decode()
    header = f"{header}    <{s_related}s>\n        <{s_related}>\n".replace(s_stix, "")
    footer = f"        </{s_related}>\n    </{s_related}s>\n{s_stix}"
    separator = f"        </{s_related}>\n        <{s_related}>\n"
    return header, separator, footer
