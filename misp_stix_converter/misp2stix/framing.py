# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import datetime
import json
import re
from mixbox import idgen
from mixbox.namespaces import Namespace
from stix.core import STIXHeader, STIXPackage
from typing import Optional, Union
from uuid import uuid4, UUID
from .stix1_mapping import NS_DICT, SCHEMALOC_DICT

json_footer = ']}\n'
_UUID_typing = Union[UUID, str]


def stix1_attributes_framing(namespace: str, orgname: str, return_format: str,
                             version: str) -> tuple:
    stix_package = _create_stix_package(orgname, version)
    return _stix1_attributes_framing(
        namespace, orgname, return_format, stix_package
    )


def _stix1_attributes_framing(namespace: str, orgname: str, return_format: str,
                              stix_package: STIXPackage) -> tuple:
    if return_format == 'xml':
        namespaces = _handle_namespaces(namespace, orgname)
        return _stix_xml_attributes_framing(stix_package, namespaces)
    return _stix_json_attributes_framing(stix_package)


def stix1_framing(namespace: str, orgname: str, return_format: str,
                  version: str) -> tuple:
    stix_package = _create_stix_package(orgname, version)
    return _stix1_framing(namespace, orgname, return_format, stix_package)


def _stix1_framing(namespace: str, orgname: str, return_format: str,
                   stix_package: STIXPackage) -> tuple:
    if return_format == 'xml':
        namespaces = _handle_namespaces(namespace, orgname)
        return _stix_xml_framing(stix_package, namespaces)
    return _stix_json_framing(stix_package)


def stix_xml_separator():
    header = "stix:Related_Package"
    return f"        </{header}>\n        <{header}>\n"


def stix20_framing(uuid: Optional[_UUID_typing] = None) -> tuple:
    header = '{"type": "bundle", "spec_version": "2.0", "id":'
    if uuid is None:
        uuid = uuid4()
    return f'{header} "bundle--{uuid}", "objects": [', ', ', json_footer


def stix21_framing(uuid: Optional[_UUID_typing] = None) -> tuple:
    header = '{"type": "bundle", "id":'
    if uuid is None:
        uuid = uuid4()
    return f'{header} "bundle--{uuid}", "objects": [', ', ', json_footer


def _handle_namespaces(namespace: str, orgname: str) -> tuple:
    parsed_orgname = re.sub('[\W]+', '', orgname.replace(' ', '_'))
    namespaces = {namespace: parsed_orgname}
    namespaces.update(NS_DICT)
    try:
        idgen.set_id_namespace(Namespace(namespace, parsed_orgname))
    except TypeError:
        idgen.set_id_namespace(Namespace(namespace, parsed_orgname, 'MISP'))
    return namespaces


def _stix_json_attributes_framing(stix_package: STIXPackage) -> tuple:
    header = {key: value for key, value in stix_package.to_dict().items() if key != 'observables'}
    return f'{json.dumps(header)[:-1]}, ', ', ', '}'


def _stix_json_framing(stix_package: STIXPackage) -> tuple:
    header = stix_package.to_json()[:-1]
    bracket = '{'
    header = f'{header}, "related_packages": {bracket}"related_packages": ['
    return header, ', ', ']}}'


def _create_stix_package(
        orgname: str, version: str,  header: Optional[bool] = True,
        uuid: Optional[_UUID_typing] = None) -> STIXPackage:
    parsed_orgname = re.sub('[\W]+', '', orgname.replace(' ', '_'))
    if uuid is None:
        uuid = uuid4()
    stix_package = STIXPackage(
        id_=f'{parsed_orgname}:STIXPackage-{uuid}',
        timestamp=datetime.datetime.now()
    )
    stix_package.version = version
    if header:
        stix_header = STIXHeader()
        stix_header.title = f"Export from {orgname}'s MISP"
        stix_header.package_intents = 'Threat Report'
        stix_package.stix_header = stix_header
    return stix_package


def _stix_xml_attributes_framing(stix_package: STIXPackage, namespaces: dict) -> tuple:
    s_stix = "</stix:STIX_Package>\n"
    header = stix_package.to_xml(auto_namespace=False, ns_dict=namespaces, schemaloc_dict=SCHEMALOC_DICT)
    return f"{header.decode().replace(s_stix, '')}", '', s_stix


def _stix_xml_framing(stix_package: STIXPackage, namespaces: dict) -> tuple:
    s_stix = "</stix:STIX_Package>\n"
    s_related = "stix:Related_Package"
    header = stix_package.to_xml(auto_namespace=False, ns_dict=namespaces, schemaloc_dict=SCHEMALOC_DICT)
    header = header.decode()
    if header.endswith('/>\n'):
        header = f'{header[:-3]}>\n'
    header = f"{header.replace(s_stix, '')}    <{s_related}s>\n        <{s_related}>\n"
    footer = f"        </{s_related}>\n    </{s_related}s>\n{s_stix}"
    separator = f"        </{s_related}>\n        <{s_related}>\n"
    return header, separator, footer
