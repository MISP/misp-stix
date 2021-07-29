# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import json
import re
from .misp2stix.framing import stix1_framing, stix20_framing, stix21_framing
from .misp2stix.misp_to_stix1 import MISPtoSTIX1AttributesParser, MISPtoSTIX1EventsParser
from .misp2stix.misp_to_stix20 import MISPtoSTIX20Parser
from .misp2stix.misp_to_stix21 import MISPtoSTIX21Parser
from .misp2stix.stix1_mapping import NS_DICT, SCHEMALOC_DICT
from mixbox import idgen
from mixbox.namespaces import Namespace, register_namespace
from pathlib import Path
from stix.core import STIXHeader, STIXPackage
from stix2.base import STIXJSONEncoder
from stix2.v20 import Bundle as Bundle_v20
from stix2.v21 import Bundle as Bundle_v21
from typing import List, TypedDict, Union
from uuid import uuid4

_default_namespace = 'https://github.com/MISP/MISP'
_default_org = 'MISP'
_files_type = Union[Path, str]


################################################################################
#                         MISP to STIX MAIN FUNCTIONS.                         #
################################################################################

def misp_event_collection_to_stix1(*args: List[_files_type], in_memory: bool=False, namespace: str=_default_namespace, org: str=_default_org):
    output_filename, return_format, version, *input_files = args
    if org != _default_org:
        org = re.sub('[\W]+', '', org.replace(" ", "_"))
    parser = MISPtoSTIX1EventsParser(org, version)
    if in_memory or len(input_files) == 1:
        package = _create_stix_package(org, version)
        for filename in input_files:
            parser.parse_json_content(filename)
            if parser.stix_package.related_packages is not None:
                for related_package in parser.stix_package.related_packages:
                    package.add_related_package(related_package)
            else:
                package.add_related_package(parser.stix_package)
        return _write_raw_stix(package, output_filename, namespace, org, return_format)
    header, separator, footer = stix1_framing(namespace, org, return_format, version)
    parser.parse_json_content(input_files[0])
    content = globals()[f'_get_{return_format}_events'](parser.stix_package)
    with open(output_filename, 'wt', encoding='utf-8') as f:
        f.write(f'{header}{content}')
    for filename in input_files[1:]:
        parser.parse_json_content(filename)
        content = globals()[f'_get_{return_format}_events'](parser.stix_package)
        with open(output_filename, 'at', encoding='utf-8') as f:
            f.write(f'{separator}{content}')
    with open(output_filename, 'at', encoding='utf-8') as f:
        f.write(footer)
    return 1


def misp_collection_to_stix2_0(output_filename: _files_type, *input_files: List[_files_type], in_memory: bool=False):
    parser = MISPtoSTIX20Parser()
    if in_memory or len(input_files) == 1:
        objects = []
        for filename in input_files:
            parser.parse_json_content(filename)
            objects.extend(parser.stix_objects)
        with open(output_filename, 'wt', encoding='utf-8') as f:
            f.write(json.dumps(Bundle_v20(objects), cls=STIXJSONEncoder, indent=4))
        return 1
    with open(output_filename, 'wt', encoding='utf-8') as f:
        f.write(f'{json.dumps(Bundle_v20(), cls=STIXJSONEncoder, indent=4)[:-2]},\n    "objects": [\n')
    for filename in input_files[:-1]:
        parser.parse_json_content(filename)
        with open(output_filename, 'at', encoding='utf-8') as f:
            f.write(f'{json.dumps([parser.stix_objects], cls=STIXJSONEncoder, indent=4)[8:-8]},\n')
    parser.parse_json_content(input_files[-1])
    with open(output_filename, 'at', encoding='utf-8') as f:
        footer = '    ]\n}'
        f.write(f'{json.dumps([parser.stix_objects], cls=STIXJSONEncoder, indent=4)[8:-8]}\n{footer}')
    return 1


def misp_collection_to_stix2_1(output_filename: _files_type, *input_files: List[_files_type], in_memory: bool=False):
    parser = MISPtoSTIX21Parser()
    if in_memory or len(input_files) == 1:
        objects = []
        for filename in input_files:
            parser.parse_json_content(filename)
            objects.extend(parser.stix_objects)
        with open(output_filename, 'wt', encoding='utf-8') as f:
            f.write(json.dumps(Bundle_v21(objects), cls=STIXJSONEncoder, indent=4))
        return 1
    with open(output_filename, 'wt', encoding='utf-8') as f:
        f.write(f'{json.dumps(Bundle_v21(), cls=STIXJSONEncoder, indent=4)[:-2]},\n    "objects": [\n')
    for filename in input_files[:-1]:
        parser.parse_json_content(filename)
        with open(output_filename, 'at', encoding='utf-8') as f:
            f.write(f'{json.dumps([parser.stix_objects], cls=STIXJSONEncoder, indent=4)[8:-8]},\n')
    parser.parse_json_content(input_files[-1])
    with open(output_filename, 'at', encoding='utf-8') as f:
        footer = '    ]\n}'
        f.write(f'{json.dumps([parser.stix_objects], cls=STIXJSONEncoder, indent=4)[8:-8]}\n{footer}')
    return 1


def misp_to_stix1(*args: List[_files_type], namespace=_default_namespace, org=_default_org):
    filename, return_format, version = args
    if org != _default_org:
        org = re.sub('[\W]+', '', org.replace(" ", "_"))
    package = _create_stix_package(org, version)
    parser = MISPtoSTIX1EventsParser(org, version)
    parser.parse_json_content(filename)
    if parser.stix_package.related_packages is not None:
        for related_package in parser.stix_package.related_packages:
            package.add_related_package(related_package)
    else:
        package.add_related_package(parser.stix_package)
    return _write_raw_stix(package, f'{filename}.out', namespace, org, return_format)


def misp_to_stix2_0(filename: _files_type):
    parser = MISPtoSTIX20Parser()
    parser.parse_json_content(filename)
    with open(f'{filename}.out', 'wt', encoding='utf-8') as f:
        f.write(json.dumps(parser.bundle, cls=STIXJSONEncoder, indent=4))
    return 1


def misp_to_stix2_1(filename: _files_type):
    parser = MISPtoSTIX21Parser()
    parser.parse_json_content(filename)
    with open(f'{filename}.out', 'wt', encoding='utf-8') as f:
        f.write(json.dumps(parser.bundle, cls=STIXJSONEncoder, indent=4))
    return 1


################################################################################
#                         STIX to MISP MAIN FUNCTIONS.                         #
################################################################################

def stix_to_misp(filename):
    event = _load_stix_event(filename)
    if isinstance(event, str):
        return event
    title = event.stix_header.title
    from_misp = (title is not None and all(feature in title for feature in ('Export from ', 'MISP')))
    stix_parser = Stix1FromMISPImportParser() if from_misp else ExternalStix1ImportParser()
    stix_parser.load_event()
    stix_parser.build_misp_event(event)
    stix_parser.save_file()
    return


def stix2_to_misp(filename):
    with open(filename, 'rt', encoding='utf-8') as f:
        event = stix2.parse(f.read(), allow_custom=True, interoperability=True)
    stix_parser = Stix2FromMISPImportParser() if _from_misp(event.objects) else ExternalStix2ImportParser()
    stix_parser.handler(event, filename)
    stix_parser.save_file()
    return


################################################################################
#                        STIX PACKAGE CREATION HELPERS.                        #
################################################################################

def _create_stix_package(orgname: str, version: str) -> STIXPackage:
    package = STIXPackage()
    package.version = version
    header = STIXHeader()
    header.title = f"Export from {orgname}'s MISP"
    header.package_intents="Threat Report"
    package.stix_header = header
    package.id_ = f"{orgname}:Package-{uuid4()}"
    return package


################################################################################
#                        STIX CONTENT LOADING FUNCTIONS                        #
################################################################################

def _from_misp(stix_objects):
    for stix_object in stix_objects:
        if stix_object['type'] == 'report' and 'misp:tool="misp2stix2"' in stix_object.get('labels', []):
            return True
    return False


def _load_stix_event(filename, tries=0):
    try:
        return STIXPackage.from_xml(filename)
    except NamespaceNotFoundError:
        if tries == 1:
            return 4
        _update_namespaces()
        return _load_stix_event(filename, 1)
    except NotImplementedError:
        print('ERROR - Missing python library: stix_edh', file=sys.stderr)
        return 5
    except Exception:
        try:
            import maec
            return 2
        except ImportError:
            print('ERROR - Missing python library: maec', file=sys.stderr)
            return 3
    return 0


def _update_namespaces():
    # LIST OF ADDITIONAL NAMESPACES
    # can add additional ones whenever it is needed
    ADDITIONAL_NAMESPACES = [
        Namespace('http://us-cert.gov/ciscp', 'CISCP',
                  'http://www.us-cert.gov/sites/default/files/STIX_Namespace/ciscp_vocab_v1.1.1.xsd'),
        Namespace('http://taxii.mitre.org/messages/taxii_xml_binding-1.1', 'TAXII',
                  'http://docs.oasis-open.org/cti/taxii/v1.1.1/cs01/schemas/TAXII-XMLMessageBinding-Schema.xsd')
    ]
    for namespace in ADDITIONAL_NAMESPACES:
        register_namespace(namespace)


################################################################################
#                        STIX CONTENT WRITING FUNCTIONS                        #
################################################################################

def _get_json_events(package: STIXPackage) -> str:
    if package.related_packages is not None:
        return ', '.join(related_package.to_json() for related_package in package.related_packages)
    return json.dumps({'package': package.to_dict()})


def _get_xml_events(package: STIXPackage) -> str:
    if package.related_packages is not None:
        length = 96 + len(package.id_) + len(package.version)
        return package.to_xml(include_namespaces=False).decode()[length:-82]
    content = '\n            '.join(package.to_xml(include_namesapces=False).decode().split('\n'))
    return f'            {content}\n'


def _write_header(package: STIXPackage, filename: str, namespace: str, org: str, return_format: str) -> str:
    namespaces = namespaces = {namespace: org}
    namespaces.update(NS_DICT)
    try:
        idgen.set_id_namespace(Namespace(namespace, org))
    except TypeError:
        idgen.set_id_namespace(Namespace(namespace, org, "MISP"))
    if return_format == 'xml':
        xml_package = package.to_xml(auto_namespace=False, ns_dict=namespaces, schemaloc_dict=SCHEMALOC_DICT).decode()
        with open(filename, 'wt', encoding='utf-8') as f:
            f.write(xml_package[:-21])
        return _xml_package[-21:]
    json_package = paclage.to_json()
    with open(filename, 'wt', encoding='utf-8') as f:
        f.wrtie(f'{json_package[:-1]}, "related_packages": {json.dumps({"related_packages": []})[:-2]}')
    return ']}}'


def _write_raw_stix(package: STIXPackage, filename: str, namespace: str, org: str, return_format: str) -> bool:
    if return_format == 'xml':
        namespaces = namespaces = {namespace: org}
        namespaces.update(NS_DICT)
        try:
            idgen.set_id_namespace(Namespace(namespace, org))
        except TypeError:
            idgen.set_id_namespace(Namespace(namespace, org, "MISP"))
        with open(filename, 'wb') as f:
            f.write(package.to_xml(auto_namespace=False, ns_dict=namespaces, schemaloc_dict=SCHEMALOC_DICT))
    else:
        with open(filename, 'wt', encoding='utf-8') as f:
            f.write(json.dumps(package.to_dict(), indent=4))
    return 1
