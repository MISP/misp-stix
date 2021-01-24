# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import json
from .misp2stix.stix1_export import Stix1ExportParser

_default_namespace = 'https://github.com/MISP/MISP'
_default_org = 'MISP'


def misp_to_stix(filename, return_format, version, include_namespaces = False, namespace=_default_namespace, org=_default_org):
    if org != _default_org:
        org = re.sub('[\W]+', '', org.replace(" ", "_"))
    export_parser = Stix1ExportParser(return_format, namespace, org, include_namespaces)
    export_parser.load_file(filename)
    export_parser.generate_stix1_package(version)
    if include_namespaces:
        args = (export_parser.decoded_package, filename, return_format)
        return _write_raw_stix(*args)
    if return_format == 'xml':
        return _stix_to_xml(export_parser.stix_package, export_parser.xml_args, filename)
    return _stix_to_json(export_parser.decoded_package, filename)


def misp_to_stix2():
    return


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


def _stix_to_json(stix_package, filename):
    stix_package = stix_package['related_packages']['related_packages'] if stix_package.get('related_packages') else [{'package': package}]
    with open(f'{filename}.out', 'wt', encoding='utf-8') as f:
        f.write(json.dumps(stix_package))
    return 1


def _stix_to_xml(stix_package, xml_args, filename):
    if stix_package.related_packages is not None:
        with open(f'{filename}.out', 'wt', encoding='utf-8') as f:
            f.write(_write_indented_package(_write_decoded_packages(
                stix_package.related_packages.related_package,
                xml_args
            )))
        return 1
    with open(f'{filename}.out', 'wt', encoding='utf-8') as f:
        f.write(_write_single_package(stix_package, xml_args))
    return 1


def _update_namespaces():
    from mixbox.namespaces import Namespace, register_namespace
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


def _write_decoded_packages(packages, args):
    return (f'            {package.to_xml(**args).decode()}' for package in packages)


def _write_indented_package(packages):
    separator = '\n            '
    package = '\n'.join(f'{separator}'.join(package.split('\n')[:-1]) for package in packages)
    return f'{package}\n'


def _write_single_package(package, args):
    package = package.to_xml(**args).decode().replace('stix:STIX_Package', 'stix:Package')
    package = '\n            '.join(package.split('\n')[:-1])
    return f'            {package}\n'


def _write_raw_stix(decoded, filename, return_format):
    if return_format == 'xml':
        with open(f'{filename}.out', 'wb') as f:
            f.write(decoded)
    else:
        with open(f'{filename}.out', 'wt', encoding='utf-8') as f:
            f.write(json.dumps(decoded))
    return 1
