#!/usr/bin/env python3

import sys
from mixbox.namespaces import NamespaceNotFoundError
from stix.core import STIXPackage


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


def load_stix1_package(filename, tries=0):
    try:
        return STIXPackage.from_xml(filename)
    except NamespaceNotFoundError:
        if tries > 0:
            sys.exit('Cannot handle STIX namespace')
        _update_namespaces()
        return load_stix1_package(filename, tries + 1)
    except NotImplementedError:
        sys.exit('Missing python library: stix_edh')
    except Exception:
        try:
            import maec
            return STIXPackage.from_xml(filename)
        except ImportError:
            sys.exit('Missing python library: maec')
        except Exception as error:
            sys.exit(f'Error while loading STIX1 package: {error.__str__()}')
