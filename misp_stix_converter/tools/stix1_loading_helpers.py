#!/usr/bin/env python3

from .exceptions import STIXLoadingError, _reduce_input_path
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
    except NamespaceNotFoundError as error:
        if tries > 0:
            raise STIXLoadingError('Cannot handle STIX namespace') from error
        _update_namespaces()
        return load_stix1_package(filename, tries + 1)
    except NotImplementedError as error:
        raise STIXLoadingError('Missing python library: stix_edh') from error
    except Exception:
        try:
            import maec
            return STIXPackage.from_xml(filename)
        except ImportError as error:
            raise STIXLoadingError('Missing python library: maec') from error
        except Exception as error:
            raise STIXLoadingError(
                'Error while loading STIX1 package: '
                f'{_reduce_input_path(error.__str__(), filename)}'
            ) from error
