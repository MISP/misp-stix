#!/usr/bin/env python3

from .exceptions import STIXLoadingError, _reduce_input_path
from .input_limits import _check_input_file_size
from lxml import etree
from mixbox.namespaces import NamespaceNotFoundError
from pathlib import Path
from stix.core import STIXPackage
from stix.xmlconst import TAG_STIX_PACKAGE
from typing import Optional

# How much of a document is read at a time while looking for its root element.
# One chunk holds the whole start tag of any ordinary document; the loop below
# exists for the ones carrying an unusual number of attributes on it.
_ROOT_ELEMENT_CHUNK_SIZE = 8192


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


def _check_stix1_root_element(filename):
    """`mixbox` builds the whole document tree before it looks at the root
    element, so XML that is not a STIX package at all is materialised - at 2 to
    7 times its size in memory - only to be refused. Read the root element on
    its own instead, and refuse the document on what `mixbox` would refuse it
    on: an exact tag match against the one tag it supports.

    The settings keep the properties `mixbox.xml.get_xml_parser()` relies on
    for the real parse: no entity is resolved, no DTD is loaded and nothing is
    fetched from the network. `huge_tree` stays off, unlike there, since a peek
    has no reason to accept an oversized start tag - a document lxml refuses to
    read here simply falls through to the parser, which reports what is wrong
    with it. Only a root element positively identified as something else is
    refused."""
    parser = etree.XMLPullParser(
        events=('start',), resolve_entities=False, no_network=True,
        load_dtd=False, huge_tree=False
    )
    try:
        with open(filename, 'rb') as f:
            while chunk := f.read(_ROOT_ELEMENT_CHUNK_SIZE):
                parser.feed(chunk)
                for _, element in parser.read_events():
                    if element.tag == TAG_STIX_PACKAGE:
                        return
                    raise STIXLoadingError(
                        f'Document root element ({element.tag}) is not the '
                        f'STIX 1 package root element ({TAG_STIX_PACKAGE})'
                    )
    except (OSError, TypeError, ValueError, etree.LxmlError):
        return


def load_stix1_package(filename, tries=0, max_size: Optional[int] = None):
    # lxml treats a plain string argument as a filename *or* a URL - resolving
    # it here keeps `file://` targets out of the parser for every caller
    if isinstance(filename, str):
        filename = Path(filename).resolve()
    if tries == 0:
        # both checks are the document's own, so the namespace retry below does
        # not run them again
        _check_input_file_size(filename, max_size)
        _check_stix1_root_element(filename)
    try:
        return STIXPackage.from_xml(filename)
    except NamespaceNotFoundError as error:
        if tries > 0:
            raise STIXLoadingError('Cannot handle STIX namespace') from error
        _update_namespaces()
        return load_stix1_package(filename, tries + 1, max_size=max_size)
    except NotImplementedError as error:
        raise STIXLoadingError('Missing python library: stix_edh') from error
    except ImportError as error:
        # `stix` imports optional parsing dependencies (e.g. `maec`) lazily
        # during the parse itself, so a missing one surfaces here
        raise STIXLoadingError(
            f'Missing python library: {error.name or error}'
        ) from error
    except MemoryError:
        # memory exhaustion must surface as what it is, not as a document
        # loading error
        raise
    except OSError as error:
        raise STIXLoadingError(
            'Error while reading the STIX1 document: '
            f'{_reduce_input_path(str(error), filename)}'
        ) from error
    except Exception as error:
        raise STIXLoadingError(
            'Error while loading STIX1 package: '
            f'{_reduce_input_path(str(error), filename)}'
        ) from error
