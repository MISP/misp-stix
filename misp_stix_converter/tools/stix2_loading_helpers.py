#!/usr/bin/env python3

import json
from .exceptions import STIXLoadingError
from .input_limits import (
    _check_input_file_size, _check_input_size, _utf8_size)
from io import BytesIO
from stix2.exceptions import InvalidValueError, ParseError
from stix2.parsing import dict_to_stix2, parse as stix2_parser
from stix2.v20.bundle import Bundle as Bundle_v20
from stix2.v21.bundle import Bundle as Bundle_v21
from typing import Optional, Union

_BUNDLE_TYPING = Union[Bundle_v20, Bundle_v21]


def _get_stix_content_version(stix_content: dict) -> str:
    for stix_object in stix_content['objects']:
        if stix_object.get('spec_version'):
            return '2.1'
    return '2.0'


def _handle_invalid_stix_content(
        invalid_objects, duplicate_invalid_ids, document_invalid_ids,
        *stix_objects):
    # `document_invalid_ids` holds the ids set aside from this content alone,
    # so a dict the caller passed in already populated by an earlier load never
    # reads as a duplicate - and the parser can tell this document's losses
    # apart from the earlier ones when it reports what nothing referenced
    for index, stix_object in enumerate(stix_objects):
        try:
            valid_object = stix2_parser(
                stix_object, allow_custom=True, interoperability=True
            )
        except Exception:
            object_id = (
                stix_object.get('id') if isinstance(stix_object, dict)
                else None
            )
            if object_id is None:
                raise STIXLoadingError(
                    f"STIX object without an 'id' property at index {index}"
                )
            # `invalid_objects` keeps its `id -> object` shape: the object
            # dropped here is never recovered, but the id it shared travels
            # to the parser, which is where the loss can be reported
            if object_id in document_invalid_ids:
                duplicate_invalid_ids.add(object_id)
            document_invalid_ids.add(object_id)
            invalid_objects[object_id] = stix_object
            continue
        yield valid_object


def _handle_stix2_loading_error(
        stix_content: dict, invalid_objects: dict,
        duplicate_invalid_ids: set,
        document_invalid_ids: set) -> _BUNDLE_TYPING:
    if 'objects' not in stix_content:
        raise STIXLoadingError(
            "The STIX 2 content has no 'objects' property"
        )
    version = _get_stix_content_version(stix_content)
    try:
        # the `spec_version` repair works on a copy so the caller's dict
        # is never mutated
        if version == '2.1' and stix_content.get('spec_version') == '2.0':
            stix_content = dict(stix_content)
            del stix_content['spec_version']
            return dict_to_stix2(
                stix_content, allow_custom=True, interoperability=True
            )
        elif version == '2.0' and stix_content.get('spec_version') == '2.1':
            stix_content = dict(stix_content)
            stix_content['spec_version'] = '2.0'
            return dict_to_stix2(
                stix_content, allow_custom=True, interoperability=True
            )
    except Exception:
        pass
    bundle_id = stix_content.get('id')
    bundle = Bundle_v21 if version == '2.1' else Bundle_v20
    return bundle(
        *_handle_invalid_stix_content(
            invalid_objects, duplicate_invalid_ids, document_invalid_ids,
            *stix_content['objects']
        ),
        id=bundle_id, allow_custom=True, interoperability=True
    )


def load_stix2_content(stix_content: BytesIO | dict | list | str,
                       invalid_objects: Optional[dict] = None,
                       max_size: Optional[int] = None) -> _BUNDLE_TYPING:
    if invalid_objects is None:
        invalid_objects = {}
    duplicate_invalid_ids: set = set()
    document_invalid_ids: set = set()
    if not isinstance(stix_content, (dict, list)):
        if isinstance(stix_content, BytesIO):
            # the buffer is sized before it is decoded: decoding an oversized
            # document is already a copy of it
            _check_input_size(stix_content.getbuffer().nbytes, max_size)
            stix_content = stix_content.getvalue().decode('utf-8')
        else:
            _check_input_size(_utf8_size(stix_content), max_size)
        # `stix2`'s own parser deserialises the JSON and builds the objects in
        # one call, so the recovery path below had to deserialise the document
        # a second time: read it once here instead
        stix_content = json.loads(stix_content)
    try:
        bundle = dict_to_stix2(
            stix_content, allow_custom=True, interoperability=True
        )
    except (InvalidValueError, KeyError, ParseError, ValueError):
        # the 2.1 code path in `stix2` reports an object without a `type`
        # property as a bare KeyError where the 2.0 one uses ParseError
        bundle = _handle_stix2_loading_error(
            stix_content, invalid_objects, duplicate_invalid_ids,
            document_invalid_ids
        )
    # keeps the recovered invalid objects with the bundle they came from, so
    # `load_stix_bundle` sees them even when the caller does not pass the dict
    bundle._invalid_objects = invalid_objects
    # the ids more than one invalid object claimed: the dict above only kept
    # the last of them, and only the parser can say what that costs
    bundle._duplicate_invalid_ids = duplicate_invalid_ids
    # the ids diverted from this document alone - what the dict above cannot
    # say once a caller-prepopulated or reused dict holds earlier losses too
    bundle._document_invalid_ids = document_invalid_ids
    return bundle


def load_stix2_file(filename, invalid_objects: Optional[dict] = None,
                    max_size: Optional[int] = None) -> _BUNDLE_TYPING:
    _check_input_file_size(filename, max_size)
    with open(filename, 'rt', encoding='utf-8') as f:
        # the file is deserialised as it is read: holding the whole document as
        # a string *and* as the structure it parses into doubles what the
        # largest accepted document costs
        stix_content = json.load(f)
    # the size was checked on the file: what reaches the content loader is the
    # structure it deserialised into, which no limit can un-materialise
    return load_stix2_content(stix_content, invalid_objects)
