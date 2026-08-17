#!/usr/bin/env python3

import json
from .exceptions import STIXLoadingError
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
        invalid_objects, duplicate_invalid_ids, *stix_objects):
    # the ids set aside from this content, so a dict the caller passed in
    # already populated by an earlier load never reads as a duplicate
    invalid_ids = set()
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
            if object_id in invalid_ids:
                duplicate_invalid_ids.add(object_id)
            invalid_ids.add(object_id)
            invalid_objects[object_id] = stix_object
            continue
        yield valid_object


def _handle_stix2_loading_error(
        stix_content: dict, invalid_objects: dict,
        duplicate_invalid_ids: set) -> _BUNDLE_TYPING:
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
            invalid_objects, duplicate_invalid_ids, *stix_content['objects']
        ),
        id=bundle_id, allow_custom=True, interoperability=True
    )


def load_stix2_content(stix_content: BytesIO | dict | list | str,
                       invalid_objects: Optional[dict] = None) -> _BUNDLE_TYPING:
    if invalid_objects is None:
        invalid_objects = {}
    duplicate_invalid_ids: set = set()
    if isinstance(stix_content, dict):
        try:
            bundle = dict_to_stix2(
                stix_content, allow_custom=True, interoperability=True
            )
        except (InvalidValueError, KeyError, ParseError, ValueError):
            # the 2.1 code path in `stix2` reports an object without a `type`
            # property as a bare KeyError where the 2.0 one uses ParseError
            bundle = _handle_stix2_loading_error(
                stix_content, invalid_objects, duplicate_invalid_ids
            )
    else:
        if isinstance(stix_content, BytesIO):
            stix_content = stix_content.getvalue().decode('utf-8')
        try:
            bundle = stix2_parser(
                stix_content, allow_custom=True, interoperability=True
            )
        except (InvalidValueError, KeyError, ParseError, ValueError):
            bundle = _handle_stix2_loading_error(
                json.loads(stix_content), invalid_objects, duplicate_invalid_ids
            )
    # keeps the recovered invalid objects with the bundle they came from, so
    # `load_stix_bundle` sees them even when the caller does not pass the dict
    bundle._invalid_objects = invalid_objects
    # the ids more than one invalid object claimed: the dict above only kept
    # the last of them, and only the parser can say what that costs
    bundle._duplicate_invalid_ids = duplicate_invalid_ids
    return bundle


def load_stix2_file(
        filename, invalid_objects: Optional[dict] = None) -> _BUNDLE_TYPING:
    with open(filename, 'rt', encoding='utf-8') as f:
        stix_content = f.read()
    return load_stix2_content(stix_content, invalid_objects)
