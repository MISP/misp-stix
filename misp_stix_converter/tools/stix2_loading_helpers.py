#!/usr/bin/env python3

import json
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


def _handle_invalid_stix_content(invalid_objects, *stix_objects):
    for stix_object in stix_objects:
        try:
            valid_object = stix2_parser(
                stix_object, allow_custom=True, interoperability=True
            )
        except Exception:
            invalid_objects[stix_object['id']] = stix_object
            continue
        yield valid_object


def _handle_stix2_loading_error(
        stix_content: dict,
        invalid_objects: Optional[dict] = {}) -> _BUNDLE_TYPING:
    version = _get_stix_content_version(stix_content)
    if isinstance(stix_content, dict):
        try:
            if version == '2.1' and stix_content.get('spec_version') == '2.0':
                del stix_content['spec_version']
                return dict_to_stix2(
                    stix_content, allow_custom=True, interoperability=True
                )
            elif version == '2.0' and stix_content.get('spec_version') == '2.1':
                stix_content['spec_version'] = '2.0'
                return dict_to_stix2(
                    stix_content, allow_custom=True, interoperability=True
                )
        except Exception:
            pass
    bundle_id = stix_content.get('id')
    bundle = Bundle_v21 if version == '2.1' else Bundle_v20
    if 'objects' in stix_content:
        stix_content = stix_content['objects']
    return bundle(
        *_handle_invalid_stix_content(invalid_objects, *stix_content),
        id=bundle_id, allow_custom=True, interoperability=True
    )


def load_stix2_content(stix_content: BytesIO | dict | list | str,
                       invalid_objects: Optional[dict] = {}) -> _BUNDLE_TYPING:
    if isinstance(stix_content, dict):
        try:
            return dict_to_stix2(
                stix_content, allow_custom=True, interoperability=True
            )
        except (InvalidValueError, ParseError, ValueError):
            return _handle_stix2_loading_error(
                stix_content, invalid_objects
            )
    if isinstance(stix_content, BytesIO):
        stix_content = stix_content.getvalue().decode('utf-8')
    try:
        return stix2_parser(
            stix_content, allow_custom=True, interoperability=True
        )
    except (InvalidValueError, ParseError, ValueError):
        return _handle_stix2_loading_error(
            json.loads(stix_content), invalid_objects
        )


def load_stix2_file(
        filename, invalid_objects: Optional[dict] = {}) -> _BUNDLE_TYPING:
    with open(filename, 'rt', encoding='utf-8') as f:
        stix_content = f.read()
    return load_stix2_content(stix_content, invalid_objects)
