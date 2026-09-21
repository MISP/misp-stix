#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import re
from functools import lru_cache
from types import MappingProxyType
from typing import Any, Mapping, Optional, Tuple

# A MISP object template is a directory named after the template, so a template
# name is a single path component. pymisp resolves a template by joining the
# name into a filesystem path (`misp_objects_path / name / 'definition.json'`),
# which means a name carrying separators or `..` segments reads a file outside
# the template directory and copies its fields onto the object. The character
# set below is the one the misp-objects repository actually uses: letters,
# digits, `-` and `_`, upper case included (`ADS`, `ftm-Airplane`,
# `regripper-NTUser`, `intelmq_event`).
_TEMPLATE_NAME_REGEX = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]*')

# Stands in for a name that cannot be a template name: the object is then built
# as a generic, template-less one, and the rejected name is kept as data.
_UNKNOWN_TEMPLATE_NAME = 'unknown-template'

# A MISP object relation or galaxy meta key no STIX property maps travels as a
# custom property named after it. STIX 2.0 §7.1 and 2.1 §11.1.1 bind such a
# name to `a-z`, `0-9` and `_`, so the relation is lowercased and every other
# character folds to `_`. The fold is lossy by design: the rule lives here,
# next to the template reader, because the template is its inverse - no
# shipped template holds two relations folding to one name - and the import
# rebuilds the original spelling and type from it.
_CUSTOM_PROPERTY_PREFIX = 'x_misp_'
_CUSTOM_PROPERTY_FORBIDDEN_RE = re.compile(r'[^a-z0-9_]')

# The fold's side channel, for the names no template can invert - galaxy meta
# keys are free-form. A dictionary, per STIX object, from a name as written on
# the wire (a custom property name, prefix included, or an `x_misp_meta` key on
# a custom galaxy cluster - both valid dictionary keys) to the key as MISP
# spelled it, which a dictionary value may carry verbatim. Present only when
# the fold changed at least one name on the object, so a name a present
# channel does not list was written as MISP had it.
_ORIGINAL_NAMES_PROPERTY = 'x_misp_original_names'


def _custom_property_name(relation: str) -> str:
    """Name the custom property carrying a MISP relation or meta key.

    :param relation: a MISP object relation or galaxy cluster meta key
    :return: the `x_misp_` name, folded to the STIX custom property charset
    """
    folded = _CUSTOM_PROPERTY_FORBIDDEN_RE.sub('_', relation.lower())
    return f'{_CUSTOM_PROPERTY_PREFIX}{folded}'


def _custom_property_relation(field: str) -> str:
    """Read the folded relation a custom property name carries.

    :param field: an `x_misp_` custom property name
    :return: the name without its prefix - the folded relation, which is the
        object relation an attribute falls back to when no template nor
        mapping table restores the original spelling
    """
    return field[len(_CUSTOM_PROPERTY_PREFIX):]


def _is_template_name(name: Any) -> bool:
    """Tell whether a name is safe to hand to pymisp's template resolution.

    :param name: candidate MISP object template name, from any source
    :return: whether the name is a single, plain template name component
    """
    return (
        isinstance(name, str)
        and _TEMPLATE_NAME_REGEX.fullmatch(name) is not None
    )


def _rejected_name_note(name: Any) -> str:
    """Word the rejected name so it survives as data, in either direction.

    :param name: the name that could not be used as a template name
    :return: the note to keep alongside the object
    """
    return f'Original MISP object name: {name}'


def _template_attribute_types(name: str) -> dict:
    """Read the attribute types a template defines, by object relation.

    pymisp types an object attribute from the template it resolved for the
    object, and refuses one whose object relation the template does not define.
    A converter that builds attributes from content-supplied relations has to
    know which of them the template can type, so it can fall back to `text`
    for the rest rather than have pymisp refuse them. pymisp exposes the
    resolved template as `_definition` only, so the private read lives here,
    next to the name guard, rather than at each call site.

    :param name: a template name `_is_template_name` accepts
    :return: the MISP attribute type per object relation, empty when the
        template is unknown to pymisp
    """
    from pymisp import MISPObject
    from pymisp.abstract import misp_objects_path
    misp_object = MISPObject(name, misp_objects_path_custom=misp_objects_path)
    definition = getattr(misp_object, '_definition', None) or {}
    return {
        object_relation: attribute['misp-attribute']
        for object_relation, attribute in definition.get('attributes', {}).items()
    }


@lru_cache(maxsize=None)
def _template_description(name: Optional[str]) -> Optional[str]:
    """Read the description a template gives every object made from it.

    A MISP object carries its template's description in its own `description`
    field, and the STIX 1 export writes that description where the object has
    no comment - so the import needs the template's own text to tell the two
    apart and read back only a description the object's author wrote.

    :param name: a MISP object template name, or None where the shape the
        object came from names none
    :return: the template description, None when the name is not a template
        pymisp knows or the template gives no description
    """
    if not _is_template_name(name):
        return None
    from pymisp import MISPObject
    from pymisp.abstract import misp_objects_path
    misp_object = MISPObject(name, misp_objects_path_custom=misp_objects_path)
    definition = getattr(misp_object, '_definition', None) or {}
    return definition.get('description')


@lru_cache(maxsize=None)
def _template_custom_properties(name: str) -> Mapping[str, dict]:
    """Invert the custom property name fold through the object template.

    Every relation a template defines has one custom property name, and no
    shipped template gives two relations the same one, so the template is the
    complete inverse of the fold: from the folded name back to the original
    spelling and the type the template assigns. Read once per template, and
    refreshed with the misp-objects pymisp ships.

    :param name: a MISP object template name
    :return: the MISP attribute - `type` and `object_relation` - per custom
        property name, empty when the name is not a template pymisp knows
    """
    if not _is_template_name(name):
        return MappingProxyType({})
    return MappingProxyType(
        {
            _custom_property_name(object_relation): {
                'type': attribute_type, 'object_relation': object_relation
            }
            for object_relation, attribute_type
            in _template_attribute_types(name).items()
        }
    )


def _sanitise_template_name(name: Any) -> Tuple[str, Optional[Any]]:
    """Pick the name to use for template resolution, and report a rejection.

    :param name: candidate MISP object template name, from any source
    :return: the name safe to resolve, and the rejected name if there is one
    """
    if _is_template_name(name):
        return name, None
    return _UNKNOWN_TEMPLATE_NAME, name
