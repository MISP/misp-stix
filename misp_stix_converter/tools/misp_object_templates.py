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

# Inside the MISP property extension of a STIX 2.1 object, the same fold names
# the value with no prefix: no producer prefixes the names inside an extension
# body. The base schema every extension body falls under is stricter than the
# custom property rule, so a bare fold is escaped where it is unusable there.
# A name shorter than three characters, not starting with a letter, or one the
# extension body uses for itself takes the prefix; a name ending with a suffix
# the base schema types as hex or base64 takes a trailing `_`. The 250
# characters limit is left unenforced, as it is for custom properties. The
# fixed MISP fields the extension holds (`filename`, `url`, `malware_sample`,
# `attachment`, `opinion`, `author_ref`) satisfy the rule, and go through the
# escape and its inverse unchanged.
_EXTENSION_PROPERTY_PREFIX = 'misp_'
_EXTENSION_PROPERTY_NAME_RE = re.compile(r'[a-z][a-z0-9_]{2,}')
_EXTENSION_RESERVED_NAMES = frozenset(
    (
        'extension_type', 'original_names',
        'windows_pebinary_ext', 'sections', 'values'
    )
)
_EXTENSION_TYPED_SUFFIXES = ('_hex', '_bin')

# The MISP Extensions: the STIX 2.1 extension definitions of the three MISP
# custom types and of the property extension holding the MISP values of a
# standard object. Both directions know them by these fixed ids only, whatever
# version of the definition a bundle carries. The MISP Project organisation
# authors them, under the identity MISP exports already carry for its uuid -
# the same organisation the import defaults to when it is given none.
MISP_org_uuid = '55f6ea65-aa10-4c5a-bf01-4f84950d210f'
_MISP_PROJECT_IDENTITY_ID = f'identity--{MISP_org_uuid}'
_MISP_ATTRIBUTE_EXTENSION_ID = (
    'extension-definition--c1f2c0fa-3786-4f27-bf57-cf050ecfc104'
)
_MISP_OBJECT_EXTENSION_ID = (
    'extension-definition--a093107b-933f-4d72-a9a6-6d7318adadda'
)
_MISP_GALAXY_CLUSTER_EXTENSION_ID = (
    'extension-definition--573a76d8-f8a0-4f53-bc93-f2777576b7b9'
)
_MISP_PROPERTY_EXTENSION_ID = (
    'extension-definition--5ece67ea-2e8b-4ed0-bb69-26d69053ee0b'
)


def _fold_relation(relation: str) -> str:
    """Fold a MISP relation or meta key to the STIX property name charset.

    :param relation: a MISP object relation or galaxy cluster meta key
    :return: the relation lowercased, every character outside `a-z`, `0-9`
        and `_` turned into `_`
    """
    return _CUSTOM_PROPERTY_FORBIDDEN_RE.sub('_', relation.lower())


def _custom_property_name(relation: str) -> str:
    """Name the custom property carrying a MISP relation or meta key.

    :param relation: a MISP object relation or galaxy cluster meta key
    :return: the `x_misp_` name, folded to the STIX custom property charset
    """
    return f'{_CUSTOM_PROPERTY_PREFIX}{_fold_relation(relation)}'


def _needs_extension_prefix(name: str) -> bool:
    """Tell whether a folded name takes the extension property prefix.

    :param name: a folded MISP relation or meta key
    :return: whether the name is too short, does not start with a letter, or
        is a name the extension body uses for itself
    """
    return (
        _EXTENSION_PROPERTY_NAME_RE.fullmatch(name) is None
        or name in _EXTENSION_RESERVED_NAMES
    )


def _extension_property_name(relation: str) -> str:
    """Name the MISP property extension property carrying a relation or key.

    :param relation: a MISP object relation or galaxy cluster meta key
    :return: the folded name, escaped where an extension body cannot hold it
    """
    name = _fold_relation(relation)
    if _needs_extension_prefix(name):
        name = f'{_EXTENSION_PROPERTY_PREFIX}{name}'
    if name.endswith(_EXTENSION_TYPED_SUFFIXES):
        name = f'{name}_'
    return name


def _custom_property_name_from_extension(name: str) -> str:
    """Name the custom property a MISP property extension property stands for.

    The escape is stripped by rule, with no template: a trailing `_` after a
    typed suffix, then the prefix when the rest would take it. So a relation
    the template does not know reads back without what looks like an escape:
    `misp-xy` as `xy`, `foo-hex-` as `foo_hex` - the same kind of loss the
    fold accepts. The custom property name then goes through the template
    inverse and the mapping tables as written.

    :param name: a property name inside the MISP property extension
    :return: the `x_misp_` name the custom property syntax gives the value
    """
    if name.endswith('_') and name[:-1].endswith(_EXTENSION_TYPED_SUFFIXES):
        name = name[:-1]
    if name.startswith(_EXTENSION_PROPERTY_PREFIX):
        rest = name[len(_EXTENSION_PROPERTY_PREFIX):]
        if _needs_extension_prefix(rest):
            name = rest
    return f'{_CUSTOM_PROPERTY_PREFIX}{name}'


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


@lru_cache(maxsize=None)
def _template_definition(name: str) -> Mapping[str, Any]:
    """Read the definition pymisp resolves for a template, once per name.

    pymisp exposes the resolved template as `_definition` only, so the private
    read lives here, next to the name guard, rather than at each call site.
    The callers guard the name, each where its contract says.

    :param name: a MISP object template name
    :return: the template definition, empty when the template is unknown to
        pymisp
    """
    from pymisp import MISPObject
    from pymisp.abstract import misp_objects_path
    misp_object = MISPObject(name, misp_objects_path_custom=misp_objects_path)
    return MappingProxyType(getattr(misp_object, '_definition', None) or {})


def _template_attribute_types(name: str) -> dict:
    """Read the attribute types a template defines, by object relation.

    pymisp types an object attribute from the template it resolved for the
    object, and refuses one whose object relation the template does not define.
    A converter that builds attributes from content-supplied relations has to
    know which of them the template can type, so it can fall back to `text`
    for the rest rather than have pymisp refuse them.

    :param name: a template name `_is_template_name` accepts
    :return: the MISP attribute type per object relation, empty when the
        template is unknown to pymisp - a fresh dict the caller may change
    """
    definition = _template_definition(name)
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
    return _template_definition(name).get('description')


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
