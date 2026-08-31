#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import re
from typing import Any, Optional, Tuple

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


def _sanitise_template_name(name: Any) -> Tuple[str, Optional[Any]]:
    """Pick the name to use for template resolution, and report a rejection.

    :param name: candidate MISP object template name, from any source
    :return: the name safe to resolve, and the rejected name if there is one
    """
    if _is_template_name(name):
        return name, None
    return _UNKNOWN_TEMPLATE_NAME, name
