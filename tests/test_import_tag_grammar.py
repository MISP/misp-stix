#!/usr/bin/env python
# -*- coding: utf-8 -*-

import ast
import re
import unittest
from misp_stix_converter.stix2misp import importparser
from pathlib import Path

_IMPORT_SOURCES = Path(importparser.__file__).parent
# Where every MISP taxonomy tag an import writes is built (ADR-0012).
_TAG_BUILDER_SOURCE = 'importparser.py'

# The two shapes a MISP taxonomy tag literal takes, as the source reads once
# the interpolated parts of an f-string are replaced by `{}`: the entry with a
# value, `<namespace>:<predicate>="<value>"`, and the bare entry, `tlp:<color>`.
_TAG_LITERALS = (
    re.compile(r'^[a-z][a-z0-9_.\-]*:\S*="'),
    re.compile(r'^[a-z][a-z0-9_.\-]*:\{\}$')
)


def _matched_literals(tree) -> set:
    """The tag literals a module reads rather than writes.

    A literal compared against the labels a document carries is the
    conversion recognising its own STIX output, not tagging a MISP record
    with it, so the one place tags are built has nothing to do with it.
    """
    return {
        id(node.left) for node in ast.walk(tree)
        if isinstance(node, ast.Compare) and any(
            isinstance(operator, (ast.In, ast.NotIn)) for operator in node.ops
        )
    }


def _literal_text(node) -> str:
    """The text a string node reads as, interpolated parts left as `{}`."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return ''.join(
            part.value if isinstance(part, ast.Constant) else '{}'
            for part in node.values
        )
    return ''


class TestImportTagGrammar(unittest.TestCase):

    def test_no_taxonomy_tag_is_written_outside_the_tag_builder(self):
        """One function writes every tag an import produces (ADR-0012).

        The number of places text a converted document supplied can reach the
        MISP taxonomy grammar is then a property of the design rather than of
        the last search for them: this test is that property.
        """
        written_elsewhere = []
        for path in sorted(_IMPORT_SOURCES.rglob('*.py')):
            if path.name == _TAG_BUILDER_SOURCE:
                continue
            tree = ast.parse(path.read_text(encoding='utf-8'))
            matched = _matched_literals(tree)
            for node in ast.walk(tree):
                if id(node) in matched:
                    continue
                text = _literal_text(node)
                if any(pattern.match(text) for pattern in _TAG_LITERALS):
                    written_elsewhere.append(
                        f'{path.relative_to(_IMPORT_SOURCES)}: {text}'
                    )
        self.assertEqual(written_elsewhere, [])
