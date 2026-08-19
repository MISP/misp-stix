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
# The namespace of a quoted entry may be interpolated too - the `="` is what
# makes the shape a tag, so nothing else can match. The bare entry has no such
# mark and reads as any two-part join (a kill chain phase, for one), so there
# the namespace has to be a literal for the shape to mean anything.
_TAG_LITERALS = (
    re.compile(r'^([a-z][a-z0-9_.\-]*|\{\}):\S*="'),
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
    """The text a string node reads as, interpolated parts left as `{}`.

    Every way a string is assembled has to read as the one text it assembles,
    or the shape is a property of how a tag was written rather than of what it
    writes: an f-string, a concatenation, a `%` and a `.format()` all fold to
    the same `<namespace>:<predicate>="` the grammar is recognised by.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return ''.join(
            _literal_text(part) or '{}' for part in node.values
        )
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Add):
            return (
                (_literal_text(node.left) or '{}')
                + (_literal_text(node.right) or '{}')
            )
        if isinstance(node.op, ast.Mod):
            # `'a:%s="%s"' % values` says its shape on the left alone
            return _literal_text(node.left)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr in ('format', 'join'):
            return _literal_text(node.func.value)
    return ''


def _tags_written_in(source: str) -> list:
    """The taxonomy tag literals a module's source writes.

    Held apart from the sweep over the tree so the guard itself can be
    measured: what it is worth is what it catches, and a shape it misses is
    indistinguishable - from the sweep alone - from a shape nothing writes.
    """
    tree = ast.parse(source)
    matched = _matched_literals(tree)
    written = []
    # A tag assembled in several steps matches at each of them - the whole
    # concatenation and every prefix of it - and is still one tag written in
    # one place. `ast.walk` yields a node before the nodes it holds, so the
    # first match of a subtree is the widest one, and the rest is that one
    # again.
    covered = set()
    for node in ast.walk(tree):
        if id(node) in matched or id(node) in covered:
            continue
        text = _literal_text(node)
        if any(pattern.match(text) for pattern in _TAG_LITERALS):
            written.append(text)
            covered.update(id(inner) for inner in ast.walk(node))
    return written


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
            written_elsewhere.extend(
                f'{path.relative_to(_IMPORT_SOURCES)}: {text}'
                for text in _tags_written_in(path.read_text(encoding='utf-8'))
            )
        self.assertEqual(written_elsewhere, [])

    def test_every_way_of_writing_a_tag_is_caught(self):
        """The guard above is worth what it catches (ADR-0012 §5).

        A grep misses `str.format`, `%`, concatenation and a variable prefix,
        which is why the guard reads the sources as syntax - but reading them
        as syntax only helps for the shapes the matcher folds. Each way of
        assembling the one tag below is a way a site could have written it and
        gone unseen: `f'{definition_type}:{definition}'` did.
        """
        for source in (
                'x = f\'misp-galaxy:{t}="{v}"\'',
                'x = "misp-galaxy:" + t + \'="\' + v + \'"\'',
                'x = \'misp-galaxy:{}="{}"\'.format(t, v)',
                'x = \'misp-galaxy:%s="%s"\' % (t, v)',
                'x = f\'{namespace}:{t}="{v}"\'',
                'x = \'{}:{}="{}"\'.format(namespace, t, v)'):
            with self.subTest(source=source):
                self.assertEqual(len(_tags_written_in(source)), 1)

    def test_a_tag_a_module_reads_is_not_a_tag_it_writes(self):
        """A literal compared against the labels a document carries is the
        conversion recognising its own STIX output, so the builder has nothing
        to do with it - the exemption the sweep relies on, measured."""
        self.assertEqual(
            _tags_written_in(
                'x = \'misp:context-layer="Analyst Note"\' in note["labels"]'
            ),
            []
        )

    def test_a_two_part_join_is_not_a_bare_tag(self):
        """The bare entry has no mark of its own: an interpolated namespace
        would make the shape match every `a:b` join, so it stays literal."""
        self.assertEqual(
            _tags_written_in("x = f'{kill_chain_name}:{phase_name}'"), []
        )
