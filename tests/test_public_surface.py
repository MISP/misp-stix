#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import unittest
import misp_stix_converter
from misp_stix_converter import misp2stix, stix2misp, tools
from pathlib import Path

_REPOSITORY = Path(__file__).resolve().parent.parent
_PYPROJECT = _REPOSITORY / 'pyproject.toml'
_README = _REPOSITORY / 'README.md'

# The two Public Surfaces: what a consumer may import from, and nothing else.
_PUBLIC_SURFACES = {
    'misp_stix_converter': misp_stix_converter,
    'misp_stix_converter.tools': tools
}

# The class names the naming conventions fix (`CLAUDE.md`): a conversion class
# is a `*Parser` or a `*Mapping`, whichever direction and STIX version it
# serves. Applied to what the two subpackages export, never to the modules
# below them, so the base classes and the converter internals stay out.
_CONVERSION_CLASS = re.compile(r'(Parser|Mapping)$')
_SUBPACKAGES = (misp2stix, stix2misp)

# `from <module> import <names>`, written on one line or with the names in
# parentheses over several, at whatever indentation the example reads best at.
_README_IMPORT = re.compile(
    r'^[ \t]*from (misp_stix_converter[\w.]*) import (\([^)]*\)|.+)$',
    re.MULTILINE
)
_VERSION = re.compile(r'^version = "([^"]+)"$', re.MULTILINE)


def _exported_classes(module) -> dict:
    return {
        name: value for name, value in vars(module).items()
        if not name.startswith('_') and isinstance(value, type)
        and _CONVERSION_CLASS.search(name)
    }


class TestPublicSurface(unittest.TestCase):
    """The surfaces as a whole, which no single import can cover.

    Tests elsewhere import a name they need, from wherever it is spelled -
    the root for some, the module a converter lives in for others - so each
    of them covers the one name it uses and says nothing about the surface
    it came from. What is asserted here is the property none of them reach:
    that the surface is complete, that both directions are on it, and that
    the README sends a reader to names that are. These assertions run in the
    same interpreter as the rest on purpose: a deep import binds the
    submodule attribute on its parent package, never the class names, so no
    other test can make them pass for the wrong reason.
    """

    def test_declared_exports_resolve(self):
        for module, surface in _PUBLIC_SURFACES.items():
            with self.subTest(module=module):
                missing = [
                    name for name in surface.__all__
                    if not hasattr(surface, name)
                ]
                self.assertEqual(missing, [])

    def test_conversion_classes_are_exported_by_the_root(self):
        """Both directions reach the root, or neither does.

        `ExternalSTIX2toMISPParser` was importable from the package while
        `ExternalSTIX1toMISPParser` was not, for no reason a consumer could
        tell from the outside. The symmetry is what this asserts: a class
        either subpackage exports is part of the surface, which means the
        root both holds it and declares it.
        """
        unreachable = []
        for subpackage in _SUBPACKAGES:
            for name, value in _exported_classes(subpackage).items():
                if (getattr(misp_stix_converter, name, None) is not value
                        or name not in misp_stix_converter.__all__):
                    unreachable.append(f'{subpackage.__name__}.{name}')
        self.assertEqual(unreachable, [])

    def test_readme_imports_the_names_the_package_exports(self):
        """The README is part of the contract.

        A name it tells a reader to import must be one they can, and from a
        Public Surface: an import statement naming a module below those two
        documents a Deep Path as if it were supported.
        """
        undocumented = []
        readme = _README.read_text(encoding='utf-8')
        for module, imported in _README_IMPORT.findall(readme):
            if module not in _PUBLIC_SURFACES:
                undocumented.append(f'{module} is not a Public Surface')
                continue
            exported = _PUBLIC_SURFACES[module].__all__
            undocumented.extend(
                f'{module}.{name}' for name in (
                    part.strip() for part in imported.strip('()').split(',')
                ) if name and name not in exported
            )
        self.assertEqual(undocumented, [])

    def test_version_matches_the_packaging_metadata(self):
        # Read with a regex rather than `tomllib`: Python 3.10 is in the CI
        # matrix and has none.
        version = _VERSION.search(_PYPROJECT.read_text(encoding='utf-8'))
        self.assertIsNotNone(version, 'no version field in pyproject.toml')
        self.assertEqual(misp_stix_converter.__version__, version.group(1))


if __name__ == '__main__':
    unittest.main()
