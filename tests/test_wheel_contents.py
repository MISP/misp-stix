#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

_REPOSITORY = Path(__file__).resolve().parent.parent

# Poetry's masonry sweeps the package directory rather than git, so anything
# sitting under `misp_stix_converter` at build time is a candidate for the
# wheel: the maintainer's scratch modules, coverage databases, Finder
# droppings, and the galaxy trees `data/STIX_2*` are generated into.
# `.coverage[^/]*` rather than `.coverage`: a parallel run writes one
# database per process, named `.coverage.<host>.<pid>.<random>`.
_LOCAL_ARTEFACTS = re.compile(
    r'(^|/)(tmp_[^/]*\.py|\.coverage[^/]*|\.DS_Store)$'
)
_GENERATED_DATA = 'misp_stix_converter/data/STIX_2'

# The reverse hazard: the only data file the runtime reads. A wheel that
# excluded it would import and then fail on the first galaxy cluster.
_CATALOG = 'misp_stix_converter/data/cti_uuid_catalog.json'

# A cluster the catalog knows, and the STIX id it answers with. Converting an
# event that carries it is what proves the catalog shipped: the id below is
# read out of `cti_uuid_catalog.json` at conversion time, never computed.
_CLUSTER_VALUE = 'Access Token Manipulation - T1134'
_CLUSTER_EXTERNAL_ID = 'T1134'
_CATALOG_STIX_ID = 'attack-pattern--dcaa092b-7de9-4a21-977f-7fcb77e89c48'

# Run inside the installed package, never here: the point is to exercise the
# artefact, so nothing this script touches may come from the source tree.
_VERIFICATION = f'''
import json

import misp_stix_converter
from misp_stix_converter import MISPtoSTIX21Parser
from pymisp import MISPEvent

event = MISPEvent()
event.from_dict(
    **{{
        'Event': {{
            'uuid': '0c2b0e29-2f5a-4e0d-9c35-8f1bfb2a9c6a',
            'info': 'Wheel contents test event',
            'date': '2026-09-16',
            'Attribute': [
                {{
                    'uuid': '6f4a5f9c-3b0e-4a1d-9a8e-2b4c6d8e0f13',
                    'type': 'domain', 'value': 'circl.lu'
                }}
            ],
            'Galaxy': [
                {{
                    'uuid': 'c4e851fa-775f-11e7-8163-b774922098cd',
                    'name': 'Attack Pattern', 'type': 'mitre-attack-pattern',
                    'GalaxyCluster': [
                        {{
                            'uuid': 'e042a41b-5ecf-4f3a-8f1f-1b528c534772',
                            'type': 'mitre-attack-pattern',
                            'value': {_CLUSTER_VALUE!r},
                            'meta': {{
                                'external_id': [{_CLUSTER_EXTERNAL_ID!r}]
                            }}
                        }}
                    ]
                }}
            ]
        }}
    }}
)
parser = MISPtoSTIX21Parser(use_cti_uuids=True)
parser.parse_misp_event(event)
print(
    json.dumps(
        {{
            'file': misp_stix_converter.__file__,
            'missing': [
                name for name in misp_stix_converter.__all__
                if not hasattr(misp_stix_converter, name)
            ],
            'object_refs': [
                reference for stix_object in parser.bundle.objects
                if stix_object['type'] == 'grouping'
                for reference in stix_object['object_refs']
            ]
        }}
    )
)
'''

_GATE = 'MISP_STIX_WHEEL_TESTS'
_SKIP = f'set {_GATE} to build a wheel and run it - takes a minute'


@unittest.skipUnless(os.environ.get(_GATE), _SKIP)
class TestWheelContents(unittest.TestCase):
    """What `poetry build` puts in the wheel, and what that wheel does.

    Every other test in this suite imports `misp_stix_converter` from the
    source tree, so none of them can see the two ways publishing goes wrong:
    a file that should not ship and does, or a file that must ship and does
    not. Both land silently on PyPI - the wheel installs either way, and the
    second only shows up when a consumer converts a galaxy cluster.

    Run before tagging a release, not in CI: a test that runs after the
    upload has nothing left to protect. See `docs/release-steps.md`.
    """

    @classmethod
    def setUpClass(cls):
        cls._directory = Path(tempfile.mkdtemp(prefix='misp-stix-wheel-'))
        cls.addClassCleanup(shutil.rmtree, cls._directory, True)
        cls._installed = None
        output = cls._directory / 'dist'
        cls._run(
            'poetry', 'build', '--no-interaction', '--quiet',
            '--format', 'wheel', '--output', str(output), cwd=_REPOSITORY
        )
        cls._wheel = next(output.glob('*.whl'))

    @classmethod
    def _run(cls, *command, **arguments) -> str:
        """Run a step, and say what it printed when it fails.

        `check=True` would raise a `CalledProcessError` whose message names
        the command and drops the captured output, which is the only part
        that says why a build or an install went wrong.
        """
        completed = subprocess.run(
            command, capture_output=True, text=True, **arguments
        )
        if completed.returncode != 0:
            raise AssertionError(
                f'{command[0]} exited {completed.returncode}:\n'
                f'{completed.stderr or completed.stdout}'
            )
        return completed.stdout

    @classmethod
    def _install(cls) -> Path:
        """Install the wheel where it shadows the source tree.

        `--target` rather than a virtual environment: the development
        environment is already one, so `--system-site-packages` would inherit
        the *base* interpreter's packages and none of the dependencies. A
        target directory on `PYTHONPATH` comes ahead of both site-packages
        and the editable install, and `--no-deps` keeps the step offline -
        which also means it says nothing about whether the dependency
        declarations are right.

        Done here on first use rather than in `setUpClass` so that the
        inventory assertion, which needs none of it, fails before it.
        """
        if cls._installed is None:
            target = cls._directory / 'installed'
            cls._run(
                sys.executable, '-m', 'pip', 'install', '--no-deps',
                '--quiet', '--disable-pip-version-check',
                '--target', str(target), str(cls._wheel)
            )
            cls._installed = target
        return cls._installed

    def _run_in_the_installed_package(self) -> dict:
        installed = self._install()
        outcome = json.loads(
            self._run(
                sys.executable, '-c', _VERIFICATION,
                # Anywhere but the repository: `python -c` puts the working
                # directory first on `sys.path`, which imports the source.
                cwd=self._directory,
                env=dict(os.environ, PYTHONPATH=str(installed))
            )
        )
        self.assertTrue(
            outcome['file'].startswith(f'{installed}{os.sep}'),
            f"imported {outcome['file']}, not the installed wheel"
        )
        return outcome

    def _shipped(self) -> list:
        with zipfile.ZipFile(self._wheel) as archive:
            return archive.namelist()

    def test_the_wheel_contains_no_local_artefacts(self):
        """Read the archive, install nothing: this one has to fail fast."""
        shipped = [
            name for name in self._shipped()
            if _LOCAL_ARTEFACTS.search(name)
            or name.startswith(_GENERATED_DATA)
        ]
        # `assertFalse` rather than a comparison with `[]`: the generated
        # galaxy trees are tens of thousands of files, and a diff of them is
        # unreadable where a count and a sample are not.
        self.assertFalse(
            shipped,
            f'{len(shipped)} local artefacts in the wheel, '
            f'starting with {shipped[:3]}'
        )

    def test_the_wheel_contains_the_data_file_the_runtime_reads(self):
        """The reverse hazard, and the cheap half of its proof.

        Converting a cluster is what shows the catalog is *usable*; this
        shows it is there at all, without paying for an install to find out.
        """
        self.assertIn(_CATALOG, self._shipped())

    def test_the_wheel_installs_and_converts_an_event(self):
        outcome = self._run_in_the_installed_package()
        # The same property `test_public_surface.py` asserts, re-asserted
        # here because only a subprocess can ask it of the installed copy.
        self.assertEqual(outcome['missing'], [])
        self.assertIn(_CATALOG_STIX_ID, outcome['object_refs'])


if __name__ == '__main__':
    unittest.main()
