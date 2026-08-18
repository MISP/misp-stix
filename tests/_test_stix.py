#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import unittest
from datetime import datetime

# Stands in for any `definition.json` a traversing object name could reach:
# the values are recognisable so a leak into the converted data is obvious.
PLANTED_TEMPLATE = {
    'name': 'planted',
    'uuid': 'deadbeef-0000-4000-8000-000000000000',
    'meta-category': 'LEAKED-CATEGORY',
    'description': 'CONTENTS OF A FILE OUTSIDE THE TEMPLATE DIRECTORY',
    'version': 99,
    'attributes': {}
}


class TestSTIX(unittest.TestCase):

    def _assert_multiple_equal(self, reference, *elements):
        for element in elements:
            self.assertEqual(reference, element)

    def _check_output_write_safety(self, conversion, filename, **kwargs):
        # What a conversion writes is as sensitive as the document it came
        # from: the file is readable by its owner alone whatever the process
        # umask allows, and one that already exists is only replaced when the
        # caller asked for it, with the refusal naming the file it left as it
        # was
        import os
        umask = os.umask(0)
        try:
            results = conversion(filename, **kwargs)
        finally:
            os.umask(umask)
        self.assertEqual(results['success'], 1)
        output = results['results'][0]
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        written = output.read_text(encoding='utf-8')
        with self.assertRaises(FileExistsError) as context:
            conversion(filename, **kwargs)
        self.assertIn(str(output), str(context.exception))
        self.assertIn('overwrite', str(context.exception))
        self.assertEqual(output.read_text(encoding='utf-8'), written)
        results = conversion(filename, overwrite=True, **kwargs)
        self.assertEqual(results['success'], 1)
        self.assertEqual(results['results'][0], output)

    def _check_output_dir_handling(
            self, conversion, filename, outputs: int = 1, **kwargs):
        # `output_dir` is documented as a `Path` or a `str`, and how many MISP
        # events a document yields is the document's own shape rather than a
        # caller parameter: both types work whichever branch that shape
        # selects, and a location that does not exist yet is created rather
        # than failing at write time - `str` and creation crossed, since the
        # branch reached for one of them is where neither held
        #
        # `_check_output_dir_refuses_a_file` covers the other half, for the
        # conversions that can reach the per-event branch
        from pathlib import Path
        from tempfile import TemporaryDirectory
        for single_event in (True, False):
            for as_str in (False, True):
                for exists in (True, False):
                    with TemporaryDirectory() as tmp_dir:
                        directory = (
                            Path(tmp_dir) / 'missing' / 'output'
                        ).resolve()
                        if exists:
                            directory.mkdir(parents=True)
                        results = conversion(
                            filename, single_event=single_event,
                            output_dir=(
                                str(directory) if as_str else directory
                            ), **kwargs
                        )
                        self.assertEqual(results['success'], 1)
                        self.assertTrue(directory.is_dir())
                        self.assertEqual(
                            len(results['results']),
                            1 if single_event else outputs
                        )
                        self._check_written_in(directory, results['results'])

    def _check_output_dir_refuses_a_file(self, conversion, filename, taken):
        # A directory is the only thing that can hold one file per MISP event,
        # so unlike the output funnels an existing file is not read as the
        # output file: the conversion says which path it could not make a
        # directory of, and leaves the file as it was
        with open(taken, 'wt', encoding='utf-8') as f:
            f.write('taken')
        with self.assertRaises(FileExistsError) as context:
            conversion(filename, output_dir=taken)
        self.assertIn(str(taken), str(context.exception))
        self.assertEqual(taken.read_text(encoding='utf-8'), 'taken')

    def _check_written_in(self, directory, outputs):
        for output in outputs:
            self.assertEqual(output.parent, directory)
            self.assertTrue(output.is_file())

    @staticmethod
    def _plant_template_definition(directory):
        """Plant a template definition outside the MISP objects directory.

        :param directory: a directory outside the template tree
        :return: the object name that reaches it from the templates path
        """
        from os.path import relpath
        from pathlib import Path
        from pymisp import AbstractMISP
        planted = Path(directory) / 'planted'
        planted.mkdir()
        with open(planted / 'definition.json', 'wt', encoding='utf-8') as f:
            json.dump(PLANTED_TEMPLATE, f)
        return relpath(planted, AbstractMISP().misp_objects_path)

    @staticmethod
    def _datetime_from_str(timestamp):
        if isinstance(timestamp, datetime):
            return timestamp
        regex = f"%Y-%m-%d{'T' if 'T' in timestamp else ' '}%H:%M:%S"
        if '.' in timestamp:
            regex = f'{regex}.%f'
        if timestamp.endswith('Z') or '+' in timestamp:
            regex = f'{regex}%z'
        return datetime.strptime(timestamp, regex)


class TestSTIX20(TestSTIX):
    __hash_types_mapping = {
        'sha1': 'SHA-1',
        'SHA-1': 'sha1',
        'sha224': 'SHA-224',
        'SHA-224': 'sha224',
        'sha256': 'SHA-256',
        'SHA-256': 'sha256',
        'sha384': 'SHA-384',
        'SHA-384': 'sha384',
        'sha512': 'SHA-512',
        'SHA-512': 'sha512',
        'sha512/224': 'SHA-224',
        'sha512/256': 'SHA-256',
        'ssdeep': 'ssdeep'
    }

    @classmethod
    def hash_types_mapping(cls, hash_type):
        if hash_type in cls.__hash_types_mapping:
            return cls.__hash_types_mapping[hash_type]
        return hash_type.lower() if hash_type.isupper() else hash_type.upper()


class TestSTIX21(TestSTIX):
    __hash_types_mapping = {
        'sha1': 'SHA-1',
        'SHA-1': 'sha1',
        'sha224': 'SHA224',
        'SHA224': 'sha224',
        'sha256': 'SHA-256',
        'SHA-256': 'sha256',
        'sha384': 'SHA384',
        'SHA384': 'sha384',
        'sha512': 'SHA-512',
        'SHA-512': 'sha512',
        'sha512/224': 'SHA224',
        'sha512/256': 'SHA-256'
    }

    @classmethod
    def hash_types_mapping(cls, hash_type):
        if hash_type in cls.__hash_types_mapping:
            return cls.__hash_types_mapping[hash_type]
        return hash_type.lower() if hash_type.isupper() else hash_type.upper()

    def _check_grouping_features(self, grouping, identity_id):
        event = self.parser._misp_event
        self.assertEqual(grouping.type, 'grouping')
        self.assertEqual(grouping.id, f"grouping--{event.uuid}")
        self.assertEqual(grouping.created_by_ref, identity_id)
        self.assertEqual(grouping.labels, self._labels)
        self.assertEqual(grouping.name, event.info)
        self.assertEqual(grouping.created, event.timestamp)
        self.assertEqual(grouping.modified, event.timestamp)
        return grouping.object_refs
