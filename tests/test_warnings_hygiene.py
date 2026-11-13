#!/usr/bin/env python
# -*- coding: utf-8 -*-

import subprocess
import sys
import textwrap
import unittest
import warnings
from misp_stix_converter.misp_stix_converter import (
    _suppressed_insecure_request_warnings)
from urllib3.exceptions import InsecureRequestWarning


class TestImportWarningsHygiene(unittest.TestCase):
    def test_import_leaves_urllib3_warnings_enabled(self):
        # In a fresh interpreter, so the import under test is the real first
        # one: importing the package must not blanket-ignore urllib3 warnings
        # process-wide (dependencies register their own filters, so the
        # filter list is not compared wholesale - the ignore entry
        # `urllib3.disable_warnings()` would insert is what may not appear).
        script = textwrap.dedent(
            '''
            import warnings
            import misp_stix_converter
            from urllib3.exceptions import HTTPWarning, InsecureRequestWarning
            ignored = [
                entry for entry in warnings.filters
                if entry[0] == 'ignore' and entry[1] is None
                and entry[2] is not None and issubclass(HTTPWarning, entry[2])
            ]
            assert not ignored, ignored
            with warnings.catch_warnings(record=True) as caught:
                warnings.warn('probe', InsecureRequestWarning)
            assert len(caught) == 1, warnings.filters
            '''
        )
        completed = subprocess.run(
            [sys.executable, '-c', script], capture_output=True, text=True
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)


class TestScopedInsecureRequestWarningSuppression(unittest.TestCase):
    def test_suppression_scoped_to_unverified_connections(self):
        filters = warnings.filters[:]
        with _suppressed_insecure_request_warnings(False):
            self.assertTrue(
                any(
                    entry[0] == 'ignore'
                    and entry[2] is InsecureRequestWarning
                    for entry in warnings.filters
                )
            )
        self.assertEqual(warnings.filters, filters)

    def test_verified_connections_left_untouched(self):
        filters = warnings.filters[:]
        with _suppressed_insecure_request_warnings(True):
            self.assertEqual(warnings.filters, filters)
        self.assertEqual(warnings.filters, filters)


if __name__ == '__main__':
    unittest.main()
