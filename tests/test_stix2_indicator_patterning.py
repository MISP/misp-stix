import unittest
from misp_stix_converter.stix2misp.converters.stix2_indicator_converter import (
    InternalSTIX2IndicatorConverter
)

_evp = InternalSTIX2IndicatorConverter._extract_value_from_pattern
_efp = InternalSTIX2IndicatorConverter._extract_features_from_pattern
_split = InternalSTIX2IndicatorConverter._split_pattern_on_and


class TestExtractValueFromPattern(unittest.TestCase):

    def test_simple_value(self):
        self.assertEqual(_evp("file:name = 'test.exe'"), 'test.exe')

    def test_value_containing_equals_sign(self):
        # A filename such as 'a = b.exe' must not be truncated at the
        # first ' = ' found inside the value itself.
        self.assertEqual(_evp("file:name = 'a = b.exe'"), 'a = b.exe')


class TestExtractFeaturesFromPattern(unittest.TestCase):

    def test_simple_value(self):
        self.assertEqual(
            _efp("file:name = 'test.exe'"), ('name', 'test.exe')
        )

    def test_value_containing_equals_sign(self):
        self.assertEqual(
            _efp("file:name = 'a = b.exe'"), ('name', 'a = b.exe')
        )


class TestSplitPatternOnAnd(unittest.TestCase):

    def test_simple_split(self):
        pattern = "file:name = 'test.exe' AND file:hashes.MD5 = 'abcd'"
        self.assertEqual(
            _split(pattern),
            ["file:name = 'test.exe'", "file:hashes.MD5 = 'abcd'"]
        )

    def test_and_inside_quoted_value_is_not_a_separator(self):
        # A filename containing the literal substring ' AND ' must not
        # shift the comparison boundaries and misassign the hash value.
        pattern = (
            "file:name = 'evil AND you.exe' AND "
            "file:hashes.MD5 = 'deadbeefdeadbeefdeadbeefdeadbeef'"
        )
        self.assertEqual(
            _split(pattern),
            [
                "file:name = 'evil AND you.exe'",
                "file:hashes.MD5 = 'deadbeefdeadbeefdeadbeefdeadbeef'"
            ]
        )

    def test_escaped_quote_inside_value(self):
        pattern = r"file:name = 'a\'b AND c' AND file:hashes.MD5 = 'x'"
        self.assertEqual(
            _split(pattern),
            [r"file:name = 'a\'b AND c'", "file:hashes.MD5 = 'x'"]
        )


if __name__ == '__main__':
    unittest.main()
