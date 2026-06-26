import re
import unittest
from misp_stix_converter.misp2stix.misp_to_stix2 import MISPtoSTIX2Parser

_qs = MISPtoSTIX2Parser._quote_segment
_ev = MISPtoSTIX2Parser._escape_pattern_value


def _cn(name: str) -> str:
    return re.sub(r'^(SHA(?:3(?=\d{3}$))?)(\d+)$', r'\1-\2', name)


class TestQuoteSegment(unittest.TestCase):

    def test_keyword_safe_bare(self):
        self.assertEqual(_qs('MD5'), 'MD5')
        self.assertEqual(_qs('SHA1'), 'SHA1')
        self.assertEqual(_qs('SHA256'), 'SHA256')
        self.assertEqual(_qs('SSDEEP'), 'SSDEEP')
        self.assertEqual(_qs('imphash'), 'imphash')
        self.assertEqual(_qs('_x'), '_x')
        self.assertEqual(_qs('x_misp_foo'), 'x_misp_foo')
        self.assertEqual(_qs('request_method'), 'request_method')

    def test_hyphen_requires_quotes(self):
        self.assertEqual(_qs('SHA-256'), "'SHA-256'")
        self.assertEqual(_qs('SHA-1'), "'SHA-1'")
        self.assertEqual(_qs('SHA3-256'), "'SHA3-256'")
        self.assertEqual(_qs('windows-pebinary-ext'), "'windows-pebinary-ext'")
        self.assertEqual(_qs('http-request-ext'), "'http-request-ext'")
        self.assertEqual(_qs('socket-ext'), "'socket-ext'")
        self.assertEqual(_qs('User-Agent'), "'User-Agent'")
        self.assertEqual(_qs('Content-Type'), "'Content-Type'")

    def test_dot_requires_quotes(self):
        self.assertEqual(_qs('a.b'), "'a.b'")

    def test_slash_requires_quotes(self):
        self.assertEqual(_qs('SHA-512/256'), "'SHA-512/256'")

    def test_leading_digit_requires_quotes(self):
        self.assertEqual(_qs('1abc'), "'1abc'")

    def test_empty_string_requires_quotes(self):
        self.assertEqual(_qs(''), "''")

    def test_embedded_apostrophe_escaped(self):
        self.assertEqual(_qs("O'Brien"), r"'O\'Brien'")

    def test_embedded_backslash_escaped(self):
        self.assertEqual(_qs('a\\b'), r"'a\\b'")


class TestCanonicalHashPatternName(unittest.TestCase):

    def test_mapped_names(self):
        self.assertEqual(_cn('SHA1'),   'SHA-1')
        self.assertEqual(_cn('SHA224'), 'SHA-224')
        self.assertEqual(_cn('SHA256'), 'SHA-256')
        self.assertEqual(_cn('SHA384'), 'SHA-384')
        self.assertEqual(_cn('SHA512'), 'SHA-512')
        self.assertEqual(_cn('SHA3224'), 'SHA3-224')
        self.assertEqual(_cn('SHA3256'), 'SHA3-256')
        self.assertEqual(_cn('SHA3384'), 'SHA3-384')
        self.assertEqual(_cn('SHA3512'), 'SHA3-512')

    def test_keyword_safe_passthrough(self):
        self.assertEqual(_cn('MD5'),         'MD5')
        self.assertEqual(_cn('SSDEEP'),      'SSDEEP')
        self.assertEqual(_cn('TLSH'),        'TLSH')
        self.assertEqual(_cn('IMPHASH'),     'IMPHASH')
        self.assertEqual(_cn('AUTHENTIHASH'), 'AUTHENTIHASH')
        self.assertEqual(_cn('VHASH'),       'VHASH')

    def test_unknown_passthrough(self):
        self.assertEqual(_cn('WEIRDHASH'), 'WEIRDHASH')

    def test_combined_with_quote_segment(self):
        self.assertEqual(_qs(_cn('SHA256')), "'SHA-256'")
        self.assertEqual(_qs(_cn('SHA3256')), "'SHA3-256'")
        self.assertEqual(_qs(_cn('MD5')), 'MD5')
        self.assertEqual(_qs(_cn('SSDEEP')), 'SSDEEP')


class TestEscapePatternValue(unittest.TestCase):

    def test_clean_value_unchanged(self):
        self.assertEqual(_ev('test_file_name'), 'test_file_name')
        self.assertEqual(_ev('plain value'), 'plain value')
        self.assertEqual(_ev(''), '')

    def test_backslash_doubled(self):
        self.assertEqual(_ev('a\\b'), r'a\\b')
        self.assertEqual(
            _ev(r'C:\Windows\System32'), r'C:\\Windows\\System32'
        )

    def test_apostrophe_escaped(self):
        self.assertEqual(_ev("O'Brien"), r"O\'Brien")

    def test_backslash_escaped_before_apostrophe(self):
        # backslash first, then quote: a lone "\'" becomes "\\\'"
        self.assertEqual(_ev("\\'"), r"\\\'")

    def test_backslash_and_apostrophe_combined(self):
        self.assertEqual(
            _ev("%USERPROFILE%\\O'Brien\\x.pdb"),
            r"%USERPROFILE%\\O\'Brien\\x.pdb"
        )

    def test_double_quote_left_untouched(self):
        self.assertEqual(_ev('say "hi"'), 'say "hi"')


if __name__ == '__main__':
    unittest.main()
