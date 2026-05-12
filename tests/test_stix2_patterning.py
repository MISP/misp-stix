import unittest
from misp_stix_converter.misp2stix.misp_to_stix2 import MISPtoSTIX2Parser

_qs = MISPtoSTIX2Parser._quote_segment
_cn = MISPtoSTIX2Parser._canonical_hash_pattern_name


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


if __name__ == '__main__':
    unittest.main()
