import re
import unittest
from misp_stix_converter.misp2stix.misp_to_stix2 import MISPtoSTIX2Parser

_qs = MISPtoSTIX2Parser._quote_segment
_qcp = MISPtoSTIX2Parser._quote_custom_property
_cpn = MISPtoSTIX2Parser._custom_property_name
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


class TestCustomPropertyName(unittest.TestCase):
    # STIX 2.0 §7.1 / STIX 2.1 §11.1.1: ASCII, a-z, 0-9 and `_` only.
    _RULE = re.compile(r'^x_misp_[a-z0-9_]*$')

    def test_conforming_relation_unchanged(self):
        self.assertEqual(_cpn('filename'), 'x_misp_filename')
        self.assertEqual(_cpn('sha512_224'), 'x_misp_sha512_224')

    def test_hyphen_becomes_underscore(self):
        self.assertEqual(_cpn('rel-with-dash'), 'x_misp_rel_with_dash')
        self.assertEqual(_cpn('user-avatar'), 'x_misp_user_avatar')

    def test_uppercase_folds_to_lowercase(self):
        self.assertEqual(_cpn('KnownMalicious'), 'x_misp_knownmalicious')
        self.assertEqual(_cpn('VAT'), 'x_misp_vat')
        self.assertEqual(_cpn('AS'), 'x_misp_as')
        self.assertEqual(_cpn('ISO3'), 'x_misp_iso3')

    def test_other_characters_become_underscore(self):
        # relations taken from the misp-objects templates
        self.assertEqual(_cpn('sha512/224'), 'x_misp_sha512_224')
        self.assertEqual(
            _cpn('classification.identifier'),
            'x_misp_classification_identifier'
        )
        self.assertEqual(_cpn('more informations'), 'x_misp_more_informations')
        self.assertEqual(
            _cpn('father-s-family-name-&-forename'),
            'x_misp_father_s_family_name___forename'
        )
        self.assertEqual(_cpn('fDenyTSConnections:'), 'x_misp_fdenytsconnections_')

    def test_non_ascii_becomes_underscore(self):
        self.assertEqual(_cpn('Aménagement'), 'x_misp_am_nagement')
        self.assertEqual(_cpn('genome_copies_®'), 'x_misp_genome_copies__')

    def test_every_output_satisfies_the_rule(self):
        for relation in (
                'filename', 'rel-with-dash', 'KnownMalicious', 'sha512/224',
                'classification.identifier', 'more informations',
                'father-s-family-name-&-forename', 'Aménagement',
                "rel' OR file:name = 'x", ''):
            with self.subTest(relation=relation):
                self.assertRegex(_cpn(relation), self._RULE)


class TestQuoteCustomProperty(unittest.TestCase):
    # The folded name is always a bare pattern keyword, so the quoting
    # backstop from the pattern property-name quoting work never fires on a
    # custom property; it stays as defence in depth.

    def test_hyphen_becomes_underscore_and_stays_bare(self):
        self.assertEqual(_qcp('rel-with-dash'), 'x_misp_rel_with_dash')
        self.assertEqual(_qcp('user-avatar'), 'x_misp_user_avatar')
        self.assertEqual(_qcp('filename'), 'x_misp_filename')

    def test_metacharacters_fold_and_stay_bare(self):
        self.assertEqual(_qcp('a.b'), 'x_misp_a_b')
        self.assertEqual(_qcp('rel]'), 'x_misp_rel_')
        self.assertEqual(_qcp('rel=1'), 'x_misp_rel_1')
        self.assertEqual(_qcp('weird relation'), 'x_misp_weird_relation')

    def test_pattern_syntax_cannot_escape_the_segment(self):
        self.assertEqual(_qcp("x'"), 'x_misp_x_')
        self.assertEqual(
            _qcp("rel' OR file:name = 'x"), 'x_misp_rel__or_file_name____x'
        )

    def test_empty_relation_stays_bare(self):
        self.assertEqual(_qcp(''), 'x_misp_')


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
