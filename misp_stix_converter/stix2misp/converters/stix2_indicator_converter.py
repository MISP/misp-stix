#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ... import Mapping
from ..exceptions import (
    AttributeFromPatternParsingError, InvalidSTIXPatternError,
    UndefinedIndicatorError, UnknownParsingFunctionError)
from ..importparser import _INDICATOR_TYPING
from ..stix2_pattern_parser import STIX2PatternParser
from .stix2converter import (
    ExternalSTIX2Converter, InternalSTIX2Converter, STIX2Converter)
from .stix2mapping import (
    ExternalSTIX2Mapping, InternalSTIX2Mapping, STIX2Mapping)
from abc import ABCMeta
from collections import defaultdict
from pymisp import MISPObject
from stix2.v21.sdo import Indicator
from stix2patterns.inspector import _PatternData as PatternData
from typing import TYPE_CHECKING, Tuple, Union

if TYPE_CHECKING:
    from ..external_stix2_to_misp import ExternalSTIX2toMISPParser
    from ..internal_stix2_to_misp import InternalSTIX2toMISPParser

_MAIN_PARSER_TYPING = Union[
    'ExternalSTIX2toMISPParser', 'InternalSTIX2toMISPParser'
]


class STIX2IndicatorMapping(STIX2Mapping, metaclass=ABCMeta):
    # SINGLE ATTRIBUTES MAPPING
    __suricata_reference_attribute = Mapping(
        **{'type': 'link', 'object_relation': 'ref'}
    )

    # MISP OBJECTS MAPPING
    __suricata_object_mapping = Mapping(
        pattern=STIX2Mapping.snort_attribute(),
        description=STIX2Mapping.comment_attribute(),
        pattern_version=STIX2Mapping.version_attribute()
    )

    @classmethod
    def socket_extension_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.network_socket_extension_mapping().get(field)

    @classmethod
    def suricata_object_mapping(cls) -> dict:
        return cls.__suricata_object_mapping

    @classmethod
    def suricata_reference_attribute(cls) -> dict:
        return cls.__suricata_reference_attribute


class STIX2IndicatorConverter(STIX2Converter, metaclass=ABCMeta):
    def __init__(self, main: _MAIN_PARSER_TYPING):
        self._set_main_parser(main)


class ExternalSTIX2IndicatorMapping(
        STIX2IndicatorMapping, ExternalSTIX2Mapping):
    pass


class ExternalSTIX2IndicatorConverter(
        STIX2IndicatorConverter, ExternalSTIX2Converter):
    def __init__(self, main: 'ExternalSTIX2toMISPParser'):
        super().__init__(main)
        self._mapping = ExternalSTIX2IndicatorMapping

    def parse(self, indicator_ref: str):
        indicator = self.main_parser._get_stix_object(indicator_ref)


    def _compile_stix_pattern(
            self, indicator: _INDICATOR_TYPING) -> PatternData:
        try:
            self._pattern_parser.handle_indicator(indicator)
        except AttributeError:
            self._pattern_parser = STIX2PatternParser()
            self._pattern_parser.handle_indicator(indicator)
        if not self._pattern_parser.valid:
            raise InvalidSTIXPatternError(indicator.pattern)
        return self._pattern_parser.pattern


class InternalSTIX2IndicatorMapping(
        STIX2IndicatorMapping, InternalSTIX2Mapping):
    # ATTRIBUTES MAPPING
    __attributes_mapping = Mapping(
        **{
            'AS': '_attribute_from_AS',
            'attachment': '_attribute_from_attachment',
            'malware-sample': '_attribute_from_malware_sample',
            **dict.fromkeys(
                (
                    'authentihash', 'cdhash', 'domain', 'email',
                    'email-attachment', 'email-body', 'email-dst',
                    'email-header', 'email-message-id', 'email-reply-to',
                    'email-src', 'email-subject', 'email-x-mailer', 'filename',
                    'hostname', 'http-method', 'imphash', 'impfuzzy', 'link',
                    'mac-address', 'md5', 'mutex', 'pehash', 'port', 'sha1',
                    'sha224', 'sha256', 'sha384', 'sha512', 'sha512/224',
                    'sha512/256', 'sha3-224', 'sha3-256', 'sha3-384',
                    'sha3-512', 'size-in-bytes', 'ssdeep', 'regkey', 'telfhash',
                    'tlsh', 'uri', 'url', 'user-agent', 'vhash',
                    'x509-fingerprint-md5', 'x509-fingerprint-sha1',
                    'x509-fingerprint-sha256'
                ),
                '_attribute_from_simple_pattern'
            ),
            **dict.fromkeys(
                (
                    'filename|authentihash', 'filename|imphash',
                    'filename|impfuzzy', 'filename|md5', 'filename|pehash',
                    'filename|sha1', 'filename|sha224', 'filename|sha256',
                    'filename|sha384', 'filename|sha512', 'filename|sha512/224',
                    'filename|sha512/256', 'filename|sha3-224',
                    'filename|sha3-256', 'filename|sha3-384',
                    'filename|sha3-512', 'filename|ssdeep', 'filename|tlsh',
                    'filename|vhash'
                ),
                '_attribute_from_filename_hash'
            ),
            **dict.fromkeys(
                (
                    'domain|ip', 'hostname|port', 'regkey|value'
                ),
                '_attribute_from_double_pattern'
            ),
            **dict.fromkeys(
                (
                    'github-username', 'ip-src', 'ip-dst'
                ),
                '_attribute_from_dual_pattern'
            ),
            **dict.fromkeys(
                (
                    'ip-src|port', 'ip-dst|port'
                ),
                '_attribute_from_ip_port'
            ),
            **dict.fromkeys(
                (
                    'sigma', 'snort', 'yara'
                ),
                '_attribute_from_patterning_language'
            )
        }
    )

    # OBJECT ATTRIBUTES MAPPING
    __image_attribute = {'type': 'filename', 'object_relation': 'image'}
    __parent_image_attribute = {'type': 'filename', 'object_relation': 'parent-image'}

    # OBJECTS MAPPING
    __email_pattern_mapping = Mapping(
        **{
            'additional_header_fields.reply_to': STIX2Mapping.reply_to_attribute(),
            'additional_header_fields.x_mailer': STIX2Mapping.x_mailer_attribute(),
            'bcc_refs': {
                'display_name': {
                    'type': 'email-dst-display-name',
                    'object_relation': 'bcc-display-name'
                },
                'value': {'type': 'email-dst', 'object_relation': 'bcc'}
            },
            'cc_refs': {
                'display_name': {
                    'type': 'email-dst-display-name',
                    'object_relation': 'cc-display-name'
                },
                'value': {'type': 'email-dst', 'object_relation': 'cc'}
            },
            'from_ref.display_name': {
                'type': 'email-src-display-name',
                'object_relation': 'from-display-name'
            },
            'from_ref.value': {'type': 'email-src', 'object_relation': 'from'},
            'to_refs': {
                'display_name': {
                    'type': 'email-dst-display-name',
                    'object_relation': 'to-display-name'
                },
                'value': {'type': 'email-dst', 'object_relation': 'to'}
            },
            **InternalSTIX2Mapping.email_object_mapping()
        }
    )
    __file_pattern_mapping = Mapping(
        **{
            'hashes.AUTHENTIHASH': InternalSTIX2Mapping.authentihash_attribute(),
            'hashes.IMPHASH': STIX2Mapping.imphash_attribute(),
            'hashes.MD5': STIX2Mapping.md5_attribute(),
            'hashes.SHA1': STIX2Mapping.sha1_attribute(),
            'hashes.SHA224': InternalSTIX2Mapping.sha224_attribute(),
            'hashes.SHA256': STIX2Mapping.sha256_attribute(),
            'hashes.SHA3224': InternalSTIX2Mapping.sha3_224_attribute(),
            'hashes.SHA3256': STIX2Mapping.sha3_256_attribute(),
            'hashes.SHA3384': InternalSTIX2Mapping.sha3_384_attribute(),
            'hashes.SHA3512': STIX2Mapping.sha3_512_attribute(),
            'hashes.SHA384': InternalSTIX2Mapping.sha384_attribute(),
            'hashes.SHA512': STIX2Mapping.sha512_attribute(),
            'hashes.SSDEEP': STIX2Mapping.ssdeep_attribute(),
            'hashes.TELFHASH': InternalSTIX2Mapping.telfhash_attribute(),
            'hashes.TLSH': STIX2Mapping.tlsh_attribute(),
            'hashes.VHASH': InternalSTIX2Mapping.vhash_attribute(),
            'parent_directory_ref.path': STIX2Mapping.path_attribute(),
            **InternalSTIX2Mapping.file_object_mapping()
        }
    )
    __http_ext = "extensions.'http-request-ext'"
    __header_ext = f'{__http_ext}.request_header'
    __http_request_pattern_mapping = Mapping(
        **{
            f"{__http_ext}.request_method": STIX2Mapping.method_attribute(),
            f"{__header_ext}.'Content-Type'": STIX2Mapping.content_type_attribute(),
            f"{__header_ext}.'Cookie'": STIX2Mapping.cookie_attribute(),
            f"{__header_ext}.'Referer'": STIX2Mapping.referer_attribute(),
            f"{__header_ext}.'User-Agent'": STIX2Mapping.user_agent_attribute(),
            **InternalSTIX2Mapping.http_request_object_mapping()
        }
    )
    __image_pattern_mapping = Mapping(
        **{
            'content_ref.url': STIX2Mapping.url_attribute(),
            'content_ref.x_misp_url': STIX2Mapping.url_attribute(),
            **InternalSTIX2Mapping.image_object_mapping()
        }
    )
    __lnk_pattern_mapping = Mapping(
        **{
            'hashes.MD5': STIX2Mapping.md5_attribute(),
            'hashes.SHA1': STIX2Mapping.sha1_attribute(),
            'hashes.SHA224': InternalSTIX2Mapping.sha224_attribute(),
            'hashes.SHA256': STIX2Mapping.sha256_attribute(),
            'hashes.SHA384': InternalSTIX2Mapping.sha384_attribute(),
            'hashes.SHA512': STIX2Mapping.sha512_attribute(),
            'hashes.SSDEEP': STIX2Mapping.ssdeep_attribute(),
            'hashes.TLSH': STIX2Mapping.tlsh_attribute(),
            'parent_directory_ref.path': STIX2Mapping.path_attribute(),
            **InternalSTIX2Mapping.lnk_object_mapping()
        }
    )
    __netflow_pattern_mapping = Mapping(
        **{
            'protocols[0]': InternalSTIX2Mapping.protocol_attribute(),
            "extensions.'icmp-ext'.icmp_type_hex": InternalSTIX2Mapping.icmp_type_attribute(),
            "extensions.'tcp-ext'.src_flags_hex": InternalSTIX2Mapping.tcp_flags_attribute(),
            **InternalSTIX2Mapping.netflow_object_mapping()
        }
    )
    __process_pattern_mapping = Mapping(
        **{
            'binary_ref.name': __image_attribute,
            'image_ref.name': __image_attribute,
            'parent_ref.command_line': InternalSTIX2Mapping.parent_command_line_attribute(),
            'parent_ref.name': InternalSTIX2Mapping.parent_process_name_attribute(),
            'parent_ref.pid': InternalSTIX2Mapping.parent_pid_attribute(),
            'parent_ref.binary_ref.name': __parent_image_attribute,
            'parent_ref.image_ref.name': __parent_image_attribute,
            'parent_ref.x_misp_guid': InternalSTIX2Mapping.parent_guid_attribute(),
            'parent_ref.x_misp_process_name': InternalSTIX2Mapping.parent_process_name_attribute(),
            'parent_ref.x_misp_process_path': InternalSTIX2Mapping.parent_process_path_attribute(),
            **InternalSTIX2Mapping.process_object_mapping()
        }
    )
    __sigma_object_mapping = Mapping(
        pattern=STIX2Mapping.sigma_attribute(),
        description=STIX2Mapping.comment_attribute(),
        name=STIX2Mapping.sigma_rule_name_attribute(),
        x_misp_context={'type': 'text', 'object_relation': 'context'}
    )
    __x509_pattern_mapping = Mapping(
        **{
            'hashes.MD5': STIX2Mapping.x509_md5_attribute(),
            'hashes.SHA1': STIX2Mapping.x509_sha1_attribute(),
            'hashes.SHA256': STIX2Mapping.x509_sha256_attribute(),
            **InternalSTIX2Mapping.x509_object_mapping()
        }
    )
    __yara_object_mapping = Mapping(
        pattern=STIX2Mapping.yara_attribute(),
        description=STIX2Mapping.comment_attribute(),
        name=STIX2Mapping.yara_rule_name_attribute(),
        pattern_version=STIX2Mapping.version_attribute(),
        x_misp_context={'type': 'text', 'object_relation': 'context'}
    )

    @classmethod
    def android_app_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.android_app_object_mapping().get(field)

    @classmethod
    def asn_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.asn_object_mapping().get(field)

    @classmethod
    def attributes_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__attributes_mapping.get(field)

    @classmethod
    def cpe_asset_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.cpe_asset_object_mapping().get(field)

    @classmethod
    def credential_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.credential_object_mapping().get(field)

    @classmethod
    def domain_ip_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.domain_ip_object_mapping().get(field)

    @classmethod
    def email_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__email_pattern_mapping.get(field)

    @classmethod
    def facebook_account_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.facebook_account_object_mapping().get(field)

    @classmethod
    def file_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__file_pattern_mapping.get(field)

    @classmethod
    def github_user_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.github_user_object_mapping().get(field)

    @classmethod
    def gitlab_user_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.gitlab_user_object_mapping().get(field)

    @classmethod
    def http_request_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__http_request_pattern_mapping.get(field)

    @classmethod
    def image_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__image_pattern_mapping.get(field)

    @classmethod
    def ip_port_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.ip_port_object_mapping().get(field)

    @classmethod
    def lnk_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__lnk_pattern_mapping.get(field)

    @classmethod
    def mutex_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.mutex_object_mapping().get(field)

    @classmethod
    def netflow_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__netflow_pattern_mapping.get(field)

    @classmethod
    def network_connection_pattern_mapping(
            cls, field: str) -> Union[dict, None]:
        return cls.network_connection_object_mapping().get(field)

    @classmethod
    def network_socket_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.network_socket_object_mapping().get(field)

    @classmethod
    def parler_account_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.parler_account_object_mapping().get(field)

    @classmethod
    def pe_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.pe_object_mapping().get(field)

    @classmethod
    def pe_section_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.pe_section_object_mapping().get(field)

    @classmethod
    def process_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__process_pattern_mapping.get(field)

    @classmethod
    def reddit_account_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.reddit_account_object_mapping().get(field)

    @classmethod
    def registry_key_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.registry_key_object_mapping().get(field)

    @classmethod
    def registry_key_values_pattern_mapping(
            cls, field: str) -> Union[dict, None]:
        return cls.registry_key_values_mapping().get(field)

    @classmethod
    def sigma_object_mapping(cls) -> dict:
        return cls.__sigma_object_mapping

    @classmethod
    def telegram_account_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.telegram_account_object_mapping().get(field)

    @classmethod
    def twitter_account_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.twitter_account_object_mapping().get(field)

    @classmethod
    def unix_user_account_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.unix_user_account_extention_mapping().get(field)

    @classmethod
    def url_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.url_object_mapping().get(field)

    @classmethod
    def user_account_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.user_account_object_mapping().get(field)

    @classmethod
    def x509_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__x509_pattern_mapping.get(field)

    @classmethod
    def yara_object_mapping(cls) -> dict:
        return cls.__yara_object_mapping


class InternalSTIX2IndicatorConverter(
        STIX2IndicatorConverter, InternalSTIX2Converter):
    def __init__(self, main: 'InternalSTIX2toMISPParser'):
        super().__init__(main)
        self._mapping = InternalSTIX2IndicatorMapping

    def parse(self, indicator_ref: str):
        indicator = self.main_parser._get_stix_object(indicator_ref)
        feature = self._handle_mapping_from_labels(
            indicator.labels, indicator.id
        )
        try:
            parser = getattr(self, f"{feature}_indicator")
        except AttributeError:
            raise UnknownParsingFunctionError(f"{feature}_indicator")
        # try:
        parser(indicator)
        # except AttributeFromPatternParsingError as error:
        #     self.main_parser._attribute_from_pattern_parsing_error(error)
        # except Exception as exception:
        #     self.main_parser._indicator_error(indicator.id, exception)

    ############################################################################
    #                        ATTRIBUTES PARSING METHODS                        #
    ############################################################################

    def _attribute_from_AS_indicator(self, indicator: _INDICATOR_TYPING):
        attribute = self._create_attribute_dict(indicator)
        attribute['value'] = self._parse_AS_value(
            self._extract_value_from_pattern(indicator.pattern[1:-1])
        )
        self.main_parser._add_misp_attribute(attribute, indicator)

    def _attribute_from_attachment_indicator(
            self, indicator: _INDICATOR_TYPING):
        attribute = self._create_attribute_dict(indicator)
        pattern = indicator.pattern[1:-1]
        if ' AND ' in pattern:
            pattern, data_pattern = pattern.split(' AND ')
            attribute['data'] = self._extract_value_from_pattern(
                data_pattern
            )
        attribute['value'] = self._extract_value_from_pattern(pattern)
        self.main_parser._add_misp_attribute(attribute, indicator)

    def _attribute_from_double_pattern_indicator(
            self, indicator: _INDICATOR_TYPING):
        attribute = self._create_attribute_dict(indicator)
        domain_pattern, pattern = indicator.pattern[1:-1].split(' AND ')
        domain_value = self._extract_value_from_pattern(
            domain_pattern
        )
        value = self._extract_value_from_pattern(pattern)
        attribute['value'] = f'{domain_value}|{value}'
        self.main_parser._add_misp_attribute(attribute, indicator)

    def _attribute_from_dual_pattern_indicator(
            self, indicator: _INDICATOR_TYPING):
        attribute = self._create_attribute_dict(indicator)
        pattern = indicator.pattern[1:-1].split(' AND ')[1]
        attribute['value'] = self._extract_value_from_pattern(pattern)
        self.main_parser._add_misp_attribute(attribute, indicator)

    def _attribute_from_filename_hash_indicator(
            self, indicator: _INDICATOR_TYPING):
        attribute = self._create_attribute_dict(indicator)
        for pattern in indicator.pattern[1:-1].split(' AND '):
            if 'file:name = ' in pattern:
                filename = self._extract_value_from_pattern(pattern)
            elif 'file:hashes.' in pattern:
                hash_value = self._extract_value_from_pattern(pattern)
        try:
            attribute['value'] = f"{filename}|{hash_value}"
        except NameError:
            raise AttributeFromPatternParsingError(indicator.id)
        self.main_parser._add_misp_attribute(attribute, indicator)

    def _attribute_from_ip_port_indicator(self, indicator: _INDICATOR_TYPING):
        attribute = self._create_attribute_dict(indicator)
        values = [
            self._extract_value_from_pattern(pattern) for pattern
            in indicator.pattern[1:-1].split(' AND ')[1:]
        ]
        attribute['value'] = '|'.join(values)
        self.main_parser._add_misp_attribute(attribute, indicator)

    def _attribute_from_malware_sample_indicator(
            self, indicator: _INDICATOR_TYPING):
        attribute = self._create_attribute_dict(indicator)
        pattern = indicator.pattern[1:-1]
        filename_pattern, md5_pattern, *pattern = pattern.split(' AND ')
        filename_value = self._extract_value_from_pattern(
            filename_pattern
        )
        md5_value = self._extract_value_from_pattern(md5_pattern)
        attribute['value'] = f'{filename_value}|{md5_value}'
        if pattern:
            attribute['data'] = self._extract_value_from_pattern(
                pattern[0]
            )
        self.main_parser._add_misp_attribute(attribute, indicator)

    def _attribute_from_patterning_language_indicator(
            self, indicator: Indicator):
        attribute = self._create_attribute_dict(indicator)
        attribute['value'] = indicator.pattern
        self.main_parser._add_misp_attribute(attribute, indicator)

    def _attribute_from_simple_pattern_indicator(
            self, indicator: _INDICATOR_TYPING):
        attribute = self._create_attribute_dict(indicator)
        attribute['value'] = self._extract_value_from_pattern(
            indicator.pattern[1:-1]
        )
        self.main_parser._add_misp_attribute(attribute, indicator)

    ############################################################################
    #                       MISP OBJECTS PARSING METHODS                       #
    ############################################################################

    def _object_from_account_indicator(
            self, indicator: _INDICATOR_TYPING, name: str):
        misp_object = self._create_misp_object(name, indicator)
        mapping = getattr(
            self._mapping, f"{name.replace('-', '_')}_pattern_mapping"
        )
        for pattern in indicator.pattern[1:-1].split(' AND '):
            key, value = self._extract_features_from_pattern(pattern)
            if key == 'account_type':
                continue
            misp_object.add_attribute(**{'value': value, **mapping(key)})
        self.main_parser._add_misp_object(misp_object, indicator)

    def _object_from_account_with_attachment_indicator(
            self, indicator: _INDICATOR_TYPING, name: str):
        misp_object = self._create_misp_object(name, indicator)
        mapping = getattr(
            self._mapping, f"{name.replace('-', '_')}_pattern_mapping"
        )
        attachments: defaultdict = defaultdict(dict)
        for pattern in indicator.pattern[1:-1].split(' AND '):
            key, value = self._extract_features_from_pattern(pattern)
            if key == 'account_type':
                continue
            if key.startswith('x_misp_') and '.' in key:
                feature, key = key.split('.')
                attachments[feature][key] = value
            else:
                misp_object.add_attribute(**{'value': value, **mapping(key)})
        if attachments:
            for feature, attribute in attachments.items():
                attribute.update(mapping(feature))
                misp_object.add_attribute(**attribute)
        self.main_parser._add_misp_object(misp_object, indicator)

    def _object_from_android_app_indicator(self, indicator: _INDICATOR_TYPING):
        self._object_from_standard_pattern(indicator, 'android-app')

    def _object_from_asn_indicator(self, indicator: _INDICATOR_TYPING):
        misp_object = self._create_misp_object('asn', indicator)
        for pattern in indicator.pattern[1:-1].split(' AND '):
            feature, value = self._extract_features_from_pattern(pattern)
            if feature == 'number':
                value = self._parse_AS_value(value)
            misp_object.add_attribute(
                **{
                    'value': value,
                    **self._mapping.asn_pattern_mapping(feature)
                }
            )
        self.main_parser._add_misp_object(misp_object, indicator)

    def _object_from_cpe_asset_indicator(self, indicator: _INDICATOR_TYPING):
        self._object_from_standard_pattern(indicator, 'cpe-asset')

    def _object_from_credential_indicator(self, indicator: _INDICATOR_TYPING):
        self._object_from_standard_pattern(indicator, 'credential')

    def _object_from_domain_ip_indicator(self, indicator: _INDICATOR_TYPING):
        misp_object = self._create_misp_object('domain-ip', indicator)
        for pattern in indicator.pattern[1:-1].split(' AND '):
            feature, value = self._extract_features_from_pattern(pattern)
            if 'resolves_to_refs' in feature:
                misp_object.add_attribute(
                    **{'value': value, **self._mapping.ip_attribute()}
                )
            else:
                misp_object.add_attribute(
                    **{
                        'value': value,
                        **self._mapping.domain_ip_pattern_mapping(feature)
                    }
                )
        self.main_parser._add_misp_object(misp_object, indicator)

    def _object_from_email_indicator(self, indicator: _INDICATOR_TYPING):
        misp_object = self._create_misp_object('email', indicator)
        mapping = self._mapping.email_pattern_mapping
        attachments: defaultdict = defaultdict(dict)
        for pattern in indicator.pattern[1:-1].split(' AND '):
            field, value = self._extract_features_from_pattern(pattern)
            if 'body_multipart[' in field:
                index = field[15]
                if field.split('.')[1] == 'content_disposition':
                    attachments[index]['object_relation'] = value
                else:
                    key = 'value' if field.split('.')[-1] == 'name' else 'data'
                    attachments[index][key] = value
                continue
            if '_refs[' in field:
                ref_type = field.split('[')[0]
                misp_object.add_attribute(
                    **{
                        'value': value,
                        **mapping(ref_type)[field.split('.')[-1]]
                    }
                )
                continue
            misp_object.add_attribute(**{'value': value, **mapping(field)})
        if attachments:
            for attribute in attachments.values():
                attribute['type'] = 'attachment'
                misp_object.add_attribute(**attribute)
        self.main_parser._add_misp_object(misp_object, indicator)

    def _object_from_file_extension_pattern(
            self, extension: dict, indicator: _INDICATOR_TYPING) -> str:
        pe_object = self._create_misp_object('pe')
        pe_object.from_dict(**self._parse_timeline(indicator))
        if 'address_of_entry_point' in extension['pe']:
            pe_object.add_attribute(
                **{
                    'value': extension['pe'].pop('address_of_entry_point'),
                    **self._mapping.entrypoint_address_attribute()
                }
            )
        for feature, value in extension['pe'].items():
            pe_object.add_attribute(
                **{'value': value, **self._mapping.pe_pattern_mapping(feature)}
            )
        misp_object = self.main_parser._add_misp_object(pe_object, indicator)
        for section in extension.get('sections').values():
            section_object = self._create_misp_object('pe-section')
            section_object.from_dict(**self._parse_timeline(indicator))
            for feature, value in section.items():
                attribute = self._mapping.pe_section_pattern_mapping(feature)
                if attribute is not None:
                    section_object.add_attribute(
                        **{'value': value, **attribute}
                    )
                    continue
                section_object.add_attribute(
                    **{
                        'value': value,
                        **self._mapping.file_hashes_mapping(feature)
                    }
                )
            self.main_parser._add_misp_object(section_object, indicator)
            misp_object.add_reference(section_object.uuid, 'includes')
        return misp_object.uuid

    def _object_from_file_indicator(self, indicator: _INDICATOR_TYPING):
        file_object = self._create_misp_object('file', indicator)
        attachment: dict
        attachments: list = []
        extension: defaultdict = defaultdict(lambda: defaultdict(dict))
        in_attachment: bool = False
        for pattern in indicator.pattern[1:-1].split(' AND '):
            feature, value = self._extract_features_from_pattern(pattern)
            if "extensions.'windows-pebinary-ext'." in feature:
                if '.sections[' in feature:
                    parsed = feature.split('.')[2:]
                    extension['sections'][parsed[0][-2]][parsed[-1]] = value
                else:
                    extension['pe'][feature.split('.')[-1]] = value
                continue
            if pattern.startswith('('):
                attachment = {feature: value}
                in_attachment = True
                continue
            if value.endswith("')"):
                attachment[feature] = value[:-2]
                attachments.append(attachment)
                in_attachment = False
                continue
            if in_attachment:
                attachment[feature] = value
            else:
                file_object.add_attribute(
                    **{
                        'value': value,
                        **self._mapping.file_pattern_mapping(feature)
                    }
                )
        if attachments:
            for attachment in attachments:
                attribute = {'value': attachment['content_ref.x_misp_filename']}
                if 'content_ref.payload_bin' in attachment:
                    attribute['data'] = attachment['content_ref.payload_bin']
                if 'content_ref.hashes.MD5' in attachment:
                    attribute.update(
                        {
                            'type': 'malware-sample',
                            'object_relation': 'malware-sample',
                            'value': f"{attribute['value']}|"
                                     f"{attachment['content_ref.hashes.MD5']}"
                        }
                    )
                else:
                    attribute.update(
                        {
                            'type': 'attachment',
                            'object_relation': 'attachment'
                        }
                    )
                file_object.add_attribute(**attribute)
        misp_object = self.main_parser._add_misp_object(file_object, indicator)
        if extension:
            pe_uuid = self._object_from_file_extension_pattern(
                extension, indicator
            )
            misp_object.add_reference(pe_uuid, 'includes')

    def _object_from_facebook_account_indicator(
            self, indicator: _INDICATOR_TYPING):
        self._object_from_account_with_attachment_indicator(
            indicator, 'facebook-account'
        )

    def _object_from_github_user_indicator(self, indicator: _INDICATOR_TYPING):
        self._object_from_account_with_attachment_indicator(
            indicator, 'github-user'
        )

    def _object_from_gitlab_user_indicator(self, indicator: _INDICATOR_TYPING):
        self._object_from_account_indicator(indicator, 'gitlab-user')

    def _object_from_http_request_indicator(self, indicator: _INDICATOR_TYPING):
        misp_object = self._create_misp_object('http-request', indicator)
        reference: dict
        request_values = []
        request_value = "extensions.'http-request-ext'.request_value"
        for pattern in indicator.pattern[1:-1].split(' AND '):
            feature, value = self._extract_features_from_pattern(pattern)
            if pattern.startswith('('):
                reference = dict(
                    self._parse_http_request_reference(feature, value)
                )
                continue
            if pattern.endswith(')'):
                reference.update(
                    self._parse_http_request_reference(feature, value)
                )
                misp_object.add_attribute(**reference)
                continue
            if feature == request_value:
                request_values.append(value)
                continue
            misp_object.add_attribute(
                **{
                    'value': value,
                    **self._mapping.http_request_pattern_mapping(feature)
                }
            )
        if request_values:
            if len(request_values) == 1:
                misp_object.add_attribute(
                    **{
                        'value': request_values[0],
                        **self._mapping.uri_attribute()
                    }
                )
            else:
                self._parse_http_request_values(
                    misp_object, *self._get_contained_value(*request_values)
                )
        self.main_parser._add_misp_object(misp_object, indicator)

    def _object_from_image_indicator(self, indicator: _INDICATOR_TYPING):
        misp_object = self._create_misp_object('image', indicator)
        attachment = {'type': 'attachment', 'object_relation': 'attachment'}
        for pattern in indicator.pattern[1:-1].split(' AND '):
            feature, value = self._extract_features_from_pattern(pattern)
            if feature == 'content_ref.mime_type':
                continue
            if 'payload_bin' in feature:
                attachment['data'] = value
                continue
            if 'x_misp_filename' in feature:
                attachment['value'] = value
                continue
            misp_object.add_attribute(
                **{
                    'value': value,
                    **self._mapping.image_pattern_mapping(feature)
                }
            )
        if 'data' in attachment or 'value' in attachment:
            misp_object.add_attribute(**attachment)
        self.main_parser._add_misp_object(misp_object, indicator)

    def _object_from_ip_port_indicator(self, indicator: _INDICATOR_TYPING):
        misp_object = self._create_misp_object('ip-port', indicator)
        reference: dict
        for pattern in indicator.pattern[1:-1].split(' AND '):
            feature, value = self._extract_features_from_pattern(pattern)
            if pattern.startswith('('):
                reference = self._parse_ip_port_reference(feature, value)
                continue
            if pattern.endswith(')'):
                reference.update(
                    self._parse_ip_port_reference(feature, value[:-2])
                )
                misp_object.add_attribute(**reference)
                continue
            if 'protocol' in feature:
                misp_object.add_attribute(
                    **{'value': value, **self._mapping.protocol_attribute()}
                )
                continue
            misp_object.add_attribute(
                **{
                    'value': value,
                    **self._mapping.ip_port_pattern_mapping(feature)
                }
            )
        self.main_parser._add_misp_object(misp_object, indicator)

    def _object_from_lnk_indicator(self, indicator: _INDICATOR_TYPING):
        misp_object = self._create_misp_object('lnk', indicator)
        attachment: dict = {}
        for pattern in indicator.pattern[1:-1].split(' AND '):
            feature, value = self._extract_features_from_pattern(pattern)
            if 'content_ref.' in feature:
                attachment[feature.split('.')[-1]] = value
                continue
            misp_object.add_attribute(
                **{'value': value, **self._mapping.lnk_pattern_mapping(feature)}
            )
        if attachment:
            attribute = {
                'type': 'malware-sample',
                'object_relation': 'malware-sample',
                'value': f"{attachment['x_misp_filename']}|{attachment['MD5']}"
            }
            if 'payload_bin' in attachment:
                attribute['data'] = attachment['payload_bin']
            misp_object.add_attribute(**attribute)
        self.main_parser._add_misp_object(misp_object, indicator)

    def _object_from_mutex_indicator(self, indicator: _INDICATOR_TYPING):
        self._object_from_standard_pattern(indicator, 'mutex')

    def _object_from_netflow_indicator(self, indicator: _INDICATOR_TYPING):
        misp_object = self._create_misp_object('netflow', indicator)
        reference: dict
        for pattern in indicator.pattern[1:-1].split(' AND '):
            feature, value = self._extract_features_from_pattern(pattern)
            if 'src_ref.' in feature or 'dst_ref.' in feature:
                if pattern.startswith('('):
                    reference = defaultdict(dict)
                elif pattern.endswith(')'):
                    self._parse_netflow_reference(
                        reference, feature, value[:-2]
                    )
                    for attribute in reference.values():
                        misp_object.add_attribute(**attribute)
                    continue
                self._parse_netflow_reference(reference, feature, value)
                continue
            misp_object.add_attribute(
                **{
                    'value': value.upper() if 'protocols' in feature else value,
                    **self._mapping.netflow_pattern_mapping(feature)
                }
            )
        self.main_parser._add_misp_object(misp_object, indicator)

    def _object_from_network_connection_indicator(
            self, indicator: _INDICATOR_TYPING):
        self._object_from_network_traffic_indicator(
            'network-connection', indicator
        )

    def _object_from_network_socket_indicator(
            self, indicator: _INDICATOR_TYPING):
        self._object_from_network_traffic_indicator(
            'network-socket', indicator
        )

    def _object_from_network_traffic_indicator(
            self, name: str, indicator: _INDICATOR_TYPING):
        misp_object = self._create_misp_object(name, indicator)
        name = name.replace('-', '_')
        mapping = getattr(self._mapping, f'{name}_pattern_mapping')
        reference: dict
        for pattern in indicator.pattern[1:-1].split(' AND '):
            feature, value = self._extract_features_from_pattern(pattern)
            if pattern.startswith('('):
                reference = dict(self._parse_network_reference(feature, value))
                continue
            if pattern.endswith(')'):
                reference.update(
                    self._parse_network_reference(feature, value[:-2])
                )
                misp_object.add_attribute(**reference)
                continue
            attribute = mapping(feature)
            if attribute is not None:
                misp_object.add_attribute(**{'value': value, **attribute})
            else:
                getattr(self, f'_parse_{name}_pattern')(
                    misp_object, feature, value
                )
        self.main_parser._add_misp_object(misp_object, indicator)

    def _object_from_parler_account_indicator(
            self, indicator: _INDICATOR_TYPING):
        self._object_from_account_with_attachment_indicator(
            indicator, 'parler-account'
        )

    def _object_from_patterning_language_indicator(self, indicator: Indicator):
        name = (
            'suricata' if indicator.pattern_type == 'snort'
            else indicator.pattern_type
        )
        misp_object = self._create_misp_object(name, indicator)
        mapping = getattr(self._mapping, f'{name}_object_mapping')
        for key, attribute in mapping().items():
            if hasattr(indicator, key):
                self.main_parser._populate_object_attributes(
                    misp_object, attribute, getattr(indicator, key)
                )
        if hasattr(indicator, 'external_references') and \
                name in ('sigma', 'suricata'):
            for reference in indicator.external_references:
                attribute = {
                    'value': reference.url,
                    **getattr(self._mapping, f'{name}_reference_attribute')()
                }
                if hasattr(reference, 'description'):
                    attribute['comment'] = reference.description
                misp_object.add_attribute(**attribute)
        self.main_parser._add_misp_object(misp_object, indicator)

    def _object_from_process_indicator(self, indicator: _INDICATOR_TYPING):
        misp_object = self._create_misp_object('process', indicator)
        for pattern in indicator.pattern[1:-1].split(' AND '):
            feature, value = self._extract_features_from_pattern(pattern)
            if 'child_refs' in feature:
                misp_object.add_attribute(
                    **{
                        'type': 'text',
                        'object_relation': 'child-pid',
                        'value': value
                    }
                )
                continue
            misp_object.add_attribute(
                **{
                    'value': value,
                    **self._mapping.process_pattern_mapping(feature)
                }
            )
        self.main_parser._add_misp_object(misp_object, indicator)

    def _object_from_reddit_account_indicator(
            self, indicator: _INDICATOR_TYPING):
        self._object_from_account_with_attachment_indicator(
            indicator, 'reddit-account'
        )

    def _object_from_registry_key_indicator(self, indicator: _INDICATOR_TYPING):
        misp_object = self._create_misp_object('registry-key', indicator)
        for pattern in indicator.pattern[1:-1].split(' AND '):
            feature, value = self._extract_features_from_pattern(pattern)
            if 'values[0].' in feature:
                misp_object.add_attribute(
                    **{
                        'value': value,
                        **self._mapping.registry_key_values_pattern_mapping(
                            feature.split('.')[-1]
                        )
                    }
                )
                continue
            misp_object.add_attribute(
                **{
                    'value': value,
                    **self._mapping.registry_key_pattern_mapping(feature)
                }
            )
        self.main_parser._add_misp_object(misp_object, indicator)

    def _object_from_standard_pattern(
            self, indicator: _INDICATOR_TYPING, name: str):
        misp_object = self._create_misp_object(name, indicator)
        mapping = getattr(
            self._mapping, f"{name.replace('-', '_')}_pattern_mapping"
        )
        for pattern in indicator.pattern[1:-1].split(' AND '):
            feature, value = self._extract_features_from_pattern(pattern)
            misp_object.add_attribute(**{'value': value, **mapping(feature)})
        self.main_parser._add_misp_object(misp_object, indicator)

    def _object_from_telegram_account_indicator(
            self, indicator: _INDICATOR_TYPING):
        self._object_from_account_indicator(indicator, 'telegram-account')

    def _object_from_twitter_account_indicator(
            self, indicator: _INDICATOR_TYPING):
        self._object_from_account_with_attachment_indicator(
            indicator, 'twitter-account'
        )

    def _object_from_url_indicator(self, indicator: _INDICATOR_TYPING):
        self._object_from_standard_pattern(indicator, 'url')

    def _object_from_user_account_indicator(self, indicator: _INDICATOR_TYPING):
        misp_object = self._create_misp_object('user-account', indicator)
        attachments: defaultdict = defaultdict(dict)
        for pattern in indicator.pattern[1:-1].split(' AND '):
            feature, value = self._extract_features_from_pattern(pattern)
            if feature.startswith('x_misp_') and '.' in feature:
                key, feature = feature.split('.')
                attachments[key][feature] = value
                continue
            if 'unix-account-ext' in feature:
                misp_object.add_attribute(
                    **{
                        'value': value,
                        **self._mapping.unix_user_account_pattern_mapping(
                            feature.split('.')[-1]
                        )
                    }
                )
                continue
            misp_object.add_attribute(
                **{
                    'value': value,
                    **self._mapping.user_account_pattern_mapping(feature)
                }
            )
        if attachments:
            for feature, attribute in attachments.items():
                attribute.update(
                    self._mapping.user_account_pattern_mapping(feature)
                )
                misp_object.add_attribute(**attribute)
        self.main_parser._add_misp_object(misp_object, indicator)

    def _object_from_x509_indicator(self, indicator: _INDICATOR_TYPING):
        misp_object = self._create_misp_object('x509', indicator)
        for pattern in indicator.pattern[1:-1].split(' AND '):
            feature, value = self._extract_features_from_pattern(pattern)
            if 'subject_alternative_name' in feature:
                for values in value.split(','):
                    key, value = values.split('=')
                    misp_object.add_attribute(
                        **{
                            'value': value,
                            **self._mapping.x509_subject_mapping(key)
                        }
                    )
                continue
            misp_object.add_attribute(
                **{
                    'value': value,
                    **self._mapping.x509_pattern_mapping(feature)
                }
            )
        self.main_parser._add_misp_object(misp_object, indicator)

    def _parse_http_request_reference(self, feature: str, value: str) -> dict:
        if feature.split('.')[1] == 'value':
            return {'value': value}
        if value == 'domain-name':
            return self._mapping.host_attribute()
        return getattr(self._mapping, f"ip_{feature.split('_')[0]}_attribute")()

    def _parse_http_request_values(
            self, misp_object: MISPObject, uri: str, url: str):
        uri_attribute = {'value': uri}
        uri_attribute.update(self._mapping.uri_attribute())
        misp_object.add_attribute(**uri_attribute)
        url_attribute = {'value': url}
        url_attribute.update(self._mapping.url_attribute())
        misp_object.add_attribute(**url_attribute)
    
    def _parse_netflow_reference(
            self, reference: dict, feature: str, value: str):
        ref_type = feature.split('_')[0]
        if '_ref.type' in feature:
            relation = f'ip-{ref_type}'
            reference[relation].update(
                {'type': relation, 'object_relation': relation}
            )
        elif '_ref.value' in feature:
            reference[f'ip-{ref_type}']['value'] = value
        else:
            reference[f'{ref_type}-as'] = {
                'value': value,
                **getattr(self._mapping, f'{ref_type}_as_attribute')()
            }

    def _parse_network_connection_pattern(
            self, misp_object: MISPObject, feature: str, value: str):
        if 'protocols' in feature:
            protocol = value.upper()
            layer = self._mapping.connection_protocols(protocol)
            misp_object.add_attribute(
                **{
                    'type': 'text',
                    'object_relation': f'layer{layer}-protocol',
                    'value': protocol
                }
            )

    def _parse_network_reference(self, feature: str, value: str) -> dict:
        if feature.split('.')[1] == 'value':
            return {'value': value}
        feature = feature.split('_')[0]
        if value == 'domain-name':
            return getattr(self._mapping, f'hostname_{feature}_attribute')()
        return getattr(self._mapping, f'ip_{feature}_attribute')()

    def _parse_network_socket_pattern(
            self, misp_object: MISPObject, feature: str, value: str):
        if 'protocols' in feature:
            protocol = value.upper()
            misp_object.add_attribute(
                **{
                    'type': 'text',
                    'object_relation': 'protocol',
                    'value': protocol
                }
            )
        elif "extensions.'socket-ext'" in feature:
            key = feature.split('.')[-1]
            if value in ('True', 'true', True):
                misp_object.add_attribute(
                    **{
                        'type': 'text',
                        'object_relation': 'state',
                        'value': key.split('_')[1]
                    }
                )
            else:
                misp_object.add_attribute(
                    **{
                        'value': value,
                        **self._mapping.socket_extension_pattern_mapping(key)
                    }
                )

    ############################################################################
    #                             UTILITY METHODS.                             #
    ############################################################################

    @staticmethod
    def _extract_value_from_pattern(pattern: str) -> str:
        return pattern.split(' = ')[1].strip("'")

    @staticmethod
    def _extract_features_from_pattern(pattern: str) -> Tuple[str]:
        identifier, value = pattern.split(' = ')
        return identifier.split(':')[1], value.strip("'")

    @staticmethod
    def _get_contained_value(first_value: str, second_value: str) -> Tuple[str]:
        if first_value in second_value:
            return first_value, second_value
        return second_value, first_value

    @staticmethod
    def _parse_ip_port_reference(feature: str, value: str) -> dict:
        if feature.split('.')[1] == 'value':
            return {'value': value}
        relation = (
            'domain' if value == 'domain-name'
            else f"ip-{feature.split('_')[0]}"
        )
        return {'type': relation, 'object_relation': relation}
