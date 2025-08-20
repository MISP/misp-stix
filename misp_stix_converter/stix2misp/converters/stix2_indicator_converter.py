#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ipaddress
import re
from ... import Mapping
from ..exceptions import (
    AttributeFromPatternParsingError, InvalidSTIXPatternError,
    UndefinedIndicatorError, UndefinedSTIXObjectError,
    UnknownParsingFunctionError, UnknownPatternMappingError,
    UnknownPatternTypeError)
from ..stix2_pattern_parser import STIX2PatternParser
from .stix2converter import (
    ExternalSTIX2Converter, InternalSTIX2Converter, STIX2Converter,
    _MAIN_PARSER_TYPING)
from .stix2mapping import (
    ExternalSTIX2Mapping, InternalSTIX2Mapping, STIX2Mapping)
from abc import ABCMeta
from collections import defaultdict
from pymisp import MISPObject
from stix2.v20.sdo import Indicator as Indicator_v20
from stix2.v21.sdo import Indicator as Indicator_v21
from stix2patterns.inspector import _PatternData as PatternData
from types import GeneratorType
from typing import TYPE_CHECKING, Tuple, Union

if TYPE_CHECKING:
    from ..external_stix2_to_misp import ExternalSTIX2toMISPParser
    from ..internal_stix2_to_misp import InternalSTIX2toMISPParser

_INDICATOR_TYPING = Union[Indicator_v20, Indicator_v21]


class STIX2IndicatorMapping(STIX2Mapping, metaclass=ABCMeta):
    # SINGLE ATTRIBUTES MAPPING
    __suricata_reference_attribute = Mapping(
        **{'type': 'link', 'object_relation': 'ref'}
    )

    # MISP OBJECTS MAPPING
    __sigma_object_mapping = Mapping(
        pattern=STIX2Mapping.sigma_attribute(),
        description=STIX2Mapping.comment_attribute(),
        name=STIX2Mapping.sigma_rule_name_attribute()
    )
    __suricata_object_mapping = Mapping(
        pattern=STIX2Mapping.snort_attribute(),
        description=STIX2Mapping.comment_attribute(),
        pattern_version=STIX2Mapping.version_attribute()
    )
    __yara_object_mapping = Mapping(
        pattern=STIX2Mapping.yara_attribute(),
        description=STIX2Mapping.comment_attribute(),
        name=STIX2Mapping.yara_rule_name_attribute(),
        pattern_version=STIX2Mapping.version_attribute()
    )

    @classmethod
    def network_connection_pattern_mapping(
            cls, field: str) -> Union[dict, None]:
        return cls.network_connection_object_mapping().get(field)

    @classmethod
    def pe_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.pe_object_mapping().get(field)

    @classmethod
    def pe_section_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.pe_section_object_mapping().get(field)

    @classmethod
    def registry_key_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.registry_key_object_mapping().get(field)

    @classmethod
    def sigma_object_mapping(cls) -> dict:
        return cls.__sigma_object_mapping

    @classmethod
    def socket_extension_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.network_socket_extension_mapping().get(field)

    @classmethod
    def suricata_object_mapping(cls) -> dict:
        return cls.__suricata_object_mapping

    @classmethod
    def suricata_reference_attribute(cls) -> dict:
        return cls.__suricata_reference_attribute

    @classmethod
    def yara_object_mapping(cls) -> dict:
        return cls.__yara_object_mapping


class STIX2IndicatorConverter(STIX2Converter, metaclass=ABCMeta):
    def __init__(self, main: _MAIN_PARSER_TYPING):
        self._set_main_parser(main)


class ExternalSTIX2IndicatorMapping(
        STIX2IndicatorMapping, ExternalSTIX2Mapping):
    __mac_address_pattern = '^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    __pattern_forbidden_relations = (
        ' < ',
        ' <= ',
        ' > ',
        ' >= ',
        ' FOLLOWEDBY ',
        ' ISSUBSET ',
        ' ISSUPERSET',
        ' MATCHES ',
        ' NOT ',
        ' REPEATS ',
        ' WITHIN '
    )
    __valid_pattern_assertions = ('=', 'IN', 'LIKE')

    # MAIN MAPPING
    __pattern_mapping = Mapping(
        **{
            'directory': 'directory',
            'email-addr': 'email_address',
            'email-message': 'email_message',
            'mac-addr': 'mac_address',
            'mutex': 'mutex',
            'network-traffic': 'network_traffic',
            'process': 'process',
            'software': 'software',
            'user-account': 'user_account',
            'windows-registry-key': 'registry_key',
            'x509-certificate': 'x509',
            **dict.fromkeys(
                (
                    'autonomous-system',
                    'autonomous-system_ipv4-addr',
                    'autonomous-system_ipv6-addr',
                    'autonomous-system_ipv4-addr_ipv6-addr'
                ),
                'asn'
            ),
            **dict.fromkeys(
                (
                    'domain-name',
                    'domain-name_ipv4-addr',
                    'domain-name_ipv6-addr',
                    'domain-name_ipv4-addr_ipv6-addr',
                    'domain-name_network-traffic'
                ),
                'domain_ip_port'
            ),
            **dict.fromkeys(
                (
                    'artifact_file',
                    'directory_file',
                    'file'
                ),
                'file'
            ),
            **dict.fromkeys(
                (
                    'ipv4-addr',
                    'ipv6-addr',
                    'ipv4-addr_ipv6-addr'
                ),
                'ip_address'
            ),
            **dict.fromkeys(
                (
                    'ipv4-addr_ipv6-addr_process',
                    'ipv4-addr_process',
                    'ipv6-addr_process',
                    'process'
                ),
                'process'
            ),
            **dict.fromkeys(
                (
                    'domain-name_ipv4-addr_url',
                    'domain-name_ipv6-addr_url',
                    'domain-name_ipv4-addr_ipv6-addr_url',
                    'domain-name_network-traffic_url',
                    'url'
                ),
                'url'
            )
        }
    )

    # MISP OBJECTS MAPPING
    __asn_pattern_mapping = Mapping(
        name=STIX2Mapping.description_attribute(),
        number=STIX2Mapping.asn_attribute()
    )
    __domain_ip_pattern_mapping = Mapping(
        **{
            'domain-name': STIX2Mapping.domain_attribute(),
            'ipv4-addr': STIX2Mapping.ip_attribute(),
            'ipv6-addr': STIX2Mapping.ip_attribute()
        }
    )
    __email_address_pattern_mapping = Mapping(
        **{
            'display_names': STIX2IndicatorMapping.to_display_name_attribute(),
            'value': STIX2IndicatorMapping.to_attribute()
        }
    )
    __email_message_mapping = Mapping(
        **{
            **STIX2Mapping.email_object_mapping(),
            'bcc_refs.display_name': STIX2Mapping.bcc_display_name_attribute(),
            'bcc_refs.value': STIX2Mapping.bcc_attribute(),
            'cc_refs.display_name': STIX2Mapping.cc_display_name_attribute(),
            'cc_refs.value': STIX2Mapping.cc_attribute(),
            'from_ref.display_name': STIX2Mapping.from_display_name_attribute(),
            'from_ref.value': STIX2Mapping.from_attribute(),
            'to_refs.display_name': STIX2Mapping.to_display_name_attribute(),
            'to_refs.value': STIX2Mapping.to_attribute()
        }
    )
    __process_pattern_mapping = Mapping(
        arguments=STIX2Mapping.args_attribute(),
        **ExternalSTIX2Mapping.process_object_mapping()
    )
    __software_pattern_mapping = Mapping(
        languages=STIX2Mapping.language_attribute(),
        **ExternalSTIX2Mapping.software_object_mapping()
    )
    __user_account_pattern_mapping = Mapping(
        **STIX2Mapping.unix_user_account_extension_object_mapping(),
        **STIX2Mapping.user_account_object_mapping()
    )
    __x509_pattern_mapping = Mapping(
        **{
            'hashes.MD5': STIX2Mapping.x509_md5_attribute(),
            'hashes.SHA1': STIX2Mapping.x509_sha1_attribute(),
            'hashes.SHA256': STIX2Mapping.x509_sha256_attribute(),
            **STIX2Mapping.x509_object_mapping()
        }
    )

    @classmethod
    def asn_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__asn_pattern_mapping.get(field)

    @classmethod
    def domain_ip_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__domain_ip_pattern_mapping.get(field)

    @classmethod
    def email_address_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__email_address_pattern_mapping.get(field)

    @classmethod
    def email_message_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__email_message_mapping.get(field)

    @classmethod
    def file_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.file_object_mapping().get(field)

    @classmethod
    def mac_address_pattern(cls) -> str:
        return cls.__mac_address_pattern

    @classmethod
    def network_socket_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.network_socket_object_mapping().get(field)

    @classmethod
    def pattern_forbidden_relations(cls) -> tuple:
        return cls.__pattern_forbidden_relations

    @classmethod
    def pattern_mapping(cls, field: str) -> Union[str, None]:
        return cls.__pattern_mapping.get(field)

    @classmethod
    def process_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__process_pattern_mapping.get(field)

    @classmethod
    def software_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__software_pattern_mapping.get(field)

    @classmethod
    def user_account_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__user_account_pattern_mapping.get(field)

    @classmethod
    def valid_pattern_assertions(cls) -> tuple:
        return cls.__valid_pattern_assertions

    @classmethod
    def x509_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__x509_pattern_mapping.get(field)


class ExternalSTIX2IndicatorConverter(
        STIX2IndicatorConverter, ExternalSTIX2Converter):
    def __init__(self, main: 'ExternalSTIX2toMISPParser'):
        super().__init__(main)
        self._mapping = ExternalSTIX2IndicatorMapping

    def parse(self, indicator_ref: str):
        indicator = self.main_parser._get_stix_object(indicator_ref)
        feature = self._handle_pattern_mapping(indicator)
        try:
            parser = getattr(self, feature)
        except AttributeError:
            raise UnknownParsingFunctionError(feature)
        try:
            parser(indicator)
        except UnknownPatternMappingError as error:
            self._unknown_pattern_mapping_warning(
                indicator.id, error.__str__().split('_')
            )
            self._create_stix_pattern_object(indicator)
        except InvalidSTIXPatternError as error:
            self.main_parser._invalid_stix_pattern_error(indicator.id, error)
            self._create_stix_pattern_object(indicator)

    ############################################################################
    #                   GENERIC INDICATORS HANDLING METHODS.                   #
    ############################################################################

    def _create_stix_pattern_object(self, indicator: _INDICATOR_TYPING):
        misp_object = self._create_misp_object('stix2-pattern', indicator)
        if hasattr(indicator, 'description'):
            misp_object.comment = indicator.description
        misp_object.add_attribute(
            **{
                'type': 'text',
                'object_relation': 'version',
                'value': f"stix {getattr(indicator, 'spec_version', '2.0')}"
            }
        )
        misp_object.add_attribute(
            **{
                'type': 'stix2-pattern',
                'object_relation': 'stix2-pattern',
                'value': indicator.pattern
            }
        )
        self.main_parser._add_misp_object(misp_object, indicator)

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

    def _handle_pattern_mapping(self, indicator: _INDICATOR_TYPING) -> str:
        if isinstance(indicator, Indicator_v21):
            pattern_type = indicator.pattern_type
            if pattern_type != 'stix':
                try:
                    return f'_parse_{pattern_type}_pattern'
                except KeyError:
                    raise UnknownPatternTypeError(pattern_type)
        pattern_too_complex = any(
            keyword in indicator.pattern for keyword
            in self._mapping.pattern_forbidden_relations()
        )
        if pattern_too_complex:
            return '_create_stix_pattern_object'
        return '_parse_stix_pattern'

    ############################################################################
    #                        INDICATORS PARSING METHODS                        #
    ############################################################################

    @staticmethod
    def _network_traffic_pattern_as_single_attribute(pattern: PatternData) -> bool:
        if len(pattern.comparisons) > 1:
            return False
        comparisons = pattern.comparisons['network-traffic']
        if len(comparisons) > 2:
            return False
        for keys, _, _ in comparisons:
            if keys[0] == 'extensions':
                return False
            if keys[0] not in ('src_ref', 'dst_ref'):
                return False
        return True

    def _parse_asn_pattern(
            self, pattern: PatternData, indicator: _INDICATOR_TYPING):
        attributes = []
        for keys, assertion, values in pattern.comparisons['autonomous-system']:
            if assertion not in self._mapping.valid_pattern_assertions():
                continue
            field = keys[0]
            mapping = self._mapping.asn_pattern_mapping(field)
            if mapping is None:
                self._unmapped_pattern_warning(indicator.id, field)
                continue
            if not isinstance(values, tuple):
                attributes.append(
                    {
                        'value': f'AS{values}' if field == 'number' else values,
                        **mapping
                    }
                )
                continue
            for value in values:
                attributes.append(
                    {
                        'value': f'AS{value}' if field == 'number' else value,
                        **mapping
                    }
                )
        mapping = self._mapping.subnet_announced_attribute()
        for feature in ('ipv4-addr', 'ipv6-addr'):
            if feature not in pattern.comparisons:
                continue
            for keys, assertion, values in pattern.comparisons[feature]:
                if assertion not in self._mapping.valid_pattern_assertions():
                    continue
                if keys[0] != 'value':
                    self._unmapped_pattern_warning(indicator.id, '.'.join(keys))
                    continue
                if isinstance(values, tuple):
                    for value in values:
                        attributes.append({'value': value, **mapping})
                else:
                    attributes.append({'value': values, **mapping})
        if 'asn' in (attr['object_relation'] for attr in attributes):
            self._handle_import_case(indicator, attributes, 'asn')
        else:
            self._no_converted_content_from_pattern_warning(indicator)
            self._create_stix_pattern_object(indicator)

    def _parse_directory_pattern(
            self, pattern: PatternData, indicator: _INDICATOR_TYPING):
        misp_object = self._create_misp_object('directory', indicator)
        for keys, assertion, values in pattern.comparisons['directory']:
            if assertion not in self._mapping.valid_pattern_assertions():
                continue
            mapping = self._mapping.directory_pattern_mapping(keys[0])
            if mapping is None:
                self._unmapped_pattern_warning(indicator.id, '.'.join(keys))
                continue
            if isinstance(values, tuple):
                for value in values:
                    misp_object.add_attribute(**{'value': value, **mapping})
            else:
                misp_object.add_attribute(**{'value': values, **mapping})
        if misp_object.attributes:
            self.main_parser._add_misp_object(misp_object, indicator)
        else:
            self._no_converted_content_from_pattern_warning(indicator)
            self._create_stix_pattern_object(indicator)

    def _parse_domain_ip_port_pattern(
            self, pattern: PatternData, indicator: _INDICATOR_TYPING):
        attributes = []
        features = ('domain-name', 'ipv4-addr', 'ipv6-addr')
        for feature in features:
            if feature not in pattern.comparisons:
                continue
            mapping = self._mapping.domain_ip_pattern_mapping(feature)
            for keys, assertion, values in pattern.comparisons[feature]:
                if assertion not in self._mapping.valid_pattern_assertions():
                    continue
                if keys[0] != 'value':
                    self._unmapped_pattern_warning(indicator.id, '.'.join(keys))
                    continue
                if isinstance(values, tuple):
                    for value in values:
                        attributes.append({'value': value, **mapping})
                else:
                    attributes.append({'value': values, **mapping})
        if any(key not in features for key in pattern.comparisons.keys()):
            self._unknown_pattern_mapping_warning(
                indicator.id,
                (
                    key for key in pattern.comparisons.keys()
                    if key not in features
                )
            )
        if attributes:
            self._handle_import_case(
                indicator, attributes, 'domain-ip',
                'first-seen', 'last-seen'
            )
        else:
            self._no_converted_content_from_pattern_warning(indicator)
            self._create_stix_pattern_object(indicator)

    def _parse_email_address_pattern(
            self, pattern: PatternData, indicator: _INDICATOR_TYPING):
        attributes = []
        for keys, assertion, values in pattern.comparisons['email-addr']:
            if assertion not in self._mapping.valid_pattern_assertions():
                continue
            mapping = self._mapping.email_address_pattern_mapping(keys[0])
            if mapping is None:
                self._unmapped_pattern_warning(indicator.id, '.'.join(keys))
                continue
            if isinstance(values, tuple):
                for value in values:
                    attributes.append({'value': value, **mapping})
            else:
                attributes.append({'value': values, **mapping})
        if attributes:
            self._handle_import_case(indicator, attributes, 'email')
        else:
            self._no_converted_content_from_pattern_warning(indicator)
            self._create_stix_pattern_object(indicator)

    def _parse_email_message_pattern(
            self, pattern: PatternData, indicator: _INDICATOR_TYPING):
        attributes = []
        for keys, assertion, values in pattern.comparisons['email-message']:
            if assertion not in self._mapping.valid_pattern_assertions():
                continue
            field = '.'.join(keys) if len(keys) > 1 else keys[0]
            mapping = self._mapping.email_message_mapping(field)
            if mapping is None:
                self._unmapped_pattern_warning(indicator.id, field)
                continue
            if isinstance(values, tuple):
                for value in values:
                    attributes.append({'value': value, **mapping})
            else:
                attributes.append({'value': values, **mapping})
        if attributes:
            self._handle_import_case(
                indicator, attributes, 'email',
                'bcc', 'cc', 'to'
            )
        else:
            self._no_converted_content_from_pattern_warning(indicator)
            self._create_stix_pattern_object(indicator)

    def _parse_file_and_pe_pattern(
            self, pattern: PatternData, indicator: _INDICATOR_TYPING):
        file_object = self._create_misp_object('file', indicator)
        attributes = defaultdict(list)
        pe_object = self._create_misp_object('pe')
        pe_object.from_dict(**self._parse_timeline(indicator))
        for keys, assertion, values in pattern.comparisons['file']:
            if assertion not in self._mapping.valid_pattern_assertions():
                continue
            if 'windows-pebinary-ext' in keys:
                if 'sections' in keys:
                    if 'hashes' in keys:
                        _, _, _, index, _, hash_type = keys
                        mapping = self._mapping.file_hashes_mapping(hash_type)
                        if mapping is None:
                            self._unmapped_pattern_warning(
                                indicator.id, '.'.join(keys)
                            )
                            continue
                        if isinstance(values, tuple):
                            for value in values:
                                attributes[index.strip('[]')].append(
                                    {'value': value, **mapping}
                                )
                        else:
                            attributes[index.strip('[]')].append(
                                {'value': values, **mapping}
                            )
                        continue
                    _, _, _, index, feature = keys
                    mapping = self._mapping.pe_section_pattern_mapping(feature)
                    if mapping is None:
                        self._unmapped_pattern_warning(
                            indicator.id, '.'.join(keys)
                        )
                        continue
                    if isinstance(values, tuple):
                        for value in values:
                            attributes[index.strip('[]')].append(
                                {'value': value, **mapping}
                            )
                    else:
                        attributes[index.strip('[]')].append(
                            {'value': values, **mapping}
                        )
                    continue
                mapping = self._mapping.pe_pattern_mapping(keys[-1])
                if mapping is not None:
                    if not isinstance(values, tuple):
                        pe_object.add_attribute(**{'value': values, **mapping})
                        continue
                    for value in values:
                        pe_object.add_attribute(**{'value': value, **mapping})
                    continue
                if keys[-1] == 'address_of_entry_point':
                    attribute = self._mapping.entrypoint_address_attribute()
                    if isinstance(values, tuple):
                        for value in values:
                            pe_object.add_attribute(
                                **{'value': value, **attribute}
                            )
                    else:
                        pe_object.add_attribute(
                            **{'value': values, **attribute}
                        )
                    continue
                self._unmapped_pattern_warning(indicator.id, '.'.join(keys))
                continue
            file_attributes = self._parse_file_attribute(
                keys, values, indicator.id
            )
            for attribute in file_attributes:
                file_object.add_attribute(**attribute)
        if pe_object.attributes or attributes:
            if file_object.attributes:
                misp_file_object = self.main_parser._add_misp_object(
                    file_object, indicator
                )
                misp_pe_object = self.main_parser._add_misp_object(
                    pe_object, indicator
                )
                misp_file_object.add_reference(misp_pe_object.uuid, 'includes')
                for section in attributes.values():
                    section_object = self._create_misp_object('pe-section')
                    for attribute in section:
                        section_object.add_attribute(**attribute)
                    self.main_parser._add_misp_object(section_object, indicator)
                    misp_pe_object.add_reference(
                        section_object.uuid, 'includes'
                    )
        else:
            if file_object.attributes:
                self.main_parser._add_misp_object(file_object, indicator)
            else:
                self._no_converted_content_from_pattern_warning(indicator)
                self._create_stix_pattern_object(indicator)

    def _parse_file_attribute(
            self, keys: list, values: Union[str, tuple], indicator_id: str):
        feature, index = (
            ('file_hashes', 1) if 'hashes' in keys else ('file_pattern', 0)
        )
        mapping = getattr(self._mapping, f'{feature}_mapping')(keys[index])
        if mapping is not None:
            if isinstance(values, tuple):
                for value in values:
                    yield {'value': value, **mapping}
            else:
                yield {'value': values, **mapping}
        else:
            self._unmapped_pattern_warning(indicator_id, '.'.join(keys))

    def _parse_file_pattern(
            self, pattern: PatternData, indicator: _INDICATOR_TYPING):
        if 'windows-pebinary-ext' in indicator.pattern:
            self._parse_file_and_pe_pattern(pattern, indicator)
        else:
            attributes = []
            for keys, assertion, value in pattern.comparisons['file']:
                if assertion not in self._mapping.valid_pattern_assertions():
                    continue
                file_attributes = self._parse_file_attribute(
                    keys, value, indicator.id
                )
                for attribute in file_attributes:
                    attributes.append(attribute)
            if attributes:
                self._handle_import_case(
                    indicator, attributes, 'file',
                    'access-time', 'compilation-timestamp', 'creation-time',
                    'file-encoding', 'fullpath', 'modification-time', 'path'
                )
            else:
                self._no_converted_content_from_pattern_warning(indicator)
                self._create_stix_pattern_object(indicator)

    def _parse_ip_address_pattern(
            self, pattern: PatternData, indicator: _INDICATOR_TYPING):
        attributes = []
        for feature in ('ipv4-addr', 'ipv6-addr'):
            if feature in pattern.comparisons:
                for keys, assertion, values in pattern.comparisons[feature]:
                    if assertion not in self._mapping.valid_pattern_assertions():
                        continue
                    if keys[0] != 'value':
                        self._unmapped_pattern_warning(
                            indicator.id, '.'.join(keys)
                        )
                        continue
                    if isinstance(values, tuple):
                        for value in values:
                            attributes.append(
                                {'value': value, **self._mapping.ip_attribute()}
                            )
                    else:
                        attributes.append(
                            {'value': values, **self._mapping.ip_attribute()}
                        )
        if attributes:
            self._handle_import_case(indicator, attributes, 'ip-port')
        else:
            self._no_converted_content_from_pattern_warning(indicator)
            self._create_stix_pattern_object(indicator)

    def _parse_mutex_pattern(
            self, pattern: PatternData, indicator: _INDICATOR_TYPING):
        attributes = []
        for keys, assertion, values in pattern.comparisons['mutex']:
            if assertion not in self._mapping.valid_pattern_assertions():
                continue
            field = keys[0]
            if field == 'name':
                if isinstance(values, tuple):
                    for value in values:
                        attributes.append(
                            {'value': value, **self._mapping.name_attribute()}
                        )
                else:
                    attributes.append(
                        {'value': values, **self._mapping.name_attribute()}
                    )
        if attributes:
            self._handle_import_case(indicator, attributes, 'mutex', 'name')
        else:
            self._no_converted_content_from_pattern_warning(indicator)
            self._create_stix_pattern_object(indicator)

    def _parse_network_connection_pattern(
            self, pattern: PatternData, indicator: _INDICATOR_TYPING):
        misp_object = self._create_misp_object('network-connection', indicator)
        for keys, assertion, values in pattern.comparisons['network-traffic']:
            if assertion not in self._mapping.valid_pattern_assertions():
                continue
            if 'protocols' in keys:
                layer = self._mapping.connection_protocols(values)
                if layer is None:
                    self._unknown_network_protocol_warning(
                        values, indicator.id
                    )
                    continue
                if isinstance(values, tuple):
                    for value in values:
                        misp_object.add_attribute(
                            f'layer{layer}-protocol', value
                        )
                else:
                    misp_object.add_attribute(f'layer{layer}-protocol', values)
                continue
            self._parse_network_traffic_attribute(
                misp_object, keys, values, indicator.id, 'network_connection'
            )
        if misp_object.attributes:
            self.main_parser._add_misp_object(misp_object, indicator)
        else:
            self._no_converted_content_from_pattern_warning(indicator)
            self._create_stix_pattern_object(indicator)

    def _parse_network_socket_pattern(
            self, pattern: PatternData, indicator: _INDICATOR_TYPING):
        misp_object = self._create_misp_object('network-socket', indicator)
        for keys, assertion, values in pattern.comparisons['network-traffic']:
            if assertion not in self._mapping.valid_pattern_assertions():
                continue
            if 'socket-ext' in keys:
                mapping = self._mapping.socket_extension_pattern_mapping(
                    keys[-1]
                )
                if mapping is None:
                    self._unmapped_pattern_warning(indicator.id, '.'.join(keys))
                    continue
                if isinstance(values, tuple):
                    for value in values:
                        misp_object.add_attribute(**{'value': value, **mapping})
                else:
                    misp_object.add_attribute(**{'value': values, **mapping})
                continue
            if 'protocols' in keys:
                if isinstance(values, tuple):
                    for value in values:
                        misp_object.add_attribute('protocol', value)
                else:
                    misp_object.add_attribute('protocol', values)
                continue
            self._parse_network_traffic_attribute(
                misp_object, keys, values, indicator.id, 'network_socket'
            )
        self.main_parser._add_misp_object(misp_object, indicator)

    def _parse_network_traffic_attribute(
            self, misp_object: MISPObject, keys: list,
            values: Union[str, tuple], indicator_id: str, name: str):
        field = keys[0]
        if any(field == f'{feature}_ref' for feature in ('src', 'dst')):
            if keys [-1] == 'type':
                return
            if isinstance(values, tuple):
                for value in values:
                    misp_object.add_attribute(
                        *self._parse_network_traffic_reference(
                            field.split('_')[0], value
                        )
                    )
            else:
                misp_object.add_attribute(
                    *self._parse_network_traffic_reference(
                        field.split('_')[0], values
                    )
                )
            return
        mapping = getattr(self._mapping, f'{name}_pattern_mapping')(field)
        if mapping is None:
            self._unmapped_pattern_warning(indicator_id, '.'.join(keys))
            return
        if isinstance(values, tuple):
            for value in values:
                misp_object.add_attribute(**{'value': value, **mapping})
        else:
            misp_object.add_attribute(**{'value': values, **mapping})

    def _parse_network_traffic_pattern(
            self, pattern: PatternData, indicator: _INDICATOR_TYPING):
        if self._network_traffic_pattern_as_single_attribute(pattern):
            for keys, assertion, value in pattern.comparisons['network-traffic']:
                if assertion not in self._mapping.valid_pattern_assertions():
                    continue
                if 'type' in keys:
                    continue
                attribute = {
                    'type': f"ip-{keys[0].split('_')[0]}", 'value': value,
                    **self._create_attribute_dict(indicator)
                }
                self.main_parser._add_misp_attribute(attribute, indicator)
        elif 'socket-ext' in indicator.pattern:
            self._parse_network_socket_pattern(pattern, indicator)
        else:
            self._parse_network_connection_pattern(pattern, indicator)

    def _parse_network_traffic_reference(
            self, feature: str, value: str) -> Tuple[str]:
        if re.match(self._mapping.mac_address_pattern(), value):
            return f'mac-{feature}', value
        try:
            ipaddress.ip_interface(value)
            return f'ip-{feature}', value
        except ValueError:
            return f'hostname-{feature}', value

    def _parse_process_pattern(
            self, pattern: PatternData, indicator: _INDICATOR_TYPING):
        attributes = []
        # if any(feature != 'process' for feature in pattern.comparisons.keys()):
        #    print(f'Process with non process values: {pattern}')
        for keys, assertion, values in pattern.comparisons['process']:
            if assertion not in self._mapping.valid_pattern_assertions():
                continue
            mapping = self._mapping.process_pattern_mapping(keys[0])
            if mapping is None:
                self._unmapped_pattern_warning(indicator.id, '.'.join(keys))
                continue
            if isinstance(values, tuple):
                for value in values:
                    attributes.append({'value': value, **mapping})
            else:
                attributes.append({'value': values, **mapping})
        if attributes:
            self._handle_import_case(
                indicator, attributes, 'process',
                'args', 'command-line', 'current-directory', 'name', 'pid'
            )
        else:
            self._no_converted_content_from_pattern_warning(indicator)
            self._create_stix_pattern_object(indicator)

    def _parse_registry_key_pattern(
            self, pattern: PatternData, indicator: _INDICATOR_TYPING):
        attributes = []
        for keys, assertion, values in pattern.comparisons['windows-registry-key']:
            if assertion not in self._mapping.valid_pattern_assertions():
                continue
            mapping = self._mapping.registry_key_pattern_mapping(
                keys[-1 if 'values' in keys else 0]
            )
            if mapping is None:
                self._unmapped_pattern_warning(indicator.id, '.'.join(keys))
                continue
            if isinstance(values, tuple):
                for value in values:
                    attributes.append({'value': value, **mapping})
            else:
                attributes.append({'value': values, **mapping})
        if attributes:
            self._handle_import_case(
                indicator, attributes, 'registry-key',
                'data', 'data-type', 'name'
            )
        else:
            self._no_converted_content_from_pattern_warning(indicator)
            self._create_stix_pattern_object(indicator)

    def _parse_sigma_pattern(self, indicator: _INDICATOR_TYPING):
        if hasattr(indicator, 'name') or hasattr(indicator, 'external_references'):
            attributes = []
            for field, mapping in self._mapping.sigma_object_mapping().items():
                if hasattr(indicator, field):
                    attributes.append(
                        {'value': getattr(indicator, field), **mapping}
                    )
            if hasattr(indicator, 'external_references'):
                for reference in indicator.external_references:
                    if not hasattr(reference, 'url'):
                        continue
                    attribute = {
                        'value': reference.url,
                        **self._mapping.sigma_reference_attribute()
                    }
                    if hasattr(reference, 'description'):
                        attribute['comment'] = reference.description
                    attributes.append(attribute)
            if len(attributes) == 1 and attributes[0]['type'] == 'sigma':
                self.main_parser._add_misp_attribute(
                    dict(
                        self._create_attribute_dict(indicator), **attributes[0]
                    ),
                    indicator
                )
            else:
                misp_object = self._create_misp_object('sigma', indicator)
                if hasattr(indicator, 'object_marking_refs'):
                    tags = tuple(
                        self.main_parser._handle_tags_from_stix_fields(
                            indicator
                        )
                    )
                    for attribute in attributes:
                        misp_attribute = misp_object.add_attribute(**attribute)
                        for tag in tags:
                            misp_attribute.add_tag(tag)
                else:
                    for attribute in attributes:
                        misp_object.add_attribute(**attribute)
                self.main_parser._add_misp_object(misp_object, indicator)
        else:
            self.main_parser._add_misp_attribute(
                {
                    'value': indicator.pattern,
                    **self._mapping.sigma_attribute(),
                    **self._create_attribute_dict(indicator)
                },
                indicator
            )

    def _parse_snort_pattern(self, indicator: _INDICATOR_TYPING):
        self.main_parser._add_misp_attribute(
            {
                'value': indicator.pattern,
                **self._mapping.snort_attribute(),
                **self._create_attribute_dict(indicator)
            },
            indicator
        )

    def _parse_software_pattern(
            self, pattern: PatternData, indicator: _INDICATOR_TYPING):
        attributes = []
        for keys, assertion, values in pattern.comparisons['software']:
            if assertion not in self._mapping.valid_pattern_assertions():
                continue
            mapping = self._mapping.software_pattern_mapping(keys[0])
            if mapping is None:
                self._unmapped_pattern_warning(indicator.id, '.'.join(keys))
                continue
            if isinstance(values, tuple):
                for value in values:
                    attributes.append({'value': value, **mapping})
            else:
                attributes.append({'value': values, **mapping})
        if attributes:
            self._handle_object_case(indicator, attributes, 'software')
        else:
            self._no_converted_content_from_pattern_warning(indicator)
            self._create_stix_pattern_object(indicator)

    def _parse_stix_pattern(self, indicator: _INDICATOR_TYPING):
        compiled_pattern = self._compile_stix_pattern(indicator)
        observable_types = '_'.join(sorted(compiled_pattern.comparisons.keys()))
        mapping = self._mapping.pattern_mapping(observable_types)
        if mapping is None:
            raise UnknownPatternMappingError(observable_types)
        feature = f'_parse_{mapping}_pattern'
        try:
            parser = getattr(self, feature)
        except AttributeError:
            raise UnknownParsingFunctionError(feature)
        parser(compiled_pattern, indicator)

    def _parse_suricata_pattern(self, indicator: _INDICATOR_TYPING):
        misp_object = self._create_misp_object('suricata', indicator)
        for feature, mapping in self._mapping.suricata_object_mapping().items():
            if hasattr(indicator, feature):
                misp_object.add_attribute(
                    **{'value': getattr(indicator, feature), **mapping}
                )
        if hasattr(indicator, 'object_marking_refs'):
            self._handle_marking_refs(
                indicator.object_marking_refs, misp_object
            )
        self.main_parser._add_misp_object(misp_object, indicator)

    def _parse_url_pattern(
            self, pattern: PatternData, indicator: _INDICATOR_TYPING):
        attributes = []
        if 'url' in pattern.comparisons:
            for keys, assertion, values in pattern.comparisons['url']:
                if assertion not in self._mapping.valid_pattern_assertions():
                    continue
                if keys[0] != 'value':
                    self._unmapped_pattern_warning(indicator.id, '.'.join(keys))
                    continue
                if isinstance(values, tuple):
                    for value in values:
                        attributes.append(
                            {'value': value, **self._mapping.url_attribute()}
                        )
                else:
                    attributes.append(
                        {'value': values, **self._mapping.url_attribute()}
                    )
        if any(key != 'url' for key in pattern.comparisons.keys()):
            self._unknown_pattern_mapping_warning(
                indicator.id,
                (key for key in pattern.comparisons.keys() if key != 'url')
            )
        if attributes:
            self._handle_import_case(indicator, attributes, 'url')
        else:
            self._no_converted_content_from_pattern_warning(indicator)
            self._create_stix_pattern_object(indicator)

    def _parse_user_account_pattern(
            self, pattern: PatternData, indicator: _INDICATOR_TYPING):
        attributes = []
        for keys, assertion, values in pattern.comparisons['user-account']:
            if assertion not in self._mapping.valid_pattern_assertions():
                continue
            mapping = self._mapping.user_account_pattern_mapping(
                keys[-1 if 'unix-account-ext' in keys else 0]
            )
            if mapping is None:
                self._unmapped_pattern_warning(indicator.id, '.'.join(keys))
                continue
            if isinstance(values, tuple):
                for value in values:
                    attributes.append({'value': value, **mapping})
            else:
                attributes.append({'value': values, **mapping})
        if attributes:
            self._handle_object_case(indicator, attributes, 'user-account')
        else:
            self._no_converted_content_from_pattern_warning(indicator)
            self._create_stix_pattern_object(indicator)

    def _parse_x509_pattern(
            self, pattern: PatternData, indicator: _INDICATOR_TYPING):
        attributes = []
        for keys, assertion, values in pattern.comparisons['x509-certificate']:
            if assertion not in self._mapping.valid_pattern_assertions():
                continue
            mapping = self._mapping.x509_pattern_mapping(
                keys[1 if 'hashes' in keys else 0]
            )
            if mapping is None:
                self._unmapped_pattern_warning(indicator.id, '.'.join(keys))
                continue
            if isinstance(values, tuple):
                for value in values:
                    attributes.append({'value': value, **mapping})
            else:
                attributes.append({'value': values, **mapping})
        if attributes:
            self._handle_import_case(
                indicator, attributes, 'x509',
                'issuer', 'pubkey-info-algorithm', 'pubkey-info-exponent',
                'pubkey-info-modulus', 'self_signed', 'serial-number',
                'signature-algorithm', 'subject', 'validity-not-after',
                'validity-not-before', 'version'
            )
        else:
            self._no_converted_content_from_pattern_warning(indicator)
            self._create_stix_pattern_object(indicator)

    def _parse_yara_pattern(self, indicator: _INDICATOR_TYPING):
        if hasattr(indicator, 'pattern_version'):
            misp_object = self._create_misp_object('yara', indicator)
            for feature, mapping in self._mapping.yara_object_mapping().items():
                if hasattr(indicator, feature):
                    misp_object.add_attribute(
                        **{'value': getattr(indicator, feature), **mapping}
                    )
            if hasattr(indicator, 'external_references'):
                for reference in indicator.external_references:
                    if not hasattr(reference, 'url'):
                        continue
                    attribute = {
                        'value': reference.url,
                        **self._mapping.yara_reference_attribute()
                    }
                    if hasattr(reference, 'description'):
                        attribute['comment'] = reference.description
                    misp_object.add_attribute(**attribute)
            self.main_parser._add_misp_object(misp_object, indicator)
        else:
            self.main_parser._add_misp_attribute(
                {
                    'value': indicator.pattern,
                    **self._mapping.yara_attribute(),
                    **self._create_attribute_dict(indicator)
                },
                indicator
            )

    ############################################################################
    #                   ERRORS AND WARNINGS HANDLING METHODS                   #
    ############################################################################

    def _no_converted_content_from_pattern_warning(
            self, indicator: _INDICATOR_TYPING):
        self.main_parser._add_warning(
            "No content extracted from the following Indicator's (id: "
            f'{indicator.id}) pattern: {indicator.pattern}'
        )

    def _unknown_pattern_mapping_warning(
            self, indicator_id: str, pattern_types: GeneratorType):
        self.main_parser._add_warning(
            f'Unable to map pattern from the Indicator with id {indicator_id}, '
            f"containing the following types: {', '.join(pattern_types)}"
        )

    def _unmapped_pattern_warning(self, indicator_id: str, feature: str):
        self.main_parser._add_warning(
            'Unmapped pattern part in indicator with id '
            f'{indicator_id}: {feature}'
        )


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

    # OBJECTS MAPPING
    __email_pattern_mapping = Mapping(
        **{
            'additional_header_fields.reply_to': STIX2Mapping.reply_to_attribute(),
            'additional_header_fields.x_mailer': STIX2Mapping.x_mailer_attribute(),
            'bcc_refs': {
                'display_name': STIX2Mapping.bcc_display_name_attribute(),
                'value': STIX2Mapping.bcc_attribute()
            },
            'cc_refs': {
                'display_name': STIX2Mapping.cc_display_name_attribute(),
                'value': STIX2Mapping.cc_attribute()
            },
            'from_ref.display_name': STIX2Mapping.from_display_name_attribute(),
            'from_ref.value': STIX2Mapping.from_attribute(),
            'to_refs': {
                'display_name': STIX2Mapping.to_display_name_attribute(),
                'value': STIX2Mapping.to_attribute()
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
            'binary_ref.name': InternalSTIX2Mapping.image_attribute(),
            'image_ref.name': InternalSTIX2Mapping.image_attribute(),
            'parent_ref.command_line': InternalSTIX2Mapping.parent_command_line_attribute(),
            'parent_ref.name': InternalSTIX2Mapping.parent_process_name_attribute(),
            'parent_ref.pid': InternalSTIX2Mapping.parent_pid_attribute(),
            'parent_ref.binary_ref.name': InternalSTIX2Mapping.parent_image_attribute(),
            'parent_ref.image_ref.name': InternalSTIX2Mapping.parent_image_attribute(),
            'parent_ref.x_misp_guid': InternalSTIX2Mapping.parent_guid_attribute(),
            'parent_ref.x_misp_process_name': InternalSTIX2Mapping.parent_process_name_attribute(),
            'parent_ref.x_misp_process_path': InternalSTIX2Mapping.parent_process_path_attribute(),
            **InternalSTIX2Mapping.process_object_mapping()
        }
    )
    __sigma_object_mapping = Mapping(
        **STIX2IndicatorMapping.sigma_object_mapping(),
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
        **STIX2IndicatorMapping.yara_object_mapping(),
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
    def network_socket_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.network_socket_object_mapping().get(field)

    @classmethod
    def parler_account_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.parler_account_object_mapping().get(field)

    @classmethod
    def process_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__process_pattern_mapping.get(field)

    @classmethod
    def reddit_account_pattern_mapping(cls, field: str) -> Union[dict, None]:
        return cls.reddit_account_object_mapping().get(field)

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
        return cls.unix_user_account_extension_object_mapping().get(field)

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
        try:
            feature = self._handle_mapping_from_labels(
                indicator.labels, indicator.id
            )
        except UndefinedSTIXObjectError as error:
            raise UndefinedIndicatorError(error)
        try:
            parser = getattr(self, f"{feature}_indicator")
        except AttributeError:
            raise UnknownParsingFunctionError(f"{feature}_indicator")
        try:
            parser(indicator)
        except AttributeFromPatternParsingError as indicator_id:
            self.main_parser._add_error(
                'Error while parsing pattern from '
                f'indicator with id {indicator_id}'
            )
        except Exception as exception:
            _traceback = self.main_parser._parse_traceback(exception)
            self.main_parser._add_error(
                'Error while parsing the Indicator object with id '
                f'{indicator.id}: {_traceback}'
            )

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
            self, indicator: _INDICATOR_TYPING):
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

    def _object_from_patterning_language_indicator(
            self, indicator: _INDICATOR_TYPING):
        name = (
            'suricata' if indicator.pattern_type == 'snort'
            else indicator.pattern_type
        )
        misp_object = self._create_misp_object(name, indicator)
        for attribute in self._generic_parser(indicator, feature=name):
            misp_object.add_attribute(**attribute)
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
                        **self._mapping.child_pid_attribute(),
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
        misp_object.add_attribute(
            **{'value': uri, **self._mapping.uri_attribute()}
        )
        misp_object.add_attribute(
            **{'value': url, **self._mapping.url_attribute()}
        )
    
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
