#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ..exceptions import UnknownParsingFunctionError
from ..external_stix2_to_misp import ExternalSTIX2toMISPParser
from ..internal_stix2_to_misp import InternalSTIX2toMISPParser
from .stix2parser import ExternalParser, InternalParser, STIX2Parser
from abc import ABCMeta
from pymisp import MISPGalaxyCluster
from stix2.v20.common import ExternalReference as ExternalReference_v20
from stix2.v20.sdo import AttackPattern as AttackPattern_v20
from stix2.v21.common import ExternalReference as ExternalReference_v21
from stix2.v21.sdo import AttackPattern as AttackPattern_v21
from typing import Optional, Union

_ATTACK_PATTERN_TYPING = Union[
    AttackPattern_v20, AttackPattern_v21
]
_EXTERNAL_REFERENCE_TYPING = Union[
    ExternalReference_v20, ExternalReference_v21
]
_MAIN_PARSER_TYPING = Union[
    ExternalSTIX2toMISPParser, InternalSTIX2toMISPParser
]


class AttackPatternParser(STIX2Parser, metaclass=ABCMeta):
    def __init__(self, main: _MAIN_PARSER_TYPING):
        super().__init__(main)

    def _create_cluster(self, attack_pattern: _ATTACK_PATTERN_TYPING,
                        description: Optional[str] = None,
                        galaxy_type: Optional[str] = None) -> MISPGalaxyCluster:
        attack_pattern_args = self._create_cluster_args(
            attack_pattern, galaxy_type, description=description
        )
        meta = self._handle_meta_fields(attack_pattern)
        if hasattr(attack_pattern, 'external_references'):
            meta.update(
                self._handle_external_references(
                    attack_pattern.external_references
                )
            )
        if hasattr(attack_pattern, 'kill_chain_phases'):
            meta['kill_chain'] = self._handle_kill_chain_phases(
                attack_pattern.kill_chain_phases
            )
        if meta:
            attack_pattern_args['meta'] = meta
        return self._create_misp_galaxy_cluster(attack_pattern_args)


class ExternalAttackPatternParser(AttackPatternParser, ExternalParser):
    def __init__(self, main: ExternalSTIX2toMISPParser):
        super().__init__(main)
        super(ExternalParser, self).__init__()

    def parse(self, stix_object_ref: str):
        super().parse(stix_object_ref)


class InternalAttackPatternParser(AttackPatternParser, InternalParser):
    def __init__(self, main: InternalSTIX2toMISPParser):
        super().__init__(main)
        super(InternalParser, self).__init__()

    def parse(self, attack_pattern_ref: str):
        attack_pattern = self.main_parser._get_stix_object(attack_pattern_ref)
        feature = self._handle_object_mapping(
            attack_pattern.labels, attack_pattern.id
        )
        try:
            parser = getattr(self, feature)
        except AttributeError:
            raise UnknownParsingFunctionError(feature)
        try:
            parser(attack_pattern)
        except Exception as exception:
            self.main_parser._attack_pattern_error(attack_pattern.id, exception)

    def _parse_attack_pattern_object(
            self, attack_pattern: _ATTACK_PATTERN_TYPING):
        misp_object = self._create_misp_object('attack-pattern', attack_pattern)
        for key, mapping in self._mapping.attack_pattern_object_mapping().items():
            if hasattr(attack_pattern, key):
                self._populate_object_attributes(
                    misp_object, mapping, getattr(attack_pattern, key)
                )
        if hasattr(attack_pattern, 'external_references'):
            for reference in attack_pattern.external_references:
                misp_object.add_attribute(
                    **self._parse_attack_pattern_reference(reference)
                )
        self.main_parser._add_misp_object(misp_object, attack_pattern)

    def _parse_attack_pattern_reference(
            self, reference: _EXTERNAL_REFERENCE_TYPING) -> dict:
        if reference.source_name == 'url':
            return {
                'value': reference.url,
                **self._mapping.references_attribute()
            }
        external_id = reference.external_id
        return {
            'value': external_id.split('-')[1]
            if external_id.startswith('CAPEC-') else external_id,
            **self._mapping.attack_pattern_id_attribute()
        }