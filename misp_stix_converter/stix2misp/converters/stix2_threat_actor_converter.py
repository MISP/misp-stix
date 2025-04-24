#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ... import Mapping
from ..exceptions import UnknownParsingFunctionError
from .stix2converter import (
    ExternalSTIX2Converter, InternalSTIX2Converter, STIX2Converter,
    _MAIN_PARSER_TYPING)
from .stix2mapping import (
    ExternalSTIX2Mapping, InternalSTIX2Mapping, STIX2Mapping)
from abc import ABCMeta
from pymisp import MISPGalaxyCluster
from stix2.v20.sdo import ThreatActor as ThreatActor_v20
from stix2.v21.sdo import ThreatActor as ThreatActor_v21
from typing import Optional, TYPE_CHECKING, Union

if TYPE_CHECKING:
    from ..external_stix2_to_misp import ExternalSTIX2toMISPParser
    from ..internal_stix2_to_misp import InternalSTIX2toMISPParser

_THREAT_ACTOR_TYPING = Union[
    ThreatActor_v20, ThreatActor_v21
]


class STIX2ThreatActorMapping(STIX2Mapping, metaclass=ABCMeta):
    __threat_actor_meta_mapping = Mapping(
        aliases='synonyms',
        first_seen='first_seen',
        goals='goals',
        last_seen='last_seen',
        personal_motivations='personal_motivations',
        primary_motivation='primary_motivation',
        resource_level='resource_level',
        roles='roles',
        secondary_motivations='secondary_motivations',
        sophistication='sophistication',
        threat_actor_types='threat_actor_types'
    )

    @classmethod
    def threat_actor_meta_mapping(cls) -> dict:
        return cls.__threat_actor_meta_mapping


class STIX2ThreatActorConverter(STIX2Converter, metaclass=ABCMeta):
    def __init__(self, main: _MAIN_PARSER_TYPING):
        self._set_main_parser(main)

    def _create_cluster(self, threat_actor: _THREAT_ACTOR_TYPING,
                        description: Optional[str] = None,
                        galaxy_type: Optional[str] = None) -> MISPGalaxyCluster:
        threat_actor_args = self._create_cluster_args(
            threat_actor, galaxy_type, description=description
        )
        meta = self._handle_meta_fields(threat_actor)
        if hasattr(threat_actor, 'external_references'):
            meta.update(
                self._handle_external_references(
                    threat_actor.external_references
                )
            )
        if hasattr(threat_actor, 'labels'):
            self._handle_labels(meta, threat_actor.labels)
        if meta:
            threat_actor_args['meta'] = meta
        return self.main_parser._create_misp_galaxy_cluster(**threat_actor_args)


class ExternalSTIX2ThreatActorMapping(
        STIX2ThreatActorMapping, ExternalSTIX2Mapping):
    pass


class ExternalSTIX2ThreatActorConverter(
        STIX2ThreatActorConverter, ExternalSTIX2Converter):
    def __init__(self, main: 'ExternalSTIX2toMISPParser'):
        super().__init__(main)
        self._mapping = ExternalSTIX2ThreatActorMapping

    def parse(self, threat_actor_ref: str):
        threat_actor = self.main_parser._get_stix_object(threat_actor_ref)
        self._parse_galaxy(threat_actor)


class InternalSTIX2ThreatActorMapping(
        STIX2ThreatActorMapping, InternalSTIX2Mapping):
    pass


class InternalSTIX2ThreatActorConverter(
        STIX2ThreatActorConverter, InternalSTIX2Converter):
    def __init__(self, main: 'InternalSTIX2toMISPParser'):
        super().__init__(main)
        self._mapping = InternalSTIX2ThreatActorMapping

    def parse(self, threat_actor_ref: str):
        threat_actor = self.main_parser._get_stix_object(threat_actor_ref)
        feature = self._handle_mapping_from_labels(
            threat_actor.labels, threat_actor.id
        )
        try:
            parser = getattr(self, feature)
        except AttributeError:
            raise UnknownParsingFunctionError(feature)
        try:
            parser(threat_actor)
        except Exception as exception:
            _traceback = self.main_parser._parse_traceback(exception)
            self.main_parser._add_error(
                'Error while parsing the Threat Actor object with id '
                f'{threat_actor.id}: {_traceback}'
            )
