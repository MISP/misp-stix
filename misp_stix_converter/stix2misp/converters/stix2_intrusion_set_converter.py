#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ... import Mapping
from ..exceptions import UnknownParsingFunctionError
from .stix2converter import ExternalSTIX2Converter, InternalSTIX2Converter
from .stix2mapping import (
    ExternalSTIX2Mapping, InternalSTIX2Mapping, STIX2Mapping)
from abc import ABCMeta
from pymisp import MISPGalaxyCluster
from stix2.v20.sdo import IntrusionSet as IntrusionSet_v20
from stix2.v21.sdo import IntrusionSet as IntrusionSet_v21
from typing import Optional, TYPE_CHECKING, Union

if TYPE_CHECKING:
    from ..external_stix2_to_misp import ExternalSTIX2toMISPParser
    from ..internal_stix2_to_misp import InternalSTIX2toMISPParser

_INTRUSION_SET_TYPING = Union[
    IntrusionSet_v20, IntrusionSet_v21
]


class STIX2IntrusionSetMapping(STIX2Mapping, metaclass=ABCMeta):
    __intrusion_set_meta_mapping = Mapping(
        aliases='synonyms',
        goals='goals',
        primary_motivation='primary_motivation',
        resource_level='resource_level',
        secondary_motivations='secondary_motivations'
    )

    @classmethod
    def intrusion_set_meta_mapping(cls) -> dict:
        return cls.__intrusion_set_meta_mapping


class ExternalSTIX2IntrusionSetMapping(
        STIX2IntrusionSetMapping, ExternalSTIX2Mapping):
    pass


class ExternalSTIX2IntrusionSetConverter(ExternalSTIX2Converter):
    def __init__(self, main: 'ExternalSTIX2toMISPParser'):
        self._set_main_parser(main)
        self._mapping = ExternalSTIX2IntrusionSetMapping

    def parse(self, intrusion_set_ref: str):
        intrusion_set = self.main_parser._get_stix_object(intrusion_set_ref)
        self._parse_galaxy(intrusion_set)

    def _create_cluster(self, intrusion_set: _INTRUSION_SET_TYPING,
                        galaxy_type: Optional[str] = None) -> MISPGalaxyCluster:
        intrusion_set_args = self._create_cluster_args(
            intrusion_set, galaxy_type
        )
        meta = self._handle_meta_fields(intrusion_set)
        if hasattr(intrusion_set, 'external_references'):
            meta.update(
                self._handle_external_references(
                    intrusion_set.external_references
                )
            )
        if meta:
            intrusion_set_args['meta'] = meta
        return self.main_parser._create_misp_galaxy_cluster(
            **intrusion_set_args
        )


class InternalSTIX2IntrusionSetMapping(
        STIX2IntrusionSetMapping, InternalSTIX2Mapping):
    __intrusion_set_object_mapping = Mapping(
        name=STIX2Mapping.name_attribute(),
        description=STIX2Mapping.description_attribute(),
        aliases={'type': 'text', 'object_relation': 'aliases'},
        first_seen={'type': 'datetime', 'object_relation': 'first_seen'},
        goals={'type': 'text', 'object_relation': 'goals'},
        last_seen={'type': 'datetime', 'object_relation': 'last_seen'},
        resource_level={'type': 'text', 'object_relation': 'resource_level'},
        primary_motivation={
            'type': 'text', 'object_relation': 'primary-motivation'
        },
        secondary_motivations={
            'type': 'text', 'object_relation': 'secondary-motivation'
        }
    )

    @classmethod
    def intrusion_set_object_mapping(cls) -> dict:
        return cls.__intrusion_set_object_mapping


class InternalSTIX2IntrusionSetConverter(InternalSTIX2Converter):
    def __init__(self, main: 'InternalSTIX2toMISPParser'):
        self._set_main_parser(main)
        self._mapping = InternalSTIX2IntrusionSetMapping

    def parse(self, intrusion_set_ref: str):
        intrusion_set = self.main_parser._get_stix_object(intrusion_set_ref)
        feature = self._handle_mapping_from_labels(
            intrusion_set.labels, intrusion_set.id
        )
        try:
            parser = getattr(self, feature)
        except AttributeError:
            raise UnknownParsingFunctionError(feature)
        try:
            parser(intrusion_set)
        except Exception as exception:
            self.main_parser.intrusion_set_error(intrusion_set.id, exception)

    def _create_cluster(self, intrusion_set: _INTRUSION_SET_TYPING,
                        description: Optional[str] = None,
                        galaxy_type: Optional[str] = None) -> MISPGalaxyCluster:
        intrusion_set_args = self._create_cluster_args(
            intrusion_set, galaxy_type, description=description
        )
        meta = self._handle_meta_fields(intrusion_set)
        if hasattr(intrusion_set, 'external_references'):
            meta.update(
                self._handle_external_references(
                    intrusion_set.external_references
                )
            )
        if meta.get('external_id'):
            self._handle_cluster_value_with_synonyms(intrusion_set_args, meta)
        if meta:
            intrusion_set_args['meta'] = meta
        return self.main_parser._create_misp_galaxy_cluster(
            **intrusion_set_args
        )

    def _parse_intrusion_set_object(self, intrusion_set: _INTRUSION_SET_TYPING):
        misp_object = self._create_misp_object('intrusion-set', intrusion_set)
        for attribute in self._generic_parser(intrusion_set):
            misp_object.add_attribute(**attribute)
        self.main_parser._add_misp_object(misp_object, intrusion_set)