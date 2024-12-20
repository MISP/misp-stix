#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ... import Mapping
from ..exceptions import UnknownParsingFunctionError
from .stix2converter import ExternalSTIX2Converter, InternalSTIX2Converter
from .stix2mapping import (
    ExternalSTIX2Mapping, InternalSTIX2Mapping, STIX2Mapping)
from abc import ABCMeta
from pymisp import MISPGalaxyCluster
from stix2.v20.sdo import CourseOfAction as CourseOfAction_v20
from stix2.v21.sdo import CourseOfAction as CourseOfAction_v21
from typing import Optional, TYPE_CHECKING, Union

if TYPE_CHECKING:
    from ..external_stix2_to_misp import ExternalSTIX2toMISPParser
    from ..internal_stix2_to_misp import InternalSTIX2toMISPParser

_COURSE_OF_ACTION_TYPING = Union[
    CourseOfAction_v20, CourseOfAction_v21
]


class ExternalSTIX2CourseOfActionConverter(ExternalSTIX2Converter):
    def __init__(self, main: 'ExternalSTIX2toMISPParser'):
        self._set_main_parser(main)
        self._mapping = ExternalSTIX2Mapping

    def parse(self, course_of_action_ref: str):
        course_of_action = self.main_parser._get_stix_object(
            course_of_action_ref
        )
        self._parse_galaxy(course_of_action)

    def _create_cluster(self, course_of_action: _COURSE_OF_ACTION_TYPING,
                        galaxy_type: Optional[str] = None) -> MISPGalaxyCluster:
        course_of_action_args = self._create_cluster_args(
            course_of_action, galaxy_type
        )
        meta = self._handle_meta_fields(course_of_action)
        if hasattr(course_of_action, 'external_references'):
            meta.update(
                self._handle_external_references(
                    course_of_action.external_references
                )
            )
        if meta:
            course_of_action_args['meta'] = meta
        return self.main_parser._create_misp_galaxy_cluster(
            **course_of_action_args
        )


class InternalSTIX2CourseOfActionMapping(InternalSTIX2Mapping):
    __course_of_action_object_mapping = Mapping(
        name=STIX2Mapping.name_attribute(),
        description=STIX2Mapping.description_attribute(),
        x_misp_cost={'type': 'text', 'object_relation': 'cost'},
        x_misp_efficacy={'type': 'text', 'object_relation': 'efficacy'},
        x_misp_impact={'type': 'text', 'object_relation': 'impact'},
        x_misp_objective={'type': 'text', 'object_relation': 'objective'},
        x_misp_stage={'type': 'text', 'object_relation': 'stage'},
        x_misp_type=STIX2Mapping.type_attribute()
    )

    @classmethod
    def course_of_action_object_mapping(cls) -> dict:
        return cls.__course_of_action_object_mapping


class InternalSTIX2CourseOfActionConverter(InternalSTIX2Converter):
    def __init__(self, main: 'InternalSTIX2toMISPParser'):
        self._set_main_parser(main)
        self._mapping = InternalSTIX2CourseOfActionMapping

    def parse(self, course_of_action_ref: str):
        course_of_action = self.main_parser._get_stix_object(
            course_of_action_ref
        )
        feature = self._handle_mapping_from_labels(
            course_of_action.labels, course_of_action.id
        )
        try:
            parser = getattr(self, feature)
        except AttributeError:
            raise UnknownParsingFunctionError(feature)
        try:
            parser(course_of_action)
        except Exception as exception:
            _traceback = self.main_parser._parse_traceback(exception)
            self.main_parser._add_error(
                'Error parsing the Course of Action object with id '
                f'{course_of_action.id}: {_traceback}'
            )

    def _create_cluster(self, course_of_action: _COURSE_OF_ACTION_TYPING,
                        description: Optional[str] = None,
                        galaxy_type: Optional[str] = None) -> MISPGalaxyCluster:
        course_of_action_args = self._create_cluster_args(
            course_of_action, galaxy_type, description=description
        )
        meta = self._handle_meta_fields(course_of_action)
        if hasattr(course_of_action, 'external_references'):
            meta.update(
                self._handle_external_references(
                    course_of_action.external_references
                )
            )
        if meta.get('external_id'):
            self._handle_cluster_value(
                course_of_action_args, meta['external_id']
            )
        if meta:
            course_of_action_args['meta'] = meta
        return self.main_parser._create_misp_galaxy_cluster(
            **course_of_action_args
        )

    def _parse_course_of_action_object(
            self, course_of_action: _COURSE_OF_ACTION_TYPING):
        misp_object = self._create_misp_object(
            'course-of-action', course_of_action
        )
        for attribute in self._generic_parser(course_of_action):
            misp_object.add_attribute(**attribute)
        self.main_parser._add_misp_object(misp_object, course_of_action)
