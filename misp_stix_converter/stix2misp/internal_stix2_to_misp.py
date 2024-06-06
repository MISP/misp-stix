#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .exceptions import UnknownParsingFunctionError, UnknownStixObjectTypeError
from .internal_stix2_mapping import InternalSTIX2toMISPMapping
from .converters import (
    InternalSTIX2AttackPatternConverter, InternalSTIX2CampaignConverter,
    InternalSTIX2CourseOfActionConverter, InternalSTIX2IdentityConverter,
    InternalSTIX2IndicatorConverter, InternalSTIX2IntrusionSetConverter,
    InternalSTIX2LocationConverter, InternalSTIX2MalwareAnalysisConverter,
    InternalSTIX2MalwareConverter, InternalSTIX2ObservedDataConverter,
    InternalSTIX2ThreatActorConverter, InternalSTIX2ToolConverter,
    InternalSTIX2VulnerabilityConverter, STIX2CustomObjectConverter,
    STIX2NoteConverter)
from .stix2_to_misp import STIX2toMISPParser, _OBSERVABLE_TYPING
from collections import defaultdict
from pymisp import MISPSighting
from stix2.v20.sdo import CustomObject as CustomObject_v20
from stix2.v21.sdo import CustomObject as CustomObject_v21
from typing import Optional, Union

_CUSTOM_TYPING = Union[
    CustomObject_v20,
    CustomObject_v21
]


class InternalSTIX2toMISPParser(STIX2toMISPParser):
    def __init__(self, distribution: Optional[int] = 0,
                 sharing_group_id: Optional[int] = None,
                 galaxies_as_tags: Optional[bool] = False):
        super().__init__(distribution, sharing_group_id, galaxies_as_tags)
        self._mapping = InternalSTIX2toMISPMapping
        # parsers
        self._attack_pattern_parser: InternalSTIX2AttackPatternConverter
        self._campaign_parser: InternalSTIX2CampaignConverter
        self._course_of_action_parser: InternalSTIX2CourseOfActionConverter
        self._custom_object_parser: STIX2CustomObjectConverter
        self._identity_parser: InternalSTIX2IdentityConverter
        self._indicator_parser: InternalSTIX2IndicatorConverter
        self._intrusion_set_parser: InternalSTIX2IntrusionSetConverter
        self._location_parser: InternalSTIX2LocationConverter
        self._malware_analysis_parser: InternalSTIX2MalwareAnalysisConverter
        self._malware_parser: InternalSTIX2MalwareConverter
        self._note_parser: STIX2NoteConverter
        self._observed_data_parser: InternalSTIX2ObservedDataConverter
        self._threat_actor_parser: InternalSTIX2ThreatActorConverter
        self._tool_parser: InternalSTIX2ToolConverter
        self._vulnerability_parser: InternalSTIX2VulnerabilityConverter

    @property
    def custom_object_parser(self) -> STIX2CustomObjectConverter:
        if not hasattr(self, '_custom_object_parser'):
            self._set_custom_object_parser()
        return self._custom_object_parser

    @property
    def note_parser(self) -> STIX2NoteConverter:
        if not hasattr(self, '_note_parser'):
            self._set_note_parser()
        return self._note_parser

    @property
    def observed_data_parser(self) -> InternalSTIX2ObservedDataConverter:
        return getattr(
            self, '_observed_data_parser', self._set_observed_data_parser()
        )

    def _set_attack_pattern_parser(self) -> InternalSTIX2AttackPatternConverter:
        self._attack_pattern_parser = InternalSTIX2AttackPatternConverter(self)

    def _set_campaign_parser(self) -> InternalSTIX2CampaignConverter:
        self._campaign_parser = InternalSTIX2CampaignConverter(self)

    def _set_course_of_action_parser(self) -> InternalSTIX2CourseOfActionConverter:
        self._course_of_action_parser = InternalSTIX2CourseOfActionConverter(self)

    def _set_custom_object_parser(self) -> STIX2CustomObjectConverter:
        self._custom_object_parser = STIX2CustomObjectConverter(self)

    def _set_identity_parser(self) -> InternalSTIX2IdentityConverter:
        self._identity_parser = InternalSTIX2IdentityConverter(self)

    def _set_indicator_parser(self) -> InternalSTIX2IndicatorConverter:
        self._indicator_parser = InternalSTIX2IndicatorConverter(self)

    def _set_intrusion_set_parser(self) -> InternalSTIX2IntrusionSetConverter:
        self._intrusion_set_parser = InternalSTIX2IntrusionSetConverter(self)

    def _set_location_parser(self) -> InternalSTIX2LocationConverter:
        self._location_parser = InternalSTIX2LocationConverter(self)

    def _set_malware_analysis_parser(self) -> InternalSTIX2MalwareAnalysisConverter:
        self._malware_analysis_parser = InternalSTIX2MalwareAnalysisConverter(self)

    def _set_malware_parser(self) -> InternalSTIX2MalwareConverter:
        self._malware_parser = InternalSTIX2MalwareConverter(self)

    def _set_note_parser(self) -> STIX2NoteConverter:
        self._note_parser = STIX2NoteConverter(self)

    def _set_observed_data_parser(self) -> InternalSTIX2ObservedDataConverter:
        self._observed_data_parser = InternalSTIX2ObservedDataConverter(self)
        return self._observed_data_parser

    def _set_threat_actor_parser(self) -> InternalSTIX2ThreatActorConverter:
        self._threat_actor_parser = InternalSTIX2ThreatActorConverter(self)

    def _set_tool_parser(self) -> InternalSTIX2ToolConverter:
        self._tool_parser = InternalSTIX2ToolConverter(self)

    def _set_vulnerability_parser(self) -> InternalSTIX2VulnerabilityConverter:
        self._vulnerability_parser = InternalSTIX2VulnerabilityConverter(self)

    ############################################################################
    #                       STIX OBJECTS LOADING METHODS                       #
    ############################################################################

    def _load_custom_attribute(self, custom_attribute: _CUSTOM_TYPING):
        self._check_uuid(custom_attribute.id)
        try:
            self._custom_attribute[custom_attribute.id] = custom_attribute
        except AttributeError:
            self._custom_attribute = {custom_attribute.id: custom_attribute}

    def _load_custom_galaxy_cluster(self, custom_galaxy: _CUSTOM_TYPING):
        self._check_uuid(custom_galaxy.id)
        try:
            self._custom_galaxy_cluster[custom_galaxy.id] = custom_galaxy
        except AttributeError:
            self._custom_galaxy_cluster = {custom_galaxy.id: custom_galaxy}

    def _load_custom_object(self, custom_object: _CUSTOM_TYPING):
        self._check_uuid(custom_object.id)
        try:
            self._custom_object[custom_object.id] = custom_object
        except AttributeError:
            self._custom_object = {custom_object.id: custom_object}

    def _load_custom_opinion(self, custom_object: CustomObject_v20):
        sighting = MISPSighting()
        sighting_args = {
            'date_sighting': self._timestamp_from_date(custom_object.modified),
            'type': '1'
        }
        if hasattr(custom_object, 'x_misp_source'):
            sighting_args['source'] = custom_object.x_misp_source
        if hasattr(custom_object, 'x_misp_author'):
            sighting_args['Organisation'] = {
                'uuid': custom_object.x_misp_author_ref.split('--')[1],
                'name': custom_object.x_misp_author
            }
        sighting.from_dict(**sighting_args)
        object_ref = self._sanitise_uuid(custom_object.object_ref)
        try:
            self._sighting['custom_opinion'][object_ref].append(sighting)
        except AttributeError:
            self._sighting = defaultdict(lambda: defaultdict(list))
            self._sighting['custom_opinion'][object_ref].append(sighting)

    def _load_observable_object(self, observable: _OBSERVABLE_TYPING):
        self._check_uuid(observable.id)
        try:
            self._observable[observable.id] = observable
        except AttributeError:
            self._observable = {observable.id: observable}

    ############################################################################
    #                    MAIN STIX OBJECTS PARSING METHODS.                    #
    ############################################################################

    def _handle_object_refs(self, object_refs: list):
        for object_ref in object_refs:
            object_type = object_ref.split('--')[0]
            if object_type in self._mapping.object_type_refs_to_skip():
                continue
            try:
                self._handle_object(object_type, object_ref)
            except UnknownStixObjectTypeError as error:
                self._unknown_stix_object_type_error(error)
            except UnknownParsingFunctionError as error:
                self._unknown_parsing_function_error(error)
