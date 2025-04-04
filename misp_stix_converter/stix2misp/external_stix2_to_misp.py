#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .exceptions import UnknownParsingFunctionError, UnknownStixObjectTypeError
from .external_stix2_mapping import ExternalSTIX2toMISPMapping
from .converters import (
    ExternalSTIX2AttackPatternConverter, ExternalSTIX2CampaignConverter,
    ExternalSTIX2CourseOfActionConverter, ExternalSTIX2IdentityConverter,
    ExternalSTIX2IndicatorConverter, ExternalSTIX2IntrusionSetConverter,
    ExternalSTIX2LocationConverter, ExternalSTIX2MalwareAnalysisConverter,
    ExternalSTIX2MalwareConverter, ExternalSTIX2ObservedDataConverter,
    ExternalSTIX2ThreatActorConverter, ExternalSTIX2ToolConverter,
    ExternalSTIX2VulnerabilityConverter, STIX2ObservableObjectConverter)
from .importparser import ExternalSTIXtoMISPParser
from .stix2_to_misp import STIX2toMISPParser, _OBSERVABLE_TYPING
from collections import defaultdict
from pymisp import MISPAttribute, MISPObject
from stix2.v20.sro import Sighting as Sighting_v20
from stix2.v21.sdo import Note, Opinion
from stix2.v21.sro import Sighting as Sighting_v21
from typing import Optional, Union

_SIGHTING_TYPING = Union[Sighting_v20, Sighting_v21]


class ExternalSTIX2toMISPParser(STIX2toMISPParser, ExternalSTIXtoMISPParser):
    def __init__(self):
        super().__init__()
        self._mapping = ExternalSTIX2toMISPMapping
        # parsers
        self._attack_pattern_parser: ExternalSTIX2AttackPatternConverter
        self._campaign_parser: ExternalSTIX2CampaignConverter
        self._course_of_action_parser: ExternalSTIX2CourseOfActionConverter
        self._identity_parser: ExternalSTIX2IdentityConverter
        self._indicator_parser: ExternalSTIX2IndicatorConverter
        self._intrusion_set_parser: ExternalSTIX2IntrusionSetConverter
        self._location_parser: ExternalSTIX2LocationConverter
        self._malware_analysis_parser: ExternalSTIX2MalwareAnalysisConverter
        self._malware_parser: ExternalSTIX2MalwareConverter
        self._observable_object_parser: STIX2ObservableObjectConverter
        self._observed_data_parser: ExternalSTIX2ObservedDataConverter
        self._threat_actor_parser: ExternalSTIX2ThreatActorConverter
        self._tool_parser: ExternalSTIX2ToolConverter
        self._vulnerability_parser: ExternalSTIX2VulnerabilityConverter

    def parse_stix_bundle(
            self, cluster_distribution: Optional[int] = 0,
            cluster_sharing_group_id: Optional[int] = None,
            organisation_uuid: Optional[str] = None, **kwargs):
        self._set_parameters(**kwargs)
        self._set_cluster_distribution(
            cluster_distribution, cluster_sharing_group_id
        )
        self._set_organisation_uuid(organisation_uuid)
        self._parse_stix_bundle()

    ############################################################################
    #                                PROPERTIES                                #
    ############################################################################

    @property
    def attack_pattern_parser(self) -> ExternalSTIX2AttackPatternConverter:
        if not hasattr(self, '_attack_pattern_parser'):
            self._attack_pattern_parser = ExternalSTIX2AttackPatternConverter(self)
        return self._attack_pattern_parser

    @property
    def campaign_parser(self) -> ExternalSTIX2CampaignConverter:
        if not hasattr(self, '_campaign_parser'):
            self._campaign_parser = ExternalSTIX2CampaignConverter(self)
        return self._campaign_parser

    @property
    def course_of_action_parser(self) -> ExternalSTIX2CourseOfActionConverter:
        if not hasattr(self, '_course_of_action_parser'):
            self._course_of_action_parser = ExternalSTIX2CourseOfActionConverter(self)
        return self._course_of_action_parser

    @property
    def identity_parser(self) -> ExternalSTIX2IdentityConverter:
        if not hasattr(self, '_identity_parser'):
            self._identity_parser = ExternalSTIX2IdentityConverter(self)
        return self._identity_parser

    @property
    def indicator_parser(self) -> ExternalSTIX2IndicatorConverter:
        if not hasattr(self, '_indicator_parser'):
            self._indicator_parser = ExternalSTIX2IndicatorConverter(self)
        return self._indicator_parser

    @property
    def intrusion_set_parser(self) -> ExternalSTIX2IntrusionSetConverter:
        if not hasattr(self, '_intrusion_set_parser'):
            self._intrusion_set_parser = ExternalSTIX2IntrusionSetConverter(self)
        return self._intrusion_set_parser

    @property
    def location_parser(self) -> ExternalSTIX2LocationConverter:
        if not hasattr(self, '_location_parser'):
            self._location_parser = ExternalSTIX2LocationConverter(self)
        return self._location_parser

    @property
    def malware_analysis_parser(self) -> ExternalSTIX2MalwareAnalysisConverter:
        if not hasattr(self, '_malware_analysis_parser'):
            self._malware_analysis_parser = ExternalSTIX2MalwareAnalysisConverter(self)
        return self._malware_analysis_parser

    @property
    def malware_parser(self) -> ExternalSTIX2MalwareConverter:
        if not hasattr(self, '_malware_parser'):
            self._malware_parser = ExternalSTIX2MalwareConverter(self)
        return self._malware_parser

    @property
    def observable_object_parser(self) -> STIX2ObservableObjectConverter:
        if not hasattr(self, '_observable_object_parser'):
            self._observable_object_parser = STIX2ObservableObjectConverter(self)
        return self._observable_object_parser

    @property
    def observed_data_parser(self) -> ExternalSTIX2ObservedDataConverter:
        if not hasattr(self, '_observed_data_parser'):
            self._observed_data_parser = ExternalSTIX2ObservedDataConverter(self)
        return self._observed_data_parser

    @property
    def threat_actor_parser(self) -> ExternalSTIX2ThreatActorConverter:
        if not hasattr(self, '_threat_actor_parser'):
            self._threat_actor_parser = ExternalSTIX2ThreatActorConverter(self)
        return self._threat_actor_parser

    @property
    def tool_parser(self) -> ExternalSTIX2ToolConverter:
        if not hasattr(self, '_tool_parser'):
            self._tool_parser = ExternalSTIX2ToolConverter(self)
        return self._tool_parser

    @property
    def vulnerability_parser(self) -> ExternalSTIX2VulnerabilityConverter:
        if not hasattr(self, '_vulnerability_parser'):
            self._vulnerability_parser = ExternalSTIX2VulnerabilityConverter(self)
        return self._vulnerability_parser

    ############################################################################
    #                       STIX OBJECTS LOADING METHODS                       #
    ############################################################################

    def _load_analyst_note(self, note: Note):
        note_dict = self._parse_analyst_note(note)
        if len(note.object_refs) == 1:
            note_dict['uuid'] = self._sanitise_uuid(note.id)
        for object_ref in note.object_refs:
            self._analyst_data[object_ref].append(note.id)
        super()._load_note(note.id, note_dict)

    def _load_analyst_opinion(self, opinion: Opinion):
        opinion_dict = {
            'opinion': self._mapping.opinion_mapping(opinion.opinion),
            **self._parse_analyst_opinion(opinion)
        }
        if len(opinion.object_refs) == 1:
            opinion_dict['uuid'] = self._sanitise_uuid(opinion.id)
        for object_ref in opinion.object_refs:
            self._analyst_data[object_ref].append(opinion.id)
        super()._load_opinion(opinion.id, opinion_dict)

    def _load_observable_object(self, observable: _OBSERVABLE_TYPING):
        self._check_uuid(observable.id)
        to_load = {'used': {}, 'observable': observable}
        try:
            self._observable[observable.id] = to_load
        except AttributeError:
            self._observable = {observable.id: to_load}

    def _load_sighting(self, sighting: _SIGHTING_TYPING):
        sighting_of_ref = self._sanitise_uuid(sighting.sighting_of_ref)
        try:
            self._sighting[sighting_of_ref].append(sighting)
        except AttributeError:
            self._sighting = defaultdict(list)
            self._sighting[sighting_of_ref].append(sighting)

    ############################################################################
    #                    MAIN STIX OBJECTS PARSING METHODS.                    #
    ############################################################################

    def _handle_attribute_sightings(self, attribute: MISPAttribute):
        attribute_uuid = attribute.uuid
        if attribute_uuid in self.replacement_uuids:
            attribute_uuid = self.replacement_uuids[attribute_uuid]
        if attribute_uuid in self._sighting:
            for sighting in self._sighting[attribute_uuid]:
                misp_sighting = self._parse_sighting(sighting)
                if misp_sighting is not None:
                    attribute.add_sighting(misp_sighting)

    def _handle_object_refs(self, object_refs: list):
        for object_ref in object_refs:
            object_type = object_ref.split('--')[0]
            if object_type in self._mapping.object_type_refs_to_skip():
                continue
            if object_type in self._mapping.observable_object_types():
                if self._observable.get(object_ref) is not None:
                    observable = self._observable[object_ref]
                    if self.misp_event.uuid not in observable['used']:
                        observable['used'][self.misp_event.uuid] = False
                continue
            try:
                self._handle_object(object_type, object_ref)
            except UnknownStixObjectTypeError as error:
                self._unknown_stix_object_type_error(error)
            except UnknownParsingFunctionError as error:
                self._unknown_parsing_function_error(error)

    def _handle_object_sightings(self, misp_object: MISPObject):
        object_uuid = misp_object.uuid
        if object_uuid in self.replacement_uuids:
            object_uuid = self.replacement_uuids[object_uuid]
        if object_uuid in self._sighting:
            for sighting in self._sighting[object_uuid]:
                misp_sighting = self._parse_sighting(sighting)
                if misp_sighting is not None:
                    for attribute in misp_object.attributes:
                        attribute.add_sighting(misp_sighting)

    def _handle_unparsed_content(self):
        if not hasattr(self, '_observable'):
            return super()._handle_unparsed_content()
        unparsed_content = defaultdict(list)
        for object_id, content in self._observable.items():
            if content['used'].get(self.misp_event.uuid, True):
                continue
            unparsed_content[content['observable'].type].append(object_id)
        for observable_type in self._mapping.observable_object_types():
            if observable_type not in unparsed_content:
                continue
            feature = self._mapping.observable_mapping(observable_type)
            if feature is None:
                observable_id = unparsed_content[observable_type][0]
                self._add_error(
                    f'Unable to map observable object with id {observable_id}'
                )
                continue
            to_call = f'_parse_{feature}_observable_object'
            for object_id in unparsed_content[observable_type]:
                if self.misp_event.uuid in self._observable[object_id]['used']:
                    if self._observable[object_id]['used'][self.misp_event.uuid]:
                        continue
                try:
                    getattr(self.observable_object_parser, to_call)(object_id)
                except Exception as exception:
                    _traceback = self._parse_traceback(exception)
                    self._add_error(
                        'Error parsing the Observable object with id '
                        f'{object_id}: {_traceback}'
                    )
        super()._handle_unparsed_content()

    def _parse_loaded_features(self):
        if hasattr(self, '_observable'):
            for observable in self._observable.values():
                observable['used'][self.misp_event.uuid] = False
        super()._parse_loaded_features()
