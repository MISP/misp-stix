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

    def parse_stix_bundle(self, cluster_distribution: Optional[int] = 0,
                          cluster_sharing_group_id: Optional[int] = None,
                          organisation_uuid: Optional[str] = None, **kwargs):
        self._set_parameters(**kwargs)
        self._set_cluster_distribution(
            cluster_distribution, cluster_sharing_group_id
        )
        self._set_organisation_uuid(organisation_uuid)
        self._parse_stix_bundle()

    @property
    def observable_object_parser(self) -> STIX2ObservableObjectConverter:
        if not hasattr(self, '_observable_object_parser'):
            self._set_observable_object_parser()
        return self._observable_object_parser

    ############################################################################
    #                              PARSER SETTERS                              #
    ############################################################################

    def _set_attack_pattern_parser(self):
        self._attack_pattern_parser = ExternalSTIX2AttackPatternConverter(self)

    def _set_campaign_parser(self):
        self._campaign_parser = ExternalSTIX2CampaignConverter(self)

    def _set_course_of_action_parser(self):
        self._course_of_action_parser = ExternalSTIX2CourseOfActionConverter(self)

    def _set_identity_parser(self):
        self._identity_parser = ExternalSTIX2IdentityConverter(self)

    def _set_indicator_parser(self):
        self._indicator_parser = ExternalSTIX2IndicatorConverter(self)

    def _set_intrusion_set_parser(self):
        self._intrusion_set_parser = ExternalSTIX2IntrusionSetConverter(self)

    def _set_location_parser(self):
        self._location_parser = ExternalSTIX2LocationConverter(self)

    def _set_malware_analysis_parser(self):
        self._malware_analysis_parser = ExternalSTIX2MalwareAnalysisConverter(self)

    def _set_malware_parser(self):
        self._malware_parser = ExternalSTIX2MalwareConverter(self)

    def _set_observable_object_parser(self):
        self._observable_object_parser = STIX2ObservableObjectConverter(self)

    def _set_observed_data_parser(self):
        self._observed_data_parser = ExternalSTIX2ObservedDataConverter(self)

    def _set_threat_actor_parser(self):
        self._threat_actor_parser = ExternalSTIX2ThreatActorConverter(self)

    def _set_tool_parser(self):
        self._tool_parser = ExternalSTIX2ToolConverter(self)

    def _set_vulnerability_parser(self):
        self._vulnerability_parser = ExternalSTIX2VulnerabilityConverter(self)

    ############################################################################
    #                       STIX OBJECTS LOADING METHODS                       #
    ############################################################################

    def _load_analyst_note(self, note: Note):
        note_dict = self._parse_analyst_note(note)
        note_ref = self._sanitise_uuid(note.id)
        for object_ref in note.object_refs:
            referenced = self._sanitise_uuid(object_ref)
            self._analyst_data[referenced].append(note_ref)
        if len(note.object_refs) == 1:
            note_dict.update({'object_uuid': referenced, 'uuid': note_ref})
        super()._load_note(note_ref, note_dict)
        try:
            self._note[note_ref] = note_dict
        except AttributeError:
            self._note = {note_ref: note_dict}

    def _load_analyst_opinion(self, opinion: Opinion):
        opinion_dict = self._parse_analyst_opinion(opinion)
        opinion_dict['opinion'] = self._mapping.opinion_mapping(opinion.opinion)
        opinion_ref = self._sanitise_uuid(opinion.id)
        for object_ref in opinion.object_refs:
            referenced = self._sanitise_uuid(object_ref)
            self._analyst_data[referenced].append(opinion_ref)
        if len(opinion.object_refs) == 1:
            opinion_dict.update(
                {'object_uuid': referenced, 'uuid': opinion_ref}
            )
        super()._load_opinion(opinion_ref, opinion_dict)

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
                attribute.add_sighting(self._parse_sighting(sighting))

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
                for attribute in misp_object.attributes:
                    attribute.add_sighting(misp_sighting)

    def _handle_unparsed_content(self):
        if not hasattr(self, '_observable'):
            return super()._handle_unparsed_content()
        unparsed_content = defaultdict(list)
        for object_id, content in self._observable.items():
            if content['used'][self.misp_event.uuid]:
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
                if self._observable[object_id]['used'][self.misp_event.uuid]:
                    # if object_id.split('--')[0] not in _force_observables_list:
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
