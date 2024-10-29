#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .exceptions import UnknownParsingFunctionError, UnknownStixObjectTypeError
from .internal_stix2_mapping import InternalSTIX2toMISPMapping
from .converters import (
    InternalSTIX2AttackPatternConverter, InternalSTIX2CampaignConverter,
    InternalSTIX2CourseOfActionConverter, InternalSTIX2IdentityConverter,
    InternalSTIX2IndicatorConverter, InternalSTIX2IntrusionSetConverter,
    InternalSTIX2LocationConverter, InternalSTIX2MalwareAnalysisConverter,
    InternalSTIX2MalwareConverter, InternalSTIX2NoteConverter,
    InternalSTIX2ObservedDataConverter, InternalSTIX2ThreatActorConverter,
    InternalSTIX2ToolConverter, InternalSTIX2VulnerabilityConverter,
    STIX2CustomObjectConverter)
from .stix2_to_misp import STIX2toMISPParser, _OBSERVABLE_TYPING
from collections import defaultdict
from pymisp import MISPAttribute, MISPEventReport, MISPObject, MISPSighting
from stix2.v20.sdo import CustomObject as CustomObject_v20
from stix2.v20.sro import Sighting as Sighting_v20
from stix2.v21.sdo import CustomObject as CustomObject_v21, Note, Opinion
from stix2.v21.sro import Sighting as Sighting_v21
from typing import Union

_CUSTOM_TYPING = Union[
    CustomObject_v20,
    CustomObject_v21
]
_SIGHTING_TYPING = Union[
    Sighting_v20, Sighting_v21
]


class InternalSTIX2toMISPParser(STIX2toMISPParser):
    def __init__(self):
        super().__init__()
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
        self._note_parser: InternalSTIX2NoteConverter
        self._observed_data_parser: InternalSTIX2ObservedDataConverter
        self._threat_actor_parser: InternalSTIX2ThreatActorConverter
        self._tool_parser: InternalSTIX2ToolConverter
        self._vulnerability_parser: InternalSTIX2VulnerabilityConverter

    def parse_stix_bundle(self, **kwargs):
        self._set_parameters(**kwargs)
        self._parse_stix_bundle()

    ############################################################################
    #                                PROPERTIES                                #
    ############################################################################

    @property
    def attack_pattern_parser(self) -> InternalSTIX2AttackPatternConverter:
        if not hasattr(self, '_attack_pattern_parser'):
            self._attack_pattern_parser = InternalSTIX2AttackPatternConverter(self)
        return self._attack_pattern_parser

    @property
    def campaign_parser(self) -> InternalSTIX2CampaignConverter:
        if not hasattr(self, '_campaign_parser'):
            self._campaign_parser = InternalSTIX2CampaignConverter(self)
        return self._campaign_parser

    @property
    def course_of_action_parser(self) -> InternalSTIX2CourseOfActionConverter:
        if not hasattr(self, '_course_of_action_parser'):
            self._course_of_action_parser = InternalSTIX2CourseOfActionConverter(self)
        return self._course_of_action_parser

    @property
    def custom_object_parser(self) -> STIX2CustomObjectConverter:
        if not hasattr(self, '_custom_object_parser'):
            self._custom_object_parser = STIX2CustomObjectConverter(self)
        return self._custom_object_parser

    @property
    def identity_parser(self) -> InternalSTIX2IdentityConverter:
        if not hasattr(self, '_identity_parser'):
            self._identity_parser = InternalSTIX2IdentityConverter(self)
        return self._identity_parser

    @property
    def indicator_parser(self) -> InternalSTIX2IndicatorConverter:
        if not hasattr(self, '_indicator_parser'):
            self._indicator_parser = InternalSTIX2IndicatorConverter(self)
        return self._indicator_parser

    @property
    def intrusion_set_parser(self) -> InternalSTIX2IntrusionSetConverter:
        if not hasattr(self, '_intrusion_set_parser'):
            self._intrusion_set_parser = InternalSTIX2IntrusionSetConverter(self)
        return self._intrusion_set_parser

    @property
    def location_parser(self) -> InternalSTIX2LocationConverter:
        if not hasattr(self, '_location_parser'):
            self._location_parser = InternalSTIX2LocationConverter(self)
        return self._location_parser

    @property
    def malware_analysis_parser(self) -> InternalSTIX2MalwareAnalysisConverter:
        if not hasattr(self, '_malware_analysis_parser'):
            self._malware_analysis_parser = InternalSTIX2MalwareAnalysisConverter(self)
        return self._malware_analysis_parser

    @property
    def malware_parser(self) -> InternalSTIX2MalwareConverter:
        if not hasattr(self, '_malware_parser'):
            self._malware_parser = InternalSTIX2MalwareConverter(self)
        return self._malware_parser

    @property
    def note_parser(self) -> InternalSTIX2NoteConverter:
        if not hasattr(self, 'note_parser_'):
            self._note_parser = InternalSTIX2NoteConverter(self)
        return self._note_parser

    @property
    def observed_data_parser(self) -> InternalSTIX2ObservedDataConverter:
        if not hasattr(self, '_observed_data_parser'):
            self._observed_data_parser = InternalSTIX2ObservedDataConverter(self)
        return self._observed_data_parser

    @property
    def threat_actor_parser(self) -> InternalSTIX2ThreatActorConverter:
        if not hasattr(self, '_threat_actor_parser'):
            self._threat_actor_parser = InternalSTIX2ThreatActorConverter(self)
        return self._threat_actor_parser

    @property
    def tool_parser(self) -> InternalSTIX2ToolConverter:
        if not hasattr(self, '_tool_parser'):
            self._tool_parser = InternalSTIX2ToolConverter(self)
        return self._tool_parser

    @property
    def vulnerability_parser(self) -> InternalSTIX2VulnerabilityConverter:
        if not hasattr(self, '_vulnerability_parser'):
            self._vulnerability_parser = InternalSTIX2VulnerabilityConverter(self)
        return self._vulnerability_parser

    ############################################################################
    #                       STIX OBJECTS LOADING METHODS                       #
    ############################################################################

    def _load_analyst_note(self, note: CustomObject_v20):
        note_dict = {
            'created': note.created, 'modified': note.modified,
            'note': note.x_misp_note, 'uuid': self._sanitise_uuid(note.id)
        }
        if hasattr(note, 'x_misp_author'):
            note_dict['authors'] = note.x_misp_author
        if hasattr(note, 'x_misp_language'):
            note_dict['language'] = note.x_misp_language
        self._analyst_data[note.object_ref].append(note.id)
        super()._load_note(note.id, note_dict)

    def _load_analyst_opinion(self, opinion: CustomObject_v20):
        opinion_dict = {
            'comment': getattr(opinion, 'x_misp_comment', ''),
            'created': opinion.created, 'modified': opinion.modified,
            'opinion': opinion.x_misp_opinion,
            'uuid': self._sanitise_uuid(opinion.id)
        }
        if hasattr(opinion, 'x_misp_author'):
            opinion_dict['authors'] = opinion.x_misp_author
        self._analyst_data[opinion.object_ref].append(opinion.id)
        super()._load_opinion(opinion.id, opinion_dict)

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

    def _load_note(self, note: Note):
        if 'misp:context-layer="Analyst Note"' in getattr(note, 'labels', []):
            note_dict = {
                'uuid': self._sanitise_uuid(note.id),
                **self._parse_analyst_note(note)
            }
            self._analyst_data[note.object_refs[0]].append(note.id)
            super()._load_note(note.id, note_dict)
        else:
            self._check_uuid(note.id)
            super()._load_note(note.id, note)

    def _load_observable_object(self, observable: _OBSERVABLE_TYPING):
        self._check_uuid(observable.id)
        try:
            self._observable[observable.id] = observable
        except AttributeError:
            self._observable = {observable.id: observable}

    def _load_opinion(self, opinion: Opinion):
        if 'misp:context-layer="Analyst Opinion"' in getattr(opinion, 'labels', []):
            opinion_dict = {
                'opinion': opinion.x_misp_opinion,
                'uuid': self._sanitise_uuid(opinion.id),
                **self._parse_analyst_opinion(opinion)
            }
            self._analyst_data[opinion.object_refs[0]].append(opinion.id)
            super()._load_opinion(opinion.id, opinion_dict)
        else:
            object_ref = self._sanitise_uuid(opinion.object_refs[0])
            try:
                self._sighting['opinion'][object_ref].append(opinion)
            except AttributeError:
                self._sighting = defaultdict(lambda: defaultdict(list))
                self._sighting['opinion'][object_ref].append(opinion)

    def _load_sighting(self, sighting: _SIGHTING_TYPING):
        sighting_of_ref = self._sanitise_uuid(sighting.sighting_of_ref)
        try:
            self._sighting['sighting'][sighting_of_ref].append(sighting)
        except AttributeError:
            self._sighting = defaultdict(lambda: defaultdict(list))
            self._sighting['sighting'][sighting_of_ref].append(sighting)

    ############################################################################
    #                    MAIN STIX OBJECTS PARSING METHODS.                    #
    ############################################################################

    def _handle_attribute_sightings(self, attribute: MISPAttribute):
        attribute_uuid = attribute.uuid
        if attribute_uuid in self.replacement_uuids:
            attribute_uuid = self.replacement_uuids[attribute_uuid]
        if attribute_uuid in self._sighting.get('sighting', {}):
            for sighting in self._sighting['sighting'][attribute_uuid]:
                attribute.add_sighting(self._parse_sighting(sighting))
        if attribute_uuid in self._sighting.get('opinion', {}):
            for opinion in self._sighting['opinion'][attribute_uuid]:
                attribute.add_sighting(self._parse_opinion(opinion))
        elif attribute_uuid in self._sighting.get('custom_opinion', {}):
            for sighting in self._sighting['custom_opinion'][attribute_uuid]:
                attribute.add_sighting(sighting)

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

    def _handle_object_sightings(self, misp_object: MISPObject):
        object_uuid = misp_object.uuid
        if object_uuid in self.replacement_uuids:
            object_uuid = self.replacement_uuids[object_uuid]
        if object_uuid in self._sighting.get('sighting', {}):
            for sighting in self._sighting['sighting'][object_uuid]:
                misp_sighting = self._parse_sighting(sighting)
                for attribute in misp_object.attributes:
                    attribute.add_sighting(misp_sighting)
        if object_uuid in self._sighting.get('opinion', {}):
            for sighting in self._sighting['opinion'][object_uuid]:
                misp_sighting = self._parse_opinion(sighting)
                for attribute in misp_object.attributes:
                    attribute.add_sighting(misp_sighting)
        elif misp_object.uuid in self._sighting.get('custom_opinion', {}):
            for sighting in self._sighting['custom_opinion'][object_uuid]:
                for attribute in misp_object.attributes:
                    attribute.add_sighting(sighting)

    def _parse_opinion(self, opinion: Opinion) -> MISPSighting:
        misp_sighting = MISPSighting()
        sighting_args = {
            'date_sighting': self._timestamp_from_date(opinion.modified),
            'type': '1' if 'disagree' in opinion.opinion else '0'
        }
        if hasattr(opinion, 'x_misp_source'):
            sighting_args['source'] = opinion.x_misp_source
        if hasattr(opinion, 'x_misp_author_ref'):
            identity = self._identity[opinion.x_misp_author_ref]
            sighting_args['Organisation'] = {
                'uuid': self._sanitise_uuid(identity.id),
                'name': identity.name
            }
        misp_sighting.from_dict(**sighting_args)
        return misp_sighting

    ############################################################################
    #                      MISP FEATURES CREATION METHODS                      #
    ############################################################################

    def _add_event_report(
            self, event_report: MISPEventReport, stix_object_id: str):
        if stix_object_id in self._analyst_data:
            for reference in self._analyst_data[stix_object_id]:
                self._add_analyst_data(event_report, reference)
        self.misp_event.add_event_report(**event_report)
