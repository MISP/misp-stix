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
    InternalSTIX2ObservableConverter, InternalSTIX2ObservedDataConverter,
    InternalSTIX2ThreatActorConverter, InternalSTIX2ToolConverter,
    InternalSTIX2VulnerabilityConverter, STIX2CustomObjectConverter)
from .stix2_to_misp import (
    STIX2toMISPParser, _BUNDLE_TYPING, _OBSERVABLE_TYPING, _SDO_TYPING)
from collections import defaultdict
from pymisp import (
    MISPAttribute, MISPEvent, MISPEventReport, MISPGalaxy, MISPObject, MISPSighting)
from stix2.v20.sdo import CustomObject as CustomObject_v20
from stix2.v20.sro import Sighting as Sighting_v20
from stix2.v21.sdo import CustomObject as CustomObject_v21, Note, Opinion
from stix2.v21.sro import Sighting as Sighting_v21
from typing import Iterator, Union

_STORAGE_VARIABLE_NAMES = ('_indicator', '_observed_data')

_CUSTOM_TYPING = Union[
    CustomObject_v20,
    CustomObject_v21
]
_SIGHTING_TYPING = Union[
    Sighting_v20, Sighting_v21
]


class InternalSTIX2toMISPParser(STIX2toMISPParser):
    _CONVERTER_CLASSES = {
        'attack-pattern': InternalSTIX2AttackPatternConverter,
        'campaign': InternalSTIX2CampaignConverter,
        'course-of-action': InternalSTIX2CourseOfActionConverter,
        'identity': InternalSTIX2IdentityConverter,
        'indicator': InternalSTIX2IndicatorConverter,
        'intrusion-set': InternalSTIX2IntrusionSetConverter,
        'location': InternalSTIX2LocationConverter,
        'malware': InternalSTIX2MalwareConverter,
        'malware-analysis': InternalSTIX2MalwareAnalysisConverter,
        'note': InternalSTIX2NoteConverter,
        'observable': InternalSTIX2ObservableConverter,
        'observed-data': InternalSTIX2ObservedDataConverter,
        'threat-actor': InternalSTIX2ThreatActorConverter,
        'tool': InternalSTIX2ToolConverter,
        'vulnerability': InternalSTIX2VulnerabilityConverter,
        'x-misp-attribute': STIX2CustomObjectConverter,
        'x-misp-event-report': STIX2CustomObjectConverter,
        'x-misp-galaxy-cluster': STIX2CustomObjectConverter,
        'x-misp-object': STIX2CustomObjectConverter,
    }

    def __init__(self):
        super().__init__()
        self._mapping = InternalSTIX2toMISPMapping

    def parse_stix_bundle(self, **kwargs):
        self._set_parameters(**kwargs)
        self._parse_stix_bundle()

    def _load_stix_bundle(self, bundle: _BUNDLE_TYPING) -> int:
        for stix_object in bundle.objects:
            self._load_stix_object(stix_object)

    ############################################################################
    #                                PROPERTIES                                #
    ############################################################################

    @property
    def attack_pattern_parser(self) -> InternalSTIX2AttackPatternConverter:
        return self._get_converter('attack-pattern')

    @property
    def campaign_parser(self) -> InternalSTIX2CampaignConverter:
        return self._get_converter('campaign')

    @property
    def course_of_action_parser(self) -> InternalSTIX2CourseOfActionConverter:
        return self._get_converter('course-of-action')

    @property
    def custom_object_parser(self) -> STIX2CustomObjectConverter:
        return self._get_converter('x-misp-attribute')

    @property
    def identity_parser(self) -> InternalSTIX2IdentityConverter:
        return self._get_converter('identity')

    @property
    def indicator_parser(self) -> InternalSTIX2IndicatorConverter:
        return self._get_converter('indicator')

    @property
    def intrusion_set_parser(self) -> InternalSTIX2IntrusionSetConverter:
        return self._get_converter('intrusion-set')

    @property
    def location_parser(self) -> InternalSTIX2LocationConverter:
        return self._get_converter('location')

    @property
    def malware_analysis_parser(self) -> InternalSTIX2MalwareAnalysisConverter:
        return self._get_converter('malware-analysis')

    @property
    def malware_parser(self) -> InternalSTIX2MalwareConverter:
        return self._get_converter('malware')

    @property
    def note_parser(self) -> InternalSTIX2NoteConverter:
        return self._get_converter('note')

    @property
    def observed_data_parser(self) -> InternalSTIX2ObservedDataConverter:
        return self._get_converter('observed-data')

    @property
    def threat_actor_parser(self) -> InternalSTIX2ThreatActorConverter:
        return self._get_converter('threat-actor')

    @property
    def tool_parser(self) -> InternalSTIX2ToolConverter:
        return self._get_converter('tool')

    @property
    def vulnerability_parser(self) -> InternalSTIX2VulnerabilityConverter:
        return self._get_converter('vulnerability')

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

    def _handle_tags_from_stix_fields(
            self, misp_layer: MISPAttribute | MISPEvent | MISPObject,
            stix_object: _SDO_TYPING) -> Iterator[str]:
        yield from super()._handle_tags_from_stix_fields(
            misp_layer, stix_object
        )
        for label in stix_object.get("labels", []):
            if label.startswith("misp:"):
                continue
            yield label

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

    def _add_attribute_galaxies(self, attribute: MISPAttribute, galaxies: dict):
        for galaxy_type, clusters in galaxies.items():
            misp_galaxy = MISPGalaxy()
            misp_galaxy.from_dict(**self._galaxies[galaxy_type])
            for cluster in clusters:
                misp_galaxy.add_galaxy_cluster(**cluster)
                attribute.add_tag(self._galaxy_cluster_tag(cluster))
            attribute.add_galaxy(misp_galaxy)

    def _add_event_galaxies(self, galaxies: dict):
        for galaxy_type, clusters in galaxies.items():
            misp_galaxy = MISPGalaxy()
            misp_galaxy.from_dict(**self._galaxies[galaxy_type])
            for cluster in clusters:
                misp_galaxy.add_galaxy_cluster(**cluster)
                self.misp_event.add_tag(self._galaxy_cluster_tag(cluster))
            self.misp_event.add_galaxy(misp_galaxy)

    def _add_galaxy_tags(self, misp_layer, misp_galaxy):
        for cluster in misp_galaxy.clusters:
            misp_layer.add_tag(self._galaxy_cluster_tag(cluster))

    @staticmethod
    def _galaxy_cluster_tag(cluster) -> str:
        tag_value = cluster.uuid if cluster.type.startswith('stix-') else cluster.value
        return f'misp-galaxy:{cluster.type}="{tag_value}"'

    def _add_object_galaxies(self, misp_object: MISPObject, galaxies: dict):
        for galaxy in self._aggregate_galaxy_clusters(galaxies):
            for attribute in misp_object.attributes:
                attribute.add_galaxy(galaxy)
                self._add_galaxy_tags(attribute, galaxy)

    def _add_event_report(
            self, event_report: MISPEventReport, stix_object_id: str):
        if stix_object_id in self._analyst_data:
            for reference in self._analyst_data[stix_object_id]:
                self._add_analyst_data(event_report, reference)
        self.misp_event.add_event_report(**event_report)

    ############################################################################
    #       METHODS TO LINK INDICATORS AND OBSERVABLES WITH SIMILAR DATA       #
    ############################################################################

    def _set_indicator_references(self):
        if not all(hasattr(self, field) for field in _STORAGE_VARIABLE_NAMES):
            return
        pattern_parser = self.indicator_parser._compile_stix_pattern
        self._indicator_references = {
            self._extract_uuid(indicator_id): tuple(val[-1] for val in pattern)
            for indicator_id, indicator in self._indicator.items()
            if getattr(indicator, 'pattern_type', 'stix') == 'stix'
            for pattern in pattern_parser(indicator).comparisons.values()
        }
