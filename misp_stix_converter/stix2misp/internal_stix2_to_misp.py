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
from .converters.stix2converter import _as_custom_syntax
from .stix2_to_misp import (
    STIX2toMISPParser, _BUNDLE_TYPING, _NOTE_TYPING, _OBSERVABLE_TYPING,
    _OPINION_TYPING, _SDO_TYPING)
from collections import defaultdict
from pymisp import (
    MISPAttribute, MISPEvent, MISPEventReport, MISPGalaxy, MISPObject, MISPSighting)
from stix2.v20.sdo import CustomObject as CustomObject_v20
from stix2.v20.sro import Sighting as Sighting_v20
from stix2.v21.sdo import CustomObject as CustomObject_v21
from stix2.v21.sro import Sighting as Sighting_v21
from typing import Any, Iterator, Optional, Union

_STORAGE_VARIABLE_NAMES = ('_indicator', '_observed_data')

_CUSTOM_TYPING = Union[
    CustomObject_v20,
    CustomObject_v21,
    dict
]
_SIGHTING_TYPING = Union[
    Sighting_v20, Sighting_v21, dict
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
        for stix_object in getattr(bundle, 'objects', []):
            self._load_stix_object(stix_object)

    ############################################################################
    #                       STIX OBJECTS LOADING METHODS                       #
    ############################################################################

    def _load_analyst_note(self, note: _CUSTOM_TYPING):
        note_dict = {
            'created': self._stix_date(note['created']),
            'modified': self._stix_date(note['modified']),
            'note': note['x_misp_note'],
            'uuid': self._sanitise_uuid(note['id'])
        }
        if 'x_misp_author' in note:
            note_dict['authors'] = note['x_misp_author']
        if 'x_misp_language' in note:
            note_dict['language'] = note['x_misp_language']
        self._analyst_data[note['object_ref']].append(note['id'])
        super()._load_note(note['id'], note_dict)

    def _load_analyst_opinion(self, opinion: _CUSTOM_TYPING):
        opinion_dict = {
            'comment': opinion.get('x_misp_comment', ''),
            'created': self._stix_date(opinion['created']),
            'modified': self._stix_date(opinion['modified']),
            'opinion': opinion['x_misp_opinion'],
            'uuid': self._sanitise_uuid(opinion['id'])
        }
        if 'x_misp_author' in opinion:
            opinion_dict['authors'] = opinion['x_misp_author']
        self._analyst_data[opinion['object_ref']].append(opinion['id'])
        super()._load_opinion(opinion['id'], opinion_dict)

    def _load_custom_attribute(self, custom_attribute: _CUSTOM_TYPING):
        self._register_uuid(custom_attribute['id'])
        try:
            self._custom_attribute[custom_attribute['id']] = custom_attribute
        except AttributeError:
            self._custom_attribute = {custom_attribute['id']: custom_attribute}

    def _load_custom_galaxy_cluster(self, custom_galaxy: _CUSTOM_TYPING):
        self._register_uuid(custom_galaxy['id'])
        try:
            self._custom_galaxy_cluster[custom_galaxy['id']] = custom_galaxy
        except AttributeError:
            self._custom_galaxy_cluster = {custom_galaxy['id']: custom_galaxy}

    def _load_custom_object(self, custom_object: _CUSTOM_TYPING):
        self._register_uuid(custom_object['id'])
        try:
            self._custom_object[custom_object['id']] = custom_object
        except AttributeError:
            self._custom_object = {custom_object['id']: custom_object}

    def _load_custom_opinion(self, custom_object: _CUSTOM_TYPING):
        # Parsed with the sightings, once every identity its author reference
        # may name is loaded
        object_ref = self._sanitise_uuid(custom_object['object_ref'])
        try:
            self._sighting['custom_opinion'][object_ref].append(custom_object)
        except AttributeError:
            self._sighting = defaultdict(lambda: defaultdict(list))
            self._sighting['custom_opinion'][object_ref].append(custom_object)

    def _load_note(self, note: _NOTE_TYPING):
        if 'misp:context-layer="Analyst Note"' in note.get('labels', []):
            note_dict = {
                'uuid': self._sanitise_uuid(note['id']),
                **self._parse_analyst_note(note)
            }
            self._analyst_data[note['object_refs'][0]].append(note['id'])
            super()._load_note(note['id'], note_dict)
        else:
            self._register_uuid(note['id'])
            super()._load_note(note['id'], note)

    def _load_observable_object(self, observable: _OBSERVABLE_TYPING):
        self._register_uuid(observable['id'])
        try:
            self._observable[observable['id']] = observable
        except AttributeError:
            self._observable = {observable['id']: observable}

    def _load_opinion(self, opinion: _OPINION_TYPING):
        # MISP values are read here, before any converter runs: an Analyst
        # Opinion's level now, the author of the Opinion a sighting is written
        # as when the sightings are parsed, from the Opinion as presented here
        opinion = _as_custom_syntax(opinion, self)
        if 'misp:context-layer="Analyst Opinion"' in opinion.get('labels', []):
            opinion_dict = {
                'opinion': opinion['x_misp_opinion'],
                'uuid': self._sanitise_uuid(opinion['id']),
                **self._parse_analyst_opinion(opinion)
            }
            self._analyst_data[opinion['object_refs'][0]].append(opinion['id'])
            super()._load_opinion(opinion['id'], opinion_dict)
        else:
            object_ref = self._sanitise_uuid(opinion['object_refs'][0])
            try:
                self._sighting['opinion'][object_ref].append(opinion)
            except AttributeError:
                self._sighting = defaultdict(lambda: defaultdict(list))
                self._sighting['opinion'][object_ref].append(opinion)

    def _load_sighting(self, sighting: _SIGHTING_TYPING):
        sighting_of_ref = self._sanitise_uuid(sighting['sighting_of_ref'])
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
        for misp_sighting in self._parse_record_sightings(attribute_uuid):
            attribute.add_sighting(misp_sighting)

    def _handle_object_refs(self, object_refs: list):
        for object_ref in object_refs:
            object_type = object_ref.split('--')[0]
            if object_type in self._mapping.observable_object_types():
                # A MISP export lists the observable objects its Observed
                # Data consumed next to it, and those are converted with
                # their parent: only a reference to one the bundle never
                # carried has anything to say.
                if not self._has_observable(object_ref):
                    self._object_ref_loading_error(object_ref)
                continue
            if object_type in self._mapping.object_type_refs_to_skip():
                continue
            if object_type == 'marking-definition':
                self._handle_marking_definition_ref(object_ref)
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
        for misp_sighting in self._parse_record_sightings(object_uuid):
            for attribute in misp_object.attributes:
                attribute.add_sighting(misp_sighting)

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

    def _parse_custom_opinion(
            self, custom_opinion: _CUSTOM_TYPING) -> Optional[MISPSighting]:
        sighting_args = {
            'date_sighting': self._timestamp_from_stix_date(
                custom_opinion['modified']
            ),
            'type': '1'
        }
        if 'x_misp_source' in custom_opinion:
            sighting_args['source'] = custom_opinion['x_misp_source']
        if any(field in custom_opinion
               for field in ('x_misp_author', 'x_misp_author_ref')):
            organisation = self._parse_opinion_organisation(
                custom_opinion['id'], custom_opinion.get('x_misp_author_ref'),
                custom_opinion.get('x_misp_author')
            )
            if organisation is None:
                return None
            sighting_args['Organisation'] = organisation
        misp_sighting = MISPSighting()
        misp_sighting.from_dict(**sighting_args)
        return misp_sighting

    def _parse_opinion(
            self, opinion: _OPINION_TYPING) -> Optional[MISPSighting]:
        sighting_args = {
            'date_sighting': self._timestamp_from_stix_date(
                opinion['modified']
            ),
            'type': '1' if 'disagree' in opinion['opinion'] else '0'
        }
        if 'x_misp_source' in opinion:
            sighting_args['source'] = opinion['x_misp_source']
        if 'x_misp_author_ref' in opinion:
            authors = opinion.get('authors')
            organisation = self._parse_opinion_organisation(
                opinion['id'], opinion['x_misp_author_ref'],
                authors[0] if authors else None
            )
            if organisation is None:
                return None
            sighting_args['Organisation'] = organisation
        misp_sighting = MISPSighting()
        misp_sighting.from_dict(**sighting_args)
        return misp_sighting

    def _parse_opinion_organisation(
            self, opinion_id: str, author_ref: Any,
            author: Optional[str]) -> Optional[dict]:
        # The organisation of the sighting an Opinion is written for: the
        # identity its author reference names, else the uuid of that
        # reference with the author name the Opinion carries itself. With
        # neither, the Opinion is dropped.
        if not isinstance(author_ref, str):
            self._opinion_author_ref_error(opinion_id, author_ref)
            return None
        identity = getattr(self, '_identity', {}).get(author_ref)
        if identity is not None:
            return {
                'uuid': self._sanitise_uuid(identity['id']),
                'name': identity['name']
            }
        if author is None:
            self._opinion_author_error(opinion_id, author_ref)
            return None
        self._opinion_author_warning(opinion_id, author_ref, author)
        return {'uuid': self._sanitise_uuid(author_ref), 'name': author}

    def _parse_record_sightings(self, record_uuid: str) -> list:
        # The sightings of an attribute or object: each one with no
        # organisation to give is reported and dropped as it is parsed, and
        # costs nothing else
        misp_sightings = [
            self._parse_sighting(sighting) for sighting
            in self._sighting.get('sighting', {}).get(record_uuid, ())
        ]
        if record_uuid in self._sighting.get('opinion', {}):
            misp_sightings.extend(
                self._parse_opinion(opinion)
                for opinion in self._sighting['opinion'][record_uuid]
            )
        else:
            misp_sightings.extend(
                self._parse_custom_opinion(custom_opinion)
                for custom_opinion in self._sighting.get(
                    'custom_opinion', {}
                ).get(record_uuid, ())
            )
        return [
            misp_sighting for misp_sighting in misp_sightings
            if misp_sighting is not None
        ]

    def _parse_sighting(
            self, sighting: _SIGHTING_TYPING) -> Optional[MISPSighting]:
        # MISP writes a sighting with no Organisation with no
        # where_sighted_refs
        if 'where_sighted_refs' not in sighting:
            return self._create_sighting(sighting)
        misp_sighting = super()._parse_sighting(sighting)
        if misp_sighting is None:
            self._sighting_identity_error(
                sighting['id'], sighting['where_sighted_refs']
            )
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
                self._add_cluster_tag(attribute, cluster)
            attribute.add_galaxy(misp_galaxy)

    def _add_cluster_tag(self, misp_layer, cluster):
        """Tag the record with the Galaxy Cluster, if a tag can name it.

        The one place a cluster tag reaches a record: a cluster type nothing
        survives from leaves no tag to write, and the cluster is then attached
        without one rather than the record being handed an empty tag.

        :param misp_layer: the record the cluster is attached to
        :param cluster: the Galaxy Cluster the tag names
        """
        tag = self._galaxy_cluster_tag(cluster)
        if tag is not None:
            misp_layer.add_tag(tag)

    def _add_event_galaxies(self, galaxies: dict):
        for galaxy_type, clusters in galaxies.items():
            misp_galaxy = MISPGalaxy()
            misp_galaxy.from_dict(**self._galaxies[galaxy_type])
            for cluster in clusters:
                misp_galaxy.add_galaxy_cluster(**cluster)
                self._add_cluster_tag(self.misp_event, cluster)
            self.misp_event.add_galaxy(misp_galaxy)

    def _add_galaxy_tags(self, misp_layer, misp_galaxy):
        for cluster in misp_galaxy.clusters:
            self._add_cluster_tag(misp_layer, cluster)

    def _galaxy_cluster_tag(self, cluster) -> Optional[str]:
        if cluster.type.startswith('stix-'):
            return self._build_tag('misp-galaxy', cluster.type, cluster.uuid)
        return self._build_cluster_tag(
            cluster.type, cluster.value, cluster.uuid
        )

    def _add_object_galaxies(self, misp_object: MISPObject, galaxies: dict):
        for galaxy in self._aggregate_galaxy_clusters(galaxies):
            for attribute in misp_object.attributes:
                attribute.add_galaxy(galaxy)
                self._add_galaxy_tags(attribute, galaxy)

    def _add_event_report(
            self, event_report: MISPEventReport, stix_object_id: str):
        # The Note and the 2.0 custom object MISP writes an Event Report as
        # both funnel here, keeping the uuid part of their id.
        self._check_record_uuid_collision(
            'event report', event_report.uuid, stix_object_id
        )
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
        pattern_parser = self._get_converter('indicator')._compile_stix_pattern
        # Keyed on the bare uuid where the External parser keys the same map
        # on the whole STIX id: an Internal Indicator and the Observed Data
        # rendering the same MISP record share that uuid and nothing else, so
        # it is what makes each of the 2 findable from the other. Only
        # Indicators feed the map, so no other type can collide with them here
        self._indicator_references = {
            self._extract_uuid(indicator_id): tuple(val[-1] for val in pattern)
            for indicator_id, indicator in self._indicator.items()
            if indicator.get('pattern_type', 'stix') == 'stix'
            for pattern in pattern_parser(indicator).comparisons.values()
        }
