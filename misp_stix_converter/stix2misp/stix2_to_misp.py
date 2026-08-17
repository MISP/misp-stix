#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
from ..tools.exceptions import STIXLoadingError, _reduce_input_path
from ..tools.stix2_loading_helpers import load_stix2_file
from .exceptions import (
    MarkingDefinitionLoadingError, MissingSTIXContentError,
    ObjectRefLoadingError, ObjectTypeLoadingError, UndefinedIndicatorError,
    UndefinedSTIXObjectError, UndefinedObservableError,
    UnknownAttributeTypeError, UnknownObjectNameError,
    UnknownParsingFunctionError, UnknownPatternTypeError,
    UnknownStixObjectTypeError)
from .external_stix2_mapping import ExternalSTIX2toMISPMapping
from .importparser import STIXtoMISPParser
from .internal_stix2_mapping import InternalSTIX2toMISPMapping
from .invalid_stix_handling import InvalidMarkingDefinition
from abc import ABCMeta
from collections import defaultdict
from pymisp import (
    MISPEvent, MISPAttribute, MISPEventReport, MISPGalaxy, MISPGalaxyCluster,
    MISPObject, MISPSighting)
from datetime import datetime
from stix2 import TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE
from stix2.utils import parse_into_datetime
from stix2.v20.bundle import Bundle as Bundle_v20
from stix2.v20.common import MarkingDefinition as MarkingDefinition_v20
from stix2.v20.observables import (
    _Extension as Extension_v20, _STIXBase20 as STIXBase_v20)
from stix2.v20.sdo import (
    AttackPattern as AttackPattern_v20, Campaign as Campaign_v20,
    CourseOfAction as CourseOfAction_v20, CustomObject as CustomObject_v20,
    Identity as Identity_v20, Indicator as Indicator_v20,
    IntrusionSet as IntrusionSet_v20, Malware as Malware_v20,
    ObservedData as ObservedData_v20, Report as Report_v20,
    ThreatActor as ThreatActor_v20, Tool as Tool_v20,
    Vulnerability as Vulnerability_v20)
from stix2.v20.sro import (
    Relationship as Relationship_v20, Sighting as Sighting_v20)
from stix2.v21.bundle import Bundle as Bundle_v21
from stix2.v21.common import MarkingDefinition as MarkingDefinition_v21
from stix2.v21.observables import (
    _Extension as Extension_v21, _STIXBase21 as STIXBase_v21, Artifact,
    AutonomousSystem, Directory, DomainName, EmailAddress, EmailMessage, File,
    IPv4Address, IPv6Address, MACAddress, Mutex,
    NetworkTraffic as NetworkTraffic_v21, Process, Software, URL, UserAccount,
    WindowsRegistryKey, X509Certificate)
from stix2.v21.sdo import Grouping, Location, MalwareAnalysis, Note, Opinion
from stix2.v21.sdo import (
    AttackPattern as AttackPattern_v21, Campaign as Campaign_v21,
    CourseOfAction as CourseOfAction_v21, CustomObject as CustomObject_v21,
    Identity as Identity_v21, Indicator as Indicator_v21,
    IntrusionSet as IntrusionSet_v21, Malware as Malware_v21,
    ObservedData as ObservedData_v21, Report as Report_v21,
    ThreatActor as ThreatActor_v21, Tool as Tool_v21,
    Vulnerability as Vulnerability_v21)
from stix2.v21.sro import (
    Relationship as Relationship_v21, Sighting as Sighting_v21)
from typing import Any, Iterator, Optional, Union

# Some constants
_EXTENSION_TYPES = (Extension_v20, Extension_v21, STIXBase_v20, STIXBase_v21)
_OBSERVABLE_FIELDS_TO_SKIP = (
    'defanged', 'granular_markings', 'id', 'object_marking_refs',
    'spec_version', 'type'
)
_LOADED_FEATURES = (
    '_attack_pattern', '_campaign', '_course_of_action', '_custom_attribute',
    '_custom_object', '_identity', '_indicator', '_intrusion_set', '_malware',
    '_malware_analysis', '_note', '_observed_data', '_opinion',
    '_threat_actor', '_tool', '_vulnerability'
)
_SDOs = (
    '_grouping', '_report', '_location', '_marking_definition',
    '_relationship', '_sighting', '_observable', *_LOADED_FEATURES
)

# Typing
# `dict` is part of every incoming typing: content parsed with `allow_custom`
# keeps the object types the STIX version it is parsed against does not know as
# plain dictionaries, so any incoming object may reach us in that form.
_OBSERVABLE_TYPING = Union[
    Artifact, AutonomousSystem, Directory, DomainName, EmailAddress,
    EmailMessage, File, IPv4Address, IPv6Address, MACAddress, Mutex,
    NetworkTraffic_v21, Process, Software, URL, UserAccount, WindowsRegistryKey,
    X509Certificate, dict
]

_BUNDLE_TYPING = Union[
    Bundle_v20, Bundle_v21
]
_DATA_LAYER_TYPING = Union[
    MISPAttribute, MISPEvent, MISPEventReport, MISPObject
]
_GROUPING_REPORT_TYPING = Union[
    Grouping, Report_v20, Report_v21, dict
]
_MARKING_DEFINITION_TYPING = Union[
    MarkingDefinition_v20, MarkingDefinition_v21, dict
]
_NOTE_TYPING = Union[
    MISPEventReport, Note, CustomObject_v20, dict
]
_OPINION_TYPING = Union[
    Opinion, CustomObject_v20, dict
]
_RELATIONSHIP_TYPING = Union[
    Relationship_v20, Relationship_v21, dict
]
_REPORT_TYPING = Union[
    Report_v20, Report_v21, dict
]
_SDO_TYPING = Union[
    AttackPattern_v20, AttackPattern_v21, Campaign_v20, Campaign_v21,
    CourseOfAction_v20, CourseOfAction_v21, CustomObject_v20, CustomObject_v21,
    Grouping, Identity_v20, Identity_v21, Indicator_v20, Indicator_v21,
    IntrusionSet_v20, IntrusionSet_v21, Location, Malware_v20, Malware_v21,
    MalwareAnalysis, Note, ObservedData_v20, ObservedData_v21, Opinion,
    Report_v20, Report_v21, ThreatActor_v20, ThreatActor_v21, Tool_v20,
    Tool_v21, Vulnerability_v20, Vulnerability_v21, dict
]
_SIGHTING_TYPING = Union[
    Sighting_v20, Sighting_v21, dict
]
_STIX_OBJECT_TYPING = Union[
    _OBSERVABLE_TYPING, _GROUPING_REPORT_TYPING,
    _MARKING_DEFINITION_TYPING, _SDO_TYPING, _SIGHTING_TYPING
]


class STIX2toMISPParser(STIXtoMISPParser, metaclass=ABCMeta):
    _CONVERTER_CLASSES: dict = {}

    def __init__(self):
        super().__init__()
        self._creators: set = set()
        self._mapping: Union[
            ExternalSTIX2toMISPMapping, InternalSTIX2toMISPMapping
        ]

        self._analyst_data: dict = defaultdict(list)
        self._clusters: dict = {}
        self._converter_cache: dict = {}
        self._galaxies: dict = {}
        self._loaded_object_ids: set = set()

        self._attack_pattern: dict
        self._campaign: dict
        self._course_of_action: dict
        self._grouping: dict
        self._identity: dict
        self._indicator: dict
        self._intrusion_set: dict
        self._location: dict
        self._malware: dict
        self._malware_analysis: dict
        self._marking_definition: dict
        self._note: dict
        self._observable: dict
        self._observed_data: dict
        self._relationship: dict
        self._report: dict
        self._sighting: dict
        self._threat_actor: dict
        self._tool: dict
        self._vulnerability: dict

    def load_stix_bundle(self, bundle: Bundle_v20 | Bundle_v21,
                         invalid_objects: Optional[dict] = None):
        self._reset_bundle_state()
        if invalid_objects is None:
            # the loading helpers keep the invalid objects they recovered
            # with the bundle they were recovered from
            invalid_objects = getattr(bundle, '_invalid_objects', None)
            if invalid_objects is None:
                invalid_objects = {}
        self.__invalid_objects = invalid_objects
        self._set_identifier(bundle.id)
        self.__stix_version = getattr(bundle, 'spec_version', '2.1')
        self._load_stix_bundle(bundle)
        self._set_indicator_references()

    def parse_stix_content(self, filename: str, **kwargs):
        try:
            bundle = load_stix2_file(filename)
        except Exception as exception:
            raise STIXLoadingError(
                'Error while loading the STIX 2 content: '
                f'{_reduce_input_path(str(exception), filename)}'
            ) from exception
        self.load_stix_bundle(bundle)
        del bundle
        self.parse_stix_bundle(**kwargs)

    def _load_stix_object(self, stix_object: _STIX_OBJECT_TYPING):
        object_type = stix_object['type']
        feature = self._mapping.stix_object_loading_mapping(object_type)
        if feature is None:
            if object_type not in self._mapping.object_type_refs_to_skip():
                self._add_error(
                    f'Unable to load STIX object type: {object_type}'
                )
            return
        self._check_duplicate_id(stix_object['id'])
        if 'created_by_ref' in stix_object:
            self._creators.add(stix_object['created_by_ref'])
        try:
            getattr(self, feature)(stix_object)
        except MarkingDefinitionLoadingError as marking_definition_id:
            self._add_error(
                'Error whil parsing the Marking Definition '
                f'object with id {marking_definition_id}'
            )
        except Exception as exception:
            # Loading methods read the fields they need with the Mapping
            # interface every incoming object honours, typed or dict-form.
            # Anything raised past that point is a field the object does not
            # carry: drop it, but name the object instead of the exception
            # alone.
            self._add_error(
                'Error while loading the STIX object with id '
                f'{stix_object["id"]}: {self._parse_traceback(exception)}'
            )

    def _check_duplicate_id(self, object_id: str):
        """Report the ids a bundle gives to more than one loaded object.

        Most loading methods store the object they get by its id, so the last
        occurrence of a duplicated id wins and the ones before it are
        shadowed. That behaviour is kept - the converted content is a
        rendering of the last version sent - but it is no longer silent. The
        few methods keying on a referenced object instead (relationship,
        sighting, opinion) keep every occurrence, hence a warning naming the
        id and what it puts at stake rather than the objects lost.
        """
        if object_id in self._loaded_object_ids:
            self._add_warning(
                f'Duplicate STIX object id: {object_id} - the converted '
                'content may be an altered rendering of the bundle'
            )
        self._loaded_object_ids.add(object_id)

    def _parse_stix_bundle(self):
        # `stix_version` is only set by `load_stix_bundle` - without it the
        # dispatch below would build a generic event from unloaded state
        if not hasattr(self, 'stix_version'):
            raise MissingSTIXContentError(
                'No STIX content loaded, please run `load_stix_bundle` first.'
            )
        n_reports = sum(
            len(getattr(self, feature, {}))
            for feature in ('_report', '_grouping')
        )
        feature = self._mapping.bundle_to_misp_mapping(
            str(2 if n_reports >= 2 else n_reports)
        )
        getattr(self, feature)()

    def _reset_bundle_state(self):
        super()._reset_bundle_state()
        self._parsed_object_refs = set()
        self._creators = set()
        self._analyst_data = defaultdict(list)
        self._clusters = {}
        self._converter_cache.clear()
        self._galaxies = {}
        self._loaded_object_ids = set()
        for feature in _SDOs:
            if hasattr(self, feature):
                delattr(self, feature)

    def _set_misp_event(self, misp_event):
        super()._set_misp_event(misp_event)
        self._parsed_object_refs = set()

    def _get_converter(self, stix_type: str):
        if stix_type not in self._converter_cache:
            cls = self._CONVERTER_CLASSES.get(stix_type)
            if cls is None:
                raise UnknownStixObjectTypeError(stix_type)
            self._converter_cache[stix_type] = cls(self)
        return self._converter_cache[stix_type]

    def _fetch_observable(self, object_ref: str) -> Optional[dict]:
        return self._observable.get(object_ref)

    def _fetch_observable_references(
            self, observable: dict | _OBSERVABLE_TYPING) -> Iterator[Any]:
        """Yield every value an observable object carries, at any depth.

        Which field holds the value an SCO is about depends on its type, and
        extensions nest further fields under it, so the values are collected
        by walking the object instead of by asking each type where it keeps
        them. Only the fields naming or qualifying the object rather than
        describing what it observed are skipped
        """
        for key, values in observable.items():
            if key in _OBSERVABLE_FIELDS_TO_SKIP:
                continue
            if isinstance(values, dict):
                yield from self._fetch_observable_references(values)
                continue
            if isinstance(values, list):
                for value in values:
                    if isinstance(value, _EXTENSION_TYPES):
                        yield from self._fetch_observable_references(value)
                        continue
                    yield value
                continue
            if isinstance(values, _EXTENSION_TYPES):
                yield from self._fetch_observable_references(values)
                continue
            yield values

    def _has_observable(self, object_ref: str) -> bool:
        return object_ref in self._observable

    ############################################################################
    #                                PROPERTIES                                #
    ############################################################################

    @property
    def event_tags(self) -> set:
        return getattr(self, '_event_tags', set())

    @property
    def generic_info_field(self) -> str:
        if self.event_title is not None:
            return self.event_title
        message = f'STIX {self.stix_version} Bundle ({self.identifier})'
        return f'{message} and converted with the MISP-STIX import feature.'

    @property
    def indicator_references(self) -> dict:
        return getattr(self, '_indicator_references', {})

    @property
    def invalid_objects(self) -> dict:
        return self.__invalid_objects

    @property
    def stix_version(self) -> str:
        return self.__stix_version

    ############################################################################
    #                       STIX OBJECTS LOADING METHODS                       #
    ############################################################################

    def _load_attack_pattern(
            self,
            attack_pattern: AttackPattern_v20 | AttackPattern_v21 | dict):
        self._check_uuid(attack_pattern['id'])
        try:
            self._attack_pattern[attack_pattern['id']] = attack_pattern
        except AttributeError:
            self._attack_pattern = {attack_pattern['id']: attack_pattern}

    def _load_campaign(self, campaign: Campaign_v20 | Campaign_v21 | dict):
        self._check_uuid(campaign['id'])
        try:
            self._campaign[campaign['id']] = campaign
        except AttributeError:
            self._campaign = {campaign['id']: campaign}

    def _load_course_of_action(
            self,
            course_of_action: CourseOfAction_v20 | CourseOfAction_v21 | dict):
        self._check_uuid(course_of_action['id'])
        try:
            self._course_of_action[course_of_action['id']] = course_of_action
        except AttributeError:
            self._course_of_action = {course_of_action['id']: course_of_action}

    def _load_grouping(self, grouping: Grouping | dict):
        self._check_uuid(grouping['id'])
        try:
            self._grouping[grouping['id']] = grouping
        except AttributeError:
            self._grouping = {grouping['id']: grouping}

    def _load_identity(self, identity: Identity_v20 | Identity_v21 | dict):
        self._check_uuid(identity['id'])
        try:
            self._identity[identity['id']] = identity
        except AttributeError:
            self._identity = {identity['id']: identity}

    def _load_indicator(self, indicator: Indicator_v20 | Indicator_v21 | dict):
        self._check_uuid(indicator['id'])
        try:
            self._indicator[indicator['id']] = indicator
        except AttributeError:
            self._indicator = {indicator['id']: indicator}

    def _load_intrusion_set(
            self, intrusion_set: IntrusionSet_v20 | IntrusionSet_v21 | dict):
        self._check_uuid(intrusion_set['id'])
        try:
            self._intrusion_set[intrusion_set['id']] = intrusion_set
        except AttributeError:
            self._intrusion_set = {intrusion_set['id']: intrusion_set}

    def _load_location(self, location: Location | dict):
        self._check_uuid(location['id'])
        try:
            self._location[location['id']] = location
        except AttributeError:
            self._location = {location['id']: location}

    def _load_malware(self, malware: Malware_v20 | Malware_v21 | dict):
        self._check_uuid(malware['id'])
        try:
            self._malware[malware['id']] = malware
        except AttributeError:
            self._malware = {malware['id']: malware}

    def _load_malware_analysis(self, malware_analysis: MalwareAnalysis | dict):
        self._check_uuid(malware_analysis['id'])
        try:
            self._malware_analysis[malware_analysis['id']] = malware_analysis
        except AttributeError:
            self._malware_analysis = {malware_analysis['id']: malware_analysis}

    def _load_marking_definition(
            self, marking_definition: _MARKING_DEFINITION_TYPING):
        tag = self._parse_marking_definition(marking_definition)
        try:
            self._marking_definition[marking_definition['id']] = tag
        except AttributeError:
            self._marking_definition = {marking_definition['id']: tag}

    def _load_note(self, note_ref: str, note: _NOTE_TYPING):
        try:
            self._note[note_ref] = note
        except AttributeError:
            self._note = {note_ref: note}

    def _load_observed_data(
            self, observed_data: ObservedData_v20 | ObservedData_v21 | dict):
        self._check_uuid(observed_data['id'])
        try:
            self._observed_data[observed_data['id']] = observed_data
        except AttributeError:
            self._observed_data = {observed_data['id']: observed_data}

    def _load_opinion(self, opinion_ref: str, opinion_dict: _OPINION_TYPING):
        try:
            self._opinion[opinion_ref] = opinion_dict
        except AttributeError:
            self._opinion = {opinion_ref: opinion_dict}

    def _load_relationship(self, relationship: _RELATIONSHIP_TYPING):
        reference = (
            relationship['target_ref'], relationship['relationship_type']
        )
        source_uuid = self._sanitise_uuid(relationship['source_ref'])
        try:
            self._relationship[source_uuid].add(reference)
        except AttributeError:
            self._relationship = defaultdict(set)
            self._relationship[source_uuid].add(reference)

    def _load_report(self, report: _REPORT_TYPING):
        self._check_uuid(report['id'])
        try:
            self._report[report['id']] = report
        except AttributeError:
            self._report = {report['id']: report}

    def _load_threat_actor(
            self, threat_actor: ThreatActor_v20 | ThreatActor_v21 | dict):
        self._check_uuid(threat_actor['id'])
        try:
            self._threat_actor[threat_actor['id']] = threat_actor
        except AttributeError:
            self._threat_actor = {threat_actor['id']: threat_actor}

    def _load_tool(self, tool: Tool_v20 | Tool_v21 | dict):
        self._check_uuid(tool['id'])
        try:
            self._tool[tool['id']] = tool
        except AttributeError:
            self._tool = {tool['id']: tool}

    def _load_vulnerability(
            self,
            vulnerability: Vulnerability_v20 | Vulnerability_v21 | dict):
        self._check_uuid(vulnerability['id'])
        try:
            self._vulnerability[vulnerability['id']] = vulnerability
        except AttributeError:
            self._vulnerability = {vulnerability['id']: vulnerability}

    ############################################################################
    #                    MAIN STIX OBJECTS PARSING METHODS.                    #
    ############################################################################

    def _get_stix_object(self, object_ref: str):
        object_type = object_ref.split('--')[0]
        if object_type.startswith('x-misp-'):
            object_type = (
                'note' if object_type == 'x-misp-event-report'
                else object_type.replace('x-misp', 'custom')
            )
        feature = f"_{object_type.replace('-', '_')}"
        try:
            return getattr(self, feature)[object_ref]
        except AttributeError:
            if (invalid := self.invalid_objects.get(object_ref)) is not None:
                if object_type == 'marking-definition':
                    invalid = InvalidMarkingDefinition(invalid)
                    getattr(self, f'_load{feature}')(invalid)
                    return getattr(self, feature)[object_ref]
            raise ObjectTypeLoadingError(object_type)
        except KeyError:
            if (invalid := self.invalid_objects.get(object_ref)) is not None:
                if object_type == 'marking-definition':
                    invalid = InvalidMarkingDefinition(invalid)
                    getattr(self, f'_load{feature}')(invalid)
                    return getattr(self, feature)[object_ref]
            raise ObjectRefLoadingError(object_ref)

    def _handle_object(self, object_type: str, object_ref: str):
        self._parsed_object_refs.add(object_ref)
        try:
            self._get_converter(object_type).parse(object_ref)
        except ObjectRefLoadingError as error:
            self._object_ref_loading_error(error)
        except ObjectTypeLoadingError as error:
            self._object_type_loading_error(error)
        except UndefinedIndicatorError as error:
            self._add_error(f'Undefined Indicator error: {error}')
        except UndefinedSTIXObjectError as object_id:
            self._add_error(
                'Unable to define the object identified '
                f'with the id {object_id}'
            )
        except UndefinedObservableError as error:
            self._add_error(f'Undefined Observable error: {error}')
        except UnknownAttributeTypeError as attribute_type:
            self._add_warning(
                f'MISP attribute type not mapped: {attribute_type}'
            )
        except UnknownObjectNameError as name:
            self._add_warning(f'MISP object name not mapped: {name}')
        except UnknownParsingFunctionError as error:
            self._unknown_parsing_function_error(error)
        except UnknownPatternTypeError as pattern_type:
            self._add_error(
                'Unknown pattern type in Indicator object with id '
                f'{object_ref}: {pattern_type}'
            )
        except UnknownStixObjectTypeError:
            # Reported by the dispatchers above us, against the object type
            # rather than the id: every object of that type yields the same
            # message, which is what lets the report say how many there were.
            # The catch-all below would bury it under one traceback each.
            raise
        except Exception as exception:
            # Converters make assumptions about the shape of what they get -
            # labels above all - that content is free not to hold. Whatever
            # they raise, the object is dropped: say which one and why.
            self._add_error(
                f'Error while parsing the STIX object with id {object_ref}: '
                f'{self._parse_traceback(exception)}'
            )

    def _handle_unparsed_content(self):
        if 'observed-data' in self._converter_cache:
            observed_data_parser = self._get_converter('observed-data')
            if hasattr(observed_data_parser, '_observable_relationships'):
                observed_data_parser.parse_relationships()
        if hasattr(self, '_relationship'):
            if hasattr(self, '_sighting'):
                self._parse_relationships_and_sightings()
            else:
                self._parse_relationships()
        elif hasattr(self, '_sighting'):
            self._parse_sightings()
        else:
            getattr(self, f'_parse_galaxies_{self.galaxy_feature}')()

    def _misp_event_from_grouping(self, grouping: Grouping) -> MISPEvent:
        misp_event = self._create_misp_event(grouping)
        misp_event.published = False
        return misp_event

    def _misp_event_from_report(self, report: _REPORT_TYPING) -> MISPEvent:
        misp_event = self._create_misp_event(report)
        published = self._stix_date(report['published'])
        if published != self._stix_date(report['modified']):
            misp_event.published = True
            misp_event.publish_timestamp = self._timestamp_from_date(published)
        else:
            misp_event.published = False
        return misp_event

    def _parse_bundle_with_multiple_reports(self):
        if self.single_event:
            self._set_misp_event(self._create_generic_event())
            if getattr(self, '_report', None):
                for report in self._report.values():
                    self._handle_object_refs(report['object_refs'])
            if getattr(self, '_grouping', None):
                for grouping in self._grouping.values():
                    self._handle_object_refs(grouping['object_refs'])
            self._handle_unparsed_content()
        else:
            self._set_misp_events()
            if getattr(self, '_report', None):
                for report in self._report.values():
                    self._set_misp_event(self._misp_event_from_report(report))
                    self._handle_object_refs(report['object_refs'])
                    self._handle_unparsed_content()
                    self._populate_misp_event()
            if getattr(self, '_grouping', None):
                for grouping in self._grouping.values():
                    self._set_misp_event(
                        self._misp_event_from_grouping(grouping)
                    )
                    self._handle_object_refs(grouping['object_refs'])
                    self._handle_unparsed_content()
                    self._populate_misp_event()

    def _parse_bundle_with_no_report(self):
        self._set_single_event(True)
        self._set_misp_event(self._create_generic_event())
        self._parse_loaded_features()
        self._handle_unparsed_content()

    def _parse_bundle_with_single_report(self):
        self._set_single_event(True)
        if getattr(self, '_report', None):
            for report in self._report.values():
                self._set_misp_event(self._misp_event_from_report(report))
                self._handle_object_refs(report['object_refs'])
        elif getattr(self, '_grouping', None):
            for grouping in self._grouping.values():
                self._set_misp_event(self._misp_event_from_grouping(grouping))
                self._handle_object_refs(grouping['object_refs'])
        else:
            self._parse_bundle_with_no_report()
        self._handle_unparsed_content()

    def _parse_galaxies_as_container(self):
        clusters = defaultdict(list)
        for cluster_id, cluster in self._clusters.items():
            if self.misp_event.uuid not in cluster['used']:
                continue
            if not cluster['used'][self.misp_event.uuid]:
                if cluster_id in getattr(self, '_marking_definition', {}):
                    for tag in self._marking_definition[cluster_id]:
                        if tag not in self.event_tags:
                            self.misp_event.add_tag(tag)
                            self.event_tags.add(tag)
                misp_cluster = cluster['cluster']
                if isinstance(misp_cluster, list):
                    for cluster in misp_cluster:
                        clusters[cluster.type].append(cluster)
                    continue
                clusters[misp_cluster.type].append(misp_cluster)
        if clusters:
            self._add_event_galaxies(clusters)

    def _parse_galaxies_as_tag_names(self):
        for tags in self._clusters.values():
            if self.misp_event.uuid not in tags['used']:
                continue
            if not tags['used'][self.misp_event.uuid]:
                for tag in tags['tag_names']:
                    self.misp_event.add_tag(tag)

    def _parse_loaded_features(self):
        for feature in _LOADED_FEATURES:
            if hasattr(self, feature):
                for object_ref in getattr(self, feature):
                    object_type = object_ref.split('--')[0]
                    try:
                        self._handle_object(object_type, object_ref)
                    except UnknownStixObjectTypeError as error:
                        self._unknown_stix_object_type_error(error)
                    except UnknownParsingFunctionError as error:
                        self._unknown_parsing_function_error(error)

    ############################################################################
    #                       ANALYST DATA PARSING METHODS                       #
    ############################################################################

    @classmethod
    def _parse_analyst_note(cls, note: _NOTE_TYPING) -> dict:
        note_dict = {
            'created': cls._stix_date(note['created']),
            'modified': cls._stix_date(note['modified']),
            'note': note['content']
        }
        if 'abstract' in note:
            note_dict['comment'] = note['abstract']
        if 'authors' in note:
            note_dict['authors'] = ', '.join(note['authors'])
        if 'lang' in note:
            note_dict['language'] = note['lang']
        return note_dict

    @classmethod
    def _parse_analyst_opinion(cls, opinion: _OPINION_TYPING) -> dict:
        opinion_dict = {
            'comment': opinion.get('explanation', ''),
            'created': cls._stix_date(opinion['created']),
            'modified': cls._stix_date(opinion['modified'])
        }
        if 'authors' in opinion:
            opinion_dict['authors'] = ', '.join(opinion['authors'])
        return opinion_dict

    ############################################################################
    #                   MARKING DEFINITIONS PARSING METHODS.                   #
    ############################################################################

    def _add_markings_to_misp_attribute(
            self, attribute: MISPAttribute, stix_object: _SDO_TYPING):
        for tags in self._handle_tags_from_stix_fields(attribute, stix_object):
            if isinstance(tags, str):
                if tags not in self.event_tags:
                    attribute.add_tag(tags)
                continue
            for tag in tags:
                if tag not in self.event_tags:
                    attribute.add_tag(tag)

    def _add_markings_to_misp_event(
            self, misp_event: MISPEvent, stix_object: _SDO_TYPING):
        for tags in self._handle_tags_from_stix_fields(misp_event, stix_object):
            if isinstance(tags, str):
                misp_event.add_tag(tags)
                self.event_tags.add(tags)
                continue
            for tag in tags:
                self.event_tags.add(tag)
                misp_event.add_tag(tag)

    def _add_markings_to_misp_object(
            self, misp_object: MISPObject, stix_object: _SDO_TYPING):
        for tags in self._handle_tags_from_stix_fields(misp_object, stix_object):
            if isinstance(tags, str):
                if tags not in self.event_tags:
                    for attribute in misp_object.attributes:
                        attribute.add_tag(tags)
                continue
            for tag in tags:
                if tag not in self.event_tags:
                    for attribute in misp_object.attributes:
                        attribute.add_tag(tag)

    def _handle_attribute_marking_clusters(
            self, misp_attribute: MISPAttribute, *marking_refs: tuple[str]):
        clusters = defaultdict(list)
        for marking_ref in marking_refs:
            cluster_storage = self._clusters[marking_ref]
            for cluster in cluster_storage['cluster']:
                if cluster.uuid not in self.event_tags:
                    clusters[cluster.type].append(cluster)
            cluster_storage['used'][self.misp_event.uuid] = True
        for galaxy in self._aggregate_galaxy_clusters(clusters):
            misp_attribute.add_galaxy(galaxy)

    def _handle_event_marking_clusters(
            self, misp_event: MISPEvent, *marking_refs: tuple[str]):
        clusters = defaultdict(list)
        for marking_ref in marking_refs:
            cluster_storage = self._clusters[marking_ref]
            for cluster in cluster_storage['cluster']:
                clusters[cluster.type].append(cluster)
                self.event_tags.add(cluster.uuid)
            cluster_storage['used'][misp_event.uuid] = True
        for galaxy in self._aggregate_galaxy_clusters(clusters):
            misp_event.add_galaxy(galaxy)

    def _handle_object_marking_clusters(
            self, misp_object: MISPObject, *marking_refs: tuple[str]):
        clusters = defaultdict(list)
        for marking_ref in marking_refs:
            cluster_storage = self._clusters[marking_ref]
            for cluster in cluster_storage['cluster']:
                if cluster.uuid not in self.event_tags:
                    clusters[cluster.type].append(cluster)
            cluster_storage['used'][self.misp_event.uuid] = True
        for galaxy in self._aggregate_galaxy_clusters(clusters):
            for attribute in misp_object.attributes:
                attribute.add_galaxy(galaxy)

    def _handle_tags_from_stix_fields(
            self, misp_layer: MISPAttribute | MISPEvent | MISPObject,
            stix_object: _SDO_TYPING) -> Iterator[str]:
        if 'confidence' in stix_object:
            yield self._parse_confidence_level(stix_object['confidence'])
        if 'object_marking_refs' in stix_object:
            cluster_ids = []
            for marking_ref in stix_object['object_marking_refs']:
                try:
                    marking_definition = self._get_stix_object(marking_ref)
                    if marking_ref in self._clusters:
                        cluster_ids.append(marking_ref)
                except ObjectTypeLoadingError as error:
                    if self._is_tlp_marking(marking_ref):
                        yield self._get_stix_object(marking_ref)
                    else:
                        self._object_type_loading_error(error)
                    continue
                except ObjectRefLoadingError as error:
                    if self._is_tlp_marking(marking_ref):
                        yield self._get_stix_object(marking_ref)
                    else:
                        self._object_ref_loading_error(error)
                    continue
                yield marking_definition
            if cluster_ids:
                to_call = self._mapping.marking_cluster_handling(
                    misp_layer.__class__.__name__
                )
                getattr(self, to_call)(misp_layer, *cluster_ids)

    def _parse_acs_access_privilege(
            self, tags: list, privilege: dict,
            privilege_action: str) -> Iterator[str, str]:
        rule_effect = privilege['rule_effect']
        yield 'rule_effect', rule_effect
        if rule_effect == 'permit':
            tags.append(f'acs-marking:privilege_action="{privilege_action}"')
        for field, scope in privilege['privilege_scope'].items():
            yield f'privilege_scope.{field}', scope

    def _parse_acs_marking_definition(
            self, tags: list, marking_definition: _MARKING_DEFINITION_TYPING,
            identifier: str, version: str) -> MISPGalaxyCluster:
        extension = marking_definition.extensions[identifier]
        galaxy_type = f'stix-{version}-acs-marking'
        name = f'STIX {version} ACS Marking'
        if galaxy_type not in self._galaxies:
            self._galaxies[galaxy_type] = {
                'namespace': 'stix', 'type': galaxy_type,
                'version': ''.join(version.split('.')),
                'uuid': identifier.split('--')[1], 'name': name,
                'description': (
                    f'STIX {version} Marking Definition '
                    'extension to support ACS Markings'
                )
            }
        meta = {
            field: marking_definition[field].strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            for field in ('created', 'modified')
            if marking_definition.get(field) is not None
        }
        for key, values in extension.items():
            if isinstance(values, dict):
                for field, subvalues in values.items():
                    if field in self._mapping.marking_vocabularies_fields():
                        if isinstance(subvalues, list):
                            for subvalue in subvalues:
                                tags.append(f'acs-marking:{field}="{subvalue}"')
                        else:
                            tags.append(f'acs-marking:{field}="{subvalues}"')
                    meta[f'{key}.{field}'] = subvalues
                continue
            if key == 'access_privilege':
                if len(values) == 1:
                    privilege = values[0]
                    privilege_action = privilege['privilege_action']
                    meta[f'{key}.privilege_action'] = privilege_action
                    entries = self._parse_acs_access_privilege(
                        tags, privilege, privilege_action
                    )
                    for field, value in dict(entries).items():
                        meta[f'{key}.{field}'] = value
                    continue
                privileges = {}
                for privilege in values:
                    privilege_action = privilege['privilege_action']
                    privileges[privilege_action] = dict(
                        self._parse_acs_access_privilege(
                            tags, privilege, privilege_action
                        )
                    )
                meta[f'{key}.privilege_action'] = list(privileges.keys())
                for privilege_action, privilege in privileges.items():
                    feature = f"{key}.{privilege_action}"
                    for field, value in privilege.items():
                        meta[f'{feature}.{field}'] = value
                continue
            if key == 'further_sharing':
                if len(values) == 1:
                    for field, subvalue in values[0].items():
                        meta[f'{key}.{field}'] = subvalue
                    continue
                further_sharing = defaultdict(list)
                for sharing in values:
                    feature = f"{key}.{sharing['rule_effect']}.sharing_scope"
                    further_sharing[feature].extend(sharing['sharing_scope'])
                meta.update(further_sharing)
                continue
            if key != 'extension_type':
                meta[key] = values
        return self._create_misp_galaxy_cluster(
            collection_uuid=self._create_v5_uuid(name),
            meta=meta, type=f'stix-{version}-acs-marking',
            version=''.join(version.split('.')),
            uuid=marking_definition['id'].split('--')[1],
            value=extension.get(
                'name',
                extension.get(
                    'identifier', marking_definition['id'].split('--')[1]
                )
            ),
            source=(
                self._handle_creator(marking_definition['created_by_ref'])
                if 'created_by_ref' in marking_definition else
                extension.get('responsible_entity_custodian')
            )
        )

    def _parse_marking_definition(
            self, marking_definition: _MARKING_DEFINITION_TYPING) -> Union[dict, str]:
        if 'definition_type' in marking_definition:
            definition_type = marking_definition['definition_type']
            definition = marking_definition['definition'][definition_type]
            if definition.startswith(f'{definition_type}:'):
                return definition
            return f"{definition_type}:{definition}"
        if 'name' in marking_definition:
            # should be TLP 2.0 definition
            return marking_definition['name'].lower()
        if 'extensions' in marking_definition:
            clusters = []
            tags = []
            version = marking_definition.get('spec_version', '2.0')
            for identifier in marking_definition['extensions'].keys():
                feature = self._mapping.marking_extension_mapping(identifier)
                if feature is None:
                    self._unknown_marking_definition_extension_error(identifier)
                    continue
                to_call = f'_parse_{feature}_marking_definition'
                clusters.append(
                    getattr(self, to_call)(
                        tags, marking_definition, identifier, version
                    )
                )
            if clusters:
                self._clusters[marking_definition['id']] = {
                    'used': {}, 'cluster': clusters
                }
                # A marking that yielded clusters was loaded successfully, even
                # when it produced no tags (e.g. an ACS marking with no meta):
                # return the (possibly empty) tags rather than raising.
                return tags
            if tags:
                return tags
        raise MarkingDefinitionLoadingError(marking_definition['id'])

    ############################################################################
    #                 MISP GALAXIES & CLUSTERS PARSING METHODS                 #
    ############################################################################

    def _aggregate_galaxy_clusters(self, galaxies: dict):
        for galaxy_type, clusters in galaxies.items():
            misp_galaxy = MISPGalaxy()
            misp_galaxy.from_dict(**self._galaxies[galaxy_type])
            for cluster in clusters:
                misp_galaxy.add_galaxy_cluster(**cluster)
            yield misp_galaxy

    ############################################################################
    #                RELATIONSHIPS & SIGHTINGS PARSING METHODS.                #
    ############################################################################

    def _check_sighting_replacements(
            self, parent_uuid: str, replaced_uuid: str):
        for field in ('opinion_refs', 'sighting'):
            if parent_uuid in getattr(self, '_sighting', {}).get(field, {}):
                self.replacement_uuids[replaced_uuid] = parent_uuid

    def _handle_opposite_reference(
            self, relationship_type: str, source_uuid: str, target_uuid: str):
        sanitised_uuid = self._sanitise_uuid(target_uuid)
        reference = (source_uuid, self.relationship_types[relationship_type])
        self._relationship[sanitised_uuid].add(reference)

    def _parse_attribute_relationships_as_container(
            self, attribute: MISPAttribute):
        clusters = defaultdict(list)
        for relationship in self._relationship[attribute.uuid]:
            referenced_uuid, relationship_type = relationship
            if referenced_uuid in self._clusters:
                cluster = self._clusters[referenced_uuid]
                clusters[cluster['cluster']['type']].append(cluster['cluster'])
                cluster['used'][self.misp_event.uuid] = True
                continue
            if relationship_type in self.relationship_types:
                self._handle_opposite_reference(
                    relationship_type, attribute.uuid, referenced_uuid
                )
        if clusters:
            self._add_attribute_galaxies(attribute, clusters)

    def _parse_attribute_relationships_as_tag_names(
            self, attribute: MISPAttribute):
        for relationship in self._relationship[attribute.uuid]:
            referenced_uuid, relationship_type = relationship
            if referenced_uuid in self._clusters:
                cluster = self._clusters[referenced_uuid]
                for tag in cluster['tag_names']:
                    attribute.add_tag(tag)
                cluster['used'][self.misp_event.uuid] = True
                continue
            if relationship_type in self.relationship_types:
                self._handle_opposite_reference(
                    relationship_type, attribute.uuid, referenced_uuid
                )

    def _parse_cluster_relationships(self, cluster: MISPGalaxyCluster):
        for relationship in self._relationship[cluster.uuid]:
            referenced_uuid, relationship_type = relationship
            if referenced_uuid in self._clusters:
                cluster.add_cluster_relation(
                    self._clusters[referenced_uuid]['cluster'].uuid,
                    relationship_type
                )

    def _parse_galaxy_relationships(self):
        for galaxy in self.misp_event.galaxies:
            for cluster in galaxy.clusters:
                if cluster.uuid in self._relationship:
                    self._parse_cluster_relationships(cluster)

    def _parse_object_relationships_as_container(self, misp_object: MISPObject):
        clusters = defaultdict(list)
        for relationship in self._relationship[misp_object.uuid]:
            referenced_id, relationship_type = relationship
            referenced_uuid = self._sanitise_uuid(referenced_id)
            if referenced_uuid == misp_object.uuid:
                continue
            if referenced_id in self._clusters:
                cluster = self._clusters[referenced_id]
                clusters[cluster['cluster']['type']].append(cluster['cluster'])
                cluster['used'][self.misp_event.uuid] = True
            else:
                misp_object.add_reference(referenced_uuid, relationship_type)
        if clusters:
            self._add_object_galaxies(misp_object, clusters)

    def _parse_object_relationships_as_tag_names(self, misp_object: MISPObject):
        for relationship in self._relationship[misp_object.uuid]:
            referenced_id, relationship_type = relationship
            referenced_uuid = self._sanitise_uuid(referenced_id)
            if referenced_uuid == misp_object.uuid:
                continue
            if referenced_id in self._clusters:
                cluster = self._clusters[referenced_id]
                for attribute in misp_object.attributes:
                    for tag in cluster['tag_names']:
                        attribute.add_tag(tag)
                cluster['used'][self.misp_event.uuid] = True
            else:
                misp_object.add_reference(referenced_uuid, relationship_type)

    def _parse_relationships(self):
        for attribute in self.misp_event.attributes:
            if attribute.uuid in self._relationship:
                getattr(
                    self,
                    f'_parse_attribute_relationships_{self.galaxy_feature}'
                )(
                    attribute
                )
        for misp_object in self.misp_event.objects:
            if misp_object.uuid in self._relationship:
                getattr(
                    self, f'_parse_object_relationships_{self.galaxy_feature}'
                )(
                    misp_object
                )
        getattr(self, f'_parse_galaxies_{self.galaxy_feature}')()
        if not self.galaxies_as_tags:
            self._parse_galaxy_relationships()

    def _parse_relationships_and_sightings(self):
        for attribute in self.misp_event.attributes:
            if attribute.uuid in self._relationship:
                getattr(
                    self,
                    f'_parse_attribute_relationships_{self.galaxy_feature}'
                )(
                    attribute
                )
            self._handle_attribute_sightings(attribute)
        for misp_object in self.misp_event.objects:
            if misp_object.uuid in self._relationship:
                getattr(
                    self, f'_parse_object_relationships_{self.galaxy_feature}'
                )(
                    misp_object
                )
            self._handle_object_sightings(misp_object)
        getattr(self, f'_parse_galaxies_{self.galaxy_feature}')()
        if not self.galaxies_as_tags:
            self._parse_galaxy_relationships()

    def _parse_sighting(self, sighting: _SIGHTING_TYPING) -> MISPSighting:
        misp_sighting = MISPSighting()
        sighting_args = {
            'date_sighting': self._timestamp_from_stix_date(
                sighting['modified']
            ),
            'type': '0'
        }
        if 'description' in sighting:
            sighting_args['source'] = sighting['description']
        if 'where_sighted_refs' in sighting:
            for reference in sighting['where_sighted_refs']:
                identity = self._identity.get(reference)
                if identity is None:
                    continue
                sighting_args['Organisation'] = {
                    'uuid': self._sanitise_uuid(identity['id']),
                    'name': identity['name']
                }
                misp_sighting.from_dict(**sighting_args)
                return misp_sighting

    def _parse_sightings(self):
        for attribute in self.misp_event.attributes:
            self._handle_attribute_sightings(attribute)
        for misp_object in self.misp_event.objects:
            self._handle_object_sightings(misp_object)
        getattr(self, f'_parse_galaxies_{self.galaxy_feature}')()

    ############################################################################
    #                      MISP FEATURES CREATION METHODS                      #
    ############################################################################

    def _add_analyst_data(self, data_layer: _DATA_LAYER_TYPING, reference: str):
        object_type = reference.split('--')[0]
        if object_type.startswith('x-misp-'):
            return getattr(self, f"_add_analyst_{object_type.split('-')[-1]}")(
                data_layer, reference
            )
        return getattr(self, f"_add_analyst_{object_type}")(
            data_layer, reference
        )

    def _add_analyst_note(self, data_layer: _DATA_LAYER_TYPING, reference: str):
        note = self._note[reference]
        if note.get('uuid') is None:
            note['uuid'] = self._create_v5_uuid(
                f'{reference} - {data_layer.uuid}'
            )
        data_layer.add_note(**note)

    def _add_analyst_opinion(
            self, data_layer: _DATA_LAYER_TYPING, reference: str):
        opinion = self._opinion[reference]
        if opinion.get('uuid') is None:
            opinion['uuid'] = self._create_v5_uuid(
                f'{reference} - {data_layer.uuid}'
            )
        data_layer.add_opinion(**opinion)

    def _add_misp_attribute(
            self, attribute: dict, stix_object: _SDO_TYPING) -> MISPAttribute:
        misp_attribute = self.misp_event.add_attribute(**attribute)
        if stix_object['id'] in self._analyst_data:
            for reference in self._analyst_data[stix_object['id']]:
                self._add_analyst_data(misp_attribute, reference)
        self._add_markings_to_misp_attribute(misp_attribute, stix_object)
        return misp_attribute

    def _add_misp_object(self, misp_object: MISPObject,
                         stix_object: _SDO_TYPING) -> MISPObject:
        if stix_object['id'] in self._analyst_data:
            for reference in self._analyst_data[stix_object['id']]:
                self._add_analyst_data(misp_object, reference)
        self._add_markings_to_misp_object(misp_object, stix_object)
        return self.misp_event.add_object(misp_object)

    def _create_generic_event(self) -> MISPEvent:
        misp_event = MISPEvent()
        event_args = {
            'uuid': self.identifier.split('--')[1],
            'info': self.generic_info_field,
            'distribution': self.distribution
        }
        if self.distribution == 4 and self.sharing_group_id is not None:
            event_args['sharing_group_id'] = self.sharing_group_id
        misp_event.from_dict(**event_args)
        if self.producer is not None:
            misp_event.add_tag(f'misp-galaxy:producer="{self.producer}"')
        elif len(self._creators) == 1:
            producer = self._handle_creator(tuple(self._creators)[0])
            misp_event.add_tag(f'misp-galaxy:producer="{producer}"')
        return misp_event

    def _create_misp_event(
            self, stix_object: _GROUPING_REPORT_TYPING) -> MISPEvent:
        misp_event = MISPEvent(force_timestamps=True)
        self._sanitise_object_uuid(misp_event, stix_object['id'])
        timestamp = self._timestamp_from_stix_date(stix_object['modified'])
        event_args = {
            'info': self._generate_info_field(stix_object),
            'distribution': self.distribution, 'timestamp': timestamp
        }
        if self.distribution == 4 and self.sharing_group_id is not None:
            event_args['sharing_group_id'] = self.sharing_group_id
        misp_event.from_dict(**event_args)
        if 'description' in stix_object:
            event_report = MISPEventReport()
            event_report.from_dict(
                content=stix_object['description'], timestamp=timestamp,
                name=(
                    f'STIX {self.stix_version} '
                    f'{stix_object["type"]} description'
                ),
                uuid=self._create_v5_uuid(
                    f'description - {stix_object["id"]}'
                )
            )
            misp_event.add_event_report(**event_report)
        if stix_object['id'] in self._analyst_data:
            for reference in self._analyst_data[stix_object['id']]:
                self._add_analyst_data(misp_event, reference)
        if self.producer is not None:
            misp_event.add_tag(f'misp-galaxy:producer="{self.producer}"')
        elif 'created_by_ref' in stix_object:
            producer = self._handle_creator(stix_object['created_by_ref'])
            misp_event.add_tag(f'misp-galaxy:producer="{producer}"')
        self._event_tags = set()
        self._add_markings_to_misp_event(misp_event, stix_object)
        if 'labels' in stix_object:
            labels = (
                label for label in stix_object['labels']
                if label.lower() != 'threat-report'
            )
            for label in labels:
                misp_event.add_tag(label)
        return misp_event

    @staticmethod
    def _create_misp_galaxy_cluster(**cluster_args: dict) -> MISPGalaxyCluster:
        cluster = MISPGalaxyCluster()
        cluster.from_dict(**cluster_args)
        cluster.parse_meta_as_elements()
        return cluster

    ############################################################################
    #                             UTILITY METHODS.                             #
    ############################################################################

    @staticmethod
    def _extract_uuid(object_id: str) -> str:
        return object_id.split('--')[-1]

    @staticmethod
    def _stix_date(date: datetime | str) -> datetime:
        """Read a date field whatever form the object carrying it takes.

        Typed STIX objects expose their dates as `datetime` values, while the
        dict-form ones keep the string the document carried. Both reach the
        same MISP-side code, which only knows what to do with a `datetime`.
        """
        if isinstance(date, str):
            return parse_into_datetime(date)
        return date

    @classmethod
    def _timestamp_from_stix_date(cls, date: datetime | str) -> int:
        return cls._timestamp_from_date(cls._stix_date(date))

    def _generate_info_field(self, stix_object: _GROUPING_REPORT_TYPING) -> str:
        if 'name' in stix_object:
            title = stix_object['name']
            if self.event_title is not None:
                title = f'{self.event_title} {title}'
            return title
        return self.generic_info_field

    def _handle_creator(self, reference: str) -> str:
        if reference in getattr(self, '_identity', {}):
            return self._identity[reference]['name']
        return self._mapping.identity_references(reference) or 'misp-stix'

    def _is_tlp_marking(self, marking_ref: str) -> bool:
        tlp_2_marking = self._mapping.tlp2_marking_definitions(marking_ref)
        if tlp_2_marking is not None:
            self._load_marking_definition(tlp_2_marking)
            return True
        for marking in (TLP_WHITE, TLP_GREEN, TLP_AMBER, TLP_RED):
            if marking_ref == marking['id']:
                self._load_marking_definition(marking)
                return True
        return False

    @staticmethod
    def _parse_confidence_level(confidence_level: int) -> str:
        if confidence_level == 100:
            return 'misp:confidence-level="completely-confident"'
        if confidence_level >= 75:
            return 'misp:confidence-level="usually-confident"'
        if confidence_level >= 50:
            return 'misp:confidence-level="fairly-confident"'
        if confidence_level >= 25:
            return 'misp:confidence-level="rarely-confident"'
        return 'misp:confidence-level="unconfident"'

    ############################################################################
    #                   ERRORS AND WARNINGS HANDLING METHODS                   #
    ############################################################################

    def _object_ref_loading_error(self, object_ref: str):
        self._add_error(f'Error loading the STIX object with id {object_ref}')

    def _object_type_loading_error(self, object_type: str):
        self._add_error(f'Error loading the STIX object of type {object_type}')

    def _unknown_marking_definition_extension_error(self, identifier: str):
        self._add_error(
            f'Unknown STIX Marking Definition extension: {identifier}'
        )

    def _unknown_network_protocol_warning(
            self, protocol: str, object_id: str,
            object_type: Optional[str] = 'indicator'):
        message = (
            'in patterning expression within the indicator with id'
            if object_type == 'indicator' else
            f'within the {object_type} object with id'
        )
        self._add_warning(
            f'Unknown network protocol: {protocol}, {message} {object_id}'
        )

    def _unknown_parsing_function_error(self, feature: Exception):
        self._add_error(f'Unknown STIX parsing function name: {feature}')

    def _unknown_stix_object_type_error(self, object_type: Exception):
        self._add_error(f'Unknown STIX object type: {object_type}')
