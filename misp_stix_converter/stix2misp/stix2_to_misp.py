#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import time
from .converters import (
    ExternalSTIX2AttackPatternConverter, ExternalSTIX2MalwareAnalysisConverter,
    ExternalSTIX2CampaignConverter, InternalSTIX2CampaignConverter,
    ExternalSTIX2CourseOfActionConverter, InternalSTIX2CourseOfActionConverter,
    ExternalSTIX2IdentityConverter, InternalSTIX2IdentityConverter,
    ExternalSTIX2IndicatorConverter, InternalSTIX2IndicatorConverter,
    ExternalSTIX2IntrusionSetConverter, InternalSTIX2IntrusionSetConverter,
    ExternalSTIX2LocationConverter, InternalSTIX2LocationConverter,
    ExternalSTIX2MalwareConverter, InternalSTIX2AttackPatternConverter,
    InternalSTIX2MalwareAnalysisConverter, InternalSTIX2MalwareConverter,
    ExternalSTIX2ObservedDataConverter, InternalSTIX2ObservedDataConverter,
    ExternalSTIX2ThreatActorConverter, InternalSTIX2ThreatActorConverter,
    ExternalSTIX2ToolConverter, InternalSTIX2ToolConverter,
    ExternalSTIX2VulnerabilityConverter, InternalSTIX2VulnerabilityConverter)
from .exceptions import (
    MarkingDefinitionLoadingError, ObjectRefLoadingError,
    ObjectTypeLoadingError, SynonymsResourceJSONError,
    UnavailableGalaxyResourcesError, UnavailableSynonymsResourceError,
    UndefinedIndicatorError, UndefinedSTIXObjectError, UndefinedObservableError,
    UnknownAttributeTypeError, UnknownObjectNameError,
    UnknownParsingFunctionError, UnknownPatternTypeError,
    UnknownStixObjectTypeError)
from .external_stix2_mapping import ExternalSTIX2toMISPMapping
from .importparser import (
    STIXtoMISPParser, _INDICATOR_TYPING, _load_stix2_content)
from .internal_stix2_mapping import InternalSTIX2toMISPMapping
from abc import ABCMeta
from collections import defaultdict
from datetime import datetime
from pymisp import (
    MISPEvent, MISPAttribute, MISPGalaxy, MISPGalaxyCluster,
    MISPObject, MISPSighting)
from stix2 import TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE
from stix2.v20.bundle import Bundle as Bundle_v20
from stix2.v20.common import MarkingDefinition as MarkingDefinition_v20
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
    Artifact, AutonomousSystem, Directory, DomainName, EmailAddress,
    EmailMessage, File, IPv4Address, IPv6Address, MACAddress, Mutex,
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
from typing import Optional, Union

# Some constants
_LOADED_FEATURES = (
    '_attack_pattern',
    '_campaign',
    '_course_of_action',
    '_custom_attribute',
    '_custom_object',
    '_identity',
    '_indicator',
    '_intrusion_set',
    '_malware',
    '_malware_analysis',
    '_note',
    '_observed_data',
    '_opinion',
    '_threat_actor',
    '_tool',
    '_vulnerability'
)

# Typing
_OBSERVABLE_TYPING = Union[
    Artifact, AutonomousSystem, Directory, DomainName, EmailAddress,
    EmailMessage, File, IPv4Address, IPv6Address, MACAddress, Mutex,
    NetworkTraffic_v21, Process, Software, URL, UserAccount, WindowsRegistryKey,
    X509Certificate
]
_ATTACK_PATTERN_PARSER_TYPING = Union[
    ExternalSTIX2AttackPatternConverter, InternalSTIX2AttackPatternConverter
]
_ATTACK_PATTERN_TYPING = Union[
    AttackPattern_v20, AttackPattern_v21
]
_CAMPAIGN_PARSER_TYPING = Union[
    ExternalSTIX2CampaignConverter, InternalSTIX2CampaignConverter
]
_CAMPAIGN_TYPING = Union[
    Campaign_v20, Campaign_v21
]
_COURSE_OF_ACTION_PARSER_TYPING = Union[
    ExternalSTIX2CourseOfActionConverter, InternalSTIX2CourseOfActionConverter
]
_COURSE_OF_ACTION_TYPING = Union[
    CourseOfAction_v20, CourseOfAction_v21
]
_GALAXY_OBJECTS_TYPING = Union[
    AttackPattern_v20, AttackPattern_v21,
    Campaign_v20, Campaign_v21,
    CourseOfAction_v20, CourseOfAction_v21,
    IntrusionSet_v20, IntrusionSet_v21,
    Location,
    Malware_v20, Malware_v21,
    ThreatActor_v20, ThreatActor_v21,
    Tool_v20, Tool_v21,
    Vulnerability_v20, Vulnerability_v21
]
_GROUPING_REPORT_TYPING = Union[
    Grouping, Report_v20, Report_v21
]
_IDENTITY_PARSER_TYPING = Union[
    ExternalSTIX2IdentityConverter, InternalSTIX2IdentityConverter
]
_IDENTITY_TYPING = Union[
    Identity_v20, Identity_v21
]
_INDICATOR_PARSER_TYPING = Union[
    ExternalSTIX2IndicatorConverter, InternalSTIX2IndicatorConverter
]
_INTRUSION_SET_PARSER_TYPING = Union[
    ExternalSTIX2IntrusionSetConverter, InternalSTIX2IntrusionSetConverter
]
_INTRUSION_SET_TYPING = Union[
    IntrusionSet_v20, IntrusionSet_v21
]
_LOCATION_PARSER_TYPING = Union[
    ExternalSTIX2LocationConverter, InternalSTIX2LocationConverter
]
_MALWARE_ANALYSIS_PARSER_TYPING = Union[
    ExternalSTIX2MalwareAnalysisConverter, InternalSTIX2MalwareAnalysisConverter
]
_MALWARE_PARSER_TYPING = Union[
    ExternalSTIX2MalwareConverter, InternalSTIX2MalwareConverter
]
_MALWARE_TYPING = Union[
    Malware_v20, Malware_v21
]
_MARKING_DEFINITION_TYPING = Union[
    MarkingDefinition_v20, MarkingDefinition_v21
]
_MISP_FEATURES_TYPING = Union[
    MISPAttribute, MISPEvent, MISPObject
]
_OBSERVED_DATA_PARSER_TYPING = Union[
    ExternalSTIX2ObservedDataConverter, InternalSTIX2ObservedDataConverter
]
_OBSERVED_DATA_TYPING = Union[
    ObservedData_v20, ObservedData_v21
]
_RELATIONSHIP_TYPING = Union[
    Relationship_v20, Relationship_v21
]
_REPORT_TYPING = Union[
    Report_v20, Report_v21
]
_SDO_TYPING = Union[
    Campaign_v20, Campaign_v21,
    CustomObject_v20, CustomObject_v21,
    Grouping,
    Indicator_v20, Indicator_v21,
    ObservedData_v20, ObservedData_v21,
    Report_v20, Report_v21,
    Vulnerability_v20, Vulnerability_v21
]
_SIGHTING_TYPING = Union[
    Sighting_v20, Sighting_v21
]
_THREAT_ACTOR_PARSER_TYPING = Union[
    ExternalSTIX2ThreatActorConverter, InternalSTIX2ThreatActorConverter
]
_THREAT_ACTOR_TYPING = Union[
    ThreatActor_v20, ThreatActor_v21
]
_TOOL_PARSER_TYPING = Union[
    ExternalSTIX2ToolConverter, InternalSTIX2ToolConverter
]
_TOOL_TYPING = Union[
    Tool_v20, Tool_v21
]
_VULNERABILITY_PARSER_TYPING = Union[
    ExternalSTIX2VulnerabilityConverter, InternalSTIX2VulnerabilityConverter
]
_VULNERABILITY_TYPING = Union[
    Vulnerability_v20, Vulnerability_v21
]


class STIX2toMISPParser(STIXtoMISPParser, metaclass=ABCMeta):
    def __init__(self, distribution: int, sharing_group_id: Union[int, None],
                 galaxies_as_tags: bool):
        super().__init__(distribution, sharing_group_id, galaxies_as_tags)
        self._creators: set = set()
        self._mapping: Union[
            ExternalSTIX2toMISPMapping, InternalSTIX2toMISPMapping
        ]

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

    def load_stix_bundle(self, bundle: Union[Bundle_v20, Bundle_v21]):
        self._identifier = bundle.id
        self.__stix_version = getattr(bundle, 'spec_version', '2.1')
        n_report = 0
        for stix_object in bundle.objects:
            try:
                object_type = stix_object.type
            except AttributeError:
                object_type = stix_object['type']
            if object_type in ('grouping', 'report'):
                n_report += 1
            feature = self._mapping.stix_object_loading_mapping(object_type)
            if feature is None:
                self._unable_to_load_stix_object_type_error(object_type)
                continue
            if hasattr(stix_object, 'created_by_ref'):
                self._creators.add(stix_object.created_by_ref)
            try:
                getattr(self, feature)(stix_object)
            except MarkingDefinitionLoadingError as error:
                self._marking_definition_error(error)
            except AttributeError as exception:
                self._critical_error(exception)
        self.__n_report = 2 if n_report >= 2 else n_report

    def parse_stix_bundle(self, single_event: Optional[bool] = False):
        self.__single_event = single_event
        try:
            feature = self._mapping.bundle_to_misp_mapping(str(self.__n_report))
        except AttributeError:
            sys.exit(
                'No STIX content loaded, please run `load_stix_content` first.'
            )
        try:
            getattr(self, feature)()
        except (
            SynonymsResourceJSONError,
            UnavailableGalaxyResourcesError,
            UnavailableSynonymsResourceError
        ) as error:
            self._critical_error(error)
        for feature in ('_grouping', 'report', *_LOADED_FEATURES):
            if hasattr(self, feature):
                setattr(self, feature, {})

    def parse_stix_content(
            self, filename: str, single_event: Optional[bool] = False):
        try:
            bundle = _load_stix2_content(filename)
        except Exception as exception:
            sys.exit(exception)
        self.load_stix_bundle(bundle)
        del bundle
        self.parse_stix_bundle(single_event)

    ############################################################################
    #                                PROPERTIES                                #
    ############################################################################

    @property
    def attack_pattern_parser(self) -> _ATTACK_PATTERN_PARSER_TYPING:
        if not hasattr(self, '_attack_pattern_parser'):
            self._set_attack_pattern_parser()
        return self._attack_pattern_parser

    @property
    def campaign_parser(self) -> _CAMPAIGN_PARSER_TYPING:
        if not hasattr(self, '_campaign_parser'):
            self._set_campaign_parser()
        return self._campaign_parser

    @property
    def course_of_action_parser(self) -> _COURSE_OF_ACTION_PARSER_TYPING:
        if not hasattr(self, '_course_of_action_parser'):
            self._set_course_of_action_parser()
        return self._course_of_action_parser

    @property
    def event_tags(self) -> list:
        return self.__event_tags

    @property
    def generic_info_field(self) -> str:
        return f'STIX {self.stix_version} Bundle imported with the MISP-STIX import feature.'

    @property
    def identity_parser(self) -> _IDENTITY_PARSER_TYPING:
        if not hasattr(self, '_identity_parser'):
            self._set_identity_parser()
        return self._identity_parser

    @property
    def indicator_parser(self) -> _INDICATOR_PARSER_TYPING:
        if not hasattr(self, '_indicator_parser'):
            self._set_indicator_parser()
        return self._indicator_parser

    @property
    def intrusion_set_parser(self) -> _INTRUSION_SET_PARSER_TYPING:
        if not hasattr(self, '_intrusion_set_parser'):
            self._set_intrusion_set_parser()
        return self._intrusion_set_parser

    @property
    def location_parser(self) -> _LOCATION_PARSER_TYPING:
        if not hasattr(self, '_location_parser'):
            self._set_location_parser()
        return self._location_parser

    @property
    def malware_analysis_parser(self) -> _MALWARE_ANALYSIS_PARSER_TYPING:
        if not hasattr(self, '_malware_analysis_parser'):
            self._set_malware_analysis_parser()
        return self._malware_analysis_parser

    @property
    def malware_parser(self) -> _MALWARE_PARSER_TYPING:
        if not hasattr(self, '_malware_parser'):
            self._set_malware_parser()
        return self._malware_parser

    @property
    def misp_event(self) -> MISPEvent:
        return self.__misp_event

    @property
    def misp_events(self) -> Union[list, MISPEvent]:
        return getattr(
            self, '_STIX2toMISPParser__misp_events', self.__misp_event
        )

    @property
    def observed_data_parser(self) -> _OBSERVED_DATA_PARSER_TYPING:
        if not hasattr(self, '_observed_data_parser'):
            self._set_observed_data_parser()
        return self._observed_data_parser

    @property
    def single_event(self) -> bool:
        return self.__single_event

    @property
    def stix_version(self) -> str:
        return self.__stix_version

    @property
    def threat_actor_parser(self) -> _THREAT_ACTOR_PARSER_TYPING:
        if not hasattr(self, '_threat_actor_parser'):
            self._set_threat_actor_parser()
        return self._threat_actor_parser

    @property
    def tool_parser(self) -> _TOOL_PARSER_TYPING:
        if not hasattr(self, '_tool_parser'):
            self._set_tool_parser()
        return self._tool_parser

    @property
    def vulnerability_parser(self) -> _VULNERABILITY_PARSER_TYPING:
        if not hasattr(self, '_vulnerability_parser'):
            self._set_vulnerability_parser()
        return self._vulnerability_parser

    ############################################################################
    #                       STIX OBJECTS LOADING METHODS                       #
    ############################################################################

    def _load_attack_pattern(self, attack_pattern: _ATTACK_PATTERN_TYPING):
        self._check_uuid(attack_pattern.id)
        try:
            self._attack_pattern[attack_pattern.id] = attack_pattern
        except AttributeError:
            self._attack_pattern = {attack_pattern.id: attack_pattern}

    def _load_campaign(self, campaign: _CAMPAIGN_TYPING):
        self._check_uuid(campaign.id)
        try:
            self._campaign[campaign.id] = campaign
        except AttributeError:
            self._campaign = {campaign.id: campaign}

    def _load_course_of_action(
            self, course_of_action: _COURSE_OF_ACTION_TYPING):
        self._check_uuid(course_of_action.id)
        try:
            self._course_of_action[course_of_action.id] = course_of_action
        except AttributeError:
            self._course_of_action = {course_of_action.id: course_of_action}

    def _load_grouping(self, grouping: Grouping):
        self._check_uuid(grouping.id)
        try:
            self._grouping[grouping.id] = grouping
        except AttributeError:
            self._grouping = {grouping.id: grouping}

    def _load_identity(self, identity: _IDENTITY_TYPING):
        self._check_uuid(identity.id)
        try:
            self._identity[identity.id] = identity
        except AttributeError:
            self._identity = {identity.id: identity}

    def _load_indicator(self, indicator: _INDICATOR_TYPING):
        self._check_uuid(indicator.id)
        try:
            self._indicator[indicator.id] = indicator
        except AttributeError:
            self._indicator = {indicator.id: indicator}

    def _load_intrusion_set(self, intrusion_set: _INTRUSION_SET_TYPING):
        self._check_uuid(intrusion_set.id)
        try:
            self._intrusion_set[intrusion_set.id] = intrusion_set
        except AttributeError:
            self._intrusion_set = {intrusion_set.id: intrusion_set}

    def _load_location(self, location: Location):
        self._check_uuid(location['id'])
        try:
            self._location[location['id']] = location
        except AttributeError:
            self._location = {location['id']: location}

    def _load_malware(self, malware: _MALWARE_TYPING):
        self._check_uuid(malware.id)
        try:
            self._malware[malware.id] = malware
        except AttributeError:
            self._malware = {malware.id: malware}

    def _load_malware_analysis(self, malware_analysis: MalwareAnalysis):
        self._check_uuid(malware_analysis.id)
        try:
            self._malware_analysis[malware_analysis.id] = malware_analysis
        except AttributeError:
            self._malware_analysis = {malware_analysis.id: malware_analysis}

    def _load_marking_definition(
            self, marking_definition: _MARKING_DEFINITION_TYPING):
        tag = self._parse_marking_definition(marking_definition)
        try:
            self._marking_definition[marking_definition.id] = tag
        except AttributeError:
            self._marking_definition = {marking_definition.id: tag}

    def _load_note(self, note: Note):
        self._check_uuid(note.id)
        try:
            self._note[note.id] = note
        except AttributeError:
            self._note = {note.id: note}

    def _load_observed_data(self, observed_data: _OBSERVED_DATA_TYPING):
        self._check_uuid(observed_data.id)
        try:
            self._observed_data[observed_data.id] = observed_data
        except AttributeError:
            self._observed_data = {observed_data.id: observed_data}

    def _load_opinion(self, opinion: Opinion):
        opinion_ref = self._sanitise_uuid(opinion.id)
        try:
            self._sighting['opinion'][opinion_ref] = opinion
        except AttributeError:
            self._sighting = defaultdict(lambda: defaultdict(list))
            self._sighting['opinion'][opinion_ref] = opinion
        for object_ref in opinion.object_refs:
            sanitised_ref = self._sanitise_uuid(object_ref)
            self._sighting['opinion_refs'][sanitised_ref].append(opinion_ref)

    def _load_relationship(self, relationship: _RELATIONSHIP_TYPING):
        reference = (relationship.target_ref, relationship.relationship_type)
        source_uuid = self._sanitise_uuid(relationship.source_ref)
        try:
            self._relationship[source_uuid].add(reference)
        except AttributeError:
            self._relationship = defaultdict(set)
            self._relationship[source_uuid].add(reference)

    def _load_report(self, report: _REPORT_TYPING):
        self._check_uuid(report.id)
        try:
            self._report[report.id] = report
        except AttributeError:
            self._report = {report.id: report}

    def _load_sighting(self, sighting: _SIGHTING_TYPING):
        sighting_of_ref = self._sanitise_uuid(sighting.sighting_of_ref)
        try:
            self._sighting['sighting'][sighting_of_ref].append(sighting)
        except AttributeError:
            self._sighting = defaultdict(lambda: defaultdict(list))
            self._sighting['sighting'][sighting_of_ref].append(sighting)

    def _load_threat_actor(self, threat_actor: _THREAT_ACTOR_TYPING):
        self._check_uuid(threat_actor.id)
        try:
            self._threat_actor[threat_actor.id] = threat_actor
        except AttributeError:
            self._threat_actor = {threat_actor.id: threat_actor}

    def _load_tool(self, tool: _TOOL_TYPING):
        self._check_uuid(tool.id)
        try:
            self._tool[tool.id] = tool
        except AttributeError:
            self._tool = {tool.id: tool}

    def _load_vulnerability(self, vulnerability: _VULNERABILITY_TYPING):
        self._check_uuid(vulnerability.id)
        try:
            self._vulnerability[vulnerability.id] = vulnerability
        except AttributeError:
            self._vulnerability = {vulnerability.id: vulnerability}

    ############################################################################
    #                    MAIN STIX OBJECTS PARSING METHODS.                    #
    ############################################################################

    def _get_stix_object(self, object_ref: str):
        object_type = object_ref.split('--')[0]
        if object_type.startswith('x-misp-'):
            object_type = object_type.replace('x-misp', 'custom')
        feature = f"_{object_type.replace('-', '_')}"
        try:
            return getattr(self, feature)[object_ref]
        except AttributeError:
            raise ObjectTypeLoadingError(object_type)
        except KeyError:
            raise ObjectRefLoadingError(object_ref)

    def _handle_unparsed_content(self):
        if hasattr(self, '_observed_data_parser'):
            if hasattr(self.observed_data_parser, '_observable_relationships'):
                self.observed_data_parser.parse_relationships()
        if hasattr(self, '_relationship'):
            if hasattr(self, '_sighting'):
                self._parse_relationships_and_sightings()
            else:
                self._parse_relationships()
        elif hasattr(self, '_sighting'):
            self._parse_sightings()
        else:
            getattr(self, f'_parse_galaxies_{self.galaxy_feature}')()

    def _handle_object(self, object_type: str, object_ref: str):
        feature = self._mapping.stix_to_misp_mapping(object_type)
        if feature is None:
            raise UnknownStixObjectTypeError(object_type)
        try:
            parser = getattr(self, feature)
        except AttributeError:
            raise UnknownParsingFunctionError(feature)
        try:
            parser.parse(object_ref)
        except ObjectRefLoadingError as error:
            self._object_ref_loading_error(error)
        except ObjectTypeLoadingError as error:
            self._object_type_loading_error(error)
        except UndefinedIndicatorError as error:
            self._undefined_indicator_error(error)
        except UndefinedSTIXObjectError as error:
            self._undefined_object_error(error)
        except UndefinedObservableError as error:
            self._undefined_observable_error(error)
        except UnknownAttributeTypeError as error:
            self._unknown_attribute_type_warning(error)
        except UnknownObjectNameError as error:
            self._unknown_object_name_warning(error)
        except UnknownParsingFunctionError as error:
            self._unknown_parsing_function_error(error)
        except UnknownPatternTypeError as error:
            self._unknown_pattern_type_error(object_ref, error)

    def _handle_misp_event_tags(
            self, misp_event: MISPEvent, stix_object: _GROUPING_REPORT_TYPING):
        self.__event_tags = set()
        for marking in self._handle_tags_from_stix_fields(stix_object):
            if isinstance(marking, str):
                misp_event.add_tag(marking)
                self.event_tags.add(marking)
                continue
            if not self.galaxies_as_tags:
                clusters = defaultdict(list)
                for cluster in marking['cluster']:
                    clusters[cluster.type].append(cluster)
                    self.event_tags.add(cluster.uuid)
                for galaxy in self._aggregate_galaxy_clusters(clusters):
                    misp_event.add_galaxy(galaxy)
            if marking.get('tags'):
                for tag in marking['tags']:
                    self.event_tags.add(tag)
                    misp_event.add_tag(tag)
        if hasattr(stix_object, 'labels'):
            labels = (
                label for label in stix_object.labels
                if label.lower() != 'threat-report'
            )
            for label in labels:
                misp_event.add_tag(label)

    def _misp_event_from_grouping(self, grouping: Grouping) -> MISPEvent:
        misp_event = self._create_misp_event(grouping)
        misp_event.published = False
        return misp_event

    def _misp_event_from_report(self, report: _REPORT_TYPING) -> MISPEvent:
        misp_event = self._create_misp_event(report)
        if report.published != report.modified:
            misp_event.published = True
            misp_event.publish_timestamp = self._timestamp_from_date(
                report.published
            )
        else:
            misp_event.published = False
        return misp_event

    def _parse_bundle_with_multiple_reports(self):
        if self.single_event:
            self.__misp_event = self._create_generic_event()
            if hasattr(self, '_report') and self._report is not None:
                for report in self._report.values():
                    self._handle_object_refs(report.object_refs)
            if hasattr(self, '_grouping') and self._grouping is not None:
                for grouping in self._grouping.values():
                    self._handle_object_refs(grouping.object_refs)
            self._handle_unparsed_content()
        else:
            self.__misp_events = []
            if hasattr(self, '_report') and self._report is not None:
                for report in self._report.values():
                    self.__misp_event = self._misp_event_from_report(report)
                    self._handle_object_refs(report.object_refs)
                    self._handle_unparsed_content()
                    self.__misp_events.append(self.misp_event)
            if hasattr(self, '_grouping') and self._grouping is not None:
                for grouping in self._grouping.values():
                    self.__misp_event = self._misp_event_from_grouping(grouping)
                    self._handle_object_refs(grouping.object_refs)
                    self._handle_unparsed_content()
                    self.__misp_events.append(self.misp_event)

    def _parse_bundle_with_no_report(self):
        self.__single_event = True
        self.__misp_event = self._create_generic_event()
        self._parse_loaded_features()
        self._handle_unparsed_content()

    def _parse_bundle_with_single_report(self):
        self.__single_event = True
        if hasattr(self, '_report') and self._report is not None:
            for report in self._report.values():
                self.__misp_event = self._misp_event_from_report(report)
                self._handle_object_refs(report.object_refs)
        elif hasattr(self, '_grouping') and self._grouping is not None:
            for grouping in self._grouping.values():
                self.__misp_event = self._misp_event_from_grouping(grouping)
                self._handle_object_refs(grouping.object_refs)
        else:
            self._parse_bundle_with_no_report()
        self._handle_unparsed_content()

    def _parse_galaxies_as_container(self):
        clusters = defaultdict(list)
        for cluster in self._clusters.values():
            if self.misp_event.uuid not in cluster['used']:
                continue
            if not cluster['used'][self.misp_event.uuid]:
                misp_cluster = cluster['cluster']
                clusters[misp_cluster.type].append(misp_cluster)
        if clusters:
            for galaxy in self._aggregate_galaxy_clusters(clusters):
                self.misp_event.add_galaxy(galaxy)

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
    #                   MARKING DEFINITIONS PARSING METHODS.                   #
    ############################################################################

    def _parse_acs_marking_definition(
            self, extension_definition: dict,
            marking_definition: _MARKING_DEFINITION_TYPING,
            identifier: str, version: str):
        extension = marking_definition.extensions[identifier]
        galaxy_type = f'stix-{version}-acs-marking'
        name = f'STIX {version} ACS Marking'
        if galaxy_type not in self._galaxies:
            self._galaxies[galaxy_type] = {
                'namespace': 'stix', 'type': galaxy_type,
                'version': ''.join(version.split('.')),
                'uuid': self._create_v5_uuid(name), 'name': name,
                'description': (
                    f'STIX {version} Marking Definition extension'
                    ' to support ACS Markings'
                )
            }
        meta = {}
        for key, value in extension.items():
            if isinstance(value, dict):
                for field, subvalues in value.items():
                    if field in self._mapping.marking_vocabularies_fields():
                        if isinstance(subvalues, list):
                            for subvalue in subvalues:
                                extension_definition['tags'].append(
                                    f'acs-marking:{field}="{subvalue}"'
                                )
                        else:
                            extension_definition['tags'].append(
                                f'acs-marking:{field}="{subvalues}"'
                            )
                    meta[f'{key}.{field}'] = subvalues
                continue
            if key == 'access_privilege':
                if len(value) == 1:
                    access_privilege = value[0]
                    for feature, privilege in access_privilege.items():
                        if isinstance(privilege, dict):
                            for field, scope in privilege.items():
                                meta[f'{key}.{feature}.{field}'] = scope
                            continue
                        if (feature == 'privilege_action' and
                                access_privilege['rule_effect'] == 'permit'):
                            extension_definition['tags'].append(
                                f'acs-marking:{feature}="{privilege}"'
                            )
                        meta[f'{key}.{feature}'] = privilege
                    continue
                for privilege in value:
                    feature = f"{key}.{privilege['privilege_action']}"
                    for field, scope in privilege['privilege_scope'].items():
                        meta[f'{feature}.privilege_scope.{field}'] = scope
                    meta[f'{feature}.rule_effect'] = privilege['rule_effect']
                continue
            if key == 'further_sharing':
                if len(value) == 1:
                    for field, subvalue in value[0].items():
                        meta[f'{key}.{field}'] = subvalue
                    continue
                for sharing in value:
                    feature = f"{key}.{sharing['rule_effect']}"
                    meta[f"{feature}.sharing_scope"] = sharing['sharing_scope']
                continue
            if key != 'extension_type':
                meta[key] = value
        galaxy_cluster = self._create_misp_galaxy_cluster(
            collection_uuid=self._create_v5_uuid(name),
            meta=meta, type=f'stix-{version}-acs-marking',
            version=''.join(version.split('.')),
            value=extension.get('name', extension['identifier']),
            source=(
                self._handle_creator(marking_definition.created_by_ref)
                if hasattr(marking_definition, 'created_by_ref') else
                extension['responsible_entity_custodian']
            ),
            uuid=self._create_v5_uuid(
                f'{marking_definition.id} - {identifier}'
            )
        )
        extension_definition['cluster'].append(galaxy_cluster)

    def _parse_marking_definition(
            self, marking_definition: _MARKING_DEFINITION_TYPING
            ) -> Union[dict, str]:
        if hasattr(marking_definition, 'definition_type'):
            definition_type = marking_definition.definition_type
            definition = marking_definition.definition[definition_type]
            return f"{definition_type}:{definition}"
        if hasattr(marking_definition, 'name'):
            # should be TLP 2.0 definition
            return marking_definition.name.lower()
        if hasattr(marking_definition, 'extensions'):
            extension_definition = defaultdict(list)
            version = getattr(marking_definition, 'spec_version', '2.0')
            for identifier in marking_definition.extensions.keys():
                feature = self._mapping.marking_extension_mapping(identifier)
                if feature is None:
                    continue
                getattr(self, f'_parse_{feature}_marking_definition')(
                    extension_definition,
                    marking_definition, identifier, version
                )
            if extension_definition:
                return extension_definition
        raise MarkingDefinitionLoadingError(marking_definition.id)

    def _parse_markings(self, marking_refs: list):
        for marking_ref in marking_refs:
            try:
                marking_definition = self._get_stix_object(marking_ref)
            except ObjectTypeLoadingError as error:
                self._object_type_loading_error(error)
                continue
            except ObjectRefLoadingError as error:
                self._object_ref_loading_error(error)
                continue
            yield marking_definition

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

    def _handle_attribute_sightings(self, attribute: MISPAttribute):
        attribute_uuid = attribute.uuid
        if attribute_uuid in self.replacement_uuids:
            attribute_uuid = self.replacement_uuids[attribute_uuid]
        if attribute_uuid in self._sighting.get('sighting', {}):
            for sighting in self._sighting['sighting'][attribute_uuid]:
                attribute.add_sighting(self._parse_sighting(sighting))
        if attribute_uuid in self._sighting.get('opinion_refs', {}):
            for opinion_ref in self._sighting['opinion_refs'][attribute_uuid]:
                attribute.add_sighting(
                    self._parse_opinion(self._sighting['opinion'][opinion_ref])
                )
        elif attribute_uuid in self._sighting.get('custom_opinion', {}):
            for sighting in self._sighting['custom_opinion'][attribute_uuid]:
                attribute.add_sighting(sighting)

    def _handle_object_sightings(self, misp_object: MISPObject):
        object_uuid = misp_object.uuid
        if object_uuid in self.replacement_uuids:
            object_uuid = self.replacement_uuids[object_uuid]
        if object_uuid in self._sighting.get('sighting', {}):
            for sighting in self._sighting['sighting'][object_uuid]:
                misp_sighting = self._parse_sighting(sighting)
                for attribute in misp_object.attributes:
                    attribute.add_sighting(misp_sighting)
        if object_uuid in self._sighting.get('opinion_refs', {}):
            for opinion_ref in self._sighting['opinion_refs'][object_uuid]:
                misp_sighting = self._parse_opinion(
                    self._sighting['opinion'][opinion_ref]
                )
                for attribute in misp_object.attributes:
                    attribute.add_sighting(misp_sighting)
        elif misp_object.uuid in self._sighting.get('custom_opinion', {}):
            for sighting in self._sighting['custom_opinion'][object_uuid]:
                for attribute in misp_object.attributes:
                    attribute.add_sighting(sighting)

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
            for galaxy in self._aggregate_galaxy_clusters(clusters):
                attribute.add_galaxy(galaxy)

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
            referenced_uuid, relationship_type = relationship
            if referenced_uuid in self._clusters:
                cluster = self._clusters[referenced_uuid]
                clusters[cluster['cluster']['type']].append(cluster['cluster'])
                cluster['used'][self.misp_event.uuid] = True
            else:
                misp_object.add_reference(
                    self._sanitise_uuid(referenced_uuid), relationship_type
                )
        if clusters:
            for galaxy in self._aggregate_galaxy_clusters(clusters):
                for attribute in misp_object.attributes:
                    attribute.add_galaxy(galaxy)

    def _parse_object_relationships_as_tag_names(self, misp_object: MISPObject):
        for relationship in self._relationship[misp_object.uuid]:
            referenced_uuid, relationship_type = relationship
            if referenced_uuid in self._clusters:
                cluster = self._clusters[referenced_uuid]
                for attribute in misp_object.attributes:
                    for tag in cluster['tag_names']:
                        attribute.add_tag(tag)
                cluster['used'][self.misp_event.uuid] = True
            else:
                misp_object.add_reference(
                    self._sanitise_uuid(referenced_uuid), relationship_type
                )

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
            'date_sighting': self._timestamp_from_date(sighting.modified),
            'type': '0'
        }
        if hasattr(sighting, 'description'):
            sighting_args['source'] = sighting.description
        if hasattr(sighting, 'where_sighted_refs'):
            identity = self._identity[sighting.where_sighted_refs[0]]
            sighting_args['Organisation'] = {
                'uuid': self._sanitise_uuid(identity.id),
                'name': identity.name
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

    def _add_misp_attribute(self, attribute: dict,
                            stix_object: _SDO_TYPING) -> MISPAttribute:
        misp_attribute = MISPAttribute()
        misp_attribute.from_dict(**attribute)
        for marking in self._handle_tags_from_stix_fields(stix_object):
            if isinstance(marking, str):
                if marking in self.event_tags:
                    continue
                misp_attribute.add_tag(marking)
                continue
            if not self.galaxies_as_tags:
                clusters = defaultdict(list)
                for cluster in marking['cluster']:
                    if cluster.uuid not in self.event_tags:
                        clusters[cluster.type].append(cluster)
                for galaxy in self._aggregate_galaxy_clusters(clusters):
                    misp_attribute.add_galaxy(galaxy)
            if marking.get('tags'):
                for tag in marking['tags']:
                    if tag not in self.event_tags:
                        misp_attribute.add_tag(tag)
        return self.misp_event.add_attribute(**misp_attribute)

    def _add_misp_object(self, misp_object: MISPObject,
                         stix_object: _SDO_TYPING) -> MISPObject:
        for marking in self._handle_tags_from_stix_fields(stix_object):
            if isinstance(marking, str):
                if marking in self.event_tags:
                    continue
                for attribute in misp_object.attributes:
                    attribute.add_tag(marking)
                continue
            if not self.galaxies_as_tags:
                clusters = defaultdict(list)
                for cluster in marking['cluster']:
                    if cluster.uuid not in self.event_tags:
                        clusters[cluster.type].append(cluster)
                for galaxy in self._aggregate_galaxy_clusters(clusters):
                    for attribute in misp_object.attributes:
                        attribute.add_galaxy(galaxy)
            if marking.get('tags'):
                for tag in marking['tags']:
                    if tag in self.event_tags:
                        continue
                    for attribute in misp_object.attributes:
                        attribute.add_tag(tag)
        return self.misp_event.add_object(misp_object)

    def _create_generic_event(self) -> MISPEvent:
        misp_event = MISPEvent()
        event_args = {
            'uuid': self._identifier.split('--')[1],
            'info': self.generic_info_field,
            'distribution': self.distribution
        }
        if self.distribution == 4 and self.sharing_group_id is not None:
            event_args['sharing_group_id'] = self.sharing_group_id
        misp_event.from_dict(**event_args)
        return misp_event

    def _create_misp_event(
            self, stix_object: _GROUPING_REPORT_TYPING) -> MISPEvent:
        misp_event = MISPEvent(force_timestamps=True)
        self._sanitise_object_uuid(misp_event, stix_object.id)
        event_args = {
            'info': getattr(stix_object, 'name', self.generic_info_field),
            'distribution': self.distribution,
            'timestamp': self._timestamp_from_date(stix_object.modified)
        }
        if self.distribution == 4 and self.sharing_group_id is not None:
            event_args['sharing_group_id'] = self.sharing_group_id
        misp_event.from_dict(**event_args)
        self._handle_misp_event_tags(misp_event, stix_object)
        return misp_event

    @staticmethod
    def _create_misp_galaxy_cluster(**cluster_args: dict) -> MISPGalaxyCluster:
        cluster = MISPGalaxyCluster()
        cluster.from_dict(**cluster_args)
        cluster.parse_meta_as_elements()
        return cluster

    def _handle_tags_from_stix_fields(self, stix_object: _SDO_TYPING):
        if hasattr(stix_object, 'confidence'):
            yield self._parse_confidence_level(stix_object.confidence)
        if hasattr(stix_object, 'object_marking_refs'):
            for marking_ref in stix_object.object_marking_refs:
                try:
                    marking_definition = self._get_stix_object(marking_ref)
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

    ############################################################################
    #                             UTILITY METHODS.                             #
    ############################################################################

    @staticmethod
    def _extract_uuid(object_id: str) -> str:
        return object_id.split('--')[-1]

    def _handle_creator(self, reference: str) -> str:
        if reference in getattr(self, '_identity', {}):
            return self._identity[reference].name
        return self._mapping.identity_references(reference) or 'misp-stix'

    def _is_tlp_marking(self, marking_ref: str) -> bool:
        for marking in (TLP_WHITE, TLP_GREEN, TLP_AMBER, TLP_RED):
            if marking_ref == marking.id:
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

    @staticmethod
    def _timestamp_from_date(date: datetime) -> int:
        return int(date.timestamp())
        try:
            return int(date.timestamp())
        except AttributeError:
            return int(
                time.mktime(
                    time.strptime(date.split('+')[0], "%Y-%m-%dT%H:%M:%S.%fZ")
                )
            )
