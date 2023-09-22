#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import time
from .exceptions import (
    ObjectRefLoadingError, ObjectTypeLoadingError, SynonymsResourceJSONError,
    UnavailableGalaxyResourcesError, UnavailableSynonymsResourceError,
    UndefinedIndicatorError, UndefinedSTIXObjectError, UndefinedObservableError,
    UnknownAttributeTypeError, UnknownObjectNameError,
    UnknownParsingFunctionError, UnknownStixObjectTypeError)
from .external_stix2_mapping import ExternalSTIX2toMISPMapping
from .importparser import STIXtoMISPParser, _INDICATOR_TYPING
from .internal_stix2_mapping import InternalSTIX2toMISPMapping
from .converters import (
    ExternalSTIX2AttackPatternConverter, ExternalSTIX2MalwareAnalysisConverter,
    ExternalSTIX2MalwareConverter, InternalSTIX2AttackPatternConverter,
    InternalSTIX2MalwareAnalysisConverter, InternalSTIX2MalwareConverter)
from abc import ABCMeta
from collections import defaultdict
from datetime import datetime
from pymisp import (
    AbstractMISP, MISPEvent, MISPAttribute, MISPGalaxy, MISPGalaxyCluster,
    MISPObject, MISPSighting)
from stix2.parsing import parse as stix2_parser
from stix2.v20.bundle import Bundle as Bundle_v20
from stix2.v20.common import MarkingDefinition as MarkingDefinition_v20
from stix2.v20.observables import NetworkTraffic as NetworkTraffic_v20
from stix2.v20.sdo import (
    AttackPattern as AttackPattern_v20, Campaign as Campaign_v20,
    CourseOfAction as CourseOfAction_v20, Identity as Identity_v20,
    Indicator as Indicator_v20, IntrusionSet as IntrusionSet_v20,
    Malware as Malware_v20, ObservedData as ObservedData_v20,
    Report as Report_v20, ThreatActor as ThreatActor_v20, Tool as Tool_v20,
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
from stix2.v21.sdo import Grouping, MalwareAnalysis, Note, Opinion
from stix2.v21.sdo import (
    AttackPattern as AttackPattern_v21, Campaign as Campaign_v21,
    CourseOfAction as CourseOfAction_v21, Identity as Identity_v21,
    Indicator as Indicator_v21, IntrusionSet as IntrusionSet_v21, Location,
    Malware as Malware_v21, ObservedData as ObservedData_v21,
    Report as Report_v21, ThreatActor as ThreatActor_v21, Tool as Tool_v21,
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
_MISP_OBJECTS_PATH = AbstractMISP().misp_objects_path

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
_CAMPAIGN_TYPING = Union[
    Campaign_v20, Campaign_v21
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
_IDENTITY_TYPING = Union[
    Identity_v20, Identity_v21
]
_INTRUSION_SET_TYPING = Union[
    IntrusionSet_v20, IntrusionSet_v21
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
_NETWORK_TRAFFIC_TYPING = Union[
    NetworkTraffic_v20, NetworkTraffic_v21
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
    Indicator_v20, Indicator_v21,
    ObservedData_v20, ObservedData_v21,
    Vulnerability_v20, Vulnerability_v21
]
_SIGHTING_TYPING = Union[
    Sighting_v20, Sighting_v21
]
_THREAT_ACTOR_TYPING = Union[
    ThreatActor_v20, ThreatActor_v21
]
_TOOL_TYPING = Union[
    Tool_v20, Tool_v21
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
            with open(filename, 'rt', encoding='utf-8') as f:
                bundle = stix2_parser(
                    f.read(), allow_custom=True, interoperability=True
                )
        except Exception as exception:
            sys.exit(exception)
        self.load_stix_bundle(bundle)
        del bundle
        self.parse_stix_bundle(single_event)

    ################################################################################
    #                                  PROPERTIES                                  #
    ################################################################################

    @property
    def attack_pattern_parser(self) -> _ATTACK_PATTERN_PARSER_TYPING:
        return getattr(
            self, '_attack_pattern_parser', self._set_attack_pattern_parser()
        )

    @property
    def generic_info_field(self) -> str:
        return f'STIX {self.stix_version} Bundle imported with the MISP-STIX import feature.'

    @property
    def malware_analysis_parser(self) -> _MALWARE_ANALYSIS_PARSER_TYPING:
        return getattr(
            self, '_malware_analysis_parser',
            self._set_malware_analysis_parser()
        )

    @property
    def malware_parser(self) -> _MALWARE_PARSER_TYPING:
        return getattr(self, '_malware_parser', self._set_malware_parser())

    @property
    def misp_event(self) -> MISPEvent:
        return self.__misp_event

    @property
    def misp_events(self) -> Union[list, MISPEvent]:
        return getattr(
            self, '_STIX2toMISPParser__misp_events', self.__misp_event
        )

    @property
    def single_event(self) -> bool:
        return self.__single_event

    @property
    def stix_version(self) -> str:
        return self.__stix_version

    ################################################################################
    #                        STIX OBJECTS LOADING FUNCTIONS                        #
    ################################################################################

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

    def _load_course_of_action(self, course_of_action: _COURSE_OF_ACTION_TYPING):
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
        if not hasattr(marking_definition, 'definition_type'):
            return
        definition_type = marking_definition.definition_type
        definition = marking_definition.definition[definition_type]
        tag = f"{definition_type}:{definition}"
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

    ################################################################################
    #                     MAIN STIX OBJECTS PARSING FUNCTIONS.                     #
    ################################################################################

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
            parser(object_ref)
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

    def _handle_misp_event_tags(
            self, misp_event: MISPEvent, stix_object: _GROUPING_REPORT_TYPING):
        if hasattr(stix_object, 'object_marking_refs'):
            for marking_ref in stix_object.object_marking_refs:
                try:
                    misp_event.add_tag(self._marking_definition[marking_ref])
                except KeyError:
                    self._unknown_marking_ref_warning(marking_ref)
                except AttributeError:
                    self._unknown_marking_object_warning(marking_ref)
        if hasattr(stix_object, 'labels'):
            self._fetch_tags_from_labels(misp_event, stix_object.labels)

    def _misp_event_from_grouping(self, grouping: Grouping) -> MISPEvent:
        self.__single_event = True
        misp_event = self._create_misp_event(grouping)
        misp_event.published = False
        return misp_event

    def _misp_event_from_report(self, report: _REPORT_TYPING) -> MISPEvent:
        self.__single_event = True
        misp_event = self._create_misp_event(report)
        if report.published != report.modified:
            misp_event.published = True
            misp_event.publish_timestamp = self._timestamp_from_date(
                report.published
            )
        else:
            misp_event.published = False
        return misp_event

    def _parse_attack_pattern(self, attack_pattern_ref: str):
        self.attack_pattern_parser.parse(attack_pattern_ref)

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
            events = []
            if hasattr(self, '_report') and self._report is not None:
                for report in self._report.values():
                    self.__misp_event = self._misp_event_from_report(report)
                    self._handle_object_refs(report.object_refs)
                    self._handle_unparsed_content()
                    events.append(self.misp_event)
            if hasattr(self, '_grouping') and self._grouping is not None:
                for grouping in self._grouping.values():
                    self.__misp_event = self._misp_event_from_grouping(grouping)
                    self._handle_object_refs(grouping.object_refs)
                    self._handle_unparsed_content()
                    events.append(self.misp_event)
            self.__misp_events = events

    def _parse_bundle_with_no_report(self):
        self.__single_event = True
        self.__misp_event = self._create_generic_event()
        self._parse_loaded_features()
        self._handle_unparsed_content()

    def _parse_bundle_with_single_report(self):
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

    def _parse_location_object(self, location: Location,
                               to_return: Optional[bool] = False) -> MISPObject:
        misp_object = self._create_misp_object('geolocation', location)
        if hasattr(location, 'description'):
            misp_object.comment = location.description
        for feature, attribute in self._mapping.location_object_mapping().items():
            if hasattr(location, feature):
                misp_object.add_attribute(
                    **{'value': getattr(location, feature), **attribute}
                )
        if hasattr(location, 'precision'):
            misp_object.add_attribute(
                **{
                    'value': float(location.precision) / 1000,
                    **self._mapping.accuracy_radius_attribute()
                }
            )
        if to_return:
            return misp_object
        self._add_misp_object(misp_object, location)

    def _parse_malware(self, malware_ref: str):
        self.malware_parser.parse(malware_ref)

    def _parse_malware_analysis(self, malware_analysis_ref: str):
        self.malware_analysis_parser.parse(malware_analysis_ref)

    ################################################################################
    #                  MISP GALAXIES & CLUSTERS PARSING FUNCTIONS                  #
    ################################################################################

    def _aggregate_galaxy_clusters(self, galaxies: dict):
        for galaxy_type, clusters in galaxies.items():
            misp_galaxy = MISPGalaxy()
            misp_galaxy.from_dict(**self._galaxies[galaxy_type])
            for cluster in clusters:
                misp_galaxy.add_galaxy_cluster(**cluster)
            yield misp_galaxy

    def _create_cluster_args(self, stix_object: _GALAXY_OBJECTS_TYPING,
                             galaxy_type: Union[None, str],
                             description: Optional[str] = None,
                             cluster_value: Optional[str] = None) -> dict:
        value = cluster_value or stix_object.name
        cluster_args = {
            'uuid': self._sanitise_uuid(stix_object.id), 'value': value
        }
        if galaxy_type is None:
            version = getattr(stix_object, 'spec_version', '2.0')
            mapping = self._mapping.galaxy_name_mapping(stix_object.type)
            name = f"STIX {version} {mapping['name']}"
            cluster_args.update(
                {
                    'version': ''.join(version.split('.')),
                    'collection_uuid': self._create_v5_uuid(name)
                }
            )
            galaxy_type = f'stix-{version}-{stix_object.type}'
        cluster_args['type'] = galaxy_type
        if description is not None:
            cluster_args['description'] = description
            return cluster_args
        if hasattr(stix_object, 'description'):
            cluster_args['description'] = stix_object.description
            return cluster_args
        cluster_args['description'] = value.capitalize()
        return cluster_args

    def _extract_custom_fields(self, stix_object: _GALAXY_OBJECTS_TYPING):
        for key, value in stix_object.items():
            if key.startswith('x_misp_'):
                separator = '-' if key in self._mapping.dash_meta_fields() else '_'
                yield separator.join(key.split('_')[2:]), value

    @staticmethod
    def _handle_kill_chain_phases(kill_chain_phases: list) -> list:
        kill_chains = []
        for kill_chain in kill_chain_phases:
            kill_chains.append(
                f'{kill_chain.kill_chain_name}:{kill_chain.phase_name}'
            )
        return kill_chains

    @staticmethod
    def _handle_labels(meta: dict, labels: list):
        meta_labels = [
            label for label in labels if not label.startswith('misp:galaxy-')
        ]
        if meta_labels:
            meta['labels'] = meta_labels

    def _handle_meta_fields(self, stix_object: _GALAXY_OBJECTS_TYPING) -> dict:
        mapping = f"{stix_object.type.replace('-', '_')}_meta_mapping"
        if hasattr(self._mapping, mapping):
            meta = {}
            for feature, field in getattr(self._mapping, mapping)().items():
                if hasattr(stix_object, feature):
                    meta[field] = getattr(stix_object, feature)
            meta.update(dict(self._extract_custom_fields(stix_object)))
            return meta
        return dict(self._extract_custom_fields(stix_object))

    def _parse_attack_pattern_cluster(
            self, attack_pattern: _ATTACK_PATTERN_TYPING,
            description: Optional[str] = None,
            galaxy_type: Optional[str] = None) -> MISPGalaxyCluster:
        attack_pattern_args = self._create_cluster_args(
            attack_pattern, galaxy_type, description=description
        )
        meta = self._handle_meta_fields(attack_pattern)
        if hasattr(attack_pattern, 'external_references'):
            meta.update(
                self._handle_external_references(
                    attack_pattern.external_references
                )
            )
        if hasattr(attack_pattern, 'kill_chain_phases'):
            meta['kill_chain'] = self._handle_kill_chain_phases(
                attack_pattern.kill_chain_phases
            )
        if meta:
            attack_pattern_args['meta'] = meta
        return self._create_misp_galaxy_cluster(attack_pattern_args)

    def _parse_campaign_cluster(
            self, campaign: _CAMPAIGN_TYPING,
            description: Optional[str] = None,
            galaxy_type: Optional[str] = None) -> MISPGalaxyCluster:
        campaign_args = self._create_cluster_args(
            campaign, galaxy_type, description=description
        )
        meta = self._handle_meta_fields(campaign)
        if hasattr(campaign, 'external_references'):
            meta.update(
                self._handle_external_references(campaign.external_references)
            )
        if meta:
            campaign_args['meta'] = meta
        return self._create_misp_galaxy_cluster(campaign_args)

    def _parse_course_of_action_cluster(
            self, course_of_action: _COURSE_OF_ACTION_TYPING,
            description: Optional[str] = None,
            galaxy_type: Optional[str] = None) -> MISPGalaxyCluster:
        course_of_action_args = self._create_cluster_args(
            course_of_action, galaxy_type, description=description
        )
        meta = dict(self._extract_custom_fields(course_of_action))
        if hasattr(course_of_action, 'external_references'):
            meta.update(
                self._handle_external_references(
                    course_of_action.external_references
                )
            )
        if meta:
            course_of_action_args['meta'] = meta
        return self._create_misp_galaxy_cluster(course_of_action_args)

    def _parse_intrusion_set_cluster(
            self, intrusion_set: _INTRUSION_SET_TYPING,
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
        if meta:
            intrusion_set_args['meta'] = meta
        return self._create_misp_galaxy_cluster(intrusion_set_args)

    def _parse_malware_cluster(
            self, malware: _MALWARE_TYPING,
            description: Optional[str] = None,
            galaxy_type: Optional[str] = None) -> MISPGalaxyCluster:
        malware_args = self._create_cluster_args(
            malware, galaxy_type, description=description
        )
        meta = self._handle_meta_fields(malware)
        if hasattr(malware, 'external_references'):
            meta.update(
                self._handle_external_references(malware.external_references)
            )
        if hasattr(malware, 'kill_chain_phases'):
            meta['kill_chain'] = self._handle_kill_chain_phases(
                malware.kill_chain_phases
            )
        if hasattr(malware, 'labels'):
            self._handle_labels(meta, malware.labels)
        if meta:
            malware_args['meta'] = meta
        return self._create_misp_galaxy_cluster(malware_args)

    def _parse_threat_actor_cluster(
            self, threat_actor: _THREAT_ACTOR_TYPING,
            description: Optional[str] = None,
            galaxy_type: Optional[str] = None) -> MISPGalaxyCluster:
        threat_actor_args = self._create_cluster_args(
            threat_actor, galaxy_type, description=description
        )
        meta = self._handle_meta_fields(threat_actor)
        if hasattr(threat_actor, 'external_references'):
            meta.update(
                self._handle_external_references(
                    threat_actor.external_references
                )
            )
        if hasattr(threat_actor, 'labels'):
            self._handle_labels(meta, threat_actor.labels)
        if meta:
            threat_actor_args['meta'] = meta
        return self._create_misp_galaxy_cluster(threat_actor_args)

    def _parse_tool_cluster(
            self, tool: _TOOL_TYPING, description: Optional[str] = None,
            galaxy_type: Optional[str] = None) -> MISPGalaxyCluster:
        tool_args = self._create_cluster_args(
            tool, galaxy_type, description=description
        )
        meta = self._handle_meta_fields(tool)
        if hasattr(tool, 'kill_chain_phases'):
            meta['kill_chain'] = self._handle_kill_chain_phases(
                tool.kill_chain_phases
            )
        if hasattr(tool, 'external_references'):
            meta.update(
                self._handle_external_references(tool.external_references)
            )
        if hasattr(tool, 'kill_chain_phases'):
            meta['kill_chain'] = self._handle_kill_chain_phases(
                tool.kill_chain_phases
            )
        if hasattr(tool, 'labels'):
            self._handle_labels(meta, tool.labels)
        if meta:
            tool_args['meta'] = meta
        return self._create_misp_galaxy_cluster(tool_args)

    def _parse_vulnerability_cluster(
            self, vulnerability: _VULNERABILITY_TYPING,
            description: Optional[str] = None,
            galaxy_type: Optional[str] = None) -> MISPGalaxyCluster:
        vulnerability_args = self._create_cluster_args(
            vulnerability, galaxy_type, description=description
        )
        meta = dict(self._extract_custom_fields(vulnerability))
        if hasattr(vulnerability, 'external_references'):
            meta.update(
                self._handle_external_references(
                    vulnerability.external_references
                )
            )
        if meta:
            vulnerability_args['meta'] = meta
        return self._create_misp_galaxy_cluster(vulnerability_args)

    ################################################################################
    #                 RELATIONSHIPS & SIGHTINGS PARSING FUNCTIONS.                 #
    ################################################################################

    def _handle_attribute_sightings(self, attribute: MISPAttribute):
        attribute_uuid = attribute.uuid
        if attribute_uuid in self._sighting.get('sighting', {}):
            self._parse_attribute_sightings(attribute)
        if attribute_uuid in self._sighting.get('opinion_refs', {}):
            self._parse_attribute_opinions(attribute)
        elif attribute_uuid in self._sighting.get('custom_opinion', {}):
            self._parse_attribute_custom_opinions(attribute)

    def _handle_object_sightings(self, misp_object: MISPObject):
        object_uuid = misp_object.uuid
        if object_uuid in self._sighting.get('sighting', {}):
            self._parse_object_sightings(misp_object)
        if object_uuid in self._sighting.get('opinion_refs', {}):
            self._parse_object_opinions(misp_object)
        elif misp_object.uuid in self._sighting.get('custom_opinion', {}):
            self._parse_object_custom_opinion(misp_object)

    def _handle_opposite_reference(
            self, relationship_type: str, source_uuid: str, target_uuid: str):
        sanitised_uuid = self._sanitise_uuid(target_uuid)
        reference = (source_uuid, self.relationship_types[relationship_type])
        self._relationship[sanitised_uuid].add(reference)

    def _parse_attribute_custom_opinions(self, attribute: MISPAttribute):
        for sighting in self._sighting['custom_opinion'][attribute.uuid]:
            attribute.add_sighting(sighting)

    def _parse_attribute_opinions(self, attribute: MISPAttribute):
        for opinion_ref in self._sighting['opinion_refs'][attribute.uuid]:
            attribute.add_sighting(self._sighting['opinion'][opinion_ref])

    def _parse_attribute_relationships_as_container(
            self, attribute: MISPAttribute):
        clusters = defaultdict(list)
        for relationship in self._relationship[attribute.uuid]:
            referenced_uuid, relationship_type = relationship
            if referenced_uuid in self._clusters:
                cluster = self._clusters[referenced_uuid]['cluster']
                clusters[cluster['type']].append(cluster)
                self._clusters[referenced_uuid]['used'][self.misp_event.uuid] = True
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
                for tag in self._clusters[referenced_uuid]['tag_names']:
                    attribute.add_tag(tag)
                self._clusters[referenced_uuid]['used'][self.misp_event.uuid] = True
                continue
            if relationship_type in self.relationship_types:
                self._handle_opposite_reference(
                    relationship_type, attribute.uuid, referenced_uuid
                )

    def _parse_attribute_sightings(self, attribute: MISPAttribute):
        for sighting in self._sighting['sighting'][attribute.uuid]:
            attribute.add_sighting(self._parse_sighting(sighting))

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

    def _parse_object_custom_opinion(self, misp_object: MISPObject):
        for sighting in self._sighting['custom_opinion'][misp_object.uuid]:
            for attribute in misp_object.attributes:
                attribute.add_sighting(sighting)

    def _parse_object_opinions(self, misp_object: MISPObject):
        for opinion_ref in self._sighting['opinion_refs'][misp_object.uuid]:
            sighting = self._sighting['opinion'][opinion_ref]
            for attribute in misp_object.attributes:
                attribute.add_sighting(sighting)

    def _parse_object_relationships_as_container(self, misp_object: MISPObject):
        clusters = defaultdict(list)
        for relationship in self._relationship[misp_object.uuid]:
            referenced_uuid, relationship_type = relationship
            if referenced_uuid in self._clusters:
                cluster = self._clusters[referenced_uuid]['cluster']
                clusters[cluster['type']].append(cluster)
                self._clusters[referenced_uuid]['used'][self.misp_event.uuid] = True
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
                for attribute in misp_object.attributes:
                    for tag in self._clusters[referenced_uuid]['tag_names']:
                        attribute.add_tag(tag)
                self._clusters[referenced_uuid]['used'][self.misp_event.uuid] = True
            else:
                misp_object.add_reference(
                    self._sanitise_uuid(referenced_uuid), relationship_type
                )

    def _parse_object_sightings(self, misp_object: MISPObject):
        for sighting in self._sighting['sighting'][misp_object.uuid]:
            misp_sighting = self._parse_sighting(sighting)
            for attribute in misp_object.attributes:
                attribute.add_sighting(misp_sighting)

    def _parse_opinion(self, opinion: Opinion) -> MISPSighting:
        sighting = MISPSighting()
        sighting_args = {
            'date_sighting': self._timestamp_from_date(opinion.modified),
            'type': '1'
        }
        if hasattr(opinion, 'x_misp_source'):
            sighting_args['source'] = opinion.x_misp_source
        if hasattr(opinion, 'x_misp_author_ref'):
            identity = self._identity[opinion.x_misp_author_ref]
            sighting_args['Organisation'] = {
                'uuid': self._sanitise_uuid(identity.id),
                'name': identity.name
            }
        sighting.from_dict(**sighting_args)
        return sighting

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
        for opinion_id, opinion in self._sighting['opinion'].items():
            self._sighting['opinion'][opinion_id] = self._parse_opinion(opinion)
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
        for opinion_id, opinion in self._sighting['opinion'].items():
            self._sighting['opinion'][opinion_id] = self._parse_opinion(opinion)
        for attribute in self.misp_event.attributes:
            self._handle_attribute_sightings(attribute)
        for misp_object in self.misp_event.objects:
            self._handle_object_sightings(misp_object)
        getattr(self, f'_parse_galaxies_{self.galaxy_feature}')()

    ################################################################################
    #                       MISP FEATURES CREATION FUNCTIONS                       #
    ################################################################################

    def _add_misp_attribute(self, attribute: dict,
                            stix_object: _SDO_TYPING) -> MISPAttribute:
        misp_attribute = MISPAttribute()
        misp_attribute.from_dict(**attribute)
        tags = tuple(self._handle_tags_from_stix_fields(stix_object))
        if tags:
            for tag in tags:
                misp_attribute.add_tag(tag)
        return self.misp_event.add_attribute(**misp_attribute)

    def _add_misp_object(self, misp_object: MISPObject,
                         stix_object: _SDO_TYPING) -> MISPObject:
        tags = tuple(self._handle_tags_from_stix_fields(stix_object))
        if tags:
            for attribute in misp_object.attributes:
                for tag in tags:
                    attribute.add_tag(tag)
        return self.misp_event.add_object(misp_object)

    def _create_attribute_dict(self, stix_object: _SDO_TYPING) -> dict:
        attribute = self._parse_timeline(stix_object)
        if hasattr(stix_object, 'description') and stix_object.description:
            attribute['comment'] = stix_object.description
        attribute.update(
            self._sanitise_attribute_uuid(
                stix_object.id, comment=attribute.get('comment')
            )
        )
        return attribute

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
    def _create_misp_galaxy(galaxy_args: dict) -> MISPGalaxy:
        galaxy = MISPGalaxy()
        galaxy.from_dict(**galaxy_args)
        return galaxy

    @staticmethod
    def _create_misp_galaxy_cluster(cluster_args: dict) -> MISPGalaxyCluster:
        cluster = MISPGalaxyCluster()
        cluster.from_dict(**cluster_args)
        return cluster

    def _create_misp_object(
            self, name: str, stix_object: Optional[_SDO_TYPING] = None
            ) -> MISPObject:
        misp_object = MISPObject(
            name,
            misp_objects_path_custom=_MISP_OBJECTS_PATH,
            force_timestamps=True
        )
        if stix_object is not None:
            self._sanitise_object_uuid(misp_object, stix_object['id'])
            misp_object.from_dict(**self._parse_timeline(stix_object))
        return misp_object

    def _handle_tags_from_stix_fields(self, stix_object: _SDO_TYPING):
        if hasattr(stix_object, 'confidence'):
            yield self._parse_confidence_level(stix_object.confidence)
        if hasattr(stix_object, 'object_marking_refs'):
            yield from self._parse_markings(stix_object.object_marking_refs)

    ################################################################################
    #                              UTILITY FUNCTIONS.                              #
    ################################################################################

    @staticmethod
    def _extract_uuid(object_id: str) -> str:
        return object_id.split('--')[-1]

    @staticmethod
    def _fetch_tags_from_labels(
            misp_feature: _MISP_FEATURES_TYPING, labels: list):
        for label in (label for label in labels
                      if label.lower() != 'threat-report'):
            misp_feature.add_tag(label)

    @staticmethod
    def _parse_AS_value(number: Union[int, str]) -> str:
        if isinstance(number, int) or not number.startswith('AS'):
            return f'AS{number}'
        return number

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
            yield(marking_definition)

    def _parse_timeline(self, stix_object: _SDO_TYPING) -> dict:
        misp_object = {
            'timestamp': self._timestamp_from_date(stix_object.modified)
        }
        object_type = stix_object.type
        if self._mapping.timeline_mapping(object_type) is not None:
            first, last = self._mapping.timeline_mapping(object_type)
            if not self._skip_first_seen_last_seen(stix_object):
                if hasattr(stix_object, first) and getattr(stix_object, first):
                    misp_object['first_seen'] = getattr(stix_object, first)
                if hasattr(stix_object, last) and getattr(stix_object, last):
                    misp_object['last_seen'] = getattr(stix_object, last)
        return misp_object

    @staticmethod
    def _populate_object_attributes(
            misp_object: MISPObject, mapping: dict, values: Union[list, str]):
        if isinstance(values, list):
            for value in values:
                misp_object.add_attribute(**{'value': value, **mapping})
        else:
            misp_object.add_attribute(**{'value': values, **mapping})

    @staticmethod
    def _sanitise_value(value: str) -> str:
        return value.replace('\\\\', '\\')

    @staticmethod
    def _skip_first_seen_last_seen(sdo: _SDO_TYPING) -> bool:
        if sdo.type != 'indicator':
            return sdo.modified == sdo.first_observed == sdo.last_observed
        if sdo.valid_from != sdo.modified:
            return False
        if not hasattr(sdo, 'valid_until'):
            return True
        return sdo.valid_until == sdo.modified

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
