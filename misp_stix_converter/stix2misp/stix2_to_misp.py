#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import time
from .exceptions import (
    ObjectRefLoadingError, ObjectTypeLoadingError, SynonymsResourceJSONError,
    UnavailableGalaxyResourcesError, UnavailableSynonymsResourceError,
    UndefinedIndicatorError, UndefinedSTIXObjectError, UndefinedObservableError,
    UnknownAttributeTypeError, UnknownObjectNameError, UnknownObservableMappingError,
    UnknownParsingFunctionError, UnknownStixObjectTypeError)
from .external_stix2_mapping import ExternalSTIX2toMISPMapping
from .importparser import STIXtoMISPParser
from .internal_stix2_mapping import InternalSTIX2toMISPMapping
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from pymisp import (
    AbstractMISP, MISPEvent, MISPAttribute, MISPGalaxy, MISPGalaxyCluster,
    MISPObject, MISPSighting)
from stix2.parsing import parse as stix2_parser
from stix2.v20.bundle import Bundle as Bundle_v20
from stix2.v20.common import MarkingDefinition as MarkingDefinition_v20
from stix2.v20.sdo import (
    AttackPattern as AttackPattern_v20, Campaign as Campaign_v20,
    CourseOfAction as CourseOfAction_v20, Identity as Identity_v20,
    Indicator as Indicator_v20, IntrusionSet as IntrusionSet_v20,
    Malware as Malware_v20, ObservedData as ObservedData_v20,
    Report as Report_v20, ThreatActor as ThreatActor_v20, Tool as Tool_v20,
    Vulnerability as Vulnerability_v20)
from stix2.v20.sro import Relationship as Relationship_v20, Sighting as Sighting_v20
from stix2.v21.bundle import Bundle as Bundle_v21
from stix2.v21.common import MarkingDefinition as MarkingDefinition_v21
from stix2.v21.observables import (
    Artifact, AutonomousSystem, Directory, DomainName, EmailAddress,
    EmailMessage, File, IPv4Address, IPv6Address, MACAddress, Mutex,
    NetworkTraffic, Process, Software, URL, UserAccount, WindowsRegistryKey,
    X509Certificate)
from stix2.v21.sdo import (
    AttackPattern as AttackPattern_v21, Campaign as Campaign_v21,
    CourseOfAction as CourseOfAction_v21, Grouping, Identity as Identity_v21,
    Indicator as Indicator_v21, IntrusionSet as IntrusionSet_v21, Location,
    Malware as Malware_v21, Note, ObservedData as ObservedData_v21, Opinion,
    Report as Report_v21, ThreatActor as ThreatActor_v21, Tool as Tool_v21,
    Vulnerability as Vulnerability_v21)
from stix2.v21.sro import Relationship as Relationship_v21, Sighting as Sighting_v21
from typing import Optional, Union

_LOADED_FEATURES = (
    '_attack_pattern',
    '_course_of_action',
    '_custom_attribute',
    '_custom_object',
    '_identity',
    '_indicator',
    '_intrusion_set',
    '_malware',
    '_note',
    '_observed_data',
    '_opinion',
    '_threat_actor',
    '_tool',
    '_vulnerability'
)
_MISP_OBJECTS_PATH = AbstractMISP().misp_objects_path
_OBSERVABLE_TYPES = Union[
    Artifact, AutonomousSystem, Directory, DomainName, EmailAddress, EmailMessage,
    File, IPv4Address, IPv6Address, MACAddress, Mutex, NetworkTraffic, Process,
    Software, URL, UserAccount, WindowsRegistryKey, X509Certificate
]
_ATTACK_PATTERN_TYPING = Union[
    AttackPattern_v20,
    AttackPattern_v21
]
_CAMPAIGN_TYPING = Union[
    Campaign_v20,
    Campaign_v21
]
_COURSE_OF_ACTION_TYPING = Union[
    CourseOfAction_v20,
    CourseOfAction_v21
]
_GALAXY_OBJECTS_TYPING = Union[
    AttackPattern_v20,
    AttackPattern_v21,
    Campaign_v20,
    Campaign_v21,
    CourseOfAction_v20,
    CourseOfAction_v21,
    IntrusionSet_v20,
    IntrusionSet_v21,
    Location,
    Malware_v20,
    Malware_v21,
    ThreatActor_v20,
    ThreatActor_v21,
    Tool_v20,
    Tool_v21,
    Vulnerability_v20,
    Vulnerability_v21
]
_IDENTITY_TYPING = Union[
    Identity_v20,
    Identity_v21
]
_INTRUSION_SET_TYPING = Union[
    IntrusionSet_v20,
    IntrusionSet_v21
]
_MALWARE_TYPING = Union[
    Malware_v20,
    Malware_v21
]
_MISP_FEATURES_TYPING = Union[
    MISPAttribute,
    MISPEvent,
    MISPObject
]
_SDO_TYPING = Union[
    Indicator_v20,
    Indicator_v21,
    ObservedData_v20,
    ObservedData_v21,
    Vulnerability_v20,
    Vulnerability_v21
]
_SIGHTING_TYPING = Union[
    Sighting_v20,
    Sighting_v21
]
_THREAT_ACTOR_TYPING = Union[
    ThreatActor_v20,
    ThreatActor_v21
]
_TOOL_TYPING = Union[
    Tool_v20,
    Tool_v21
]
_VULNERABILITY_TYPING = Union[
    Vulnerability_v20,
    Vulnerability_v21
]


class STIX2toMISPParser(STIXtoMISPParser):
    def __init__(self, galaxies_as_tags: bool):
        super().__init__(galaxies_as_tags)
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
        self._marking_definition: dict
        self._note: dict
        self._observable: dict
        self._observed_data: dict
        self._opinion: dict
        self._relationship: dict
        self._report: dict
        self._threat_actor: dict
        self._tool: dict
        self._vulnerability: dict

    def load_stix_bundle(self, bundle: Union[Bundle_v20, Bundle_v21]):
        self._identifier = bundle.id
        self.__stix_version = bundle.spec_version if hasattr(bundle, 'spec_version') else '2.1'
        n_report = 0
        for stix_object in bundle.objects:
            try:
                object_type = stix_object.type
            except AttributeError:
                object_type = stix_object['type']
            if object_type in ('grouping', 'report'):
                n_report += 1
            try:
                feature = self._mapping.stix_object_loading_mapping[object_type]
            except KeyError:
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
            feature = self._mapping.bundle_to_misp_mapping[str(self.__n_report)]
        except AttributeError:
            sys.exit('No STIX content loaded, please run `load_stix_content` first.')
        try:
            getattr(self, feature)()
        except (
            SynonymsResourceJSONError,
            UnavailableGalaxyResourcesError,
            UnavailableSynonymsResourceError
        ) as error:
            self._critical_error(error)

    def parse_stix_content(self, filename: str):
        try:
            with open(filename, 'rt', encoding='utf-8') as f:
                bundle = stix2_parser(f.read(), allow_custom=True, interoperability=True)
        except Exception as exception:
            sys.exit(exception)
        self.load_stix_bundle(bundle)
        del bundle
        self.parse_stix_bundle()

    ################################################################################
    #                                  PROPERTIES                                  #
    ################################################################################

    @classmethod
    def generic_info_field(cls) -> str:
        return f'STIX {cls.stix_version} Bundle imported with the MISP-STIX import feature.'

    @property
    def misp_event(self) -> MISPEvent:
        return self.__misp_event

    @property
    def misp_events(self) -> Union[list, MISPEvent]:
        try:
            return self.__misp_events
        except AttributeError:
            return self.__misp_event

    @property
    def single_event(self) -> bool:
        return self.__single_event

    @property
    def stix_version(self) -> str:
        return self.__stix_version

    ################################################################################
    #                        STIX OBJECTS LOADING FUNCTIONS                        #
    ################################################################################

    def _load_attack_pattern(self, attack_pattern: Union[AttackPattern_v20, AttackPattern_v21]):
        self._check_uuid(attack_pattern.id)
        try:
            self._attack_pattern[attack_pattern.id] = attack_pattern
        except AttributeError:
            self._attack_pattern = {attack_pattern.id: attack_pattern}

    def _load_campaign(self, campaign: Union[Campaign_v20, Campaign_v21]):
        self._check_uuid(campaign.id)
        try:
            self._campaign[campaign.id] = campaign
        except AttributeError:
            self._campaign = {campaign.id: campaign}

    def _load_course_of_action(self, course_of_action: Union[CourseOfAction_v20, CourseOfAction_v21]):
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

    def _load_identity(self, identity: Union[Identity_v20, Identity_v21]):
        self._check_uuid(identity.id)
        try:
            self._identity[identity.id] = identity
        except AttributeError:
            self._identity = {identity.id: identity}

    def _load_indicator(self, indicator: Union[Indicator_v20, Indicator_v21]):
        self._check_uuid(indicator.id)
        try:
            self._indicator[indicator.id] = indicator
        except AttributeError:
            self._indicator = {indicator.id: indicator}

    def _load_intrusion_set(self, intrusion_set: Union[IntrusionSet_v20, IntrusionSet_v21]):
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

    def _load_malware(self, malware: Union[Malware_v20, Malware_v21]):
        self._check_uuid(malware.id)
        try:
            self._malware[malware.id] = malware
        except AttributeError:
            self._malware = {malware.id: malware}

    def _load_marking_definition(self, marking_definition: Union[MarkingDefinition_v20, MarkingDefinition_v21]):
        if not hasattr(marking_definition, 'definition_type'):
            if not hasattr(self, '_marking_definition'):
                self._marking_definition = {}
            return
        definition_type = marking_definition.definition_type
        definition = marking_definition.definition[definition_type]
        data_to_load = {
            'tag_name': f"{definition_type}:{definition}",
            'used': False
        }
        try:
            self._marking_definition[marking_definition.id] = data_to_load
        except AttributeError:
            self._marking_definition = {marking_definition.id: data_to_load}

    def _load_note(self, note: Note):
        self._check_uuid(note.id)
        try:
            self._note[note.id] = note
        except AttributeError:
            self._note = {note.id: note}

    def _load_observable_object(self, observable: _OBSERVABLE_TYPES):
        self._check_uuid(observable.id)
        try:
            self._observable[observable.id] = observable
        except AttributeError:
            self._observable = {observable.id: observable}

    def _load_observed_data(self, observed_data: Union[ObservedData_v20, ObservedData_v21]):
        self._check_uuid(observed_data.id)
        try:
            self._observed_data[observed_data.id] = observed_data
        except AttributeError:
            self._observed_data = {observed_data.id: observed_data}

    def _load_opinion(self, opinion: Opinion):
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
        for object_ref in opinion.object_refs:
            sanitised_ref = self._sanitise_uuid(object_ref)
            try:
                self._sighting[sanitised_ref].append(sighting)
            except AttributeError:
                self._sighting = defaultdict(list)
                self._sighting[sanitised_ref].append(sighting)

    def _load_relationship(self, relationship: Union[Relationship_v20, Relationship_v21]):
        reference = {
            'referenced_uuid': relationship.target_ref,
            'relationship_type': relationship.relationship_type
        }
        source_uuid = self._sanitise_uuid(relationship.source_ref)
        try:
            self._relationship[source_uuid].append(reference)
        except AttributeError:
            self._relationship = defaultdict(list)
            self._relationship[source_uuid].append(reference)

    def _load_report(self, report: Union[Report_v20, Report_v21]):
        self._check_uuid(report.id)
        try:
            self._report[report.id] = report
        except AttributeError:
            self._report = {report.id: report}

    def _load_sighting(self, sighting: _SIGHTING_TYPING):
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
        sighting_of_ref = self._sanitise_uuid(sighting.sighting_of_ref)
        try:
            self._sighting[sighting_of_ref].append(misp_sighting)
        except AttributeError:
            self._sighting = defaultdict(list)
            self._sighting[sighting_of_ref].append(misp_sighting)

    def _load_threat_actor(self, threat_actor: Union[ThreatActor_v20, ThreatActor_v21]):
        self._check_uuid(threat_actor.id)
        try:
            self._threat_actor[threat_actor.id] = threat_actor
        except AttributeError:
            self._threat_actor = {threat_actor.id: threat_actor}

    def _load_tool(self, tool: Union[Tool_v20, Tool_v21]):
        self._check_uuid(tool.id)
        try:
            self._tool[tool.id] = tool
        except AttributeError:
            self._tool = {tool.id: tool}

    def _load_vulnerability(self, vulnerability: Union[Vulnerability_v20, Vulnerability_v21]):
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

    def _handle_object_refs(self, object_refs: list):
        for object_ref in object_refs:
            object_type = object_ref.split('--')[0]
            if object_type in self._mapping.object_type_refs_to_skip:
                continue
            try:
                self._handle_object(object_type, object_ref)
            except UnknownStixObjectTypeError as error:
                self._unknown_stix_object_type_error(error)
            except UnknownParsingFunctionError as error:
                self._unknown_parsing_function_error(error)

    def _handle_object(self, object_type: str, object_ref: str):
        try:
            feature = self._mapping.stix_to_misp_mapping[object_type]
        except KeyError:
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

    def _handle_misp_event_tags(self, misp_event: MISPEvent, stix_object: Union[Report_v20, Report_v21, Grouping]):
        if hasattr(stix_object, 'object_marking_refs'):
            for marking_ref in stix_object.object_marking_refs:
                try:
                    misp_event.add_tag(self._marking_definition[marking_ref])
                except KeyError:
                    self._unknown_marking_ref_warning(marking_ref)
        if hasattr(stix_object, 'labels'):
            self._fetch_tags_from_labels(misp_event, stix_object.labels)

    def _misp_event_from_grouping(self, grouping: Grouping) -> MISPEvent:
        misp_event = self._create_misp_event(grouping)
        misp_event.published = False
        return misp_event

    def _misp_event_from_report(self, report: Union[Report_v20, Report_v21]) -> MISPEvent:
        misp_event = self._create_misp_event(report)
        if report.published != report.modified:
            misp_event.published = True
            misp_event.publish_timestamp = self._timestamp_from_date(report.published)
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
            self._parse_SROs()
            self._parse_galaxies()
        else:
            events = []
            if hasattr(self, '_report') and self._report is not None:
                for report in self._report.values():
                    self.__misp_event = self._misp_event_from_report(report)
                    self._handle_object_refs(report.object_refs)
                    self._parse_SROs()
                    self._parse_galaxies()
                    events.append(self.misp_event)
            if hasattr(self, '_grouping') and self._grouping is not None:
                for grouping in self._grouping.values():
                    self.__misp_event = self._misp_event_from_grouping(grouping)
                    self._handle_object_refs(grouping.object_refs)
                    self._parse_SROs()
                    self._parse_galaxies()
                    events.append(self.misp_event)
            self.__misp_events = events

    def _parse_bundle_with_no_report(self):
        self.__misp_event = self._create_generic_event()
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
        self._parse_SROs()
        self._parse_galaxies()

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
        self._parse_SROs()
        self._parse_galaxies()

    def _parse_galaxies(self):
        if self.galaxies_as_tags:
            for tags in self._clusters.values():
                if self.misp_event.uuid not in tags['used']:
                    continue
                if not tags['used'][self.misp_event.uuid]:
                    for tag in tags['tag_names']:
                        self.misp_event.add_tag(tag)
        else:
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

    def _parse_location_object(self, location: Location, to_return: Optional[bool] = False) -> MISPObject:
        misp_object = self._create_misp_object('geolocation', location)
        if hasattr(location, 'description'):
            misp_object.comment = location.description
        for feature, attribute in self._mapping.location_object_mapping.items():
            if hasattr(location, feature):
                misp_attribute = {'value': getattr(location, feature)}
                misp_attribute.update(attribute)
                misp_object.add_attribute(**misp_attribute)
        if hasattr(location, 'precision'):
            attribute = {'value': float(location.precision) / 1000}
            attribute.update(self._mapping.accuracy_radius_attribute)
            misp_object.add_attribute(**attribute)
        if hasattr(location, 'object_marking_refs'):
            self._handle_object_marking_refs(
                location.object_marking_refs, misp_object
            )
        if to_return:
            return misp_object
        self._add_misp_object(misp_object)

    def _parse_observed_data(self, observed_data_ref: str):
        observed_data = self._get_stix_object(observed_data_ref)
        try:
            if hasattr(observed_data, 'spec_version') and observed_data.spec_version == '2.1':
                self._parse_observed_data_v21(observed_data)
            else:
                self._parse_observed_data_v20(observed_data)
        except UnknownObservableMappingError as observable_types:
            self._observable_mapping_error(observed_data.id, observable_types)

    ################################################################################
    #                  MISP GALAXIES & CLUSTERS PARSING FUNCTIONS                  #
    ################################################################################

    def _aggregate_galaxy_clusters(self, galaxies: dict):
        for galaxy_type, clusters in galaxies.items():
            misp_galaxy = MISPGalaxy()
            misp_galaxy.from_dict(**self._galaxies[galaxy_type])
            for cluster in clusters:
                misp_galaxy.clusters.append(cluster)
            yield misp_galaxy

    @staticmethod
    def _create_cluster_args(stix_object: _GALAXY_OBJECTS_TYPING,
                             galaxy_type: Union[None, str],
                             description: Optional[str] = None,
                             cluster_value: Optional[str] = None) -> dict:
        if galaxy_type is None:
            galaxy_type = stix_object.type
        if cluster_value is None:
            cluster_value = stix_object.name
        if description is not None:
            return {
                'type': galaxy_type,
                'value': cluster_value,
                'description': description
            }
        cluster_args = {
            'type': galaxy_type,
            'value': cluster_value
        }
        if hasattr(stix_object, 'description'):
            cluster_args['description'] = stix_object.description
            return cluster_args
        cluster_args['description'] = cluster_value.capitalize()
        return cluster_args

    def _extract_custom_fields(self, stix_object: _GALAXY_OBJECTS_TYPING):
        for key, value in stix_object.items():
            if key.startswith('x_misp_'):
                separator = '-' if key in self._mapping.dash_meta_fields else '_'
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
    def _handle_external_references(external_references: list) -> dict:
        meta = defaultdict(list)
        for reference in external_references:
            if reference.get('url'):
                meta['refs'].append(reference['url'])
            if reference.get('external_id'):
                meta['external_id'].append(reference['external_id'])
        if 'external_id' in meta and len(meta['external_id']) == 1:
            meta['external_id'] = meta.pop('external_id')[0]
        return meta

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
            for feature, field in getattr(self._mapping, mapping).items():
                if hasattr(stix_object, feature):
                    meta[field] = getattr(stix_object, feature)
            meta.update(dict(self._extract_custom_fields(stix_object)))
            return meta
        return dict(self._extract_custom_fields(stix_object))

    def _parse_attack_pattern_cluster(self, attack_pattern: _ATTACK_PATTERN_TYPING,
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

    def _parse_campaign_cluster(self, campaign: _CAMPAIGN_TYPING,
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

    def _parse_course_of_action_cluster(self, course_of_action: _COURSE_OF_ACTION_TYPING,
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

    def _parse_intrusion_set_cluster(self, intrusion_set: _INTRUSION_SET_TYPING,
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

    def _parse_malware_cluster(self, malware: _MALWARE_TYPING,
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

    def _parse_threat_actor_cluster(self, threat_actor: _THREAT_ACTOR_TYPING,
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

    def _parse_tool_cluster(self, tool: _TOOL_TYPING, description: Optional[str] = None,
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

    def _parse_vulnerability_cluster(self, vulnerability: _VULNERABILITY_TYPING,
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

    def _parse_attribute_relationships(self, attribute: MISPAttribute):
        if self.galaxies_as_tags:
            for relationship in self._relationship[attribute.uuid]:
                referenced_uuid = relationship['referenced_uuid']
                if referenced_uuid in self._clusters:
                    for tag in self._clusters[referenced_uuid]['tag_names']:
                        attribute.add_tag(tag)
                    self._clusters[referenced_uuid]['used'][self.misp_event.uuid] = True
        else:
            clusters = defaultdict(list)
            for relationship in self._relationship[attribute.uuid]:
                referenced_uuid = relationship['referenced_uuid']
                if referenced_uuid in self._clusters:
                    cluster = self._clusters[referenced_uuid]['cluster']
                    clusters[cluster['type']].append(cluster)
                    self._clusters[referenced_uuid]['used'][self.misp_event.uuid] = True
            if clusters:
                for galaxy in self._aggregate_galaxy_clusters(clusters):
                    attribute.add_galaxy(galaxy)

    def _parse_attribute_sightings(self, attribute: MISPAttribute):
        for sighting in self._sighting[attribute.uuid]:
            attribute.add_sighting(sighting)

    def _parse_object_relationships(self, misp_object: MISPObject):
        if self.galaxies_as_tags:
            for relationship in self._relationship[misp_object.uuid]:
                referenced_uuid = relationship['referenced_uuid']
                if referenced_uuid in self._clusters:
                    for attribute in misp_object.attributes:
                        for tag in self._clusters[referenced_uuid]['tag_names']:
                            attribute.add_tag(tag)
                    self._clusters[referenced_uuid]['used'][self.misp_event.uuid] = True
        else:
            clusters = defaultdict(list)
            for relationship in self._relationship[misp_object.uuid]:
                referenced_uuid = relationship['referenced_uuid']
                if referenced_uuid in self._clusters:
                    cluster = self._clusters[referenced_uuid]['cluster']
                    clusters[cluster['type']].append(cluster)
                    self._clusters[referenced_uuid]['used'][self.misp_event.uuid] = True
                else:
                    misp_object.add_reference(
                        self._sanitise_uuid(referenced_uuid),
                        relationship['relationship_type']
                    )
            if clusters:
                for galaxy in self._aggregate_galaxy_clusters(clusters):
                    for attribute in misp_object.attributes:
                        attribute.add_galaxy(galaxy)

    def _parse_object_sightings(self, misp_object: MISPObject):
        for sighting in self._sighting[misp_object.uuid]:
            for attribute in misp_object.attributes:
                attribute.add_sighting(sighting)

    def _parse_relationships(self):
        for attribute in self.misp_event.attributes:
            if attribute.uuid in self._relationship:
                self._parse_attribute_relationships(attribute)
        for misp_object in self.misp_event.objects:
            if misp_object.uuid in self._relationship:
                self._parse_object_relationships(misp_object)

    def _parse_relationships_and_sightings(self):
        for attribute in self.misp_event.attributes:
            if attribute.uuid in self._relationship:
                self._parse_attribute_relationships(attribute)
            if attribute.uuid in self._sighting:
                self._parse_attribute_sightings(attribute)
        for misp_object in self.misp_event.objects:
            if misp_object.uuid in self._relationship:
                self._parse_object_relationships(misp_object)
            if misp_object.uuid in self._sighting:
                self._parse_object_sightings(misp_object)

    def _parse_sightings(self):
        for attribute in self.misp_event.attributes:
            if attribute.uuid in self._sighting:
                self._parse_attribute_sightings(attribute)
        for misp_object in self.misp_event.objects:
            if misp_object.uuid in self._sighting:
                self._parse_object_sightings(misp_object)

    def _parse_SROs(self):
        if hasattr(self, '_relationship'):
            if hasattr(self, '_sighting'):
                self._parse_relationships_and_sightings()
            else:
                self._parse_relationships()
        elif hasattr(self, '_sighting'):
            self._parse_sightings()

    ################################################################################
    #                       MISP FEATURES CREATION FUNCTIONS                       #
    ################################################################################

    def _create_attribute_dict(self, stix_object: _SDO_TYPING) -> dict:
        attribute = self._parse_timeline(stix_object)
        if hasattr(stix_object, 'description') and stix_object.description:
            attribute['comment'] = stix_object.description
        attribute.update(
            self._sanitise_attribute_uuid(
                stix_object.id, comment=attribute.get('comment')
            )
        )
        if hasattr(stix_object, 'object_marking_refs'):
            tags = tuple(self._parse_markings(stix_object.object_marking_refs))
            attribute['Tag'] = [{'name': tag} for tag in tags]
        return attribute

    def _create_generic_event(self) -> MISPEvent:
        misp_event = MISPEvent()
        misp_event.uuid = self._identifier.split('--')[1]
        misp_event.info = self.generic_info_field
        return misp_event

    def _create_misp_event(self, stix_object: Union[Grouping, Report_v20, Report_v21]) -> MISPEvent:
        misp_event = MISPEvent(force_timestamps=True)
        event_uuid = self._extract_uuid(stix_object.id)
        if event_uuid in self.replacement_uuids:
            self._sanitise_object_uuid(misp_event, event_uuid)
        else:
            misp_event.uuid = event_uuid
        misp_event.info = stix_object.name if hasattr(stix_object, 'name') else self.generic_info_field
        misp_event.timestamp = self._timestamp_from_date(stix_object.modified)
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

    def _create_misp_object(self, name: str, stix_object: Optional[_SDO_TYPING] = None) -> MISPObject:
        misp_object = MISPObject(
            name,
            misp_objects_path_custom=_MISP_OBJECTS_PATH,
            force_timestamps=True
        )
        if stix_object is not None:
            object_uuid = self._extract_uuid(
                stix_object['id'] if isinstance(stix_object, dict) else stix_object.id
            )
            if object_uuid in self.replacement_uuids:
                self._sanitise_object_uuid(misp_object, object_uuid)
            else:
                misp_object.uuid = object_uuid
            misp_object.update(self._parse_timeline(stix_object))
        return misp_object

    ################################################################################
    #                              UTILITY FUNCTIONS.                              #
    ################################################################################

    def _all_refs_parsed(self, object_refs: list) -> bool:
        try:
            return all(object_ref in self._observable for object_ref in object_refs)
        except AttributeError:
            return False

    @staticmethod
    def _extract_uuid(object_id: str) -> str:
        return object_id.split('--')[-1]

    @staticmethod
    def _fetch_tags_from_labels(misp_feature: _MISP_FEATURES_TYPING, labels: list):
        for label in (label for label in labels if label.lower() != 'threat-report'):
            misp_feature.add_tag(label)

    @staticmethod
    def _parse_AS_value(number: Union[int, str]) -> str:
        if isinstance(number, int) or not number.startswith('AS'):
            return f'AS{number}'
        return number

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
            yield(marking_definition.name)

    def _parse_timeline(self, stix_object: _SDO_TYPING) -> dict:
        misp_object = {'timestamp': self._timestamp_from_date(stix_object.modified)}
        object_type = stix_object.type
        if object_type in self._mapping.timeline_mapping:
            first, last = self._mapping.timeline_mapping[object_type]
            if not self._skip_first_seen_last_seen(stix_object):
                if hasattr(stix_object, first) and getattr(stix_object, first):
                    misp_object['first_seen'] = getattr(stix_object, first)
                if hasattr(stix_object, last) and getattr(stix_object, last):
                    misp_object['last_seen'] = getattr(stix_object, last)
        return misp_object

    @staticmethod
    def _sanitise_value(value: str) -> str:
        return value.replace('\\\\', '\\')

    @staticmethod
    def _skip_first_seen_last_seen(stix_object: _SDO_TYPING) -> bool:
        if stix_object.type != 'indicator':
            return stix_object.modified == stix_object.first_observed == stix_object.last_observed
        if stix_object.valid_from != stix_object.modified:
            return False
        if not hasattr(stix_object, 'valid_until'):
            return True
        return stix_object.valid_until == stix_object.modified

    @staticmethod
    def _timestamp_from_date(date: datetime) -> int:
        return int(date.timestamp())
        try:
            return int(date.timestamp())
        except AttributeError:
            return int(time.mktime(time.strptime(date.split('+')[0], "%Y-%m-%dT%H:%M:%S.%fZ")))
