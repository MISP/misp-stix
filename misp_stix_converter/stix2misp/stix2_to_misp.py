# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import sys
import time
from .exceptions import (ObjectRefLoadingError, ObjectTypeLoadingError,
    SynonymsResourceJSONError, UnavailableGalaxyResourcesError,
    UnavailableSynonymsResourceError, UndefinedIndicatorError,
    UndefinedSTIXObjectError, UndefinedObservableError, UnknownAttributeTypeError,
    UnknownObjectNameError, UnknownParsingFunctionError, UnknownStixObjectTypeError)
from .external_stix2_mapping import ExternalSTIX2Mapping
from .importparser import STIXtoMISPParser
from .internal_stix2_mapping import InternalSTIX2Mapping
from collections import defaultdict
from datetime import datetime
from pymisp import AbstractMISP, MISPEvent, MISPAttribute, MISPObject
from stix2.parsing import parse as stix2_parser
from stix2.v20.bundle import Bundle as Bundle_v20
from stix2.v20.common import MarkingDefinition as MarkingDefinition_v20
from stix2.v20.sdo import (AttackPattern as AttackPattern_v20, Campaign as Campaign_v20,
    CourseOfAction as CourseOfAction_v20, Identity as Identity_v20,
    Indicator as Indicator_v20, IntrusionSet as IntrusionSet_v20, Malware as Malware_v20,
    ObservedData as ObservedData_v20, Report as Report_v20, ThreatActor as ThreatActor_v20,
    Tool as Tool_v20, Vulnerability as Vulnerability_v20)
from stix2.v20.sro import Relationship as Relationship_v20
from stix2.v21.bundle import Bundle as Bundle_v21
from stix2.v21.common import MarkingDefinition as MarkingDefinition_v21
from stix2.v21.observables import (Artifact, AutonomousSystem, Directory, DomainName,
    EmailAddress, EmailMessage, File, IPv4Address, IPv6Address, MACAddress, Mutex,
    NetworkTraffic, Process, Software, URL, UserAccount, WindowsRegistryKey,
    X509Certificate)
from stix2.v21.sdo import (AttackPattern as AttackPattern_v21, Campaign as Campaign_v21,
    CourseOfAction as CourseOfAction_v21, Grouping, Identity as Identity_v21,
    Indicator as Indicator_v21, IntrusionSet as IntrusionSet_v21, Location,
    Malware as Malware_v21, ObservedData as ObservedData_v21, Note, Report as Report_v21,
    ThreatActor as ThreatActor_v21, Tool as Tool_v21, Vulnerability as Vulnerability_v21)
from stix2.v21.sro import Relationship as Relationship_v21
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
_COURSE_OF_ACTION_TYPING = Union[
    CourseOfAction_v20,
    CourseOfAction_v21
]
_GALAXY_OBJECTS_TYPING = Union[
    AttackPattern_v20,
    AttackPattern_v21,
    CourseOfAction_v20,
    CourseOfAction_v21,
    IntrusionSet_v20,
    IntrusionSet_v21,
    Malware_v20,
    Malware_v21,
    ThreatActor_v20,
    ThreatActor_v21,
    Tool_v20,
    Tool_v21,
    Vulnerability_v20,
    Vulnerability_v21
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
_VULNERABILITY_TYPING = Union[
    Vulnerability_v20,
    Vulnerability_v21
]


class STIX2toMISPParser(STIXtoMISPParser):
    def __init__(self, synonyms_path: Union[None, str]):
        super().__init__(synonyms_path)
        self._creators: set = set()
        self._mapping: Union[ExternalSTIX2Mapping, InternalSTIX2Mapping]

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

    @staticmethod
    def _build_data_to_load(stix_object) -> dict:
        return {
            'stix_object': stix_object,
            'used': False
        }

    def _load_attack_pattern(self, attack_pattern: Union[AttackPattern_v20, AttackPattern_v21]):
        data_to_load = self._build_data_to_load(attack_pattern)
        try:
            self._attack_pattern[attack_pattern.id] = data_to_load
        except AttributeError:
            self._attack_pattern = {attack_pattern.id: data_to_load}

    def _load_campaign(self, campaign: Union[Campaign_v20, Campaign_v21]):
        data_to_load = self._build_data_to_load(campaign)
        try:
            self._campaign[campaign.id] = data_to_load
        except AttributeError:
            self._campaign = {campaign.id: campaign}

    def _load_course_of_action(self, course_of_action: Union[CourseOfAction_v20, CourseOfAction_v21]):
        data_to_load = self._build_data_to_load(course_of_action)
        try:
            self._course_of_action[course_of_action.id] = data_to_load
        except AttributeError:
            self._course_of_action = {course_of_action.id: data_to_load}

    def _load_grouping(self, grouping: Grouping):
        try:
            self._grouping[grouping.id] = grouping
        except AttributeError:
            self._grouping = {grouping.id: grouping}

    def _load_identity(self, identity: Union[Identity_v20, Identity_v21]):
        data_to_load = self._build_data_to_load(identity)
        try:
            self._identity[identity.id] = data_to_load
        except AttributeError:
            self._identity = {identity.id: data_to_load}

    def _load_indicator(self, indicator: Union[Indicator_v20, Indicator_v21]):
        try:
            self._indicator[indicator.id] = indicator
        except AttributeError:
            self._indicator = {indicator.id: indicator}

    def _load_intrusion_set(self, intrusion_set: Union[IntrusionSet_v20, IntrusionSet_v21]):
        data_to_load = self._build_data_to_load(intrusion_set)
        try:
            self._intrusion_set[intrusion_set.id] = data_to_load
        except AttributeError:
            self._intrusion_set = {intrusion_set.id: data_to_load}

    def _load_location(self, location: Location):
        try:
            self._location[location.id] = location
        except AttributeError:
            try:
                self._location = {location.id: location}
            except AttributeError:
                self._location = {location['id']: location}

    def _load_malware(self, malware: Union[Malware_v20, Malware_v21]):
        data_to_load = self._build_data_to_load(malware)
        try:
            self._malware[malware.id] = data_to_load
        except AttributeError:
            self._malware = {malware.id: data_to_load}

    def _load_marking_definition(self, marking_definition: Union[MarkingDefinition_v20, MarkingDefinition_v21]):
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
        try:
            self._note[note.id] = note
        except AttributeError:
            self._note = {note.id: note}

    def _load_observable_object(self, observable: _OBSERVABLE_TYPES):
        try:
            self._observable[observable.id] = observable
        except AttributeError:
            self._observable = {observable.id: observable}

    def _load_observed_data(self, observed_data: Union[ObservedData_v20, ObservedData_v21]):
        try:
            self._observed_data[observed_data.id] = observed_data
        except AttributeError:
            self._observed_data = {observed_data.id: observed_data}

    def _load_relationship(self, relationship: Union[Relationship_v20, Relationship_v21]):
        reference = {
            'referenced_uuid': relationship.target_ref,
            'relationship_type': relationship.relationship_type
        }
        try:
            self._relationship[relationship.source_ref.split('--')[1]].append(reference)
        except AttributeError:
            self._relationship = defaultdict(list)
            self._relationship[relationship.source_ref.split('--')[1]].append(reference)

    def _load_report(self, report: Union[Report_v20, Report_v21]):
        try:
            self._report[report.id] = report
        except AttributeError:
            self._report = {report.id: report}

    def _load_threat_actor(self, threat_actor: Union[ThreatActor_v20, ThreatActor_v21]):
        data_to_load = self._build_data_to_load(threat_actor)
        try:
            self._threat_actor[threat_actor.id] = data_to_load
        except AttributeError:
            self._threat_actor = {threat_actor.id: data_to_load}

    def _load_tool(self, tool: Union[Tool_v20, Tool_v21]):
        data_to_load = self._build_data_to_load(tool)
        try:
            self._tool[tool.id] = data_to_load
        except AttributeError:
            self._tool = {tool.id: data_to_load}

    def _load_vulnerability(self, vulnerability: Union[Vulnerability_v20, Vulnerability_v21]):
        data_to_load = self._build_data_to_load(vulnerability)
        try:
            self._vulnerability[vulnerability.id] = data_to_load
        except AttributeError:
            self._vulnerability = {vulnerability.id: data_to_load}

    ################################################################################
    #                     MAIN STIX OBJECTS PARSING FUNCTIONS.                     #
    ################################################################################

    def _get_stix_object(self, object_ref: str):
        object_type = object_ref.split('--')[0]
        if object_type.startswith('x-misp-'):
            object_type = object_type.replace('x-misp', 'custom')
        feature = f"_{object_type.replace('-', '_')}"
        try:
            stix_object = getattr(self, feature)[object_ref]
            if isinstance(stix_object, dict):
                stix_object['used'] = True
                return stix_object['stix_object']
            return stix_object
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
        for galaxy in self._galaxies.values():
            if self.misp_event.uuid not in galaxy['used']:
                continue
            if not galaxy['used'][self.misp_event.uuid]:
                for tag_name in galaxy['tag_names']:
                    self.misp_event.add_tag(tag_name)

    def _parse_location_object(self, location: Location) -> MISPObject:
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
            self._parse_markings(misp_object, location.object_marking_refs)
        return misp_object

    def _parse_observed_data(self, observed_data_ref: str):
        observed_data = self._get_stix_object(observed_data_ref)
        if hasattr(observed_data, 'spec_version') and observed_data.spec_version == '2.1':
            self._parse_observed_data_v21(observed_data)
        else:
            self._parse_observed_data_v20(observed_data)

    ################################################################################
    #                 RELATIONSHIPS & SIGHTINGS PARSING FUNCTIONS.                 #
    ################################################################################

    def _parse_attribute_relationships(self, attribute: MISPAttribute):
        for relationship in self._relationship[attribute.uuid]:
            referenced_uuid = relationship['referenced_uuid']
            if referenced_uuid in self._galaxies:
                for tag_name in self._galaxies[referenced_uuid]['tag_names']:
                    attribute.add_tag(tag_name)
                self._galaxies[referenced_uuid]['used'][self.misp_event.uuid] = True

    def _parse_attribute_sightings(self, attribute: MISPAttribute):
        for sighting in self._sighting[attribute.uuid]:
            attribute.add_sighting(sighting)

    def _parse_object_relationships(self, misp_object: MISPObject):
        for relationship in self._relationship[misp_object.uuid]:
            referenced_uuid = relationship['referenced_uuid']
            if referenced_uuid in self._galaxies:
                for tag_name in self._galaxies[referenced_uuid]['tag_names']:
                    for attribute in misp_object.attributes:
                        attribute.add_tag(tag_name)
                self._galaxies[referenced_uuid]['used'][self.misp_event.uuid] = True
            else:
                misp_object.add_reference(
                    referenced_uuid.split('--')[1],
                    relationship['relationship_type']
                )

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

    def _create_generic_event(self) -> MISPEvent:
        misp_event = MISPEvent()
        misp_event.uuid = self._identifier.split('--')[1]
        misp_event.info = f'STIX {self.stix_version} Bundle imported with the MISP-STIX import feature.'
        return misp_event

    def _create_misp_event(self, stix_object: Union[Grouping, Report_v20, Report_v21]) -> MISPEvent:
        misp_event = MISPEvent(force_timestamps=True)
        misp_event.uuid = stix_object.id.split('--')[-1]
        misp_event.info = stix_object.name
        misp_event.timestamp = self._timestamp_from_date(stix_object.modified)
        self._handle_misp_event_tags(misp_event, stix_object)
        return misp_event

    def _create_misp_object(self, name: str, stix_object: Optional[_SDO_TYPING] = None) -> MISPObject:
        misp_object = MISPObject(
            name,
            misp_objects_path_custom=_MISP_OBJECTS_PATH,
            force_timestamps=True
        )
        if stix_object is not None:
            try:
                misp_object.uuid = stix_object.id.split('--')[-1]
            except AttributeError:
                misp_object.uuid = stix_object['id'].split('--')[1]
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
    def _fetch_tags_from_labels(misp_feature: _MISP_FEATURES_TYPING, labels: list):
        for label in (label for label in labels if label.lower() != 'threat-report'):
            misp_feature.add_tag(label)

    @staticmethod
    def _parse_AS_value(number: Union[int, str]) -> str:
        if isinstance(number, int) or not number.startswith('AS'):
            return f'AS{number}'
        return number

    def _parse_markings(self, misp_feature: Union[MISPAttribute, MISPObject], marking_refs: list):
        for marking_ref in marking_refs:
            try:
                marking_definition = self._get_stix_object(marking_ref)
            except ObjectTypeLoadingError as error:
                self._object_type_loading_error(error)
                continue
            except ObjectRefLoadingError as error:
                self._object_ref_loading_error(error)
                continue
            misp_feature.add_tag(marking_definition.name)

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
    def _sanitize_value(value: str) -> str:
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
