# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import sys
import time
from .exceptions import (ObjectRefLoadingError, ObjectTypeLoadingError,
    UndefinedSTIXObjectError, UnknownAttributeTypeError, UnknownObjectNameError, UnknownParsingFunctionError)
from .importparser import STIXtoMISPParser
from collections import defaultdict
from datetime import datetime
from pymisp import MISPEvent, MISPAttribute, MISPObject
from stix2.parsing import parse as stix2_parser
from stix2.v20.bundle import Bundle as Bundle_v20
from stix2.v20.common import MarkingDefinition as MarkingDefinition_v20
from stix2.v20.sdo import (AttackPattern as AttackPattern_v20,
    CourseOfAction as CourseOfAction_v20, CustomObject as CustomObject_v20,
    Identity as Identity_v20, Indicator as Indicator_v20,
    IntrusionSet as IntrusionSet_v20, Malware as Malware_v20,
    ObservedData as ObservedData_v20, Report as Report_v20,
    ThreatActor as ThreatActor_v20, Tool as Tool_v20,
    Vulnerability as Vulnerability_v20)
from stix2.v20.sro import Relationship as Relationship_v20
from stix2.v21.bundle import Bundle as Bundle_v21
from stix2.v21.common import MarkingDefinition as MarkingDefinition_v21
from stix2.v21.observables import (Artifact, AutonomousSystem, Directory, DomainName,
    EmailAddress, EmailMessage, File, IPv4Address, IPv6Address, MACAddress, Mutex,
    NetworkTraffic, Process, Software, URL, UserAccount, WindowsRegistryKey,
    X509Certificate)
from stix2.v21.sdo import (AttackPattern as AttackPattern_v21,
    CourseOfAction as CourseOfAction_v21, CustomObject as CustomObject_v21, Grouping,
    Identity as Identity_v21, Indicator as Indicator_v21,
    IntrusionSet as IntrusionSet_v21, Malware as Malware_v21,
    ObservedData as ObservedData_v21, Note, Report as Report_v21,
    ThreatActor as ThreatActor_v21, Tool as Tool_v21,
    Vulnerability as Vulnerability_v21)
from stix2.v21.sro import Relationship as Relationship_v21
from typing import Union

_OBSERVABLE_TYPES = Union[
    Artifact, AutonomousSystem, Directory, DomainName, EmailAddress, EmailMessage,
    File, IPv4Address, IPv6Address, MACAddress, Mutex, NetworkTraffic, Process,
    Software, URL, UserAccount, WindowsRegistryKey, X509Certificate
]


class STIX2toMISPParser(STIXtoMISPParser):
    def __init__(self, single_event: bool):
        super().__init__()
        self.__single_event = single_event
        self.__n_report = 0

    def load_stix_bundle(self, bundle: Union[Bundle_v20, Bundle_v21]):
        self._identifier = bundle.id
        self._relationship = defaultdict(list)
        self.__stix_version = bundle.spec_version if hasattr(bundle, 'spec_version') else '2.1'
        n_report = self.__n_report
        for stix_object in bundle.objects:
            object_type = stix_object.type
            if object_type in ('grouping', 'report'):
                n_report += 1
            try:
                feature = self._mapping.stix_object_loading_mapping[object_type]
            except KeyError:
                self._unknown_stix_object_type_warning(object_type)
                continue
            try:
                getattr(self, feature)(stix_object)
            except AttributeError as exception:
                sys.exit(exception)
        self.__n_report = 2 if n_report >= 2 else n_report

    def parse_stix_bundle(self):
        try:
            feature = self._mapping.bundle_to_misp_mapping[str(self.__n_report)]
        except AttributeError:
            sys.exit('No STIX content loaded, please run `load_stix_content` first.')
        getattr(self, feature)()

    def parse_stix_content(self, filename: str):
        try:
            with open(filename, 'rt', encoding='utf-8') as f:
                bundle = stix2_parser(f.read(), allow_custom=True, interoperability=True)
        except Exception as exception:
            sys.exit(exception)
        self.load_stix_bundle(bundle)
        del bundle
        self.parse_stix_bundle()

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

    @property
    def misp_event(self) -> Union[MISPEvent, dict]:
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
        try:
            self._attack_pattern[attack_pattern.id] = attack_pattern
        except AttributeError:
            self._attack_pattern = {attack_pattern.id: attack_pattern}

    def _load_course_of_action(self, course_of_action: Union[CourseOfAction_v20, CourseOfAction_v21]):
        try:
            self._course_of_action[course_of_action.id] = course_of_action
        except AttributeError:
            self._course_of_action = {course_of_action.id: course_of_action}

    def _load_custom_attribute(self, custom_attribute: Union[CustomObject_v20, CustomObject_v21]):
        try:
            self._custom_attribute[custom_attribute.id] = custom_attribute
        except AttributeError:
            self._custom_attribute = {custom_attribute.id: custom_attribute}

    def _load_custom_object(self, custom_object: Union[CustomObject_v20, CustomObject_v21]):
        try:
            self._custom_object[custom_object.id] = custom_object
        except AttributeError:
            self._custom_object = {custom_object.id: custom_object}

    def _load_grouping(self, grouping: Grouping):
        try:
            self._grouping[grouping.id] = grouping
        except AttributeError:
            self._grouping = {grouping.id: grouping}

    def _load_identity(self, identity: Union[Identity_v20, Identity_v21]):
        try:
            self._identity[identity.id] = identity
        except AttributeError:
            self._identity = {identity.id: identity}

    def _load_indicator(self, indicator: Union[Indicator_v20, Indicator_v21]):
        try:
            self._indicator[indicator.id] = indicator
        except:
            self._indicator = {indicator.id: indicator}

    def _load_intrusion_set(self, intrusion_set: Union[IntrusionSet_v20, IntrusionSet_v21]):
        try:
            self._intrusion_set[intrusion_set.id] = intrusion_set
        except AttributeError:
            self._intrusion_set = {intrusion_set.id: intrusion_set}

    def _load_malware(self, malware: Union[Malware_v20, Malware_v21]):
        try:
            self._malware[malware.id] = malware
        except AttributeError:
            self._malware = {malware.id: malware}

    def _load_marking_definition(self, marking_definition: Union[MarkingDefinition_v20, MarkingDefinition_v21]):
        definition_type = marking_definition.definition_type
        tag_name = f"{definition_type}:{marking_definition.definition[definition_type]}"
        try:
            self._marking_definition[marking_definition.id] = tag_name
        except AttributeError:
            self._marking_definition = {marking_definition.id: tag_name}

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
        self._relationship[relationship.source_ref].append(
            {
                'referenced_uuid': relationship.target_ref,
                'relationship_type': relationship.relationship_type
            }
        )

    def _load_report(self, report: Union[Report_v20, Report_v21]):
        try:
            self._report[report.id] = report
        except AttributeError:
            self._report = {report.id: report}

    def _load_sighting(self, sighting):
        try:
            self._sighting[sighting.id] = sighting
        except AttributeError:
            self._sighting = {sighting.id: sighting}

    def _load_threat_actor(self, threat_actor: Union[ThreatActor_v20, ThreatActor_v21]):
        try:
            self._threat_actor[threat_actor.id] = threat_actor
        except AttributeError:
            self._threat_actor = {threat_actor.id: threat_actor}

    def _load_tool(self, tool: Union[Tool_v20, Tool_v21]):
        try:
            self._tool[tool.id] = tool
        except AttributeError:
            self._tool = {tool.id: tool}

    def _load_vulnerability(self, vulnerability: Union[Vulnerability_v20, Vulnerability_v21]):
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
            try:
                feature = self._mapping.stix_to_misp_mapping[object_type]
            except KeyError:
                self._unknown_stix_object_type_warning(object_type)
                continue
            try:
                parser = getattr(self, feature)
            except AttributeError:
                self._unknown_parsing_function_error(feature)
                continue
            try:
                parser(object_ref)
            except ObjectRefLoadingError as error:
                self._object_ref_loading_error(error)
            except ObjectTypeLoadingError as error:
                self._object_type_loading_error(error)
            except UndefinedSTIXObjectError as error:
                self._undefined_object_error(error)
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
        misp_event = MISPEvent()
        misp_event.uuid = grouping.id.split('--')[-1]
        misp_event.info = grouping.name
        misp_event.published = False
        misp_event.timestamp = self._timestamp_from_date(grouping.modified)
        self._handle_misp_event_tags(misp_event, grouping)
        return misp_event

    def _misp_event_from_report(self, report: Union[Report_v20, Report_v21]) -> MISPEvent:
        misp_event = MISPEvent()
        misp_event.uuid = report.id.split('--')[-1]
        misp_event.info = report.name
        if report.published != report.modified:
            misp_event.published = True
            misp_event.publish_timestamp = self._timestamp_from_date(report.published)
        else:
            misp_event.published = False
        misp_event.timestamp = self._timestamp_from_date(report.modified)
        self._handle_misp_event_tags(misp_event, report)
        return misp_event

    def _parse_observed_data(self, observed_data_ref: str):
        observed_data = self._get_stix_object(observed_data_ref)
        if hasattr(observed_data, 'spec_version') and observed_data.spec_version == '2.1':
            self._parse_observed_data_v21(observed_data)
        else:
            self._parse_observed_data_v20(observed_data)

    ################################################################################
    #                       MISP FEATURES CREATION FUNCTIONS                       #
    ################################################################################

    def _add_attribute(self, attribute: dict):
        misp_attribute = MISPAttribute()
        misp_attribute.from_dict(**attribute)
        self.misp_event.add_attribute(**misp_attribute)

    def _add_object(self, misp_object: MISPObject):
        self.misp_event.add_object(misp_object)

    ################################################################################
    #                              UTILITY FUNCTIONS.                              #
    ################################################################################

    def _all_refs_parsed(self, object_refs: list) -> bool:
        try:
            return all(object_ref in self._observable for object_ref in object_refs)
        except AttributeError:
            return False

    def _parse_timeline(self, stix_object: _MISP_OBJECT_TYPING) -> dict:
        misp_object = {'timestamp': self._timestamp_from_date(stix_object.modified)}
        first, last = self._mapping.timeline_mapping[stix_object.type]
        if hasattr(stix_object, first) and getattr(stix_object, first):
            misp_object['first_seen'] = getattr(stix_object, first)
        if hasattr(stix_object, last) and getattr(stix_object, last):
            misp_object['last_seen'] = getattr(stix_object, last)
        return misp_object

    @staticmethod
    def _sanitize_value(value: str) -> str:
        return value.replace('\\\\', '\\')

    @staticmethod
    def _timestamp_from_date(date: datetime) -> int:
        return int(date.timestamp())
        try:
            return int(date.timestamp())
        except AttributeError:
            return int(time.mktime(time.strptime(date.split('+')[0], "%Y-%m-%dT%H:%M:%S.%fZ")))
