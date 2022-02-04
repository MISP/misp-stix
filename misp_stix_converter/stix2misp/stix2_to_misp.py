# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import time
from .exceptions import (UndefinedSTIXObjectError, UnknownAttributeTypeError,
    UnknownObjectNameError)
from .importparser import STIXtoMISPParser
from collections import defaultdict
from datetime import datetime
from pymisp import MISPEvent, MISPAttribute, MISPObject
from stix2.v20.bundle import Bundle as Bundle_v20
from stix2.v20.common import MarkingDefinition as MarkingDefinition_v20
from stix2.v20.sdo import (AttackPattern as AttackPattern_v20,
    CourseOfAction as CourseOfAction_v20, Identity as Identity_v20,
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
    CourseOfAction as CourseOfAction_v21, Grouping, Identity as Identity_v21,
    IntrusionSet as IntrusionSet_v21, Malware as Malware_v21,
    ObservedData as ObservedData_v21, Report as Report_v21,
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
    def __init__(self):
        super().__init__()

    def parse_stix_content(self, bundle: Union[Bundle_v20, Bundle_v21]):
        self._relationship = defaultdict(list)
        self.__stix_version = bundle.spec_version if hasattr(bundle, 'spec_version') else '2.1'
        self.__misp_event = MISPEvent()
        self._identifier = bundle.id
        for stix_object in bundle.objects:
            object_type = stix_object['type']
            try:
                if object_type in self._mapping.stix_to_misp_mapping:
                    getattr(self, self._mapping.stix_to_misp_mapping[object_type])(stix_object)
                else:
                    self._unknown_stix_object_type_warning(object_type)
            except UndefinedSTIXObjectError as error:
                self._undefined_object_error(error)
            except UnknownAttributeTypeError as error:
                self._unknown_attribute_type_warning(error)
            except UnknownObjectNameError as error:
                self._unknown_object_name_warning(error)

    @property
    def misp_event(self) -> MISPEvent:
        return self.__misp_event

    @property
    def stix_version(self) -> str:
        return self.__stix_version

    ################################################################################
    #                     MAIN STIX OBJECTS PARSING FUNCTIONS.                     #
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
        try:
            self._marking_definition[marking_definition.id] = marking_definition
        except AttributeError:
            self._marking_definition = {marking_definition.id: marking_definition}

    def _load_observable_object(self, observable: _OBSERVABLE_TYPES):
        try:
            self._observable[observable.id] = observable
        except AttributeError:
            self._observable = {observable.id: observable}

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

    def _parse_observed_data(self, observed_data: Union[ObservedData_v20, ObservedData_v21]):
        if hasattr(observed_data, 'spec_version') and observed_data.spec_version == '2.1':
            if self._all_refs_parsed(observed_data.object_refs):
                self._parse_observed_data_v21(observed_data)
            else:
                try:
                    self._observed_data[observed_data.id] = observed_data
                except AttributeError:
                    self._observed_data = {observed_data.id: observed_data}
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

    @staticmethod
    def _get_timestamp_from_date(date: datetime) -> int:
        return int(date.timestamp())
        try:
            return int(date.timestamp())
        except AttributeError:
            return int(time.mktime(time.strptime(date.split('+')[0], "%Y-%m-%dT%H:%M:%S.%fZ")))

    @staticmethod
    def _sanitize_value(value: str) -> str:
        return value.replace('\\\\', '\\')
