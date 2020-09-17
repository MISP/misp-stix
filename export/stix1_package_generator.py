# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import datetime
import .stix1_mapping
from collections import defaultdict
from cybox.core import Object, Observable, ObservableComposition, RelatedObject
from cybox.common import Hash, HashList, ByteRun, ByteRuns
from cybox.common.object_properties import CustomProperties,  Property
from cybox.objects.account_object import Account, Authentication, StructuredAuthenticationMechanism
from cybox.objects.address_object import Address
from cybox.objects.artifact_object import Artifact, RawArtifact
from cybox.objects.as_object import AutonomousSystem
from cybox.objects.custom_object import Custom
from cybox.objects.domain_name_object import DomainName
from cybox.objects.email_message_object import EmailMessage, EmailHeader, EmailRecipients, Attachments
from cybox.objects.file_object import File
from cybox.objects.hostname_object import Hostname
from cybox.objects.http_session_object import HTTPClientRequest, HTTPRequestHeader, HTTPRequestHeaderFields, HTTPRequestLine, HTTPRequestResponse, HTTPSession
from cybox.objects.mutex_object import Mutex
from cybox.objects.network_connection_object import NetworkConnection
from cybox.objects.network_socket_object import NetworkSocket
from cybox.objects.pipe_object import Pipe
from cybox.objects.port_object import Port
from cybox.objects.process_object import ChildPIDList, ImageInfo, PortList, Process
from cybox.objects.socket_address_object import SocketAddress
from cybox.objects.system_object import System, NetworkInterface, NetworkInterfaceList
from cybox.objects.unix_user_account_object import UnixUserAccount
from cybox.objects.uri_object import URI
from cybox.objects.user_account_object import UserAccount
from cybox.objects.whois_object import WhoisEntry, WhoisRegistrants, WhoisRegistrant, WhoisRegistrar, WhoisNameservers
from cybox.objects.win_executable_file_object import WinExecutableFile, PEHeaders, PEFileHeader, PESectionList, PESection, PESectionHeaderStruct, Entropy
from cybox.objects.win_registry_key_object import RegistryValue, RegistryValues, WinRegistryKey
from cybox.objects.win_service_object import WinService
from cybox.objects.win_user_account_object import WinUser
from cybox.objects.x509_certificate_object import X509Certificate, X509CertificateSignature, X509Cert, SubjectPublicKey, RSAPublicKey, Validity
from cybox.utils import Namespace
from mixbox import idgen
from stix.coa import CourseOfAction
from stix.common import InformationSource, Identity, ToolInformation
from stix.common.confidence import Confidence
from stix.common.related import RelatedIndicator, RelatedObservable, RelatedThreatActor, RelatedTTP
from stix.common.vocabs import IncidentStatus
from stix.core import STIXPackage, STIXHeader
from stix.data_marking import Marking, MarkingSpecification
from stix.exploit_target import ExploitTarget, Vulnerability, Weakness
from stix.exploit_target.vulnerability import CVSSVector
from stix.extensions.identity.ciq_identity_3_0 import CIQIdentity3_0Instance, STIXCIQIdentity3_0, PartyName, ElectronicAddressIdentifier, FreeTextAddress
from stix.extensions.identity.ciq_identity_3_0 import Address as ciq_Address
from stix.extensions.marking.simple_marking import SimpleMarkingStructure
from stix.extensions.marking.tlp import TLPMarkingStructure
from stix.extensions.test_mechanism.snort_test_mechanism import SnortTestMechanism
from stix.incident import Incident, Time, ExternalID, AffectedAsset, AttributedThreatActors, COATaken
from stix.incident.history import History, HistoryItem
from stix.indicator import Indicator
from stix.indicator.valid_time import ValidTime
from stix.threat_actor import ThreatActor
from stix.ttp import TTP, Behavior
from stix.ttp.attack_pattern import AttackPattern
from stix.ttp.malware_instance import MalwareInstance
from stix.ttp.resource import Resource, Tools


class Stix1PackageGenerator():
    def __init__(self, namespace, orgname):
        self.namespace = namespace
        self.orgname = orgname
        self.errors = defaultdict(set)
        self.header_comment = []
        self.misp_event = MISPEvent()
        self.objects_to_parse = defaultdict(dict)
        self.ttps = {}
        self.ttps_references = {}

    def parse_misp_event(self, misp_event, version):
        self.misp_event.from_dict(**misp_event)
        self.stix_package = self._create_stix_package(version)
        self.incident = self._create_incident()
        self._generate_stix_objects()

    ################################################################################
    ##                    MAIN STIX PACKAGE CREATION FUNCTIONS                    ##
    ################################################################################

    def _create_incident(self):
        incident_id = f'{self.orgname}:Incident-{self.misp_event.uuid}'
        incident = Incident(id_=incident_id, title=self.misp_event.info)
        incident_time = Time()
        incident_time.incident_discovery = self.misp_event.date
        if self.misp_event.published:
            incident.timestamp = self.misp_event.publish_timestamp
            incident_time.incident_reported = self.misp_event.publish_timestamp
        else:
            incident.timestamp = self.misp_event.timestamp
        incident.time = incident_time
        return incident

    def _create_stix_package(self, version):
        package_id = f'{self.orgname}:STIXPackage-{self.misp_event.uuid}'
        timestamp = self.misp_event.timestamp
        stix_package = STIXPackage(id_=package_id, timestamp=timestamp)
        stix_package.version = version
        return stix_package

    def _generate_stix_objects(self):
        self.history = History()
        if hasattr(self.misp_event, 'threat_level_id'):
            threat_level = stix1_mapping.threat_level_mapping[self.misp_event.threat_level_id]
            self._add_journal_entry(f'Event Threat Level: {threat_level}')
        if self.misp_event.tags:
            tags = tuple(tag.name for tag in self.misp_event.tags)
            self.incident.handling = self._set_handling(tags)
        external_id = ExternalID(value=self.misp_event.id, source='MISP Event')
        self.incident.add_external_id(external_id)
        if hasattr(self.misp_event, 'analysis'):
            status = stix1_mapping.status_mapping[self.misp_event.analysis]
            self.incident.status = IncidentStatus(status)
        self.orgc_name = self._set_creator()
        self.incident.information_source = self._set_source()
        self.incident.reporter = self._set_reporter()
        self._resolve_galaxies()

    def _resolve_galaxies(self):
        for galaxy in self.misp_event.get('Galaxy', []):
            galaxy_type = galaxy['type']
            if galaxy_type in stix1_mapping.galaxy_types_mapping:
                getattr(self, stix1_mapping.galaxy_types_mapping[galaxy_type])(galaxy)
            else:
                self.errors['galaxy'].add(f'Unknown galaxy type: {galaxy_type}')

    ################################################################################
    ##                         GALAXIES PARSING FUNCTIONS                         ##
    ################################################################################

    def _parse_attack_pattern_galaxy(self, galaxy):
        ttp = self._create_ttp_from_galaxy(
            galaxy['GalaxyCluster'][0]['collection_uuid'],
            galaxy['name']
        )
        behavior = Behavior()
        for cluster in galaxy['GalaxyCluster']:
            attack_pattern = AttackPattern()
            attack_pattern.id_ = f"{self.namespace}:AttackPattern-{cluster['uuid']}"
            attack_pattern.title = cluster['value']
            attack_pattern.description = cluster['description']
            if cluster['meta'].get('external_id'):
                external_id = cluster['meta']['external_id'][0]
                if external_id.startswith('CAPEC'):
                    attack_pattern.capec_id = external_id
            behavior.add_attack_pattern(attack_pattern)
        ttp.behavior = behavior
        self.stix_package.add_ttp(ttp)

    def _parse_course_of_action_galaxy(self, galaxy):
        for cluster in galaxy['GalaxyCluster']:
            course_of_action = CourseOfAction()
            course_of_action.id_ = f"{self.namespace}:CourseOfAction-{cluster['uuid']}"
            course_of_action.title = cluster['value']
            course_of_action.description = cluster['description']
            self.stix_package.add_course_of_action(course_of_action)

    def _parse_malware_galaxy(self, galaxy):
        ttp = self._create_ttp_from_galaxy(
            galaxy['GalaxyCluster'][0]['collection_uuid'],
            galaxy['name']
        )
        behavior = Behavior()
        for cluster in galaxy['GalaxyCluster']:
            malware = MalwareInstance()
            malware.id_ = f"{self.namespace}:MalwareInstance-{cluster['uuid']}"
            malware.title = cluster['value']
            if cluster.get('description'):
                malware.description = cluster['description']
            if cluster['meta'].get('synonyms'):
                for synonym in cluster['meta']['synonyms']:
                    malware.add_name(synonym)
            behavior.add_malware_instance(malware)
        ttp.behavior = behavior
        self.stix_package.add_ttp(ttp)

    def _parse_threat_actor_galaxy(self, galaxy):
        for cluster in galaxy['GalaxyCluster']:
            threat_actor = ThreatActor()
            threat_actor.id_ = f"{self.namespace}:ThreatActor-{cluster['uuid']}"
            threat_actor.title = cluster['value']
            if cluster.get('description'):
                threat_actor.description = cluster['description']
            meta = cluster['meta']
            if meta.get('cfr-type-of-incident'):
                intended_effect = meta['cfr-type-of-incident']
                if isinstance(intended_effect, list):
                    for effect in intended_effect:
                        threat_actor.add_intended_effect(effect)
                else:
                    threat_actor.add_intended_effect(intended_effect)
            self.stix_package.add_threat_actor(threat_actor)

    def _parse_tool_galaxy(self, galaxy):
        ttp = self.create_ttp_from_galaxy(
            galaxy['GalaxyCluster'][0]['collection_uuid'],
            galaxy['name']
        )
        tools = Tools()
        for cluster in galaxy['GalaxyCluster']:
            tool = ToolInformation()
            tool.id_ = f"{self.namespace}:ToolInformation-{cluster['value']}"
            tool.name = cluster['value']
            if cluster.get('description'):
                tool.description = cluster['description']
            tools.append(tool)
        resource = Resource()
        resource.tools = tools
        ttp.resources = resource
        self.stix_package.add_ttp(ttp)

    def _parse_vulnerability_galaxy(self, galaxy):
        ttp = self.create_ttp_from_galaxy(
            galaxy['GalaxyCluster'][0]['collection_uuid'],
            galaxy['name']
        )
        exploit_target = ExploitTarget()
        for cluster in galaxy['GalaxyCluster']:
            vulnerability = Vulnerability()
            vulnerability.id_ = f"{self.namespace}:Vulnerability-{cluster['uuid']}"
            vulnerability.title = cluster['value']
            vulnerability.description = cluster['description']
            if cluster['meta'].get('aliases'):
                vulnerability.cve_id = cluster['meta']['aliases'][0]
            if cluster['meta'].get('refs'):
                for reference in cluster['meta']['refs']:
                    vulnerability.add_reference(reference)
            exploit_target.add_vulnerability(vulnerability)
        ttp.add_exploit_target(exploit_target)
        self.stix_package.add_ttp(ttp)

    ################################################################################
    ##                     OBJECTS CREATION HELPER FUNCTIONS.                     ##
    ################################################################################

    def _add_journal_entry(self, entry_line):
        history_item = HistoryItem()
        history_item.journal_entry = entryline
        self.history.append(history_item)

    @staticmethod
    def _create_information_source(identity):
        information_source = InformationSource(identity=identity)
        return information_source

    def _create_ttp_from_galaxy(self, uuid, galaxy_name):
        ttp = TTP()
        ttp.id_ = f'{self.namespace}:TTP-{uuid}'
        ttp.title = f'{galaxy_name} (MISP Galaxy)'
        return ttp

    @staticmethod
    def _fetch_colors(tags):
        return (tag.split(':')[-1].upper() for tag in tags)

    @staticmethod
    def _set_color(tags):
        tlp_color = 0
        for color in colors:
            color_num = stix1_mapping.TLP_order[color]
            if color_num > tlp_color:
                tlp_color = color_num
                color_value = color
        return color_value

    def _set_creator(self):
        if not hasattr(self.misp_event, 'orgc'):
            return self.orgname
        return self.misp_event.orgc.name

    def _set_handling(self, tags):
        sorted_tags = defaultdict(list)
        for tag in tags:
            feature = 'tlp_tags' if tag.startswith('tlp:') else 'simple_tags'
            ordered_tags[feature].append(tag)
        handling = Marking()
        if 'tlp_tags' in sorted_tags:
            handling.add_marking(self._set_tlp(sorted_tags['tlp_tags']))
        for tag in sorted_tags['simple_tags']:
            handling.add_marking(self._set_tag(tag))
        return handling

    def _set_reporter(self):
        reporter = self.misp_event.org.name if hasattr(self.misp_event, 'org') else self.orgname
        identity = Identity(name=reporter)
        return self._create_information_source(identity)

    def _set_source(self):
        identity = Identity(name=self.orgc_name)
        return self._create_information_source(identity)

    @staticmethod
    def _set_tag(tag):
        simple_marking = SimpleMarkingStructure()
        simple_marking.statement = tag
        marking_specification = MarkingSpecification()
        marking_specification.marking_structures.append(simple)
        return marking_specification

    def _set_tlp(self, tags):
        tlp = TLPMarkingStructure()
        tlp.color = self._set_color(self._fetch_colors(tags))
        marking_specification = MarkingSpecification()
        marking_specification.controlled_structure = "../../../descendant-or-self::node()"
        marking_specification.marking_structures.append(tlp)
        return marking_specification
