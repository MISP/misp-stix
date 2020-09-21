# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import datetime
import socket
import .stix1_mapping
from collections import defaultdict
from cybox.core import Object, Observable, ObservableComposition, RelatedObject
from cybox.common import Hash, HashList, ByteRun, ByteRuns
from cybox.common.hashes import _set_hash_type
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
        self._resolve_attributes()

    def _resolve_attributes(self):
        for attribute in self.misp_event.attributes:
            attribute_type = attribute['type']
            if attribute_type in stix1_mapping.attribute_types_mapping:
                getattr(self, stix1_mapping.attribute_types_mapping[attribute_type])(attribute)
            else:
                self.errors['attribute'].add(f'Unmapped attribute type: {attribute_type}')

    def _resolve_galaxies(self):
        for galaxy in self.misp_event.get('Galaxy', []):
            galaxy_type = galaxy['type']
            if galaxy_type in stix1_mapping.galaxy_types_mapping:
                getattr(self, stix1_mapping.galaxy_types_mapping[galaxy_type])(galaxy)
            else:
                self.errors['galaxy'].add(f'Unknown galaxy type: {galaxy_type}')

    ################################################################################
    ##                        ATTRIBUTES PARSING FUNCTIONS                        ##
    ################################################################################

    def _handle_attribute(self, attribute, observable):
        if attribute.to_ids:
            indicator = self._create_indicator(attribute)
            indicator.add_indicator_type(self._set_indicator_type(attribute.type))
            indicator.add_valid_time_position(ValidTime())
            indicator.add_observable(observable)
            related_indicator = RelatedIndicator(
                indicator,
                relationship=attribute.category
            )
            self.incident.related_indicators.append(related_indicator)
        else:
            related_observable = RelatedObservable(
                observable,
                relationship=attribute.category
            )
            self.incident.related_observables.append(related_observable)

    def _handle_file_observable(self, attribute, file_object):
        observable = self._create_observable(file_object, attribute.uuid, 'File')
        observable = Observable(file_object)
        observable.id_ = f"{self.namespace}:File-{attribute.uuid}"
        self._handle_attribute(attribute, observable)

    def _parse_attachment(self, attribute):
        if attribute.data:
            artifact_object = self._create_artifact_object(attribute.data)
            observable = self._create_observable(artifact_object, attribute.uuid, 'Artifact')
            observable.title = attribute.value
            self._handle_attribute(attribute, observable)
        else:
            self._parse_file_attribute(attribute)

    def _parse_autonomous_system_attribute(self, attribute):
        autonomous_system = self._create_autonomous_system_object(attribute.value)
        observable = self._create_observable(autonomous_system, attribute.uuid, 'AS')
        self._handle_attribute(attribute, observable)

    def _parse_domain_attribute(self, attribute):
        domain_object = self._create_domain_object(attribute.value)
        observable = self._create_observable(domain_object, attribute.uuid, 'DomainName')
        self._handle_attribute(attribute, observable)

    def _parse_domain_ip_attribute(self, attribute):
        domain, ip = attribute.value.split('|')
        address_object = self._create_address_object(attribute.type, ip)
        address_observable = self._create_observable(address_object, attribute.uuid, 'Address')
        domain_object = self._create_domain_object(domain)
        domain_observable = self._create_observable(domain_object, attribute.uuid, 'DomainName')
        composite_object = ObservableComposition(
            observables=[address_observable, domain_observable]
        )
        composite_object.operator = "AND"
        observable = Observable(
            id_=f"{self.namespace}:ObservableComposition-{attribute.uuid}"
        )
        observable.observable_composition = composite_object
        self._handle_attribute(attribute, observable)

    def _parse_email_attachment(self, attribute):
        file_object = File()
        file_object.file_name = attribute.value
        file_object.file_name.condition = "Equals"
        file_object.parent.id_ = f"{self.namespace}:FileObject-{attribute.uuid}"
        email = EmailMessage()
        email.attachments = Attachments()
        email.add_related(file_object, "Contains", inline=True)
        email.attachments.append(file_object.parent.id_)
        observable = self._create_observable(email, attribute.uuid, 'EmailMessage')
        self._handle_attribute(attribute, observable)

    def _parse_email_attribute(self, attribute):
        email_object = EmailMessage()
        email_header = EmailHeader()
        feature = stix1_mapping.email_attribute_mapping[attribute.type]
        setattr(email_header, feature, attribute.value)
        setattr(getattr(email_header, feature), 'condition', 'Equals')
        email_object.header = email_header
        observable = self._create_observable(email_object, attribute.uuid, 'EmailMessage')
        self._handle_attribute(attribute, observable)

    def _parse_file_attribute(self, attribute):
        file_object = self._create_file_object(attribute.value, attribute.uuid)
        self._handle_file_observable(attribute, file_object)

    def _parse_hash_attribute(self, attribute):
        hash = self._parse_hash_value(attribute.type, attribute.value)
        file_object = File()
        file_object.add_hash(hash)
        self._handle_file_observable(attribute, file_object)

    def _parse_hash_composite_attribute(self, attribute):
        filename, hash_value = attribute.value.split('|')
        file_object = self._create_file_object(filename, attribute.uuid)
        attribute_type = attribute.type.split('|')[1] if '|' in attribute.type else 'filename|md5'
        hash = self._parse_hash_value(attribute_type, hash_value)
        file_object.add_hash(hash)
        self._handle_file_observable(attribute, file_object)

    @staticmethod
    def _parse_hash_value(attribute_type, attribute_value):
        args = {'hash_value': attribute_value, 'exact': True}
        if hasattr(Hash, f'TYPE_{attribute_type.upper()}'):
            args['type_'] = getattr(Hash, f'TYPE_{attribute_type.upper()}')
            return Hash(**args)
        hash = Hash(**args)
        _set_hash_type(hash, attribute_value)
        return hash

    def _parse_hostname_attribute(self, attribute):
        hostname_object = self._create_hostname_object(attribute.value)
        observable = self._create_observable(hostname_object, attribute.uuid, 'Hostname')
        self._handle_attribute(attribute, observable)

    def _parse_hostname_port_attribute(self, attribute):
        hostname, socket_address = self._create_socket_address_object(attribute)
        socket_address.hostname = self._create_hostname_object(hostname)
        observable = self._create_observable(socket_address, attribute.uuid, 'SocketAddress')
        self._handle_attribute(attribute, observable)

    def _parse_http_method_attribute(self, attribute):
        http_client_request = HTTPClientRequest()
        http_request_line = HTTPRequestLine()
        http_request_line.http_method = attribute.value
        http_request_line.http_method.condition = "Equals"
        http_client_request.http_request_line = http_request_line
        self._parse_http_session(attribute, http_client_request)

    def _parse_http_session(self, attribute, http_client_request):
        http_request_response = HTTPRequestResponse()
        request_response.http_client_request = http_client_request
        http_session_object = HTTPSession()
        http_session_object.http_request_response = http_request_response
        observable = self._create_observable(http_session_object, attribute.uuid, 'HTTPSession')
        self._handle_attribute(attribute, observable)

    def _parse_ip_attribute(self, attribute):
        address_object = self._create_address_object(attribute.type, attribute.value)
        observable = self._create_observable(address_object, attribute.uuid, 'Address')
        self._handle_attribute(attribute, observable)

    def _parse_ip_port_attribute(self, attribute):
        ip, socket_address = self._create_socket_address_object(attribute)
        socket_address.ip_address = self._create_address_object(attribute.type.split('|')[0], ip)
        observable = self._create_observable(socket_address, attribute.uuid, 'SocketAddress')
        self._handle_attribute(attribute, observable)

    def _parse_mac_address(self, attribute):
        network_interface = NetworkInterface()
        network_interface.mac = attribute.value
        network_interface_list = NetworkInterfaceList()
        network_interface_list.append(network_interface)
        system_object = System()
        system_object.network_interface_list = network_interface_list
        observable = self._create_observable(system_object, attribute.uuid, 'System')
        self._handle_attribute(attribute, observable)

    def _parse_malware_sample(self, attribute):
        if attribute.data:
            filename, hash_value = attribute.value.split('|')
            artifact_object = self.create_artifact_object(attribute.data)
            artifact_object.hashes = HashList(self._parse_hash_value('md5', hash_value))
            observable = self._create_observable(artifact_object, attribute.uuid, 'Artifact')
            observable.title = filename
            self._handle_attribute(attribute, observable)
        else:
            self._parse_hash_composite_attribute(attribute)

    def _parse_mutex_attribute(self, attribute):
        mutex_object = self._create_mutex_object(attribute.value)
        observable = self._create_observable(mutex_object, attribute.value, 'Mutex')
        self._handle_attribute(attribute, observable)

    def _parse_named_pipe(self, attribute):
        pipe_object = Pipe()
        pipe_object.named = True
        pipe_object.name = attribute.value
        pipe_object.name.condition = "Equals"
        observable = self._create_observable(pipe_object, attribute.uuid, 'Pipe')
        self._handle_attribute(attribute, observable)

    def _parse_pattern_attribute(self, attribute):
        byte_run = ByteRun()
        byte_run.byte_run_data = attribute.value
        byte_run.byte_run_data.condition = "Equals"
        file_object = File()
        file_object.byte_runs = ByteRuns(byte_run)
        observable = self._create_observable(file_object, attribute.uuid, 'File')
        self._handle_attribute(attribute, observable)

    def _parse_port_attribute(self, attribute):
        port_object = self._create_port_object(attribute.value)
        observable = self._create_observable(port_object, attribute.uuid, 'Port')
        self._handle_attribute(attribute, observable)

    def _parse_regkey_attribute(self, attribute):
        registry_key = self._create_registry_key_object(attribute.value)
        observable = self._create_observable(registry_key, attribute.uuid, 'WinRegistryKey')
        self._handle_attribute(attribute, observable)

    def _parse_regkey_value_attribute(self, attribute):
        regkey, value = attribute.value.split('|')
        registry_key = self._create_registry_key_object(regkey)
        registry_value = RegistryValue()
        registry_value.data = value.strip()
        registry_value.data.condition = "Equals"
        registry_key.values = RegistryValues(registry_value)
        observable = self._create_observable(registry_key, attribute.uuid, 'WinRegistryKey')
        self._handle_attribute(attribute, observable)

    def _parse_url_attribute(self, attribute):
        uri_object = self._create_uri_object(attribute.value)
        observable = self._create_observable(uri_object, attribute.uuid, 'URI')
        self._handle_attribute(attribute, observable)

    def _parse_undefined_attribute(self, attribute):
        if hasattr(attribute, 'comment') and attribute.comment == 'Imported from STIX header descrption':
            self.header_comment.append(attribute.value)
        elif attribute.category == 'Payload type':
            ttp = self._create_ttp(attribute)
            malware = MalwareInstance()
            malware.add_name(attribute.value)
            ttp.behavior = Behavior()
            ttp.behavior.add_malware_instance(malware)
            if hasattr(attribute, 'comment') and attribute.comment:
                ttp.description = attribute.comment
            self._append_ttp(ttp, attribute.category, attribute.uuid)
        elif attribute.category == 'Attribution':
            threat_actor = ThreatActor(timestamp=attribute.timestamp)
            threat_actor.id_ = f"{self.namespace}:ThreatActor-{attribute.uuid}"
            threat_actor.title = f"{attribute.category}: {attribute.value} (MISP Attribute)"
            description = attribute.value
            if hasattr(attribute, 'comment') and attribute.comment:
                description = f"{descrption} ({attribute.comment})"
            threat_actor.description = description
            try:
                self.attributed_threat_actors.append(threat_actor)
            except AttributeError:
                self.attributed_threat_actors = AttributedThreatActors()
                self.attributed_threat_actors.append(threat_actor)
            rta = ThreatActor(idref=threat_actor.id_, timestamp=attribute.timestamp)
            related_threat_actor = RelatedThreatActor(rta, relationship=attribute.category)
            self.stix_package.add_threat_actor(related_threat_actor)
        else:
            self._add_journal_entry(f"Attribute ({attribute.category} - {attribute.type}): {attribute.value}")

    def _parse_user_agent_attribute(self, attribute):
        http_client_request = HTTPClientRequest()
        http_request_header = HTTPRequestHeader()
        header_fields = HTTPRequestHeaderFields()
        header_fields.user_agent = attribute.value
        header_fields.user_agent.condition = "Equals"
        http_request_header.parsed_header = header_fields
        http_client_request.http_request_header = http_request_header
        self._parse_http_session(attribute, http_client_request)

    def _parse_vulnerability_attribute(self, attribute):
        ttp = self._create_ttp(attribute)
        vulnerability = Vulnerability()
        vulnerability.cve_id = attribute.value
        exploit_target = ExploitTarget(timestamp=attribute.timestamp)
        exploit_target.id_ = f"{self.namespace}:ExploitTarget-{attribute.uuid}"
        if hasattr(attribute, 'comment') and attribute.comment != "Imported via the freetext import.":
            exploit_target.title = attribute.comment
        else:
            exploit_target.title = f"Vulnerability {attribute.value}"
        exploit_target.add_vulnerability(vulnerability)
        ttp.add_exploit_target(exploit_target)
        self._append_ttp(ttp, 'vulnerability', attribute.uuid)

    def _parse_windows_service_attribute(self, attribute):
        windows_service = WinService()
        feature = 'service_name' if attribute.type == 'windows-service-name' else 'display_name'
        setttr(windows_service, feature, attribute.value)
        observable = self._create_observable(windows_service, attribute.uuid, 'WinService')
        self._handle_attribute(attribute, observable)

    def _parse_x509_fingerprint_attribute(self, attribute):
        x509_signature = X509CertificateSignature()
        signature_algorithm = attribute.type.split('-')[-1].upper()
        for feature, value in zip(('signature', 'signature_algorithm'), (attribute.value, signature_algorithm)):
            setattr(x509_signature, feature, value)
            setattr(getattr(x509_signature, feature), 'condition', 'Equals')
        x509_certificate = X509Certificate()
        x509_certificate.certificate_signature = x509_signature
        observable = self._create_observable(x509_certificate, attribute.uuid, 'X509Certificate')
        self._handle_attribute(attribute, observable)

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

    def _append_ttp(self, ttp, category, uuid):
        rttp = TTP(idref=ttp.id_, timestamp=ttp.timestamp)
        related_ttp = RelatedTTP(rttp, relationship=category)
        self.incident.add_leveraged_ttps(related_ttp)
        self.ttps[uuid] = ttp

    @staticmethod
    def _create_address_object(attribute_type, attribute_value):
        address_object = Address()
        if '/' in attribute_value:
            address_object.category = "cidr"
            address_object.condition = "Contains"
        else:
            try:
                socket.inet_aton(attribute_value)
                address_object.category = "ipv4-addr"
            except socket.error:
                address_object.category = "ipv6-addr"
            address_object.condition = "Equals"
        if 'src' in attribute_type:
            address_object.is_source = True
            address_object.is_destination = False
        else:
            address_object.is_source = False
            address_object.is_destination = True
        address_object.address_value = attribute_value
        return address_object

    @staticmethod
    def _create_artifact_object(data):
        raw_artifact = RawArtifact(data)
        artifact = Artifact()
        artifact.raw_artifact = raw_artifact
        artifact.raw_artifact.condition = "Equals"
        return artifact

    @staticmethod
    def _create_autonomous_system_object(AS):
        autonomous_system = AutonomousSystem()
        feature = 'handle' is AS.stratswith('AS') else 'number'
        setattr(autonomous_system, feature, AS)
        setattr(getattr(autonomous_system, feature), 'condition', 'Equals')
        return autonomous_system

    @staticmethod
    def _create_domain_object(domain):
        domain_object = DomainName()
        domain_object.value = domain
        domain_object.value.condition = "Equals"
        return domain_object

    @staticmethod
    def _create_file_object(attribute_value, attribute_uuid):
        file_object = File()
        file_object.file_name = attribute_value
        file_object.file_name.condition = "Equals"
        return file_object

    @staticmethod
    def _create_hostname_object(hostname):
        hostname_object = Hostname()
        hostname_object.hostname_value = hostname
        hostname_object.hostname_value.condition = "Equals"
        return hostname_object

    def _create_indicator(self, attribute):
        indicator = Indicator(timestamp=attribute.timestamp)
        indicator.id_ = f"{self.namespace}:indicator-{attribute.uuid}"
        indicator.producer = self._set_producer()
        if attribute.tags:
            tags = tuple(tag.name for tag in attribute.tags)
            indicator.handling = self._set_handling(tags)
        indicator.title = f"{attribute.category}: {attribute.value} (MISP Attribute)"
        indicator.description = attribute.comment if attribute.comment else indicator.title
        indicator.confidence = Confidence(
            value=stix1_mapping.confidence_mapping[attribute.to_ids],
            description=stix1_mapping.confidence_description,
            timestamp=attribute.timestamp
        )
        return indicator

    @staticmethod
    def _create_information_source(identity):
        information_source = InformationSource(identity=identity)
        return information_source

    @staticmethod
    def _create_mutex_object(name):
        mutex_object = Mutex()
        mutex_object.name = name
        mutex_object.name.condition = "Equals"
        return mutex_object

    def _create_observable(self, stix_object, attribute_uuid, feature):
        stix_object.parent.id_ = f"{self.namespace}:{feature}Object-{attribute_uuid}"
        observable = Observable(stix_object)
        observable.id_ = f"{self.namespace}:{feature}-{attribute_uuid}"
        return observable

    @staticmethod
    def _create_port_object(port):
        port_object = Port()
        port_object.port_value = port
        port_object.port_value.condition = "Equals"
        return port_object

    @staticmethod
    def _create_registry_key_object(regkey):
        registry_key = WinRegistryKey()
        registry_key.key = regkey.strip()
        registry_key.key.condition = "Equals"
        return registry_key

    def _create_socket_address_object(self, attribute):
        value, port = attribute.value.split('|')
        socket_address = SocketAddress()
        socket_address.port = self._create_port_object(port)
        return value, socket_address

    def _create_ttp(self, attribute):
        ttp = TTP(timestamp=attribute.timestamp)
        ttp.id_ = f"{self.namespace}:TTP-{attribute.uuid}"
        if attribute.tags:
            tags = tuple(tag.name for tag in attribute.tags)
            ttp.handling = self._set_handling(tags)
        ttp.title = f"{attribute.category}: {attribute.value} (MISP Attribute)"
        return ttp

    def _create_ttp_from_galaxy(self, uuid, galaxy_name):
        ttp = TTP()
        ttp.id_ = f'{self.namespace}:TTP-{uuid}'
        ttp.title = f'{galaxy_name} (MISP Galaxy)'
        return ttp

    @staticmethod
    def _create_uri_object(url):
        uri_object = URI(value=url, type_='URL')
        uri_object.value.condition = "Equals"
        return uri_object

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

    @staticmethod
    def _set_indicator_type(attribute_type):
        if attribute_type in stix1_mapping.misp_indicator_type:
            return stix1_mapping.misp_indicator_type[attribute_type]
        return 'Malware Artifacts'

    def _set_producer(self):
        identity = Identity(name=self.orgc_name)
        information_source = InformationSource(identity=identity)
        return information_source

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
