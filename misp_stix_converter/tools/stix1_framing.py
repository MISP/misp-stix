#!/usr/bin/env python3

import json
import re
from ..misp_stix_mapping import Mapping
from datetime import datetime
from mixbox import idgen
from mixbox.namespaces import Namespace
from stix.core import STIXHeader, STIXPackage
from typing import Optional
from uuid import UUID, uuid4

# STIX header
NS_DICT = Mapping(
    **{
        "http://cybox.mitre.org/common-2": 'cyboxCommon',
        "http://cybox.mitre.org/cybox-2": 'cybox',
        "http://cybox.mitre.org/default_vocabularies-2": 'cyboxVocabs',
        "http://cybox.mitre.org/objects#AccountObject-2": 'AccountObj',
        "http://cybox.mitre.org/objects#ArtifactObject-2": 'ArtifactObj',
        "http://cybox.mitre.org/objects#ASObject-1": 'ASObj',
        "http://cybox.mitre.org/objects#AddressObject-2": 'AddressObj',
        "http://cybox.mitre.org/objects#PortObject-2": 'PortObj',
        "http://cybox.mitre.org/objects#DomainNameObject-1": 'DomainNameObj',
        "http://cybox.mitre.org/objects#EmailMessageObject-2": 'EmailMessageObj',
        "http://cybox.mitre.org/objects#FileObject-2": 'FileObj',
        "http://cybox.mitre.org/objects#HTTPSessionObject-2": 'HTTPSessionObj',
        "http://cybox.mitre.org/objects#HostnameObject-1": 'HostnameObj',
        "http://cybox.mitre.org/objects#MutexObject-2": 'MutexObj',
        "http://cybox.mitre.org/objects#PipeObject-2": 'PipeObj',
        "http://cybox.mitre.org/objects#URIObject-2": 'URIObj',
        "http://cybox.mitre.org/objects#WinRegistryKeyObject-2": 'WinRegistryKeyObj',
        'http://cybox.mitre.org/objects#WinServiceObject-2': 'WinServiceObj',
        "http://cybox.mitre.org/objects#NetworkConnectionObject-2": 'NetworkConnectionObj',
        "http://cybox.mitre.org/objects#NetworkSocketObject-2": 'NetworkSocketObj',
        "http://cybox.mitre.org/objects#SocketAddressObject-1": 'SocketAddressObj',
        "http://cybox.mitre.org/objects#SystemObject-2": 'SystemObj',
        "http://cybox.mitre.org/objects#ProcessObject-2": 'ProcessObj',
        "http://cybox.mitre.org/objects#X509CertificateObject-2": 'X509CertificateObj',
        "http://cybox.mitre.org/objects#WhoisObject-2": 'WhoisObj',
        "http://cybox.mitre.org/objects#WinExecutableFileObject-2": 'WinExecutableFileObj',
        "http://cybox.mitre.org/objects#UnixUserAccountObject-2": "UnixUserAccountObj",
        "http://cybox.mitre.org/objects#UserAccountObject-2": "UserAccountObj",
        "http://cybox.mitre.org/objects#WinUserAccountObject-2": "WinUserAccountObj",
        "http://cybox.mitre.org/objects#CustomObject-1": "CustomObj",
        "http://data-marking.mitre.org/Marking-1": 'marking',
        "http://data-marking.mitre.org/extensions/MarkingStructure#Simple-1": 'simpleMarking',
        "http://data-marking.mitre.org/extensions/MarkingStructure#TLP-1": 'tlpMarking',
        "http://stix.mitre.org/ExploitTarget-1": 'et',
        "http://stix.mitre.org/Incident-1": 'incident',
        "http://stix.mitre.org/Indicator-2": 'indicator',
        "http://stix.mitre.org/Campaign-1": 'campaign',
        "http://stix.mitre.org/CourseOfAction-1": 'coa',
        "http://stix.mitre.org/TTP-1": 'ttp',
        "http://stix.mitre.org/ThreatActor-1": 'ta',
        "http://stix.mitre.org/common-1": 'stixCommon',
        "http://stix.mitre.org/default_vocabularies-1": 'stixVocabs',
        "http://stix.mitre.org/extensions/Identity#CIQIdentity3.0-1": 'ciqIdentity',
        "http://stix.mitre.org/extensions/TestMechanism#Snort-1": 'snortTM',
        "http://stix.mitre.org/extensions/TestMechanism#YARA-1": 'yaraTM',
        "http://stix.mitre.org/stix-1": 'stix',
        "http://www.w3.org/2001/XMLSchema-instance": 'xsi',
        "urn:oasis:names:tc:ciq:xal:3": 'xal',
        "urn:oasis:names:tc:ciq:xnl:3": 'xnl',
        "urn:oasis:names:tc:ciq:xpil:3": 'xpil'
    }
)
SCHEMALOC_DICT = Mapping(
    **{
        'http://cybox.mitre.org/common-2': 'http://cybox.mitre.org/XMLSchema/common/2.1/cybox_common.xsd',
        'http://cybox.mitre.org/cybox-2': 'http://cybox.mitre.org/XMLSchema/core/2.1/cybox_core.xsd',
        'http://cybox.mitre.org/default_vocabularies-2': 'http://cybox.mitre.org/XMLSchema/default_vocabularies/2.1/cybox_default_vocabularies.xsd',
        'http://cybox.mitre.org/objects#AccountObject-2': ' http://cybox.mitre.org/XMLSchema/objects/Account/2.1/Account_Object.xsd',
        'http://cybox.mitre.org/objects#ArtifactObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Artifact/2.1/Artifact_Object.xsd',
        'http://cybox.mitre.org/objects#ASObject-1': 'http://cybox.mitre.org/XMLSchema/objects/AS/1.0/AS_Object.xsd',
        'http://cybox.mitre.org/objects#AddressObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Address/2.1/Address_Object.xsd',
        'http://cybox.mitre.org/objects#PortObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Port/2.1/Port_Object.xsd',
        'http://cybox.mitre.org/objects#DomainNameObject-1': 'http://cybox.mitre.org/XMLSchema/objects/Domain_Name/1.0/Domain_Name_Object.xsd',
        'http://cybox.mitre.org/objects#EmailMessageObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Email_Message/2.1/Email_Message_Object.xsd',
        'http://cybox.mitre.org/objects#FileObject-2': 'http://cybox.mitre.org/XMLSchema/objects/File/2.1/File_Object.xsd',
        'http://cybox.mitre.org/objects#HTTPSessionObject-2': 'http://cybox.mitre.org/XMLSchema/objects/HTTP_Session/2.1/HTTP_Session_Object.xsd',
        'http://cybox.mitre.org/objects#HostnameObject-1': 'http://cybox.mitre.org/XMLSchema/objects/Hostname/1.0/Hostname_Object.xsd',
        'http://cybox.mitre.org/objects#MutexObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Mutex/2.1/Mutex_Object.xsd',
        'http://cybox.mitre.org/objects#PipeObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Pipe/2.1/Pipe_Object.xsd',
        'http://cybox.mitre.org/objects#URIObject-2': 'http://cybox.mitre.org/XMLSchema/objects/URI/2.1/URI_Object.xsd',
        'http://cybox.mitre.org/objects#WinServiceObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Service/2.1/Win_Service_Object.xsd',
        'http://cybox.mitre.org/objects#WinRegistryKeyObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Registry_Key/2.1/Win_Registry_Key_Object.xsd',
        'http://cybox.mitre.org/objects#NetworkConnectionObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Network_Connection/2.0.1/Network_Connection_Object.xsd',
        'http://cybox.mitre.org/objects#NetworkSocketObject-2': 'https://cybox.mitre.org/XMLSchema/objects/Network_Socket/2.1/Network_Socket_Object.xsd',
        'http://cybox.mitre.org/objects#SystemObject-2': 'http://cybox.mitre.org/XMLSchema/objects/System/2.1/System_Object.xsd',
        'http://cybox.mitre.org/objects#SocketAddressObject-1': 'http://cybox.mitre.org/XMLSchema/objects/Socket_Address/1.1/Socket_Address_Object.xsd',
        'http://cybox.mitre.org/objects#ProcessObject-2': 'https://cybox.mitre.org/XMLSchema/objects/Process/2.1/Process_Object.xsd',
        'http://cybox.mitre.org/objects#X509CertificateObject-2': 'http://cybox.mitre.org/XMLSchema/objects/X509_Certificate/2.1/X509_Certificate_Object.xsd',
        'http://cybox.mitre.org/objects#WhoisObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Whois/2.1/Whois_Object.xsd',
        'http://cybox.mitre.org/objects#WinExecutableFileObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Executable_File/2.1/Win_Executable_File_Object.xsd',
        'http://cybox.mitre.org/objects#UnixUserAccountObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Unix_User_Account/2.1/Unix_User_Account_Object.xsd',
        'http://cybox.mitre.org/objects#UserAccountObject-2': 'http://cybox.mitre.org/XMLSchema/objects/User_Account/2.1/User_Account_Object.xsd',
        'http://cybox.mitre.org/objects#WinUserAccountObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_User_Account/2.1/Win_User_Account_Object.xsd',
        'http://cybox.mitre.org/objects#CustomObject-1': 'http://cybox.mitre.org/XMLSchema/objects/Custom/1.1/Custom_Object.xsd',
        'http://data-marking.mitre.org/Marking-1': 'http://stix.mitre.org/XMLSchema/data_marking/1.1.1/data_marking.xsd',
        'http://data-marking.mitre.org/extensions/MarkingStructure#Simple-1': 'http://stix.mitre.org/XMLSchema/extensions/marking/simple/1.1.1/simple_marking.xsd',
        'http://data-marking.mitre.org/extensions/MarkingStructure#TLP-1': 'http://stix.mitre.org/XMLSchema/extensions/marking/tlp/1.1.1/tlp_marking.xsd',
        'http://stix.mitre.org/ExploitTarget-1': 'http://stix.mitre.org/XMLSchema/exploit_target/1.1.1/exploit_target.xsd',
        'http://stix.mitre.org/Incident-1': 'http://stix.mitre.org/XMLSchema/incident/1.1.1/incident.xsd',
        'http://stix.mitre.org/Indicator-2': 'http://stix.mitre.org/XMLSchema/indicator/2.1.1/indicator.xsd',
        'http://stix.mitre.org/Campaign-1': 'http://stix.mitre.org/XMLSchema/campaign/1.1.1/campaign.xsd',
        'http://stix.mitre.org/CourseOfAction-1': 'http://stix.mitre.org/XMLSchema/course_of_action/1.1.1/course_of_action.xsd',
        'http://stix.mitre.org/TTP-1': 'http://stix.mitre.org/XMLSchema/ttp/1.1.1/ttp.xsd',
        'http://stix.mitre.org/ThreatActor-1': 'http://stix.mitre.org/XMLSchema/threat_actor/1.1.1/threat_actor.xsd',
        'http://stix.mitre.org/common-1': 'http://stix.mitre.org/XMLSchema/common/1.1.1/stix_common.xsd',
        'http://stix.mitre.org/default_vocabularies-1': 'http://stix.mitre.org/XMLSchema/default_vocabularies/1.1.1/stix_default_vocabularies.xsd',
        'http://stix.mitre.org/extensions/Identity#CIQIdentity3.0-1': 'http://stix.mitre.org/XMLSchema/extensions/identity/ciq_3.0/1.1.1/ciq_3.0_identity.xsd',
        'http://stix.mitre.org/extensions/TestMechanism#Snort-1': 'http://stix.mitre.org/XMLSchema/extensions/test_mechanism/snort/1.1.1/snort_test_mechanism.xsd',
        'http://stix.mitre.org/extensions/TestMechanism#YARA-1': 'http://stix.mitre.org/XMLSchema/extensions/test_mechanism/yara/1.2/yara_test_mechanism.xsd',
        'http://stix.mitre.org/stix-1': 'http://stix.mitre.org/XMLSchema/core/1.1.1/stix_core.xsd',
        'urn:oasis:names:tc:ciq:xal:3': 'http://stix.mitre.org/XMLSchema/external/oasis_ciq_3.0/xAL.xsd',
        'urn:oasis:names:tc:ciq:xnl:3': 'http://stix.mitre.org/XMLSchema/external/oasis_ciq_3.0/xNL.xsd',
    }
)


def stix1_attributes_framing(namespace: str, orgname: str, return_format: str,
                             version: str) -> tuple:
    stix_package = _create_stix_package(orgname, version)
    return _stix1_attributes_framing(
        namespace, orgname, return_format, stix_package
    )


def stix1_framing(namespace: str, orgname: str, return_format: str,
                  version: str) -> tuple:
    stix_package = _create_stix_package(orgname, version)
    return _stix1_framing(namespace, orgname, return_format, stix_package)


def stix_xml_separator():
    header = "stix:Related_Package"
    return f"        </{header}>\n        <{header}>\n"


def _create_stix_package(
        orgname: str, version: str,  header: Optional[bool] = True,
        uuid: Optional[UUID | str] = None) -> STIXPackage:
    parsed_orgname = re.sub('[\W]+', '', orgname.replace(' ', '_'))
    if uuid is None:
        uuid = uuid4()
    stix_package = STIXPackage(
        id_=f'{parsed_orgname}:STIXPackage-{uuid}',
        timestamp=datetime.now()
    )
    stix_package.version = version
    if header:
        stix_header = STIXHeader()
        stix_header.title = f"Export from {orgname}'s MISP"
        stix_header.package_intents = 'Threat Report'
        stix_package.stix_header = stix_header
    return stix_package


def _handle_namespaces(namespace: str, orgname: str) -> tuple:
    parsed_orgname = re.sub('[\W]+', '', orgname.replace(' ', '_'))
    namespaces = {namespace: parsed_orgname}
    namespaces.update(NS_DICT)
    try:
        idgen.set_id_namespace(Namespace(namespace, parsed_orgname))
    except TypeError:
        idgen.set_id_namespace(Namespace(namespace, parsed_orgname, 'MISP'))
    return namespaces


def _stix1_attributes_framing(namespace: str, orgname: str, return_format: str,
                              stix_package: STIXPackage) -> tuple:
    if return_format == 'xml':
        namespaces = _handle_namespaces(namespace, orgname)
        return _stix_xml_attributes_framing(stix_package, namespaces)
    return _stix_json_attributes_framing(stix_package)


def _stix1_framing(namespace: str, orgname: str, return_format: str,
                   stix_package: STIXPackage) -> tuple:
    if return_format == 'xml':
        namespaces = _handle_namespaces(namespace, orgname)
        return _stix_xml_framing(stix_package, namespaces)
    return _stix_json_framing(stix_package)


def _stix_json_attributes_framing(stix_package: STIXPackage) -> tuple:
    header = {key: value for key, value in stix_package.to_dict().items() if key != 'observables'}
    return f'{json.dumps(header)[:-1]}, ', ', ', '}'


def _stix_json_framing(stix_package: STIXPackage) -> tuple:
    header = stix_package.to_json()[:-1]
    bracket = '{'
    header = f'{header}, "related_packages": {bracket}"related_packages": ['
    return header, ', ', ']}}'


def _stix_xml_attributes_framing(stix_package: STIXPackage, namespaces: dict) -> tuple:
    s_stix = "</stix:STIX_Package>\n"
    header = stix_package.to_xml(auto_namespace=False, ns_dict=namespaces, schemaloc_dict=SCHEMALOC_DICT)
    return f"{header.decode().replace(s_stix, '')}", '', s_stix


def _stix_xml_framing(stix_package: STIXPackage, namespaces: dict) -> tuple:
    s_stix = "</stix:STIX_Package>\n"
    s_related = "stix:Related_Package"
    header = stix_package.to_xml(auto_namespace=False, ns_dict=namespaces, schemaloc_dict=SCHEMALOC_DICT)
    header = header.decode()
    if header.endswith('/>\n'):
        header = f'{header[:-3]}>\n'
    header = f"{header.replace(s_stix, '')}    <{s_related}s>\n        <{s_related}>\n"
    footer = f"        </{s_related}>\n    </{s_related}s>\n{s_stix}"
    separator = f"        </{s_related}>\n        <{s_related}>\n"
    return header, separator, footer