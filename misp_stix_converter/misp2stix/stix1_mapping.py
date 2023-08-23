#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .. import Mapping
from .stix_mapping import MISPtoSTIXMapping
from typing import Union

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


class MISPtoSTIX1Mapping(MISPtoSTIXMapping):
    __confidence_mapping = {
        'misp:confidence-level="completely-confident"': {
            'score': 100,
            'stix_value': 'High'
        },
        'misp:confidence-level="usually-confident"': {
            'score': 75,
            'stix_value': 'High'
        },
        'misp:confidence-level="fairly-confident"': {
            'score': 50,
            'stix_value': 'Medium'
        },
        'misp:confidence-level="rarely-confident"': {
            'score': 25,
            'stix_value': 'Low'
        },
        'misp:confidence-level="unconfident"': {
            'score': 0,
            'stix_value': 'None'
        },
        'misp:confidence-level="confidence-cannot-be-evaluated"': {
            'score': 200,
            'stix_value': 'Unknown'
        }
    }
    __confidence_description = "Derived from MISP's IDS flag. If an attribute is marked for IDS exports, the confidence will be high, otherwise none"
    __confidence_value = 'High'
    __hash_type_attributes = {
        'single': (
            'md5',
            'sha1',
            'sha224',
            'sha256',
            'sha384',
            'sha512',
            'sha512/224',
            'sha512/256',
            'ssdeep',
            'imphash',
            'authentihash',
            'pehash',
            'tlsh',
            'cdhash',
            'vhash',
            'impfuzzy'
        ),
        'composite': (
            'filename|md5',
            'filename|sha1',
            'filename|sha224',
            'filename|sha256',
            'filename|sha384',
            'filename|sha512',
            'filename|sha512/224',
            'filename|sha512/256',
            'filename|authentihash',
            'filename|ssdeep',
            'filename|tlsh',
            'filename|imphash',
            'filename|pehash',
            'filename|vhash',
            'filename|impfuzzy'
        )
    }
    __misp_indicator_type = Mapping(
        **{
            'malware-sample': 'Malware Artifacts',
            'mutex': 'Host Characteristics',
            'named pipe': 'Host Characteristics',
            'url': 'URL Watchlist',
            **dict.fromkeys(
                __hash_type_attributes['single'], 'File Hash Watchlist'
            ),
            **dict.fromkeys(
                __hash_type_attributes['composite'], 'File Hash Watchlist'
            ),
            **dict.fromkeys(
                ('file', 'filename'), 'File Hash Watchlist'
            ),
            **dict.fromkeys(
                (
                    'email', 'email-attachment', 'email-src', 'email-dst',
                    'email-message-id', 'email-mime-boundary', 'email-subject',
                    'email-reply-to', 'email-x-mailer'
                ),
                'Malicious E-mail'
            ),
            **dict.fromkeys(
                ('AS', 'asn', 'ip-src', 'ip-dst', 'ip-src|port', 'ip-dst|port'),
                'IP Watchlist'
            ),
            **dict.fromkeys(
                (
                    'domain', 'domain|ip', 'domain-ip', 'hostname',
                    'hostname|port'
                ),
                'Domain Watchlist'
            ),
            **dict.fromkeys(('regkey', 'regkey|value'), 'Host Characteristics')
        }
    )
    __TLP_order = Mapping(
        red=4,
        amber=3,
        green=2,
        white=1
    )
    __misp_reghive = Mapping(
        HKEY_CLASSES_ROOT="HKEY_CLASSES_ROOT",
        HKCR="HKEY_CLASSES_ROOT",
        HKEY_CURRENT_CONFIG="HKEY_CURRENT_CONFIG",
        HKCC="HKEY_CURRENT_CONFIG",
        HKEY_CURRENT_USER="HKEY_CURRENT_USER",
        HKCU="HKEY_CURRENT_USER",
        HKEY_LOCAL_MACHINE="HKEY_LOCAL_MACHINE",
        HKLM="HKEY_LOCAL_MACHINE",
        HKEY_USERS="HKEY_USERS",
        HKU="HKEY_USERS",
        HKEY_CURRENT_USER_LOCAL_SETTINGS="HKEY_CURRENT_USER_LOCAL_SETTINGS",
        HKCULS="HKEY_CURRENT_USER_LOCAL_SETTINGS",
        HKEY_PERFORMANCE_DATA="HKEY_PERFORMANCE_DATA",
        HKPD="HKEY_PERFORMANCE_DATA",
        HKEY_PERFORMANCE_NLSTEXT="HKEY_PERFORMANCE_NLSTEXT",
        HKPN="HKEY_PERFORMANCE_NLSTEXT",
        HKEY_PERFORMANCE_TEXT="HKEY_PERFORMANCE_TEXT",
        HKPT="HKEY_PERFORMANCE_TEXT",
    )
    __status_mapping = Mapping(
        **{
            '0': 'New',
            '1': 'Open',
            '2': 'Closed'
        }
    )
    __threat_level_mapping = Mapping(
        **{
            '1': 'High',
            '2': 'Medium',
            '3': 'Low',
            '4': 'Undefined'
        }
    )

    # ATTRIBUTES MAPPING
    __attribute_types_mapping = Mapping(
        **{
            'AS': '_parse_autonomous_system_attribute',
            'attachment': '_parse_attachment',
            'campaign-name': '_parse_campaign_name_attribute',
            'domain': '_parse_domain_attribute',
            'domain|ip': '_parse_domain_ip_attribute',
            'email-attachment': '_parse_email_attachment',
            'email-body': '_parse_email_body_attribute',
            'email-header': '_parse_email_header_attribute',
            'filename': '_parse_file_attribute',
            'hostname': '_parse_hostname_attribute',
            'hostname|port': '_parse_hostname_port_attribute',
            'http-method': '_parse_http_method_attribute',
            'mac-address': '_parse_mac_address',
            'malware-sample': '_parse_malware_sample',
            'mutex': '_parse_mutex_attribute',
            'named pipe': '_parse_named_pipe',
            'pattern-in-file': '_parse_pattern_attribute',
            'port': '_parse_port_attribute',
            'regkey': '_parse_regkey_attribute',
            'regkey|value': '_parse_regkey_value_attribute',
            'size-in-bytes': '_parse_size_in_bytes_attribute',
            'snort': '_parse_snort_attribute',
            'target-email': '_parse_target_email',
            'target-external': '_parse_target_external',
            'target-location': '_parse_target_location',
            'target-machine': '_parse_target_machine',
            'target-org': '_parse_target_org',
            'target-user': '_parse_target_user',
            'user-agent': '_parse_user_agent_attribute',
            'vulnerability': '_parse_vulnerability_attribute',
            'weakness': '_parse_weakness_attribute',
            'whois-registrar': '_parse_whois_registrar_attribute',
            'yara': '_parse_yara_attribute',
            **dict.fromkeys(
                (
                    'email-src', 'email-dst', 'email-message-id',
                    'email-mime-boundary', 'email-subject', 'email-reply-to',
                    'email-x-mailer'
                ),
                '_parse_email_attribute'
            ),
            **dict.fromkeys(
                __hash_type_attributes['single'], '_parse_hash_attribute'
            ),
            **dict.fromkeys(
                __hash_type_attributes['composite'],
                '_parse_hash_composite_attribute'
            ),
            **dict.fromkeys(('ip-src', 'ip-dst'), '_parse_ip_attribute'),
            **dict.fromkeys(
                ('ip-src|port', 'ip-dst|port'), '_parse_ip_port_attribute'
            ),
            **dict.fromkeys(
                ('comment', 'other', 'text'), '_parse_undefined_attribute'
            ),
            **dict.fromkeys(('uri', 'url', 'link'), '_parse_url_attribute'),
            **dict.fromkeys(
                (
                    'whois-registrant-email', 'whois-registrant-name',
                    'whois-registrant-org', 'whois-registrant-phone'
                ),
                '_parse_whois_registrant_attribute'
            ),
            **dict.fromkeys(
                ('windows-service-displayname', 'windows-service-name'),
                '_parse_windows_service_attribute'
            ),
            **dict.fromkeys(
                (
                    'x509-fingerprint-md5', 'x509-fingerprint-sha1',
                    'x509-fingerprint-sha256'
                ),
                '_parse_x509_fingerprint_attribute'
            )
        }
    )
    __email_attribute_mapping = Mapping(
        **{
            'email-src': 'from_',
            'email-dst': 'to',
            'email-message-id': 'message_id',
            'email-mime-boundary': 'boundary',
            'email-reply-to': 'reply_to',
            'email-subject': 'subject',
            'email-x-mailer': 'x_mailer'
        }
    )
    __whois_registrant_mapping = Mapping(
        **{
            'registrant-name': 'name',
            'registrant-phone': 'phone_number',
            'registrant-email': 'email_address',
            'registrant-org': 'organization'
        }
    )

    # GALAXIES MAPPING
    __galaxy_types_mapping = Mapping(
        **{
            'branded-vulnerability': '_parse_vulnerability_{}_galaxy',
            **dict.fromkeys(
                MISPtoSTIXMapping.attack_pattern_types(),
                '_parse_attack_pattern_{}_galaxy'
            ),
            **dict.fromkeys(
                MISPtoSTIXMapping.course_of_action_types(),
                '_parse_course_of_action_{}_galaxy'
            ),
            **dict.fromkeys(
                MISPtoSTIXMapping.malware_types(), '_parse_malware_{}_galaxy'
            ),
            **dict.fromkeys(
                MISPtoSTIXMapping.threat_actor_types(),
                '_parse_threat_actor_galaxy'
            ),
            **dict.fromkeys(
                MISPtoSTIXMapping.tool_types(), '_parse_tool_{}_galaxy'
            )
        }
    )
    __ttp_names = (
        'branded-vulnerability',
        *MISPtoSTIXMapping.attack_pattern_types(),
        *MISPtoSTIXMapping.malware_types(),
        *MISPtoSTIXMapping.tool_types()
    )

    # MISP OBJECTS MAPPING
    __non_indicator_names = Mapping(
        **{
            'attack-pattern': '_parse_attack_pattern_object',
            'course-of-action': '_parse_course_of_action_object',
            'vulnerability': '_parse_vulnerability_object',
            'weakness': '_parse_weakness_object'
        }
    )
    __objects_mapping = Mapping(
        **{
            "asn": '_parse_asn_object',
            "credential": '_parse_credential_object',
            "domain-ip": '_parse_domain_ip_object',
            "domain|ip": '_parse_domain_ip_object',
            "email": '_parse_email_object',
            "file": '_parse_file_object',
            "ip-port": '_parse_ip_port_object',
            "ip|port": '_parse_ip_port_object',
            "mutex": "_parse_mutex_object",
            "network-connection": '_parse_network_connection_object',
            "network-socket": '_parse_network_socket_object',
            "process": '_parse_process_object',
            "registry-key": '_parse_registry_key_object',
            "url": '_parse_url_object',
            "user-account": '_parse_user_account_object',
            "whois": '_parse_whois_object',
            "x509": '_parse_x509_object'
        }
    )
    __as_single_fields = (
        'asn',
        'description'
    )
    __attack_pattern_object_mapping = Mapping(
        id='capec_id',
        name='title',
        summary='description'
    )
    __course_of_action_object_mapping = Mapping(
        name='title',
        type='type_',
        description='description',
        objective='objective',
        stage='stage',
        cost='cost',
        impact='impact',
        efficacy='efficacy'
    )
    __credential_object_mapping = Mapping(
        username='username',
        text='description'
    )
    __email_object_mapping = Mapping(
        **{
            'from': 'from_',
            'reply-to': 'reply_to',
            'subject': 'subject',
            'x-mailer': 'x_mailer',
            'mime-boundary': 'boundary',
            'user-agent': 'user_agent',
            'message-id': 'message_id'
        }
    )
    __email_uuid_fields = (
        'attachment',
    )
    __file_object_mapping = Mapping(
        **{
            'access-time': 'accessed_time',
            'creation-time': 'created_time',
            'entropy': 'peak_entropy',
            'fullpath': 'full_path',
            'modification-time': 'modified_time',
            'path': 'file_path',
            'size-in-bytes': 'size_in_bytes'
        }
    )
    __network_socket_mapping = Mapping(
        **{
            'address-family': 'address_family',
            'domain-family': 'domain',
            'protocol': 'protocol',
            'socket-type': 'type_'
        }
    )
    __network_socket_single_fields = (
        'address-family',
        'domain-family',
        'dst-port',
        'hostname-dst',
        'hostname-src',
        'ip-dst',
        'ip-src',
        'protocol',
        'socket-type',
        'src-port'
    )
    __pe_resource_mapping = Mapping(
        **{
            'company-name': 'companyname',
            'file-description': 'filedescription',
            'file-version': 'fileversion',
            'internal-filename': 'internalname',
            'lang-id': 'langid',
            'legal-copyright': 'legalcopyright',
            'original-filename': 'originalfilename',
            'product-name': 'productname',
            'product-version': 'productversion'
        }
    )
    __pe_single_fields = (
        'company-name',
        'entrypoint-address',
        'file-description',
        'file-version',
        'impfuzzy',
        'imphash',
        'internal-filename',
        'lang-id',
        'legal-copyright',
        'number-sections',
        'original-filename',
        'pehash',
        'product-name',
        'product-version',
        'type'
    )
    __process_object_mapping = Mapping(
        **{
            'creation-time': 'creation_time',
            'start-time': 'start_time',
            'name': 'name',
            'pid': 'pid',
            'parent-pid': 'parent_pid'
        }
    )
    __process_single_fields = (
        'command-line',
        'creation-time',
        'hidden',
        'image',
        'name',
        'parent-pid',
        'pid',
        'start-time'
    )
    __regkey_object_mapping = Mapping(
        **{
            'name': 'name',
            'data': 'data',
            'data-type': 'datatype'
        }
    )
    __user_account_object_mapping = Mapping(
        **{
            'username': 'username',
            'display-name': 'full_name',
            'disabled': 'disabled',
            'created': 'creation_date',
            'last_login': 'last_login',
            'home_dir': 'home_directory',
            'shell': 'script_path'
        }
    )
    __user_account_single_fields = (
        'account-type',
        'created',
        'disabled',
        'display-name',
        'home_dir',
        'last_login',
        'password',
        'shell',
        'text',
        'username'
    )
    __vulnerability_object_mapping = Mapping(
        id='cve_id',
        created='discovered_datetime',
        summary='description',
        published='published_datetime'
    )
    __vulnerability_single_fields = (
        'created',
        'cvss-score',
        'published',
        'summary'
    )
    __weakness_object_mapping = Mapping(
        id='cwe_id',
        description='description'
    )
    __whois_object_mapping = Mapping(
        **{
            'creation-date': 'creation_date',
            'modification-date': 'updated_date',
            'expiration-date': 'expiration_date'
        }
    )
    __whois_single_fields = (
        'comment',
        'creation-date',
        'expiration-date',
        'modification-date',
        'registrant-email',
        'registrant-name',
        'registrant-org',
        'registrant-phone',
        'registrar',
        'text'
    )
    __x509_creation_mapping = Mapping(
        **{
            'version': 'certificate',
            'serial-number': 'certificate',
            'issuer': 'certificate',
            'subject': 'certificate',
            'signature_algorithm': 'certificate',
            'validity-not-before': 'validity',
            'validity-not-after': 'validity',
            'pubkey-info-algorithm': 'pubkey',
            'pubkey-info-exponent': 'pubkey',
            'pubkey-info-modulus': 'pubkey',
            'raw-base64': 'raw_certificate',
            'pem': 'raw_certificate',
            'x509-fingerprint-md5': 'signature',
            'x509-fingerprint-sha1': 'signature',
            'x509-fingerprint-sha256': 'signature'
        }
    )
    __x509_object_mapping = Mapping(
        **{
            'version': 'version',
            'serial-number': 'serial_number',
            'issuer': 'issuer',
            'signature_algorithm': 'signature_algorithm',
            'subject': 'subject'
        }
    )

    @classmethod
    def as_single_fields(cls) -> tuple:
        return cls.__as_single_fields

    @classmethod
    def attack_pattern_object_mapping(cls) -> dict:
        return cls.__attack_pattern_object_mapping

    @classmethod
    def attribute_types_mapping(cls, field: str) -> Union[str, None]:
        return cls.__attribute_types_mapping.get(field)

    @classmethod
    def confidence_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__confidence_mapping.get(field)

    @classmethod
    def confidence_description(cls) -> str:
        return cls.__confidence_description

    @classmethod
    def confidence_value(cls) -> str:
        return cls.__confidence_value

    @classmethod
    def course_of_action_names(cls) -> tuple:
        return cls.__course_of_action_names

    @classmethod
    def course_of_action_object_mapping(cls) -> dict:
        return cls.__course_of_action_object_mapping

    @classmethod
    def credential_object_mapping(cls) -> dict:
        return cls.__credential_object_mapping

    @classmethod
    def email_attribute_mapping(cls, field: str) -> Union[str, None]:
        return cls.__email_attribute_mapping.get(field)

    @classmethod
    def email_object_mapping(cls) -> dict:
        return cls.__email_object_mapping

    @classmethod
    def email_uuid_fields(cls) -> tuple:
        return cls.__email_uuid_fields

    @classmethod
    def file_object_mapping(cls) -> dict:
        return cls.__file_object_mapping

    @classmethod
    def galaxy_types_mapping(cls, field: str) -> Union[str, None]:
        return cls.__galaxy_types_mapping.get(field)

    @classmethod
    def hash_type_attributes(cls, field: str) -> Union[tuple, None]:
        return cls.__hash_type_attributes.get(field)

    @classmethod
    def misp_indicator_type(cls, field: str) -> Union[str, None]:
        return cls.__misp_indicator_type.get(field)

    @classmethod
    def misp_reghive(cls, field: str) -> Union[str, None]:
        return cls.__misp_reghive.get(field)

    @classmethod
    def network_socket_mapping(cls) -> dict:
        return cls.__network_socket_mapping

    @classmethod
    def network_socket_single_fields(cls) -> tuple:
        return cls.__network_socket_single_fields

    @classmethod
    def non_indicator_names(cls, field: str) -> Union[str, None]:
        return cls.__non_indicator_names.get(field)

    @classmethod
    def objects_mapping(cls, field: str) -> Union[str, None]:
        return cls.__objects_mapping.get(field)

    @classmethod
    def pe_resource_mapping(cls) -> dict:
        return cls.__pe_resource_mapping

    @classmethod
    def pe_single_fields(cls) -> tuple:
        return cls.__pe_single_fields

    @classmethod
    def process_object_mapping(cls) -> dict:
        return cls.__process_object_mapping

    @classmethod
    def process_single_fields(cls) -> tuple:
        return cls.__process_single_fields

    @classmethod
    def regkey_object_mapping(cls) -> dict:
        return cls.__regkey_object_mapping

    @classmethod
    def status_mapping(cls, field: str) -> Union[str, None]:
        return cls.__status_mapping.get(field)

    @classmethod
    def threat_level_mapping(cls, field: str) -> Union[str, None]:
        return cls.__threat_level_mapping.get(field)

    @classmethod
    def TLP_order(cls, field: str) -> Union[int, None]:
        return cls.__TLP_order.get(field)

    @classmethod
    def ttp_names(cls) -> tuple:
        return cls.__ttp_names

    @classmethod
    def user_account_object_mapping(cls) -> dict:
        return cls.__user_account_object_mapping

    @classmethod
    def user_account_single_fields(cls) -> tuple:
        return cls.__user_account_single_fields

    @classmethod
    def vulnerability_object_mapping(cls) -> dict:
        return cls.__vulnerability_object_mapping

    @classmethod
    def vulnerability_single_fields(cls) -> tuple:
        return cls.__vulnerability_single_fields

    @classmethod
    def weakness_object_mapping(cls) -> dict:
        return cls.__weakness_object_mapping

    @classmethod
    def whois_object_mapping(cls) -> dict:
        return cls.__whois_object_mapping

    @classmethod
    def whois_registrant_mapping(cls, field: str) -> Union[str, None]:
        return cls.__whois_registrant_mapping.get(field)

    @classmethod
    def whois_registrant_object_mapping(cls) -> dict:
        return cls.__whois_registrant_mapping

    @classmethod
    def whois_single_fields(cls) -> tuple:
        return cls.__whois_single_fields

    @classmethod
    def x509_creation_mapping(cls, field: str) -> Union[str, None]:
        return cls.__x509_creation_mapping.get(field)

    @classmethod
    def x509_object_mapping(cls) -> dict:
        return cls.__x509_object_mapping
