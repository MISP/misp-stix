#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .. import Mapping

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


class Stix1Mapping:
    def __init__(self):
        self.__confidence_mapping = {
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
        self.__confidence_description = "Derived from MISP's IDS flag. If an attribute is marked for IDS exports, the confidence will be high, otherwise none"
        self.__confidence_value = "High"
        _hash_type_attributes = {
            "single": (
                "md5",
                "sha1",
                "sha224",
                "sha256",
                "sha384",
                "sha512",
                "sha512/224",
                "sha512/256",
                "ssdeep",
                "imphash",
                "authentihash",
                "pehash",
                "tlsh",
                "cdhash",
                "vhash",
                "impfuzzy"
            ),
            "composite": (
                "filename|md5",
                "filename|sha1",
                "filename|sha224",
                "filename|sha256",
                "filename|sha384",
                "filename|sha512",
                "filename|sha512/224",
                "filename|sha512/256",
                "filename|authentihash",
                "filename|ssdeep",
                "filename|tlsh",
                "filename|imphash",
                "filename|pehash",
                "filename|vhash",
                "filename|impfuzzy"
            )
        }
        _misp_indicator_type = {
            "malware-sample": "Malware Artifacts",
            "mutex": "Host Characteristics",
            "named pipe": "Host Characteristics",
            "url": "URL Watchlist"
        }
        _misp_indicator_type.update(
            dict.fromkeys(
                list(_hash_type_attributes["single"]),
                "File Hash Watchlist"
            )
        )
        _misp_indicator_type.update(
            dict.fromkeys(
                list(_hash_type_attributes["composite"]),
                "File Hash Watchlist"
            )
        )
        self.__hash_type_attributes = Mapping(**_hash_type_attributes)
        _misp_indicator_type.update(
            dict.fromkeys(
                [
                    "file",
                    "filename"
                ],
                "File Hash Watchlist"
            )
        )
        _misp_indicator_type.update(
            dict.fromkeys(
                [
                    "email",
                    "email-attachment",
                    "email-src",
                    "email-dst",
                    "email-message-id",
                    "email-mime-boundary",
                    "email-subject",
                    "email-reply-to",
                    "email-x-mailer"
                ],
                "Malicious E-mail"
            )
        )
        _misp_indicator_type.update(
            dict.fromkeys(
                [
                    "AS",
                    "asn",
                    "ip-src",
                    "ip-dst",
                    "ip-src|port",
                    "ip-dst|port"
                ],
                "IP Watchlist"
            )
        )
        _misp_indicator_type.update(
            dict.fromkeys(
                [
                    "domain",
                    "domain|ip",
                    "domain-ip",
                    "hostname",
                    "hostname|port"
                ],
                "Domain Watchlist"
            )
        )
        _misp_indicator_type.update(
            dict.fromkeys(
                [
                    "regkey",
                    "regkey|value"
                ],
                "Host Characteristics"
            )
        )
        self.__misp_indicator_type = Mapping(**_misp_indicator_type)
        self.__TLP_order = Mapping(
            **{
                'red': 4,
                'amber': 3,
                'green': 2,
                'white': 1
            }
        )
        # ATTRIBUTES MAPPING
        _attribute_types_mapping = {
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
            'yara': '_parse_yara_attribute'
        }
        _attribute_types_mapping.update(
            dict.fromkeys(
                list(self.__hash_type_attributes["single"]),
                '_parse_hash_attribute'
            )
        )
        _attribute_types_mapping.update(
            dict.fromkeys(
                list(self.__hash_type_attributes["composite"]),
                '_parse_hash_composite_attribute'
            )
        )
        _attribute_types_mapping.update(
            dict.fromkeys(
                [
                    "ip-src",
                    "ip-dst"
                ],
                '_parse_ip_attribute'
            )
        )
        _attribute_types_mapping.update(
            dict.fromkeys(
                [
                    "ip-src|port",
                    "ip-dst|port"
                ],
                '_parse_ip_port_attribute'
            )
        )
        _attribute_types_mapping.update(
            dict.fromkeys(
                [
                    "windows-service-displayname",
                    "windows-service-name"
                ],
                '_parse_windows_service_attribute'
            )
        )
        _attribute_types_mapping.update(
            dict.fromkeys(
                [
                    "uri",
                    "url",
                    "link"
                ],
                '_parse_url_attribute'
            )
        )
        _attribute_types_mapping.update(
            dict.fromkeys(
                [
                    "email-src",
                    "email-dst",
                    "email-message-id",
                    "email-mime-boundary",
                    "email-subject",
                    "email-reply-to",
                    'email-x-mailer'
                ],
                '_parse_email_attribute'
            )
        )
        _attribute_types_mapping.update(
            dict.fromkeys(
                [
                    'x509-fingerprint-md5',
                    'x509-fingerprint-sha1',
                    'x509-fingerprint-sha256'
                ],
                '_parse_x509_fingerprint_attribute'
            )
        )
        _attribute_types_mapping.update(
            dict.fromkeys(
                [
                    'comment',
                    'other',
                    'text'
                ],
                '_parse_undefined_attribute'
            )
        )
        _attribute_types_mapping.update(
            dict.fromkeys(
                [
                    'whois-registrant-email',
                    'whois-registrant-name',
                    'whois-registrant-org',
                    'whois-registrant-phone'
                ],
                '_parse_whois_registrant_attribute'
            )
        )
        self.__attribute_types_mapping = Mapping(**_attribute_types_mapping)
        self.__email_attribute_mapping = Mapping(
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
        self.__whois_registrant_mapping = Mapping(
            **{
                'registrant-name': 'name',
                'registrant-phone': 'phone_number',
                'registrant-email': 'email_address',
                'registrant-org': 'organization'
            }
        )
        # GALAXIES MAPPING
        _attack_pattern_names = (
            'mitre-attack-pattern',
            'mitre-enterprise-attack-attack-pattern',
            'mitre-mobile-attack-attack-pattern',
            'mitre-pre-attack-attack-pattern'
        )
        _malware_names = (
            'android',
            'banker',
            'stealer',
            'backdoor',
            'ransomware',
            'mitre-malware',
            'malpedia',
            'mitre-enterprise-attack-malware',
            'mitre-mobile-attack-malware'
        )
        _tool_names = (
            'botnet',
            'rat',
            'exploit-kit',
            'tds',
            'tool',
            'mitre-tool',
            'mitre-enterprise-attack-tool',
            'mitre-mobile-attack-tool'
        )
        self.__course_of_action_names = (
            'mitre-course-of-action',
            'mitre-enterprise-attack-course-of-action',
            'mitre-mobile-attack-course-of-action'
        )
        _galaxy_types_mapping = {'branded-vulnerability': '_parse_vulnerability_{}_galaxy'}
        _galaxy_types_mapping.update(
            dict.fromkeys(
                _attack_pattern_names,
                '_parse_attack_pattern_{}_galaxy'
            )
        )
        _galaxy_types_mapping.update(
            dict.fromkeys(
                self.__course_of_action_names,
                '_parse_course_of_action_{}_galaxy'
            )
        )
        _galaxy_types_mapping.update(
            dict.fromkeys(
                _malware_names,
                '_parse_malware_{}_galaxy'
            )
        )
        _galaxy_types_mapping.update(
            dict.fromkeys(
                (
                    'threat-actor',
                    'microsoft-activity-group'
                ),
                '_parse_threat_actor_galaxy'
            )
        )
        _galaxy_types_mapping.update(
            dict.fromkeys(
                _tool_names,
                '_parse_tool_{}_galaxy'
            )
        )
        self.__galaxy_types_mapping = Mapping(**_galaxy_types_mapping)
        self.__ttp_names = (
            'branded-vulnerability',
            *_attack_pattern_names,
            *_malware_names,
            *_tool_names
        )

    def declare_objects_mapping(self):
        self.__misp_reghive = Mapping(
            HKEY_CLASSES_ROOT = "HKEY_CLASSES_ROOT",
            HKCR = "HKEY_CLASSES_ROOT",
            HKEY_CURRENT_CONFIG = "HKEY_CURRENT_CONFIG",
            HKCC = "HKEY_CURRENT_CONFIG",
            HKEY_CURRENT_USER = "HKEY_CURRENT_USER",
            HKCU = "HKEY_CURRENT_USER",
            HKEY_LOCAL_MACHINE = "HKEY_LOCAL_MACHINE",
            HKLM = "HKEY_LOCAL_MACHINE",
            HKEY_USERS = "HKEY_USERS",
            HKU = "HKEY_USERS",
            HKEY_CURRENT_USER_LOCAL_SETTINGS = "HKEY_CURRENT_USER_LOCAL_SETTINGS",
            HKCULS = "HKEY_CURRENT_USER_LOCAL_SETTINGS",
            HKEY_PERFORMANCE_DATA = "HKEY_PERFORMANCE_DATA",
            HKPD = "HKEY_PERFORMANCE_DATA",
            HKEY_PERFORMANCE_NLSTEXT = "HKEY_PERFORMANCE_NLSTEXT",
            HKPN = "HKEY_PERFORMANCE_NLSTEXT",
            HKEY_PERFORMANCE_TEXT = "HKEY_PERFORMANCE_TEXT",
            HKPT = "HKEY_PERFORMANCE_TEXT",
        )
        self.__status_mapping = Mapping(
            **{
                '0': 'New',
                '1': 'Open',
                '2': 'Closed'
            }
        )
        self.__threat_level_mapping = Mapping(
            **{
                '1': 'High',
                '2': 'Medium',
                '3': 'Low',
                '4': 'Undefined'
            }
        )
        # OBJECTS MAPPING
        self.__non_indicator_names = Mapping(
            **{
                'attack-pattern': '_parse_attack_pattern_object',
                'course-of-action': '_parse_course_of_action_object',
                'vulnerability': '_parse_vulnerability_object',
                'weakness': '_parse_weakness_object'
            }
        )
        self.__objects_mapping = Mapping(
            **{
                "asn": '_parse_asn_object',
                "credential": '_parse_credential_object',
                "domain-ip": '_parse_domain_ip_object',
                "email": '_parse_email_object',
                "file": '_parse_file_object',
                "ip-port": '_parse_ip_port_object',
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
        self.__as_single_fields = (
            'asn',
            'description'
        )
        self.__attack_pattern_object_mapping = Mapping(
            id = 'capec_id',
            name = 'title',
            summary = 'description'
        )
        self.__course_of_action_object_mapping = Mapping(
            name = 'title',
            type = 'type_',
            description = 'description',
            objective = 'objective',
            stage = 'stage',
            cost = 'cost',
            impact = 'impact',
            efficacy = 'efficacy'
        )
        self.__credential_object_mapping = Mapping(
            username = 'username',
            text = 'description'
        )
        self.__email_object_mapping = Mapping(
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
        self.__email_uuid_fields = (
            'attachment',
        )
        self.__file_object_mapping = Mapping(
            **{
                'entropy': 'peak_entropy',
                'fullpath': 'full_path',
                'path': 'file_path',
                'size-in-bytes': 'size_in_bytes'
            }
        )
        self.__network_socket_mapping = Mapping(
            **{
                'address-family': 'address_family',
                'domain-family': 'domain',
                'protocol': 'protocol',
                'socket-type': 'type_'
            }
        )
        self.__network_socket_single_fields = (
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
        self.__pe_resource_mapping = Mapping(
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
        self.__pe_single_fields = (
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
        self.__process_object_mapping = Mapping(
            **{
                'creation-time': 'creation_time',
                'start-time': 'start_time',
                'name': 'name',
                'pid': 'pid',
                'parent-pid': 'parent_pid'
            }
        )
        self.__process_single_fields = (
            'command-line',
            'creation-time',
            'hidden',
            'image',
            'name',
            'parent-pid',
            'pid',
            'start-time'
        )
        self.__regkey_object_mapping = Mapping(
            **{
                'name': 'name',
                'data': 'data',
                'data-type': 'datatype'
            }
        )
        self.__user_account_object_mapping = Mapping(
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
        self.__user_account_single_fields = (
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
        self.__vulnerability_object_mapping = Mapping(
            id = 'cve_id',
            created = 'discovered_datetime',
            summary = 'description',
            published = 'published_datetime'
        )
        self.__vulnerability_single_fields = (
            'created',
            'cvss-score',
            'published',
            'summary'
        )
        self.__weakness_object_mapping = Mapping(
            id = 'cwe_id',
            description = 'description'
        )
        self.__whois_object_mapping = Mapping(
            **{
                'creation-date': 'creation_date',
                'modification-date': 'updated_date',
                'expiration-date': 'expiration_date'
            }
        )
        self.__whois_single_fields = (
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
        self.__x509_creation_mapping = Mapping(
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
        self.__x509_object_mapping = Mapping(
            **{
                'version': 'version',
                'serial-number': 'serial_number',
                'issuer': 'issuer',
                'signature_algorithm': 'signature_algorithm',
                'subject': 'subject'
            }
        )

    @property
    def as_single_fields(self) -> tuple:
        return self.__as_single_fields

    @property
    def attack_pattern_object_mapping(self) -> dict:
        return self.__attack_pattern_object_mapping

    @property
    def attribute_types_mapping(self) -> dict:
        return self.__attribute_types_mapping

    @property
    def confidence_mapping(self) -> dict:
        return self.__confidence_mapping

    @property
    def confidence_description(self) -> str:
        return self.__confidence_description

    @property
    def confidence_value(self) -> str:
        return self.__confidence_value

    @property
    def course_of_action_names(self) -> tuple:
        return self.__course_of_action_names

    @property
    def course_of_action_object_mapping(self) -> dict:
        return self.__course_of_action_object_mapping

    @property
    def credential_object_mapping(self) -> dict:
        return self.__credential_object_mapping

    @property
    def email_attribute_mapping(self) -> dict:
        return self.__email_attribute_mapping

    @property
    def email_object_mapping(self) -> dict:
        return self.__email_object_mapping

    @property
    def email_uuid_fields(self) -> tuple:
        return self.__email_uuid_fields

    @property
    def file_object_mapping(self) -> dict:
        return self.__file_object_mapping

    @property
    def galaxy_types_mapping(self) -> dict:
        return self.__galaxy_types_mapping

    @property
    def hash_type_attributes(self) -> dict:
        return self.__hash_type_attributes

    @property
    def misp_indicator_type(self) -> dict:
        return self.__misp_indicator_type

    @property
    def misp_reghive(self) -> dict:
        return self.__misp_reghive

    @property
    def network_socket_mapping(self) -> dict:
        return self.__network_socket_mapping

    @property
    def network_socket_single_fields(self) -> tuple:
        return self.__network_socket_single_fields

    @property
    def non_indicator_names(self) -> dict:
        return self.__non_indicator_names

    @property
    def objects_mapping(self) -> dict:
        return self.__objects_mapping

    @property
    def pe_resource_mapping(self) -> dict:
        return self.__pe_resource_mapping

    @property
    def pe_single_fields(self) -> tuple:
        return self.__pe_single_fields

    @property
    def process_object_mapping(self) -> dict:
        return self.__process_object_mapping

    @property
    def process_single_fields(self) -> tuple:
        return self.__process_single_fields

    @property
    def regkey_object_mapping(self) -> dict:
        return self.__regkey_object_mapping

    @property
    def status_mapping(self) -> dict:
        return self.__status_mapping

    @property
    def threat_level_mapping(self) -> dict:
        return self.__threat_level_mapping

    @property
    def TLP_order(self) -> dict:
        return self.__TLP_order

    @property
    def ttp_names(self) -> tuple:
        return self.__ttp_names

    @property
    def user_account_object_mapping(self) -> dict:
        return self.__user_account_object_mapping

    @property
    def user_account_single_fields(self) -> tuple:
        return self.__user_account_single_fields

    @property
    def vulnerability_object_mapping(self) -> dict:
        return self.__vulnerability_object_mapping

    @property
    def vulnerability_single_fields(self) -> tuple:
        return self.__vulnerability_single_fields

    @property
    def weakness_object_mapping(self) -> dict:
        return self.__weakness_object_mapping

    @property
    def whois_object_mapping(self) -> dict:
        return self.__whois_object_mapping

    @property
    def whois_registrant_mapping(self) -> dict:
        return self.__whois_registrant_mapping

    @property
    def whois_single_fields(self) -> tuple:
        return self.__whois_single_fields

    @property
    def x509_creation_mapping(self) -> dict:
        return self.__x509_creation_mapping

    @property
    def x509_object_mapping(self) -> dict:
        return self.__x509_object_mapping
