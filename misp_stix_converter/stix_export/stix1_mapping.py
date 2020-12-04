#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# STIX header
NS_DICT = {
    "http://cybox.mitre.org/common-2" : 'cyboxCommon',
    "http://cybox.mitre.org/cybox-2" : 'cybox',
    "http://cybox.mitre.org/default_vocabularies-2" : 'cyboxVocabs',
    "http://cybox.mitre.org/objects#AccountObject-2" : 'AccountObj',
    "http://cybox.mitre.org/objects#ArtifactObject-2": 'ArtifactObj',
    "http://cybox.mitre.org/objects#ASObject-1" : 'ASObj',
    "http://cybox.mitre.org/objects#AddressObject-2" : 'AddressObj',
    "http://cybox.mitre.org/objects#PortObject-2" : 'PortObj',
    "http://cybox.mitre.org/objects#DomainNameObject-1" : 'DomainNameObj',
    "http://cybox.mitre.org/objects#EmailMessageObject-2" : 'EmailMessageObj',
    "http://cybox.mitre.org/objects#FileObject-2" : 'FileObj',
    "http://cybox.mitre.org/objects#HTTPSessionObject-2" : 'HTTPSessionObj',
    "http://cybox.mitre.org/objects#HostnameObject-1" : 'HostnameObj',
    "http://cybox.mitre.org/objects#MutexObject-2" : 'MutexObj',
    "http://cybox.mitre.org/objects#PipeObject-2" : 'PipeObj',
    "http://cybox.mitre.org/objects#URIObject-2" : 'URIObj',
    "http://cybox.mitre.org/objects#WinRegistryKeyObject-2" : 'WinRegistryKeyObj',
    'http://cybox.mitre.org/objects#WinServiceObject-2' : 'WinServiceObj',
    "http://cybox.mitre.org/objects#NetworkConnectionObject-2" : 'NetworkConnectionObj',
    "http://cybox.mitre.org/objects#NetworkSocketObject-2" : 'NetworkSocketObj',
    "http://cybox.mitre.org/objects#SocketAddressObject-1" : 'SocketAddressObj',
    "http://cybox.mitre.org/objects#SystemObject-2" : 'SystemObj',
    "http://cybox.mitre.org/objects#ProcessObject-2" : 'ProcessObj',
    "http://cybox.mitre.org/objects#X509CertificateObject-2" : 'X509CertificateObj',
    "http://cybox.mitre.org/objects#WhoisObject-2" : 'WhoisObj',
    "http://cybox.mitre.org/objects#WinExecutableFileObject-2" : 'WinExecutableFileObj',
    "http://cybox.mitre.org/objects#UnixUserAccountObject-2": "UnixUserAccountObj",
    "http://cybox.mitre.org/objects#UserAccountObject-2": "UserAccountObj",
    "http://cybox.mitre.org/objects#WinUserAccountObject-2": "WinUserAccountObj",
    "http://cybox.mitre.org/objects#CustomObject-1": "CustomObj",
    "http://data-marking.mitre.org/Marking-1" : 'marking',
    "http://data-marking.mitre.org/extensions/MarkingStructure#Simple-1": 'simpleMarking',
    "http://data-marking.mitre.org/extensions/MarkingStructure#TLP-1" : 'tlpMarking',
    "http://stix.mitre.org/ExploitTarget-1" : 'et',
    "http://stix.mitre.org/Incident-1" : 'incident',
    "http://stix.mitre.org/Indicator-2" : 'indicator',
    "http://stix.mitre.org/CourseOfAction-1": 'coa',
    "http://stix.mitre.org/TTP-1" : 'ttp',
    "http://stix.mitre.org/ThreatActor-1" : 'ta',
    "http://stix.mitre.org/common-1" : 'stixCommon',
    "http://stix.mitre.org/default_vocabularies-1" : 'stixVocabs',
    "http://stix.mitre.org/extensions/Identity#CIQIdentity3.0-1" : 'ciqIdentity',
    "http://stix.mitre.org/extensions/TestMechanism#Snort-1" : 'snortTM',
    "http://stix.mitre.org/extensions/TestMechanism#YARA-1": 'yaraTM',
    "http://stix.mitre.org/stix-1" : 'stix',
    "http://www.w3.org/2001/XMLSchema-instance" : 'xsi',
    "urn:oasis:names:tc:ciq:xal:3" : 'xal',
    "urn:oasis:names:tc:ciq:xnl:3" : 'xnl',
    "urn:oasis:names:tc:ciq:xpil:3" : 'xpil'
}

SCHEMALOC_DICT = {
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

# mappings
status_mapping = {0: 'New', 1: 'Open', 2: 'Closed'}
threat_level_mapping = {1: 'High', 2: 'Medium', 3: 'Low', 4: 'Undefined'}
TLP_order = {'RED': 4, 'AMBER': 3, 'AMBER NATO ALLIANCE': 3, 'GREEN': 2, 'WHITE': 1}

hash_type_attributes = {
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

# mapping for the attributes that can go through the simpleobservable script
misp_indicator_type = {
    "email-attachment": "Malicious E-mail",
    "filename": "File Hash Watchlist",
    "mutex": "Host Characteristics",
    "named pipe": "Host Characteristics",
    "url": "URL Watchlist"
}
misp_indicator_type.update(dict.fromkeys(list(hash_type_attributes["single"]), "File Hash Watchlist"))
misp_indicator_type.update(dict.fromkeys(list(hash_type_attributes["composite"]), "File Hash Watchlist"))
misp_indicator_type.update(
    dict.fromkeys(
        [
            "email-src",
            "email-dst",
            "email-subject",
            "email-reply-to",
            "email-attachment"
        ],
        "Malicious E-mail"
    )
)
misp_indicator_type.update(
    dict.fromkeys(
        [
            "AS",
            "ip-src",
            "ip-dst",
            "ip-src|port",
            "ip-dst|port"
        ],
        "IP Watchlist"
    )
)
misp_indicator_type.update(
    dict.fromkeys(
        [
            "domain",
            "domain|ip",
            "hostname"
        ],
        "Domain Watchlist"
    )
)
misp_indicator_type.update(
    dict.fromkeys(
        [
            "regkey",
            "regkey|value"
        ],
        "Host Characteristics"
    )
)

cybox_validation = {"AutonomousSystem": "isInt"}

## ATTRIBUTES MAPPING
email_attribute_mapping = {
    'email-src': 'from_',
    'email-dst': 'to',
    'email-reply-to': 'reply_to',
    'email-subject': 'subject'
}

attribute_types_mapping = {
    'AS': '_parse_autonomous_system_attribute',
    'attachment': '_parse_attachment',
    'domain': '_parse_domain_attribute',
    'domain|ip': '_parse_domain_ip_attribute',
    'email-attachment': '_parse_email_attachment',
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
    'snort': '_parse_snort_attribute',
    'target-email': '_parse_target_email',
    'target-external': '_parse_target_external',
    'target-location': '_parse_target_location',
    'target-machine': '_parse_target_machine',
    'target-org': '_parse_target_org',
    'target-user': '_parse_target_user',
    'user-agent': '_parse_user_agent_attribute',
    'vulnerability': '_parse_vulnerability_attribute',
    'yara': '_parse_yara_attribute'
}
attribute_types_mapping.update(
    dict.fromkeys(
        list(hash_type_attributes["single"]),
        '_parse_hash_attribute'
    )
)
attribute_types_mapping.update(
    dict.fromkeys(
        list(hash_type_attributes["composite"]),
        '_parse_hash_composite_attribute'
    )
)
attribute_types_mapping.update(
    dict.fromkeys(
        [
            "ip-src",
            "ip-dst"
        ],
        '_parse_ip_attribute'
    )
)
attribute_types_mapping.update(
    dict.fromkeys(
        [
            "ip-src|port",
            "ip-dst|port"
        ],
        '_parse_ip_port_attribute'
    )
)
attribute_types_mapping.update(
    dict.fromkeys(
        [
            "windows-service-displayname",
            "windows-service-name"
        ],
        '_parse_windows_service_attribute'
    )
)
attribute_types_mapping.update(
    dict.fromkeys(
        [
            "url",
            "link"
        ],
        '_parse_url_attribute'
    )
)
attribute_types_mapping.update(
    dict.fromkeys(
        [
            "email-src",
            "email-dst",
            "email-subject",
            "email-reply-to"
        ],
        '_parse_email_attribute'
    )
)
attribute_types_mapping.update(
    dict.fromkeys(
        [
            'x509-fingerprint-md5',
            'x509-fingerprint-sha1',
            'x509-fingerprint-sha256'
        ],
        '_parse_x509_fingerprint_attribute'
    )
)
attribute_types_mapping.update(
    dict.fromkeys(
        [
            'comment',
            'other',
            'text'
        ],
        '_parse_undefined_attribute'
    )
)

## OBJECTS MAPPING
ttp_names = {
    'attack-pattern': 'parse_attack_pattern',
    'course-of-action': 'parse_course_of_action',
    'vulnerability': 'parse_vulnerability',
    'weakness': 'parse_weakness'
}
objects_mapping = {
    "asn": 'parse_asn_object',
    "credential": 'parse_credential_object',
    "domain-ip": 'parse_domain_ip_object',
    "email": 'parse_email_object',
    "file": 'parse_file_object',
    "ip-port": 'parse_ip_port_object',
    "network-connection": 'parse_network_connection_object',
    "network-socket": 'parse_network_socket_object',
    "pe": 'store_pe',
    "pe-section": 'store_pe',
    "process": 'parse_process_object',
    "registry-key": 'parse_regkey_object',
    "url": 'parse_url_object',
    "user-account": 'parse_user_account_object',
    "whois": 'parse_whois',
    "x509": 'parse_x509_object'
}

## GALAXIES MAPPING
galaxy_types_mapping = {'branded-vulnerability': '_parse_vulnerability_{}_galaxy'}
galaxy_types_mapping.update(
    dict.fromkeys(
        [
            'mitre-attack-pattern',
            'mitre-enterprise-attack-attack-pattern',
            'mitre-mobile-attack-attack-pattern',
            'mitre-pre-attack-attack-pattern'
        ],
        '_parse_attack_pattern_{}_galaxy'
    )
)
galaxy_types_mapping.update(
    dict.fromkeys(
        [
            'mitre-course-of-action',
            'mitre-enterprise-attack-course-of-action',
            'mitre-mobile-attack-course-of-action'
        ],
        '_parse_course_of_action_{}_galaxy'
    )
)
galaxy_types_mapping.update(
    dict.fromkeys(
        [
            'android',
            'banker',
            'stealer',
            'backdoor',
            'ransomware',
            'mitre-malware',
            'malpedia',
            'mitre-enterprise-attack-malware',
            'mitre-mobile-attack-malware'
        ],
        '_parse_malware_{}_galaxy'
    )
)
galaxy_types_mapping.update(
    dict.fromkeys(
        [
            'threat-actor',
            'microsoft-activity-group'
        ],
        '_parse_threat_actor_galaxy'
    )
)
galaxy_types_mapping.update(
    dict.fromkeys(
        [
            'botnet',
            'rat',
            'exploit-kit',
            'tds',
            'tool',
            'mitre-tool',
            'mitre-enterprise-attack-tool',
            'mitre-mobile-attack-tool'
        ],
        '_parse_tool_{}_galaxy'
    )
)

# mapping Windows Registry Hives and their abbreviations
# see https://cybox.mitre.org/language/version2.1/xsddocs/objects/Win_Registry_Key_Object_xsd.html#RegistryHiveEnum
# the dict keys must be UPPER CASE and end with \\
misp_reghive = {
    "HKEY_CLASSES_ROOT\\": "HKEY_CLASSES_ROOT",
    "HKCR\\": "HKEY_CLASSES_ROOT",
    "HKEY_CURRENT_CONFIG\\": "HKEY_CURRENT_CONFIG",
    "HKCC\\": "HKEY_CURRENT_CONFIG",
    "HKEY_CURRENT_USER\\": "HKEY_CURRENT_USER",
    "HKCU\\": "HKEY_CURRENT_USER",
    "HKEY_LOCAL_MACHINE\\": "HKEY_LOCAL_MACHINE",
    "HKLM\\": "HKEY_LOCAL_MACHINE",
    "HKEY_USERS\\": "HKEY_USERS",
    "HKU\\": "HKEY_USERS",
    "HKEY_CURRENT_USER_LOCAL_SETTINGS\\": "HKEY_CURRENT_USER_LOCAL_SETTINGS",
    "HKCULS\\": "HKEY_CURRENT_USER_LOCAL_SETTINGS",
    "HKEY_PERFORMANCE_DATA\\": "HKEY_PERFORMANCE_DATA",
    "HKPD\\": "HKEY_PERFORMANCE_DATA",
    "HKEY_PERFORMANCE_NLSTEXT\\": "HKEY_PERFORMANCE_NLSTEXT",
    "HKPN\\": "HKEY_PERFORMANCE_NLSTEXT",
    "HKEY_PERFORMANCE_TEXT\\": "HKEY_PERFORMANCE_TEXT",
    "HKPT\\": "HKEY_PERFORMANCE_TEXT",
}


attack_pattern_object_mapping = {
    'id': 'capec_id',
    'name': 'title',
    'summary': 'description'
}
course_of_action_object_keys = (
    'type',
    'description',
    'objective',
    'stage',
    'cost',
    'impact',
    'efficacy'
)
email_object_mapping = {
    'from': 'from_',
    'reply-to': 'reply_to',
    'subject': 'subject',
    'x-mailer': 'x_mailer',
    'mime-boundary': 'boundary',
    'user-agent': 'user_agent'
}
file_object_mapping = {
    'entropy': 'peak_entropy',
    'fullpath': 'full_path',
    'path': 'file_path',
    'size-in-bytes': 'size_in_bytes'
}
process_object_keys = (
    'creation-time',
    'start-time',
    'name',
    'pid',
    'parent-pid'
)
regkey_object_mapping = {
    'name': 'name',
    'data': 'data',
    'data-type': 'datatype'
}
user_account_id_mapping = {
    'unix': 'user_id',
    'windows-domain': 'security_id',
    'windows-local': 'security_id'
}
user_account_object_mapping = {
    'username': 'username',
    'display-name': 'full_name',
    'disabled': 'disabled',
    'created': 'creation_date',
    'last_login': 'last_login',
    'home_dir': 'home_directory',
    'shell': 'script_path'
}
vulnerability_object_mapping = {
    'id': 'cve_id',
    'summary': 'description',
    'published': 'published_datetime'
}
weakness_object_mapping = {
    'id': 'cwe_id',
    'description': 'description'
}
whois_object_mapping = {
    'creation-date': 'creation_date',
    'modification-date': 'updated_date',
    'expiration-date': 'expiration_date'
}
whois_registrant_mapping = {
    'registrant-name': 'name',
    'registrant-phone': 'phone_number',
    'registrant-email': 'email_address',
    'registrant-org': 'organization'
}
x509_creation_mapping = {
    'version': 'contents',
    'serial-number': 'contents',
    'issuer': 'contents',
    'subject': 'contents',
    'validity-not-before': 'validity',
    'validity-not-after': 'validity',
    'pubkey-info-exponent': 'rsa_pubkey',
    'pubkey-info-modulus': 'rsa_pubkey',
    'raw-base64': 'raw_certificate',
    'pem': 'raw_certificate',
    'x509-fingerprint-md5': 'signature',
    'x509-fingerprint-sha1': 'signature',
    'x509-fingerprint-sha256': 'signature',
    'pubkey-info-algorithm': 'subject_pubkey'
}
x509_object_keys = (
    'version',
    'serial-number',
    'issuer',
    'subject'
)

# Descriptions

confidence_description = "Derived from MISP's IDS flag. If an attribute is marked for IDS exports, the confidence will be high, otherwise none"
confidence_value = "High"
