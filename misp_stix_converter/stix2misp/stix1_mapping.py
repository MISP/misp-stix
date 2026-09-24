#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ..misp_stix_mapping import Mapping
from typing import Optional, Union


class STIX1toMISPMapping:
    __attribute_types_mapping = Mapping(
        AccountObjectType = '_handle_credential',
        AddressObjectType = '_handle_address',
        ArtifactObjectType = '_handle_attachment',
        ASObjectType = '_handle_as',
        CustomObjectType = '_handle_custom',
        DNSRecordObjectType = '_handle_dns',
        DomainNameObjectType = '_handle_domain_or_url',
        EmailMessageObjectType = '_handle_email',
        FileObjectType = '_handle_file',
        HostnameObjectType = '_handle_hostname',
        HTTPSessionObjectType = '_handle_http',
        LinkObjectType = '_handle_link',
        MutexObjectType = '_handle_mutex',
        NetworkConnectionObjectType = '_handle_network_connection',
        NetworkSocketObjectType = '_handle_network_socket',
        PDFFileObjectType = '_handle_file',
        PipeObjectType = '_handle_pipe',
        PortObjectType = '_handle_port',
        ProcessObjectType = '_handle_process',
        SocketAddressObjectType = '_handle_socket_address',
        SystemObjectType = '_handle_system',
        UnixUserAccountObjectType = '_handle_unix_user',
        URIObjectType = '_handle_domain_or_url',
        UserAccountObjectType = '_handle_user',
        WhoisObjectType = '_handle_whois',
        WindowsExecutableFileObjectType = '_handle_pe',
        WindowsFileObjectType = '_handle_file',
        WindowsRegistryKeyObjectType = '_handle_regkey',
        WindowsServiceObjectType = '_handle_windows_service',
        WindowsUserAccountObjectType = '_handle_windows_user',
        X509CertificateObjectType = '_handle_x509'
    )
    _file_attribute_type = ('filename', 'filename')
    __event_types = Mapping(
        ArtifactObjectType = {"type": "attachment", "relation": "attachment"},
        DomainNameObjectType = {"type": "domain", "relation": "domain"},
        FileObjectType = _file_attribute_type,
        HostnameObjectType = {"type": "hostname", "relation": "host"},
        MutexObjectType = {"type": "mutex", "relation": "mutex"},
        PDFFileObjectType = _file_attribute_type,
        PortObjectType = {"type": "port", "relation": "port"},
        URIObjectType = {"type": "url", "relation": "url"},
        WindowsFileObjectType = _file_attribute_type,
        WindowsExecutableFileObjectType = _file_attribute_type,
        WindowsRegistryKeyObjectType = {"type": "regkey", "relation": ""}
    )
    # Test mechanism type -> the MISP attribute type its rules land as
    __test_mechanism_mapping = Mapping(
        **{
            'snortTM:SnortTestMechanismType': 'snort',
            'yaraTM:YaraTestMechanismType': 'yara'
        }
    )
    # Marking structure type -> the method reading the tags it carries
    __marking_mapping = Mapping(
        **{
            'AIS:AISMarkingStructure': '_parse_AIS_marking',
            'simpleMarking:SimpleMarkingStructureType': '_parse_simple_marking',
            'tlpMarking:TLPMarkingStructureType': '_parse_TLP_marking'
        }
    )

    # Objects mappings
    _AS_attribute = ('AS', 'asn')
    __as_mapping = Mapping(
        number = _AS_attribute,
        handle = _AS_attribute,
        name = ('text', 'description')
    )
    # Course of Action property -> the property holding its textual value.
    # `title` is handled apart, since it maps to the `name` object relation.
    __course_of_action_mapping = Mapping(
        type_ = 'value',
        description = 'value',
        objective = 'description',
        stage = 'value',
        cost = 'value',
        impact = 'value',
        efficacy = 'value'
    )
    __credential_authentication_mapping = Mapping(
        authentication_type = ('text', 'value', 'type'),
        authentication_data = ('text', 'value', 'password'),
        structured_authentication_mechanism = ('text', 'description.value', 'format')
    )
    __email_mapping = Mapping(
        boundary = ("email-mime-boundary", 'value', "mime-boundary"),
        from_ = ("email-src", "address_value.value", "from"),
        message_id = ("email-message-id", "value", "message-id"),
        reply_to = ("email-reply-to", 'address_value.value', "reply-to"),
        subject = ("email-subject", 'value', "subject"),
        user_agent = ("text", 'value', "user-agent"),
        x_mailer = ("email-x-mailer", 'value', "x-mailer")
    )
    _file_mapping = Mapping(
        accessed_time = ('datetime', 'accessed_time.value', 'access-time'),
        created_time = ('datetime', 'created_time.value', 'creation-time'),
        modified_time = ('datetime', 'modified_time.value', 'modification-time'),
        file_path = ('text', 'file_path.value', 'path'),
        full_path = ('text', 'full_path.value', 'fullpath'),
        file_format = ('mime-type', 'file_format.value', 'mimetype'),
        size_in_bytes = ('size-in-bytes', 'size_in_bytes.value', 'size-in-bytes'),
        peak_entropy = ('float', 'peak_entropy.value', 'entropy')
    )
    # The galaxy each STIX 1 construct is imported as a cluster of: the export
    # writes the cluster's value and never its galaxy, so the import names one
    # the cluster can be looked up in - the consolidated MITRE ATT&CK galaxy
    # where MITRE has one, the single MISP galaxy of the type otherwise.
    __galaxy_types_mapping = Mapping(
        attack_pattern = 'mitre-attack-pattern',
        course_of_action = 'mitre-course-of-action',
        malware = 'mitre-malware',
        threat_actor = 'threat-actor',
        tool = 'mitre-tool',
        vulnerability = 'branded-vulnerability'
    )
    __network_connection_fields = ('source_socket_address', 'destination_socket_address')
    __network_fields = ('src', 'dst')
    __network_reference_mapping = Mapping(
        ip_address = ('ip-{}', 'address_value', 'ip-{}'),
        port = ('port', 'port_value', '{}-port'),
        hostname = ('hostname', 'hostname_value', 'hostname-{}')
    )
    __network_socket_fields = ('local_address', 'remote_address')
    __network_socket_mapping = Mapping(
        protocol = ('text', 'protocol.value', 'protocol'),
        address_family = ('text', 'address_family.value', 'address-family'),
        domain = ('text', 'domain.value', 'domain-family'),
        type_ = ('text', 'type_.value', 'socket-type')
    )
    # PE file header field -> the `pe` object relation it is read as. The
    # template types every one of them, so a relation it retypes later is
    # self-correcting and no type is spelt here.
    __pe_header_mapping = Mapping(
        characteristics = 'characteristics-hex',
        machine = 'machine-type-hex',
        number_of_sections = 'number-sections',
        pointer_to_symbol_table = 'pointer-to-symbol-table',
        size_of_optional_header = 'size-of-optional-header'
    )
    # The cybox type `_set_hash_type` gives each `pe` header hash, by the
    # length of its value alone -> the relation it came from. cybox has a type
    # for none of them, so the length table is the whole typing and reading it
    # backwards the whole inverse; a type outside the table names no relation.
    # `Other` is what the table falls back to, and what an `authentihash` an
    # export older than 2026.9.21 wrote: the shape of the value tells those
    # two apart, in `_pe_header_hash_relation`.
    __pe_header_hash_mapping = Mapping(
        md5 = 'imphash',
        sha1 = 'pehash',
        sha256 = 'authentihash',
        other = 'impfuzzy'
    )
    __pe_mapping = Mapping(
        type_ = 'type'
    )
    # PE version info resource field -> the `pe` object relation it is read
    # as: the export folds the relation into the field name - `company-name`
    # into `companyname` - and no template can invert that fold.
    __pe_resource_mapping = Mapping(
        companyname = 'company-name',
        filedescription = 'file-description',
        fileversion = 'file-version',
        internalname = 'internal-filename',
        langid = 'lang-id',
        legalcopyright = 'legal-copyright',
        originalfilename = 'original-filename',
        productname = 'product-name',
        productversion = 'product-version'
    )
    __process_mapping = Mapping(
        creation_time = ('datetime', 'creation-time'),
        start_time = ('datetime', 'start-time'),
        name = ('text', 'name'),
        pid = ('text', 'pid'),
        parent_pid = ('text', 'parent-pid')
    )
    __regkey_mapping = Mapping(
        hive = ('text', 'hive'),
        key = ('regkey', 'key'),
        modified_time = ('datetime', 'last-modified')
    )
    __regkey_value_mapping = Mapping(
        data = ('text', 'data'),
        datatype = ('text', 'data-type'),
        name = ('text', 'name')
    )
    # Both spellings of every hive in the CybOX enumeration, to its full name
    __registry_hives = Mapping(
        HKEY_CLASSES_ROOT = 'HKEY_CLASSES_ROOT',
        HKCR = 'HKEY_CLASSES_ROOT',
        HKEY_CURRENT_CONFIG = 'HKEY_CURRENT_CONFIG',
        HKCC = 'HKEY_CURRENT_CONFIG',
        HKEY_CURRENT_USER = 'HKEY_CURRENT_USER',
        HKCU = 'HKEY_CURRENT_USER',
        HKEY_LOCAL_MACHINE = 'HKEY_LOCAL_MACHINE',
        HKLM = 'HKEY_LOCAL_MACHINE',
        HKEY_USERS = 'HKEY_USERS',
        HKU = 'HKEY_USERS',
        HKEY_CURRENT_USER_LOCAL_SETTINGS = 'HKEY_CURRENT_USER_LOCAL_SETTINGS',
        HKCULS = 'HKEY_CURRENT_USER_LOCAL_SETTINGS',
        HKEY_PERFORMANCE_DATA = 'HKEY_PERFORMANCE_DATA',
        HKPD = 'HKEY_PERFORMANCE_DATA',
        HKEY_PERFORMANCE_NLSTEXT = 'HKEY_PERFORMANCE_NLSTEXT',
        HKPN = 'HKEY_PERFORMANCE_NLSTEXT',
        HKEY_PERFORMANCE_TEXT = 'HKEY_PERFORMANCE_TEXT',
        HKPT = 'HKEY_PERFORMANCE_TEXT'
    )
    __user_account_object_mapping = Mapping(
        username = ('text', 'username'),
        full_name = ('text', 'display-name'),
        creation_date = ('datetime', 'created'),
        last_login = ('datetime', 'last_login'),
        home_directory = ('text', 'home_dir'),
        script_path = ('text', 'shell')
    )
    __whois_mapping = Mapping(
        registrar_info = ('whois-registrar', 'name.value', 'registrar'),
        ip_address = ('ip-src', 'address_value.value', 'ip-address'),
        domain_name = ('domain', 'value.value', 'domain')
    )
    __whois_registrant_mapping = Mapping(
        email_address = ('whois-registrant-email', 'address_value.value', 'registrant-email'),
        name = ('whois-registrant-name', 'value', 'registrant-name'),
        phone_number = ('whois-registrant-phone', 'value', 'registrant-phone'),
        organization = ('whois-registrant-org', 'value', 'registrant-org')
    )
    __x509_certificate_mapping = Mapping(
        version = 'version',
        serial_number = 'serial-number',
        issuer = 'issuer',
        signature_algorithm = 'signature_algorithm',
        subject = 'subject'
    )
    __x509_datetime_types = ('not_before', 'not_after')
    __x509_pubkey_types = ('exponent', 'modulus')

    @classmethod
    def as_mapping(cls) -> dict:
        return cls.__as_mapping

    @classmethod
    def attribute_types_mapping(cls, object_type: str) -> Union[str, None]:
        return cls.__attribute_types_mapping.get(object_type)

    @classmethod
    def course_of_action_mapping(cls) -> dict:
        return cls.__course_of_action_mapping

    @classmethod
    def credential_authentication_mapping(cls) -> dict:
        return cls.__credential_authentication_mapping

    @classmethod
    def email_mapping(cls) -> dict:
        return cls.__email_mapping

    @classmethod
    def event_types(cls, object_type: str) -> Union[dict, None]:
        return cls.__event_types.get(object_type)

    @classmethod
    def file_mapping(cls) -> dict:
        return cls._file_mapping

    @classmethod
    def galaxy_types_mapping(cls, construct: str) -> str:
        return cls.__galaxy_types_mapping[construct]

    @classmethod
    def network_fields(cls) -> tuple:
        return cls.__network_fields

    @classmethod
    def network_connection_fields(cls) -> tuple:
        return cls.__network_connection_fields

    @classmethod
    def network_reference_mapping(cls) -> dict:
        return cls.__network_reference_mapping

    @classmethod
    def network_socket_fields(cls) -> tuple:
        return cls.__network_socket_fields

    @classmethod
    def marking_mapping(cls, marking_type: str) -> Union[str, None]:
        return cls.__marking_mapping.get(marking_type)

    @classmethod
    def network_socket_mapping(cls) -> dict:
        return cls.__network_socket_mapping

    @classmethod
    def pe_header_hash_mapping(cls, hash_type: str) -> Optional[str]:
        return cls.__pe_header_hash_mapping.get(hash_type)

    @classmethod
    def pe_header_mapping(cls) -> dict:
        return cls.__pe_header_mapping

    @classmethod
    def pe_mapping(cls) -> dict:
        return cls.__pe_mapping

    @classmethod
    def pe_resource_mapping(cls) -> dict:
        return cls.__pe_resource_mapping

    @classmethod
    def process_mapping(cls) -> dict:
        return cls.__process_mapping

    @classmethod
    def registry_hive(cls, hive: str) -> str:
        """The full name of a hive in the CybOX enumeration, whichever way
        it is spelled - any other hive upper-cased, to compare as the
        enumeration does."""
        return cls.__registry_hives.get(hive.upper(), hive.upper())

    @classmethod
    def regkey_mapping(cls) -> dict:
        return cls.__regkey_mapping

    @classmethod
    def regkey_value_mapping(cls) -> dict:
        return cls.__regkey_value_mapping

    @classmethod
    def test_mechanism_mapping(cls, test_mechanism_type: str) -> Union[str, None]:
        return cls.__test_mechanism_mapping.get(test_mechanism_type)

    @classmethod
    def user_account_object_mapping(cls) -> dict:
        return cls.__user_account_object_mapping

    @classmethod
    def whois_mapping(cls) -> dict:
        return cls.__whois_mapping

    @classmethod
    def whois_registrant_mapping(cls) -> dict:
        return cls.__whois_registrant_mapping

    @classmethod
    def x509_certificate_mapping(cls) -> dict:
        return cls.__x509_certificate_mapping

    @classmethod
    def x509_datetime_types(cls) -> tuple:
        return cls.__x509_datetime_types

    @classmethod
    def x509_pubkey_types(cls) -> tuple:
        return cls.__x509_pubkey_types


class ExternalSTIX1toMISPMapping(STIX1toMISPMapping):
    pass


class InternalSTIX1toMISPMapping(STIX1toMISPMapping):
    __attack_pattern_object_mapping = Mapping(
        capec_id = 'id',
        title = 'name',
        description = 'summary'
    )
    __threat_level_mapping = Mapping(
        High = '1',
        Medium = '2',
        Low = '3',
        Undefined = '4'
    )
    __vulnerability_object_mapping = Mapping(
        cve_id = ('vulnerability', 'id'),
        description = ('text', 'summary'),
        discovered_datetime = ('datetime', 'created'),
        published_datetime = ('datetime', 'published')
    )
    __weakness_object_mapping = Mapping(
        cwe_id = 'id',
        description = 'description'
    )

    @classmethod
    def attack_pattern_object_mapping(cls) -> dict:
        return cls.__attack_pattern_object_mapping

    @classmethod
    def threat_level_mapping(cls, threat_level: str) -> Union[str, None]:
        return cls.__threat_level_mapping.get(threat_level)

    @classmethod
    def vulnerability_object_mapping(cls) -> dict:
        return cls.__vulnerability_object_mapping

    @classmethod
    def weakness_object_mapping(cls) -> dict:
        return cls.__weakness_object_mapping
