#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ..misp_stix_mapping import Mapping
from .stix_mapping import MISPtoSTIXMapping
from typing import Union


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
