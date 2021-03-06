#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from stix2.properties import (DictionaryProperty, ListProperty, ObjectReferenceProperty,
                              StringProperty, TimestampProperty)
from stix2.v20.common import (TLP_WHITE as TLP_WHITE_v20, TLP_GREEN as TLP_GREEN_v20,
                              TLP_AMBER as TLP_AMBER_v20, TLP_RED as TLP_RED_v20)
from stix2.v20.sdo import CustomObject as CustomObject_v20
from stix2.v21.common import (TLP_WHITE as TLP_WHITE_v21, TLP_GREEN as TLP_GREEN_v21,
                              TLP_AMBER as TLP_AMBER_v21, TLP_RED as TLP_RED_v21)
from stix2.v21.sdo import CustomObject as CustomObject_v21


@CustomObject_v20(
    'x-misp-attribute',
    [
        ('id', StringProperty(required=True)),
        ('labels', ListProperty(StringProperty, required=True)),
        ('created', TimestampProperty(required=True, precision='millisecond')),
        ('modified', TimestampProperty(required=True, precision='millisecond')),
        ('created_by_ref', StringProperty(required=True)),
        ('object_marking_refs', ListProperty(ObjectReferenceProperty(valid_types=['marking']))),
        ('x_misp_type', StringProperty(required=True)),
        ('x_misp_value', StringProperty(required=True)),
        ('x_misp_comment', StringProperty()),
        ('x_misp_category', StringProperty())
    ]
)
class CustomAttribute_v20():
    pass


@CustomObject_v21(
    'x-misp-attribute',
    [
        ('id', StringProperty(required=True)),
        ('labels', ListProperty(StringProperty, required=True)),
        ('created', TimestampProperty(required=True, precision='millisecond')),
        ('modified', TimestampProperty(required=True, precision='millisecond')),
        ('created_by_ref', StringProperty(required=True)),
        ('object_marking_refs', ListProperty(ObjectReferenceProperty(valid_types=['marking']))),
        ('x_misp_type', StringProperty(required=True)),
        ('x_misp_value', StringProperty(required=True)),
        ('x_misp_comment', StringProperty()),
        ('x_misp_category', StringProperty())
    ]
)
class CustomAttribute_v21():
    pass


@CustomObject_v20(
    'x-misp-object',
    [
        ('id', StringProperty(required=True)),
        ('labels', ListProperty(StringProperty, required=True)),
        ('created', TimestampProperty(required=True, precision='millisecond')),
        ('modified', TimestampProperty(required=True, precision='millisecond')),
        ('created_by_ref', StringProperty(required=True)),
        ('object_marking_refs', ListProperty(ObjectReferenceProperty(valid_types=['marking']))),
        ('x_misp_name', StringProperty(required=True)),
        ('x_misp_attributes', ListProperty(DictionaryProperty())),
        ('x_misp_comment', StringProperty()),
        ('x_misp_meta_category', StringProperty())
    ]
)
class CustomMispObject_v20():
    pass


@CustomObject_v21(
    'x-misp-object',
    [
        ('id', StringProperty(required=True)),
        ('labels', ListProperty(StringProperty, required=True)),
        ('created', TimestampProperty(required=True, precision='millisecond')),
        ('modified', TimestampProperty(required=True, precision='millisecond')),
        ('created_by_ref', StringProperty(required=True)),
        ('object_marking_refs', ListProperty(ObjectReferenceProperty(valid_types=['marking']))),
        ('x_misp_name', StringProperty(required=True)),
        ('x_misp_attributes', ListProperty(DictionaryProperty())),
        ('x_misp_comment', StringProperty()),
        ('x_misp_meta_category', StringProperty())
    ]
)
class CustomMispObject_v21():
    pass


@CustomObject_v20(
    'x-misp-event-note',
    [
        ('id', StringProperty(required=True)),
        ('created', TimestampProperty(required=True, precision='millisecond')),
        ('modified', TimestampProperty(required=True, precision='millisecond')),
        ('created_by_ref', StringProperty(required=True)),
        ('x_misp_event_note', StringProperty(required=True)),
        ('object_ref', StringProperty(required=True))
    ]
)
class CustomNote():
    pass


# ATTRIBUTES MAPPING
_hash_attribute_types = (
    'md5',
    'sha1',
    'sha224',
    'sha256',
    'sha384',
    'sha512',
    'sha512/224',
    'sha512/256',
    'sha3-224',
    'sha3-256',
    'sha3-384',
    'sha3-512',
    'ssdeep',
    'tlsh'
)

attribute_types_mapping = {
    'AS': '_parse_autonomous_system_attribute',
    'attachment': '_parse_attachment_attribute',
    'campaign-name': '_parse_campaign_name_attribute',
    'domain': '_parse_domain_attribute',
    'domain|ip': '_parse_domain_ip_attribute',
    'email': '_parse_email_attribute',
    'email-attachment': '_parse_email_attachment_attribute',
    'email-body': '_parse_email_body_attribute',
    'email-dst': '_parse_email_destination_attribute',
    'email-header': '_parse_email_header_attribute',
    'email-reply-to': '_parse_email_reply_to_attribute',
    'email-src': '_parse_email_source_attribute',
    'email-subject': '_parse_email_subject_attribute',
    'email-x-mailer': '_parse_email_x_mailer_attribute',
    'filename': '_parse_filename_attribute',
    'hostname': '_parse_domain_attribute',
    'hostname|port': '_parse_hostname_port_attribute',
    'http-method': '_parse_http_method_attribute',
    'mac-address': '_parse_mac_address_attribute',
    'malware-sample': '_parse_malware_sample_attribute',
    'mutex': '_parse_mutex_attribute',
    'port': '_parse_port_attribute',
    'regkey': '_parse_regkey_attribute',
    'regkey|value': '_parse_regkey_value_attribute',
    'size-in-bytes': '_parse_size_in_bytes_attribute',
    'user-agent': '_parse_user_agent_attribute',
    'vulnerability': '_parse_vulnerability_attribute'
}
attribute_types_mapping.update(
    dict.fromkeys(
        _hash_attribute_types,
        '_parse_hash_attribute'
    )
)
attribute_types_mapping.update(
    dict.fromkeys(
        (f"filename|{hash}" for hash in _hash_attribute_types),
        '_parse_hash_composite_attribute'
    )
)
attribute_types_mapping.update(
    dict.fromkeys(
        (
            'ip-src',
            'ip-dst'
        ),
        '_parse_ip_attribute'
    )
)
attribute_types_mapping.update(
    dict.fromkeys(
        (
            'ip-src|port',
            'ip-dst|port'
        ),
        '_parse_ip_port_attribute'
    )
)
attribute_types_mapping.update(
    dict.fromkeys(
        [
            "uri",
            "url",
            "link"
        ],
        '_parse_url_attribute'
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


# OBJECTS MAPPING
objects_mapping = {
    'asn': '_parse_asn_object',
    'attack-pattern': '_parse_attack_pattern_object',
    'course-of-action': '_parse_course_of_action_object',
    'credential': '_parse_credential_object',
    'domain-ip': '_parse_domain_ip_object',
    'email': '_parse_email_object',
    'facebook-account': '_parse_account_object',
    'file': '_parse_file_object',
    'ip-port': '_parse_ip_port_object',
    'mutex': '_parse_mutex_object',
    'network-connection': '_parse_network_connection_object',
    'network-socket': '_parse_network_socket_object',
    'pe': '_populate_objects_to_parse',
    'pe-section': '_populate_objects_to_parse',
    'process': '_parse_process_object',
    'registry-key': '_parse_registry_key_object',
    'twitter-account': '_parse_account_object',
    'url': '_parse_url_object',
    'user-account': '_parse_user_account_object',
    'vulnerability': '_parse_vulnerability_object',
    'x509': '_parse_x509_object'
}

as_single_fields = (
    'asn',
    'description'
)

attack_pattern_object_mapping = {
    'name': 'name',
    'summary': 'description'
}
attack_pattern_reference_mapping = {
    'id': ('capec', 'external_id'),
    'references': ('mitre-attack', 'url')
}
attack_pattern_single_fields = (
    'name',
    'summary'
)

course_of_action_object_mapping = (
    'name',
    'description'
)

credential_object_mapping = {
    'password': 'credential',
    'username': 'user_id'
}
credential_single_fields = (
    'username',
)

domain_ip_object_mapping = {
    'domain': 'value',
    'ip': 'resolves_to_refs[*].value'
}
domain_ip_uuid_fields = (
    'ip',
)

email_header_fields = {
    'reply-to': 'Reply-To',
    'x-mailer': 'X-Mailer'
}
email_data_fields = (
    'attachment',
    'screenshot'
)
email_object_mapping = {
    'cc': 'cc_refs.value',
    'email-body': 'body',
    'from': 'from_ref.value',
    'from-display-name': 'from_ref.display_name',
    'reply-to': 'additional_header_fields.reply_to',
    'send-date': 'date',
    'subject': 'subject',
    'to': 'to_refs.value',
    'to-display-name': 'to_refs.display_name',
    'x-mailer': 'additional_header_fields.x_mailer'
}
email_uuid_fields = (
    'attachment',
    'cc',
    'from',
    'screenshot',
    'to'
)

facebook_account_object_mapping = {
    'account-id': 'user_id',
    'account-name': 'account_login'
}
facebook_account_single_fields = (
    'account-id',
    'account-name'
)

file_data_fields = (
    'attachment',
    'malware-sample'
)
file_hash_main_types = (
    'md5',
    'sha1',
    'sha224',
    'sha256',
    'sha384',
    'sha512',
    'sha3-224',
    'sha3-256',
    'sha3-384',
    'sha3-512',
    'ssdeep',
    'tlsh'
)
file_hash_types = (
    'sha512/224',
    'sha512/256',
)
file_object_mapping = {
    'filename': 'name',
    'file-encoding': 'name_enc',
    'mime-type': 'mime_type',
    'size-in-bytes': 'size'
}
file_uuid_fields = file_data_fields + ('path',)
file_single_fields = file_uuid_fields + _hash_attribute_types

geolocation_object_mapping = {
    'address': 'street_address',
    'city': 'city',
    'country': 'country',
    'latitude': 'latitude',
    'longitude': 'longitude',
    'region': 'region',
    'zipcode': 'postal_code'
}

ip_port_object_mapping = {
    'ip_features': {
        'ip': "dst_ref.type = '{}' AND network-traffic:dst_ref.value",
        'ip-src': "src_ref.type = '{}' AND network-traffic:src_ref.value",
        'ip-dst': "dst_ref.type = '{}' AND network-traffic:dst_ref.value",
    },
    'domain_features': {
        'domain': "dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value",
        'hostname': "dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value"
    },
    'features': {
        'dst-port': "dst_port",
        'first-seen': "start",
        'last-seen': "end",
        'src-port': "src_port"
    }
}
ip_port_single_fields = (
    'first-seen',
    'last-seen'
)
ip_port_uuid_fields = (
    'ip',
    'ip-dst',
    'ip-src'
)

network_connection_mapping = {
    "features": {
        'dst-port': 'dst_port',
        'first-packet-seen': 'start',
        'src-port': 'src_port'
    },
    'protocols': (
        'layer3-protocol',
        'layer4-protocol',
        'layer7-protocol'
    )
}

network_socket_mapping = {
    'features': {
        'dst-port': 'dst_port',
        'src-port': 'src_port'
    },
    'extension': {
        'address-family': 'address_family',
        'socket-type': 'socket_type'
    }
}

network_socket_v21_single_fields = (
    'address-family',
    'dst-port',
    'hostname-dst',
    'hostname-src',
    'ip-dst',
    'ip-src',
    'protocol',
    'socket-type',
    'src-port'
)
network_socket_v20_single_fields = network_socket_v21_single_fields + ('domain-family', )
network_socket_state_fields = (
    'blocking',
    'listening'
)

network_traffic_uuid_fields = (
    'hostname-dst',
    'hostname-src',
    'ip-dst',
    'ip-src'
)

pe_object_mapping = {
    'features': {
        'imphash': 'imphash',
        'number-sections': 'number_of_sections',
        'type': 'pe_type'
    },
    'header': {
        'entrypoint-address': 'address_of_entry_point',
    }
}
pe_object_single_fields = (
    'entrypoint-address',
    'imphash',
    'number-sections',
    'type'
)

pe_section_mapping = {
    'entropy': 'entropy',
    'name': 'name',
    'size-in-bytes': 'size'
}

process_object_mapping = {
    'features': {
        'command-line': 'command_line',
        'creation-time': 'created',
        'current-directory': 'cwd',
        'pid': 'pid'
    },
    'parent': {
        'parent-command-line': 'command_line',
        'parent-pid': 'pid'
    }
}
process_uuid_fields = (
    'child-pid',
    'image',
    'parent-command-line',
    'parent-image',
    'parent-pid'
)
process_v21_single_fields = (
    'command-line',
    'creation-time',
    'current-directory',
    'image',
    'parent-command-line',
    'parent-image',
    'parent-pid',
    'pid'
)
process_v20_single_fields = process_v21_single_fields + ('args', 'name', 'parent-process-name')

registry_key_mapping = {
    'features': {
        'key': 'key',
        'last-modified': 'modified'
    },
    'values': {
        'data': 'data',
        'data-type': 'data_type',
        'name': 'name'
    }
}

twitter_account_object_mapping = {
    'displayed-name': 'display_name',
    'id': 'user_id',
    'name': 'account_login'
}
twitter_account_single_fields = (
    'displayed-name',
    'id',
    'name'
)

user_account_object_mapping = {
    'features': {
        'account-type': 'account_type',
        'can_escalate_privs': 'can_escalate_privs',
        'disabled': 'is_disabled',
        'display-name': 'display_name',
        'is_service_account': 'is_service_account',
        'privileged': 'is_privileged',
        'user-id': 'user_id',
        'username': 'account_login'
    },
    'extension': {
        'group': 'groups',
        'group-id': 'gid',
        'home_dir': 'home_dir',
        'shell': 'shell'
    },
    'timeline': {
        'created': 'account_created',
        'expires': 'account_expires',
        'first_login': 'account_first_login',
        'last_login': 'account_last_login',
        'password_last_changed': 'password_last_changed'
    }
}
user_account_single_fields = (
    'account-type',
    'can_escalate_privs',
    'created',
    'disabled',
    'display-name',
    'expires',
    'first_login',
    'group-id',
    'home_dir',
    'is_service_account',
    'last_login',
    'password',
    'password_last_changed',
    'privileged',
    'shell',
    'user-id',
    'username'
)

x509_hash_fields = (
    'x509-fingerprint-md5',
    'x509-fingerprint-sha1',
    'x509-fingerprint-sha256'
)
x509_object_mapping = {
    'extension': {
        'dns_names': 'DNS name',
        'email': 'email',
        'ip': 'IP',
        'rid': 'RID',
        'uri': 'URI'
    },
    'features': {
        'issuer': 'issuer',
        'pubkey-info-algorithm': 'subject_public_key_algorithm',
        'pubkey-info-exponent': 'subject_public_key_exponent',
        'pubkey-info-modulus': 'subject_public_key_modulus',
        'serial-number': 'serial_number',
        'signature_algorithm': 'signature_algorithm',
        'subject': 'subject',
        'version': 'version'
    },
    'timeline': {
        'validity-not-after': 'validity_not_after',
        'validity-not-before': 'validity_not_before'
    }
}
x509_single_fields = (
    'is_ca',
    'issuer',
    'pem',
    'pubkey-info-algorithm',
    'pubkey-info-exponent',
    'pubkey-info-modulus',
    'pubkey-info-size',
    'raw-base64',
    'self_signed',
    'serial-number',
    'signature_algorithm',
    'subject',
    'text',
    'validity-not-after',
    'validity-not-before',
    'version',
    'x509-fingerprint-md5',
    'x509-fingerprint-sha1',
    'x509-fingerprint-sha256'
)


# GALAXIES MAPPING
_attack_pattern_types = (
    'mitre-attack-pattern',
    'mitre-enterprise-attack-attack-pattern',
    'mitre-mobile-attack-attack-pattern',
    'mitre-pre-attack-attack-pattern'
)
_course_of_action_types = (
    'mitre-course-of-action',
    'mitre-enterprise-attack-course-of-action',
    'mitre-mobile-attack-course-of-action'
)
_intrusion_set_types = (
    'mitre-enterprise-attack-intrusion-set',
    'mitre-intrusion-set',
    'mitre-mobile-attack-intrusion-set',
    'mitre-pre-attack-intrusion-set'
)
_malware_types = (
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
_threat_actor_types = (
    'threat-actor',
    'microsoft-activity-group'
)
_tool_types = (
    'botnet',
    'rat',
    'exploit-kit',
    'tds',
    'tool',
    'mitre-tool',
    'mitre-enterprise-attack-tool',
    'mitre-mobile-attack-tool'
)

galaxy_types_mapping = {'branded-vulnerability': '_parse_vulnerability_{}_galaxy'}
galaxy_types_mapping.update(
    dict.fromkeys(
        _attack_pattern_types,
        '_parse_attack_pattern_{}_galaxy'
    )
)
galaxy_types_mapping.update(
    dict.fromkeys(
        _course_of_action_types,
        '_parse_course_of_action_{}_galaxy'
    )
)
galaxy_types_mapping.update(
    dict.fromkeys(
        _intrusion_set_types,
        '_parse_intrusion_set_{}_galaxy'
    )
)
galaxy_types_mapping.update(
    dict.fromkeys(
        _malware_types,
        '_parse_malware_{}_galaxy'
    )
)
galaxy_types_mapping.update(
    dict.fromkeys(
        _threat_actor_types,
        '_parse_threat_actor_{}_galaxy'
    )
)
galaxy_types_mapping.update(
    dict.fromkeys(
        _tool_types,
        '_parse_tool_{}_galaxy'
    )
)

cluster_to_stix_object = {'branded-vulnerability': 'vulnerability'}
cluster_to_stix_object.update(
    dict.fromkeys(
        _attack_pattern_types,
        'attack-pattern'
    )
)
cluster_to_stix_object.update(
    dict.fromkeys(
        _course_of_action_types,
        'course-of-action'
    )
)
cluster_to_stix_object.update(
    dict.fromkeys(
        _intrusion_set_types,
        'intrusion-set'
    )
)
cluster_to_stix_object.update(
    dict.fromkeys(
        _malware_types,
        'malware'
    )
)
cluster_to_stix_object.update(
    dict.fromkeys(
        _threat_actor_types,
        'threat-actor'
    )
)
cluster_to_stix_object.update(
    dict.fromkeys(
        _tool_types,
        'tool'
    )
)

external_id_to_source_name = {
    'CAPEC': 'capec',
    'CVE': 'cve',
    'CWE': 'cwe',
    'MOB': 'mitre-mobile-attack',
    'PRE': 'mitre-pre-attack',
    'REF': 'reference_from_CAPEC'
}


# RELATIONSHIPS BETWEEN STIX OBJECTS
relationship_specs = {
    'attack-pattern': {
        'malware': 'uses',
        'tool': 'uses',
        'vulnerability': 'targets'
    },
    'campaign': {
        'attack-pattern': 'uses',
        'intrusion-set': 'attributed-to',
        'malware': 'uses',
        'threat-actor': 'attributed-to',
        'tool': 'uses',
        'vulnerability': 'targets'
    },
    'course-of-action': {
        'attack-pattern': 'mitigates',
        'malware': 'mitigates',
        'tool': 'mitigates',
        'vulnerability': 'mitigates'
    },
    'indicator': {
        'attack-pattern': 'indicates',
        'intrusion-set': 'indicates',
        'malware': 'indicates',
        'threat-actor': 'indicates',
        'tool': 'indicates'
    }
}


# STIX OBJECTS PREDEFINED MAPPINGS
address_family_enum_list = (
    "AF_UNSPEC",
    "AF_INET",
    "AF_IPX",
    "AF_APPLETALK",
    "AF_NETBIOS",
    "AF_INET6",
    "AF_IRDA",
    "AF_BTH"
)

domain_family_enum_list = (
    "PF_INET",
    "PF_IPX",
    "PF_APPLETALK",
    "PF_INET6",
    "PF_AX25",
    "PF_NETROM"
)

misp_identity_args = {
    'id': 'identity--55f6ea65-aa10-4c5a-bf01-4f84950d210f',
    'type': 'identity',
    'identity_class': 'organization',
    'name': 'MISP',
    'created': '2015-09-14T15:40:21Z',
    'modified': '2015-09-14T15:40:21Z'
}

socket_type_enum_list = (
    "SOCK_STREAM",
    "SOCK_DGRAM",
    "SOCK_RAW",
    "SOCK_RDM",
    "SOCK_SEQPACKET"
)

source_names = (
    'ATTACK',
    'NIST Mobile Threat Catalogue',
    'WASC',
    'capec',
    'cve',
    'cwe',
    'mitre-attack',
    'mitre-ics-attack',
    'mitre-mobile-attack',
    'mitre-pre-attack',
    'reference_from_CAPEC'
)

tlp_markings_v20 = {
    'tlp:white': TLP_WHITE_v20,
    'tlp:green': TLP_GREEN_v20,
    'tlp:amber': TLP_AMBER_v20,
    'tlp:red': TLP_RED_v20
}

tlp_markings_v21 = {
    'tlp:white': TLP_WHITE_v21,
    'tlp:green': TLP_GREEN_v21,
    'tlp:amber': TLP_AMBER_v21,
    'tlp:red': TLP_RED_v21
}
