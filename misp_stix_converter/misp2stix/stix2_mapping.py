#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from stix2.properties import (ListProperty, ObjectReferenceProperty,
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
    'file': '_parse_file_object',
    'ip-port': '_parse_ip_port_object',
    'network-connection': '_parse_network_connection_object',
    'network-socket': '_parse_network_socket_object',
    'process': '_parse_process_object',
    'registry-key': '_parse_registry_key_object',
    'url': '_parse_url_object',
    'user-account': '_parse_user_account_object',
    'vulnerability': '_parse_vulnerability_object',
    'whois': '_parse_whois_object',
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


# GALAXIES MAPPING
galaxy_types_mapping = {'branded-vulnerability': '_parse_vulnerability_{}_galaxy'}
galaxy_types_mapping.update(
    dict.fromkeys(
        (
            'mitre-attack-pattern',
            'mitre-enterprise-attack-attack-pattern',
            'mitre-mobile-attack-attack-pattern',
            'mitre-pre-attack-attack-pattern'
        ),
        '_parse_attack_pattern_{}_galaxy'
    )
)
galaxy_types_mapping.update(
    dict.fromkeys(
        (
            'mitre-course-of-action',
            'mitre-enterprise-attack-course-of-action',
            'mitre-mobile-attack-course-of-action'
        ),
        '_parse_course_of_action_{}_galaxy'
    )
)
galaxy_types_mapping.update(
    dict.fromkeys(
        (
            'android',
            'banker',
            'stealer',
            'backdoor',
            'ransomware',
            'mitre-malware',
            'malpedia',
            'mitre-enterprise-attack-malware',
            'mitre-mobile-attack-malware'
        ),
        '_parse_malware_{}_galaxy'
    )
)
galaxy_types_mapping.update(
    dict.fromkeys(
        (
            'threat-actor',
            'microsoft-activity-group'
        ),
        '_parse_threat_actor_{}_galaxy'
    )
)
galaxy_types_mapping.update(
    dict.fromkeys(
        (
            'botnet',
            'rat',
            'exploit-kit',
            'tds',
            'tool',
            'mitre-tool',
            'mitre-enterprise-attack-tool',
            'mitre-mobile-attack-tool'
        ),
        '_parse_tool_{}_galaxy'
    )
)


relationship_specs = {
    'campaign': {
        'attack-pattern': 'uses',
        'malware': 'uses',
        'threat-actor': 'attributed-to',
        'tool': 'uses'
    },
    'indicator': {
        'attack-pattern': 'indicates',
        'malware': 'indicates',
        'threat-actor': 'indicates',
        'tool': 'indicates'
    }
}


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
