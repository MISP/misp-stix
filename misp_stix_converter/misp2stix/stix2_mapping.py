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


## ATTRIBUTES MAPPING
_hash_attribute_types = (
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha512/224",
    "sha512/256",
    "sha3-224",
    "sha3-256",
    "sha3-384",
    "sha3-512",
    "ssdeep",
    "tlsh"
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


## GALAXIES MAPPING
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
        '_parse_threat_actor_galaxy'
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
