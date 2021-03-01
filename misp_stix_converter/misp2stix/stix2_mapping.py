#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from stix2.v20.common import (TLP_WHITE as TLP_WHITE_v20, TLP_GREEN as TLP_GREEN_v20,
                              TLP_AMBER as TLP_AMBER_v20, TLP_RED as TLP_RED_v20)
from stix2.v21.common import (TLP_WHITE as TLP_WHITE_v21, TLP_GREEN as TLP_GREEN_v21,
                              TLP_AMBER as TLP_AMBER_v21, TLP_RED as TLP_RED_v21)

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
    'mac-address': '_parse_mac_address_attribute',
    'mutex': '_parse_mutex_attribute',
    'port': '_parse_port_attribute',
    'regkey': '_parse_regkey_attribute',
    'regkey|value': '_parse_regkey_value_attribute',
    'size-in-bytes': '_parse_size_in_bytes_attribute'
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
            'x509-fingerprint-md5',
            'x509-fingerprint-sha1',
            'x509-fingerprint-sha256'
        ],
        '_parse_x509_fingerprint_attribute'
    )
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