#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from stix2.v20.common import (TLP_WHITE as TLP_WHITE_v20, TLP_GREEN as TLP_GREEN_v20,
                              TLP_AMBER as TLP_AMBER_v20, TLP_RED as TLP_RED_v20)
from stix2.v21.common import (TLP_WHITE as TLP_WHITE_v21, TLP_GREEN as TLP_GREEN_v21,
                              TLP_AMBER as TLP_AMBER_v21, TLP_RED as TLP_RED_v21)

attribute_types_mapping = {
    'AS': '_parse_autonomous_system_attribute',
    'attachment': '_parse_attachment_attribute',
    'domain': '_parse_domain_attribute',
    'domain|ip': '_parse_domain_ip_attribute',
    'email': '_parse_email_attribute',
    'email-attachment': '_parse_email_attachment_attribute',
    'email-body': '_parse_email_body_attribute',
    'email-dst': '_parse_email_destination_attribute',
    'email-reply-to': '_parse_email_reply_to_attribute',
    'email-src': '_parse_email_source_attribute',
    'email-subject': '_parse_email_subject_attribute',
    'email-x-mailer': '_parse_email_x_mailer_attribute',
    'filename': '_parse_filename_attribute',
    'hostname': '_parse_domain_attribute',
    'hostname|port': '_parse_hostname_port_attribute',
    'mac-address': '_parse_mac_address_attribute',
    'mutex': '_parse_mutex_attribute',
    'regkey': '_parse_regkey_attribute',
    'regkey|value': '_parse_regkey_value_attribute'
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
