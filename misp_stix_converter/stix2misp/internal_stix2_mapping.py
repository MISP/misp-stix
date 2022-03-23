#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .. import Mapping
from .stix2_mapping import STIX2Mapping


class InternalSTIX2Mapping(STIX2Mapping):
    def __init__(self):
        super().__init__()
        self._declare_mapping()
        attributes_mapping = {
            'AS': '_attribute_from_AS',
            'attachment': '_attribute_from_attachment',
            'domain': '_attribute_from_domain',
            'domain|ip': '_attribute_from_domain_ip',
            'email': '_attribute_from_email',
            'email-attachment': '_attribute_from_email_attachment',
            'email-body': '_attribute_from_email_body',
            'email-dst': '_attribute_from_email_destination',
            'email-header': '_attribute_from_email_header',
            'email-reply-to': '_attribute_from_email_reply_to',
            'email-src': '_attribute_from_email_source',
            'email-subject': '_attribute_from_email_subject',
            'email-x-mailer': '_attribute_from_email_x_mailer',
            'filename': '_attribute_from_filename',
            'hostname': '_attribute_from_domain',
            'hostname|port': '_attribute_from_hostname_port',
            'http-method': '_attribute_from_http_method',
            'mac-address': '_attribute_from_mac_address',
            'malware-sample': '_attribute_from_malware_sample',
            'mutex': '_attribute_from_mutex',
            'port': '_attribute_from_port',
            'regkey': '_attribute_from_regkey',
            'regkey|value': '_attribute_from_regkey_value',
            'size-in-bytes': '_attribute_from_size_in_bytes',
            'user-agent': '_attribute_from_user_agent',
            'vulnerability': '_parse_vulnerability_attribute'
        }
        attributes_mapping.update(
            dict.fromkeys(
                (
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
                ),
                '_attribute_from_hash'
            )
        )
        attributes_mapping.update(
            dict.fromkeys(
                (
                    'filename|md5',
                    'filename|sha1',
                    'filename|sha224',
                    'filename|sha256',
                    'filename|sha384',
                    'filename|sha512',
                    'filename|sha512/224',
                    'filename|sha512/256',
                    'filename|sha3-224',
                    'filename|sha3-256',
                    'filename|sha3-384',
                    'filename|sha3-512',
                    'filename|ssdeep',
                    'filename|tlsh'
                ),
                '_attribute_from_filename_hash'
            )
        )
        attributes_mapping.update(
            dict.fromkeys(
                (
                    'ip-src',
                    'ip-dst'
                ),
                '_attribute_from_ip'
            )
        )
        attributes_mapping.update(
            dict.fromkeys(
                (
                    'ip-src|port',
                    'ip-dst|port'
                ),
                '_attribute_from_ip_port'
            )
        )
        attributes_mapping.update(
            dict.fromkeys(
                (
                    'uri',
                    'url',
                    'link'
                ),
                '_attribute_from_url'
            )
        )
        attributes_mapping.update(
            dict.fromkeys(
                (
                    'x509-fingerprint-md5',
                    'x509-fingerprint-sha1',
                    'x509-fingerprint-sha256'
                ),
                '_attribute_from_x509_fingerprint'
            )
        )
        attributes_mapping.update(
            dict.fromkeys(
                (
                    'sigma',
                    'snort',
                    'yara'
                ),
                '_attribute_from_patterning_language'
            )
        )
        self.__attributes_mapping = Mapping(**attributes_mapping)
        objects_mapping = {
            'android-app': '_object_from_android_app',
            'asn': '_object_from_asn',
            'cpe-asset': '_object_from_cpe_asset',
            'credential': '_object_from_credential',
            'domain-ip': '_object_from_domain_ip',
            'email': '_object_from_email',
            'facebook-account': '_object_from_account',
            'file': '_object_from_file',
            'image': '_object_from_image',
            'ip-port': '_object_from_ip_port',
            'lnk': '_object_from_lnk',
            'mutex': '_object_from_mutex',
            'network-connection': '_object_from_network_connection',
            'network-socket': '_object_from_network_socket',
            'process': '_object_from_process',
            'registry-key': '_object_from_registry_key',
            'url': '_object_from_url',
            'vulnerability': '_parse_vulnerability_object',
            'x509': '_object_from_x509'
        }
        objects_mapping.update(
            dict.fromkeys(
                (
                    'github-user',
                    'gitlab-user',
                    'parler-account',
                    'reddit-account',
                    'telegram-account',
                    'twitter-account',
                    'user-account'
                ),
                '_object_from_account'
            )
        )
        self.__objects_mapping = Mapping(**objects_mapping)

    @property
    def attributes_mapping(self) -> dict:
        return self.__attributes_mapping

    @property
    def objects_mapping(self) -> dict:
        return self.__objects_mapping