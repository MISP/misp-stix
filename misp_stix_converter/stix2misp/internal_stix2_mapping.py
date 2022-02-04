#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .. import Mapping
from .stix2_mapping import STIX2Mapping


class InternalSTIX2Mapping(STIX2Mapping):
    def __init__(self):
        super().__init__()
        self._declare_mapping()
        observable_attributes_mapping = {
            'AS': '_parse_AS_observable_attribute',
            'attachment': '_parse_attachment_observable_attribute',
            'domain': '_parse_domain_obsevrable_attribute',
            'domain|ip': '_parse_domain_ip_observable_attribute',
            'email': '_parse_email_observable_attribute',
            'email-attachment': '_parse_email_attachment_observable_attribute',
            'email-body': '_parse_email_body_observable_attribute',
            'email-dst': '_parse_email_destination_observable_attribute',
            'email-header': '_parse_email_header_observable_attribute',
            'email-reply-to': '_parse_email_reply_to_observable_attribute',
            'email-src': '_parse_email_source_observable_attribute',
            'email-subject': '_parse_email_subject_observable_attribute',
            'email-x-mailer': '_parse_email_x_mailer_observable_attribute',
            'filename': '_parse_filename_observable_attribute',
            'hostname': '_parse_domain_observable_attribute',
            'hostname|port': '_parse_hostname_port_observable_attribute',
            'http-method': '_parse_http_method_observable_attribute',
            'mac-address': '_parse_mac_address_observable_attribute',
            'malware-sample': '_parse_malware_sample_observable_attribute',
            'mutex': '_parse_mutex_observable_attribute',
            'port': '_parse_port_observable_attribute',
            'regkey': '_parse_regkey_observable_attribute',
            'regkey|value': '_parse_regkey_value_observable_attribute',
            'size-in-bytes': '_parse_size_in_bytes_observable_attribute',
            'user-agent': '_parse_user_agent_observable_attribute',
        }
        observable_attributes_mapping.update(
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
                '_parse_hash_observable_attribute'
            )
        )
        observable_attributes_mapping.update(
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
                '_parse_filename_hash_observable_attribute'
            )
        )
        observable_attributes_mapping.update(
            dict.fromkeys(
                (
                    'ip-src',
                    'ip-dst'
                ),
                '_parse_ip_observable_attribute'

            )
        )
        observable_attributes_mapping.update(
            dict.fromkeys(
                (
                    'ip-src|port',
                    'ip-dst|port'
                ),
                '_parse_ip_port_observable_attribute'
            )
        )
        observable_attributes_mapping.update(
            dict.fromkeys(
                (
                    'uri',
                    'url',
                    'link'
                ),
                '_parse_url_observable_attribute'
            )
        )
        observable_attributes_mapping.update(
            dict.fromkeys(
                (
                    'x509-fingerprint-md5',
                    'x509-fingerprint-sha1',
                    'x509-fingerprint-sha256'
                ),
                '_parse_x509_fingerprint_observable_attribute'
            )
        )
        self.__observable_attributes_mapping = Mapping(**observable_attributes_mapping)
        observable_objects_mapping = {
            'android-app': '_parse_android_app_observable_object',
            'asn': '_parse_asn_observable_object',
            'cpe-asset': '_parse_cpe_asset_observable_object',
            'credential': '_parse_credential_observable_object',
            'domain-ip': '_parse_domain_ip_observable_object',
            'email': '_parse_email_observable_object',
            'facebook-account': '_parse_account_observable_object',
            'file': '_parse_file_observable_object',
            'image': '_parse_image_observable_object',
            'ip-port': '_parse_ip_port_observable_object',
            'lnk': '_parse_lnk_observable_object',
            'mutex': '_parse_mutex_observable_object',
            'network-connection': '_parse_network_connection_observable_object',
            'network-socket': '_parse_network_socket_observable_object',
            'process': '_parse_process_observable_object',
            'registry-key': '_parse_registry_key_observable_object',
            'url': '_parse_url_observable_object',
            'x509': '_parse_x509observable__object'
        }
        observable_objects_mapping.update(
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
                '_parse_account_observable_object'
            )
        )
        self.__observable_objects_mapping = Mapping(**observable_objects_mapping)

    @property
    def observable_attributes_mapping(self) -> dict:
        return self.__observable_attributes_mapping

    @property
    def observable_objects_mapping(self) -> dict:
        return self.__observable_objects_mapping