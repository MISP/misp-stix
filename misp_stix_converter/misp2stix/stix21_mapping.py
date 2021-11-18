#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .. import Mapping
from .stix2_mapping import Stix2Mapping
from stix2.v21.common import TLP_WHITE, TLP_GREEN, TLP_AMBER, TLP_RED
from stix2.v21.sdo import CustomObject


class Stix21Mapping(Stix2Mapping):
    def __init__(self):
        super().__init__()
        v21_specific_attributes = {
            'email-message-id': '_parse_email_message_id_attribute'
        }
        self._declare_attributes_mapping(updates=v21_specific_attributes)
        self.__tlp_markings = Mapping(
            **{
                'tlp:white': TLP_WHITE,
                'tlp:green': TLP_GREEN,
                'tlp:amber': TLP_AMBER,
                'tlp:red': TLP_RED
            }
        )

    def declare_objects_mapping(self):
        v21_specific_objects = {
            'geolocation': '_parse_geolocation_object'
        }
        self._declare_objects_mapping(updates=v21_specific_objects)
        self.__credential_object_mapping = Mapping(
            password = 'credential',
            username = 'user_id'
        )
        self.__domain_ip_uuid_fields = (
            'domain',
            'hostname',
            'ip'
        )
        self.__email_object_mapping = Mapping(
            **{
                'bcc': 'bcc_refs.value',
                'bcc-display-name': 'bcc_refs.display_name',
                'cc': 'cc_refs.value',
                'cc-display-name': 'cc_refs.display_name',
                'email-body': 'body',
                'from': 'from_ref.value',
                'from-display-name': 'from_ref.display_name',
                'message-id': 'message_id',
                'reply-to': 'additional_header_fields.reply_to',
                'send-date': 'date',
                'subject': 'subject',
                'to': 'to_refs.value',
                'to-display-name': 'to_refs.display_name',
                'x-mailer': 'additional_header_fields.x_mailer'
            }
        )
        self.__email_uuid_fields = (
            'attachment',
            'bcc',
            'cc',
            'from',
            'screenshot',
            'to'
        )
        self.__file_uuid_fields = self.file_data_fields + ('path',)
        self.__geolocation_object_mapping = Mapping(
            address = 'street_address',
            city = 'city',
            country = 'country',
            latitude = 'latitude',
            longitude = 'longitude',
            region = 'region',
            zipcode = 'postal_code'
        )
        self.__ip_port_uuid_fields = (
            'ip',
            'ip-dst',
            'ip-src'
        )
        self.__network_socket_mapping = Mapping(
            features = Mapping(
                **{
                    'dst-port': 'dst_port',
                    'src-port': 'src_port'
                }
            ),
            extension = Mapping(
                **{
                    'address-family': 'address_family',
                    'socket-type': 'socket_type'
                }
            )
        )
        self.__network_socket_single_fields = (
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
        self.__network_traffic_uuid_fields = (
            'hostname-dst',
            'hostname-src',
            'ip-dst',
            'ip-src'
        )
        self.__parent_process_fields = (
            'parent-command-line',
            'parent-pid'
        )
        self.__process_object_mapping = Mapping(
            features = Mapping(
                **{
                    'command-line': 'command_line',
                    'creation-time': 'created',
                    'current-directory': 'cwd',
                    'pid': 'pid'
                }
            ),
            parent = Mapping(
                **{
                    'parent-command-line': 'command_line',
                    'parent-image': 'image_ref.name',
                    'parent-pid': 'pid'
                }
            )
        )
        self.__process_single_fields = (
            'command-line',
            'creation-time',
            'current-directory',
            'image',
            'parent-command-line',
            'parent-image',
            'parent-pid',
            'pid'
        )
        self.__process_uuid_fields = (
            'child-pid',
            'image',
            'parent-command-line',
            'parent-image',
            'parent-pid'
        )
        self.__user_account_object_mapping = Mapping(
            features = Mapping(
                **{
                    'account-type': 'account_type',
                    'can_escalate_privs': 'can_escalate_privs',
                    'disabled': 'is_disabled',
                    'display-name': 'display_name',
                    'is_service_account': 'is_service_account',
                    'password': 'credential',
                    'privileged': 'is_privileged',
                    'user-id': 'user_id',
                    'username': 'account_login'
                }
            ),
            extension = Mapping(
                **{
                    'group': 'groups',
                    'group-id': 'gid',
                    'home_dir': 'home_dir',
                    'shell': 'shell'
                }
            ),
            timeline = Mapping(
                created = 'account_created',
                expires = 'account_expires',
                first_login = 'account_first_login',
                last_login = 'account_last_login',
                password_last_changed = 'credential_last_changed'
            )
        )

    @property
    def credential_object_mapping(self) -> dict:
        return self.__credential_object_mapping

    @property
    def domain_ip_uuid_fields(self) -> tuple:
        return self.__domain_ip_uuid_fields

    @property
    def email_object_mapping(self) -> dict:
        return self.__email_object_mapping

    @property
    def email_uuid_fields(self) -> tuple:
        return self.__email_uuid_fields

    @property
    def file_uuid_fields(self) -> tuple:
        return self.__file_uuid_fields

    @property
    def geolocation_object_mapping(self) -> dict:
        return self.__geolocation_object_mapping

    @property
    def ip_port_uuid_fields(self) -> tuple:
        return self.__ip_port_uuid_fields

    @property
    def network_socket_mapping(self) -> dict:
        return self.__network_socket_mapping

    @property
    def network_socket_single_fields(self) -> tuple:
        return self.__network_socket_single_fields

    @property
    def network_traffic_uuid_fields(self) -> tuple:
        return self.__network_traffic_uuid_fields

    @property
    def parent_process_fields(self) -> tuple:
        return self.__parent_process_fields

    @property
    def process_object_mapping(self) -> dict:
        return self.__process_object_mapping

    @property
    def process_single_fields(self) -> tuple:
        return self.__process_single_fields

    @property
    def process_uuid_fields(self) -> tuple:
        return self.__process_uuid_fields

    @property
    def tlp_markings(self) -> dict:
        return self.__tlp_markings

    @property
    def user_account_object_mapping(self) -> dict:
        return self.__user_account_object_mapping
