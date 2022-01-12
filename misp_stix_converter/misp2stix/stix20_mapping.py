#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .. import Mapping
from .stix2_mapping import Stix2Mapping
from stix2.v20.common import TLP_WHITE, TLP_GREEN, TLP_AMBER, TLP_RED
from stix2.v20.sdo import CustomObject


class Stix20Mapping(Stix2Mapping):
    def __init__(self):
        super().__init__()
        self._declare_attributes_mapping()
        self.__tlp_markings = Mapping(
            **{
                'tlp:white': TLP_WHITE,
                'tlp:green': TLP_GREEN,
                'tlp:amber': TLP_AMBER,
                'tlp:red': TLP_RED
            }
        )

    def declare_objects_mapping(self):
        self._declare_objects_mapping()
        self.__credential_object_mapping = Mapping(
            username = 'user_id'
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
                'reply-to': 'additional_header_fields.reply_to',
                'send-date': 'date',
                'subject': 'subject',
                'to': 'to_refs.value',
                'to-display-name': 'to_refs.display_name',
                'x-mailer': 'additional_header_fields.x_mailer'
            }
        )
        self.__employee_object_mapping = Mapping(
            **{
                'email-address': 'contact_information',
                'text': 'description'
            }
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
                    'domain-family': 'protocol_family',
                    'socket-type': 'socket_type'
                }
            )
        )
        self.__network_socket_single_fields = (
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
        self.__process_object_mapping = Mapping(
            features = Mapping(
                **{
                    'args': 'arguments',
                    'command-line': 'command_line',
                    'creation-time': 'created',
                    'current-directory': 'cwd',
                    'name': 'name',
                    'pid': 'pid'
                }
            ),
            parent = Mapping(
                **{
                    'parent-command-line': 'command_line',
                    'parent-image': 'binary_ref.name',
                    'parent-pid': 'pid',
                    'parent-process-name': 'name'
                }
            )
        )
        self.__process_single_fields = (
            'args',
            'command-line',
            'creation-time',
            'current-directory',
            'image',
            'name',
            'parent-command-line',
            'parent-image',
            'parent-pid',
            'parent-process-name',
            'pid'
        )
        self.__user_account_object_mapping = Mapping(
            features = Mapping(
                **{
                    'account-type': 'account_type',
                    'can_escalate_privs': 'can_escalate_privs',
                    'disabled': 'is_disabled',
                    'display-name': 'display_name',
                    'is_service_account': 'is_service_account',
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
                password_last_changed = 'password_last_changed'
            )
        )

    @property
    def credential_object_mapping(self) -> dict:
        return self.__credential_object_mapping

    @property
    def email_object_mapping(self) -> dict:
        return self.__email_object_mapping

    @property
    def employee_object_mapping(self) -> dict:
        return self.__employee_object_mapping

    @property
    def network_socket_mapping(self) -> dict:
        return self.__network_socket_mapping

    @property
    def network_socket_single_fields(self) -> tuple:
        return self.__network_socket_single_fields

    @property
    def process_object_mapping(self) -> dict:
        return self.__process_object_mapping

    @property
    def process_single_fields(self) -> tuple:
        return self.__process_single_fields

    @property
    def tlp_markings(self) -> dict:
        return self.__tlp_markings

    @property
    def user_account_object_mapping(self) -> dict:
        return self.__user_account_object_mapping
