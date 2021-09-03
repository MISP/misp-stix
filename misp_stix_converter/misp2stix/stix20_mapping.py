#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .stix2_mapping import Stix2Mapping
from stix2.v20.common import TLP_WHITE, TLP_GREEN, TLP_AMBER, TLP_RED
from stix2.v20.sdo import CustomObject


class Stix20Mapping(Stix2Mapping):
    def __init__(self):
        super().__init__()
        self._declare_attributes_mapping()

    def declare_objects_mapping(self):
        self._declare_objects_mapping()
        self.__credential_object_mapping = {
            'username': 'user_id'
        }
        self.__email_object_mapping = {
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
        self.__network_socket_mapping = {
            'features': {
                'dst-port': 'dst_port',
                'src-port': 'src_port'
            },
            'extension': {
                'address-family': 'address_family',
                'domain-family': 'protocol_family',
                'socket-type': 'socket_type'
            }
        }
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
        self.__process_object_mapping = {
            'features': {
                'args': 'arguments',
                'command-line': 'command_line',
                'creation-time': 'created',
                'current-directory': 'cwd',
                'name': 'name',
                'pid': 'pid'
            },
            'parent': {
                'parent-command-line': 'command_line',
                'parent-pid': 'pid'
            }
        }
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
        self.__tlp_markings = tlp_markings = {
            'tlp:white': TLP_WHITE,
            'tlp:green': TLP_GREEN,
            'tlp:amber': TLP_AMBER,
            'tlp:red': TLP_RED
        }
        self.__user_account_object_mapping = {
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

    @property
    def credential_object_mapping(self) -> dict:
        return self.__credential_object_mapping

    @property
    def email_object_mapping(self) -> dict:
        return self.__email_object_mapping

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
