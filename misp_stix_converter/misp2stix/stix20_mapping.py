#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .. import Mapping
from .stix2_mapping import MISPtoSTIX2Mapping
from stix2.v20.common import MarkingDefinition, TLP_WHITE, TLP_GREEN, TLP_AMBER, TLP_RED
from typing import Union


class MISPtoSTIX20Mapping(MISPtoSTIX2Mapping):
    __tlp_markings = Mapping(
        **{
            'tlp:white': TLP_WHITE,
            'tlp:green': TLP_GREEN,
            'tlp:amber': TLP_AMBER,
            'tlp:red': TLP_RED
        }
    )
    __attribute_types_mapping = MISPtoSTIX2Mapping.attribute_types_mapping()

    # STIX 2.0 specific GALAXIES MAPPING
    __cluster_to_stix_object = dict(MISPtoSTIX2Mapping.cluster_to_stix_object())
    __galaxy_types_mapping = dict(MISPtoSTIX2Mapping.galaxy_types_mapping())
    for galaxy_type in MISPtoSTIX2Mapping.generic_galaxy_types():
        for version in ('2.0', '2.1'):
            key = f'stix-{version}-{galaxy_type}'
            __cluster_to_stix_object[key] = galaxy_type
            feature = f"_parse_{galaxy_type.replace('-', '_')}_{{}}_galaxy"
            __galaxy_types_mapping[key] = feature
    __cluster_to_stix_object = Mapping(**__cluster_to_stix_object)
    __galaxy_types_mapping = Mapping(**__galaxy_types_mapping)
    __attack_pattern_meta_mapping = Mapping(
        kill_chain='_parse_kill_chain'
    )
    __generic_meta_mapping = Mapping(
        **{
            'malware': {'created': True, 'modified': True},
            'threat-actor': {
                'created': True, 'goals': False, 'modified': True,
                'personal_motivations': False, 'primary_motivation': True,
                'resource_level': True, 'roles': False,
                'secondary_motivations': False, 'sophistication': True
            },
            **MISPtoSTIX2Mapping.generic_meta_mapping()
        }
    )
    __malware_sample_additional_observable_values = {
        "mime_type": "application/zip"
    }
    __malware_sample_additional_pattern_values = "file:content_ref.mime_type = 'application/zip'"

    # STIX 2.0 specific MISP OBJECTS MAPPING
    __objects_mapping = MISPtoSTIX2Mapping.objects_mapping()
    __credential_object_mapping = Mapping(
        username='user_id'
    )
    __email_object_mapping = Mapping(
        **{
            'email-body': 'body',
            'from': 'from_ref.value',
            'from-display-name': 'from_ref.display_name',
            'reply-to': 'additional_header_fields.reply_to',
            'send-date': 'date',
            'subject': 'subject',
            'x-mailer': 'additional_header_fields.x_mailer'
        }
    )
    __email_observable_mapping = Mapping(
        subject='subject'
    )
    __employee_object_mapping = Mapping(
        **{
            'full-name': 'name',
            'text': 'description'
        }
    )
    __file_time_fields = Mapping(
        **{
            'access-time': 'accessed',
            'creation-time': 'created',
            'modification-time': 'modified'
        }
    )
    __lnk_time_fields = Mapping(
        **{
            'lnk-access-time': 'accessed',
            'lnk-creation-time': 'created',
            'lnk-modification-time': 'modified'
        }
    )
    __network_socket_mapping = Mapping(
        features={
            'dst-port': 'dst_port',
            'src-port': 'src_port'
        },
        extension={
            'address-family': 'address_family',
            'domain-family': 'protocol_family',
            'socket-type': 'socket_type'
        }
    )
    __network_socket_single_fields = (
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
    __organization_object_mapping = Mapping(
        description='description',
        name='name'
    )
    __person_object_mapping = Mapping(
        **{
            'full-name': 'name',
            'text': 'description'
        }
    )
    __process_object_mapping = Mapping(
        features={
            'args': 'arguments',
            'command-line': 'command_line',
            'creation-time': 'created',
            'current-directory': 'cwd',
            'hidden': 'is_hidden',
            'name': 'name',
            'pid': 'pid'
        },
        parent={
            'parent-command-line': 'command_line',
            'parent-image': 'binary_ref.name',
            'parent-pid': 'pid',
            'parent-process-name': 'name'
        }
    )
    __process_single_fields = (
        'args',
        'command-line',
        'creation-time',
        'current-directory',
        'hidden',
        'image',
        'name',
        'parent-command-line',
        'parent-image',
        'parent-pid',
        'parent-process-name',
        'pid'
    )
    __user_account_object_mapping = Mapping(
        features={
            'account-type': 'account_type',
            'can_escalate_privs': 'can_escalate_privs',
            'disabled': 'is_disabled',
            'display-name': 'display_name',
            'is_service_account': 'is_service_account',
            'privileged': 'is_privileged',
            'user-id': 'user_id',
            'username': 'account_login'
        },
        extension={
            'group': 'groups',
            'group-id': 'gid',
            'home_dir': 'home_dir',
            'shell': 'shell'
        },
        timeline={
            'created': 'account_created',
            'expires': 'account_expires',
            'first_login': 'account_first_login',
            'last_login': 'account_last_login',
            'password_last_changed': 'password_last_changed'
        }
    )

    @classmethod
    def attack_pattern_meta_mapping(cls, field: str) -> Union[str, None]:
        return cls.__attack_pattern_meta_mapping.get(field)

    @classmethod
    def attribute_types_mapping(cls, field: str) -> Union[str, None]:
        return cls.__attribute_types_mapping.get(field)

    @classmethod
    def cluster_to_stix_object(cls, field: str) -> Union[str, None]:
        return cls.__cluster_to_stix_object.get(field)

    @classmethod
    def credential_object_mapping(cls) -> dict:
        return cls.__credential_object_mapping

    @classmethod
    def email_object_mapping(cls) -> dict:
        return cls.__email_object_mapping

    @classmethod
    def email_observable_mapping(cls) -> dict:
        return cls.__email_observable_mapping

    @classmethod
    def employee_object_mapping(cls) -> dict:
        return cls.__employee_object_mapping

    @classmethod
    def file_time_fields(cls) -> dict:
        return cls.__file_time_fields

    @classmethod
    def galaxy_types_mapping(cls, field: str) -> Union[str, None]:
        return cls.__galaxy_types_mapping.get(field)

    @classmethod
    def generic_meta_mapping(cls, object_type: str) -> dict:
        return cls.__generic_meta_mapping.get(object_type, {})

    @classmethod
    def lnk_time_fields(cls) -> dict:
        return cls.__lnk_time_fields

    @classmethod
    def malware_sample_additional_observable_values(cls) -> dict:
        return cls.__malware_sample_additional_observable_values

    @classmethod
    def malware_sample_additional_pattern_values(cls) -> str:
        return cls.__malware_sample_additional_pattern_values

    @classmethod
    def network_socket_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__network_socket_mapping.get(field)

    @classmethod
    def network_socket_single_fields(cls) -> tuple:
        return cls.__network_socket_single_fields

    @classmethod
    def objects_mapping(cls, field: str) -> Union[str, None]:
        return cls.__objects_mapping.get(field)

    @classmethod
    def organization_object_mapping(cls) -> dict:
        return cls.__organization_object_mapping

    @classmethod
    def person_object_mapping(cls) -> dict:
        return cls.__person_object_mapping

    @classmethod
    def process_object_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__process_object_mapping.get(field)

    @classmethod
    def process_single_fields(cls) -> tuple:
        return cls.__process_single_fields

    @classmethod
    def tlp_markings(cls, field: str) -> Union[MarkingDefinition, None]:
        return cls.__tlp_markings.get(field)

    @classmethod
    def user_account_object_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__user_account_object_mapping.get(field)
