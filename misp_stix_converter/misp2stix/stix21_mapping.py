#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .. import Mapping
from .stix2_mapping import Stix2Mapping
from stix2.v21.common import TLP_WHITE, TLP_GREEN, TLP_AMBER, TLP_RED


class Stix21Mapping(Stix2Mapping):
    def __init__(self):
        super().__init__()
        v21_specific_attributes = {
            'email-message-id': '_parse_email_message_id_attribute'
        }
        v21_specific_attributes.update(
            dict.fromkeys(
                [
                    'sigma',
                    'snort',
                    'yara'
                ],
                '_parse_patterning_language_attribute'
            )
        )
        self._declare_attributes_mapping(updates=v21_specific_attributes)
        self.__confidence_tags = {
            'misp:confidence-level="completely-confident"': 100,
            'misp:confidence-level="usually-confident"': 75,
            'misp:confidence-level="fairly-confident"': 50,
            'misp:confidence-level="rarely-confident"': 25,
            'misp:confidence-level="unconfident"': 0
        }
        artifact_values = {
            "mime_type": "application/zip",
            "encryption_algorithm": "mime-type-indicated",
            "decryption_key": "infected"
        }
        pattern_values = (f"file:content_ref.{key} = '{value}'" for key, value in artifact_values.items())
        self.__malware_sample_additional_observable_values = artifact_values
        self.__malware_sample_additional_pattern_values = ' AND '.join(pattern_values)
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
            'annotation': '_populate_objects_to_parse',
            'geolocation': '_parse_geolocation_object',
            'sigma': '_parse_sigma_object',
            'suricata': '_parse_suricata_object',
            'yara': '_parse_yara_object'
        }
        self._declare_objects_mapping(updates=v21_specific_objects)
        self.__annotation_data_fields = (
            'attachment',
        )
        self.__annotation_single_fields = (
            'attachment',
            'text'
        )
        self.__credential_object_mapping = Mapping(
            password = 'credential',
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
                'message-id': 'message_id',
                'reply-to': 'additional_header_fields.reply_to',
                'send-date': 'date',
                'subject': 'subject',
                'to': 'to_refs.value',
                'to-display-name': 'to_refs.display_name',
                'x-mailer': 'additional_header_fields.x_mailer'
            }
        )
        self.__email_observable_mapping = Mapping(
            **{
                'message-id': 'message_id',
                'send-date': 'date',
                'subject': 'subject'
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
        self.__employee_object_mapping = Mapping(
            **{
                'employee-type': 'roles',
                'full-name': 'name',
                'text': 'description'
            }
        )
        self.__file_uuid_fields = self.file_data_fields + ('path',)
        self.__geolocation_object_mapping = Mapping(
            address = 'street_address',
            city = 'city',
            countrycode = 'country',
            latitude = 'latitude',
            longitude = 'longitude',
            region = 'region',
            text = 'description',
            zipcode = 'postal_code'
        )
        self.__http_request_uuid_fields = (
            'ip-src',
            'ip-dst',
            'host'
        )
        self.__ip_port_uuid_fields = (
            'ip',
            'ip-dst',
            'ip-src'
        )
        self.__lnk_time_fields = Mapping(
            **{
                'lnk-access-time': 'atime',
                'lnk-creation-time': 'ctime',
                'lnk-modification-time': 'mtime'
            }
        )
        self.__lnk_uuid_fields = (
            'fullpath',
            'malware-sample',
            'path'
        )
        self.__netflow_uuid_fields = (
            'dst-as',
            'ip-dst',
            'ip-src',
            'src-as'
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
        self.__organization_object_mapping = Mapping(
            description = 'description',
            name = 'name',
            role = 'roles'
        )
        self.__parent_process_fields = (
            'parent-pid',
            'parent-command-line'
        )
        self.__process_object_mapping = Mapping(
            features = Mapping(
                **{
                    'command-line': 'command_line',
                    'creation-time': 'created',
                    'current-directory': 'cwd',
                    'hidden': 'is_hidden',
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
            'hidden',
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
        self.__sigma_object_mapping = Mapping(
            **{
                'comment': 'description',
                'sigma': 'pattern',
                'sigma-rule-name': 'name'
            }
        )
        self.__suricata_object_mapping = Mapping(
            comment = 'description',
            suricata = 'pattern',
            version = 'pattern_version'
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
        self.__yara_object_mapping = Mapping(
            **{
                'comment': 'description',
                'version': 'pattern_version',
                'yara': 'pattern',
                'yara-rule-name': 'name'
            }
        )

    @property
    def annotation_data_fields(self) -> tuple:
        return self.__annotation_data_fields

    @property
    def annotation_single_fields(self) -> tuple:
        return self.__annotation_single_fields

    @property
    def confidence_tags(self) -> dict:
        return self.__confidence_tags

    @property
    def credential_object_mapping(self) -> dict:
        return self.__credential_object_mapping

    @property
    def email_object_mapping(self) -> dict:
        return self.__email_object_mapping

    @property
    def email_observable_mapping(self) -> dict:
        return self.__email_observable_mapping

    @property
    def email_uuid_fields(self) -> tuple:
        return self.__email_uuid_fields

    @property
    def employee_object_mapping(self) -> dict:
        return self.__employee_object_mapping

    @property
    def file_uuid_fields(self) -> tuple:
        return self.__file_uuid_fields

    @property
    def geolocation_object_mapping(self) -> dict:
        return self.__geolocation_object_mapping

    @property
    def http_request_uuid_fields(self) -> tuple:
        return self.__http_request_uuid_fields

    @property
    def ip_port_uuid_fields(self) -> tuple:
        return self.__ip_port_uuid_fields

    @property
    def lnk_time_fields(self) -> dict:
        return self.__lnk_time_fields

    @property
    def lnk_uuid_fields(self) -> tuple:
        return self.__lnk_uuid_fields

    @property
    def malware_sample_additional_observable_values(self) -> dict:
        return self.__malware_sample_additional_observable_values

    @property
    def malware_sample_additional_pattern_values(self) -> str:
        return self.__malware_sample_additional_pattern_values

    @property
    def netflow_uuid_fields(self) -> tuple:
        return self.__netflow_uuid_fields

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
    def organization_object_mapping(self) -> dict:
        return self.__organization_object_mapping

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
    def sigma_object_mapping(self) -> dict:
        return self.__sigma_object_mapping

    @property
    def suricata_object_mapping(self) -> dict:
        return self.__suricata_object_mapping

    @property
    def tlp_markings(self) -> dict:
        return self.__tlp_markings

    @property
    def user_account_object_mapping(self) -> dict:
        return self.__user_account_object_mapping

    @property
    def yara_object_mapping(self) -> dict:
        return self.__yara_object_mapping
