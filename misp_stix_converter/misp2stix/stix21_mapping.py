#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .. import Mapping
from .stix2_mapping import MISPtoSTIX2Mapping
from stix2.v21.common import MarkingDefinition, TLP_WHITE, TLP_GREEN, TLP_AMBER, TLP_RED
from typing import Union


class MISPtoSTIX21Mapping(MISPtoSTIX2Mapping):
    __confidence_tags = {
        'misp:confidence-level="completely-confident"': 100,
        'misp:confidence-level="usually-confident"': 75,
        'misp:confidence-level="fairly-confident"': 50,
        'misp:confidence-level="rarely-confident"': 25,
        'misp:confidence-level="unconfident"': 0
    }
    __tlp_markings = Mapping(
        **{
            'tlp:white': TLP_WHITE,
            'tlp:green': TLP_GREEN,
            'tlp:amber': TLP_AMBER,
            'tlp:red': TLP_RED
        }
    )

    # STIX 2.1 specific ATTRIBUTE TYPES MAPPING
    __attribute_types_mapping = Mapping(
        **{
            'email-message-id': '_parse_email_message_id_attribute',
            **dict.fromkeys(
                ('sigma', 'snort', 'yara'),
                '_parse_patterning_language_attribute'
            ),
            **MISPtoSTIX2Mapping.attribute_types_mapping()
        }
    )

    # STIX 2.1 specitif GALAXIES MAPPING
    __cluster_to_stix_object = {
        'country': 'location',
        'region': 'location',
        'stix-2.1-location': 'location',
        **MISPtoSTIX2Mapping.cluster_to_stix_object()
    }
    __galaxy_types_mapping = {
        'country': '_parse_location_{}_galaxy',
        'region': '_parse_location_{}_galaxy',
        'stix-2.1-location': '_parse_location_{}_galaxy',
        **MISPtoSTIX2Mapping.galaxy_types_mapping()
    }
    for galaxy_type in MISPtoSTIX2Mapping.generic_galaxy_types():
        for version in ('2.0', '2.1'):
            key = f'stix-{version}-{galaxy_type}'
            __cluster_to_stix_object[key] = galaxy_type
            feature = f"_parse_{galaxy_type.replace('-', '_')}_{{}}_galaxy"
            __galaxy_types_mapping[key] = feature
    __cluster_to_stix_object = Mapping(**__cluster_to_stix_object)
    __galaxy_types_mapping = Mapping(**__galaxy_types_mapping)
    __attack_pattern_meta_mapping = Mapping(
        kill_chain='_parse_kill_chain',
        synonyms='_parse_synonyms_meta_field'
    )
    __generic_meta_mapping = Mapping(
        **{
            'location': {
                'administrative_area': True, 'created': True,
                'modified': True, 'region': True
            },
            'malware': {
                'architecture_execution_envs': False, 'capabilities': False,
                'created': True, 'first_seen': True, 'last_seen': True,
                'implementation_languages': False, 'modified': True
            },
            'threat-actor': {
                'created': True, 'first_seen': True, 'goals': False,
                'last_seen': True, 'modified': True, 'resource_level': True,
                'personal_motivations': False, 'primary_motivation': True,
                'roles': False, 'secondary_motivations': False,
                'sophistication': True
            },
            **MISPtoSTIX2Mapping.generic_meta_mapping()
        }
    )
    __location_meta_mapping = Mapping(
        country='_parse_country_meta_field',
    )
    __malware_sample_additional_observable_values = Mapping(
        mime_type="application/zip",
        encryption_algorithm="mime-type-indicated",
        decryption_key="infected"
    )
    __malware_sample_additional_pattern_values = ' AND '.join(
        f"file:content_ref.{key} = '{value}'"
        for key, value in __malware_sample_additional_observable_values.items()
    )
    __regions_mapping = Mapping(
        **{
            'Latin America and the Caribbean': 'latin-america-caribbean',
            'Australia and New Zealand': 'australia-new-zealand'
        }
    )

    # STIX 2.1 specific MISP OBJECTS MAPPING
    __objects_mapping = {
        'annotation': '_populate_objects_to_parse',
        'geolocation': '_parse_geolocation_object',
        'sigma': '_parse_sigma_object',
        'suricata': '_parse_suricata_object',
        'yara': '_parse_yara_object',
        **MISPtoSTIX2Mapping.objects_mapping()
    }
    __annotation_data_fields = (
        'attachment',
    )
    __annotation_single_fields = (
        'attachment',
        'text'
    )
    __credential_object_mapping = Mapping(
        password='credential',
        username='user_id'
    )
    __email_object_mapping = Mapping(
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
    __email_observable_mapping = Mapping(
        **{
            'message-id': 'message_id',
            'subject': 'subject'
        }
    )
    __email_uuid_fields = (
        'attachment',
        'bcc',
        'cc',
        'from',
        'screenshot',
        'to'
    )
    __employee_object_mapping = Mapping(
        **{
            'employee-type': 'roles',
            'full-name': 'name',
            'text': 'description'
        }
    )
    __file_uuid_fields = (
        'path',
        *MISPtoSTIX2Mapping.file_data_fields()
    )
    __geolocation_object_mapping = Mapping(
        address='street_address',
        city='city',
        countrycode='country',
        latitude='latitude',
        longitude='longitude',
        region='region',
        text='description',
        zipcode='postal_code'
    )
    __http_request_uuid_fields = (
        'ip-src',
        'ip-dst',
        'host'
    )
    __ip_port_uuid_fields = (
        'ip',
        'ip-dst',
        'ip-src'
    )
    __file_time_fields = Mapping(
        **{
            'access-time': 'atime',
            'creation-time': 'ctime',
            'modification-time': 'mtime'
        }
    )
    __lnk_time_fields = Mapping(
        **{
            'lnk-access-time': 'atime',
            'lnk-creation-time': 'ctime',
            'lnk-modification-time': 'mtime'
        }
    )
    __lnk_uuid_fields = (
        'fullpath',
        'malware-sample',
        'path'
    )
    __netflow_uuid_fields = (
        'dst-as',
        'ip-dst',
        'ip-src',
        'src-as'
    )
    __network_socket_mapping = Mapping(
        features={
            'dst-port': 'dst_port',
            'src-port': 'src_port'
        },
        extension={
            'address-family': 'address_family',
            'socket-type': 'socket_type'
        }
    )
    __network_socket_single_fields = (
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
    __network_traffic_uuid_fields = (
        'hostname-dst',
        'hostname-src',
        'ip-dst',
        'ip-src'
    )
    __organization_object_mapping = Mapping(
        description='description',
        name='name',
        role='roles'
    )
    __parent_process_fields = (
        'parent-pid',
        'parent-command-line'
    )
    __person_object_mapping = Mapping(
        **{
            'full-name': 'name',
            'text': 'description',
            'role': 'roles'
        }
    )
    __process_object_mapping = Mapping(
        features={
            'command-line': 'command_line',
            'creation-time': 'created',
            'current-directory': 'cwd',
            'hidden': 'is_hidden',
            'pid': 'pid'
        },
        parent={
            'parent-command-line': 'command_line',
            'parent-image': 'image_ref.name',
            'parent-pid': 'pid'
        }
    )
    __process_single_fields = (
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
    __process_uuid_fields = (
        'child-pid',
        'image',
        'parent-command-line',
        'parent-image',
        'parent-pid'
    )
    __sigma_object_mapping = Mapping(
        **{
            'comment': 'description',
            'sigma': 'pattern',
            'sigma-rule-name': 'name'
        }
    )
    __suricata_object_mapping = Mapping(
        comment='description',
        suricata='pattern',
        version='pattern_version'
    )
    __user_account_object_mapping = Mapping(
        features={
            'account-type': 'account_type',
            'can_escalate_privs': 'can_escalate_privs',
            'disabled': 'is_disabled',
            'display-name': 'display_name',
            'is_service_account': 'is_service_account',
            'password': 'credential',
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
            'password_last_changed': 'credential_last_changed'
        }
    )
    __yara_object_mapping = Mapping(
        **{
            'comment': 'description',
            'version': 'pattern_version',
            'yara': 'pattern',
            'yara-rule-name': 'name'
        }
    )

    @classmethod
    def annotation_data_fields(cls) -> tuple:
        return cls.__annotation_data_fields

    @classmethod
    def annotation_single_fields(cls) -> tuple:
        return cls.__annotation_single_fields

    @classmethod
    def attack_pattern_meta_mapping(cls, field: str) -> Union[str, None]:
        return cls.__attack_pattern_meta_mapping.get(field)

    @classmethod
    def attribute_types_mapping(cls, field) -> Union[str, None]:
        return cls.__attribute_types_mapping.get(field)

    @classmethod
    def cluster_to_stix_object(cls) -> dict:
        return cls.__cluster_to_stix_object

    @classmethod
    def confidence_tags(cls, field: str) -> Union[int, None]:
        return cls.__confidence_tags.get(field)

    @classmethod
    def credential_object_mapping(cls) -> dict:
        return cls.__credential_object_mapping

    @classmethod
    def cluster_to_stix_object(cls, field: str) -> Union[str, None]:
        return cls.__cluster_to_stix_object.get(field)

    @classmethod
    def email_object_mapping(cls) -> dict:
        return cls.__email_object_mapping

    @classmethod
    def email_observable_mapping(cls) -> dict:
        return cls.__email_observable_mapping

    @classmethod
    def email_uuid_fields(cls) -> tuple:
        return cls.__email_uuid_fields

    @classmethod
    def employee_object_mapping(cls) -> dict:
        return cls.__employee_object_mapping

    @classmethod
    def file_time_fields(cls) -> dict:
        return cls.__file_time_fields

    @classmethod
    def file_uuid_fields(cls) -> tuple:
        return cls.__file_uuid_fields

    @classmethod
    def galaxy_types_mapping(cls, field: str) -> Union[str, None]:
        return cls.__galaxy_types_mapping.get(field)

    @classmethod
    def generic_meta_mapping(cls, object_type: str) -> dict:
        return cls.__generic_meta_mapping.get(object_type, {})

    @classmethod
    def geolocation_object_mapping(cls) -> dict:
        return cls.__geolocation_object_mapping

    @classmethod
    def http_request_uuid_fields(cls) -> tuple:
        return cls.__http_request_uuid_fields

    @classmethod
    def ip_port_uuid_fields(cls) -> tuple:
        return cls.__ip_port_uuid_fields

    @classmethod
    def lnk_time_fields(cls) -> dict:
        return cls.__lnk_time_fields

    @classmethod
    def lnk_uuid_fields(cls) -> tuple:
        return cls.__lnk_uuid_fields

    @classmethod
    def location_meta_mapping(cls, field: str) -> Union[str, None]:
        return cls.__location_meta_mapping.get(field)

    @classmethod
    def malware_sample_additional_observable_values(cls) -> dict:
        return cls.__malware_sample_additional_observable_values

    @classmethod
    def malware_sample_additional_pattern_values(cls) -> str:
        return cls.__malware_sample_additional_pattern_values

    @classmethod
    def netflow_uuid_fields(cls) -> tuple:
        return cls.__netflow_uuid_fields

    @classmethod
    def network_socket_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__network_socket_mapping.get(field)

    @classmethod
    def network_socket_single_fields(cls) -> tuple:
        return cls.__network_socket_single_fields

    @classmethod
    def network_traffic_uuid_fields(cls) -> tuple:
        return cls.__network_traffic_uuid_fields

    @classmethod
    def objects_mapping(cls, field: str) -> Union[str, None]:
        return cls.__objects_mapping.get(field)

    @classmethod
    def organization_object_mapping(cls) -> dict:
        return cls.__organization_object_mapping

    @classmethod
    def parent_process_fields(cls) -> tuple:
        return cls.__parent_process_fields

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
    def process_uuid_fields(cls) -> tuple:
        return cls.__process_uuid_fields

    @classmethod
    def regions_mapping(cls, field: str) -> Union[str, None]:
        return cls.__regions_mapping.get(field)

    @classmethod
    def sigma_object_mapping(cls, field: str) -> Union[str, None]:
        return cls.__sigma_object_mapping.get(field)

    @classmethod
    def suricata_object_mapping(cls, field: str) -> Union[str, None]:
        return cls.__suricata_object_mapping.get(field)

    @classmethod
    def tlp_markings(cls, field: str) -> Union[MarkingDefinition, None]:
        return cls.__tlp_markings.get(field)

    @classmethod
    def user_account_object_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__user_account_object_mapping.get(field)

    @classmethod
    def yara_object_mapping(cls, field: str) -> Union[str, None]:
        return cls.__yara_object_mapping.get(field)
