#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ... import Mapping
from .stix2converter import (
    ExternalSTIX2Converter, InternalSTIX2Converter, STIX2Converter)
from .stix2mapping import (
    ExternalSTIX2Mapping, InternalSTIX2Mapping, STIX2Mapping)
from abc import ABCMeta
from pymisp import MISPObject
from stix2.v20.observables import (
    Artifact as Artifact_v20, AutonomousSystem as AutonomousSystem_v20,
    Directory as Directory_v20, DomainName as DomainName_v20,
    EmailAddress as EmailAddress_v20, EmailMessage as EmailMessage_v20,
    File as File_v20, HTTPRequestExt as HTTPRequestExt_v20, Mutex as Mutex_v20,
    NetworkTraffic as NetworkTraffic_v20, Process as Process_v20,
    Software as Software_v20, UNIXAccountExt as UNIXAccountExt_v20,
    URL as URL_v20, UserAccount as UserAccount_v20,
    WindowsPEBinaryExt as WindowsExtension_v20,
    WindowsPESection as WindowsPESection_v20,
    WindowsRegistryKey as WindowsRegistryKey_v20,
    WindowsRegistryValueType as WindowsRegistryValue_v20,
    X509Certificate as X509Certificate_v20)
from stix2.v21.observables import (
    Artifact as Artifact_v21, AutonomousSystem as AutonomousSystem_v21,
    Directory as Directory_v21, DomainName as DomainName_v21,
    EmailAddress as EmailAddress_v21, EmailMessage as EmailMessage_v21,
    File as File_v21, HTTPRequestExt as HTTPRequestExt_v21, IPv4Address, IPv6Address,
    Mutex as Mutex_v21, MACAddress, NetworkTraffic as NetworkTraffic_v21,
    Process as Process_v21, Software as Software_v21,
    UNIXAccountExt as UNIXAccountExt_v21, URL as URL_v21,
    UserAccount as UserAccount_v21, WindowsPEBinaryExt as WindowsExtension_v21,
    WindowsPESection as WindowsPESection_v21,
    WindowsRegistryKey as WindowsRegistryKey_v21,
    WindowsRegistryValueType as WindowsRegistryValue_v21,
    X509Certificate as X509Certificate_v21)
from typing import Iterator, Optional, Tuple, Union

# TYPINGS
_ARTIFACT_TYPING = Union[
    Artifact_v20, Artifact_v21
]
_AUTONOMOUS_SYSTEM_TYPING = Union[
    AutonomousSystem_v20, AutonomousSystem_v21
]
_DIRECTORY_TYPING = Union[
    Directory_v20, Directory_v21
]
_DOMAIN_TYPING = Union[
    DomainName_v20, DomainName_v21
]
_EMAIL_ADDRESS_TYPING = Union[
    EmailAddress_v20, EmailAddress_v21
]
_EMAIL_ATTACHMENT_TYPING = Union[
    Artifact_v20, Artifact_v20,
    File_v20, File_v21
]
_EMAIL_MESSAGE_TYPING = Union[
    EmailMessage_v20, EmailMessage_v21
]
_EXTENSION_TYPING = Union[
    WindowsExtension_v20,
    WindowsExtension_v21
]
_FILE_TYPING = Union[
    File_v20, File_v21
]
_HTTP_REQUEST_EXTENSION_TYPING = Union[
    HTTPRequestExt_v20, HTTPRequestExt_v21
]
_IP_OBSERVABLE_TYPING = Union[
    IPv4Address, IPv6Address
]
_NETWORK_TRAFFIC_REFERENCE_TYPING = Union[
    DomainName_v21, IPv4Address, IPv6Address, MACAddress
]
_NETWORK_TRAFFIC_TYPING = Union[
    NetworkTraffic_v20, NetworkTraffic_v21
]
_OBSERVABLE_TYPING = Union[
    EmailMessage_v20, EmailMessage_v21,
    Mutex_v20, Mutex_v21,
    NetworkTraffic_v20, NetworkTraffic_v21,
    WindowsRegistryValue_v20, WindowsRegistryValue_v21,
    Software_v20, Software_v21,
    UNIXAccountExt_v20, UNIXAccountExt_v21,
    URL_v20, URL_v21,
    UserAccount_v20, UserAccount_v21,
]
_PROCESS_TYPING = Union[
    Process_v20, Process_v21
]
_REGISTRY_KEY_TYPING = Union[
    WindowsRegistryKey_v20, WindowsRegistryKey_v21
]
_SECTION_TYPING = Union[
    WindowsPESection_v20, WindowsPESection_v21
]
_URL_TYPING = Union[
    URL_v20, URL_v21
]
_USER_ACCOUNT_TYPING = Union[
    UserAccount_v20, UserAccount_v21
]
_X509_CERTIFICATE_TYPING = Union[
    X509Certificate_v20, X509Certificate_v21
]


class STIX2ObservableMapping(STIX2Mapping, metaclass=ABCMeta):
    __artifact_object_mapping = Mapping(
        decryption_key={'type': 'text', 'object_relation': 'decryption_key'},
        encyption_algorithm={
            'type': 'text', 'object_relation': 'encryption_algorithm'
        },
        mime_type={'type': 'mime-type', 'object_relation': 'mime_type'},
        url=STIX2Mapping.url_attribute()
    )
    __email_additional_header_fields_mapping = Mapping(
        **{
            'Reply-To': STIX2Mapping.reply_to_attribute(),
            'X-Mailer': STIX2Mapping.x_mailer_attribute(),
            'X-Originating-IP': STIX2Mapping.received_header_ip_attribute(),
        }
    )
    __dst_ip_attribute = {'type': 'ip-dst', 'object_relation': 'dst_ip'}
    __src_ip_attribute = {'type': 'ip-src', 'object_relation': 'src_ip'}
    __generic_network_traffic_reference_mapping = Mapping(
        **{
            'domain-name_dst': {'type': 'hostname', 'object_relation': 'dst_hostname'},
            'domain-name_src': {'type': 'hostname', 'object_relation': 'src_hostname'},
            'ipv4-addr_dst': __dst_ip_attribute,
            'ipv4-addr_src': __src_ip_attribute,
            'ipv6-addr_dst': __dst_ip_attribute,
            'ipv6-addr_src': __src_ip_attribute,
            'mac-address_dst': {'type': 'mac-address', 'object_relation': 'dst_mac'},
            'mac-address_src': {'type': 'mac-address', 'object_relation': 'src_mac'}
        }
    )
    __network_traffic_reference_mapping = Mapping(
        **{
            'domain-name_dst': STIX2Mapping.hostname_dst_attribute(),
            'domain-name_src': STIX2Mapping.hostname_src_attribute(),
            'ipv4-addr_dst': STIX2Mapping.ip_dst_attribute(),
            'ipv4-addr_src': STIX2Mapping.ip_src_attribute(),
            'ipv6-addr_dst': STIX2Mapping.ip_dst_attribute(),
            'ipv6-addr_src': STIX2Mapping.ip_src_attribute(),
            'mac-address_dst': {'type': 'mac-address', 'object_relation': 'mac-dst'},
            'mac-address_src': {'type': 'mac-address', 'object_relation': 'mac-src'}
        }
    )
    __software_object_mapping = Mapping(
        cpe={'type': 'cpe', 'object_relation': 'cpe'},
        languages={'type': 'text', 'object_relation': 'language'},
        name={'type': 'text', 'object_relation': 'name'},
        swid={'type': 'text', 'object_relation': 'swid'},
        vendor={'type': 'text', 'object_relation': 'vendor'},
        version={'type': 'text', 'object_relation': 'version'}
    )
    __x509_hashes_mapping = Mapping(
        **{
            'MD5': STIX2Mapping.x509_md5_attribute(),
            'SHA-1': STIX2Mapping.x509_sha1_attribute(),
            'SHA-256': STIX2Mapping.x509_sha256_attribute()
        }
    )

    @classmethod
    def artifact_object_mapping(cls) -> dict:
        return cls.__artifact_object_mapping

    @classmethod
    def email_additional_header_fields_mapping(cls) -> dict:
        return cls.__email_additional_header_fields_mapping

    @classmethod
    def network_traffic_reference_mapping(cls, field: str) -> dict:
        return cls.__generic_network_traffic_reference_mapping.get(field)

    @classmethod
    def network_socket_reference_mapping(cls, field: str) -> dict:
        return cls.__network_traffic_reference_mapping.get(field)

    @classmethod
    def network_traffic_references(cls) -> dict:
        return cls.__network_traffic_reference_mapping

    @classmethod
    def software_object_mapping(cls) -> dict:
        return cls.__software_object_mapping

    @classmethod
    def x509_hashes_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__x509_hashes_mapping.get(field)


class STIX2ObservableConverter(STIX2Converter):
    def _handle_misp_object_storage(
            self, observable: dict, misp_object: MISPObject):
        observable['used'][self.event_uuid] = True
        if observable.get('misp_object') is None:
            observable['misp_object'] = misp_object
        elif isinstance(observable['misp_object'], list):
            observable['misp_object'].append(misp_object)
        else:
            observable['misp_object'] = [observable['misp_object'], misp_object]

    def _parse_email_observable(
            self, observable: _EMAIL_MESSAGE_TYPING,
            object_id: Optional[str] = None) -> Iterator[dict]:
        if object_id is None:
            object_id = observable.id
        for field, attribute in self._mapping.email_object_mapping().items():
            if hasattr(observable, field):
                yield from self._populate_object_attributes(
                    attribute, getattr(observable, field), object_id
                )
        if hasattr(observable, 'additional_header_fields'):
            mapping = self._mapping.email_additional_header_fields_mapping
            email_header = observable.additional_header_fields
            for field, attribute in mapping().items():
                if email_header.get(field):
                    yield from self._populate_object_attributes(
                        attribute, email_header[field], object_id
                    )

    def _parse_email_reference_observable(
            self, observable: _EMAIL_ADDRESS_TYPING, feature: str,
            object_id: Optional[str] = None) -> Iterator[dict]:
        if object_id is None:
            object_id = observable.id
        if hasattr(observable, 'display_name'):
            yield {
                'value': observable.value,
                **getattr(self._mapping, f'{feature}_attribute')(),
                'uuid': self.main_parser._create_v5_uuid(
                    f'{object_id} - {feature} - {observable.value}'
                )
            }
            relation = f'{feature}-display-name'
            attribute = getattr(
                self._mapping, f"{relation.replace('-', '_')}_attribute"
            )
            yield {
                'value': observable.display_name, **attribute(),
                'uuid': self.main_parser._create_v5_uuid(
                    f'{object_id} - {relation} - {observable.display_name}'
                )
            }
        else:
            attribute = {
                'value': observable.value,
                **getattr(self._mapping, f'{feature}_attribute')()
            }
            if hasattr(observable, 'id'):
                attribute.update(
                    self.main_parser._sanitise_attribute_uuid(object_id)
                )
            else:
                attribute['uuid'] = self.main_parser._create_v5_uuid(
                    f'{object_id} - {feature} - {observable.value}'
                )
            yield attribute

    def _parse_file_observable(
            self, observable: _FILE_TYPING,
            object_id: Optional[str] = None) -> Iterator[dict]:
        if object_id is None:
            object_id = observable.id
        if hasattr(observable, 'hashes'):
            for hash_type, value in observable.hashes.items():
                attribute = self._mapping.file_hashes_mapping(hash_type)
                if attribute is None:
                    self.main_parser._add_error(
                        f'Wrong hash_type: {hash_type}'
                    )
                    continue
                yield from self._populate_object_attributes(
                    attribute, value, object_id
                )
        for field, mapping in self._mapping.file_object_mapping().items():
            if hasattr(observable, field):
                yield from self._populate_object_attributes_with_data(
                    mapping, getattr(observable, field), object_id
                )
    
    def _parse_generic_observable(
            self, observable: _OBSERVABLE_TYPING, name: str,
            object_id: Optional[str] = None) -> Iterator[dict]:
        if object_id is None:
            object_id = observable.id
        feature = f'{name}_object_mapping'
        for field, mapping in getattr(self._mapping, feature)().items():
            if hasattr(observable, field):
                yield from self._populate_object_attributes(
                    mapping, getattr(observable, field), object_id
                )

    def _parse_network_socket_observable(
            self, observable: _NETWORK_TRAFFIC_TYPING,
            object_id: Optional[str] = None) -> Iterator[dict]:
        if object_id is None:
            object_id = observable.id
        for protocol in observable.protocols:
            protocol_value = protocol.upper()
            yield {
                'value': protocol_value, **self._mapping.protocol_attribute(),
                'uuid': self.main_parser._create_v5_uuid(
                    f'{object_id} - protocol - {protocol_value}'
                )
            }
        socket_extension = observable.extensions['socket-ext']
        mapping = self._mapping.network_socket_extension_mapping
        for field, attribute in mapping().items():
            if hasattr(socket_extension, field):
                yield from self._populate_object_attributes(
                    attribute, getattr(socket_extension, field), object_id
                )
        for feature in ('blocking', 'listening'):
            if getattr(socket_extension, f'is_{feature}', False):
                yield {
                    **self._mapping.state_attribute(),
                    'value': feature, 'uuid': self.main_parser._create_v5_uuid(
                        f'{object_id} - state - {feature}'
                    )
                }

    def _parse_network_traffic_observable(
            self, observable: _NETWORK_TRAFFIC_TYPING,
            object_id: Optional[str] = None) -> Iterator[dict]:
        if object_id is None:
            object_id = observable.id
        mapping = self._mapping.network_traffic_object_mapping()
        for field, attribute in mapping.items():
            if hasattr(observable, field):
                yield from self._populate_object_attributes(
                    attribute, getattr(observable, field), object_id
                )
        for protocol in observable.protocols:
            protocol_value = protocol.upper()
            yield {
                'value': protocol_value, **self._mapping.protocol_attribute(),
                'uuid': self.main_parser._create_v5_uuid(
                    f'{object_id} - protocol - {protocol_value}'
                )
            }

    def _parse_network_traffic_reference_observable(
            self, asset: str, observable: _NETWORK_TRAFFIC_REFERENCE_TYPING,
            object_id: str, name: Optional[str] = 'network_traffic'):
        attribute = getattr(self._mapping, f'{name}_reference_mapping')(
            f'{observable.type}_{asset}'
        )
        if attribute is not None:
            yield {
                'value': observable.value, **attribute,
                'uuid': self.main_parser._create_v5_uuid(
                    f"{object_id} - {attribute['object_relation']}"
                    f' - {observable.value}'
                )
            }

    def _parse_pe_extension_observable(self, extension: _EXTENSION_TYPING,
                                       reference: str) -> Iterator[dict]:
        if hasattr(extension, 'optional_header'):
            if hasattr(extension.optional_header, 'address_of_entry_point'):
                yield from self._populate_object_attributes(
                    self._mapping.entrypoint_address_attribute(),
                    extension.optional_header.address_of_entry_point,
                    reference
                )
        for field, mapping in self._mapping.pe_object_mapping().items():
            if hasattr(extension, field):
                yield from self._populate_object_attributes(
                    mapping, getattr(extension, field), reference
                )

    def _parse_pe_section_observable(self, section: _SECTION_TYPING,
                                     reference: str) -> Iterator[dict]:
        for field, mapping in self._mapping.pe_section_object_mapping().items():
            if hasattr(section, field):
                yield from self._populate_object_attributes(
                    mapping, getattr(section, field), reference
                )
        if hasattr(section, 'hashes'):
            for hash_type, hash_value in section.hashes.items():
                attribute = self._mapping.file_hashes_mapping(hash_type)
                if attribute is None:
                    self.main_parser.hash_type_error(hash_type)
                    continue
                yield from self._populate_object_attributes(
                    attribute, hash_value, reference
                )

    def _parse_process_observable(
            self, observable: _PROCESS_TYPING,
            object_id: Optional[str] = None) -> Iterator[dict]:
        if object_id is None:
            object_id = observable.id
        for field, mapping in self._mapping.process_object_mapping().items():
            if hasattr(observable, field):
                yield from self._populate_object_attributes(
                    mapping, getattr(observable, field), object_id
                )
        if hasattr(observable, 'arguments'):
            value = ' '.join(observable.arguments)
            yield {
                **self._mappping.args_attribute(),
                'value': value, 'uuid': self.main_parser._create_v5_uuid(
                    f'{object_id} -  args - {value}'
                )
            }
        if hasattr(observable, 'environment_variables'):
            value = ' - '.join(
                f'{key}: {value}' for key, value in
                observable.environment_variables.items()
            )
            yield {
                **self._mapping.environment_variables_attribute(),
                'value': value, 'uuid': self.main_parser._create_v5_uuid(
                    f'{object_id} - environment-variables - {value}'
                )
            }

    def _parse_registry_key_observable(
            self, observable: _REGISTRY_KEY_TYPING,
            object_id: Optional[str] = None) -> Iterator[dict]:
        if object_id is None:
            object_id = observable.id
        mapping = self._mapping.registry_key_object_mapping
        for field, attribute in mapping().items():
            if hasattr(observable, field):
                yield from self._populate_object_attributes(
                    attribute, getattr(observable, field), object_id
                )
        if len(observable.get('values', [])) == 1:
            registry_key_value = observable['values'][0]
            values_mapping = self._mapping.registry_key_values_mapping
            for field, attribute in values_mapping().items():
                if hasattr(registry_key_value, field):
                    yield from self._populate_object_attributes(
                        attribute, getattr(registry_key_value, field), object_id
                    )

    def _parse_x509_observable(
            self, observable: _X509_CERTIFICATE_TYPING,
            object_id: Optional[str] = None) -> Iterator[dict]:
        if object_id is None:
            object_id = observable.id
        if hasattr(observable, 'hashes'):
            for hash_type, hash_value in observable.hashes.items():
                attribute = self._mapping.x509_hashes_mapping(hash_type)
                if attribute is not None:
                    yield from self._populate_object_attributes(
                        attribute, hash_value, object_id
                    )
        for field, mapping in self._mapping.x509_object_mapping().items():
            if hasattr(observable, field):
                yield from self._populate_object_attributes(
                    mapping, getattr(observable, field), object_id
                )


class ExternalSTIX2ObservableMapping(
        STIX2ObservableMapping, ExternalSTIX2Mapping):
    __observable_mapping = Mapping(
        **{
            'artifact': 'artifact',
            'autonomous-system': 'as',
            'directory': 'directory',
            'domain-name': 'domain',
            'email-addr': 'email_address',
            'mac-addr': 'mac_address',
            'mutex': 'mutex',
            'software': 'software',
            'url': 'url',
            'user-account': 'user_account',
            'x509-certificate': 'x509',
            **dict.fromkeys(
                (
                    'autonomous-system_ipv4-addr',
                    'autonomous-system_ipv6-addr',
                    'autonomous-system_ipv4-addr_ipv6-addr'
                ),
                'asn'
            ),
            **dict.fromkeys(
                (
                    'domain-name_ipv4-addr',
                    'domain-name_ipv6-addr',
                    'domain-name_ipv4-addr_ipv6-addr'
                ),
                'domain_ip'
            ),
            **dict.fromkeys(
                (
                    'artifact_email-addr_email-message',
                    'artifact_email-addr_email-message_file',
                    'artifact_email-message',
                    'email-addr_email-message',
                    'email-addr_email-message_file',
                    'email-message',
                    'email-message_file'
                ),
                'email_message'
            ),
            **dict.fromkeys(
                (
                    'artifact_file',
                    'artifact_directory_file',
                    'directory_file',
                    'file'
                ),
                'file'
            ),
            **dict.fromkeys(
                (
                    'ipv4-addr',
                    'ipv4-addr_ipv6-addr',
                    'ipv6-addr'
                ),
                'ip_address'
            ),
            **dict.fromkeys(
                (
                    'domain-name_ipv4-addr_network-traffic',
                    'domain-name_ipv6-addr_network-traffic',
                    'domain-name_ipv4-addr_ipv6-addr_network-traffic',
                    'domain-name_ipv4-addr_mac-addr_network-traffic',
                    'domain-name_ipv6-addr_mac-addr_network-traffic',
                    'domain-name_ipv4-addr_ipv6-addr_mac-addr_network-traffic',
                    'domain-name_network-traffic',
                    'domain-name_network-traffic_url',
                    'ipv4-addr_network-traffic',
                    'ipv6-addr_network-traffic',
                    'ipv4-addr_ipv6-addr_network-traffic',
                    'mac-addr_network-traffic',
                    'mac-addr_ipv4-addr_network-traffic',
                    'mac-addr_ipv6-addr_network-traffic',
                    'mac-addr_ipv4-addr_ipv6-addr_network-traffic',
                    'network-traffic'
                ),
                'network_traffic'
            ),
            **dict.fromkeys(
                (
                    'file_process',
                    'process'
                ),
                'process'
            ),
            **dict.fromkeys(
                (
                    'user-account_windows-registry-key',
                    'windows-registry-key'
                ),
                'registry_key'
            )
        }
    )

    @classmethod
    def observable_mapping(cls, field: str) -> Union[str, None]:
        return cls.__observable_mapping.get(field)


class ExternalSTIX2ObservableConverter(
        STIX2ObservableConverter, ExternalSTIX2Converter):
    def _parse_artifact_observable(
            self, observable: _ARTIFACT_TYPING,
            object_id: Optional[str] = None) -> Iterator[dict]:
        if object_id is None:
            object_id = observable.id
        if hasattr(observable, 'payload_bin'):
            value = getattr(observable, 'id', object_id.split(' - ')[0])
            yield from self._populate_object_attributes_with_data(
                {'type': 'attachment', 'object_relation': 'payload_bin'},
                {'data': observable.payload_bin, 'value': value.split('--')[1]},
                object_id
            )
        if hasattr(observable, 'hashes'):
            for hash_type, value in observable.hashes.items():
                attribute = self._mapping.file_hashes_mapping(hash_type)
                if attribute is None:
                    self.main_parser.hash_type_error(hash_type)
                    continue
                yield from self._populate_object_attributes(
                    attribute, value, object_id
                )
        for field, mapping in self._mapping.artifact_object_mapping().items():
            if hasattr(observable, field):
                yield from self._populate_object_attributes(
                    mapping, getattr(observable, field), object_id
                )

    def _parse_asn_observable(
            self, observable: _AUTONOMOUS_SYSTEM_TYPING,
            observed_data_id: Optional[str] = None) -> Iterator:
        object_id = getattr(observable, 'id', observed_data_id)
        yield from self._populate_object_attributes(
            self._mapping.asn_attribute(),
            self._parse_AS_value(observable.number), object_id
        )
        if hasattr(observable, 'name'):
            yield from self._populate_object_attributes(
                self._mapping.description_attribute(), observable.name,
                object_id
            )

    def _parse_domain_observable(self, observable: _DOMAIN_TYPING,
                                 object_id: Optional[str] = None) -> dict:
        attribute = {
            'value': observable.value, **self._mapping.domain_attribute()
        }
        if object_id is None:
            attribute.update(
                self.main_parser._sanitise_attribute_uuid(observable.id)
            )
            return attribute
        attribute['uuid'] = self.main_parser._create_v5_uuid(
            f'{object_id} - domain - {observable.value}'
        )
        return attribute

    def _parse_ip_belonging_to_AS_observable(
            self, observable: _IP_OBSERVABLE_TYPING,
            object_id: Optional[str] = None) -> dict:
        attribute = {
            'value': observable.value,
            **self._mapping.subnet_announced_attribute()
        }
        if object_id is None:
            attribute.update(
                self.main_parser._sanitise_attribute_uuid(observable.id)
            )
            return attribute
        attribute['uuid'] = self.main_parser._create_v5_uuid(
            f'{object_id} - subnet-announced - {observable.value}'
        )
        return attribute

    def _parse_ip_observable(self, observable: _IP_OBSERVABLE_TYPING,
                             object_id: Optional[str] = None) -> dict:
        attribute = {
            'value': observable.value, **self._mapping.ip_attribute()
        }
        if object_id is None:
            attribute.update(
                self.main_parser._sanitise_attribute_uuid(observable.id)
            )
            return attribute
        attribute['uuid'] = self.main_parser._create_v5_uuid(
            f'{object_id} - ip - {observable.value}'
        )
        return attribute

    @staticmethod
    def _parse_network_traffic_observable_fields(
            observable: NetworkTraffic_v21) -> str:
        if getattr(observable, 'extensions', {}).get('socket-ext'):
            return 'network-socket'
        return 'network-traffic'

    def _parse_url_observable(self, observable: _URL_TYPING,
                              observed_data_id: str) -> Iterator[dict]:
        object_id = getattr(observable, 'id', observed_data_id)
        for field, mapping in self._mapping.url_object_mapping().items():
            if hasattr(observable, field):
                yield from self._populate_object_attributes(
                    mapping, getattr(observable, field), object_id
                )

    def _parse_user_account_observable(
            self, observable: _USER_ACCOUNT_TYPING,
            object_id: Optional[str] = None) -> Iterator[dict]:
        if object_id is None:
            object_id = observable.id
        user_account_mapping = self._mapping.user_account_object_mapping
        for field, attribute in user_account_mapping().items():
            if hasattr(observable, field):
                yield from self._populate_object_attributes(
                    attribute, getattr(observable, field), object_id
                )
        if 'unix-account-ext' in getattr(observable, 'extensions', {}):
            extension = observable.extensions['unix-account-ext']
            mapping = self._mapping.unix_user_account_extension_object_mapping
            for field, attribute in mapping().items():
                if hasattr(extension, field):
                    yield from self._populate_object_attributes(
                        attribute, getattr(extension, field), object_id
                    )


class InternalSTIX2ObservableMapping(
        STIX2ObservableMapping, InternalSTIX2Mapping):
    __attributes_mapping = Mapping(
        **{
            'AS': '_attribute_from_AS',
            'attachment': '_attribute_from_attachment',
            'domain': '_attribute_from_domain',
            'domain|ip': '_attribute_from_domain_ip',
            'email-attachment': '_attribute_from_email_attachment',
            'email-body': '_attribute_from_email_body',
            'email-header': '_attribute_from_email_header',
            'email-message-id': '_attribute_from_email_message_id',
            'email-reply-to': '_attribute_from_email_reply_to',
            'email-subject': '_attribute_from_email_subject',
            'email-x-mailer': '_attribute_from_email_x_mailer',
            'github-username': '_attribute_from_github_username',
            'hostname|port': '_attribute_from_hostname_port',
            'malware-sample': '_attribute_from_malware_sample',
            'regkey': '_attribute_from_regkey',
            'regkey|value': '_attribute_from_regkey_value',
            **dict.fromkeys(
                (
                    'domain', 'email', 'hostname', 'link', 'mac-address',
                    'mutex', 'uri', 'url'
                ),
                '_attribute_from_first'
            ),
            **dict.fromkeys(
                (
                    'authentihash', 'cdhash', 'imphash', 'impfuzzy', 'md5',
                    'pehash', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
                    'sha512/224', 'sha512/256', 'sha3-224', 'sha3-256',
                    'sha3-384', 'sha3-512', 'ssdeep', 'telfhash', 'tlsh',
                    'vhash', 'x509-fingerprint-md5', 'x509-fingerprint-sha1',
                    'x509-fingerprint-sha256'
                ),
                '_attribute_from_hash'
            ),
            **dict.fromkeys(
                (
                    'filename|authentihash', 'filename|imphash',
                    'filename|impfuzzy', 'filename|md5', 'filename|pehash',
                    'filename|sha1', 'filename|sha224', 'filename|sha256',
                    'filename|sha384', 'filename|sha512', 'filename|sha512/224',
                    'filename|sha512/256', 'filename|sha3-224',
                    'filename|sha3-256', 'filename|sha3-384',
                    'filename|sha3-512', 'filename|ssdeep', 'filename|tlsh',
                    'filename|vhash'
                ),
                '_attribute_from_filename_hash'
            ),
            **dict.fromkeys(
                (
                    'ip-src|port', 'ip-dst|port'
                ),
                '_attribute_from_ip_port'
            ),
            **dict.fromkeys(
                (
                    'filename', 'mutex'
                ),
                '_attribute_from_name'
            ),
            **dict.fromkeys(
                (
                    'email-dst', 'email-src', 'ip-src', 'ip-dst'
                ),
                '_attribute_from_address'
            )
        }
    )

    __malware_sample_attribute = Mapping(
        **{'type': 'malware-sample', 'object_relation': 'malware-sample'}
    )
    __http_request_extension_mapping = Mapping(
        request_method=STIX2Mapping.method_attribute(),
        request_value=STIX2Mapping.uri_attribute()
    )
    __http_request_header_mapping = Mapping(
        **{
            'Content-Type': STIX2Mapping.content_type_attribute(),
            'Cookie': STIX2Mapping.cookie_attribute(),
            'Referer': STIX2Mapping.referer_attribute(),
            'User-Agent': STIX2Mapping.user_agent_attribute()
        }
    )
    __parent_process_object_mapping = Mapping(
        command_line=InternalSTIX2Mapping.parent_command_line_attribute(),
        name=InternalSTIX2Mapping.parent_process_name_attribute(),
        x_misp_process_name=InternalSTIX2Mapping.parent_process_name_attribute(),
        pid=InternalSTIX2Mapping.parent_pid_attribute(),
        x_misp_guid=InternalSTIX2Mapping.parent_guid_attribute(),
        x_misp_process_path=InternalSTIX2Mapping.parent_process_path_attribute()
    )

    @classmethod
    def attributes_mapping(cls, field: str) -> Union[str, None]:
        return cls.__attributes_mapping.get(field)

    @classmethod
    def http_request_extension_mapping(cls) -> dict:
        return cls.__http_request_extension_mapping

    @classmethod
    def http_request_header_mapping(cls) -> dict:
        return cls.__http_request_header_mapping

    @classmethod
    def http_request_reference_mapping(cls, field: str) -> dict:
        return cls.network_traffic_references().get(field)

    @classmethod
    def malware_sample_attribute(cls) -> dict:
        return cls.__malware_sample_attribute

    @classmethod
    def network_connection_reference_mapping(cls, field: str) -> dict:
        return cls.network_traffic_references().get(field)

    @classmethod
    def parent_process_object_mapping(cls) -> dict:
        return cls.__parent_process_object_mapping


class InternalSTIX2ObservableConverter(
        STIX2ObservableConverter, InternalSTIX2Converter):
    def _has_domain_custom_fields(self, observable: DomainName_v21) -> bool:
        for feature in self._mapping.domain_ip_object_mapping():
            if feature == 'value':
                continue
            if hasattr(observable, feature):
                return True
        return False

    def _parse_asn_observable(self, observable: _AUTONOMOUS_SYSTEM_TYPING,
                              observed_data_id: str) -> Iterator[dict]:
        object_id = getattr(observable, 'id', observed_data_id)
        for field, mapping in self._mapping.asn_object_mapping().items():
            if hasattr(observable, field):
                value = getattr(observable, field)
                yield from self._populate_object_attributes(
                    mapping,
                    self._parse_AS_value(value) if field == 'number' else value,
                    object_id
                )

    def _parse_domain_ip_observable(
            self, observable: _DOMAIN_TYPING) -> Iterator[dict]:
        if self._has_domain_custom_fields(observable):
            mapping = self._mapping.domain_ip_object_mapping
            for field, attribute in mapping().items():
                if hasattr(observable, field):
                    yield from self._populate_object_attributes(
                        attribute, getattr(observable, field), observable.id
                    )
        else:
            yield {
                'value': observable.value,
                **self._mapping.domain_attribute(),
                **self.main_parser._sanitise_attribute_uuid(observable.id)
            }

    def _parse_email_body_observable(
            self, observable: _EMAIL_ATTACHMENT_TYPING, feature: str,
            value: str, object_id: str) -> Iterator[dict]:
        if observable.type == 'file':
            attribute = {
                'value': observable.name,
                **getattr(self._mapping, f'{feature}_attribute')()
            }
            if hasattr(observable, 'id'):
                attribute.update(
                    self.main_parser._sanitise_attribute_uuid(
                        observable.id
                    )
                )
            else:
                attribute['uuid'] = self.main_parser._create_v5_uuid(
                    f"{object_id} - {feature.replace('_', '-')}"
                    f' - {observable.name}'
                )
            yield attribute
        else:
            content = {
                'value': value.split('=').strip("'"),
                'data': observable.payload_bin
            }
            mapping = f'{feature}_attribute'
            if hasattr(observable, 'id'):
                yield {
                    **content, **getattr(self._mapping, mapping)(),
                    'uuid': self.main_parser._sanitise_attribute_uuid(
                        observable.id
                    )
                }
            else:
                yield from self._populate_object_attributes_with_data(
                    getattr(self._mapping, mapping)(), content, object_id
                )

    def _parse_file_parent_observable(self, observable: _DIRECTORY_TYPING,
                                      observed_data_id: str) -> dict:
        if hasattr(observable, 'id'):
            return {
                'value': observable.path, **self._mapping.path_attribute(),
                **self.main_parser._sanitise_attribute_uuid(observable.id)
            }
        return {
            'value': observable.path, **self._mapping.path_attribute(),
            'uuid': self.main_parser._create_v5_uuid(
                f'{observed_data_id} - path - {observable.path}'
            )
        }

    def _parse_generic_observable_with_data(
            self, observable: _USER_ACCOUNT_TYPING,
            name: str, observed_data_id: str) -> Iterator[dict]:
        feature = f'{name}_object_mapping'
        object_id = getattr(observable, 'id', observed_data_id)
        for feature, mapping in getattr(self._mapping, feature)().items():
            if hasattr(observable, feature):
                yield from self._populate_object_attributes_with_data(
                    mapping, getattr(observable, feature), object_id
                )

    def _parse_http_request_extension_observable(
            self, extension: _HTTP_REQUEST_EXTENSION_TYPING,
            object_id: str) -> Iterator[dict]:
        mapping = self._mapping.http_request_extension_mapping
        for field, attribute in mapping().items():
            if hasattr(extension, field):
                yield from self._populate_object_attributes(
                    attribute, getattr(extension, field), object_id
                )
        if hasattr(extension, 'request_header'):
            mapping = self._mapping.http_request_header_mapping
            for field, attribute in mapping().items():
                if extension.request_header.get(field):
                    yield from self._populate_object_attributes(
                        attribute, extension.request_header[field], object_id
                    )

    def _parse_image_attachment_observable(
            self, observable: _ARTIFACT_TYPING,
            observed_data_id: str) -> Iterator[dict]:
        attribute = {
            'value': observable.x_misp_filename,
            'data': observable.payload_bin
        }
        if hasattr(observable, 'id'):
            if hasattr(observable, 'x_misp_url'):
                yield from self._populate_object_attributes_with_data(
                    self._mapping.attachment_attribute(),
                    attribute, observable.id
                )
                yield from self._populate_object_attributes(
                    self._mapping.url_attribute(),
                    observable.x_misp_url, observable.id
                )
            else:
                yield {
                    **attribute, **self._mapping.attachment_attribute(),
                    **self.main_parser._sanitise_attribute_uuid(observable.id)
                }
        else:
            yield from self._populate_object_attributes_with_data(
                self._mapping.attachment_attribute(),
                attribute, observed_data_id
            )
            if hasattr(observable, 'x_misp_url'):
                yield from self._populate_object_attributes(
                    self._mapping.url_attribute(),
                    observable.x_misp_url, observed_data_id
                )
    
    def _parse_image_url_observable(self, observable: _ARTIFACT_TYPING,
                                    observed_data_id: str) -> Iterator[dict]:
        if hasattr(observable, 'id'):
            yield {
                'value': observable.url, **self._mapping.url_attribute(),
                'uuid': self.main_parser._sanitise_attribute_uuid(observable.id)
            }
        else:
            yield from self._populate_object_attributes(
                self._mapping.url_attribute(), observable.url, observed_data_id
            )

    def _parse_lnk_observable(self, observable: _FILE_TYPING,
                              observed_data_id: str) -> Iterator[dict]:
        object_id = getattr(observable, 'id', observed_data_id)
        if hasattr(observable, 'hashes'):
            for hash_type, value in observable.hashes.items():
                attribute = self._mapping.file_hashes_mapping(hash_type)
                if attribute is None:
                    self.main_parser.hash_type_error(hash_type)
                    continue
                yield from self._populate_object_attributes(
                    attribute, value, object_id
                )
        for feature, mapping in self._mapping.lnk_object_mapping().items():
            if hasattr(observable, feature):
                yield from self._populate_object_attributes(
                    mapping, getattr(observable, feature), object_id
                )

    def _parse_netflow_observable(self, observable: _NETWORK_TRAFFIC_TYPING,
                                  observed_data_id: str) -> Iterator[dict]:
        object_id = getattr(observable, 'id', observed_data_id)
        for feature, mapping in self._mapping.netflow_object_mapping().items():
            if hasattr(observable, feature):
                yield from self._populate_object_attributes(
                    mapping, getattr(observable, feature), object_id
                )
        protocols = {protocol: False for protocol in observable.protocols}
        if hasattr(observable, 'extensions'):
            if observable.extensions.get('tcp-ext'):
                tcp_extension = observable.extensions['tcp-ext']
                yield from self._populate_object_attributes(
                    self._mapping.tcp_flags_attribute(),
                    tcp_extension.src_flags_hex, object_id
                )
                if 'tcp' in protocols:
                    protocols['tcp'] = True
            if observable.extensions.get('icmp-ext'):
                icmp_extension = observable.extensions['icmp-ext']
                yield from self._populate_object_attributes(
                    self._mapping.icmp_type_attribute(),
                    icmp_extension.icmp_type_hex, object_id
                )
                if 'icmp' in protocols:
                    protocols['icmp'] = True
        for protocol, present in protocols.items():
            if not present:
                value = protocol.upper()
                yield {
                    'value': value, **self._mapping.protocol_attribute(),
                    'uuid': self.main_parser._create_v5_uuid(
                        f'{object_id} - protocol - {value}'
                    )
                }
                break
        else:
            if len(protocols) == 1:
                value = list(protocols.keys())[0].upper()
                yield {
                    'value': value, **self._mapping.protocol_attribute(),
                    'uuid': self.main_parser._create_v5_uuid(
                        f'{object_id} - protocol - {value}'
                    )
                }

    def _parse_netflow_references(
            self, feature: str, observed_data_id: str,
            *systems: Iterator[_AUTONOMOUS_SYSTEM_TYPING]) -> Iterator[dict]:
        as_attribute = getattr(self._mapping, f'{feature}_as_attribute')
        for observable in systems:
            value = self._parse_AS_value(observable.number)
            if hasattr(observable, 'id'):
                yield {
                    'value': value, **as_attribute(),
                    **self.main_parser._sanitise_attribute_uuid(observable.id)
                }
                continue
            yield {
                'value': value, **as_attribute(),
                'uuid': self.main_parser._create_v5_uuid(
                    f'{observed_data_id} - {feature}-as - {value}'
                )
            }

    def _parse_network_connection_observable(
            self, observable: _NETWORK_TRAFFIC_TYPING,
            object_id: Optional[str] = None) -> Iterator[dict]:
        if object_id is None:
            object_id = observable.id
        for protocol in observable.protocols:
            layer = self._mapping.connection_protocols(protocol)
            if layer is None:
                args = (
                    (object_id.split(' - ')[0].split('--')[1], 'Observed Data')
                    if ' - ' in object_id else
                    (object_id.split('--')[1], 'Network Traffic observable')
                )
                self.main_parser._unknown_network_protocol_warning(
                    protocol, *args
                )
                continue
            yield {
                'object_relation': f'layer{layer}-protocol',
                'type': 'text', 'value': protocol.upper(),
                'uuid': self.main_parser._create_v5_uuid(
                    f'{object_id} - layer{layer}-protocol - {protocol.upper()}'
                )
            }
