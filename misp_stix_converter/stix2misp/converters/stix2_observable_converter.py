#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ... import Mapping
from .stix2mapping import (
    ExternalSTIX2Mapping, InternalSTIX2Mapping, STIX2Mapping)
from abc import ABCMeta
from stix2.v21.observables import (
    Artifact, Directory, DomainName, EmailAddress, EmailMessage, File,
    IPv4Address, IPv6Address, MACAddress, NetworkTraffic, Process, Software,
    UserAccount, WindowsRegistryKey, WindowsRegistryValueType, X509Certificate)
from typing import Tuple, Union

# TYPINGS
_IP_OBSERVABLE_TYPING = Union[
    IPv4Address, IPv6Address
]
_NETWORK_TRAFFIC_REFERENCE_TYPING = Union[
    DomainName, IPv4Address, IPv6Address, MACAddress
]


class STIX2ObservableMapping(STIX2Mapping, metaclass=ABCMeta):
    __artifact_object_mapping = Mapping(
        decryption_key={'type': 'text', 'object_relation': 'decryption_key'},
        encyption_algorithm={
            'type': 'text', 'object_relation': 'encryption_algorithm'
        },
        mime_type={'type': 'mime-type', 'object_relation': 'mime_type'},
        payload_bin={'type': 'text', 'object_relation': 'payload_bin'},
        url=STIX2Mapping.url_attribute()
    )
    __software_object_mapping = Mapping(
        cpe={'type': 'cpe', 'object_relation': 'cpe'},
        languages={'type': 'text', 'object_relation': 'language'},
        name={'type': 'text', 'object_relation': 'name'},
        swid={'type': 'text', 'object_relation': 'swid'},
        vendor={'type': 'text', 'object_relation': 'vendor'},
        version={'type': 'text', 'object_relation': 'version'}
    )

    @classmethod
    def artifact_object_mapping(cls) -> dict:
        return cls.__artifact_object_mapping

    @classmethod
    def software_object_mapping(cls) -> dict:
        return cls.__software_object_mapping


class ExternalSTIX2ObservableMapping(
        STIX2ObservableMapping, ExternalSTIX2Mapping):
    __network_traffic_reference_mapping = Mapping(
        **{
            'domain-name_dst': 'hostname-dst',
            'domain-name_src': 'hostname-src',
            'ipv4-addr_dst': 'ip-dst',
            'ipv4-addr_src': 'ip-src',
            'ipv6-addr_dst': 'ip-dst',
            'ipv6-addr_src': 'ip-src',
            'mac-address_dst': 'mac-dst',
            'mac-address_src': 'mad-src'
        }
    )
    __x509_hashes_mapping = Mapping(
        **{
            'MD5': STIX2Mapping.x509_md5_attribute(),
            'SHA-1': STIX2Mapping.x509_sha1_attribute(),
            'SHA-256': STIX2Mapping.x509_sha256_attribute()
        }
    )

    @classmethod
    def network_traffic_reference_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__network_traffic_reference_mapping.get(field)

    @classmethod
    def x509_hashes_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__x509_hashes_mapping.get(field)


class InternalSTIX2ObservableMapping(
        STIX2ObservableMapping, InternalSTIX2Mapping):
    pass


class STIX2ObservableConverter:
    def _parse_artifact_observable(self, observable: Artifact):
        if hasattr(observable, 'hashes'):
            for hash_type, value in observable.hashes.items():
                attribute = self._mapping.file_hashes_mapping(hash_type)
                if attribute is None:
                    self.main_parser.hash_type_error(hash_type)
                    continue
                yield from self._populate_object_attributes(
                    attribute, value, observable.id
                )
        for field, mapping in self._mapping.artifact_object_mapping().items():
            if hasattr(observable, field):
                yield from self._populate_object_attributes(
                    mapping, getattr(observable, field), observable.id
                )

    def _parse_directory_observable(self, observable: Directory):
        for field, mapping in self._mapping.directory_object_mapping().items():
            if hasattr(observable, field):
                yield from self._populate_object_attributes(
                    mapping, getattr(observable, field), observable.id
                )

    def _parse_domain_observable(self, observable: DomainName) -> Tuple:
        return 'domain', observable.value, {
            'uuid': self.main_parser._create_v5_uuid(
                f'{observable.id} - domain - {observable.value}'
            )
        }

    def _parse_email_additional_header(self, observable: EmailMessage):
        mapping = self._mapping.email_additional_header_fields
        email_header = observable.additional_header_fields
        for field, attribute in mapping().items():
            if email_header.get(field):
                yield from self._populate_object_attributes(
                    attribute, email_header[field], observable.id
                )

    def _parse_email_message_observable(self, observable: EmailMessage):
        for field, mapping in self._mapping.email_object_mapping().items():
            if hasattr(observable, field):
                yield from self._populate_object_attributes(
                    mapping, getattr(observable, field), observable.id
                )

    def _parse_email_reference_observable(
            self, observable: EmailAddress, feature: str):
        yield feature, observable.value, {
            'uuid': self.main_parser._create_v5_uuid(
                f'{observable.id} - {feature} - {observable.value}'
            )
        }
        if hasattr(observable, 'display_name'):
            relation = f'{feature}-display-name'
            yield relation, observable.display_name, {
                'uuid': self.main_parser._create_v5_uuid(
                    f'{observable.id} - {relation} - {observable.display_name}'
                )
            }

    def _parse_file_observable(self, observable: File):
        if hasattr(observable, 'hashes'):
            for hash_type, value in observable.hashes.items():
                attribute = self._mapping.file_hashes_mapping(hash_type)
                if attribute is None:
                    self.main_parser.hash_type_error(hash_type)
                    continue
                yield from self._populate_object_attributes(
                    attribute, value, observable.id
                )
        for field, mapping in self._mapping.file_object_mapping().items():
            if hasattr(observable, field):
                yield from self._populate_object_attributes(
                    mapping, getattr(observable, field), observable.id
                )

    def _parse_ip_belonging_to_AS_observable(
            self, observable: _IP_OBSERVABLE_TYPING) -> Tuple:
        return 'subnet-announced', observable.value, {
            'uuid': self.main_parser._create_v5_uuid(
                f'{observable.id} - subnet-announced - {observable.value}'
            )
        }

    def _parse_ip_observable(self, observable: _IP_OBSERVABLE_TYPING) -> Tuple:
        return 'ip', observable.value, {
            'uuid': self.main_parser._create_v5_uuid(
                f'{observable.id} - ip - {observable.value}'
            )
        }

    def _parse_network_connection_observable(self, observable: NetworkTraffic):
        for protocol in observable.protocols:
            layer = self._mapping.connection_protocols(protocol)
            if layer is not None:
                yield f'layer{layer}-protocol', protocol, {
                    'uuid': self.main_parser._create_v5_uuid(
                        f'{observable.id} - layer{layer}-protocol - {protocol}'
                    )
                }

    def _parse_network_socket_observable(self, observable: NetworkTraffic):
        for protocol in observable.protocols:
            yield {
                'type': 'text', 'object_relation': 'protocol',
                'value': protocol, 'uuid': self.main_parser._create_v5_uuid(
                    f'{observable.id} - protocol - {protocol}'
                )
            }
        socket_extension = observable.extensions['socket-ext']
        mapping = self._mapping.network_socket_extension_object_mapping
        for field, attribute in mapping().items():
            if hasattr(socket_extension, field):
                yield from self._populate_object_attributes(
                    attribute, getattr(socket_extension, field), observable.id
                )
        for feature in ('blocking', 'listening'):
            if getattr(socket_extension, f'is_{feature}', False):
                yield {
                    'type': 'text', 'object_relation': 'state',
                    'value': feature, 'uuid': self.main_parser._create_v5_uuid(
                        f'{observable.id} - state - {feature}'
                    )
                }

    def _parse_network_traffic_observable(self, observable: NetworkTraffic):
        mapping = self._mapping.network_traffic_object_mapping
        for field, attribute in mapping().items():
            if hasattr(observable, field):
                yield from self._populate_object_attributes(
                    attribute, getattr(observable, field), observable.id
                )

    def _parse_network_traffic_reference_observable(
            self, asset: str, observable: _NETWORK_TRAFFIC_REFERENCE_TYPING):
        relation = self._mapping.network_traffic_reference_mapping(
            f'{observable.type}_{asset}'
        )
        if relation is not None:
            yield relation, observable.value, {
                'uuid': self.main_parser._sanitise_uuid(observable.id)
            }

    def _parse_process_observable(self, observable: Process):
        for field, mapping in self._mapping.process_object_mapping().items():
            if hasattr(observable, field):
                yield from self._populate_object_attributes(
                    mapping, getattr(observable, field), observable.id
                )
        for feature in ('environment_variables', 'arguments'):
            if hasattr(observable, feature):
                value = ' '.join(
                    f'{key} {value}' for key, value in
                    getattr(observable, feature).items()
                )
                yield {
                    'type': 'text', 'object_relation': 'args', 'value': value,
                    'uuid': self.main_parser._create_v5_uuid(
                        f'{observable.id} - args - {value}'
                    )
                }
                break

    def _parse_registry_key_observable(self, observable: WindowsRegistryKey):
        mapping = self._mapping.registry_key_object_mapping
        for field, attribute in mapping().items():
            if hasattr(observable, field):
                yield from self._populate_object_attributes(
                    attribute, getattr(observable, field), observable.id
                )
        if len(observable.get('values', [])) == 1:
            registry_key_value = observable['values'][0]
            values_mapping = self._mapping.registry_key_values_mapping
            for field, attribute in values_mapping().items():
                if hasattr(registry_key_value, field):
                    yield from self._populate_object_attributes(
                        attribute, getattr(registry_key_value, field),
                        observable.id
                    )

    def _parse_registry_key_value_observable(
            self, observable: WindowsRegistryValueType, reference: str):
        mapping = self._mapping.registry_key_values_mapping
        for field, attribute in mapping().items():
            if hasattr(observable, field):
                yield from self._populate_object_attributes(
                    attribute, getattr(observable, field), reference
                )

    def _parse_software_observable(self, observable: Software):
        for field, mapping in self._mapping.software_object_mapping().items():
            if hasattr(observable, field):
                yield from self._populate_object_attributes(
                    mapping, getattr(observable, field), observable.id
                )

    def _parse_user_account_observable(self, observable: UserAccount):
        user_account_mapping = self._mapping.user_account_object_mapping
        for field, mapping in user_account_mapping().items():
            if hasattr(observable, field):
                yield from self._populate_object_attributes(
                    mapping, getattr(observable, field), observable.id
                )
        if 'unix-account-ext' in getattr(observable, 'extensions', {}):
            extension = observable.extensions['unix-account-ext']
            extension_mapping = getattr(
                self._mapping, 'unix_user_account_extension_mapping'
            )
            for field, mapping in extension_mapping().items():
                if hasattr(extension, field):
                    yield from self._populate_object_attributes(
                        mapping, getattr(extension, field), observable.id
                    )

    def _parse_x509_observable(self, observable: X509Certificate):
        for field, mapping in self._mapping.x509_object_mapping().items():
            if hasattr(observable, field):
                yield from self._populate_object_attributes(
                    mapping, getattr(observable, field), observable.id
                )
        if hasattr(observable, 'hashes'):
            for hash_type, hash_value in observable.hashes.items():
                attribute = self._mapping.x509_hashes_mapping.get(hash_type)
                if attribute is not None:
                    yield from self._populate_object_attributes(
                        attribute, hash_value, observable.id
                    )

    def _populate_object_attributes(
            self, mapping: dict, values: Union[list, str], observable_id: str):
        reference = f"{observable_id} - {mapping['object_relation']}"
        if isinstance(values, list):
            for value in values:
                yield {
                    'value': value, **mapping,
                    'uuid': self.main_parser._create_v5_uuid(
                        f'{reference} - {value}'
                    )
                }
        else:
            yield {
                'value': values, **mapping,
                'uuid': self.main_parser._create_v5_uuid(
                    f'{reference} - {values}'
                )
            }
