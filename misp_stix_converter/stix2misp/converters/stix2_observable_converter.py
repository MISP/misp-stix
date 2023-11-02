#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ... import Mapping
from .stix2converter import STIX2Converter
from .stix2mapping import (
    ExternalSTIX2Mapping, InternalSTIX2Mapping, STIX2Mapping)
from abc import ABCMeta
from pymisp import AbstractMISP, MISPAttribute, MISPObject
from stix2.v21.observables import (
    Artifact, Directory, DomainName, EmailAddress, EmailMessage, File,
    IPv4Address, IPv6Address, MACAddress, NetworkTraffic, Process, Software,
    UserAccount)
from stix2.v21.sdo import Malware
from typing import Dict, Optional, TYPE_CHECKING, Tuple, Union

if TYPE_CHECKING:
    from ..external_stix2_to_misp import ExternalSTIX2toMISPParser
    from .stix2_malware_converter import (
        ExternalSTIX2MalwareConverter, InternalSTIX2MalwareConverter)

_MISP_OBJECTS_PATH = AbstractMISP().misp_objects_path

# TYPINGS
_IP_OBSERVABLE_TYPING = Union[
    IPv4Address, IPv6Address
]
_MAIN_CONVERTER_TYPING = Union[
    'ExternalSTIX2MalwareConverter', 'InternalSTIX2MalwareConverter'
]
_MISP_CONTENT_TYPING = Union[
    MISPAttribute, MISPObject
]
_NETWORK_TRAFFIC_REFERENCE_TYPING = Union[
    DomainName, IPv4Address, IPv6Address, MACAddress
]
_OBSERVABLE_TYPING = Union[
    Artifact, Directory, DomainName, EmailMessage, File, NetworkTraffic,
    Process, Software, UserAccount
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

    @classmethod
    def network_traffic_reference_mapping(cls, field: str) -> Union[dict, None]:
        return cls.__network_traffic_reference_mapping.get(field)


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


class STIX2ObservableObjectConverter(STIX2Converter, STIX2ObservableConverter):
    def __init__(self, main: 'ExternalSTIX2toMISPParser'):
        self._set_main_parser(main)
        self._mapping = ExternalSTIX2ObservableMapping

    def _create_misp_attribute(
            self, attribute_type: str, observable: DomainName,
            feature: Optional[str] = 'value',
            **kwargs: Dict[str, str]) -> MISPAttribute:
        return {
            'value': getattr(observable, feature), 'type': attribute_type,
            **kwargs, **self.main_parser._sanitise_attribute_uuid(observable.id)
        }

    def _create_misp_object_from_observable_object(
            self, name: str, observable: _OBSERVABLE_TYPING) -> MISPObject:
        misp_object = MISPObject(
            name, force_timestamps=True,
            misp_objects_path_custom=_MISP_OBJECTS_PATH
        )
        self.main_parser._sanitise_object_uuid(
            misp_object, observable.get('id')
        )
        return misp_object

    def _parse_artifact_observable_object(
            self, artifact_ref: str) -> MISPObject:
        observable = self.main_parser._observable[artifact_ref]
        if observable['used'].get(self.event_uuid, False):
            return observable['misp_object']
        artifact = observable['observable']
        artifact_object = self._create_misp_object_from_observable_object(
            'artifact', artifact
        )
        for attribute in super()._parse_artifact_observable(artifact):
            artifact_object.add_attribute(**attribute)
        observable['used'][self.event_uuid] = True
        misp_object = self._main_parser._add_misp_object(
            artifact_object, artifact
        )
        observable['misp_object'] = misp_object
        return misp_object

    def _parse_as_observable_object(self, as_ref: str) -> _MISP_CONTENT_TYPING:
        observable = self.main_parser._observable[as_ref]
        if observable['used'].get(self.event_uuid, False):
            return observable.get(
                'misp_object', observable.get('misp_attribute')
            )
        autonomous_system = observable['observable']
        attributes = tuple(
            self._parse_ip_addresses_belonging_to_AS(autonomous_system.id)
        )
        observable['used'][self.event_uuid] = True
        if attributes:
            AS_object = self._create_misp_object_from_observable_object(
                'asn', autonomous_system
            )
            value = f'AS{autonomous_system.number}'
            AS_object.add_attribute(
                'asn', value,
                uuid=self.main_parser._create_v5_uuid(
                    f'{autonomous_system.id} - asn - {value}'
                )
            )
            for *attribute, kwargs in attributes:
                AS_object.add_attribute(*attribute, **kwargs)
            misp_object = self.main_parser._add_misp_object(
                AS_object, autonomous_system
            )
            observable['misp_object'] = misp_object
            return misp_object
        attribute = {
            'type': 'AS', 'value': f'AS{autonomous_system.number}',
            **self.main_parser._sanitise_attribute_uuid(autonomous_system.id)
        }
        misp_attribute = self.main_parser._add_misp_attribute(
            attribute, autonomous_system
        )
        observable['misp_attribute'] = misp_attribute
        return misp_attribute

    def _parse_directory_observable_object(
            self, directory_ref: str, child: Optional[str] = None
            ) -> _MISP_CONTENT_TYPING:
        observable = self.main_parser._observable[directory_ref]
        if observable['used'].get(self.event_uuid, False):
            return observable.get('misp_object', observable['misp_attribute'])
        directory = observable['observable']
        attributes = tuple(super()._parse_directory_observable(directory))
        observable['used'][self.event_uuid] = True
        force_object = (
            len(attributes) > 1 or any(
                ref != child for ref in getattr(directory, 'contains_refs', [])
            )
        )
        if force_object:
            directory_object = self._create_misp_object_from_observable_object(
                'directory', directory
            )
            for attribute in attributes:
                directory_object.add_attribute(**attribute)
            misp_object = self.main_parser._add_misp_object(
                directory_object, directory
            )
            observable['misp_object'] = misp_object
            if hasattr(directory, 'contains_refs'):
                for ref in directory.contains_refs:
                    feature = f"_parse_{ref.split('--')[0]}_observable_object"
                    referenced_object = (
                        self.main_parser._observable[child]['observable']
                        if child == ref else getattr(self, feature)(ref)
                    )
                    misp_object.add_reference(
                        referenced_object.uuid, 'contains'
                    )
            return misp_object
        if child is None:
            attribute = attributes[0]
            misp_attribute = self.main_parser._add_misp_attribute(
                {
                    'type': attribute['type'], 'value': attribute['value'],
                    **self.main_parser._sanitise_attribute_uuid(
                        directory.id
                    )
                },
                directory
            )
            observable['misp_attribute'] = misp_attribute
            return misp_attribute
        file_object = self.main_parser._observable[child]['observable']
        file_object.add_attribute(**attributes[0])
        observable['misp_object'] = file_object
        return misp_object

    def _parse_domain_observable_object(
            self, domain_ref: str) -> _MISP_CONTENT_TYPING:
        observable = self.main_parser._observable[domain_ref]
        if observable['used'].get(self.event_uuid, False):
            return observable.get(
                'misp_object', observable.get('misp_attribute')
            )
        domain_name = observable['observable']
        if hasattr(domain_name, 'resolves_to_refs'):
            domain_object = self._create_misp_object_from_observable_object(
                'domain-ip', domain_name
            )
            for attribute in super()._parse_domain_observable(domain_name):
                domain_object.add_attribute(**attribute)
            observable['used'][self.event_uuid] = True
            misp_object = self.main_parser._add_misp_object(
                domain_object, domain_name
            )
            observable['misp_object'] = misp_object
            for reference in domain_name.resolves_to_refs:
                if reference.split('--')[0] == 'domain-name':
                    referenced_domain = self._parse_domain_observable_object(
                        reference
                    )
                    misp_object.add_reference(
                        referenced_domain.uuid, 'resolves-to'
                    )
                    continue
                resolved_ip = self.main_parser._observable[reference]
                ip_address = resolved_ip['observable']
                *attribute, kwargs = super()._parse_ip_observable(ip_address)
                misp_object.add_attribute(*attribute, **kwargs)
                resolved_ip['used'][self.event_uuid] = True
                resolved_ip['misp_object'] = misp_object
                if hasattr(ip_address, 'resolves_to_refs'):
                    for referenced_mac in ip_address.resolves_to_refs:
                        resolved_mac = self.main_parser._observable[
                            referenced_mac
                        ]
                        mac_address = resolved_mac['observable']
                        attribute = self._create_misp_attribute(
                            'mac-address', mac_address,
                            comment=f'Resolved by {ip_address.value}'
                        )
                        resolved_mac['used'][self.event_uuid] = True
                        misp_attribute = self.main_parser._add_misp_attribute(
                            attribute, mac_address
                        )
                        resolved_mac['misp_attribute'] = misp_attribute
                        misp_object.add_reference(
                            misp_attribute.uuid, 'resolves-to'
                        )
            return misp_object
        observable['used'][self.event_uuid] = True
        misp_attribute = self.main_parser._add_misp_attribute(
            self._create_misp_attribute('domain', domain_name), domain_name
        )
        observable['misp_attribute'] = misp_attribute
        return misp_attribute

    def _parse_email_address_observable_object(
            self, email_address_ref: str) -> _MISP_CONTENT_TYPING:
        observable = self.main_parser._observable[email_address_ref]
        if observable['used'].get(self.event_uuid, False):
            return observable.get(
                'misp_attribute', observable.get('misp_object')
            )
        email_address = observable['observable']
        if hasattr(email_address, 'belongs_to_ref'):
            user_account_object = self._parse_user_account_observable_object(
                email_address.belongs_to_ref
            )
            user_account_object.add_attribute(
                'email', email_address.value, **{
                    'uuid': self.main_parser._create_v5_uuid(
                        f'{email_address.id} - email - {email_address.value}'
                    )
                }
            )
            observable['used'][self.event_uuid] = True
            observable['misp_object'] = user_account_object
            return user_account_object
        misp_attribute = self.main_parser._add_misp_attribute(
            self._create_misp_attribute('email', email_address), email_address
        )
        observable['used'][self.event_uuid] = True
        observable['misp_attribute'] = misp_attribute
        return misp_attribute

    def _parse_email_message_observable_object(
            self, email_message_ref: str) -> MISPObject:
        observable = self.main_parser._observable[email_message_ref]
        if observable['used'].get(self.event_uuid, False):
            return observable['misp_object']
        email_message = observable['observable']
        email_object = self._create_misp_object_from_observable_object(
            'email', email_message
        )
        for attribute in super()._parse_email_message_observable(email_message):
            email_object.add_attribute(**attribute)
        observable['used'][self.event_uuid] = True
        misp_object = self.main_parser._add_misp_object(
            email_object, email_message
        )
        observable['misp_object'] = misp_object
        if hasattr(email_message, 'from_ref'):
            observable = self.main_parser._observable[email_message.from_ref]
            attributes = super()._parse_email_reference_observable(
                observable['observable'], 'from'
            )
            for *attribute, kwargs in attributes:
                misp_object.add_attribute(*attribute, **kwargs)
            observable['used'][self.event_uuid] = True
            observable['misp_object'] = misp_object
        for feature in ('to', 'bcc', 'cc'):
            field = f'{feature}_refs'
            if hasattr(email_message, field):
                for reference in getattr(email_message, field):
                    observable = self.main_parser._observable[reference]
                    attributes = super()._parse_email_reference_observable(
                        observable['observable'], feature
                    )
                    for *attribute, kwargs in attributes:
                        misp_object.add_attribute(*attribute, **kwargs)
                    observable['used'][self.event_uuid] = True
                    observable['misp_object'] = misp_object
        if hasattr(email_message, 'additional_header_fields'):
            attributes = super()._parse_email_additional_header(
                email_message.additional_header_fields
            )
            for attribute in attributes:
                misp_object.add_attribute(**attribute)
        return misp_object

    def _parse_file_observable_object(self, file_ref: str) -> MISPObject:
        observable = self.main_parser._observable[file_ref]
        if observable['used'].get(self.event_uuid, False):
            return observable['misp_object']
        _file = observable['observable']
        file_object = self._create_misp_object_from_observable_object(
            'file', _file
        )
        for attribute in super()._parse_file_observable(_file):
            file_object.add_attribute(**attribute)
        observable['used'][self.event_uuid] = True
        misp_object = self.main_parser._add_misp_object(file_object, _file)
        observable['misp_object'] = misp_object
        if hasattr(_file, 'content_ref'):
            artifact_object = self._parse_artifact_observable_object(
                _file.content_ref
            )
            artifact_object.add_reference(misp_object.uuid, 'content-of')
        if hasattr(_file, 'parent_directory_ref'):
            self._parse_directory_observable_object(
                _file.parent_directory_ref, child=_file.id
            )
        return misp_object

    def _parse_ip_addresses_belonging_to_AS(self, AS_id: str):
        for content in self.main_parser._observable.values():
            observable = content['observable']
            if observable.type not in ('ipv4-addr', 'ipv6-addr'):
                continue
            if AS_id in getattr(observable, 'belongs_to_refs', []):
                content['used'][self.event_uuid] = True
                yield super()._parse_ip_belonging_to_AS_observable(observable)

    def _parse_ip_address_observable_object(
            self, ip_address_ref: str) -> _MISP_CONTENT_TYPING:
        observable = self.main_parser._observable[ip_address_ref]
        if observable['used'].get(self.event_uuid, False):
            return observable.get(
                'misp_attribute', observable.get('misp_object')
            )
        ip_address = observable['observable']
        observable['used'][self.event_uuid] = True
        misp_attribute = self.main_parser._add_misp_attribute(
            self._create_misp_attribute('ip-dst', ip_address), ip_address
        )
        observable['misp_attribute'] = misp_attribute
        return misp_attribute

    def _parse_mac_address_observable_object(
            self, mac_address_ref: str) -> MISPAttribute:
        observable = self.main_parser._observable[mac_address_ref]
        if observable['used'].get(self.event_uuid, False):
            return observable['misp_attribute']
        mac_address = observable['observable']
        misp_attribute = self.main_parser._add_misp_attribute(
            self._create_misp_attribute('mac-address', mac_address), mac_address
        )
        observable['used'][self.event_uuid] = True
        observable['misp_attribute'] = misp_attribute
        return misp_attribute

    def _parse_mutex_observable_object(self, mutex_ref: str) -> MISPAttribute:
        observable = self.main_parser._observable[mutex_ref]
        if observable['used'].get(self.event_uuid, False):
            return observable['misp_attribute']
        mutex = observable['observable']
        misp_attribute = self.main_parser._add_misp_attribute(
            self._create_misp_attribute('mutex', mutex), mutex
        )
        observable['used'][self.event_uuid] = True
        observable['misp_attribute'] = misp_attribute
        return misp_attribute

    def _parse_network_connection_observable_object(
            self, observable: NetworkTraffic) -> MISPObject:
        connection_object = self._create_misp_object_from_observable_object(
            'network-connection', observable
        )
        for attribute in super()._parse_network_traffic_observable(observable):
            connection_object.add_attribute(**attribute)
        protocols = super()._parse_network_connection_observable(observable)
        for *attribute, kwargs in protocols:
            connection_object.add_attribute(*attribute, **kwargs)
        return connection_object

    def _parse_network_socket_observable_object(
            self, observable: NetworkTraffic) -> MISPObject:
        socket_object = self._create_misp_object_from_observable_object(
            'network-socket', observable
        )
        for attribute in super()._parse_network_traffic_observable(observable):
            socket_object.add_attribute(**attribute)
        for attribute in super()._parse_network_socket_observable(observable):
            socket_object.add_attribute(**attribute)
        return socket_object

    def _parse_network_traffic_observable_object(
            self, network_traffic_ref: str) -> MISPObject:
        observable = self.main_parser._observable[network_traffic_ref]
        if observable['used'].get(self.event_uuid, False):
            return observable['misp_object']
        network_traffic = observable['observable']
        feature = self._parse_network_traffic_observable_fields(network_traffic)
        network_object = getattr(self, feature)(network_traffic)
        observable['used'][self.event_uuid] = True
        misp_object = self.main_parser._add_misp_object(
            network_object, network_traffic
        )
        observable['misp_object'] = misp_object
        for asset in ('src', 'dst'):
            if hasattr(network_traffic, f'{asset}_ref'):
                referenced_object = self.main_parser._observable[
                    getattr(network_traffic, f'{asset}_ref')
                ]
                content = super()._parse_network_traffic_reference_observable(
                    asset, referenced_object['observable']
                )
                for *attribute, kwargs in content:
                    misp_object.add_attribute(*attribute, **kwargs)
                referenced_object['used'][self.event_uuid] = True
                referenced_object['misp_object'] = misp_object
        if hasattr(network_traffic, 'encapsulates_refs'):
            for reference in network_traffic.encapsulates_refs:
                referenced = self._parse_network_traffic_observable_object(
                    reference
                )
                misp_object.add_reference(referenced.uuid, 'encapsulates')
        if hasattr(network_traffic, 'encapsulated_by_ref'):
            referenced = self._parse_network_traffic_observable_object(
                network_traffic.encapsulated_by_ref
            )
            misp_object.add_reference(referenced.uuid, 'encapsulated-by')
        return misp_object

    @staticmethod
    def _parse_network_traffic_observable_fields(
            observable: NetworkTraffic) -> str:
        if getattr(observable, 'extensions', {}).get('socket-ext'):
            return '_parse_network_socket_observable_object'
        return '_parse_network_connection_observable_object'

    def _parse_process_observable_object(self, process_ref: str) -> MISPObject:
        observable = self.main_parser._observable[process_ref]
        if observable['used'].get(self.event_uuid, False):
            return observable['misp_object']
        process = observable['observable']
        process_object = self._create_misp_object_from_observable_object(
            'process', process
        )
        for attribute in super()._parse_process_observable(process):
            process_object.add_attribute(**attribute)
        observable['used'][self.event_uuid] = True
        misp_object = self.main_parser._add_misp_object(process_object, process)
        observable['misp_object'] = misp_object
        if hasattr(process, 'opened_connection_refs'):
            for reference in process.opened_connection_refs:
                network_object = self._parse_network_traffic_observable_object(
                    reference
                )
                misp_object.add_reference(
                    network_object.uuid, 'opens-connection'
                )
        if hasattr(process, 'creator_user_ref'):
            user_object = self._parse_user_account_observable_object(
                process.creator_user_ref
            )
            user_object.add_reference(misp_object.uuid, 'creates')
        if hasattr(process, 'image_ref'):
            file_object = self._parse_file_observable_object(process.image_ref)
            misp_object.add_reference(file_object.uuid, 'executes')
        if hasattr(process, 'parent_ref'):
            parent_object = self._parse_process_observable_object(
                process.parent_ref
            )
            parent_object.add_reference(misp_object.uuid, 'parent-of')
        if hasattr(process, 'child_refs'):
            for reference in process.child_refs:
                child_object = self._parse_process_observable_object(reference)
                child_object.add_reference(misp_object.uuid, 'child-of')
        return misp_object

    def _parse_software_observable_object(
            self, software_ref: str) -> MISPObject:
        observable = self.main_parser._observable[software_ref]
        if observable['used'].get(self.event_uuid, False):
            return observable['misp_object']
        software = observable['observable']
        software_object = self._create_misp_object_from_observable_object(
            'software', software
        )
        for attribute in super()._parse_software_observable(software):
            software_object.add_attribute(**attribute)
        observable['used'][self.event_uuid] = True
        misp_object = self.main_parser._add_misp_object(
            software_object, software
        )
        observable['misp_object'] = misp_object
        return misp_object

    def _parse_user_account_observable_object(
            self, user_account_ref: str) -> MISPObject:
        observable = self.main_parser._observable[user_account_ref]
        if observable['used'].get(self.event_uuid, False):
            return observable['misp_object']
        user_account = observable['observable']
        user_account_object = self._create_misp_object_from_observable_object(
            'user-account', user_account
        )
        for attribute in super()._parse_user_account_observable(user_account):
            user_account_object.add_attribute(**attribute)
        observable['used'][self.event_uuid] = True
        misp_object = self.main_parser._add_misp_object(
            user_account_object, user_account
        )
        observable['misp_object'] = misp_object
        return misp_object


class STIX2SampleObservableConverter(
        STIX2ObservableConverter, metaclass=ABCMeta):
    def __init__(self, main: _MAIN_CONVERTER_TYPING):
        self._main_converter = main

    @property
    def event_uuid(self) -> str:
        return self.main_parser.misp_event.uuid

    @property
    def main_parser(self) -> 'ExternalSTIX2toMISPParser':
        return self._main_converter.main_parser

    def _create_misp_object_from_observable(
            self, name: str, observable: _OBSERVABLE_TYPING,
            malware: Malware) -> MISPObject:
        misp_object = MISPObject(
            name, force_timestamps=True,
            misp_objects_path_custom=_MISP_OBJECTS_PATH
        )
        self.main_parser._sanitise_object_uuid(
            misp_object, observable.get('id')
        )
        misp_object.from_dict(**self._main_converter._parse_timeline(malware))
        return misp_object

    def _parse_artifact_observable_object(
            self, artifact_ref: str, malware: Malware) -> MISPObject:
        observable = self.main_parser._observable[artifact_ref]
        if observable['used'][self.event_uuid]:
            return observable['misp_object']
        artifact = observable['observable']
        artifact_object = self._create_misp_object_from_observable(
            'artifact', artifact, malware
        )
        for attribute in super()._parse_artifact_observable(artifact):
            artifact_object.add_attribute(**attribute)
        observable['used'][self.event_uuid] = True
        misp_object = self._main_parser._add_misp_object(
            artifact_object, artifact
        )
        observable['misp_object'] = misp_object
        return misp_object

    def _parse_file_observable_object(
            self, file_ref: str, malware: Malware) -> MISPObject:
        observable = self.main_parser._observable[file_ref]
        if observable['used'][self.event_uuid]:
            return observable['misp_object']
        _file = observable['observable']
        file_object = self._create_misp_object_from_observable(
            'file', _file, malware
        )
        for attribute in super()._parse_file_observable(_file):
            file_object.add_attribute(**attribute)
        observable['used'][self.event_uuid] = True
        misp_object = self.main_parser._add_misp_object(file_object, _file)
        observable['misp_object'] = misp_object
        return misp_object

    def _parse_software_observable_object(
            self, software_ref: str, malware: Malware) -> MISPObject:
        observable = self.main_parser._observable[software_ref]
        if observable['used'][self.event_uuid]:
            return observable['misp_object']
        software = observable['observable']
        software_object = self._create_misp_object_from_observable(
            'software', software, malware
        )
        for attribute in super()._parse_software_observable(software):
            software_object.add_attribute(**attribute)
        observable['used'][self.event_uuid] = True
        misp_object = self.main_parser._add_misp_object(
            software_object, software
        )
        observable['misp_object'] = misp_object
        return misp_object


class ExternalSTIX2SampleObservableConverter(STIX2SampleObservableConverter):
    def __init__(self, main: 'ExternalSTIX2MalwareConverter'):
        super().__init__(main)
        self._mapping = ExternalSTIX2ObservableMapping


class InternalSTIX2SampleObservableConverter(STIX2SampleObservableConverter):
    def __init__(self, main: 'InternalSTIX2MalwareConverter'):
        super().__init__(main)
        self._mapping = InternalSTIX2ObservableMapping
