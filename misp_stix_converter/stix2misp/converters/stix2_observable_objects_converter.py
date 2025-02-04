#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .stix2_observable_converter import (
    ExternalSTIX2ObservableConverter, ExternalSTIX2ObservableMapping,
    InternalSTIX2ObservableConverter, InternalSTIX2ObservableMapping)
from abc import ABCMeta
from pymisp import AbstractMISP, MISPAttribute, MISPObject
from stix2.v21.observables import (
    Artifact, AutonomousSystem, Directory, DomainName, EmailMessage, File,
    NetworkTraffic, Process, Software, UserAccount, WindowsRegistryKey,
    X509Certificate)
from stix2.v21.sdo import Malware
from typing import Dict, Iterator, Optional, TYPE_CHECKING, Union

if TYPE_CHECKING:
    from ..external_stix2_to_misp import ExternalSTIX2toMISPParser
    from .stix2_malware_converter import (
        ExternalSTIX2MalwareConverter, InternalSTIX2MalwareConverter)

_MISP_OBJECTS_PATH = AbstractMISP().misp_objects_path

# TYPINGS
_MAIN_CONVERTER_TYPING = Union[
    'ExternalSTIX2MalwareConverter', 'InternalSTIX2MalwareConverter'
]
_MISP_CONTENT_TYPING = Union[
    MISPAttribute, MISPObject
]
_OBSERVABLE_TYPING = Union[
    Artifact, AutonomousSystem, Directory, DomainName, EmailMessage, File,
    NetworkTraffic, Process, Software, UserAccount, WindowsRegistryKey,
    X509Certificate
]


class STIX2SampleObervableParser(metaclass=ABCMeta):

    def _parse_artifact_observable_object(
            self, artifact_ref: str, *args) -> MISPObject:
        observable = self._fetch_observable(artifact_ref)
        if observable['used'].get(self.event_uuid, False):
            return observable['misp_object']
        artifact = observable['observable']
        artifact_object = self._create_misp_object_from_observable(
            'artifact', artifact, *args
        )
        attributes = self._parse_artifact_observable(
            artifact, indicator_ref=observable.get('indicator_ref', '')
        )
        for attribute in attributes:
            artifact_object.add_attribute(**attribute)
        observable['used'][self.event_uuid] = True
        misp_object = self._main_parser._add_misp_object(
            artifact_object, artifact
        )
        observable['misp_object'] = misp_object
        return misp_object

    def _parse_directory_observable_object(
            self, directory_ref: str, *args,
            child: Optional[str] = None) -> _MISP_CONTENT_TYPING:
        observable = self._fetch_observable(directory_ref)
        if observable['used'].get(self.event_uuid, False):
            return observable.get('misp_object', observable['misp_attribute'])
        directory = observable['observable']
        attributes = tuple(
            self._parse_generic_observable(
                directory, 'directory',
                indicator_ref=observable.get('indicator_ref', '')
            )
        )
        observable['used'][self.event_uuid] = True
        force_object = (
            len(attributes) > 1 or any(
                ref != child for ref in getattr(directory, 'contains_refs', [])
            )
        )
        if force_object:
            directory_object = self._create_misp_object_from_observable(
                'directory', directory, *args
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
                        self._fetch_observable(child)['misp_object']
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
                    'type': attribute['type'],
                    'value': attribute['value'],
                    'to_ids': attribute['to_ids'],
                    **self.main_parser._sanitise_attribute_uuid(directory.id)
                },
                directory
            )
            observable['misp_attribute'] = misp_attribute
            return misp_attribute
        file_object = self._fetch_observable(child)['misp_object']
        file_object.add_attribute(**attributes[0])
        observable['misp_object'] = file_object
        return misp_object

    def _parse_file_observable_object(self, file_ref: str, *args) -> MISPObject:
        observable = self._fetch_observable(file_ref)
        if observable['used'].get(self.event_uuid, False):
            return observable['misp_object']
        _file = observable['observable']
        file_object = self._create_misp_object_from_observable(
            'file', _file, *args
        )
        indicator_ref = observable.get('indicator_ref', '')
        attributes = self._parse_file_observable(
            _file, indicator_ref=indicator_ref
        )
        for attribute in attributes:
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
        if hasattr(_file, 'extensions'):
            extensions = _file.extensions
            if extensions.get('archive-ext'):
                archive_ext = extensions['archive-ext']
                if hasattr(archive_ext, 'comment'):
                    comment = archive_ext.comment
                    if hasattr(misp_object, 'comment'):
                        comment = f'{comment} - {misp_object.comment}'
                    misp_object.comment = comment
                for contains_ref in archive_ext.contains_refs:
                    object_type = contains_ref.split('--')[0]
                    contained_object = getattr(
                        self,
                        f'_parse_{object_type}_observable_object'
                    )(
                        contains_ref
                    )
                    misp_object.add_reference(contained_object.uuid, 'contains')
            if extensions.get('windows-pebinary-ext'):
                pe_object = self._parse_file_pe_extension_observable_object(
                    _file, indicator_ref
                )
                misp_object.add_reference(pe_object.uuid, 'includes')
        return misp_object

    def _parse_file_pe_extension_observable_object(
            self, observable: File, indicator_ref: str | tuple) -> MISPObject:
        extension = observable.extensions['windows-pebinary-ext']
        pe_object = self._create_misp_object('pe')
        pe_object.from_dict(
            uuid=self.main_parser._create_v5_uuid(
                f'{observable.id} - windows-pebinary-ext'
            )
        )
        attributes = self._parse_pe_extension_observable(
            extension, f'{observable.id} - windows-pebinary-ext',
            indicator_ref=indicator_ref
        )
        for attribute in attributes:
            pe_object.add_attribute(**attribute)
        misp_object = self.main_parser._add_misp_object(pe_object, observable)
        if hasattr(extension, 'sections'):
            for index, section in enumerate(extension.sections):
                section_object = self._create_misp_object('pe-section')
                section_object.from_dict(
                    uuid=self.main_parser._create_v5_uuid(
                        f'{observable.id} - section #{index}'
                    )
                )
                attributes = self._parse_pe_section_observable(
                    section, f'{observable.id} - section #{index}',
                    indicator_ref=indicator_ref
                )
                for attribute in attributes:
                    section_object.add_attribute(**attribute)
                self.main_parser._add_misp_object(section_object, observable)
                misp_object.add_reference(section_object.uuid, 'includes')
        return misp_object

    def _parse_software_observable_object(
            self, software_ref: str, *args) -> MISPObject:
        observable = self._fetch_observable(software_ref)
        if observable['used'].get(self.event_uuid, False):
            return observable['misp_object']
        software = observable['observable']
        software_object = self._create_misp_object_from_observable(
            'software', software, *args
        )
        attributes = self._parse_generic_observable(
            software, 'software',
            indicator_ref=observable.get('indicator_ref', '')
        )
        for attribute in attributes:
            software_object.add_attribute(**attribute)
        observable['used'][self.event_uuid] = True
        misp_object = self.main_parser._add_misp_object(
            software_object, software
        )
        observable['misp_object'] = misp_object
        return misp_object


class STIX2ObservableObjectConverter(
        STIX2SampleObervableParser, ExternalSTIX2ObservableConverter):
    def __init__(self, main: 'ExternalSTIX2toMISPParser'):
        self._set_main_parser(main)
        self._mapping = ExternalSTIX2ObservableMapping

    def _create_misp_attribute(
            self, attribute_type: str, observable: DomainName,
            feature: Optional[str] = 'value', comment: Optional[str] = None,
            indicator_ref: Optional[str] = '',
            **kwargs: Dict[str, str | bool]) -> MISPAttribute:
        if kwargs.get('to_ids', False):
            attribute = {'type': attribute_type, **kwargs}
            if comment is not None:
                attribute['comment'] = comment
            return self._populate_object_attribute(
                attribute, getattr(observable, feature),
                f'{indicator_ref} - {observable.id}'
            )
        return {
            'value': getattr(observable, feature), 'type': attribute_type,
            **kwargs, **self.main_parser._sanitise_attribute_uuid(
                observable.id, comment=comment
            )
        }

    def _create_misp_object_from_observable(
            self, name: str, observable: _OBSERVABLE_TYPING) -> MISPObject:
        misp_object = MISPObject(
            name, force_timestamps=True,
            misp_objects_path_custom=_MISP_OBJECTS_PATH
        )
        self.main_parser._sanitise_object_uuid(
            misp_object, observable.get('id')
        )
        return misp_object

    def _parse_as_observable_object(self, as_ref: str) -> _MISP_CONTENT_TYPING:
        observable = self._fetch_observable(as_ref)
        if observable['used'].get(self.event_uuid, False):
            return observable.get(
                'misp_object', observable.get('misp_attribute')
            )
        autonomous_system = observable['observable']
        indicator_ref = observable.get('indicator_ref', '')
        ip_attributes = tuple(
            self._parse_ip_addresses_belonging_to_AS(
                autonomous_system.id, indicator_ref
            )
        )
        observable['used'][self.event_uuid] = True
        if ip_attributes or hasattr(observable, 'name'):
            AS_object = self._create_misp_object_from_observable(
                'asn', autonomous_system
            )
            attributes = self._parse_asn_observable(
                observable, indicator_ref=indicator_ref
            )
            for attribute in attributes:
                AS_object.add_attribute(**attribute)
            for attribute in ip_attributes:
                AS_object.add_attribute(**attribute)
            misp_object = self.main_parser._add_misp_object(
                AS_object, autonomous_system
            )
            observable['misp_object'] = misp_object
            return misp_object
        to_ids = self._check_indicator_reference(
            indicator_ref, f'number - {autonomous_system.number}'
        )
        value = self._parse_AS_value(autonomous_system.number)
        attribute = {
            'type': 'AS', 'to_ids': to_ids,
            'value': f'AS{autonomous_system.number}'
        }
        if to_ids:
            attribute['uuid'] = self.main_parser._create_v5_uuid(
                f'{indicator_ref} - {autonomous_system.id} - AS - {value}'
            )
        else:
            attribute.update(
                self.main_parser._sanitise_attribute_uuid(autonomous_system.id)
            )
        misp_attribute = self.main_parser._add_misp_attribute(
            attribute, autonomous_system
        )
        observable['misp_attribute'] = misp_attribute
        return misp_attribute

    def _parse_domain_observable_object(
            self, domain_ref: str) -> _MISP_CONTENT_TYPING:
        observable = self._fetch_observable(domain_ref)
        if observable['used'].get(self.event_uuid, False):
            return observable.get(
                'misp_object', observable.get('misp_attribute')
            )
        domain_name = observable['observable']
        if hasattr(domain_name, 'resolves_to_refs'):
            domain_object = self._create_misp_object_from_observable(
                'domain-ip', domain_name
            )
            attributes = self._parse_domain_observable(
                domain_name, indicator_ref=observable.get('indicator_ref', '')
            )
            for attribute in attributes:
                domain_object.add_attribute(**attribute)
            misp_object = self.main_parser._add_misp_object(
                domain_object, domain_name
            )
            observable['misp_object'] = misp_object
            observable['used'][self.event_uuid] = True
            for reference in domain_name.resolves_to_refs:
                if reference.split('--')[0] == 'domain-name':
                    referenced_domain = self._parse_domain_observable_object(
                        reference
                    )
                    misp_object.add_reference(
                        referenced_domain.uuid, 'resolves-to'
                    )
                    continue
                resolved_ip = self._fetch_observable(reference)
                ip_address = resolved_ip['observable']
                misp_object.add_attribute(
                    **self._parse_ip_observable(
                        ip_address,
                        indicator_ref=resolved_ip.get('indicator_ref', '')
                    )
                )
                resolved_ip['used'][self.event_uuid] = True
                resolved_ip['misp_object'] = misp_object
                if hasattr(ip_address, 'resolves_to_refs'):
                    for referenced_mac in ip_address.resolves_to_refs:
                        resolved_mac = self._fetch_observable(referenced_mac)
                        mac_address = resolved_mac['observable']
                        indicator_ref = resolved_mac.get('indicator_ref', '')
                        to_ids = self._check_indicator_reference(
                            indicator_ref, f'value - {mac_address.value}'
                        )
                        attribute = self._create_misp_attribute(
                            'mac-address', mac_address, to_ids=to_ids,
                            comment=f'Resolved by {ip_address.value}',
                            indicator_ref=indicator_ref
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
        indicator_ref = observable.get('indicator_ref', '')
        to_ids = self._check_indicator_reference(
            indicator_ref, f'value - {domain_name.value}'
        )
        attribute = self._create_misp_attribute(
            'domain', domain_name, to_ids=to_ids, indicator_ref=indicator_ref
        )
        misp_attribute = self.main_parser._add_misp_attribute(
            attribute, domain_name
        )
        observable['used'][self.event_uuid] = True
        observable['misp_attribute'] = misp_attribute
        return misp_attribute

    def _parse_email_address_observable_object(
            self, email_address_ref: str) -> _MISP_CONTENT_TYPING:
        observable = self._fetch_observable(email_address_ref)
        if observable['used'].get(self.event_uuid, False):
            return observable.get(
                'misp_attribute', observable.get('misp_object')
            )
        email_address = observable['observable']
        indicator_ref = observable.get('indicator_ref', '')
        to_ids = self._check_indicator_reference(
            indicator_ref, f'value - {email_address.value}'
        )
        if hasattr(email_address, 'belongs_to_ref'):
            user_account_object = self._parse_user_account_observable_object(
                email_address.belongs_to_ref
            )
            object_id = (
                f'{indicator_ref} - {email_address.id}'
                if to_ids else email_address.id
            )
            user_account_object.add_attribute(
                'email', email_address.value, to_ids=to_ids,
                uuid=self.main_parser._create_v5_uuid(
                    f'{object_id} - email - {email_address.value}'
                )
            )
            observable['misp_object'] = user_account_object
            observable['used'][self.event_uuid] = True
            return user_account_object
        attribute = self._create_misp_attribute(
            'email', email_address, to_ids=to_ids, indicator_ref=indicator_ref
        )
        misp_attribute = self.main_parser._add_misp_attribute(
            attribute, email_address
        )
        observable['used'][self.event_uuid] = True
        observable['misp_attribute'] = misp_attribute
        return misp_attribute

    def _parse_email_message_observable_object(
            self, email_message_ref: str) -> MISPObject:
        observable = self._fetch_observable(email_message_ref)
        if observable['used'].get(self.event_uuid, False):
            return observable['misp_object']
        email_message = observable['observable']
        email_object = self._create_misp_object_from_observable(
            'email', email_message
        )
        attributes = self._parse_email_observable(
            email_message, indicator_ref=observable.get('indicator_ref', '')
        )
        for attribute in attributes:
            email_object.add_attribute(**attribute)
        observable['used'][self.event_uuid] = True
        misp_object = self.main_parser._add_misp_object(
            email_object, email_message
        )
        observable['misp_object'] = misp_object
        if hasattr(email_message, 'from_ref'):
            from_address = self._fetch_observable(email_message.from_ref)
            attributes = self._parse_email_reference_observable(
                from_address['observable'], 'from',
                indicator_ref=from_address.get('indicator_ref', '')
            )
            for attribute in attributes:
                misp_object.add_attribute(**attribute)
            from_address['misp_object'] = misp_object
            from_address['used'][self.event_uuid] = True
        for feature in ('to', 'bcc', 'cc'):
            field = f'{feature}_refs'
            if hasattr(email_message, field):
                for reference in getattr(email_message, field):
                    email_address = self._fetch_observable(reference)
                    attributes = self._parse_email_reference_observable(
                        email_address['observable'], feature,
                        indicator_ref=email_address.get('indicator_ref', '')
                    )
                    for attribute in attributes:
                        misp_object.add_attribute(**attribute)
                    email_address['misp_object'] = misp_object
                    email_address['used'][self.event_uuid] = True
        return misp_object

    def _parse_ip_addresses_belonging_to_AS(
            self, AS_id: str, indicator_ref: str | tuple) -> Iterator[dict]:
        for content in self.main_parser._observable.values():
            observable = content['observable']
            if observable.type not in ('ipv4-addr', 'ipv6-addr'):
                continue
            if AS_id in getattr(observable, 'belongs_to_refs', []):
                content['used'][self.event_uuid] = True
                yield self._parse_ip_belonging_to_AS_observable(
                    observable, indicator_ref=indicator_ref
                )

    def _parse_ip_address_observable_object(
            self, ip_address_ref: str) -> _MISP_CONTENT_TYPING:
        observable = self._fetch_observable(ip_address_ref)
        if observable['used'].get(self.event_uuid, False):
            return observable.get(
                'misp_attribute', observable.get('misp_object')
            )
        ip_address = observable['observable']
        indicator_ref = observable.get('indicator_ref', '')
        to_ids = self._check_indicator_reference(
            indicator_ref, f'value - {ip_address.value}'
        )
        attribute = self._create_misp_attribute(
            'ip-dst', ip_address, to_ids=to_ids, indicator_ref=indicator_ref
        )
        misp_attribute = self.main_parser._add_misp_attribute(
            attribute, ip_address
        )
        observable['used'][self.event_uuid] = True
        observable['misp_attribute'] = misp_attribute
        return misp_attribute

    def _parse_mac_address_observable_object(
            self, mac_address_ref: str) -> MISPAttribute:
        observable = self._fetch_observable(mac_address_ref)
        if observable['used'].get(self.event_uuid, False):
            return observable['misp_attribute']
        mac_address = observable['observable']
        indicator_ref = observable.get('indicator_ref', '')
        to_ids = self._check_indicator_reference(
            indicator_ref, f'value - {mac_address.value}'
        )
        attribute = self._create_misp_attribute(
            'mac-address', mac_address, to_ids=to_ids,
            indicator_ref=indicator_ref
        )
        misp_attribute = self.main_parser._add_misp_attribute(
            attribute, mac_address
        )
        observable['used'][self.event_uuid] = True
        observable['misp_attribute'] = misp_attribute
        return misp_attribute

    def _parse_mutex_observable_object(self, mutex_ref: str) -> MISPAttribute:
        observable = self._fetch_observable(mutex_ref)
        if observable['used'].get(self.event_uuid, False):
            return observable['misp_attribute']
        mutex = observable['observable']
        indicator_ref = observable.get('indicator_ref', '')
        to_ids = self._check_indicator_reference(
            indicator_ref, f'value - {mutex.value}'
        )
        attribute = self._create_misp_attribute(
            'mutex', mutex, to_ids=to_ids, indicator_ref=indicator_ref
        )
        misp_attribute = self.main_parser._add_misp_attribute(attribute, mutex)
        observable['used'][self.event_uuid] = True
        observable['misp_attribute'] = misp_attribute
        return misp_attribute

    def _parse_network_traffic_observable_object(
            self, network_traffic_ref: str) -> MISPObject:
        observable = self._fetch_observable(network_traffic_ref)
        if observable['used'].get(self.event_uuid, False):
            return observable['misp_object']
        network_traffic = observable['observable']
        name = self._parse_network_traffic_observable_fields(network_traffic)
        network_object = self._create_misp_object_from_observable(
            name, network_traffic
        )
        feature = f"_parse_{name.replace('-', '_')}_observable"
        attributes = getattr(self, feature)(
            network_traffic, indicator_ref=observable.get('indicator_ref', '')
        )
        for attribute in attributes:
            network_object.add_attribute(**attribute)
        observable['used'][self.event_uuid] = True
        misp_object = self.main_parser._add_misp_object(
            network_object, network_traffic
        )
        observable['misp_object'] = misp_object
        for asset in ('src', 'dst'):
            if hasattr(network_traffic, f'{asset}_ref'):
                referenced = self._fetch_observable(
                    getattr(network_traffic, f'{asset}_ref')
                )
                referenced_observable = referenced['observable']
                attributes = self._parse_network_traffic_reference_observable(
                    asset, referenced_observable,
                    f'{network_traffic.id} - {referenced_observable.id}',
                    indicator_ref=referenced.get('indicator_ref', '')
                )
                for attribute in attributes:
                    misp_object.add_attribute(**attribute)
                self._handle_misp_object_storage(referenced, misp_object)
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

    def _parse_process_observable_object(self, process_ref: str) -> MISPObject:
        observable = self._fetch_observable(process_ref)
        if observable['used'].get(self.event_uuid, False):
            return observable['misp_object']
        process = observable['observable']
        process_object = self._create_misp_object_from_observable(
            'process', process
        )
        attributes = self._parse_process_observable(
            process, indicator_ref=observable.get('indicator_ref', '')
        )
        for attribute in attributes:
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

    def _parse_registry_key_observable_object(self, registry_key_ref: str):
        observable = self._fetch_observable(registry_key_ref)
        if observable['used'].get(self.event_uuid, False):
            return observable['misp_object']
        registry_key = observable['observable']
        indicator_ref = observable.get('indicator_ref', '')
        registry_key_object = self._create_misp_object_from_observable(
            'registry-key', registry_key
        )
        attributes = self._parse_registry_key_observable(
            registry_key, indicator_ref=indicator_ref
        )
        for attribute in attributes:
            registry_key_object.add_attribute(**attribute)
        observable['used'][self.event_uuid] = True
        misp_object = self.main_parser._add_misp_object(
            registry_key_object, registry_key
        )
        observable['misp_object'] = misp_object
        if len(registry_key.get('values', [])) > 1:
            object_id = registry_key.id
            for index, registry_key_value in enumerate(registry_key['values']):
                value_object = self._create_misp_object('registry-key-value')
                reference = f'{object_id} - values - {index}'
                value_object.from_dict(
                    uuid=self.main_parser._create_v5_uuid(reference),
                    comment=f'Original Windows Registry Key ID: {object_id}'
                )
                attributes = self._parse_generic_observable(
                    registry_key_value, 'registry_key_values', reference,
                    indicator_ref=indicator_ref
                )
                for attribute in attributes:
                    value_object.add_attribute(**attribute)
                misp_object.add_reference(value_object.uuid, 'contains')
                self.main_parser._add_misp_object(value_object, registry_key)
        return misp_object

    def _parse_url_observable_object(self, url_ref: str) -> MISPAttribute:
        observable = self._fetch_observable(url_ref)
        if observable['used'].get(self.event_uuid, False):
            return observable['misp_attribute']
        url = observable['observable']
        indicator_ref = observable.get('indicator_ref', '')
        to_ids = self._check_indicator_reference(
            indicator_ref, f'value - {url.value}'
        )
        attribute = self._create_misp_attribute(
            'url', url, to_ids=to_ids, indicator_ref=indicator_ref
        )
        misp_attribute = self.main_parser._add_misp_attribute(attribute, url)
        observable['used'][self.event_uuid] = True
        observable['misp_attribute'] = misp_attribute
        return misp_attribute

    def _parse_user_account_observable_object(
            self, user_account_ref: str) -> MISPObject:
        observable = self._fetch_observable(user_account_ref)
        if observable['used'].get(self.event_uuid, False):
            return observable['misp_object']
        user_account = observable['observable']
        user_account_object = self._create_misp_object_from_observable(
            'user-account', user_account
        )
        attributes = self._parse_user_account_observable(
            user_account, indicator_ref=observable.get('indicator_ref', '')
        )
        for attribute in attributes:
            user_account_object.add_attribute(**attribute)
        observable['used'][self.event_uuid] = True
        misp_object = self.main_parser._add_misp_object(
            user_account_object, user_account
        )
        observable['misp_object'] = misp_object
        return misp_object

    def _parse_x509_observable_object(self, x509_ref: str) -> MISPObject:
        observable = self._fetch_observable(x509_ref)
        if observable['used'].get(self.event_uuid, False):
            return observable['misp_object']
        x509 = observable['observable']
        x509_object = self._create_misp_object_from_observable(
            'x509', x509
        )
        attributes = self._parse_x509_observable(
            x509, indicator_ref=observable.get('indicator_ref', '')
        )
        for attribute in attributes:
            x509_object.add_attribute(**attribute)
        observable['used'][self.event_uuid] = True
        misp_object = self.main_parser._add_misp_object(x509_object, x509)
        observable['misp_object'] = misp_object
        return misp_object


class STIX2SampleObservableConverter(STIX2SampleObervableParser):
    def __init__(self, main: _MAIN_CONVERTER_TYPING):
        self._main_converter = main

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


class ExternalSTIX2SampleObservableConverter(
        STIX2SampleObservableConverter, ExternalSTIX2ObservableConverter):
    def __init__(self, main: 'ExternalSTIX2MalwareConverter'):
        super().__init__(main)
        self._mapping = ExternalSTIX2ObservableMapping


class InternalSTIX2SampleObservableConverter(
        STIX2SampleObservableConverter, InternalSTIX2ObservableConverter):
    def __init__(self, main: 'InternalSTIX2MalwareConverter'):
        super().__init__(main)
        self._mapping = InternalSTIX2ObservableMapping
