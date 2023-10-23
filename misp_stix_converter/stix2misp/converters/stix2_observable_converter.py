#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ... import Mapping
from .stix2converter import STIX2Converter
from .stix2mapping import (
    ExternalSTIX2Mapping, InternalSTIX2Mapping, STIX2Mapping)
from abc import ABCMeta
from pymisp import AbstractMISP, MISPObject
from stix2.v21.observables import Artifact, File, NetworkTraffic, Software
from stix2.v21.sdo import Malware
from typing import TYPE_CHECKING, Union

if TYPE_CHECKING:
    from ..external_stix2_to_misp import ExternalSTIX2toMISPParser
    from .stix2_malware_converter import (
        ExternalSTIX2MalwareConverter, InternalSTIX2MalwareConverter)

_MISP_OBJECTS_PATH = AbstractMISP().misp_objects_path

_MAIN_CONVERTER_TYPING = Union[
    'ExternalSTIX2MalwareConverter', 'InternalSTIX2MalwareConverter'
]
_OBSERVABLE_TYPING = Union[
    Artifact, File, NetworkTraffic, Software
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
    pass


class InternalSTIX2ObservableMapping(
        STIX2ObservableMapping, InternalSTIX2Mapping):
    pass


class STIX2ObservableConverter:
    def _parse_artifact_observable(
            self, misp_object: MISPObject, observable: Artifact):
        if hasattr(observable, 'hashes'):
            for hash_type, value in observable.hashes.items():
                attribute = self._mapping.file_hashes_mapping(hash_type)
                if attribute is None:
                    self.main_parser.hash_type_error(hash_type)
                    continue
                misp_object.add_attribute(**{'value': value, **attribute})
        for field, mapping in self._mapping.artifact_object_mapping().items():
            if hasattr(observable, field):
                self._populate_object_attributes(
                    misp_object, mapping, getattr(observable, field),
                    observable.id
                )

    def _parse_file_observable(self, misp_object: MISPObject, observable: File):
        if hasattr(observable, 'hashes'):
            for hash_type, value in observable.hashes.items():
                attribute = self._mapping.file_hashes_mapping(hash_type)
                if attribute is None:
                    self.main_parser.hash_type_error(hash_type)
                    continue
                misp_object.add_attribute(**{'value': value, **attribute})
        for field, mapping in self._mapping.file_object_mapping().items():
            if hasattr(observable, field):
                self._populate_object_attributes(
                    misp_object, mapping, getattr(observable, field),
                    observable.id
                )

    def _parse_network_connection_observable(
            self, misp_object: MISPObject, observable: NetworkTraffic):
        for protocol in observable.protocols:
            layer = self._mapping.connection_protocols(protocol)
            if layer is not None:
                misp_object.add_attribute(
                    f'layer{layer}-protocol', protocol,
                    uuid=self.main_parser._create_v5_uuid(
                        f'{observable.id} - layer{layer}-protocol - {protocol}'
                    )
                )

    def _parse_network_socket_observable(
            self, misp_object: MISPObject, observable: NetworkTraffic):
        for protocol in observable.protocols:
            misp_object.add_attribute(
                'protocol', protocol, uuid=self.main_parser._create_v5_uuid(
                    f'{observable.id} - protocol - {protocol}'
                )
            )
        socket_extension = observable.extensions['socket-ext']
        mapping = self._mapping.network_socket_extension_object_mapping
        for field, attribute in mapping().items():
            if hasattr(socket_extension, field):
                self._populate_object_attributes(
                    misp_object, attribute, getattr(socket_extension, field),
                    observable.id
                )
        for feature in ('blocking', 'listening'):
            if getattr(socket_extension, f'is_{feature}', False):
                misp_object.add_attribute(
                    'state', feature, uuid=self.main_parser._create_v5_uuid(
                        f'{observable.id} - state - {feature}'
                    )
                )

    def _parse_network_traffic_observable(
            self, misp_object: MISPObject, observable: NetworkTraffic):
        mapping = self._mapping.network_traffic_object_mapping
        for field, attribute in mapping().items():
            if hasattr(observable, field):
                self._populate_object_attributes(
                    misp_object, attribute, getattr(observable, field),
                    observable.id
                )

    def _parse_software_observable(
            self, misp_object: MISPObject, observable: Software):
        for field, mapping in self._mapping.software_object_mapping().items():
            if hasattr(observable, field):
                self._populate_object_attributes(
                    misp_object, mapping, getattr(observable, field),
                    observable.id
                )

    def _populate_object_attributes(
            self, misp_object: MISPObject, mapping: dict,
            values: Union[list, str], observable_id: str):
        reference = f"{observable_id} - {mapping['object_relation']}"
        if isinstance(values, list):
            for value in values:
                misp_object.add_attribute(
                    **{
                        'value': value, **mapping,
                        'uuid': self.main_parser._create_v5_uuid(
                            f'{reference} - {value}'
                        )
                    }
                )
        else:
            print(misp_object)
            misp_object.add_attribute(
                **{
                    'value': values, **mapping,
                    'uuid': self.main_parser._create_v5_uuid(
                        f'{reference} - {values}'
                    )
                }
            )


class STIX2ObservableObjectConverter(STIX2Converter, STIX2ObservableConverter):
    def __init__(self, main: 'ExternalSTIX2toMISPParser'):
        self._set_main_parser(main)
        self._mapping = ExternalSTIX2ObservableMapping

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
        if observable['used'][self.event_uuid]:
            return observable['misp_object']
        artifact = observable['observable']
        artifact_object = self._create_misp_object_from_observable_object(
            'artifact', artifact
        )
        super()._parse_artifact_observable(artifact_object, artifact)
        observable['used'][self.event_uuid] = True
        misp_object = self._main_parser._add_misp_object(
            artifact_object, artifact
        )
        observable['misp_object'] = misp_object
        return misp_object

    def _parse_file_observable_object(self, file_ref: str) -> MISPObject:
        observable = self.main_parser._observable[file_ref]
        if observable['used'][self.event_uuid]:
            return observable['misp_object']
        _file = observable['observable']
        file_object = self._create_misp_object_from_observable_object(
            'file', _file
        )
        super()._parse_file_observable(file_object, _file)
        observable['used'][self.event_uuid] = True
        misp_object = self.main_parser._add_misp_object(file_object, _file)
        observable['misp_object'] = misp_object
        return misp_object

    def _parse_network_connection_observable_object(
            self, observable: NetworkTraffic) -> MISPObject:
        connection_object = self._create_misp_object_from_observable_object(
            'network-connection', observable
        )
        super()._parse_network_traffic_observable(connection_object, observable)
        super()._parse_network_connection_observable(
            connection_object, observable
        )
        return connection_object

    def _parse_network_socket_observable_object(
            self, observable: NetworkTraffic) -> MISPObject:
        socket_object = self._create_misp_object_from_observable_object(
            'network-socket', observable
        )
        super()._parse_network_traffic_observable(socket_object, observable)
        super()._parse_network_socket_observable(socket_object, observable)
        return socket_object

    def _parse_network_traffic_observable_object(
            self, network_traffic_ref: str):
        observable = self.main_parser._observable[network_traffic_ref]
        network_traffic = observable['observable']
        feature = self._parse_network_traffic_observable_fields(network_traffic)
        network_object = getattr(self, feature)(network_traffic)
        observable['used'][self.event_uuid] = True
        misp_object = self.main_parser._add_misp_object(
            network_object, network_traffic
        )
        observable['misp_object'] = misp_object
        return misp_object

    @staticmethod
    def _parse_network_traffic_observable_fields(
            observable: NetworkTraffic) -> str:
        if getattr(observable, 'extensions', {}).get('socket-ext'):
            return '_parse_network_socket_observable_object'
        return '_parse_network_connection_observable_object'

    def _parse_software_observable_object(
            self, software_ref: str) -> MISPObject:
        observable = self.main_parser._observable[software_ref]
        if observable['used'][self.event_uuid]:
            return observable['misp_object']
        software = observable['observable']
        software_object = self._create_misp_object_from_observable_object(
            'software', software
        )
        super()._parse_software_observable(software_object, software)
        observable['used'][self.event_uuid] = True
        misp_object = self.main_parser._add_misp_object(
            software_object, software
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
        super()._parse_artifact_observable(artifact_object, artifact)
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
        super()._parse_file_observable(file_object, _file)
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
        super()._parse_software_observable(software_object, software)
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
