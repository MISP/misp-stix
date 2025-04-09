#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ..exceptions import (
    UndefinedObservableError, UndefinedSTIXObjectError,
    UnknownObservableMappingError, UnknownParsingFunctionError)
from .stix2_observable_converter import (
    ExternalSTIX2ObservableConverter, ExternalSTIX2ObservableMapping,
    InternalSTIX2ObservableConverter, InternalSTIX2ObservableMapping,
    STIX2ObservableConverter, _AUTONOMOUS_SYSTEM_TYPING, _EMAIL_ADDRESS_TYPING,
    _EXTENSION_TYPING, _NETWORK_TRAFFIC_TYPING, _PROCESS_TYPING)
from .stix2converter import _MAIN_PARSER_TYPING
from abc import ABCMeta
from collections import defaultdict, deque
from collections.abc import Generator
from datetime import datetime
from pymisp import MISPAttribute, MISPObject
from stix2.v20.observables import (
    File as File_v20, WindowsPEBinaryExt as WindowsPEBinaryExt_v20,
    WindowsRegistryValueType as WindowsRegistryValueType_v20)
from stix2.v20.sdo import ObservedData as ObservedData_v20
from stix2.v21.observables import (
    Artifact, AutonomousSystem, Directory, DomainName, File as File_v21,
    IPv4Address, IPv6Address, MACAddress, Mutex, Process, Software, URL,
    UserAccount, WindowsRegistryKey, X509Certificate,
    WindowsPEBinaryExt as WindowsPEBinaryExt_v21,
    WindowsRegistryValueType as WindowsRegistryValueType_v21)
from stix2.v21.sdo import ObservedData as ObservedData_v21
from typing import Optional, TYPE_CHECKING, Union

if TYPE_CHECKING:
    from ..external_stix2_to_misp import ExternalSTIX2toMISPParser
    from ..internal_stix2_to_misp import InternalSTIX2toMISPParser

_FILE_TYPING = Union[
    File_v20, File_v21
]
_GENERIC_OBSERVABLE_OBJECT_TYPING = Union[
    Artifact, Directory, File_v21, Process, Software, UserAccount,
    WindowsRegistryKey, X509Certificate
]
_GENERIC_OBSERVABLE_TYPING = Union[
    DomainName, IPv4Address, IPv6Address, MACAddress, Mutex, URL
]
_OBSERVABLE_OBJECTS_TYPING = Union[
    Artifact, AutonomousSystem, Directory, File_v21, Process, Software,
    UserAccount, WindowsRegistryKey, X509Certificate
]
_OBSERVED_DATA_TYPING = Union[
    ObservedData_v20, ObservedData_v21
]
_WINDOWS_PE_BINARY_EXT_TYPING = Union[
    WindowsPEBinaryExt_v20, WindowsPEBinaryExt_v21
]
_WINDOWS_REGISTRY_VALUE_TYPING = Union[
    WindowsRegistryValueType_v20, WindowsRegistryValueType_v21
]


class STIX2ObservedDataConverter(STIX2ObservableConverter, metaclass=ABCMeta):
    def __init__(self, main: _MAIN_PARSER_TYPING):
        self._set_main_parser(main)

    def _fetch_observable(self, object_ref: str) -> Union[dict, None]:
        return self.main_parser._observable.get(object_ref)

    # Errors handling
    def _missing_observable_object_error(
            self, observed_data_id: str, observable_object_id: str):
        self.main_parser._add_error(
            f'Missing observable object with id {observable_object_id} '
            'mentioned as object reference in the Observed Data object '
            f'with id {observed_data_id}.'
        )

    def _observable_mapping_error(
            self, observed_data_id: str, observable_types: Exception):
        self.main_parser._add_error(
            'Unable to map observable objects related to the Observed Data '
            f'object with id {observed_data_id} containing the folowing types'
            f": {observable_types.__str__().replace('_', ', ')}"
        )


class ExternalSTIX2ObservedDataConverter(
        STIX2ObservedDataConverter, ExternalSTIX2ObservableConverter):
    def __init__(self, main: 'ExternalSTIX2toMISPParser'):
        super().__init__(main)
        self._mapping = ExternalSTIX2ObservableMapping
        self._observable_relationships: dict

    @property
    def observable_relationships(self):
        if not hasattr(self, '_observable_relationships'):
            self._observable_relationships = defaultdict(set)
        return self._observable_relationships

    @property
    def referenced_ids(self):
        try:
            return self.__referenced_ids
        except AttributeError:
            self._extract_referenced_ids_from_observable_object_refs()
            return self.__referenced_ids

    def parse(self, observed_data_ref: str):
        observed_data = self.main_parser._get_stix_object(observed_data_ref)
        try:
            if hasattr(observed_data, 'object_refs'):
                self._parse_observable_object_refs(observed_data)
            else:
                self._parse_observable_objects(observed_data)
        except UnknownObservableMappingError as observable_types:
            self._observable_mapping_error(observed_data.id, observable_types)

    def parse_relationships(self):
        for misp_object in self.main_parser.misp_event.objects:
            object_uuid = misp_object.uuid
            if object_uuid in self.observable_relationships:
                for relationship in self.observable_relationships[object_uuid]:
                    referenced_uuid, relationship_type = relationship
                    self._handle_misp_object_references(
                        misp_object, referenced_uuid,
                        relationship_type=relationship_type
                    )

    ############################################################################
    #                  GENERIC OBSERVED DATA HANDLING METHODS                  #
    ############################################################################

    def _parse_observable_object_refs(self, observed_data: ObservedData_v21):
        observable_types = set(
            reference.split('--')[0] for reference in observed_data.object_refs
        )
        fields = '_'.join(sorted(observable_types))
        mapping = self._mapping.observable_mapping(fields)
        if mapping is None:
            if len(observable_types) == 1:
                raise UnknownObservableMappingError(fields)
            self._parse_multiple_observable_object_refs(observed_data)
        else:
            feature = f'_parse_{mapping}_observable_object_refs'
            try:
                parser = getattr(self, feature)
            except AttributeError:
                raise UnknownParsingFunctionError(feature)
            parser(observed_data)

    def _parse_observable_objects(self, observed_data: _OBSERVED_DATA_TYPING):
        observable_types = set(
            observable['type'] for observable in observed_data.objects.values()
        )
        fields = '_'.join(sorted(observable_types))
        mapping = self._mapping.observable_mapping(fields)
        if mapping is None:
            if len(observable_types) == 1:
                raise UnknownObservableMappingError(fields)
            self._parse_multiple_observable_objects(observed_data)
        else:
            feature = f'_parse_{mapping}_observable_objects'
            try:
                parser = getattr(self, feature)
            except AttributeError:
                raise UnknownParsingFunctionError(feature)
            parser(observed_data)

    ############################################################################
    #               MULTIPLE OBSERVABLE OBJECTS PARSING METHODS.               #
    ############################################################################

    def _extract_referenced_ids_from_observable_object_refs(self):
        self.__referenced_ids = defaultdict(set)
        for object_id, observable in self.main_parser._observable.items():
            for key, value in observable['observable'].items():
                if key.endswith('_ref'):
                    self.referenced_ids[value].add(object_id)
                if key.endswith('_refs'):
                    for reference in value:
                        self.referenced_ids[reference].add(object_id)

    @staticmethod
    def _extract_referenced_ids_from_observable_objects(
            **observable_objects: dict) -> dict:
        referenced_ids = defaultdict(set)
        for identifier, observable_object in observable_objects.items():
            for key, value in observable_object.items():
                if key.endswith('_ref'):
                    referenced_ids[value].add(identifier)
                if key.endswith('_refs'):
                    for reference in value:
                        referenced_ids[reference].add(identifier)
        return referenced_ids

    def _fetch_multiple_observable_ids(
            self, observed_data: _OBSERVED_DATA_TYPING,
            object_id: str) -> Generator:
        yield object_id
        for key, value in observed_data.objects[object_id].items():
            if key.endswith('_ref'):
                yield from self._fetch_multiple_observable_ids(
                    observed_data, value
                )
            if key.endswith('_refs'):
                for reference in value:
                    yield from self._fetch_multiple_observable_ids(
                        observed_data, reference
                    )

    def _parse_multiple_observable_object_refs(
            self, observed_data: ObservedData_v21):
        for object_ref in observed_data.object_refs:
            observable = self._fetch_observable(object_ref)
            if observable is None:
                self._missing_observable_object_error(
                    observed_data.id, object_ref
                )
                continue
            if observable['used'].get(self.event_uuid, False):
                self._handle_misp_object_fields(
                    observable['misp_object'], observed_data
                )
                continue
            object_type = object_ref.split('--')[0]
            mapping = self._mapping.observable_mapping(object_type)
            if mapping is None:
                self._observable_mapping_error(observed_data.id, object_type)
                continue
            feature = f'_parse_{mapping}_observable_object_refs'
            try:
                parser = getattr(self, feature)
            except AttributeError:
                self.main_parser._unknown_parsing_function_error(feature)
                continue
            parser(observed_data, object_ref)

    def _parse_multiple_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING):
        observable_objects = {
            object_id: {'used': False} for object_id in observed_data.objects
        }
        referenced_ids = self._extract_referenced_ids_from_observable_objects(
            **observed_data.objects
        )
        for object_id in observable_objects.keys():
            if observable_objects[object_id]['used']:
                continue
            observables = {
                identifier: observable_objects[identifier]
                for identifier in set(
                    self._fetch_multiple_observable_ids(
                        observed_data, object_id
                    )
                )
            }
            if object_id in referenced_ids:
                for reference in referenced_ids[object_id]:
                    observables[reference] = observable_objects[reference]
            observable_types = set(
                observed_data.objects[identifier].type
                for identifier in observables
            )
            object_type = '_'.join(sorted(observable_types))
            mapping = self._mapping.observable_mapping(object_type)
            if mapping is not None:
                feature = f'_parse_{mapping}_observable_objects'
                try:
                    parser = getattr(self, feature)
                except AttributeError:
                    self.main_parser._unknown_parsing_function_error(feature)
                    continue
                parser(observed_data, observables)
                observable_objects.update(observables)
                continue
            if len(observable_types) == 1:
                self._observable_mapping_error(observed_data.id, object_type)
                continue
            mapping = self._mapping.observable_mapping(
                observed_data.objects[object_id]['type']
            )
            if mapping is None:
                self._observable_mapping_error(observed_data.id, object_type)
                continue
            feature = f'_parse_{mapping}_observable_objects'
            try:
                parser = getattr(self, feature)
            except AttributeError:
                self.main_parser._unknown_parsing_function_error(feature)
                continue
            parser(observed_data, observable_objects)

    ############################################################################
    #                    OBSERVABLE OBJECTS PARSING METHODS                    #
    ############################################################################

    def _handle_observable_object_refs_parsing(
            self, observable: dict, observed_data: ObservedData_v21,
            *args: tuple) -> MISPObject:
        if observable['used'].get(self.event_uuid, False):
            misp_object = observable['misp_object']
            self._handle_misp_object_fields(misp_object, observed_data)
            return misp_object
        misp_object = self._parse_generic_observable_object_ref(
            observable['observable'], observed_data, *args
        )
        observable['misp_object'] = misp_object
        observable['used'][self.event_uuid] = True
        return misp_object

    def _handle_observable_objects_parsing(
            self, observable_objects: dict, object_id: str,
            observed_data: _OBSERVED_DATA_TYPING, *args: tuple) -> MISPObject:
        observable = observable_objects[object_id]
        if observable['used']:
            return observable['misp_object']
        misp_object = self._parse_generic_observable_object(
            observed_data, object_id, *args
        )
        observable.update({'misp_object': misp_object, 'used': True})
        return misp_object

    def _parse_artifact_observable_object_refs(
            self, observed_data: ObservedData_v21, *object_refs: tuple):
        for object_ref in object_refs or observed_data.object_refs:
            observable = self._fetch_observable(object_ref)
            if observable is None:
                self._missing_observable_object_error(
                    observed_data.id, object_ref
                )
                continue
            if observable['used'].get(self.event_uuid, False):
                self._handle_misp_object_fields(
                    observable['misp_object'], observed_data
                )
                continue
            artifact = observable['observable']
            misp_object = self._parse_generic_observable_object_ref(
                artifact, observed_data, 'artifact', False
            )
            observable['misp_object'] = misp_object
            observable['used'][self.event_uuid] = True

    def _parse_artifact_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING,
            observable_objects: Optional[dict] = None):
        if observable_objects is not None:
            for object_id, observable in observable_objects.items():
                if observable['used']:
                    continue
                misp_object = self._parse_generic_observable_object(
                    observed_data, object_id, 'artifact', False
                )
                observable.update({'misp_object': misp_object, 'used': True})
            return
        if len(observed_data.objects) == 1:
            return self._parse_generic_single_observable_object(
                observed_data, 'artifact', False
            )
        for identifier in observed_data.objects:
            self._parse_generic_observable_object(
                observed_data, identifier, 'artifact', False
            )

    def _parse_as_observable_object(
            self, observed_data: ObservedData_v20, object_id: str):
        autonomous_system = observed_data.objects[object_id]
        if autonomous_system.get('id') is not None:
            return self._parse_autonomous_system_observable_object_ref(
                autonomous_system, observed_data
            )
        object_id = f'{observed_data.id} - {object_id}'
        AS_value = self._parse_AS_value(autonomous_system.number)
        if hasattr(autonomous_system, 'name'):
            misp_object = self._create_misp_object_from_observable_object(
                'asn', observed_data, object_id
            )
            misp_object.add_attribute(
                'asn', AS_value,
                uuid=self.main_parser._create_v5_uuid(
                    f'{object_id} - asn - {AS_value}'
                )
            )
            description = autonomous_system.name
            misp_object.add_attribute(
                'description', description,
                uuid=self.main_parser._create_v5_uuid(
                    f'{object_id} - description - {description}'
                )
            )
            return self.main_parser._add_misp_object(misp_object, observed_data)
        return self.main_parser._add_misp_attribute(
            {
                'type': 'AS', 'value': AS_value,
                'uuid': self.main_parser._create_v5_uuid(object_id),
                'comment': f'Observed Data ID: {observed_data.id}',
                **self._parse_timeline(observed_data)
            },
            observed_data
        )

    def _parse_as_observable_object_refs(
            self, observed_data: ObservedData_v21, *object_refs: tuple):
        for object_ref in object_refs or observed_data.object_refs:
            observable = self._fetch_observable(object_ref)
            if observable is None:
                self._missing_observable_object_error(
                    observed_data.id, object_ref
                )
                continue
            if observable['used'].get(self.event_uuid, False):
                self._handle_misp_object_fields(
                    observable[
                        'misp_object' if 'misp_object' in observable
                        else 'misp_attribute'
                    ],
                    observed_data
                )
                continue
            autonomous_system = observable['observable']
            if not hasattr(autonomous_system, 'name'):
                attribute = self.main_parser._add_misp_attribute(
                    {
                        'type': 'AS',
                        'value': self._parse_AS_value(autonomous_system.number),
                        **self._parse_timeline(observed_data),
                        **self.main_parser._sanitise_attribute_uuid(
                            autonomous_system.id,
                            comment=f'Observed Data ID: {observed_data.id}'
                        )
                    },
                    observed_data
                )
                observable['misp_attribute'] = attribute
                observable['used'][self.event_uuid] = True
                continue
            misp_object = self._parse_autonomous_system_observable_object_ref(
                autonomous_system, observed_data
            )
            observable['misp_object'] = misp_object
            observable['used'][self.event_uuid] = True

    def _parse_as_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING,
            observable_objects: Optional[dict] = None):
        if observable_objects is not None:
            for object_id, observable in observable_objects.items():
                if observable['used']:
                    continue
                misp_content = self._parse_as_observable_object(
                    observed_data, object_id
                )
                feature = (
                    'misp_object' if isinstance(misp_content, MISPObject)
                    else 'misp_attribute'
                )
                observable.update({feature: misp_content, 'used': True})
            return
        if len(observed_data.objects) == 1:
            autonomous_system = next(iter(observed_data.objects.values()))
            if autonomous_system.get('id') is not None:
                return self._parse_autonomous_system_observable_object_ref(
                    autonomous_system, observed_data
                )
            AS_value = self._parse_AS_value(autonomous_system.number)
            if hasattr(autonomous_system, 'name'):
                misp_object = self._create_misp_object_from_observable_object(
                    'asn', observed_data
                )
                misp_object.add_attribute(
                    'asn', AS_value,
                    uuid=self.main_parser._create_v5_uuid(
                        f'{observed_data.id} - asn - {AS_value}'
                    )
                )
                description = autonomous_system.name
                misp_object.add_attribute(
                    'description', description,
                    uuid=self.main_parser._create_v5_uuid(
                        f'{observed_data.id} - description - {description}'
                    )
                )
                return self.main_parser._add_misp_object(
                    misp_object, observed_data
                )
            return self.main_parser._add_misp_attribute(
                {
                    'type': 'AS', 'value': AS_value,
                    **self._parse_timeline(observed_data),
                    **self.main_parser._sanitise_attribute_uuid(
                        observed_data.id
                    )
                },
                observed_data
            )
        for object_id in observed_data.objects:
            self._parse_as_observable_object(observed_data, object_id)

    def _parse_autonomous_system_observable_object_ref(
            self, autonomous_system: _AUTONOMOUS_SYSTEM_TYPING,
            observed_data: ObservedData_v21) -> MISPObject:
        misp_object = self._create_misp_object_from_observable_object_ref(
            'asn', autonomous_system, observed_data
        )
        AS_value = self._parse_AS_value(autonomous_system.number)
        misp_object.add_attribute(
            'asn', AS_value,
            uuid=self.main_parser._create_v5_uuid(
                f'{autonomous_system.id} - asn - {AS_value}'
            )
        )
        description = autonomous_system.name
        misp_object.add_attribute(
            'description', description,
            uuid=self.main_parser._create_v5_uuid(
                f'{autonomous_system.id} - description - {description}'
            )
        )
        return self.main_parser._add_misp_object(misp_object, observed_data)

    def _parse_contained_object_refs(
            self, observed_data: ObservedData_v21, misp_object_uuid: str,
            *contains_refs: tuple) -> Generator:
        for contained_ref in contains_refs:
            contained = self._fetch_observable(contained_ref)
            if contained is None:
                self._missing_observable_object_error(
                    observed_data.id, contained_ref
                )
                continue
            if contained['used'].get(self.event_uuid, False):
                contained_object = contained['misp_object']
                self._handle_misp_object_fields(contained_object, observed_data)
                yield contained_object.uuid
                continue
            if contained_ref not in observed_data.object_refs:
                self.observable_relationships[misp_object_uuid].add(
                    (
                        self.main_parser._sanitise_uuid(contained_ref),
                        'contains'
                    )
                )
                continue
            observable_object = contained['observable']
            contained_object = self._parse_generic_observable_object_ref(
                observable_object, observed_data, observable_object.type,
                (observable_object.type == 'directory')
            )
            contained['misp_object'] = contained_object
            contained['used'][self.event_uuid] = True
            yield contained_object.uuid

    def _parse_contained_objects(
            self, observed_data: _OBSERVED_DATA_TYPING,
            observable_objects: dict, *contained_refs: tuple) -> Generator:
        for contained_ref in contained_refs:
            contained = observable_objects[contained_ref]
            if contained['used']:
                yield contained['misp_object'].uuid
                continue
            observable_object = observed_data.objects[contained_ref]
            misp_object = self._parse_generic_observable_object(
                observed_data, contained_ref, observable_object.type,
                (observable_object.type == 'directory')
            )
            contained.update({'misp_object': misp_object, 'used': True})
            yield misp_object.uuid

    def _parse_directory_observable_object_refs(
            self, observed_data: ObservedData_v21, *object_refs: tuple):
        for object_ref in object_refs or observed_data.object_refs:
            observable = self._fetch_observable(object_ref)
            if observable is None:
                self._missing_observable_object_error(
                    observed_data.id, object_ref
                )
                continue
            if observable['used'].get(self.event_uuid, False):
                self._handle_misp_object_fields(
                    observable['misp_object'], observed_data
                )
                continue
            misp_object = self._handle_observable_object_refs_parsing(
                observable, observed_data, 'directory'
            )
            directory = observable['observable']
            if hasattr(directory, 'contains_refs'):
                self._handle_misp_object_references(
                    misp_object,
                    *self._parse_contained_object_refs(
                        observed_data, misp_object.uuid,
                        *directory.contains_refs
                    )
                )

    def _parse_directory_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING,
            observable_objects: Optional[dict] = None):
        if len(observed_data.objects) == 1:
            return self._parse_generic_single_observable_object(
                observed_data, 'directory'
            )
        if observable_objects is None:
            observable_objects = {
                object_id: {'used': False}
                for object_id in observed_data.objects
            }
        for object_id in observable_objects.keys():
            misp_object = self._handle_observable_objects_parsing(
                observable_objects, object_id, observed_data, 'directory'
            )
            directory = observed_data.objects[object_id]
            if hasattr(directory, 'contains_refs'):
                self._handle_misp_object_references(
                    misp_object,
                    *self._parse_contained_objects(
                        observed_data, observable_objects,
                        *directory.contains_refs
                    )
                )

    def _parse_domain_ip_observable_object_refs(
            self, observed_data: ObservedData_v21, *object_refs: tuple):
        for object_ref in object_refs or observed_data.object_refs:
            if not object_ref.startswith('domain-name--'):
                continue
            observable = self._fetch_observable(object_ref)
            if observable is None:
                self._missing_observable_object_error(
                    observed_data.id, object_ref
                )
                continue
            domain = observable['observable']
            if hasattr(domain, 'resolves_to_refs'):
                if observable['used'].get(self.event_uuid, False):
                    self._handle_misp_object_fields(
                        observable['misp_object'], observed_data
                    )
                    continue
                domain_object = self._create_misp_object('domain-ip')
                domain_object.from_dict(
                    comment=f'Observed Data ID: {observed_data.id}',
                    **self._parse_timeline(observed_data)
                )
                self.main_parser._check_sighting_replacements(
                    self.main_parser._sanitise_uuid(observed_data.id),
                    domain_object.uuid
                )
                domain_object.uuid = self.main_parser._create_v5_uuid(
                    ' - '.join(
                        (
                            domain.id,
                            *(
                                resolved_id for resolved_id
                                in domain.resolves_to_refs
                                if not resolved_id.startswith('domain-name--')
                            )
                        )
                    )
                )
                domain_object.add_attribute(
                    'domain', domain.value,
                    uuid=self.main_parser._create_v5_uuid(
                        f'{domain.id} - domain - {domain.value}'
                    )
                )
                misp_object = self.main_parser._add_misp_object(
                    domain_object, observed_data
                )
                observable['used'][self.event_uuid] = True
                observable['misp_object'] = misp_object
                for resolved_ref in domain.resolves_to_refs:
                    resolved = self._fetch_observable(resolved_ref)
                    if resolved is None:
                        self._missing_observable_object_error(
                            observed_data.id, resolved_ref
                        )
                        continue
                    resolved_observable = resolved['observable']
                    if resolved_observable.type == 'domain-name':
                        if resolved['used'].get(self.event_uuid, False):
                            resolved_object = (
                                resolved['misp_object']
                                if resolved.get('misp_object') is not None
                                else resolved['misp_attribute']
                            )
                            misp_object.add_reference(
                                resolved_object.uuid, 'resolves-to'
                            )
                        continue
                    value = resolved_observable.value
                    misp_object.add_attribute(
                        'ip', value, uuid=self.main_parser._create_v5_uuid(
                            f'{domain.id} - {resolved_ref} - ip - {value}'
                        )
                    )
                    resolved['used'][self.event_uuid] = True
                    resolved['misp_object'] = misp_object
                if object_ref in self.referenced_ids:
                    for referencing_id in self.referenced_ids[object_ref]:
                        referencing = self._fetch_observable(referencing_id)
                        if referencing is None:
                            self._missing_observable_object_error(
                                observed_data.id, referencing_id
                            )
                            continue
                        if referencing['observable'].type != 'domain-name':
                            continue
                        if referencing['used'].get(self.event_uuid, False):
                            referencing['misp_object'].add_reference(
                                misp_object.uuid, 'resolves-to'
                            )
                continue
            if observable['used'].get(self.event_uuid, False):
                self._handle_misp_object_fields(
                    observable['misp_attribute'], observed_data
                )
                continue
            attribute = self._parse_generic_observable_object_ref_as_attribute(
                domain, observed_data, 'domain'
            )
            observable['misp_attribute'] = attribute
            observable['used'][self.event_uuid] = True

    def _parse_domain_ip_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING):
        referenced_ids = self._extract_referenced_ids_from_observable_objects(
            **observed_data.objects
        )
        for identifier, observable_object in observed_data.objects.items():
            if identifier in referenced_ids:
                continue
            if hasattr(observable_object, 'resolves_to_refs'):
                object_id = f'{observed_data.id} - {identifier}'
                misp_object = self._create_misp_object_from_observable_object(
                    'domain-ip', observed_data, ' - '.join(
                        (object_id, *observable_object.resolves_to_refs)
                    )
                )
                misp_object.add_attribute(
                    'domain', observable_object.value,
                    uuid=self.main_parser._create_v5_uuid(
                        f'{object_id} - domain - {observable_object.value}'
                    )
                )
                for resolved_ref in observable_object.resolves_to_refs:
                    resolved_object = observed_data.objects[resolved_ref]
                    object_relation = (
                        'domain' if resolved_object.type == 'domain-name'
                        else 'ip'
                    )
                    misp_object.add_attribute(
                        object_relation, resolved_object.value,
                        uuid=self.main_parser._create_v5_uuid(
                            f'{object_id} - {resolved_ref} - '
                            f'{object_relation} - {resolved_object.value}'
                        )
                    )
                self.main_parser._add_misp_object(misp_object, observed_data)
                continue
            self._parse_generic_observable_object_as_attribute(
                observed_data, identifier, 'domain'
            )

    def _parse_domain_observable_object_refs(
            self, observed_data: ObservedData_v21, *object_refs: tuple):
        for object_ref in object_refs or observed_data.object_refs:
            observable = self._fetch_observable(object_ref)
            if observable is None:
                self._missing_observable_object_error(
                    observed_data.id, object_ref
                )
                continue
            if observable['used'].get(self.event_uuid, False):
                self._handle_misp_object_fields(
                    observable['misp_attribute'], observed_data
                )
                continue
            domain = observable['observable']
            if hasattr(domain, 'resolves_to_refs'):
                self._parse_domain_ip_observable_object_refs(
                    observed_data, object_ref
                )
                continue
            attribute = self._parse_generic_observable_object_ref_as_attribute(
                domain, observed_data, 'domain'
            )
            observable['misp_attribute'] = attribute
            observable['used'][self.event_uuid] = True

    def _parse_domain_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING,
            observable_objects: Optional[dict] = None):
        if observable_objects is not None:
            for object_id, observable in observable_objects.items():
                if observable['used']:
                    continue
                attribute = self._parse_generic_observable_object_as_attribute(
                    observed_data, object_id, 'domain'
                )
                observable.update({'misp_attribute': attribute, 'used': True})
            return
        if len(observed_data.objects) == 1:
            domain = next(iter(observed_data.objects.values()))
            if domain.get('id') is not None:
                return self._parse_generic_observable_object_ref_as_attribute(
                    domain, observed_data, 'domain'
                )
            return self.main_parser._add_misp_attribute(
                {
                    'type': 'domain', 'value': domain.value,
                    **self._parse_timeline(observed_data),
                    **self.main_parser._sanitise_attribute_uuid(
                        observed_data.id
                    )
                },
                observed_data
            )
        for identifier in observed_data.objects:
            self._parse_generic_observable_object_as_attribute(
                observed_data, identifier, 'domain'
            )

    def _parse_email_address_observable_object(
            self, observed_data: ObservedData_v20,
            identifier: str) -> Generator:
        attribute = {
            'comment': f'Observed Data ID: {observed_data.id}',
            **self._parse_timeline(observed_data)
        }
        email_address = observed_data.objects[identifier]
        object_id = f'{observed_data.id} - {identifier}'
        if hasattr(email_address, 'display_name'):
            yield self.main_parser._add_misp_attribute(
                {
                    'type': 'email-dst', 'value': email_address.value,
                    'uuid': self.main_parser._create_v5_uuid(
                        f'{object_id} - email-dst - {email_address.value}'
                    ),
                    **attribute
                },
                observed_data
            )
            attr_type = 'email-dst-display-name'
            display_name = email_address.display_name
            yield self.main_parser._add_misp_attribute(
                {
                    'type': attr_type, 'value': display_name, **attribute,
                    'uuid': self.main_parser._create_v5_uuid(
                        f'{object_id} - {attr_type} - {display_name}'
                    )
                },
                observed_data
            )
        else:
            yield self.main_parser._add_misp_attribute(
                {
                    'type': 'email-dst', 'value': email_address.value,
                    'uuid': self.main_parser._create_v5_uuid(object_id),
                    **attribute
                },
                observed_data
            )

    def _parse_email_address_observable_object_ref(
            self, email_address: _EMAIL_ADDRESS_TYPING,
            observed_data: _OBSERVED_DATA_TYPING) -> Generator:
        if hasattr(email_address, 'display_name'):
            attribute = {
                'comment': f'Observed Data ID: {observed_data.id}',
                **self._parse_timeline(observed_data)
            }
            address = email_address.value
            yield self.main_parser._add_misp_attribute(
                {
                    'type': 'email-dst', 'value': address, **attribute,
                    'uuid': self.main_parser._create_v5_uuid(
                        f'{email_address.id} - email-dst - {address}'
                    )
                },
                observed_data
            )
            attr_type = 'email-dst-display-name'
            display_name = email_address.display_name
            yield self.main_parser._add_misp_attribute(
                {
                    'type': attr_type, 'value': display_name, **attribute,
                    'uuid': self.main_parser._create_v5_uuid(
                        f'{email_address.id} - {attr_type} - {display_name}'
                    )
                },
                observed_data
            )
        else:
            yield self.main_parser._add_misp_attribute(
                {
                    'type': 'email-dst', 'value': email_address.value,
                    **self._parse_timeline(observed_data),
                    **self.main_parser._sanitise_attribute_uuid(
                        email_address.id,
                        comment=f'Observed Data ID: {observed_data.id}'
                    )
                },
                observed_data
            )

    def _parse_email_address_observable_object_refs(
            self, observed_data: ObservedData_v21, *object_refs: tuple):
        for object_ref in object_refs or observed_data.object_refs:
            observable = self._fetch_observable(object_ref)
            if observable is None:
                self._missing_observable_object_error(
                    observed_data.id, object_ref
                )
                continue
            if observable['used'].get(self.event_uuid, False):
                for attribute in observable['misp_attribute']:
                    self._handle_misp_object_fields(attribute, observed_data)
                continue
            email_address = observable['observable']
            observable['misp_attribute'] = tuple(
                self._parse_email_address_observable_object_ref(
                    email_address, observed_data
                )
            )
            observable['used'][self.event_uuid] = True

    def _parse_email_address_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING,
            observable_objects: Optional[dict] = None):
        if observable_objects is not None:
            for object_id, observable in observable_objects.items():
                if observable['used']:
                    continue
                attributes = tuple(
                    self._parse_email_address_observable_object(
                        observed_data, object_id
                    )
                )
                observable.update(
                    {
                        'used': True,
                        'misp_attribute': (
                            attributes[0] if len(attributes) == 1
                            else attributes
                        )
                    }
                )
            return
        if len(observed_data.objects) == 1:
            email_address = next(iter(observed_data.objects.values()))
            if email_address.get('id') is not None:
                return self._parse_email_address_observable_object_ref(
                    email_address, observed_data
                )
            address = email_address.value
            if hasattr(email_address, 'display_name'):
                attribute = {
                    'comment': f'Observed Data ID: {observed_data.id}',
                    **self._parse_timeline(observed_data)
                }
                self.main_parser._add_misp_attribute(
                    {
                        'type': 'email-dst', 'value': address, **attribute,
                        'uuid': self.main_parser._create_v5_uuid(
                            f'{observed_data.id} - email-dst - {address}'
                        )
                    },
                    observed_data
                )
                attr_type = 'email-dst-display-name'
                display_name = email_address.display_name
                self.main_parser._add_misp_attribute(
                    {
                        'type': attr_type, 'value': display_name, **attribute,
                        'uuid': self.main_parser._create_v5_uuid(
                            f'{observed_data.id} - {attr_type} - {display_name}'
                        )
                    },
                    observed_data
                )
            else:
                self.main_parser._add_misp_attribute(
                    {
                        'type': 'email-dst', 'value': address,
                        **self._parse_timeline(observed_data),
                        **self.main_parser._sanitise_attribute_uuid(
                            observed_data.id
                        )
                    },
                    observed_data
                )
        else:
            for identifier in observed_data.objects:
                deque(
                    self._parse_email_address_observable_object(
                        observed_data, identifier
                    ),
                    maxlen=0
                )

    def _parse_email_message_observable_object_refs(
            self, observed_data: ObservedData_v21, *object_refs: tuple):
        for object_ref in object_refs or observed_data.object_refs:
            if object_ref.split('--')[0] != 'email-message':
                continue
            observable = self._fetch_observable(object_ref)
            if observable is None:
                self._missing_observable_object_error(
                    observed_data.id, object_ref
                )
                continue
            email_message = observable['observable']
            misp_object = self._parse_generic_observable_object_ref(
                email_message, observed_data, 'email', False
            )
            observable['used'][self.event_uuid] = True
            observable['misp_object'] = misp_object
            if hasattr(email_message, 'from_ref'):
                observable = self._fetch_observable(email_message.from_ref)
                if observable is None:
                    self._missing_observable_object_error(
                        observed_data.id, email_message.from_ref
                    )
                else:
                    attributes = self._parse_email_reference_observable(
                        observable['observable'], 'from'
                    )
                    for attribute in attributes:
                        misp_object.add_attribute(**attribute)
                    self._handle_misp_object_storage(observable, misp_object)
            for feature in ('to', 'cc', 'bcc'):
                field = f'{feature}_refs'
                if hasattr(email_message, field):
                    for reference in getattr(email_message, field):
                        observable = self._fetch_observable(reference)
                        if observable is None:
                            self._missing_observable_object_error(
                                observed_data.id, reference
                            )
                            continue
                        attributes = self._parse_email_reference_observable(
                            observable['observable'], feature
                        )
                        for attribute in attributes:
                            misp_object.add_attribute(**attribute)
                        self._handle_misp_object_storage(
                            observable, misp_object
                        )
            if hasattr(email_message, 'body_multipart'):
                for index, multipart in enumerate(email_message.body_multipart):
                    if hasattr(multipart, 'body'):
                        misp_object.add_attribute(
                            'email-body', multipart.body,
                            uuid=self.main_parser._create_v5_uuid(
                                f'{email_message.id} - body_multipart - {index}'
                                f' - email-body - {multipart.body}'
                            )
                        )
                        continue
                    observable = self._fetch_observable(
                        multipart.body_raw_ref
                    )
                    if observable is None:
                        self._missing_observable_object_error(
                            observed_data.id, multipart.body_raw_ref
                        )
                        continue
                    if observable['used'].get(self.event_uuid, False):
                        referenced_object = observable['misp_object']
                        self._handle_misp_object_fields(
                            referenced_object, observed_data
                        )
                        misp_object.add_reference(
                            referenced_object.uuid, 'contains'
                        )
                        continue
                    observable_object = observable['observable']
                    if observable_object.type == 'artifact':
                        artifact = self._parse_generic_observable_object_ref(
                            observable_object, observed_data, 'artifact', False
                        )
                        misp_object.add_reference(artifact.uuid, 'contains')
                        observable['misp_object'] = artifact
                        observable['used'][self.event_uuid] = True
                        continue
                    file_object = self._parse_generic_observable_object_ref(
                        observable_object, observed_data, 'file', False
                    )
                    misp_object.add_reference(file_object.uuid, 'contains')
                    observable['misp_object'] = file_object
                    observable['used'][self.event_uuid] = True
                    self._parse_file_observable_object_ref_references(
                        file_object, observable_object, observed_data
                    )

    def _parse_email_message_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING):
        if len(observed_data.objects) == 1:
            misp_object = self._parse_generic_single_observable_object(
                observed_data, 'email', False
            )
            email_message = observed_data.objects['0']
            if hasattr(email_message, 'body_multipart'):
                for index, multipart in enumerate(email_message.body_multipart):
                    if hasattr(multipart, 'body'):
                        misp_object.add_attribute(
                            'email-body', multipart.body,
                            uuid=self.main_parser._create_v5_uuid(
                                f'{observed_data.id} - body_multipart - {index}'
                                f' - email-body - {multipart.body}'
                            )
                        )
                        continue
        observable_objects = {
            object_id: {'used': False}
            for object_id, observable in observed_data.objects.items()
            if observable.type in ('file', 'artifact')
        }
        for identifier, observable in observed_data.objects.items():
            if observable.type != 'email-message':
                continue
            misp_object = self._parse_generic_observable_object(
                observed_data, identifier, 'email', False
            )
            object_id = f'{observed_data.id} - {identifier}'
            if hasattr(observable, 'from_ref'):
                from_ref = observable.from_ref
                attributes = self._parse_email_reference_observable(
                    observed_data.objects[from_ref],
                    'from', f'{object_id} - {from_ref}'
                )
                for attribute in attributes:
                    misp_object.add_attribute(**attribute)
            for feature in ('to', 'cc', 'bcc'):
                field = f'{feature}_refs'
                if hasattr(observable, field):
                    for reference in getattr(observable, field):
                        attributes = self._parse_email_reference_observable(
                            observed_data.objects[reference],
                            feature, f'{object_id} - {reference}'
                        )
                        for attribute in attributes:
                            misp_object.add_attribute(**attribute)
            if hasattr(observable, 'body_multipart'):
                for index, multipart in enumerate(observable.body_multipart):
                    if hasattr(multipart, 'body'):
                        misp_object.add_attribute(
                            'email-body', multipart.body,
                            uuid=self.main_parser._create_v5_uuid(
                                f'{object_id} - body_multipart - {index}'
                                f' - email-body - {multipart.body}'
                            )
                        )
                        continue
                    body_ref = multipart.body_raw_ref
                    if observable_objects[body_ref]['used']:
                        misp_object.add_reference(
                            observable_objects[body_ref]['misp_object'].uuid,
                            'contains'
                        )
                        continue
                    if observed_data.objects[body_ref].type == 'artifact':
                        artifact = self._parse_generic_observable_object(
                            observed_data, body_ref, 'artifact', False
                        )
                        misp_object.add_reference(artifact.uuid, 'contains')
                        continue
                    file_object = self._parse_generic_observable_object(
                        observed_data, body_ref, 'file', False
                    )
                    misp_object.add_reference(file_object.uuid, 'contains')
                    self._parse_file_observable_object_references(
                        file_object, observable, observed_data,
                        observable_objects, body_ref
                    )

    def _parse_file_observable_object_ref_references(
            self, misp_object: MISPObject, observable_object: File_v21,
            observed_data: ObservedData_v21):
        if hasattr(observable_object, 'extensions'):
            extensions = observable_object.extensions
            if extensions.get('archive-ext'):
                archive_ext = extensions['archive-ext']
                if hasattr(archive_ext, 'comment'):
                    misp_object.from_dict(
                        comment=' - '.join(
                            (archive_ext.comment, misp_object.comment)
                        )
                    )
                self._handle_misp_object_references(
                    misp_object,
                    *self._parse_contained_object_refs(
                        observed_data, misp_object.uuid,
                        *archive_ext.contains_refs
                    )
                )
            if extensions.get('windows-pebinary-ext'):
                windows_pe_ext = extensions['windows-pebinary-ext']
                pe_object_uuid = self._parse_file_pe_extension_observable(
                    windows_pe_ext, observed_data,
                    f'{observable_object.id} - windows-pebinary-ext'
                )
                misp_object.add_reference(pe_object_uuid, 'includes')
        if hasattr(observable_object, 'parent_directory_ref'):
            parent_ref = observable_object.parent_directory_ref
            if parent_ref not in observed_data.object_refs:
                self.observable_relationships[misp_object.uuid].add(
                    (
                        self.main_parser._sanitise_uuid(parent_ref),
                        'contained-in'
                    )
                )
            else:
                parent = self._fetch_observable(parent_ref)
                if parent is None:
                    self._missing_observable_object_error(
                        observed_data.id, parent_ref
                    )
                else:
                    parent_object = self._handle_observable_object_refs_parsing(
                        parent, observed_data, 'directory'
                    )
                    self._handle_misp_object_references(
                        misp_object, parent_object.uuid,
                        relationship_type='contained-in'
                    )
        if hasattr(observable_object, 'content_ref'):
            content_ref = observable_object.content_ref
            if content_ref not in observed_data.object_refs:
                content_uuid = self.main_parser._sanitise_uuid(content_ref)
                self.observable_relationships[content_uuid].add(
                    (misp_object.uuid, 'content-of')
                )
            else:
                content = self._fetch_observable(content_ref)
                if content is None:
                    self._missing_observable_object_error(
                        observed_data.id, content_ref
                    )
                else:
                    artifact = self._handle_observable_object_refs_parsing(
                        content, observed_data, 'artifact', False
                    )
                    self._handle_misp_object_references(
                        artifact, misp_object.uuid,
                        relationship_type='content-of'
                    )

    def _parse_file_observable_object_references(
            self, misp_object: MISPObject, file_object: _FILE_TYPING,
            observed_data: _OBSERVED_DATA_TYPING,
            observable_objects: dict, object_id: str):
        if hasattr(file_object, 'extensions'):
            extensions = file_object.extensions
            if extensions.get('archive-ext'):
                archive_ext = extensions['archive-ext']
                if hasattr(archive_ext, 'comment'):
                    misp_object.from_dict(
                        comment=' - '.join(
                            (archive_ext.comment, misp_object.comment)
                        )
                    )
                self._handle_misp_object_references(
                    misp_object,
                    *self._parse_contained_objects(
                        observed_data, observable_objects,
                        *archive_ext.contains_refs
                    )
                )
            if extensions.get('windows-pebinary-ext'):
                pe_object_uuid = self._parse_file_pe_extension_observable(
                    extensions['windows-pebinary-ext'], observed_data,
                    f'{observed_data.id} - '
                    f'{object_id} - windows-pebinary-ext'
                )
                misp_object.add_reference(pe_object_uuid, 'includes')
        if hasattr(file_object, 'parent_directory_ref'):
            parent_ref = file_object.parent_directory_ref
            parent_object = self._handle_observable_objects_parsing(
                observable_objects, parent_ref, observed_data, 'directory'
            )
            self._handle_misp_object_references(
                misp_object, parent_object.uuid,
                relationship_type='contained-in'
            )
        if hasattr(file_object, 'content_ref'):
            content_ref = file_object.content_ref
            artifact = self._handle_observable_objects_parsing(
                observable_objects, content_ref, observed_data,
                'artifact', False
            )
            self._handle_misp_object_references(
                artifact, misp_object.uuid, relationship_type='content-of'
            )

    def _parse_file_observable_object_refs(
            self, observed_data: ObservedData_v21, *object_refs: tuple):
        for object_ref in object_refs or observed_data.object_refs:
            object_type = object_ref.split('--')[0]
            observable = self._fetch_observable(object_ref)
            if observable is None:
                self._missing_observable_object_error(
                    observed_data.id, object_ref
                )
                continue
            misp_object = self._handle_observable_object_refs_parsing(
                observable, observed_data, object_type,
                (object_type == 'directory')
            )
            if object_type == 'artifact':
                continue
            observable_object = observable['observable']
            if hasattr(observable_object, 'contains_refs'):
                self._handle_misp_object_references(
                    misp_object,
                    *self._parse_contained_object_refs(
                        observed_data, misp_object.uuid,
                        *observable_object.contains_refs
                    )
                )
            if object_type == 'directory':
                continue
            self._parse_file_observable_object_ref_references(
                misp_object, observable_object, observed_data
            )

    def _parse_file_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING,
            observable_objects: Optional[dict] = None):
        if len(observed_data.objects) == 1:
            misp_object = self._parse_generic_single_observable_object(
                observed_data, 'file', False
            )
            observable = observed_data.objects['0']
            if getattr(observable, 'extensions', {}).get(
                    'windows-pebinary-ext'):
                object_id = getattr(observable, 'id', observed_data.id)
                pe_object_uuid = self._parse_file_pe_extension_observable(
                    observable.extensions['windows-pebinary-ext'],
                    observed_data, f'{object_id} - windows-pebinary-ext'
                )
                misp_object.add_reference(pe_object_uuid, 'includes')
            return misp_object
        if observable_objects is None:
            observable_objects = {
                object_id: {'used': False}
                for object_id in observed_data.objects
            }
        for object_id, observable in observable_objects.items():
            observable_object = observed_data.objects[object_id]
            object_type = observable_object.type
            if object_type == 'artifact':
                if not observable['used']:
                    misp_object = self._parse_generic_observable_object(
                        observed_data, object_id, object_type, False
                    )
                    observable.update(
                        {'misp_object': misp_object, 'used': True}
                    )
                continue
            misp_object = self._handle_observable_objects_parsing(
                observable_objects, object_id, observed_data,
                object_type, (object_type == 'directory')
            )
            if hasattr(observable_object, 'contains_refs'):
                self._handle_misp_object_references(
                    misp_object,
                    *self._parse_contained_objects(
                        observed_data, observable_objects,
                        *observable_object.contains_refs
                    )
                )
            if object_type == 'directory':
                continue
            self._parse_file_observable_object_references(
                misp_object, observable_object, observed_data,
                observable_objects, object_id
            )

    def _parse_file_pe_extension_observable(
            self, pe_extension: _WINDOWS_PE_BINARY_EXT_TYPING,
            observed_data: _OBSERVED_DATA_TYPING, object_id: str) -> str:
        pe_object = self._create_misp_object_from_observable_object(
            'pe', observed_data, object_id
        )
        attributes = self._parse_pe_extension_observable(
            pe_extension, object_id
        )
        for attribute in attributes:
            pe_object.add_attribute(**attribute)
        misp_object = self.main_parser._add_misp_object(
            pe_object, observed_data
        )
        if hasattr(pe_extension, 'sections'):
            for section_id, section in enumerate(pe_extension.sections):
                section_reference = f'{object_id} - section - {section_id}'
                section_object = self._create_misp_object_from_observable_object(
                    'pe-section', observed_data, section_reference
                )
                attributes = self._parse_pe_section_observable(
                    section, section_reference
                )
                for attribute in attributes:
                    section_object.add_attribute(**attribute)
                self.main_parser._add_misp_object(section_object, observed_data)
                misp_object.add_reference(section_object.uuid, 'includes')
        return misp_object.uuid

    def _parse_generic_observable_object(
            self, observed_data: _OBSERVED_DATA_TYPING, object_id: str,
            name: str, generic: Optional[bool] = True) -> MISPObject:
        observable_object = observed_data.objects[object_id]
        if observable_object.get('id') is not None:
            return self._parse_generic_observable_object_ref(
                observable_object, observed_data, name, generic
            )
        object_id = f'{observed_data.id} - {object_id}'
        misp_object = self._create_misp_object_from_observable_object(
            name, observed_data, object_id
        )
        _name = name.replace('-', '_')
        attributes = (
            self._parse_generic_observable(observable_object, _name, object_id)
            if generic else getattr(self, f'_parse_{_name}_observable')(
                observable_object, object_id
            )
        )
        for attribute in attributes:
            misp_object.add_attribute(**attribute)
        return self.main_parser._add_misp_object(misp_object, observed_data)

    def _parse_generic_observable_object_as_attribute(
            self, observed_data: _OBSERVED_DATA_TYPING, identifier: str,
            attribute_type: str, feature: Optional[str] = 'value'
            ) -> MISPAttribute:
        observable_object = observed_data.objects[identifier]
        if hasattr(observable_object, 'id'):
            return self._parse_generic_observable_object_ref_as_attribute(
                observable_object, observed_data, attribute_type, feature
            )
        return self.main_parser._add_misp_attribute(
            {
                'type': attribute_type,
                'value': getattr(observable_object, feature),
                'comment': f'Observed Data ID: {observed_data.id}',
                'uuid': self.main_parser._create_v5_uuid(
                    f'{observed_data.id} - {identifier}'
                ),
                **self._parse_timeline(observed_data)
            },
            observed_data
        )

    def _parse_generic_observable_object_ref(
            self, observable_object: _GENERIC_OBSERVABLE_OBJECT_TYPING,
            observed_data: ObservedData_v21, name: str,
            generic: Optional[bool] = True,
            mapping_name: Optional[str] = None) -> MISPObject:
        misp_object = self._create_misp_object_from_observable_object_ref(
            name, observable_object, observed_data
        )
        if mapping_name is None:
            mapping_name = name.replace('-', '_')
        attributes = (
            self._parse_generic_observable(observable_object, mapping_name)
            if generic else getattr(self, f'_parse_{mapping_name}_observable')(
                observable_object
            )
        )
        for attribute in attributes:
            misp_object.add_attribute(**attribute)
        return self.main_parser._add_misp_object(misp_object, observed_data)

    def _parse_generic_observable_object_ref_as_attribute(
            self, observable_object: _GENERIC_OBSERVABLE_TYPING,
            observed_data: _OBSERVED_DATA_TYPING, attribute_type: str,
            feature: Optional[str] = 'value') -> MISPAttribute:
        return self.main_parser._add_misp_attribute(
            {
                'type': attribute_type,
                'value': getattr(observable_object, feature),
                **self._parse_timeline(observed_data),
                **self.main_parser._sanitise_attribute_uuid(
                    observable_object.id,
                    comment=f'Observed Data ID: {observed_data.id}'
                ),
            },
            observed_data
        )

    def _parse_generic_single_observable_object(
            self, observed_data: _OBSERVED_DATA_TYPING, name: str,
            generic: Optional[bool] = True) -> MISPObject:
        observable_object = next(iter(observed_data.objects.values()))
        if observable_object.get('id') is not None:
            return self._parse_generic_observable_object_ref(
                observable_object, observed_data, name, generic
            )
        misp_object = self._create_misp_object_from_observable_object(
            name, observed_data
        )
        _name = name.replace('-', '_')
        object_id = observed_data.id
        attributes = (
            self._parse_generic_observable(observable_object, _name, object_id)
            if generic else getattr(self, f'_parse_{_name}_observable')(
                observable_object, object_id
            )
        )
        for attribute in attributes:
            misp_object.add_attribute(**attribute)
        return self.main_parser._add_misp_object(misp_object, observed_data)

    def _parse_ip_address_observable_object_refs(
            self, observed_data: ObservedData_v21, *object_refs: tuple):
        for object_ref in object_refs or observed_data.object_refs:
            observable = self._fetch_observable(object_ref)
            if observable is None:
                self._missing_observable_object_error(
                    observed_data.id, object_ref
                )
                continue
            if observable['used'].get(self.event_uuid, False):
                self._handle_misp_object_fields(
                    observable['misp_attribute'], observed_data
                )
                continue
            attribute = self._parse_generic_observable_object_ref_as_attribute(
                observable['observable'], observed_data, 'ip-dst'
            )
            observable['misp_attributes'] = attribute
            observable['used'][self.event_uuid] = True

    def _parse_ip_address_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING,
            observable_objects: Optional[dict] = None):
        if observable_objects is not None:
            for object_id, observable in observable_objects.items():
                if observable['used']:
                    continue
                attribute = self._parse_generic_observable_object_as_attribute(
                    observed_data, object_id, 'ip-dst'
                )
                observable.update({'misp_attribute': attribute, 'used': True})
            return
        if len(observed_data.objects) == 1:
            ip_address = next(iter(observed_data.objects.values()))
            if ip_address.get('id') is not None:
                return self._parse_generic_observable_object_ref_as_attribute(
                    ip_address, observed_data, 'ip-dst'
                )
            return self.main_parser._add_misp_attribute(
                {
                    'type': 'ip-dst', 'value': ip_address.value,
                    **self._parse_timeline(observed_data),
                    **self.main_parser._sanitise_attribute_uuid(
                        observed_data.id
                    )
                },
                observed_data
            )
        for identifier in observed_data.objects:
            self._parse_generic_observable_object_as_attribute(
                observed_data, identifier, 'ip-dst'
            )

    def _parse_mac_address_observable_object_refs(
            self, observed_data: ObservedData_v21, *object_refs: tuple):
        for object_ref in object_refs or observed_data.object_refs:
            observable = self._fetch_observable(object_ref)
            if observable is None:
                self._missing_observable_object_error(
                    observed_data.id, object_ref
                )
                continue
            if observable['used'].get(self.event_uuid, False):
                self._handle_misp_object_fields(
                    observable['misp_attribute'], observed_data
                )
                continue
            attribute = self._parse_generic_observable_object_ref_as_attribute(
                observable['observable'], observed_data, 'mac-address'
            )
            observable['misp_attribute'] = attribute
            observable['used'][self.event_uuid] = True

    def _parse_mac_address_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING,
            observable_objects: Optional[dict] = None):
        if observable_objects is not None:
            for object_id, observable in observable_objects.items():
                if observable['used']:
                    continue
                attribute = self._parse_generic_observable_object_as_attribute(
                    observed_data, object_id, 'mac-address'
                )
                observable.update({'misp_attribute': attribute, 'used': True})
            return
        if len(observed_data.objects) == 1:
            mac_address = next(iter(observed_data.objects.values()))
            if mac_address.get('id') is not None:
                return self._parse_generic_observable_object_ref_as_attribute(
                    mac_address, observed_data, 'mac-address'
                )
            return self.main_parser._add_misp_attribute(
                {
                    'type': 'mac-address', 'value': mac_address.value,
                    **self._parse_timeline(observed_data),
                    **self.main_parser._sanitise_attribute_uuid(
                        observed_data.id
                    )
                },
                observed_data
            )
        for identifier in observed_data.objects:
            self._parse_generic_observable_object_as_attribute(
                observed_data, identifier, 'mac-address'
            )

    def _parse_mutex_observable_object_refs(
            self, observed_data: ObservedData_v21, *object_refs: tuple):
        for object_ref in object_refs or observed_data.object_refs:
            observable = self._fetch_observable(object_ref)
            if observable is None:
                self._missing_observable_object_error(
                    observed_data.id, object_ref
                )
                continue
            if observable['used'].get(self.event_uuid, False):
                self._handle_misp_object_fields(
                    observable['misp_attribute'], observed_data
                )
                continue
            attribute = self._parse_generic_observable_object_ref_as_attribute(
                observable['observable'], observed_data, 'mutex', feature='name'
            )
            observable['misp_attribute'] = attribute
            observable['used'][self.event_uuid] = True

    def _parse_mutex_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING,
            observable_objects: Optional[dict] = None):
        if observable_objects is not None:
            for object_id, observable in observable_objects.items():
                if observable['used']:
                    continue
                attribute = self._parse_generic_observable_object_as_attribute(
                    observed_data, object_id, 'mutex', feature='name'
                )
                observable.update({'misp_attribute': attribute, 'used': True})
            return
        if len(observed_data.objects) == 1:
            mutex = next(iter(observed_data.objects.values()))
            if mutex.get('id') is not None:
                return self._parse_generic_observable_object_ref_as_attribute(
                    mutex, observed_data, 'mutex', feature='name'
                )
            return self.main_parser._add_misp_attribute(
                {
                    'type': 'mutex', 'value': mutex.name,
                    **self._parse_timeline(observed_data),
                    **self.main_parser._sanitise_attribute_uuid(
                        observed_data.id
                    )
                },
                observed_data
            )
        for identifier in observed_data.objects:
            self._parse_generic_observable_object_as_attribute(
                observed_data, identifier, 'mutex', feature='name'
            )

    def _parse_network_traffic_observable_object(
            self, observable_objects: dict, identifier: str,
            observed_data: _OBSERVED_DATA_TYPING, name: str) -> MISPObject:
        network_traffic = observed_data.objects[identifier]
        if hasattr(network_traffic, 'id'):
            return self._parse_network_traffic_observable_object_ref(
                network_traffic, observed_data, name
            )
        observable = observable_objects[identifier]
        if observable['used']:
            return observable['misp_object']
        object_id = f'{observed_data.id} - {identifier}'
        misp_object = self._create_misp_object_from_observable_object(
            name, observed_data, object_id
        )
        feature = f"_parse_{name.replace('-', '_')}_observable"
        attributes = getattr(self, feature)(network_traffic, object_id)
        for attribute in attributes:
            misp_object.add_attribute(**attribute)
        observable.update({'misp_object': misp_object, 'used': True})
        return self.main_parser._add_misp_object(misp_object, observed_data)

    def _parse_network_traffic_observable_object_ref(
            self, observable: dict, observed_data: ObservedData_v21,
            name: str) -> MISPObject:
        if observable['used'].get(self.event_uuid, False):
            misp_object = observable['misp_object']
            self._handle_misp_object_fields(misp_object, observed_data)
            return misp_object
        misp_object = self._create_misp_object_from_observable_object_ref(
            name, observable['observable'], observed_data
        )
        feature = f"_parse_{name.replace('-', '_')}_observable"
        attributes = getattr(self, feature)(observable['observable'])
        for attribute in attributes:
            misp_object.add_attribute(**attribute)
        observable['used'][self.event_uuid] = True
        observable['misp_object'] = misp_object
        return self.main_parser._add_misp_object(misp_object, observed_data)

    def _parse_network_traffic_observable_object_refs(
            self, observed_data: ObservedData_v21, *object_refs: tuple):
        for object_ref in object_refs or observed_data.object_refs:
            if object_ref.split('--')[0] != 'network-traffic':
                continue
            observable = self._fetch_observable(object_ref)
            if observable is None:
                self._missing_observable_object_error(
                    observed_data.id, object_ref
                )
                continue
            network_traffic = observable['observable']
            name = self._parse_network_traffic_observable_fields(
                network_traffic
            )
            misp_object = self._parse_network_traffic_observable_object_ref(
                observable, observed_data, name
            )
            feature = f"_parse_{name.replace('-', '_')}_reference_observable"
            for asset in ('src', 'dst'):
                if hasattr(network_traffic, f'{asset}_ref'):
                    reference = getattr(network_traffic, f'{asset}_ref')
                    referenced = self._fetch_observable(reference)
                    if referenced is None:
                        self._missing_observable_object_error(
                            observed_data.id, reference
                        )
                        continue
                    referenced_observable = referenced['observable']
                    attributes = getattr(self, feature)(
                        asset, referenced_observable,
                        f'{network_traffic.id} - {referenced_observable.id}'
                    )
                    for attribute in attributes:
                        misp_object.add_attribute(**attribute)
                    self._handle_misp_object_storage(referenced, misp_object)
            if hasattr(network_traffic, 'encapsulates_refs'):
                for reference in network_traffic.encapsulates_refs:
                    encapsulated_observable = self._fetch_observable(reference)
                    if encapsulated_observable is None:
                        self._missing_observable_object_error(
                            observed_data.id, reference
                        )
                        continue
                    name = self._parse_network_traffic_observable_fields(
                        encapsulated_observable['observable']
                    )
                    encapsulated = self._parse_network_traffic_observable_object_ref(
                        encapsulated_observable, observed_data, name
                    )
                    misp_object.add_reference(encapsulated.uuid, 'encapsulates')
            if hasattr(network_traffic, 'encapsulated_by_ref'):
                referenced_observable = self._fetch_observable(
                    network_traffic.encapsulated_by_ref
                )
                if referenced_observable is None:
                    self._missing_observable_object_error(
                        observed_data.id, network_traffic.encapsulated_by_ref
                    )
                    continue
                name = self._parse_network_traffic_observable_fields(
                    referenced_observable['observable']
                )
                referenced = self._parse_network_traffic_observable_object_ref(
                    referenced_observable, observed_data, name
                )
                misp_object.add_reference(referenced.uuid, 'encapsulated-by')

    def _parse_network_traffic_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING):
        observable_objects = {
            object_id: {'used': False}
            for object_id, observable in observed_data.objects.items()
            if observable.type == 'network-traffic'
        }
        for object_id, observable in observable_objects.items():
            network_traffic = observed_data.objects[object_id]
            name = self._parse_network_traffic_observable_fields(
                network_traffic
            )
            misp_object = self._parse_network_traffic_observable_object(
                observable_objects, object_id, observed_data, name
            )
            for asset in ('src', 'dst'):
                if hasattr(network_traffic, f'{asset}_ref'):
                    referenced_id = getattr(network_traffic, f'{asset}_ref')
                    referenced = observed_data.objects[referenced_id]
                    attributes = self._parse_network_traffic_reference_observable(
                        asset, referenced,
                        f'{observed_data.id} - {object_id} - {referenced_id}'
                    )
                    for attribute in attributes:
                        misp_object.add_attribute(**attribute)
            if hasattr(network_traffic, 'encapsulates_refs'):
                for reference in network_traffic.encapsulates_refs:
                    observable = observed_data.objects[reference]
                    name = self._parse_network_traffic_observable_fields(
                        observable
                    )
                    encapsulated = self._parse_network_traffic_observable_object(
                        observable_objects, reference, observed_data, name
                    )
                    misp_object.add_reference(encapsulated.uuid, 'encapsulates')
            if hasattr(network_traffic, 'encapsulated_by_ref'):
                referenced = observed_data.objects[
                    network_traffic.encapsulated_by_ref
                ]
                name = self._parse_network_traffic_observable_fields(referenced)
                referenced_object = self._parse_network_traffic_observable_object(
                    observable_objects, network_traffic.encapsulated_by_ref,
                    observed_data, name
                )
                misp_object.add_reference(
                    referenced_object.uuid, 'encapsulated-by'
                )

    def _parse_process_observable_object_refs(
            self, observed_data: ObservedData_v21, *object_refs: tuple):
        for object_ref in object_refs or observed_data.object_refs:
            object_type = object_ref.split('--')[0]
            observable = self._fetch_observable(object_ref)
            if observable is None:
                self._missing_observable_object_error(
                    observed_data.id, object_ref
                )
                continue
            misp_object = self._handle_observable_object_refs_parsing(
                observable, observed_data, object_type, False
            )
            if object_type == 'file':
                continue
            process = observable['observable']
            if hasattr(process, 'parent_ref'):
                self._parse_process_reference_observable_object_ref(
                    observed_data, misp_object, process.parent_ref, 'child-of'
                )
            if hasattr(process, 'child_refs'):
                for child_ref in process.child_refs:
                    self._parse_process_reference_observable_object_ref(
                        observed_data, misp_object, child_ref, 'parent-of'
                    )
            if hasattr(process, 'image_ref'):
                self._parse_process_reference_observable_object_ref(
                    observed_data, misp_object, process.image_ref,
                    'executes', name='file'
                )

    def _parse_process_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING,
            observable_objects: Optional[dict] = None):
        if len(observed_data.objects) == 1:
            return self._parse_generic_single_observable_object(
                observed_data, 'process'
            )
        if observable_objects is None:
            observable_objects = {
                object_id: {'used': False}
                for object_id in observed_data.objects
            }
        for object_id, observable in observable_objects.items():
            observable_object = observed_data.objects[object_id]
            object_type = observable_object.type
            if object_type == 'file':
                if not observable['used']:
                    misp_object = self._parse_generic_observable_object(
                        observed_data, object_id, object_type, False
                    )
                    observable.update(
                        {'misp_object': misp_object, 'used': True}
                    )
                continue
            misp_object = self._handle_observable_objects_parsing(
                observable_objects, object_id, observed_data, 'process', False
            )
            if hasattr(observable_object, 'parent_ref'):
                self._parse_process_reference_observable_object(
                    observed_data, misp_object,
                    observable_objects[observable_object.parent_ref],
                    observable_object.parent_ref, 'child-of'
                )
            if hasattr(observable_object, 'child_refs'):
                for child_ref in observable_object.child_refs:
                    self._parse_process_reference_observable_object(
                        observed_data, misp_object,
                        observable_objects[child_ref],
                        child_ref, 'parent-of'
                    )
            for feature in ('binary', 'image'):
                if hasattr(observable_object, f'{feature}_ref'):
                    reference = getattr(observable_object, f'{feature}_ref')
                    self._parse_process_reference_observable_object(
                        observed_data, misp_object,
                        observable_objects[reference],
                        reference, 'executes', name='file'
                    )

    def _parse_process_reference_observable_object(
            self, observed_data: _OBSERVED_DATA_TYPING, misp_object: MISPObject,
            observable: dict, reference: str, relationship_type: str,
            name: Optional[str] = 'process'):
        if observable['used']:
            self._handle_misp_object_references(
                misp_object, observable['misp_object'].uuid,
                relationship_type=relationship_type
            )
            return
        referenced_object = self._parse_generic_observable_object(
            observed_data, reference, name, False
        )
        self._handle_misp_object_references(
            misp_object, referenced_object.uuid,
            relationship_type=relationship_type
        )
        observable.update({'used': True, 'misp_object': referenced_object})

    def _parse_process_reference_observable_object_ref(
            self, observed_data: _OBSERVED_DATA_TYPING, misp_object: MISPObject,
            reference: str, relationship_type: str,
            name: Optional[str] = 'process'):
        observable = self._fetch_observable(reference)
        if observable is None:
            self._missing_observable_object_error(
                observed_data.id, reference
            )
            return
        if observable['used'].get(self.event_uuid, False):
            self._handle_misp_object_fields(misp_object, observed_data)
            self._handle_misp_object_references(
                misp_object, observable['misp_object'].uuid,
                relationship_type=relationship_type
            )
            return
        if reference in observed_data.object_refs:
            referenced_object = self._parse_generic_observable_object_ref(
                observable['observable'], observed_data, name, False
            )
            observable['misp_object'] = referenced_object
            observable['used'][self.event_uuid] = True
            self._handle_misp_object_references(
                misp_object, referenced_object.uuid,
                relationship_type=relationship_type
            )
        else:
            self.observable_relationships[misp_object.uuid].add(
                (
                    self.main_parser._sanitise_uuid(reference),
                    relationship_type
                )
            )

    def _parse_registry_key_observable_object(
            self, observed_data: _OBSERVED_DATA_TYPING,
            identifier: str) -> MISPObject:
        registry_key = observed_data.objects[identifier]
        if hasattr(registry_key, 'id'):
            return self._parse_registry_key_observable_object_ref(
                registry_key, observed_data
            )
        object_id = f'{observed_data.id} - {identifier}'
        regkey_object = self._create_misp_object_from_observable_object(
            'registry-key', observed_data, object_id
        )
        attributes = self._parse_registry_key_observable(
            registry_key, object_id
        )
        for attribute in attributes:
            regkey_object.add_attribute(**attribute)
        misp_object = self.main_parser._add_misp_object(
            regkey_object, observed_data
        )
        if len(registry_key.get('values', [])) > 1:
            for index, value in enumerate(registry_key['values']):
                value_uuid = self._parse_registry_key_value_observable(
                    value, observed_data, f'{object_id} - values - {index}'
                )
                self._handle_misp_object_references(
                    misp_object, value_uuid
                )
        return misp_object

    def _parse_registry_key_observable_object_ref(
            self, registry_key: WindowsRegistryKey,
            observed_data: ObservedData_v21) -> MISPObject:
        regkey_object = self._create_misp_object_from_observable_object_ref(
            'registry-key', registry_key, observed_data,
        )
        for attribute in self._parse_registry_key_observable(registry_key):
            regkey_object.add_attribute(**attribute)
        misp_object = self.main_parser._add_misp_object(
            regkey_object, observed_data
        )
        if len(registry_key.get('values', [])) > 1:
            for index, registry_value in enumerate(registry_key['values']):
                value_uuid = self._parse_registry_key_value_observable(
                    registry_value, observed_data,
                    f'{registry_key.id} - values - {index}'
                )
                self._handle_misp_object_references(
                    misp_object, value_uuid
                )
        return misp_object

    def _parse_registry_key_observable_object_refs(
            self, observed_data: ObservedData_v21, *object_refs: tuple):
        for object_ref in object_refs or observed_data.object_refs:
            observable = self._fetch_observable(object_ref)
            if observable is None:
                self._missing_observable_object_error(
                    observed_data.id, object_ref
                )
                continue
            if observable['used'].get(self.event_uuid, False):
                self._handle_misp_object_fields(
                    observable['misp_object'], observed_data
                )
                continue
            observable_object = observable['observable']
            if observable_object.type == 'user-account':
                misp_object = self._parse_generic_observable_object_ref(
                    observable_object, observed_data, 'user-account', False
                )
                observable['misp_object'] = misp_object
                observable['used'][self.event_uuid] = True
                continue
            misp_object = self._parse_registry_key_observable_object_ref(
                observable_object, observed_data
            )
            observable['misp_object'] = misp_object
            observable['used'][self.event_uuid] = True
            if hasattr(observable_object, 'creator_user_ref'):
                creator_observable = self._fetch_observable(
                    observable_object.creator_user_ref
                )
                if creator_observable is None:
                    self._missing_observable_object_error(
                        observed_data.id, observable_object.creator_user_ref
                    )
                    continue
                if creator_observable['used'].get(self.event_uuid, False):
                    creator_object = creator_observable['misp_object']
                    self._handle_misp_object_fields(
                        creator_object, observed_data
                    )
                    self._handle_misp_object_references(
                        creator_object, misp_object.uuid,
                        relationship_type='creates'
                    )
                    continue
                creator_object = self._parse_generic_observable_object_ref(
                    creator_observable['observable'], observed_data,
                    'user-account', False
                )
                self._handle_misp_object_references(
                    creator_object, misp_object.uuid,
                    relationship_type='creates'
                )
                creator_observable['misp_object'] = creator_object
                creator_observable['used'][self.event_uuid] = True

    def _parse_registry_key_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING,
            observable_objects: Optional[dict] = None):
        if len(observed_data.objects) == 1:
            registry_key = next(iter(observed_data.objects.values()))
            if hasattr(registry_key, 'id'):
                return self._parse_registry_key_observable_object_ref(
                    registry_key, observed_data
                )
            regkey_object = self._create_misp_object_from_observable_object(
                'registry-key', observed_data
            )
            attributes = self._parse_registry_key_observable(
                registry_key, observed_data.id
            )
            for attribute in attributes:
                regkey_object.add_attribute(**attribute)
            misp_object = self.main_parser._add_misp_object(
                regkey_object, observed_data
            )
            if len(registry_key.get('values', [])) > 1:
                for index, registry_value in enumerate(registry_key['values']):
                    value_uuid = self._parse_registry_key_value_observable(
                        registry_value, observed_data,
                        f'{observed_data.id} - values - {index}'
                    )
                    self._handle_misp_object_references(
                        misp_object, value_uuid
                    )
            return misp_object
        if observable_objects is None:
            observable_objects = {
                object_id: {'used': False}
                for object_id in observed_data.objects
            }
        for object_id, observable in observable_objects.items():
            observable_object = observed_data.objects[object_id]
            if observable_object.type == 'user-account':
                if observable['used']:
                    continue
                misp_object = (
                    self._parse_generic_observable_object_ref(
                        observable_object, observed_data, 'user-account', False
                    ) if observable['used'] else
                    self._parse_generic_observable_object(
                        observed_data, object_id, 'user-account', False
                    )
                )
                observable.update({'misp_object': misp_object, 'used': True})
                continue
            misp_object = self._parse_registry_key_observable_object(
                observed_data, object_id
            )
            if hasattr(observable_object, 'creator_user_ref'):
                creator_observable = observable_objects[
                    observable_object.creator_user_ref
                ]
                if creator_observable['used']:
                    self._handle_misp_object_references(
                        creator_observable['misp_object'], misp_object.uuid,
                        relationship_type='creates'
                    )
                    continue
                creator_object = self._parse_generic_observable_object(
                    observed_data, observable_object.creator_user_ref,
                    'user-account', False
                )
                self._handle_misp_object_references(
                    creator_object, misp_object.uuid,
                    relationship_type='creates'
                )
                creator_observable.update(
                    {'misp_object': creator_object, 'used': True}
                )

    def _parse_registry_key_value_observable(
            self, registry_value: _WINDOWS_REGISTRY_VALUE_TYPING,
            observed_data: _OBSERVED_DATA_TYPING, object_id: str) -> str:
        misp_object = self._create_misp_object_from_observable_object(
            'registry-key-value', observed_data, object_id
        )
        mapping = self._mapping.registry_key_values_mapping
        for field, attribute in mapping().items():
            if hasattr(registry_value, field):
                misp_object.add_attribute(
                    **self._populate_object_attribute(
                        attribute, object_id, getattr(registry_value, field)
                    )
                )
        misp_object = self.main_parser._add_misp_object(
            misp_object, observed_data
        )
        return misp_object.uuid

    def _parse_software_observable_object_refs(
            self, observed_data: ObservedData_v21, *object_refs: tuple):
        for object_ref in object_refs or observed_data.object_refs:
            observable = self._fetch_observable(object_ref)
            if observable is None:
                self._missing_observable_object_error(
                    observed_data.id, object_ref
                )
                continue
            if observable['used'].get(self.event_uuid, False):
                self._handle_misp_object_fields(
                    observable['misp_object'], observed_data
                )
                continue
            misp_object = self._parse_generic_observable_object_ref(
                observable['observable'], observed_data, 'software'
            )
            observable['misp_object'] = misp_object
            observable['used'][self.event_uuid] = True

    def _parse_software_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING,
            observable_objects: Optional[dict] = None):
        if observable_objects is not None:
            for object_id, observable in observable_objects.items():
                if observable['used']:
                    continue
                misp_object = self._parse_generic_observable_object(
                    observed_data, object_id, 'software'
                )
                observable.update({'misp_object': misp_object, 'used': True})
            return
        if len(observed_data.objects) == 1:
            return self._parse_generic_single_observable_object(
                observed_data, 'software'
            )
        for identifier in observed_data.objects:
            self._parse_generic_observable_object(
                observed_data, identifier, 'software'
            )

    def _parse_url_observable_object_refs(
            self, observed_data: ObservedData_v21, *object_refs: tuple):
        for object_ref in object_refs or observed_data.object_refs:
            observable = self._fetch_observable(object_ref)
            if observable is None:
                self._missing_observable_object_error(
                    observed_data.id, object_ref
                )
                continue
            if observable['used'].get(self.event_uuid, False):
                self._handle_misp_object_fields(
                    observable['misp_attribute'], observed_data
                )
                continue
            attribute = self._parse_generic_observable_object_ref_as_attribute(
                observable['observable'], observed_data, 'url'
            )
            observable['misp_attribute'] = attribute
            observable['used'][self.event_uuid] = True

    def _parse_url_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING,
            observable_objects: Optional[dict] = None):
        if observable_objects is not None:
            for object_id, observable in observable_objects.items():
                if observable['used']:
                    continue
                attribute = self._parse_generic_observable_object_as_attribute(
                    observed_data, object_id, 'url'
                )
                observable.update({'misp_attribute': attribute, 'used': True})
            return
        if len(observed_data.objects) == 1:
            url = next(iter(observed_data.objects.values()))
            if url.get('id') is not None:
                return self._parse_generic_observable_object_ref_as_attribute(
                    url, observed_data, 'url'
                )
            return self.main_parser._add_misp_attribute(
                {
                    'type': 'url', 'value': url.value,
                    **self._parse_timeline(observed_data),
                    **self.main_parser._sanitise_attribute_uuid(
                        observed_data.id
                    )
                },
                observed_data
            )
        for identifier in observed_data.objects:
            self._parse_generic_observable_object_as_attribute(
                observed_data, identifier, 'url'
            )

    def _parse_user_account_observable_object_refs(
            self, observed_data: ObservedData_v21, *object_refs: tuple):
        for object_ref in object_refs or observed_data.object_refs:
            observable = self._fetch_observable(object_ref)
            if observable is None:
                self._missing_observable_object_error(
                    observed_data.id, object_ref
                )
                continue
            if observable['used'].get(self.event_uuid, False):
                self._handle_misp_object_fields(
                    observable['misp_object'], observed_data
                )
                continue
            misp_object = self._parse_generic_observable_object_ref(
                observable['observable'], observed_data, 'user-account', False
            )
            observable['misp_object'] = misp_object
            observable['used'][self.event_uuid] = True

    def _parse_user_account_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING,
            observable_objects: Optional[dict] = None):
        if observable_objects is not None:
            for object_id, observable in observable_objects.items():
                if observable['used']:
                    continue
                misp_object = self._parse_generic_observable_object(
                    observed_data, object_id, 'user-account', False
                )
                observable.update({'misp_object': misp_object, 'used': True})
            return
        if len(observed_data.objects) == 1:
            return self._parse_generic_single_observable_object(
                observed_data, 'user-account', False
            )
        for identifier in observed_data.objects:
            self._parse_generic_observable_object(
                observed_data, identifier, 'user-account', False
            )

    def _parse_x509_observable_object_refs(
            self, observed_data: ObservedData_v21, *object_refs: tuple):
        for object_ref in object_refs or observed_data.object_refs:
            observable = self._fetch_observable(object_ref)
            if observable is None:
                self._missing_observable_object_error(
                    observed_data.id, object_ref
                )
                continue
            if observable['used'].get(self.event_uuid, False):
                self._handle_misp_object_fields(
                    observable['misp_object'], observed_data
                )
                continue
            misp_object = self._parse_generic_observable_object_ref(
                observable['observable'], observed_data, 'x509', False
            )
            observable['misp_object'] = misp_object
            observable['used'][self.event_uuid] = True

    def _parse_x509_observable_objects(
            self, observed_data: _OBSERVED_DATA_TYPING,
            observable_objects: Optional[dict] = None):
        if observable_objects is not None:
            for object_id, observable in observable_objects.items():
                if observable['used']:
                    continue
                misp_object = self._parse_generic_observable_object(
                    observed_data, object_id, 'x509', False
                )
                observable.update({'misp_object': misp_object, 'used': True})
            return
        if len(observed_data.objects) == 1:
            return self._parse_generic_single_observable_object(
                observed_data, 'x509', False
            )
        for identifier in observed_data.objects:
            self._parse_generic_observable_object(
                observed_data, identifier, 'x509', False
            )

    ############################################################################
    #                             UTILITY METHODS.                             #
    ############################################################################

    def _create_misp_object_from_observable_object(
            self, name: str, observed_data: _OBSERVED_DATA_TYPING,
            object_id: Optional[str] = None) -> MISPObject:
        if object_id is None:
            return self._create_misp_object(name, observed_data)
        misp_object = self._create_misp_object(name)
        misp_object.from_dict(
            uuid=self.main_parser._create_v5_uuid(object_id),
            comment=f'Observed Data ID: {observed_data.id}',
            **self._parse_timeline(observed_data)
        )
        return misp_object

    def _create_misp_object_from_observable_object_ref(
            self, name: str, observable: _OBSERVABLE_OBJECTS_TYPING,
            observed_data: _OBSERVED_DATA_TYPING) -> MISPObject:
        misp_object = self._create_misp_object(name)
        misp_object.from_dict(
            comment=f'Observed Data ID: {observed_data.id}',
            **self._parse_timeline(observed_data)
        )
        self.main_parser._sanitise_object_uuid(misp_object, observable.id)
        self.main_parser._check_sighting_replacements(
            self.main_parser._sanitise_uuid(observed_data.id), misp_object.uuid
        )
        return misp_object


    def _handle_misp_object_fields(
            self, misp_object: Union[MISPAttribute, MISPObject],
            observed_data: ObservedData_v21):
        time_fields = self._parse_timeline(observed_data)
        for field in ('timestamp', 'last_seen'):
            if time_fields.get(field) is None:
                continue
            if time_fields[field] > misp_object.get(field, datetime.max):
                setattr(misp_object, field, time_fields[field])
        if time_fields.get('first_seen') is not None:
            field = 'first_seen'
            if time_fields[field] < misp_object.get(field, datetime.min):
                misp_object.first_seen = time_fields[field]
        comment = f'Observed Data ID: {observed_data.id}'
        if misp_object.get('comment') is None:
            misp_object.comment = comment
        elif comment not in misp_object.comment:
            misp_object.comment = f'{misp_object.comment} - {comment}'

    @staticmethod
    def _handle_misp_object_references(
            misp_object: MISPObject, *object_ids: tuple,
            relationship_type: str = 'contains'):
        for object_id in object_ids:
            if not any(reference.referenced_uuid == object_id and
                   reference.relationship_type == relationship_type
                   for reference in misp_object.references):
                misp_object.add_reference(object_id, relationship_type)


class InternalSTIX2ObservedDataConverter(
        STIX2ObservedDataConverter, InternalSTIX2ObservableConverter):
    def __init__(self, main: 'InternalSTIX2toMISPParser'):
        super().__init__(main)
        self._mapping = InternalSTIX2ObservableMapping

    def parse(self, observed_data_ref: str):
        observed_data = self.main_parser._get_stix_object(observed_data_ref)
        try:
            feature = self._handle_mapping_from_labels(
                observed_data.labels, observed_data.id
            )
        except UndefinedSTIXObjectError as error:
            raise UndefinedObservableError(error)
        version = getattr(observed_data, 'spec_version', '2.0')
        to_call = f"{feature}_observable_v{version.replace('.', '')}"
        try:
            parser = getattr(self, to_call)
        except AttributeError:
            raise UnknownParsingFunctionError(to_call)
        try:
            parser(observed_data)
        except UnknownObservableMappingError as observable_types:
            self._observable_mapping_error(observed_data.id, observable_types)

    def _fetch_observables(self, observed_data_id: str,
                           object_refs: Union[tuple, str]) -> Generator:
        for object_ref in object_refs:
            observable = self._fetch_observable(object_ref)
            if observable is None:
                self._missing_observable_object_error(
                    observed_data_id, object_ref
                )
                continue
            yield self.main_parser._observable[object_ref]

    ############################################################################
    #                        ATTRIBUTES PARSING METHODS                        #
    ############################################################################

    def _attribute_from_address_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        for observable_object in observed_data.objects.values():
            if '-addr' in observable_object.type:
                attribute['value'] = observable_object.value
                break
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_address_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        for reference in observed_data.object_refs:
            if '-addr' in reference:
                observable = self._fetch_observable(reference)
                attribute['value'] = observable.value
                break
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_AS_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        observable = observed_data.objects['0']
        attribute['value'] = self._parse_AS_value(observable.number)
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_AS_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observable(observed_data.object_refs[0])
        attribute['value'] = self._parse_AS_value(observable.number)
        self.main_parser._add_misp_attribute(attribute, observed_data)

    @staticmethod
    def _attribute_from_attachment_observable(observables: tuple) -> dict:
        attribute = {}
        for observable in observables:
            if observable.type == 'file':
                attribute['value'] = observable.name
            else:
                attribute['data'] = observable.payload_bin
        return attribute

    def _attribute_from_attachment_observable_v20(
            self, observed_data: ObservedData_v20):
        self.main_parser._add_misp_attribute(
            dict(
                self._create_attribute_dict(observed_data),
                **self._attribute_from_attachment_observable(
                    tuple(observed_data.objects.values())
                )
            ),
            observed_data
        )

    def _attribute_from_attachment_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observables = tuple(
            self._fetch_observables(observed_data.id, observed_data.object_refs)
        )
        if len(observables) > 1:
            attribute.update(
                self._attribute_from_attachment_observable(observables)
            )
        else:
            attribute['value'] = observables.name
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_domain_ip_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        domain, address = observed_data.objects.values()
        attribute['value'] = f'{domain.value}|{address.value}'
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_domain_ip_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        domain, address = self._fetch_observables(
            observed_data.id, observed_data.object_refs
        )
        attribute['value'] = f'{domain.value}|{address.value}'
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_attachment_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        attribute['value'] = observed_data.objects['1'].name
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_attachment_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observable(observed_data.object_refs[1])
        attribute['value'] = observable.name
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_body_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        attribute['value'] = observed_data.objects['0'].body
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_body_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observable(observed_data.object_refs[0])
        attribute['value'] = observable.body
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_header_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        attribute['value'] = observed_data.objects['0'].received_lines[0]
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_header_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observable(observed_data.object_refs[0])
        attribute['value'] = observable.received_lines[0]
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_message_id_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observable(observed_data.object_refs[0])
        attribute['value'] = observable.message_id
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_reply_to_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        email_message = observed_data.objects['0']
        attribute['value'] = email_message.additional_header_fields['Reply-To']
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_reply_to_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observable(observed_data.object_refs[0])
        attribute['value'] = observable.additional_header_fields['Reply-To']
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_subject_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        attribute['value'] = observed_data.objects['0'].subject
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_subject_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observable(observed_data.object_refs[0])
        attribute['value'] = observable.subject
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_x_mailer_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        email_message = observed_data.objects['0']
        attribute['value'] = email_message.additional_header_fields['X-Mailer']
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_x_mailer_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observable(observed_data.object_refs[0])
        attribute['value'] = observable.additional_header_fields['X-Mailer']
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_filename_hash_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        observable = observed_data.objects['0']
        hash_value = list(observable.hashes.values())[0]
        attribute['value'] = f'{observable.name}|{hash_value}'
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_filename_hash_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observable(observed_data.object_refs[0])
        hash_value = list(observable.hashes.values())[0]
        attribute['value'] = f'{observable.name}|{hash_value}'
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_first_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        attribute['value'] = observed_data.objects['0'].value
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_first_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observable(observed_data.object_refs[0])
        attribute['value'] = observable.value
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_github_username_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observable(observed_data.object_refs[0])
        attribute['value'] = observable.account_login
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_hash_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        attribute['value'] = list(observed_data.objects['0'].hashes.values())[0]
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_hash_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observable(observed_data.object_refs[0])
        attribute['value'] = list(observable.hashes.values())[0]
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_hostname_port_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        domain, network = observed_data.objects.values()
        attribute['value'] = f'{domain.value}|{network.dst_port}'
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_hostname_port_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        domain, network = self._fetch_observables(
            observed_data.id, observed_data.object_refs
        )
        attribute['value'] = f'{domain.value}|{network.dst_port}'
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_ip_port_observable(
            self, network_traffic: _NETWORK_TRAFFIC_TYPING,
            ip_value: str, observed_data: _OBSERVED_DATA_TYPING):
        attribute = self._create_attribute_dict(observed_data)
        for feature in ('src_port', 'dst_port'):
            if hasattr(network_traffic, feature):
                port_value = getattr(network_traffic, feature)
                attribute['value'] = f'{ip_value}|{port_value}'
                self.main_parser._add_misp_attribute(attribute, observed_data)
                break

    def _attribute_from_ip_port_observable_v20(
            self, observed_data: ObservedData_v20):
        self._attribute_from_ip_port_observable(
            observed_data.objects['0'], observed_data.objects['1'].value,
            observed_data
        )

    def _attribute_from_ip_port_observable_v21(
            self, observed_data: ObservedData_v21):
        network, address = self._fetch_observables(
            observed_data.id, observed_data.object_refs
        )
        self._attribute_from_ip_port_observable(
            network, address.value, observed_data
        )

    @staticmethod
    def _attribute_from_malware_sample_observable(observables: tuple) -> dict:
        attribute = {}
        for observable in observables:
            if observable.type == 'file':
                attribute['value'] = (
                    f"{observable.name}|{observable.hashes['MD5']}"
                )
            else:
                attribute['data'] = observable.payload_bin
        return attribute

    def _attribute_from_malware_sample_observable_v20(
            self, observed_data: ObservedData_v20):
        self.main_parser._add_misp_attribute(
            dict(
                self._create_attribute_dict(observed_data),
                **self._attribute_from_malware_sample_observable(
                    observed_data.objects.values()
                )
            ),
            observed_data
        )

    def _attribute_from_malware_sample_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observables = tuple(
            self._fetch_observables(observed_data.id, observed_data.object_refs)
        )
        if len(observables) > 1:
            attribute.update(
                self._attribute_from_malware_sample_observable(observables)
            )
        else:
            attribute['value'] = (
                f"{observables.name}|{observables.hashes['MD5']}"
            )
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_name_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        attribute['value'] = observed_data.objects['0'].name
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_name_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observable(observed_data.object_refs[0])
        attribute['value'] = observable.name
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_regkey_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        attribute['value'] = observed_data.objects['0'].key
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_regkey_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observable(observed_data.object_refs[0])
        attribute['value'] = observable.key
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_regkey_value_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        observable = observed_data.objects['0']
        attribute['value'] = f"{observable.key}|{observable['values'][0].data}"
        self.main_parser._add_misp_attribute(attribute, observed_data)

    def _attribute_from_regkey_value_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observable(observed_data.object_refs[0])
        attribute['value'] = f"{observable.key}|{observable['values'][0].data}"
        self.main_parser._add_misp_attribute(attribute, observed_data)

    ############################################################################
    #                       MISP OBJECTS PARSING METHODS                       #
    ############################################################################

    def _object_from_account_with_attachment_observable(
            self, observed_data: _OBSERVED_DATA_TYPING,
            name: str, version: str):
        misp_object = self._create_misp_object(name, observed_data)
        observable = getattr(self, f'_fetch_observables_{version}')(
            observed_data
        )
        attributes = self._parse_generic_observable_with_data(
            observable, name.replace('-', '_'), observed_data.id
        )
        for attribute in attributes:
            misp_object.add_attribute(**attribute)
        self.main_parser._add_misp_object(misp_object, observed_data)

    def _object_from_android_app_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_generic_observable(
            observed_data, 'android-app', 'v20'
        )

    def _object_from_android_app_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_generic_observable(
            observed_data, 'android-app', 'v21'
        )

    def _object_from_asn_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        misp_object = self._create_misp_object('asn', observed_data)
        observable = getattr(self, f'_fetch_observables_{version}')(
            observed_data
        )
        attributes = self._parse_asn_observable(
            observable, getattr(observable, 'id', observed_data.id)
        )
        for attribute in attributes:
            misp_object.add_attribute(**attribute)
        self.main_parser._add_misp_object(misp_object, observed_data)

    def _object_from_asn_observable_v20(self, observed_data: ObservedData_v20):
        self._object_from_asn_observable(observed_data, 'v20')

    def _object_from_asn_observable_v21(self, observed_data: ObservedData_v21):
        self._object_from_asn_observable(observed_data, 'v21')

    def _object_from_cpe_asset_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_generic_observable(observed_data, 'cpe-asset', 'v20')

    def _object_from_cpe_asset_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_generic_observable(observed_data, 'cpe-asset', 'v21')

    def _object_from_credential_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_generic_observable(
            observed_data, 'credential', 'v20'
        )

    def _object_from_credential_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_generic_observable(
            observed_data, 'credential', 'v21'
        )

    def _object_from_domain_ip_observable_v20(
            self, observed_data: ObservedData_v20):
        misp_object = self._create_misp_object('domain-ip', observed_data)
        mapping = self._mapping.domain_ip_object_mapping
        ip_parsed = set()
        for observable in observed_data.objects.values():
            if observable.type == 'domain-name':
                for field, attribute in mapping().items():
                    if hasattr(observable, field):
                        attributes = self._populate_object_attributes(
                            attribute, getattr(observable, field),
                            observed_data.id
                        )
                        for attribute in attributes:
                            misp_object.add_attribute(**attribute)
                if hasattr(observable, 'resolves_to_refs'):
                    for reference in observable.resolves_to_refs:
                        if reference in ip_parsed:
                            continue
                        value = observed_data.objects[reference].value
                        misp_object.add_attribute(
                            **{
                                'value': value, **self._mapping.ip_attribute(),
                                'uuid': self.main_parser._create_v5_uuid(
                                    f'{observed_data.id} - ip - {value}'
                                )
                            }
                        )
                        ip_parsed.add(reference)
        self.main_parser._add_misp_object(misp_object, observed_data)

    def _object_from_domain_ip_observable_v21(
            self, observed_data: ObservedData_v21):
        misp_object = self._create_misp_object('domain-ip', observed_data)
        ip_parsed = set()
        for object_ref in observed_data.object_refs:
            if object_ref.startswith('domain-name--'):
                observable = self._fetch_observable(object_ref)
                for attribute in self._parse_domain_ip_observable(observable):
                    misp_object.add_attribute(**attribute)
                if hasattr(observable, 'resolves_to_refs'):
                    for reference in observable.resolves_to_refs:
                        if reference in ip_parsed:
                            continue
                        address = self._fetch_observable(reference)
                        misp_object.add_attribute(
                            **{
                                'value': address.value,
                                **self._mapping.ip_attribute(),
                                **self.main_parser._sanitise_attribute_uuid(
                                    address.id
                                )
                            }
                        )
                        ip_parsed.add(reference)
        self.main_parser._add_misp_object(misp_object, observed_data)

    def _object_from_email_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        misp_object = self._create_misp_object('email', observed_data)
        observables = dict(
            getattr(self, f'_fetch_observables_with_id_{version}')(
                observed_data
            )
        )
        for observable in observables.values():
            if observable.type != 'email-message':
                continue
            if hasattr(observable, 'from_ref'):
                address = observables[observable.from_ref]
                attributes = self._parse_email_reference_observable(
                    address, 'from', getattr(address, 'id', observed_data.id)
                )
                for attribute in attributes:
                    misp_object.add_attribute(**attribute)
            for feature in ('to', 'cc', 'bcc'):
                if hasattr(observable, f'{feature}_refs'):
                    for reference in getattr(observable, f'{feature}_refs'):
                        address = observables[reference]
                        attributes = self._parse_email_reference_observable(
                            address, feature,
                            getattr(address, 'id', observed_data.id)
                        )
                        for attribute in attributes:
                            misp_object.add_attribute(**attribute)
            object_id = getattr(observable, 'id', observed_data.id)
            attributes = self._parse_email_observable(observable, object_id)
            for attribute in attributes:
                misp_object.add_attribute(**attribute)
            if hasattr(observable, 'body_multipart'):
                for body_part in observable.body_multipart:
                    relation, value = body_part.content_disposition.split(';')
                    feature = (
                        'email_attachment' if relation == 'attachment'
                        else 'attachment'
                    )
                    reference = observables[body_part.body_raw_ref]
                    attributes = self._parse_email_body_observable(
                        reference, feature, value,
                        getattr(reference, 'id', observed_data.id)
                    )
                    for attribute in attributes:
                        misp_object.add_attribute(**attribute)
        self.main_parser._add_misp_object(misp_object, observed_data)

    def _object_from_email_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_email_observable(observed_data, 'v20')

    def _object_from_email_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_email_observable(observed_data, 'v21')

    def _object_from_facebook_account_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_account_with_attachment_observable(
            observed_data, 'facebook-account', 'v20'
        )

    def _object_from_facebook_account_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_account_with_attachment_observable(
            observed_data, 'facebook-account', 'v21'
        )

    def _object_from_file_extension_observable(
            self, extension: _EXTENSION_TYPING,
            observed_data: _OBSERVED_DATA_TYPING, object_id: str) -> str:
        pe_object = self._create_misp_object('pe')
        pe_object.from_dict(
            uuid=self.main_parser._create_v5_uuid(
                f'{observed_data.id} - windows-pebinary-ext'
            ),
            **self._parse_timeline(observed_data)
        )
        attributes = self._parse_pe_extension_observable(
            extension, f'{object_id} - windows-pebinary-ext'
        )
        for attribute in attributes:
            pe_object.add_attribute(**attribute)
        misp_object = self.main_parser._add_misp_object(pe_object, observed_data)
        if hasattr(extension, 'sections'):
            for index, section in enumerate(extension.sections):
                section_object = self._create_misp_object('pe-section')
                section_object.from_dict(
                    uuid=self.main_parser._create_v5_uuid(
                        f'{observed_data.id} - section #{index}'
                    ),
                    **self._parse_timeline(observed_data)
                )
                attributes = self._parse_pe_section_observable(
                    section, f'{object_id} - section #{index}'
                )
                for attribute in attributes:
                    section_object.add_attribute(**attribute)
                self.main_parser._add_misp_object(section_object, observed_data)
                misp_object.add_reference(section_object.uuid, 'includes')
        return misp_object.uuid

    def _object_from_file_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        file_object = self._create_misp_object('file', observed_data)
        observables = dict(
            getattr(self, f'_fetch_observables_with_id_{version}')(
                observed_data
            )
        )
        for observable in observables.values():
            if observable.type != 'file':
                continue
            object_id = getattr(observable, 'id', observed_data.id)
            attributes = self._parse_file_observable(observable, object_id)
            for attribute in attributes:
                file_object.add_attribute(**attribute)
            if hasattr(observable, 'parent_directory_ref'):
                file_object.add_attribute(
                    **self._parse_file_parent_observable(
                        observables[observable.parent_directory_ref],
                        observed_data.id
                    )
                )
            if hasattr(observable, 'content_ref'):
                artifact = observables[observable.content_ref]
                attribute = {
                    'value': artifact.x_misp_filename,
                    'data': artifact.payload_bin
                }
                if getattr(artifact, 'hashes', {}).get('MD5') is not None:
                    attribute['value'] += f"|{artifact.hashes['MD5']}"
                    attribute.update(self._mapping.malware_sample_attribute())
                else:
                    attribute.update(self._mapping.attachment_attribute())
                if hasattr(artifact, 'id'):
                    attribute.update(
                        self.main_parser._sanitise_attribute_uuid(artifact.id)
                    )
                else:
                    attribute['uuid'] = self.main_parser._create_v5_uuid(
                        f"{observed_data.id} - {attribute['type']}"
                        f" - {attribute['value']}"
                    )
                file_object.add_attribute(**attribute)
            misp_object = self.main_parser._add_misp_object(
                file_object, observed_data
            )
            if getattr(observable, 'extensions', {}).get('windows-pebinary-ext'):
                pe_uuid = self._object_from_file_extension_observable(
                    observable.extensions['windows-pebinary-ext'],
                    observed_data, object_id
                )
                misp_object.add_reference(pe_uuid, 'includes')

    def _object_from_file_observable_v20(self, observed_data: ObservedData_v20):
        self._object_from_file_observable(observed_data, 'v20')

    def _object_from_file_observable_v21(self, observed_data: ObservedData_v21):
        self._object_from_file_observable(observed_data, 'v21')

    def _object_from_generic_observable(
            self, observed_data: _OBSERVED_DATA_TYPING,
            name: str, version: str):
        misp_object = self._create_misp_object(name, observed_data)
        observable = getattr(self, f'_fetch_observables_{version}')(
            observed_data
        )
        attributes = self._parse_generic_observable(
            observable, name.replace('-', '_'),
            getattr(observable, 'id', observed_data.id)
        )
        for attribute in attributes:
            misp_object.add_attribute(**attribute)
        self.main_parser._add_misp_object(misp_object, observed_data)

    def _object_from_github_user_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_account_with_attachment_observable(
            observed_data, 'github-user', 'v20'
        )

    def _object_from_github_user_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_account_with_attachment_observable(
            observed_data, 'github-user', 'v21'
        )

    def _object_from_gitlab_user_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_generic_observable(
            observed_data, 'gitlab-user', 'v20'
        )

    def _object_from_gitlab_user_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_generic_observable(
            observed_data, 'gitlab-user', 'v21'
        )

    def _object_from_http_request_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        misp_object = self._create_misp_object('http-request', observed_data)
        observables = dict(
            getattr(self, f'_fetch_observables_with_id_{version}')(
                observed_data
            )
        )
        for observable_id, observable in observables.items():
            object_id = getattr(
                observable, 'id', f'{observed_data.id} - {observable_id}'
            )
            if observable.type == 'domain-name':
                attribute = {
                    'value': observable.value, **self._mapping.host_attribute()
                }
                attribute['uuid'] = self.main_parser._create_v5_uuid(
                    f'{object_id} - host - {observable.value}'
                )
                misp_object.add_attribute(**attribute)
                continue
            attributes = self._parse_generic_observable(
                observable, 'http_request', object_id
            )
            for attribute in attributes:
                misp_object.add_attribute(**attribute)
            for feature in ('src', 'dst'):
                if hasattr(observable, f'{feature}_ref'):
                    address_ref = getattr(observable, f'{feature}_ref')
                    address = observables[address_ref]
                    content = self._parse_network_traffic_reference_observable(
                        feature, address, getattr(
                            address, 'id', f'{observed_data.id} - {address_ref}'
                        ),
                        name='http_request'
                    )
                    for attribute in content:
                        misp_object.add_attribute(**attribute)
            if getattr(observable, 'extensions', {}).get('http-request-ext'):
                attributes = self._parse_http_request_extension_observable(
                    observable.extensions['http-request-ext'], object_id
                )
                for attribute in attributes:
                    misp_object.add_attribute(**attribute)
        self.main_parser._add_misp_object(misp_object, observed_data)

    def _object_from_http_request_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_http_request_observable(observed_data, 'v20')

    def _object_from_http_request_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_http_request_observable(observed_data, 'v21')

    def _object_from_image_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        misp_object = self._create_misp_object('image', observed_data)
        observables = dict(
            getattr(self, f'_fetch_observables_with_id_{version}')(
                observed_data
            )
        )
        for observable in observables.values():
            if observable.type == 'file':
                attributes = self._parse_generic_observable(
                    observable, 'image', observed_data.id
                )
                for attribute in attributes:
                    misp_object.add_attribute(**attribute)
            elif observable.type == 'artifact':
                if hasattr(observable, 'payload_bin'):
                    artifacts = self._parse_image_attachment_observable(
                        observable, observed_data.id
                    )
                    for attribute in artifacts:
                        misp_object.add_attribute(**attribute)
                elif hasattr(observable, 'url'):
                    urls = self._parse_image_url_observable(
                        observable, observed_data.id
                    )
                    for attribute in urls:
                        misp_object.add_attribute(**attribute)
        self.main_parser._add_misp_object(misp_object, observed_data)

    def _object_from_image_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_image_observable(observed_data, 'v20')

    def _object_from_image_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_image_observable(observed_data, 'v21')

    def _object_from_ip_port_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        misp_object = self._create_misp_object('ip-port', observed_data)
        observables = dict(
            getattr(self, f'_fetch_observables_with_id_{version}')(
                observed_data
            )
        )
        for observable in observables.values():
            if observable.type == 'network-traffic':
                ip_protocols: set = set()
                for feature in ('src', 'dst'):
                    if hasattr(observable, f'{feature}_ref'):
                        ip_attribute = getattr(
                            self._mapping, f'ip_{feature}_attribute'
                        )
                        address = observables[
                            getattr(observable, f'{feature}_ref')
                        ]
                        ip_protocols.add(address.type.split('-')[0])
                        if hasattr(address, 'id'):
                            misp_object.add_attribute(
                                **{
                                    'value': address.value, **ip_attribute(),
                                    **self.main_parser._sanitise_attribute_uuid(
                                        address.id
                                    )
                                }
                            )
                            continue
                        misp_object.add_attribute(
                            **{
                                'value': address.value, **ip_attribute(),
                                'uuid': self.main_parser._create_v5_uuid(
                                    f'{observed_data.id} - ip-{feature}'
                                    f' - {address.value}'
                                )
                            }
                        )
                attributes = self._parse_generic_observable(
                    observable, 'ip_port', observed_data.id
                )
                for attribute in attributes:
                    misp_object.add_attribute(**attribute)
                for protocol in observable.protocols:
                    if protocol not in ip_protocols:
                        misp_object.add_attribute(
                            **{
                                'value': protocol,
                                **self._mapping.protocol_attribute()
                            }
                        )
                self.main_parser._add_misp_object(misp_object, observed_data)

    def _object_from_ip_port_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_ip_port_observable(observed_data, 'v20')

    def _object_from_ip_port_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_ip_port_observable(observed_data, 'v21')

    def _object_from_lnk_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        misp_object = self._create_misp_object('lnk', observed_data)
        observables = dict(
            getattr(self, f'_fetch_observables_with_id_{version}')(
                observed_data
            )
        )
        for observable in observables.values():
            if observable.type != 'file':
                continue
            attributes = self._parse_lnk_observable(
                observable, observed_data.id
            )
            for attribute in attributes:
                misp_object.add_attribute(**attribute)
            if hasattr(observable, 'parent_directory_ref'):
                misp_object.add_attribute(
                    **self._parse_file_parent_observable(
                        observables[observable.parent_directory_ref],
                        observed_data.id
                    )
                )
            if hasattr(observable, 'content_ref'):
                artifact = observables[observable.content_ref]
                value = f"{artifact.x_misp_filename}|{artifact.hashes['MD5']}"
                attribute = {
                    'data': artifact.payload_bin, 'value': value,
                    **self._mapping.malware_sample_attribute()
                }
                if hasattr(artifact, 'id'):
                    attribute.update(
                        self.main_parser._sanitise_attribute_uuid(artifact.id)
                    )
                else:
                    attribute['uuid'] = self.main_parser._create_v5_uuid(
                        f'{observed_data.id} - malware-sample - {value}'
                    )
                misp_object.add_attribute(**attribute)
        self.main_parser._add_misp_object(misp_object, observed_data)

    def _object_from_lnk_observable_v20(self, observed_data: ObservedData_v20):
        self._object_from_lnk_observable(observed_data, 'v20')

    def _object_from_lnk_observable_v21(self, observed_data: ObservedData_v21):
        self._object_from_lnk_observable(observed_data, 'v21')

    def _object_from_mutex_observable_v20(self, observed_data: ObservedData_v20):
        self._object_from_generic_observable(observed_data, 'mutex', 'v20')

    def _object_from_mutex_observable_v21(self, observed_data: ObservedData_v21):
        self._object_from_generic_observable(observed_data, 'mutex', 'v21')

    def _object_from_netflow_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        misp_object = self._create_misp_object('netflow', observed_data)
        observables = dict(
            getattr(self, f'_fetch_observables_with_id_{version}')(
                observed_data
            )
        )
        for observable in observables.values():
            if observable.type != 'network-traffic':
                continue
            for feature in ('src', 'dst'):
                if hasattr(observable, f'{feature}_ref'):
                    address = observables[getattr(observable, f'{feature}_ref')]
                    attribute = {
                        'value': address.value,
                        **getattr(self._mapping, f'ip_{feature}_attribute')()
                    }
                    if hasattr(address, 'id'):
                        attribute.update(
                            self.main_parser._sanitise_attribute_uuid(
                                address.id
                            )
                        )
                    else:
                        attribute['uuid'] = self.main_parser._create_v5_uuid(
                            f'{observed_data.id} - ip-{feature}'
                            f' - {address.value}'
                        )
                    misp_object.add_attribute(**attribute)
                    if hasattr(address, 'belongs_to_refs'):
                        autonomous_systems = (
                            observables[reference] for reference
                            in getattr(address, 'belongs_to_refs')
                        )
                        attributes = self._parse_netflow_references(
                            feature, observed_data.id, *autonomous_systems
                        )
                        for attribute in attributes:
                            misp_object.add_attribute(**attribute)
            attributes = self._parse_netflow_observable(
                observable, observed_data.id
            )
            for attribute in attributes:
                misp_object.add_attribute(**attribute)
            self.main_parser._add_misp_object(misp_object, observed_data)

    def _object_from_netflow_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_netflow_observable(observed_data, 'v20')

    def _object_from_netflow_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_netflow_observable(observed_data, 'v21')

    def _object_from_network_connection_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        observables = dict(
            getattr(self, f'_fetch_observables_with_id_{version}')(
                observed_data
            )
        )
        for observable_id, observable in observables.items():
            if observable.type != 'network-traffic':
                continue
            misp_object = self._object_from_network_traffic_observable(
                'network-connection', observed_data, observables,
                observable_id
            )
            attributes = self._parse_network_connection_observable(
                observable, getattr(
                    observable, 'id', f'{observed_data.id} - {observable_id}'
                )
            )
            for attribute in attributes:
                misp_object.add_attribute(**attribute)
            self.main_parser._add_misp_object(misp_object, observed_data)

    def _object_from_network_connection_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_network_connection_observable(observed_data, 'v20')

    def _object_from_network_connection_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_network_connection_observable(observed_data, 'v21')

    def _object_from_network_socket_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        observables = dict(
            getattr(self, f'_fetch_observables_with_id_{version}')(
                observed_data
            )
        )
        for observable_id, observable in observables.items():
            if observable.type != 'network-traffic':
                continue
            misp_object = self._object_from_network_traffic_observable(
                'network-socket', observed_data, observables, observable_id
            )
            attributes = self._parse_network_socket_observable(
                observable, getattr(
                    observable, 'id', f'{observed_data.id} - {observable_id}'
                )
            )
            for attribute in attributes:
                misp_object.add_attribute(**attribute)
            self.main_parser._add_misp_object(misp_object, observed_data)

    def _object_from_network_socket_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_network_socket_observable(observed_data, 'v20')

    def _object_from_network_socket_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_network_socket_observable(observed_data, 'v21')

    def _object_from_network_traffic_observable(
            self, name: str, observed_data: _OBSERVED_DATA_TYPING,
            observables: dict, observable_id: str) -> MISPObject:
        misp_object = self._create_misp_object(name, observed_data)
        observable = observables[observable_id]
        attributes = self._parse_generic_observable(
            observable, name.replace('-', '_'), getattr(
                observable, 'id', f'{observed_data.id} - {observable_id}'
            )
        )
        for attribute in attributes:
            misp_object.add_attribute(**attribute)
        for asset in ('src', 'dst'):
            if hasattr(observable, f'{asset}_ref'):
                address_ref = getattr(observable, f'{asset}_ref')
                address = observables[address_ref]
                attributes = self._parse_network_traffic_reference_observable(
                    asset, address,
                    getattr(
                        address, 'id', f'{observed_data.id} - {address_ref}'
                    ),
                    name.replace('-', '_')
                )
                for attribute in attributes:
                    misp_object.add_attribute(**attribute)
        return misp_object

    def _object_from_parler_account_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_account_with_attachment_observable(
            observed_data, 'parler-account', 'v20'
        )

    def _object_from_parler_account_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_account_with_attachment_observable(
            observed_data, 'parler-account', 'v21'
        )

    def _object_from_process_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        misp_object = self._create_misp_object('process', observed_data)
        observables = dict(
            getattr(self, f'_fetch_observables_with_id_{version}')(
                observed_data
            )
        )
        main_process = self._fetch_main_process(observables)
        attributes = self._parse_process_observable(
            main_process, getattr(main_process, 'id', observed_data.id)
        )
        for attribute in attributes:
            misp_object.add_attribute(**attribute)
        if hasattr(main_process, 'binary_ref'):
            image = observables[main_process.binary_ref]
            misp_object.add_attribute(
                **{
                    **self._mapping.image_attribute(),
                    'value': image.name,
                    'uuid': self.main_parser._create_v5_uuid(
                        f'{observed_data.id} - image - {image.name}'
                    )
                }
            )
        elif hasattr(main_process, 'image_ref'):
            image = observables[main_process.image_ref]
            misp_object.add_attribute(
                **{
                    'value': image.name,
                    **self._mapping.image_attribute(),
                    **self.main_parser._sanitise_attribute_uuid(image.id)
                }
            )
        if hasattr(main_process, 'child_refs'):
            for child_ref in main_process.child_refs:
                process = observables[child_ref]
                attribute = {
                    'value': process.pid,
                    **self._mapping.child_pid_attribute()
                }
                if hasattr(process, 'id'):
                    attribute.update(
                        self.main_parser._sanitise_attribute_uuid(process.id)
                    )
                else:
                    attribute['uuid'] = self.main_parser._create_v5_uuid(
                        f'{observed_data.id} - child-pid - {process.pid}'
                    )
                misp_object.add_attribute(**attribute)
        if hasattr(main_process, 'parent_ref'):
            parent_process = observables[main_process.parent_ref]
            object_id = getattr(parent_process, 'id', observed_data.id)
            mapping = self._mapping.parent_process_object_mapping
            for feature, attribute in mapping().items():
                if hasattr(parent_process, feature):
                    misp_object.add_attribute(
                        **{
                            **attribute,
                            'value': getattr(parent_process, feature),
                            'uuid': self.main_parser._create_v5_uuid(
                                f"{object_id} - {attribute['object_relation']}"
                                f" - {getattr(parent_process, feature)}"
                            )
                        }
                    )
                    misp_object.add_attribute(**attribute)
            if hasattr(parent_process, 'binary_ref'):
                image = observables[parent_process.binary_ref]
                misp_object.add_attribute(
                    **{
                        **self._mapping.parent_image_attribute(),
                        'value': image.name,
                        'uuid': self.main_parser._create_v5_uuid(
                            f'{observed_data.id} - parent-image - {image.name}'
                        )
                    }
                )
            elif hasattr(parent_process, 'image_ref'):
                image = observables[parent_process.image_ref]
                misp_object.add_attribute(
                    **{
                        'value': image.name,
                        **self._mapping.parent_image_attribute(),
                        **self.main_parser._sanitise_attribute_uuid(image.id)
                    }
                )
        self.main_parser._add_misp_object(misp_object, observed_data)

    def _object_from_process_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_process_observable(observed_data, 'v20')

    def _object_from_process_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_process_observable(observed_data, 'v21')

    def _object_from_reddit_account_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_account_with_attachment_observable(
            observed_data, 'reddit-account', 'v20'
        )

    def _object_from_reddit_account_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_account_with_attachment_observable(
            observed_data, 'reddit-account', 'v21'
        )

    def _object_from_registry_key_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        misp_object = self._create_misp_object('registry-key', observed_data)
        observable = getattr(self, f'_fetch_observables_{version}')(
            observed_data
        )
        attributes = self._parse_registry_key_observable(
            observable, getattr(observable, 'id', observed_data.id)
        )
        for attribute in attributes:
            misp_object.add_attribute(**attribute)
        self.main_parser._add_misp_object(misp_object, observed_data)

    def _object_from_registry_key_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_registry_key_observable(observed_data, 'v20')

    def _object_from_registry_key_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_registry_key_observable(observed_data, 'v21')

    def _object_from_telegram_account_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_generic_observable(
            observed_data, 'telegram-account', 'v20'
        )

    def _object_from_telegram_account_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_generic_observable(
            observed_data, 'telegram-account', 'v21'
        )

    def _object_from_twitter_account_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_account_with_attachment_observable(
            observed_data, 'twitter-account', 'v20'
        )

    def _object_from_twitter_account_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_account_with_attachment_observable(
            observed_data, 'twitter-account', 'v21'
        )

    def _object_from_url_observable_v20(self, observed_data: ObservedData_v20):
        self._object_from_generic_observable(observed_data, 'url', 'v20')

    def _object_from_url_observable_v21(self, observed_data: ObservedData_v21):
        self._object_from_generic_observable(observed_data, 'url', 'v21')

    def _object_from_user_account_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        misp_object = self._create_misp_object('user-account', observed_data)
        observable = getattr(self, f'_fetch_observables_{version}')(
            observed_data
        )
        object_id = getattr(observable, 'id', observed_data.id)
        attributes = self._parse_generic_observable_with_data(
            observable, 'user_account', object_id
        )
        for attribute in attributes:
            misp_object.add_attribute(**attribute)
        if getattr(observable, 'extensions', {}).get('unix-account-ext'):
            attributes = self._parse_generic_observable(
                observable.extensions['unix-account-ext'],
                'unix_user_account_extension', object_id
            )
            for attribute in attributes:
                misp_object.add_attribute(**attribute)
        self.main_parser._add_misp_object(misp_object, observed_data)

    def _object_from_user_account_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_user_account_observable(observed_data, 'v20')

    def _object_from_user_account_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_user_account_observable(observed_data, 'v21')

    def _object_from_x509_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        misp_object = self._create_misp_object('x509', observed_data)
        observable = getattr(self, f'_fetch_observables_{version}')(
            observed_data
        )
        object_id = getattr(observable, 'id', observed_data.id)
        for attribute in self._parse_x509_observable(observable, object_id):
            misp_object.add_attribute(**attribute)
        if hasattr(observable, 'x509_v3_extensions'):
            extension = observable.x509_v3_extensions
            for values in extension.subject_alternative_name.split(','):
                key, value = values.split('=')
                mapping = self._mapping.x509_subject_alternative_name_mapping(
                    key
                )
                if mapping is not None:
                    misp_object.add_attribute(
                        **{
                            'value': value, **mapping,
                            'uuid': self.main_parser._create_v5_uuid(
                                f"{object_id} - {mapping['object_relation']}"
                                f" - {value}"
                            )
                        }
                    )
        self.main_parser._add_misp_object(misp_object, observed_data)

    def _object_from_x509_observable_v20(self, observed_data: ObservedData_v20):
        self._object_from_x509_observable(observed_data, 'v20')

    def _object_from_x509_observable_v21(self, observed_data: ObservedData_v21):
        self._object_from_x509_observable(observed_data, 'v21')

    ############################################################################
    #                             UTILITY METHODS.                             #
    ############################################################################

    @staticmethod
    def _fetch_main_process(observables: dict) -> _PROCESS_TYPING:
        observable_types = tuple(
            observable.type for observable in observables.values()
        )
        if observable_types.count('process') == 1:
            for observable in observables.values():
                if observable.type == 'process':
                    return observable
        ref_features = ('child_refs', 'parent_ref')
        for observable in observables.values():
            if observable.type != 'process':
                continue
            if any(hasattr(observable, feature) for feature in ref_features):
                return observable

    @staticmethod
    def _fetch_observables_v20(observed_data: ObservedData_v20):
        observables = tuple(observed_data.objects.values())
        return observables[0] if len(observables) == 1 else observables

    def _fetch_observables_v21(self, observed_data: ObservedData_v21):
        observables = tuple(
            self._fetch_observables(observed_data.id, observed_data.object_refs)
        )
        return observables[0] if len(observables) == 1 else observables

    @staticmethod
    def _fetch_observables_with_id_v20(observed_data: ObservedData_v20) -> dict:
        return observed_data.objects

    def _fetch_observables_with_id_v21(
            self, observed_data: ObservedData_v21) -> Generator:
        for reference in observed_data.object_refs:
            observable = self._fetch_observable(reference)
            if observable is None:
                self._missing_observable_object_error(
                    observed_data.id, reference
                )
                continue
            yield reference, observable
